/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type dnsKnowledgeEntry struct {
	expiresAt  int64
	cacheCount int
}

func parseDnsKnowledgeEntry(value any) (dnsKnowledgeEntry, bool) {
	switch value := value.(type) {
	case dnsKnowledgeEntry:
		return value, true
	case int64:
		// Accept legacy/test values written before cache-family counts existed.
		return dnsKnowledgeEntry{expiresAt: value}, true
	default:
		return dnsKnowledgeEntry{}, false
	}
}

func (c *DnsController) storeDnsCache(cacheKey string, cache *DnsCache) (previous any, loaded bool) {
	previous, loaded = c.dnsCache.Swap(cacheKey, cache)
	if !loaded {
		c.dnsCacheSize.Add(1)
	}
	return previous, loaded
}

func (c *DnsController) loadAndDeleteDnsCache(cacheKey string) (value any, loaded bool) {
	value, loaded = c.dnsCache.LoadAndDelete(cacheKey)
	if loaded {
		c.decrementDnsCacheSize()
	}
	return value, loaded
}

func (c *DnsController) compareAndDeleteDnsCache(cacheKey string, cache *DnsCache) bool {
	if !c.dnsCache.CompareAndDelete(cacheKey, cache) {
		return false
	}
	c.decrementDnsCacheSize()
	return true
}

func (c *DnsController) decrementDnsCacheSize() {
	for {
		current := c.dnsCacheSize.Load()
		if current <= 0 || c.dnsCacheSize.CompareAndSwap(current, current-1) {
			return
		}
	}
}

func (c *DnsController) CloneCacheForReload() map[string]*DnsCache {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	result := make(map[string]*DnsCache)
	c.dnsCache.Range(func(key, value any) bool {
		k, ok1 := key.(string)
		v, ok2 := value.(*DnsCache)
		if ok1 && ok2 {
			result[k] = v.CloneForReload()
		} else if c.log != nil {
			c.log.Errorf("CloneCacheForReload: invalid type found in sync.Map: key=%T, value=%T", key, value)
		}
		return true
	})
	return result
}

// RestoreReloadCacheAndProject restores cache entries and synchronously
// applies their BPF side effects. Reload publication uses this variant so an
// inactive routing plan has a complete domain projection before it becomes
// visible to packets. The runtime callback must not attempt to update this
// controller's runtime while it is executing.
func (c *DnsController) RestoreReloadCacheAndProject(entries map[string]*DnsCache, matchDomainBitmap func(string) []uint32, now time.Time) (int, error) {
	return c.restoreReloadCache(entries, matchDomainBitmap, now)
}

func (c *DnsController) restoreReloadCache(entries map[string]*DnsCache, matchDomainBitmap func(string) []uint32, now time.Time) (int, error) {
	if c == nil || len(entries) == 0 {
		return 0, nil
	}
	c.requireStore()
	count := 0
	for k, v := range entries {
		if v == nil {
			continue
		}

		for {
			rt := c.runtime()
			restored := v.CloneForReload()
			ensureDNSCacheRouteOwnerKey(k, restored)
			if rt != nil {
				restored.RouteProjectionEpoch = rt.routeProjectionEpoch
			}
			switch {
			case rt != nil && rt.projectCacheRoute != nil:
				restored.DomainBitmap = rt.projectCacheRoute(restored)
			case matchDomainBitmap != nil:
				restored.DomainBitmap = matchDomainBitmap(restored.GetFqdn())
			case v.DomainBitmap != nil:
				restored.DomainBitmap = append([]uint32(nil), v.DomainBitmap...)
			}

			// Pair the rebuilt bitmap with the runtime that supplied its epoch.
			// A reload can replace the runtime while the matcher is running, in
			// which case retrying avoids publishing an old projection as new.
			c.runtimeMu.RLock()
			if c.runtime() != rt {
				c.runtimeMu.RUnlock()
				continue
			}

			c.cacheProjectionMu.Lock()
			c.enforceDnsCacheCapacityLocked(k)
			_, loaded := c.storeDnsCache(k, restored)
			c.rememberDnsKnowledge(dnsCacheBaseKey(k), restored.OriginalDeadline, !loaded)
			if rt != nil && rt.cacheAccessCallback != nil {
				if err := rt.cacheAccessCallback(restored); err != nil {
					c.cacheProjectionMu.Unlock()
					c.runtimeMu.RUnlock()
					return count, fmt.Errorf("project restored DNS cache %q: %w", k, err)
				}
				restored.MarkBpfUpdated(now)
			} else {
				c.triggerBpfUpdateIfNeededForRuntime(restored, now, rt)
			}
			c.cacheProjectionMu.Unlock()
			c.runtimeMu.RUnlock()

			count++
			break
		}
	}
	return count, nil
}

// cacheEntry represents a DNS cache entry with its access time for LRU eviction.
type cacheEntry struct {
	key        string
	lastAccess int64
}

func (c *DnsController) cacheKey(qname string, qtype uint16) string {
	// To fqdn.
	qname = dnsmessage.CanonicalName(qname)
	// Fast path: use pre-computed string for common qtypes
	if s, ok := qtypeStrCache[qtype]; ok {
		return qname + s
	}
	// Slow path: fallback to strconv for uncommon types
	return qname + strconv.Itoa(int(qtype))
}

func dnsCacheBaseKey(cacheKey string) string {
	if before, _, ok := strings.Cut(cacheKey, "|"); ok {
		return before
	}
	return cacheKey
}

// responseCacheKey scopes a base cache key to the upstream that produced the
// answer, so an as-is answer for one destination cannot be served for another.
func (c *DnsController) responseCacheKey(baseKey string, req *udpRequest, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream) string {
	var scope string
	switch upstreamIndex {
	case consts.DnsRequestOutboundIndex_AsIs:
		scope = "asis"
		if req != nil && req.realDst.IsValid() {
			scope = "asis@" + req.realDst.String()
		}
	case consts.DnsRequestOutboundIndex_Reject:
		scope = "reject"
	default:
		switch {
		case upstream != nil:
			scope = "upstream@" + upstream.String()
		case upstreamIndex != 0:
			scope = "upstream-index@" + strconv.Itoa(int(upstreamIndex))
		}
	}
	if scope == "" {
		return baseKey
	}
	return baseKey + "|" + scope
}

func ensureDNSCacheRouteOwnerKey(cacheKey string, cache *DnsCache) *DnsCache {
	if cache == nil {
		return nil
	}
	if cache.RouteOwnerKey == "" {
		cache.RouteOwnerKey = cacheKey
	}
	return cache
}

func (c *DnsController) RemoveDnsRespCacheFamily(baseKey string) {
	c.requireStore()
	if baseKey == "" {
		return
	}
	c.cacheProjectionMu.Lock()
	defer c.cacheProjectionMu.Unlock()
	c.dnsCache.Range(func(key, value any) bool {
		cacheKey, ok := key.(string)
		if !ok || dnsCacheBaseKey(cacheKey) != baseKey {
			return true
		}
		cache, ok := value.(*DnsCache)
		if !ok {
			c.loadAndDeleteDnsCache(cacheKey)
			return true
		}
		if c.compareAndDeleteDnsCache(cacheKey, cache) {
			c.invokeCacheDeleteCallback(cacheKey, cache)
		}
		return true
	})
	c.syncDnsKnowledge(baseKey)
}

func (c *DnsController) rememberDnsKnowledge(baseKey string, originalDeadline time.Time, newCacheEntry bool) {
	if baseKey == "" {
		return
	}
	expiresAt := originalDeadline.UnixNano()
	c.dnsKnowledgeMu.Lock()
	defer c.dnsKnowledgeMu.Unlock()

	current, loaded := c.dnsKnowledge.Load(baseKey)
	entry, valid := parseDnsKnowledgeEntry(current)
	switch {
	case !loaded || !valid:
		entry = dnsKnowledgeEntry{cacheCount: 1}
	case newCacheEntry:
		entry.cacheCount++
	case entry.cacheCount == 0:
		entry.cacheCount = 1
	}
	if entry.expiresAt < expiresAt {
		entry.expiresAt = expiresAt
	}
	c.dnsKnowledge.Store(baseKey, entry)
}

func (c *DnsController) forgetDnsKnowledge(cacheKey string, cache *DnsCache) {
	baseKey := dnsCacheBaseKey(cacheKey)
	if baseKey == "" || cache == nil {
		return
	}

	deletedExpiresAt := cache.OriginalDeadline.UnixNano()

	c.dnsKnowledgeMu.Lock()
	defer c.dnsKnowledgeMu.Unlock()

	current, ok := c.dnsKnowledge.Load(baseKey)
	if !ok {
		return
	}
	entry, ok := parseDnsKnowledgeEntry(current)
	if !ok || entry.cacheCount <= 0 {
		c.syncDnsKnowledgeLocked(baseKey)
		return
	}
	if entry.cacheCount == 1 {
		c.dnsKnowledge.Delete(baseKey)
		return
	}
	entry.cacheCount--
	if deletedExpiresAt < entry.expiresAt {
		c.dnsKnowledge.Store(baseKey, entry)
		return
	}
	c.syncDnsKnowledgeLocked(baseKey)
}

func (c *DnsController) syncDnsKnowledge(baseKey string) {
	if baseKey == "" {
		return
	}
	c.dnsKnowledgeMu.Lock()
	defer c.dnsKnowledgeMu.Unlock()
	c.syncDnsKnowledgeLocked(baseKey)
}

func (c *DnsController) syncDnsKnowledgeLocked(baseKey string) {
	entry := dnsKnowledgeEntry{}

	c.dnsCache.Range(func(key, value any) bool {
		cacheKey, ok := key.(string)
		if !ok || dnsCacheBaseKey(cacheKey) != baseKey {
			return true
		}
		cache, ok := value.(*DnsCache)
		if !ok {
			c.loadAndDeleteDnsCache(cacheKey)
			return true
		}

		expiresAt := cache.OriginalDeadline.UnixNano()
		entry.cacheCount++
		if expiresAt > entry.expiresAt {
			entry.expiresAt = expiresAt
		}
		return true
	})

	if entry.cacheCount == 0 {
		c.dnsKnowledge.Delete(baseKey)
		return
	}
	c.dnsKnowledge.Store(baseKey, entry)
}

func (c *DnsController) HasDnsKnowledge(baseKey string) bool {
	c.requireStore()
	if baseKey == "" {
		return false
	}
	value, ok := c.dnsKnowledge.Load(baseKey)
	if !ok {
		return false
	}
	entry, ok := parseDnsKnowledgeEntry(value)
	if !ok {
		c.dnsKnowledge.Delete(baseKey)
		return false
	}
	if entry.expiresAt <= time.Now().UnixNano() {
		return false
	}
	return true
}

func (c *DnsController) invokeCacheDeleteCallback(cacheKey string, cache *DnsCache) {
	rt := c.runtime()
	if cache == nil || rt == nil || rt.cacheDeleteCallback == nil {
		return
	}
	if err := rt.cacheDeleteCallback(cacheKey, ensureDNSCacheRouteOwnerKey(cacheKey, cache)); err != nil {
		if c.log != nil {
			c.log.Warnf("failed to delete exact dns cache side effects: %v", err)
		}
	}
}

// evictDnsCacheLocked removes one cache entry while cacheProjectionMu is held.
func (c *DnsController) evictDnsCacheLocked(cacheKey string, cache *DnsCache) bool {
	if cache == nil || !c.compareAndDeleteDnsCache(cacheKey, cache) {
		return false
	}
	c.forgetDnsKnowledge(cacheKey, cache)
	c.invokeCacheDeleteCallback(cacheKey, cache)
	return true
}

// enforceDnsCacheCapacityLocked keeps a configured maximum as an admission
// bound rather than waiting for the periodic janitor. The normal at-capacity
// case selects the oldest entry from a fixed sample so admission work does not
// grow with cache cardinality.
func (c *DnsController) enforceDnsCacheCapacityLocked(incomingKey string) {
	_, _, maxCacheSize := c.currentOptimisticCacheConfig()
	if maxCacheSize <= 0 {
		return
	}
	if _, exists := c.dnsCache.Load(incomingKey); exists {
		return
	}
	c.trimDnsCacheToSizeLocked(maxCacheSize - 1)
}

func (c *DnsController) trimDnsCacheToSizeLocked(targetSize int) {
	if targetSize < 0 {
		targetSize = 0
	}
	count := int(c.dnsCacheSize.Load())
	if count <= targetSize {
		return
	}

	excess := count - targetSize
	if excess == 1 {
		const admissionEvictionSampleSize = 16
		var victimKey string
		var victim *DnsCache
		var oldestAccess int64
		sampled := 0
		c.dnsCache.Range(func(key, value any) bool {
			sampled++
			cacheKey, keyOK := key.(string)
			cache, cacheOK := value.(*DnsCache)
			if !keyOK || !cacheOK || cache == nil {
				return sampled < admissionEvictionSampleSize
			}
			access := cache.lastAccessNano.Load()
			if victim == nil || access < oldestAccess {
				victimKey, victim, oldestAccess = cacheKey, cache, access
			}
			return sampled < admissionEvictionSampleSize
		})
		if victim != nil {
			c.evictDnsCacheLocked(victimKey, victim)
		}
		return
	}

	// A runtime limit reduction can require a bulk trim. Prefer bounded memory
	// over allocating and retaining an O(cache-size) LRU scratch slice here; the
	// janitor continues to provide precise LRU ordering during normal operation.
	c.dnsCache.Range(func(key, value any) bool {
		if excess == 0 {
			return false
		}
		cacheKey, keyOK := key.(string)
		cache, cacheOK := value.(*DnsCache)
		if !keyOK || !cacheOK || cache == nil {
			return true
		}
		if c.evictDnsCacheLocked(cacheKey, cache) {
			excess--
		}
		return true
	})
}

func (c *DnsController) evictDnsRespCacheIfSame(cacheKey string, cache *DnsCache) {
	if cache == nil {
		return
	}
	c.cacheProjectionMu.Lock()
	defer c.cacheProjectionMu.Unlock()
	c.evictDnsCacheLocked(cacheKey, cache)
}

func (c *DnsController) evictExpiredDnsCache(now time.Time) {
	optimisticCacheEnabled, optimisticCacheTtl, maxCacheSize := c.currentOptimisticCacheConfig()
	// Step 1: Time-based eviction
	// - When optimistic_cache_ttl > 0: evict entries older than (deadline + stale_window)
	// - When optimistic_cache_ttl == 0 AND maxCacheSize > 0: skip time-based eviction (rely on LRU)
	// - When both are 0 (backward compat / direct struct creation): use deadline-based eviction
	useTimeBasedEviction := optimisticCacheTtl > 0 || (optimisticCacheTtl == 0 && maxCacheSize == 0)

	if useTimeBasedEviction {
		c.dnsCache.Range(func(key, value any) bool {
			cacheKey, ok := key.(string)
			if !ok {
				if _, loaded := c.dnsCache.LoadAndDelete(key); loaded {
					c.decrementDnsCacheSize()
				}
				return true
			}
			cache, ok := value.(*DnsCache)
			if !ok {
				c.loadAndDeleteDnsCache(cacheKey)
				return true
			}

			// Calculate effective deadline
			// - If optimistic cache is enabled and ttl > 0: use (deadline + optimisticCacheTtl)
			// - Otherwise: use deadline directly
			effectiveDeadline := cache.Deadline
			if optimisticCacheEnabled && optimisticCacheTtl > 0 {
				effectiveDeadline = cache.Deadline.Add(time.Duration(optimisticCacheTtl) * time.Second)
			}

			if effectiveDeadline.After(now) {
				return true // Still valid, keep it
			}

			// Too stale or expired without optimistic cache, evict it
			c.evictDnsRespCacheIfSame(cacheKey, cache)
			return true
		})
	}

	// Step 2: LRU eviction if cache size exceeds limit
	// This is important when optimistic_cache_ttl=0 (never expire)
	if maxCacheSize > 0 {
		c.evictLRUIfFull(maxCacheSize)
	}
}

func (c *DnsController) takeLRUScratch(minCap int) []cacheEntry {
	c.lruScratchMu.Lock()
	defer c.lruScratchMu.Unlock()

	if cap(c.lruScratch) >= minCap {
		entries := c.lruScratch[:0]
		c.lruScratch = nil
		return entries
	}

	c.lruScratch = nil
	return make([]cacheEntry, 0, minCap)
}

func (c *DnsController) putLRUScratch(entries []cacheEntry) {
	if entries == nil {
		return
	}

	clear(entries)
	const maxRetainedLRUScratchEntries = 4096
	if cap(entries) > maxRetainedLRUScratchEntries {
		return
	}

	c.lruScratchMu.Lock()
	if cap(entries) > cap(c.lruScratch) {
		c.lruScratch = entries[:0]
	}
	c.lruScratchMu.Unlock()
}

// evictLRUIfFull evicts least recently used entries if cache size exceeds limit.
// OPTIMIZATION: Uses heap selection algorithm (O(n + k log n)) instead of
// full sort (O(n log n)) or insertion sort (O(n²)) for better performance
// with large caches. For typical cache sizes (<1000), the overhead is negligible.
// For large caches (>5000), this is 10-100x faster than insertion sort.
func (c *DnsController) evictLRUIfFull(maxCacheSize int) {
	if maxCacheSize <= 0 {
		return
	}
	// Count current cache size
	var count int
	c.dnsCache.Range(func(_, _ any) bool {
		count++
		return true
	})

	if count <= maxCacheSize {
		return
	}

	// Find and evict oldest entries
	// Need to evict (count - maxCacheSize) entries
	numToEvict := count - maxCacheSize

	// Collect all cache entries with their access times
	// Reuse a scratch buffer to avoid allocating a new slice on every janitor run.
	entries := c.takeLRUScratch(count)
	scratch := entries
	defer func() {
		c.putLRUScratch(scratch)
	}()
	c.dnsCache.Range(func(key, value any) bool {
		cacheKey, ok := key.(string)
		if !ok {
			return true
		}
		cache, ok := value.(*DnsCache)
		if !ok {
			return true
		}
		entries = append(entries, cacheEntry{
			key:        cacheKey,
			lastAccess: cache.lastAccessNano.Load(),
		})
		return true
	})
	scratch = entries

	// Use heap selection to find the k oldest entries.
	// Build a min-heap and extract k elements: O(n + k log n)
	// This is more efficient than full sort O(n log n) when k << n.
	if numToEvict < len(entries) {
		// Build min-heap based on lastAccess (smallest = oldest)
		buildMinHeap(entries)

		// Extract k oldest entries from heap
		for i := range numToEvict {
			// Swap root (minimum) with last element
			lastIdx := len(entries) - 1 - i
			entries[0], entries[lastIdx] = entries[lastIdx], entries[0]

			// Restore heap property for remaining elements
			heapifyMin(entries, 0, lastIdx)
		}

		// The k oldest are now at the end of entries (indices len-n to len-1)
		entries = entries[len(entries)-numToEvict:]
	}

	// Evict oldest entries
	evicted := 0
	for _, entry := range entries {
		if evicted >= numToEvict {
			break
		}

		// Load cache again to get current reference
		if val, ok := c.dnsCache.Load(entry.key); ok {
			if cache, ok := val.(*DnsCache); ok {
				c.evictDnsRespCacheIfSame(entry.key, cache)
				evicted++
			}
		}
	}
}

// startDnsCacheJanitor runs a periodic goroutine that evicts expired DNS cache
// entries and retires idle DNS forwarders.
//
// IMPORTANT: This goroutine intentionally does NOT watch baseContext().Done().
// See bpfUpdateWorker comment for the rationale — the same stale-context problem
// applies here when the DnsController is reused across reload generations.
func (c *DnsController) startDnsCacheJanitor() {
	c.requireStore()
	go func() {
		ticker := time.NewTicker(dnsCacheJanitorInterval)
		defer ticker.Stop()
		defer close(c.janitorDone)

		for {
			select {
			case <-c.janitorStop:
				return
			case now := <-ticker.C:
				c.evictExpiredDnsCache(now)
				c.evictIdleDnsForwarders(now)
			}
		}
	}()
}

func (c *DnsController) LookupDnsRespCache(cacheKey string, ignoreFixedTtl bool) (cache *DnsCache) {
	c.requireStore()
	val, ok := c.dnsCache.Load(cacheKey)
	if !ok {
		return nil
	}
	cache = val.(*DnsCache)
	now := time.Now()
	var deadline time.Time
	if !ignoreFixedTtl {
		deadline = cache.Deadline
	} else {
		deadline = cache.OriginalDeadline
	}
	// We should make sure the cache did not expire, or
	// return nil and request a new lookup to refresh the cache.
	if !deadline.After(now) {
		c.evictDnsRespCacheIfSame(cacheKey, cache)
		return nil
	}
	// OPTIMIZATION: Asynchronous BPF map update to keep hot path fast.
	// BPF update happens in background goroutine with bounded queue.
	// CAS in NeedsBpfUpdate ensures update is triggered at most once per interval.
	c.triggerBpfUpdateIfNeeded(cache, now)
	return cache
}

// LookupDnsRespCache_ will modify the msg in place.

// OPTIMIZED: Uses pre-packed response with approximate TTL for near-zero latency.
// TTL is refreshed when difference exceeds ttlRefreshThresholdSeconds (15 seconds by default).
// OPTIMISTIC CACHE (RFC 8767): Returns stale response while background refresh is in progress.
// Falls back to an owned in-place TTL-aware pack if pre-packed response is not available.
func (c *DnsController) LookupDnsRespCache_(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) (resp []byte, needRefresh bool) {
	c.requireStore()
	// Load cache directly without expiry check (to support optimistic cache)
	val, ok := c.dnsCache.Load(cacheKey)
	if !ok {
		return nil, false
	}
	cache := val.(*DnsCache)

	now := time.Now()

	// Update last access time for LRU eviction (atomic operation)
	cache.lastAccessNano.Store(now.UnixNano())

	// Determine deadline based on ignoreFixedTtl
	var deadline time.Time
	if !ignoreFixedTtl {
		deadline = cache.Deadline
	} else {
		deadline = cache.OriginalDeadline
	}

	// Fast path: use pre-packed response with approximate TTL (fresh response)
	if deadline.After(now) {
		// Extract qname and qtype from the message for TTL refresh
		var qname string
		var qtype uint16
		if len(msg.Question) > 0 {
			qname = msg.Question[0].Name
			qtype = msg.Question[0].Qtype
		}

		if resp := cache.GetPackedResponseWithApproximateTTL(qname, qtype, now); resp != nil {
			// Fresh cache hit - return immediately
			// Trigger async BPF update if needed
			c.triggerBpfUpdateIfNeeded(cache, now)
			return resp, false
		}

		// Fallback: pre-packed response not available, use the owned in-place path.
		// LookupDnsRespCache_ already owns dnsMessage exclusively and is documented
		// to mutate it in place, so this avoids the extra request copy on the
		// remaining TTL-aware cache-hit fallback.
		if resp = cache.fillIntoWithTTLInPlace(msg, now); resp != nil {
			return resp, false
		}
		return nil, false
	}

	// Cache expired - check if optimistic cache is enabled
	optimisticCacheEnabled, optimisticCacheTtl, _ := c.currentOptimisticCacheConfig()
	if optimisticCacheEnabled {
		// Try stale response (RFC 8767)
		// Use optimisticCacheTtl (0 means never expire)
		if resp = cache.GetStaleResponse(now, optimisticCacheTtl); resp != nil {
			// Within stale window - return stale response and trigger background refresh
			// Use CAS to ensure only one goroutine triggers refresh
			if cache.refreshing.CompareAndSwap(false, true) {
				needRefresh = true
			}
			return resp, needRefresh
		}
	}

	// Cache expired and beyond stale window (or optimistic cache disabled)
	// Evict the cache
	c.evictDnsRespCacheIfSame(cacheKey, cache)
	return nil, false
}

// NormalizeAndCacheDnsResp_ handle DNS resp in place.
func (c *DnsController) NormalizeAndCacheDnsResp_(msg *dnsmessage.Msg, responseCacheKey string) (err error) {
	// Check healthy resp.
	if !msg.Response || len(msg.Question) == 0 || msg.Rcode != dnsmessage.RcodeSuccess {
		return nil
	}

	q := msg.Question[0]

	// Get TTL.
	var ttl uint32
	if len(msg.Answer) > 0 {
		ttl = msg.Answer[0].Header().Ttl
	} else {
		// NXDomain or empty answer
		ttl = minFirefoxCacheTtl
	}

	// Clamp TTL to 1 year max to prevent integer overflow when casting to int on 32-bit platforms
	if ttl > 31536000 {
		ttl = 31536000
	}

	// For A/AAAA records, we set TTL to 0 to prevent downstream caching while we manage it.
	if q.Qtype == dnsmessage.TypeA || q.Qtype == dnsmessage.TypeAAAA {
		for i := range msg.Answer {
			msg.Answer[i].Header().Ttl = 0
		}
	}

	// Update DnsCache.
	return c.updateDnsCache(msg, responseCacheKey, ttl, &q)
}

func (c *DnsController) updateDnsCache(msg *dnsmessage.Msg, responseCacheKey string, ttl uint32, q *dnsmessage.Question) error {
	// Update DnsCache.
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"_qname": q.Name,
			"rcode":  msg.Rcode,
			"ans":    FormatDnsRsc(msg.Answer),
		}).Tracef("Update DNS record cache")
	}

	if err := c.UpdateDnsCacheTtlWithKey(responseCacheKey, q.Name, q.Qtype, msg.Answer, msg.Ns, msg.Extra, int(ttl)); err != nil {
		return err
	}
	return nil
}

type daedlineFunc func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time)

func (c *DnsController) __updateDnsCacheDeadline(cacheKey string, host string, dnsTyp uint16, answers, ns, extra []dnsmessage.RR, deadlineFunc daedlineFunc) (err error) {
	var fqdn string
	if strings.HasSuffix(host, ".") {
		fqdn = strings.ToLower(host)
		host = host[:len(host)-1]
	} else {
		fqdn = dnsmessage.CanonicalName(host)
	}
	// Bypass pure IP.
	if _, err = netip.ParseAddr(host); err == nil {
		return nil
	}

	now := time.Now()
	deadline, originalDeadline := deadlineFunc(now, host)

	if cacheKey == "" {
		cacheKey = c.cacheKey(fqdn, dnsTyp)
	}
	baseKey := dnsCacheBaseKey(cacheKey)

	for {
		rt := c.runtime()
		if rt == nil || rt.newCache == nil {
			return fmt.Errorf("dns controller runtime newCache is not configured")
		}
		newCache, err := rt.newCache(fqdn, answers, ns, extra, deadline, originalDeadline)
		if err != nil {
			return err
		}
		newCache.RouteProjectionEpoch = rt.routeProjectionEpoch

		// Pre-pack before publication so cache readers only observe a complete
		// entry. The cache/runtime locks below make the entry, its projection,
		// and reload epoch one atomic publication unit.
		if err = newCache.prepackResponseBeforeStore(fqdn, dnsTyp, ttlFromDeadline(deadline, now), now); err != nil {
			if c.log != nil {
				c.log.Warnf("failed to prepack DNS response: %v", err)
			}
		}

		c.runtimeMu.RLock()
		if c.runtime() != rt {
			c.runtimeMu.RUnlock()
			continue
		}
		c.cacheProjectionMu.Lock()
		if c.runtime() != rt {
			c.cacheProjectionMu.Unlock()
			c.runtimeMu.RUnlock()
			continue
		}

		newCache.RouteOwnerKey = cacheKey
		c.enforceDnsCacheCapacityLocked(cacheKey)
		_, loaded := c.storeDnsCache(cacheKey, newCache)
		c.rememberDnsKnowledge(baseKey, originalDeadline, !loaded)

		projectionErr := error(nil)
		if rt.cacheAccessCallback != nil {
			projectionErr = rt.cacheAccessCallback(newCache)
		}
		if projectionErr == nil {
			newCache.MarkBpfUpdated(now)
		}
		c.cacheProjectionMu.Unlock()
		c.runtimeMu.RUnlock()

		if projectionErr != nil {
			c.startBpfUpdateWorker()
			c.scheduleBpfProjectionRetry(&bpfUpdateTask{
				cache:                newCache,
				routeProjectionEpoch: rt.routeProjectionEpoch,
			})
			return projectionErr
		}
		return nil
	}
}

func (c *DnsController) UpdateDnsCacheTtl(host string, dnsTyp uint16, answers, ns, extra []dnsmessage.RR, ttl int) (err error) {
	c.requireStore()
	return c.__updateDnsCacheDeadline("", host, dnsTyp, answers, ns, extra, func(now time.Time, host string) (daedline time.Time, originalDeadline time.Time) {
		originalDeadline = now.Add(time.Duration(ttl) * time.Second)
		if rt := c.runtime(); rt != nil {
			if fixedTtl, ok := rt.fixedDomainTtl[host]; ok {
				return now.Add(time.Duration(fixedTtl) * time.Second), originalDeadline
			}
		}
		return originalDeadline, originalDeadline
	})
}

func (c *DnsController) UpdateDnsCacheTtlWithKey(cacheKey string, host string, dnsTyp uint16, answers, ns, extra []dnsmessage.RR, ttl int) (err error) {
	c.requireStore()
	return c.__updateDnsCacheDeadline(cacheKey, host, dnsTyp, answers, ns, extra, func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time) {
		originalDeadline = now.Add(time.Duration(ttl) * time.Second)
		if rt := c.runtime(); rt != nil {
			if fixedTtl, ok := rt.fixedDomainTtl[host]; ok {
				return now.Add(time.Duration(fixedTtl) * time.Second), originalDeadline
			}
		}
		return originalDeadline, originalDeadline
	})
}

// buildMinHeap constructs a min-heap from the cache entries slice.
// The heap property: parent <= children (root is minimum, i.e., oldest access).
// Time complexity: O(n)
func buildMinHeap(entries []cacheEntry) {
	n := len(entries)
	// Start from the last non-leaf node and heapify down
	for i := n/2 - 1; i >= 0; i-- {
		heapifyMin(entries, i, n)
	}
}

// heapifyMin restores the min-heap property for the subtree rooted at index i.
// The heap size is limited to n elements.
// Time complexity: O(log n)
func heapifyMin(entries []cacheEntry, i, n int) {
	for {
		smallest := i
		left := 2*i + 1
		right := 2*i + 2

		// Find smallest (oldest) among root, left child, and right child
		if left < n && entries[left].lastAccess < entries[smallest].lastAccess {
			smallest = left
		}
		if right < n && entries[right].lastAccess < entries[smallest].lastAccess {
			smallest = right
		}

		// If root is already smallest, heap property is satisfied
		if smallest == i {
			break
		}

		// Swap and continue heapifying
		entries[i], entries[smallest] = entries[smallest], entries[i]
		i = smallest
	}
}
