/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"container/heap"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// dnsResponseBufPool is a pool for DNS response buffers.
// This avoids memory allocation on every cache hit for ID patching.
// Typical DNS response size is under 512 bytes, we allocate 1024 to be safe.
var dnsResponseBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 1024)
		return &buf
	},
}

const (
	MaxDnsLookupDepth  = 3
	minFirefoxCacheTtl = 120
)

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

var (
	ErrUnsupportedQuestionType          = fmt.Errorf("unsupported question type")
	ErrDNSQueryConcurrencyLimitExceeded = errors.New("dns query concurrency limit exceeded")
	ErrDNSUDPConnPoolExhausted          = errors.New("dns udp conn pool exhausted")
	ErrDNSTruncated                     = errors.New("dns response truncated")
)

var (
	UnspecifiedAddressA          = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA       = netip.MustParseAddr("::")
	DnsCacheRouteRefreshInterval = 10 * time.Second // Aligned with health check granularity (default 30s)
	dnsCacheJanitorInterval      = 30 * time.Second
	dnsForwarderIdleTTL          = 2 * time.Minute
)

type DnsControllerOption struct {
	Log                  *logrus.Logger
	LifecycleContext     context.Context
	CacheAccessCallback  func(cache *DnsCache) (err error)
	CacheRemoveCallback  func(cache *DnsCache) (err error)
	CacheDeleteCallback  func(cacheKey string, cache *DnsCache) (err error)
	NewCache             func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	RouteProjectionEpoch uint64
	// RouteProjectionHash identifies the semantic policy content used to build
	// DomainBitmap. A non-zero hash lets reload reuse an existing projection
	// without walking or cloning the DNS cache when only the generation epoch
	// changed.
	RouteProjectionHash [32]byte
	ProjectCacheRoute   func(cache *DnsCache) []uint32
	// BestDialerChooser is the transport-independent dialer selector: it takes
	// the routing facts of the request rather than its socket.
	BestDialerChooser     func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *dns.Upstream) (*dialArgument, error)
	TimeoutExceedCallback func(dialArgument *dialArgument, err error)
	IpVersionPrefer       int
	FixedDomainTtl        map[string]int
	ConcurrencyLimit      int
	OptimisticCache       bool
	OptimisticCacheTtl    int // 0 means never expire (rely on LRU eviction)
	MaxCacheSize          int // maximum number of cache entries (0 = unlimited)
}

type dnsControllerRuntimeState struct {
	routing                   *dns.Dns
	lifecycleCtx              context.Context
	cacheAccessCallback       func(cache *DnsCache) (err error)
	cacheRemoveCallback       func(cache *DnsCache) (err error)
	cacheDeleteCallback       func(cacheKey string, cache *DnsCache) (err error)
	newCache                  func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	routeProjectionEpoch      uint64
	routeProjectionHash       [32]byte
	projectCacheRoute         func(cache *DnsCache) []uint32
	bestDialerChooser         func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *dns.Upstream) (*dialArgument, error)
	timeoutExceedCallback     func(dialArgument *dialArgument, err error)
	fixedDomainTtl            map[string]int
}

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

type dnsControllerStore struct {
	// dnsCache uses sync.Map for lock-free concurrent access
	dnsCache               sync.Map // map[string]*DnsCache
	dnsCacheSize           atomic.Int64
	dnsKnowledge           sync.Map // map[string]int64 (base cache key -> original deadline unix nano)
	dnsKnowledgeMu         sync.Mutex
	qtypePrefer            atomic.Uint32
	optimisticCacheEnabled atomic.Bool
	optimisticCacheTtl     atomic.Int64 // seconds, 0 means never expire
	maxCacheSize           atomic.Int64 // maximum number of cache entries (0 = unlimited)
	// runtimeState belongs to the shared store so long-lived workers always
	// observe the latest reload facade instead of the facade that started them.
	runtimeState      atomic.Pointer[dnsControllerRuntimeState]
	runtimeMu         sync.RWMutex // Serializes runtime publication with reload cache projection.
	cacheProjectionMu sync.RWMutex // Serializes cache membership with BPF projection callbacks.
	dnsForwarderCache sync.Map     // map[dnsForwarderKey]*cachedDnsForwarder
	sf                singleflight.Group

	janitorStop  chan struct{}
	janitorDone  chan struct{}
	evictorDone  chan struct{}
	evictorQ     chan *DnsCache
	evictorWake  chan struct{}
	evictorChMu  sync.RWMutex
	evictorMu    sync.Mutex
	evictorBuf   []*DnsCache
	lruScratchMu sync.Mutex
	lruScratch   []cacheEntry
	closeOnce    sync.Once

	// Async BPF update uses one worker and a durable, deduplicated retry intent
	// set. A full primary queue must not discard a projection for a cache entry
	// that has no later reader.
	bpfUpdateCh      chan *bpfUpdateTask
	bpfRetryWake     chan struct{}
	bpfRetryMu       sync.Mutex
	bpfRetryPending  map[bpfProjectionRetryKey]*bpfUpdateTask
	bpfRetryOverflow bool
	bpfUpdateStop    chan struct{}
	bpfUpdateStopMu  sync.Mutex // Protects bpfUpdateStop initialization and closing
	bpfUpdateWg      sync.WaitGroup
	bpfUpdateOnce    sync.Once
	bpfUpdateClosed  atomic.Bool

	// prefWaitRegistry manages waits for preferred DNS response types.
	// When ip_version_prefer is set, non-preferred responses wait briefly
	// for preferred responses to arrive (RFC 8305 Happy Eyeballs).
	prefWaitRegistry *preferenceWaitRegistry
}

// DnsController is a lightweight generation-local facade over a shared
// dnsControllerStore. The zero value is not ready for production use; construct
// controllers with NewDnsController, ReuseForReload, or dedicated test helpers
// so the shared store invariant is established before business methods run.
type DnsController struct {
	*dnsControllerStore

	concurrencyLimiter chan struct{}

	dnsForwarderIdleTTL time.Duration
	log                 *logrus.Logger
}

func newDnsControllerStore() *dnsControllerStore {
	return &dnsControllerStore{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		janitorStop:       make(chan struct{}),
		janitorDone:       make(chan struct{}),
		evictorDone:       make(chan struct{}),
		evictorQ:          make(chan *DnsCache, 512),
		evictorWake:       make(chan struct{}, 1),
		prefWaitRegistry:  newPreferenceWaitRegistry(),
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

func normalizeDnsRuntimeBehavior(option *DnsControllerOption) (qtypePrefer uint16, optimisticCacheEnabled bool, optimisticCacheTtl int, maxCacheSize int, err error) {
	if option == nil {
		option = &DnsControllerOption{}
	}
	qtypePrefer, err = parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return 0, false, 0, 0, err
	}
	optimisticCacheTtl = option.OptimisticCacheTtl
	maxCacheSize = option.MaxCacheSize
	if optimisticCacheTtl == 0 && maxCacheSize == 0 {
		optimisticCacheTtl = 60
	}
	return qtypePrefer, option.OptimisticCache, optimisticCacheTtl, maxCacheSize, nil
}

func (c *DnsController) requireStore() *dnsControllerStore {
	if c == nil {
		return nil
	}
	if c.dnsControllerStore == nil {
		// Business-path DNS methods require the shared store invariant to have
		// been established by NewDnsController, ReuseForReload, or test helpers.
		// Panic here so misuse fails fast instead of silently constructing an
		// empty store and masking initialization bugs.
		panic("DnsController.dnsControllerStore is nil; construct controllers with NewDnsController or test helpers")
	}
	return c.dnsControllerStore
}

func (c *DnsController) ensureStoreForReload() *dnsControllerStore {
	if c == nil {
		return nil
	}
	if c.dnsControllerStore == nil {
		c.dnsControllerStore = newDnsControllerStore()
	}
	return c.dnsControllerStore
}

func (c *DnsController) sharedStoreFacade() *DnsController {
	if c == nil {
		return nil
	}
	store := c.requireStore()
	facade := &DnsController{
		dnsControllerStore:  store,
		concurrencyLimiter:  c.concurrencyLimiter,
		dnsForwarderIdleTTL: c.dnsForwarderIdleTTL,
		log:                 c.log,
	}
	return facade
}

func (c *DnsController) currentQtypePrefer() uint16 {
	if c == nil {
		return 0
	}
	return uint16(c.qtypePrefer.Load())
}

func (c *DnsController) currentOptimisticCacheConfig() (enabled bool, ttl int, maxCacheSize int) {
	if c == nil {
		return false, 0, 0
	}
	return c.optimisticCacheEnabled.Load(), int(c.optimisticCacheTtl.Load()), int(c.maxCacheSize.Load())
}

// ReuseForReload updates the current facade to the replacement generation's
// runtime and returns a fresh facade that shares the same long-lived store.
// The shared store carries DNS cache, forwarders, janitors, async BPF workers,
// and the current runtime/config across reloads. The old control plane publishes
// the new facade as a handoff bridge so ActiveDnsController observes the
// replacement runtime without a nil window during reload retirement.
func (c *DnsController) ReuseForReload(option *DnsControllerOption, routing *dns.Dns) (*DnsController, error) {
	if c == nil {
		return nil, nil
	}
	c.ensureStoreForReload()
	previousRuntime := c.runtime()
	projectionUnchanged := previousRuntime != nil && option != nil &&
		option.RouteProjectionHash != ([32]byte{}) &&
		previousRuntime.routeProjectionHash == option.RouteProjectionHash
	if projectionUnchanged {
		// Projection epochs identify bitmap content, not control-plane lifetime.
		// Keeping the old epoch makes every existing cache wrapper valid for the
		// replacement runtime, avoiding an O(cache size) reload walk.
		adjustedOption := *option
		adjustedOption.RouteProjectionEpoch = previousRuntime.routeProjectionEpoch
		option = &adjustedOption
	}
	if err := c.TryUpdateRuntime(option, routing); err != nil {
		return nil, err
	}
	if !projectionUnchanged {
		c.reprojectCachedRoutes(c.runtime())
	}
	if err := c.ResetDnsForwarders(); err != nil && c.log != nil {
		c.log.WithError(err).Warn("failed to retire stale DNS forwarders during reload reuse")
	}
	return c.sharedStoreFacade(), nil
}

func (c *DnsController) reprojectCachedRoutes(rt *dnsControllerRuntimeState) {
	if c == nil || c.dnsControllerStore == nil || rt == nil || rt.projectCacheRoute == nil {
		return
	}

	now := time.Now()
	c.dnsCache.Range(func(key, value any) bool {
		cacheKey, ok := key.(string)
		if !ok {
			return true
		}
		cache, ok := value.(*DnsCache)
		if !ok || cache == nil || cache.RouteProjectionEpoch == rt.routeProjectionEpoch {
			return true
		}

		replacement := cache.CloneForReload()
		ensureDNSCacheRouteOwnerKey(cacheKey, replacement)
		replacement.RouteProjectionEpoch = rt.routeProjectionEpoch
		replacement.DomainBitmap = rt.projectCacheRoute(replacement)

		// Pair the rebuilt bitmap with the runtime that supplied its epoch.
		// A reload can replace the runtime while the matcher is running, in
		// which case the stale projection must not be published.
		c.runtimeMu.RLock()
		if c.runtime() == rt {
			c.cacheProjectionMu.Lock()
			if c.runtime() == rt && c.dnsCache.CompareAndSwap(key, cache, replacement) {
				c.triggerBpfUpdateIfNeededForRuntime(replacement, now, rt)
			}
			c.cacheProjectionMu.Unlock()
		}
		c.runtimeMu.RUnlock()
		return true
	})
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

// RestoreReloadCache restores cache entries during reload and schedules their
// BPF side effects through the regular asynchronous path.
func (c *DnsController) RestoreReloadCache(entries map[string]*DnsCache, matchDomainBitmap func(string) []uint32, now time.Time) int {
	count, _ := c.restoreReloadCache(entries, matchDomainBitmap, now, false)
	return count
}

// RestoreReloadCacheAndProject restores cache entries and synchronously
// applies their BPF side effects. Reload publication uses this variant so an
// inactive routing plan has a complete domain projection before it becomes
// visible to packets. The runtime callback must not attempt to update this
// controller's runtime while it is executing.
func (c *DnsController) RestoreReloadCacheAndProject(entries map[string]*DnsCache, matchDomainBitmap func(string) []uint32, now time.Time) (int, error) {
	return c.restoreReloadCache(entries, matchDomainBitmap, now, true)
}

func (c *DnsController) restoreReloadCache(entries map[string]*DnsCache, matchDomainBitmap func(string) []uint32, now time.Time, projectSynchronously bool) (int, error) {
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
			if projectSynchronously && rt != nil && rt.cacheAccessCallback != nil {
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

// bpfUpdateTask represents a BPF map update request.
type bpfUpdateTask struct {
	cache                *DnsCache
	routeProjectionEpoch uint64
	retryAttempt         uint8
}

const (
	bpfProjectionRetryLimit     = 5
	bpfProjectionRetryBaseDelay = 25 * time.Millisecond
	bpfProjectionRetryMaxDelay  = time.Second
	bpfProjectionRetryCapacity  = 4096
)

type bpfProjectionRetryKey struct {
	cacheKey             string
	routeProjectionEpoch uint64
}

func (task *bpfUpdateTask) retryKey() (bpfProjectionRetryKey, bool) {
	if task == nil || task.cache == nil || task.cache.RouteOwnerKey == "" {
		return bpfProjectionRetryKey{}, false
	}
	return bpfProjectionRetryKey{
		cacheKey:             task.cache.RouteOwnerKey,
		routeProjectionEpoch: task.routeProjectionEpoch,
	}, true
}

type bpfProjectionRetryItem struct {
	task  *bpfUpdateTask
	due   time.Time
	key   bpfProjectionRetryKey
	index int
}

type bpfProjectionRetryHeap []*bpfProjectionRetryItem

func (h bpfProjectionRetryHeap) Len() int {
	return len(h)
}

func (h bpfProjectionRetryHeap) Less(i, j int) bool {
	return h[i].due.Before(h[j].due)
}

func (h bpfProjectionRetryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *bpfProjectionRetryHeap) Push(value any) {
	item := value.(*bpfProjectionRetryItem)
	item.index = len(*h)
	*h = append(*h, item)
}

func (h *bpfProjectionRetryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	old[last] = nil
	item.index = -1
	*h = old[:last]
	return item
}

type bpfProjectionRetryScheduler struct {
	queue   bpfProjectionRetryHeap
	pending map[bpfProjectionRetryKey]*bpfProjectionRetryItem
}

func newBpfProjectionRetryScheduler() *bpfProjectionRetryScheduler {
	return &bpfProjectionRetryScheduler{
		pending: make(map[bpfProjectionRetryKey]*bpfProjectionRetryItem),
	}
}

func (s *bpfProjectionRetryScheduler) add(task *bpfUpdateTask) bool {
	if s == nil || task == nil {
		return false
	}
	return s.addAt(task, time.Now())
}

func (s *bpfProjectionRetryScheduler) addAt(task *bpfUpdateTask, now time.Time) bool {
	if s == nil || task == nil {
		return false
	}
	key, ok := task.retryKey()
	if !ok {
		return false
	}
	due := now.Add(bpfProjectionRetryDelay(task.retryAttempt))
	if pending := s.pending[key]; pending != nil {
		if pending.task.cache != task.cache {
			pending.task = task
			pending.due = due
			heap.Fix(&s.queue, pending.index)
			return true
		}
		if !due.Before(pending.due) && task.retryAttempt >= pending.task.retryAttempt {
			return true
		}
		pending.task = task
		pending.due = due
		heap.Fix(&s.queue, pending.index)
		return true
	}
	if len(s.pending) >= bpfProjectionRetryCapacity {
		return false
	}
	item := &bpfProjectionRetryItem{task: task, due: due, key: key}
	heap.Push(&s.queue, item)
	s.pending[key] = item
	return true
}

func (s *bpfProjectionRetryScheduler) nextDue() (time.Time, bool) {
	if s == nil || s.queue.Len() == 0 {
		return time.Time{}, false
	}
	return s.queue[0].due, true
}

func (s *bpfProjectionRetryScheduler) popDue(now time.Time) []*bpfUpdateTask {
	if s == nil {
		return nil
	}
	var tasks []*bpfUpdateTask
	for s.queue.Len() > 0 && !s.queue[0].due.After(now) {
		item := heap.Pop(&s.queue).(*bpfProjectionRetryItem)
		delete(s.pending, item.key)
		tasks = append(tasks, item.task)
	}
	return tasks
}

func bpfProjectionRetryDelay(attempt uint8) time.Duration {
	delay := bpfProjectionRetryBaseDelay
	for retry := uint8(1); retry < attempt && delay < bpfProjectionRetryMaxDelay; retry++ {
		delay *= 2
	}
	if delay > bpfProjectionRetryMaxDelay {
		return bpfProjectionRetryMaxDelay
	}
	return delay
}

// cacheEntry represents a DNS cache entry with its access time for LRU eviction.
type cacheEntry struct {
	key        string
	lastAccess int64
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	if option == nil {
		option = &DnsControllerOption{}
	}

	prefer, optimisticCacheEnabled, optimisticCacheTtl, maxCacheSize, err := normalizeDnsRuntimeBehavior(option)
	if err != nil {
		return nil, err
	}

	// Set concurrency limit for DNS queries
	// This prevents resource exhaustion from DNS query storms.
	//
	// Best Practice (based on CoreDNS/AdGuard Home):
	// Go DNS apps typically don't have hard concurrency limits because:
	// - Go goroutines are lightweight (~2KB stack)
	// - Real bottleneck is upstream latency, not goroutine count
	//
	// However, for proxy chains (Shadowsocks/VMess), each query takes longer,
	// so we need a higher limit to maintain throughput.
	//
	// Memory calculation: Each concurrent query uses ~4KB
	//   * 16384 concurrent = ~64MB memory (default)
	//   * 32768 concurrent = ~128MB memory
	//
	// Comparison with other DNS apps:
	//   * CoreDNS: No hard limit (relies on Go runtime)
	//   * AdGuard Home: No hard limit
	//   * Unbound (C): 10000 (outgoing-range)
	//   * PowerDNS: 2048 (max-mthreads)
	//
	// Default: 16384 (suitable for proxy scenarios)
	// - Handles up to ~8000 QPS with 2s upstream latency
	// - Memory usage: ~64MB for concurrent queries
	//
	// Configuration:
	// - <= 0: Use default (16384)
	// - > 0: Use specified value
	const defaultConcurrencyLimit = 16384
	limit := option.ConcurrencyLimit
	if limit <= 0 {
		limit = defaultConcurrencyLimit
	}

	controller := &DnsController{
		dnsControllerStore:  newDnsControllerStore(),
		concurrencyLimiter:  make(chan struct{}, limit), // 0 means no limit (unbuffered channel, always non-blocking)
		log:                 option.Log,
		dnsForwarderIdleTTL: dnsForwarderIdleTTL, // Use package-level default
	}
	controller.qtypePrefer.Store(uint32(prefer))
	controller.optimisticCacheEnabled.Store(optimisticCacheEnabled)
	controller.optimisticCacheTtl.Store(int64(optimisticCacheTtl))
	controller.maxCacheSize.Store(int64(maxCacheSize))
	if err := controller.TryUpdateRuntime(option, routing); err != nil {
		return nil, err
	}
	controller.startDnsCacheJanitor()
	controller.startCacheEvictor()
	return controller, nil
}

func (c *DnsController) updateRuntime(option *DnsControllerOption, routing *dns.Dns) error {
	if c == nil {
		return nil
	}
	c.requireStore()
	if option == nil {
		option = &DnsControllerOption{}
	}
	qtypePrefer, optimisticCacheEnabled, optimisticCacheTtl, maxCacheSize, err := normalizeDnsRuntimeBehavior(option)
	if err != nil {
		return err
	}
	c.qtypePrefer.Store(uint32(qtypePrefer))
	c.optimisticCacheEnabled.Store(optimisticCacheEnabled)
	c.optimisticCacheTtl.Store(int64(optimisticCacheTtl))
	c.maxCacheSize.Store(int64(maxCacheSize))
	c.log = option.Log
	lifecycleCtx := option.LifecycleContext
	if lifecycleCtx == nil {
		lifecycleCtx = context.Background()
	}
	runtimeState := &dnsControllerRuntimeState{
		routing:                   routing,
		lifecycleCtx:              lifecycleCtx,
		cacheAccessCallback:       option.CacheAccessCallback,
		cacheRemoveCallback:       option.CacheRemoveCallback,
		cacheDeleteCallback:       option.CacheDeleteCallback,
		newCache:                  option.NewCache,
		routeProjectionEpoch:      option.RouteProjectionEpoch,
		routeProjectionHash:       option.RouteProjectionHash,
		projectCacheRoute:         option.ProjectCacheRoute,
		bestDialerChooser:         option.BestDialerChooser,
		timeoutExceedCallback:     option.TimeoutExceedCallback,
		fixedDomainTtl:            option.FixedDomainTtl,
	}
	c.runtimeMu.Lock()
	c.runtimeState.Store(runtimeState)
	c.runtimeMu.Unlock()
	if maxCacheSize > 0 && c.dnsCacheSize.Load() > int64(maxCacheSize) {
		c.cacheProjectionMu.Lock()
		c.trimDnsCacheToSizeLocked(maxCacheSize)
		c.cacheProjectionMu.Unlock()
	}
	return nil
}

func (c *DnsController) runtime() *dnsControllerRuntimeState {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	return c.runtimeState.Load()
}

// TryUpdateRuntime updates generation-local DNS runtime state and reports
// invalid behavior config via error.
func (c *DnsController) TryUpdateRuntime(option *DnsControllerOption, routing *dns.Dns) error {
	return c.updateRuntime(option, routing)
}

// UpdateRuntime preserves the historical panic-on-invalid-input API for
// external callers. New internal code should use TryUpdateRuntime.
func (c *DnsController) UpdateRuntime(option *DnsControllerOption, routing *dns.Dns) {
	if err := c.TryUpdateRuntime(option, routing); err != nil {
		panic(err)
	}
}

func (c *DnsController) baseContext() context.Context {
	if rt := c.runtime(); rt != nil && rt.lifecycleCtx != nil {
		return rt.lifecycleCtx
	}
	return context.Background()
}

func (c *DnsController) newWorkContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.baseContext(), timeout)
}

func (c *DnsController) Close() error {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	var (
		bpfWorkerDone <-chan struct{}
		janitorDone   <-chan struct{}
		evictorDone   <-chan struct{}
	)

	// Acquire lock before closeOnce to synchronize with startBpfUpdateWorker.
	// This prevents the race where Close and startBpfUpdateWorker access
	// bpfUpdateStop concurrently.
	c.bpfUpdateStopMu.Lock()
	c.closeOnce.Do(func() {
		c.bpfUpdateClosed.Store(true)
		// Stop BPF update worker (if it was started).
		if c.bpfUpdateStop != nil {
			// Signal worker to stop and drain remaining tasks
			close(c.bpfUpdateStop)
			// Wait for worker to finish draining.
			done := make(chan struct{})
			go func() {
				c.bpfUpdateWg.Wait()
				close(done)
			}()
			bpfWorkerDone = done
			// Note: We intentionally do NOT close bpfUpdateCh here.
			// Closing the channel while concurrent sends might be in progress
			// would cause panics. Instead, the channel will be garbage collected
			// when the DnsController is no longer referenced.
		}

		if c.janitorStop != nil {
			close(c.janitorStop)
		}
		if c.janitorDone != nil {
			janitorDone = c.janitorDone
		}
		if c.evictorDone != nil {
			evictorDone = c.evictorDone
		}
	})
	c.bpfUpdateStopMu.Unlock()
	// Wait for any in-flight projection callback before cache teardown. A task
	// that arrives after this barrier observes bpfUpdateClosed and is discarded.
	c.cacheProjectionMu.Lock()
	// This lock/unlock pair is an intentional barrier for in-flight projection callbacks.
	//nolint:staticcheck // The empty critical section provides the required wait barrier.
	c.cacheProjectionMu.Unlock()

	if bpfWorkerDone != nil || janitorDone != nil || evictorDone != nil {
		timer := time.NewTimer(gracefulShutdownWaitTimeout)
		defer timer.Stop()

		for bpfWorkerDone != nil || janitorDone != nil || evictorDone != nil {
			select {
			case <-bpfWorkerDone:
				bpfWorkerDone = nil
			case <-janitorDone:
				janitorDone = nil
			case <-evictorDone:
				evictorDone = nil
			case <-timer.C:
				if c.log != nil {
					if bpfWorkerDone != nil {
						c.log.Warn("DnsController.Close: timeout waiting for bpfUpdateWg")
					}
					if janitorDone != nil {
						c.log.Warn("DnsController.Close: timeout waiting for janitorDone")
					}
					if evictorDone != nil {
						c.log.Warn("DnsController.Close: timeout waiting for evictorDone")
					}
				}
				bpfWorkerDone = nil
				janitorDone = nil
				evictorDone = nil
			}
		}
	}

	errs := c.closeAllDnsForwarders()

	// Clear dnsCache to prevent memory leak on reload.
	// Each DnsCache entry contains DomainBitmap and Answer which can accumulate
	// significant memory over time if not released.
	c.cacheProjectionMu.Lock()
	c.dnsCache.Range(func(key, value any) bool {
		c.dnsCache.Delete(key)
		return true
	})
	c.dnsCacheSize.Store(0)
	c.cacheProjectionMu.Unlock()
	c.dnsKnowledge.Range(func(key, value any) bool {
		c.dnsKnowledge.Delete(key)
		return true
	})
	c.evictorMu.Lock()
	c.evictorBuf = nil
	c.evictorMu.Unlock()
	c.lruScratchMu.Lock()
	c.lruScratch = nil
	c.lruScratchMu.Unlock()
	c.evictorChMu.Lock()
	c.evictorWake = nil
	c.evictorQ = nil
	c.evictorChMu.Unlock()
	c.bpfUpdateStopMu.Lock()
	c.bpfUpdateCh = nil
	c.bpfUpdateStop = nil
	c.bpfUpdateStopMu.Unlock()
	c.bpfRetryMu.Lock()
	c.bpfRetryWake = nil
	c.bpfRetryPending = nil
	c.bpfRetryMu.Unlock()

	return errors.Join(errs...)
}

func (c *DnsController) closeAllDnsForwarders() []error {
	if c == nil {
		return nil
	}
	var errs []error
	c.dnsForwarderCache.Range(func(key, value any) bool {
		k := key.(dnsForwarderKey)
		c.dnsForwarderCache.Delete(k)
		switch entry := value.(type) {
		case *cachedDnsForwarder:
			if err := entry.closeNow(); err != nil {
				errs = append(errs, fmt.Errorf("close dns forwarder %q: %w", k.upstream, err))
			}
		default:
			forwarder := c.extractDnsForwarder(value)
			if forwarder != nil {
				if err := forwarder.Close(); err != nil {
					errs = append(errs, fmt.Errorf("close dns forwarder %q: %w", k.upstream, err))
				}
			}
		}
		return true
	})
	return errs
}

func (c *DnsController) retireAllDnsForwarders() []error {
	if c == nil {
		return nil
	}
	var errs []error
	c.dnsForwarderCache.Range(func(key, value any) bool {
		k := key.(dnsForwarderKey)
		switch entry := value.(type) {
		case *cachedDnsForwarder:
			if !c.dnsForwarderCache.CompareAndDelete(k, entry) {
				return true
			}
			if err := entry.retire(); err != nil {
				errs = append(errs, fmt.Errorf("retire dns forwarder %q: %w", k.upstream, err))
			}
		default:
			if !c.dnsForwarderCache.CompareAndDelete(k, value) {
				return true
			}
			forwarder := c.extractDnsForwarder(value)
			if forwarder != nil {
				if err := forwarder.Close(); err != nil {
					errs = append(errs, fmt.Errorf("close dns forwarder %q: %w", k.upstream, err))
				}
			}
		}
		return true
	})
	return errs
}

func (c *DnsController) ResetDnsForwarders() error {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	// Retire cached forwarders so new requests redial using the replacement
	// generation's runtime, while in-flight upstream exchanges finish cleanly.
	return errors.Join(c.retireAllDnsForwarders()...)
}

var (
	// Pre-computed strings for common DNS query types to reduce allocations
	// in the hot path. Fallback to strconv.Itoa for uncommon types.
	qtypeStrCache = map[uint16]string{
		dnsmessage.TypeA:     "1",
		dnsmessage.TypeNS:    "2",
		dnsmessage.TypeCNAME: "5",
		dnsmessage.TypePTR:   "12",
		dnsmessage.TypeMX:    "15",
		dnsmessage.TypeTXT:   "16",
		dnsmessage.TypeAAAA:  "28",
		dnsmessage.TypeSRV:   "33",
	}
)

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

func aggregateDNSRemovalCandidate(caches []*DnsCache) *DnsCache {
	var (
		base    *DnsCache
		answers []dnsmessage.RR
		seen    = make(map[netip.Addr]struct{})
	)

	for _, cache := range caches {
		if cache == nil {
			continue
		}
		if base == nil {
			base = cache
		}
		for _, ans := range cache.Answer {
			ip, ok := dnsAnswerIP(ans)
			if !ok || ip.IsUnspecified() {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			answers = append(answers, ans)
		}
	}

	if base == nil || len(answers) == 0 {
		return nil
	}
	return &DnsCache{
		DomainBitmap:     base.DomainBitmap,
		Answer:           answers,
		Deadline:         base.Deadline,
		OriginalDeadline: base.OriginalDeadline,
	}
}

// orphanedDnsSideEffects filters removal side effects against the authoritative
// remaining cache state for the same base key. Once scoped cache keys exist,
// removing one scoped entry must not blindly delete IP-derived side effects
// that are still backed by another live scoped entry.
func (c *DnsController) orphanedDnsSideEffects(baseKey string, candidate *DnsCache) *DnsCache {
	if candidate == nil {
		return nil
	}
	if baseKey == "" {
		return candidate
	}
	// Cache deletion updates dnsKnowledge before reaching this function. A
	// missing family proves that no sibling cache can still own these IPs and
	// avoids an O(total cache size) scan for normal unique-domain eviction.
	if _, familyStillCached := c.dnsKnowledge.Load(baseKey); !familyStillCached {
		return candidate
	}

	liveIPs := make(map[netip.Addr]struct{})
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
		for _, ans := range cache.Answer {
			ip, ok := dnsAnswerIP(ans)
			if !ok || ip.IsUnspecified() {
				continue
			}
			liveIPs[ip] = struct{}{}
		}
		return true
	})

	if len(liveIPs) == 0 {
		return candidate
	}

	orphaned := make([]dnsmessage.RR, 0, len(candidate.Answer))
	for _, ans := range candidate.Answer {
		ip, ok := dnsAnswerIP(ans)
		if !ok || ip.IsUnspecified() {
			continue
		}
		if _, ok := liveIPs[ip]; ok {
			continue
		}
		orphaned = append(orphaned, ans)
	}

	if len(orphaned) == 0 {
		return nil
	}
	return &DnsCache{
		DomainBitmap:     candidate.DomainBitmap,
		Answer:           orphaned,
		Deadline:         candidate.Deadline,
		OriginalDeadline: candidate.OriginalDeadline,
	}
}

func (c *DnsController) onBaseKeySideEffectsEvicted(baseKey string, candidate *DnsCache) {
	if cache := c.orphanedDnsSideEffects(baseKey, candidate); cache != nil {
		c.onDnsCacheEvicted(cache)
	}
}

func (c *DnsController) RemoveDnsRespCache(cacheKey string) {
	c.requireStore()
	c.cacheProjectionMu.Lock()
	defer c.cacheProjectionMu.Unlock()
	if removed, ok := c.loadAndDeleteDnsCache(cacheKey); ok {
		if cache, ok := removed.(*DnsCache); ok {
			baseKey := dnsCacheBaseKey(cacheKey)
			c.forgetDnsKnowledge(cacheKey, cache)
			c.invokeCacheDeleteCallback(cacheKey, cache)
			c.onBaseKeySideEffectsEvicted(baseKey, cache)
		}
	}
}

func (c *DnsController) RemoveDnsRespCacheFamily(baseKey string) {
	c.requireStore()
	if baseKey == "" {
		return
	}
	c.cacheProjectionMu.Lock()
	defer c.cacheProjectionMu.Unlock()
	var removedCaches []*DnsCache
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
			removedCaches = append(removedCaches, cache)
		}
		return true
	})
	c.syncDnsKnowledge(baseKey)
	c.onBaseKeySideEffectsEvicted(baseKey, aggregateDNSRemovalCandidate(removedCaches))
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

// startBpfUpdateWorker lazily starts the BPF update worker goroutine.
// This is called on-demand when the first BPF update is needed.
func (c *DnsController) startBpfUpdateWorker() {
	c.requireStore()
	c.bpfUpdateOnce.Do(func() {
		c.bpfUpdateStopMu.Lock()
		if c.bpfUpdateClosed.Load() {
			c.bpfUpdateStopMu.Unlock()
			return
		}
		const bpfUpdateQueueSize = 1024
		c.bpfUpdateCh = make(chan *bpfUpdateTask, bpfUpdateQueueSize)
		c.bpfRetryMu.Lock()
		c.bpfRetryWake = make(chan struct{}, 1)
		c.bpfRetryPending = make(map[bpfProjectionRetryKey]*bpfUpdateTask)
		c.bpfRetryMu.Unlock()
		c.bpfUpdateStop = make(chan struct{})
		c.bpfUpdateWg.Add(1)
		c.bpfUpdateStopMu.Unlock()
		go c.bpfUpdateWorker()
	})
}

// processBpfUpdateTask executes a single BPF map update task.
// Returns true if the task was processed, false if it was nil/empty.
func (c *DnsController) processBpfUpdateTask(task *bpfUpdateTask, draining bool) bool {
	processed, _ := c.processBpfUpdateTaskInternal(task, draining, !draining)
	return processed
}

func (c *DnsController) processBpfUpdateTaskInternal(task *bpfUpdateTask, draining, scheduleRetry bool) (processed, failed bool) {
	if task == nil || task.cache == nil {
		return false, false
	}
	if c.bpfUpdateClosed.Load() {
		return true, false
	}
	c.runtimeMu.RLock()
	defer c.runtimeMu.RUnlock()
	c.cacheProjectionMu.RLock()
	defer c.cacheProjectionMu.RUnlock()
	if c.bpfUpdateClosed.Load() {
		return true, false
	}
	rt := c.runtime()
	if !c.bpfUpdateTaskCurrent(task, rt) {
		return true, false
	}
	if err := rt.cacheAccessCallback(task.cache); err != nil {
		if c.log != nil {
			suffix := ""
			if draining {
				suffix = " (during shutdown)"
			}
			c.log.WithError(err).Warnf("async BPF map update failed%s", suffix)
		}
		if scheduleRetry {
			c.scheduleBpfProjectionRetry(task)
		}
		failed = true
	} else {
		task.cache.MarkBpfUpdated(time.Now())
	}
	return true, failed
}

func (c *DnsController) bpfUpdateTaskCurrent(task *bpfUpdateTask, rt *dnsControllerRuntimeState) bool {
	if task == nil || task.cache == nil || rt == nil || rt.cacheAccessCallback == nil ||
		task.routeProjectionEpoch != rt.routeProjectionEpoch {
		return false
	}
	if task.cache.RouteProjectionEpoch != task.routeProjectionEpoch {
		return false
	}
	cacheKey := task.cache.RouteOwnerKey
	if cacheKey == "" {
		return task.retryAttempt == 0
	}
	value, ok := c.dnsCache.Load(cacheKey)
	return ok && value == task.cache
}

func (c *DnsController) scheduleBpfProjectionRetry(task *bpfUpdateTask) {
	key, ok := task.retryKey()
	if !ok || task.retryAttempt >= bpfProjectionRetryLimit || c.bpfUpdateClosed.Load() {
		return
	}
	retry := *task
	retry.retryAttempt++
	c.bpfRetryMu.Lock()
	if c.bpfUpdateClosed.Load() || c.bpfRetryWake == nil || c.bpfRetryPending == nil {
		c.bpfRetryMu.Unlock()
		return
	}
	if pending := c.bpfRetryPending[key]; pending != nil {
		if retry.retryAttempt < pending.retryAttempt || pending.cache != retry.cache {
			c.bpfRetryPending[key] = &retry
		}
	} else if len(c.bpfRetryPending) < bpfProjectionRetryCapacity {
		c.bpfRetryPending[key] = &retry
	} else {
		// Preserve a bounded retry set. The worker will reconcile current cache
		// ownership without retaining one task per cache entry.
		c.bpfRetryOverflow = true
	}
	wake := c.bpfRetryWake
	c.bpfRetryMu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
		// A wake is already pending. The durable intent remains in the shared
		// map and will be consumed by the worker before it blocks again.
	}
}

func (c *DnsController) takeBpfProjectionRetryIntents() (tasks []*bpfUpdateTask, overflow bool) {
	c.bpfRetryMu.Lock()
	defer c.bpfRetryMu.Unlock()
	overflow = c.bpfRetryOverflow
	c.bpfRetryOverflow = false
	if len(c.bpfRetryPending) == 0 {
		return nil, overflow
	}
	tasks = make([]*bpfUpdateTask, 0, len(c.bpfRetryPending))
	for _, task := range c.bpfRetryPending {
		tasks = append(tasks, task)
	}
	clear(c.bpfRetryPending)
	return tasks, overflow
}

// reconcileCurrentBpfProjections recovers work coalesced by the bounded retry
// queue. It walks the authoritative cache in place and never builds an
// O(cache-size) task slice.
func (c *DnsController) reconcileCurrentBpfProjections() (failed bool) {
	if c == nil || c.bpfUpdateClosed.Load() {
		return false
	}
	rt := c.runtime()
	if rt == nil || rt.cacheAccessCallback == nil {
		return false
	}
	c.dnsCache.Range(func(key, value any) bool {
		if c.bpfUpdateClosed.Load() {
			return false
		}
		if c.runtime() != rt {
			failed = true
			return false
		}
		cacheKey, keyOK := key.(string)
		cache, cacheOK := value.(*DnsCache)
		if !keyOK || !cacheOK || cache == nil || cache.RouteOwnerKey != cacheKey ||
			cache.RouteProjectionEpoch != rt.routeProjectionEpoch {
			return true
		}
		currentHash := cache.ComputeBpfDataHash()
		if currentHash == 0 || currentHash == cache.lastBpfDataHash.Load() {
			return true
		}
		_, taskFailed := c.processBpfUpdateTaskInternal(&bpfUpdateTask{
			cache:                cache,
			routeProjectionEpoch: rt.routeProjectionEpoch,
		}, false, false)
		failed = failed || taskFailed
		if c.runtime() != rt {
			failed = true
			return false
		}
		return true
	})
	if !c.bpfUpdateClosed.Load() && c.runtime() != rt {
		failed = true
	}
	return failed
}

// bpfUpdateWorker processes BPF map updates asynchronously.
// It runs until bpfUpdateStop is closed, then drains remaining tasks and exits.
// Note: bpfUpdateCh is never closed; the worker exits when bpfUpdateStop is signaled.
//
// IMPORTANT: This goroutine intentionally does NOT watch baseContext().Done().
// When the DnsController is reused across reload generations (ReuseDNSControllerFrom),
// UpdateRuntime swaps the lifecycleCtx, but goroutines blocked in select still hold
// a reference to the OLD context's Done channel. If the old generation's context is
// canceled during retirement, the worker would exit prematurely, permanently killing
// BPF domain_routing_map updates (sync.Once prevents restart). The worker exits only
// via bpfUpdateStop, which is closed during DnsController.Close().
func (c *DnsController) bpfUpdateWorker() {
	defer c.bpfUpdateWg.Done()
	retries := newBpfProjectionRetryScheduler()
	retryTimer := time.NewTimer(time.Hour)
	if !retryTimer.Stop() {
		select {
		case <-retryTimer.C:
		default:
		}
	}
	defer retryTimer.Stop()
	var retryTimerCh <-chan time.Time
	var (
		reconcilePending bool
		reconcileAttempt uint8
		reconcileDue     time.Time
	)
	scheduleReconcile := func(now time.Time) {
		if reconcilePending {
			return
		}
		reconcilePending = true
		reconcileAttempt = 1
		reconcileDue = now.Add(bpfProjectionRetryDelay(reconcileAttempt))
	}
	resetRetryTimer := func() {
		due, ok := retries.nextDue()
		if reconcilePending && (!ok || reconcileDue.Before(due)) {
			due, ok = reconcileDue, true
		}
		if !ok {
			if retryTimerCh != nil && !retryTimer.Stop() {
				select {
				case <-retryTimer.C:
				default:
				}
			}
			retryTimerCh = nil
			return
		}
		if retryTimerCh != nil && !retryTimer.Stop() {
			select {
			case <-retryTimer.C:
			default:
			}
		}
		delay := time.Until(due)
		if delay < 0 {
			delay = 0
		}
		retryTimer.Reset(delay)
		retryTimerCh = retryTimer.C
	}

	for {
		select {
		case task := <-c.bpfUpdateCh:
			c.processBpfUpdateTask(task, false)
			c.drainBpfUpdateTasks(false)
		case <-c.bpfRetryWake:
			tasks, overflow := c.takeBpfProjectionRetryIntents()
			if overflow {
				scheduleReconcile(time.Now())
			}
			for _, task := range tasks {
				if !retries.add(task) {
					scheduleReconcile(time.Now())
				}
			}
			resetRetryTimer()
		case <-retryTimerCh:
			retryTimerCh = nil
			now := time.Now()
			for _, task := range retries.popDue(now) {
				c.processBpfUpdateTask(task, false)
			}
			if reconcilePending && !reconcileDue.After(now) {
				failed := c.reconcileCurrentBpfProjections()
				if failed && reconcileAttempt < bpfProjectionRetryLimit {
					reconcileAttempt++
					reconcileDue = now.Add(bpfProjectionRetryDelay(reconcileAttempt))
				} else {
					if failed && c.log != nil {
						c.log.Warn("BPF projection reconciliation exhausted its retry budget")
					}
					reconcilePending = false
					reconcileAttempt = 0
					reconcileDue = time.Time{}
				}
			}
			resetRetryTimer()
		case <-c.bpfUpdateStop:
			c.drainBpfUpdateTasks(true)
			return
		}
	}
}

const bpfUpdateDrainBatch = 64

// drainBpfUpdateTasks processes a bounded primary-task batch. Returning to the
// worker select between batches prevents a sustained cache-write stream from
// starving delayed retries or shutdown.
func (c *DnsController) drainBpfUpdateTasks(draining bool) {
	for range bpfUpdateDrainBatch {
		select {
		case task := <-c.bpfUpdateCh:
			c.processBpfUpdateTask(task, draining)
		default:
			return
		}
	}
}

// triggerBpfUpdateIfNeeded enqueues a BPF update task if needed. It never
// blocks cache readers; a full primary queue is handed to the bounded retry
// scheduler when the cache still belongs to the current runtime.
func (c *DnsController) triggerBpfUpdateIfNeeded(cache *DnsCache, now time.Time) {
	c.triggerBpfUpdateIfNeededForRuntime(cache, now, c.runtime())
}

func (c *DnsController) triggerBpfUpdateIfNeededForRuntime(cache *DnsCache, now time.Time, rt *dnsControllerRuntimeState) {
	c.requireStore()
	if cache == nil || rt == nil || rt.cacheAccessCallback == nil || c.runtime() != rt {
		return
	}
	if !cache.NeedsBpfUpdate(now) {
		return
	}

	if c.bpfUpdateClosed.Load() {
		return
	}

	c.startBpfUpdateWorker()

	if c.bpfUpdateClosed.Load() || c.runtime() != rt {
		return
	}

	task := &bpfUpdateTask{
		cache:                cache,
		routeProjectionEpoch: rt.routeProjectionEpoch,
	}
	if !c.sendBpfUpdateTask(task) {
		c.scheduleBpfProjectionRetry(task)
		if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.Debug("BPF update queue full or closed, skipping update")
		}
	}
}

func (c *DnsController) sendBpfUpdateTask(task *bpfUpdateTask) (sent bool) {
	// Check if controller is shutting down before attempting send.
	// This avoids the data race of reading bpfUpdateStop while it's being initialized.
	if c.bpfUpdateClosed.Load() {
		return false
	}
	c.bpfUpdateStopMu.Lock()
	bpfUpdateCh := c.bpfUpdateCh
	c.bpfUpdateStopMu.Unlock()
	if bpfUpdateCh == nil {
		return false
	}

	// Try to send without blocking. The caller may move a dropped task to the
	// bounded retry scheduler, which revalidates cache ownership before retry.
	select {
	case bpfUpdateCh <- task:
		return true
	default:
		// Queue is full; the caller decides whether this cache is eligible for
		// a bounded delayed retry.
		return false
	}
}

func (c *DnsController) onDnsCacheEvicted(cache *DnsCache) {
	rt := c.runtime()
	if cache == nil || rt == nil || rt.cacheRemoveCallback == nil {
		return
	}

	if c.janitorStop != nil {
		select {
		case <-c.janitorStop:
			c.invokeCacheRemoveCallback(cache)
			return
		default:
		}
	}

	c.evictorChMu.RLock()
	evictorQ := c.evictorQ
	c.evictorChMu.RUnlock()
	if evictorQ == nil {
		c.invokeCacheRemoveCallback(cache)
		return
	}

	select {
	case evictorQ <- cache:
	default:
		// Keep datapath non-blocking under eviction bursts without creating an
		// unbounded number of short-lived goroutines. A single background worker
		// drains this spill buffer with the same callback semantics.
		c.enqueueEvictorSpill(cache)
	}
}

func (c *DnsController) enqueueEvictorSpill(cache *DnsCache) {
	if cache == nil {
		return
	}
	// If the evictor worker was never initialized, fall back to direct removal.
	// This preserves behavior for manually constructed test controllers.
	c.evictorChMu.RLock()
	evictorWake := c.evictorWake
	c.evictorChMu.RUnlock()
	if evictorWake == nil {
		c.invokeCacheRemoveCallback(cache)
		return
	}

	const maxEvictorSpillEntries = 4096
	c.evictorMu.Lock()
	if len(c.evictorBuf) >= maxEvictorSpillEntries {
		c.evictorMu.Unlock()
		// Sustained callback overload must not create an unbounded retention
		// queue. Preserve cleanup correctness with synchronous backpressure.
		c.invokeCacheRemoveCallback(cache)
		return
	}
	c.evictorBuf = append(c.evictorBuf, cache)
	c.evictorMu.Unlock()

	select {
	case evictorWake <- struct{}{}:
	default:
	}
}

func (c *DnsController) takeEvictorSpillBatch() []*DnsCache {
	c.evictorMu.Lock()
	defer c.evictorMu.Unlock()
	if len(c.evictorBuf) == 0 {
		return nil
	}
	batch := c.evictorBuf
	c.evictorBuf = nil
	return batch
}

func (c *DnsController) drainEvictorSpill() {
	for {
		batch := c.takeEvictorSpillBatch()
		if len(batch) == 0 {
			return
		}
		for _, cache := range batch {
			c.invokeCacheRemoveCallback(cache)
		}
	}
}

func (c *DnsController) invokeCacheRemoveCallback(cache *DnsCache) {
	rt := c.runtime()
	if cache == nil || rt == nil || rt.cacheRemoveCallback == nil {
		return
	}
	if err := rt.cacheRemoveCallback(cache); err != nil {
		if c.log != nil {
			c.log.Warnf("failed to remove dns cache side effects: %v", err)
		}
	}
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
	baseKey := dnsCacheBaseKey(cacheKey)
	c.forgetDnsKnowledge(cacheKey, cache)
	c.invokeCacheDeleteCallback(cacheKey, cache)
	c.onBaseKeySideEffectsEvicted(baseKey, cache)
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

// startCacheEvictor runs a goroutine that processes asynchronous cache eviction
// callbacks (CacheRemoveCallback / BatchRemoveDomainRouting).
//
// IMPORTANT: This goroutine intentionally does NOT watch baseContext().Done().
// See bpfUpdateWorker comment for the rationale — the same stale-context problem
// applies here when the DnsController is reused across reload generations.
func (c *DnsController) startCacheEvictor() {
	c.requireStore()
	go func() {
		defer close(c.evictorDone)
		if c.evictorQ == nil {
			return
		}
		if c.evictorWake == nil {
			c.evictorWake = make(chan struct{}, 1)
		}

		for {
			select {
			case cache := <-c.evictorQ:
				c.invokeCacheRemoveCallback(cache)
				c.drainEvictorSpill()
			case <-c.evictorWake:
				c.drainEvictorSpill()
			case <-c.janitorStop:
				for {
					select {
					case cache := <-c.evictorQ:
						c.invokeCacheRemoveCallback(cache)
					default:
						c.drainEvictorSpill()
						return
					}
				}
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

// staleDnsSideEffects builds a minimal cache entry containing only IP answers
// that exist in prev but not in next. This lets us remove stale domain-routing
// side effects after replacing a cache entry without deleting IPs that are
// still present in the refreshed cache.
func staleDnsSideEffects(prev, next *DnsCache) *DnsCache {
	if prev == nil {
		return nil
	}
	if next == nil {
		return prev
	}

	staleCount := 0
	firstStaleIdx := -1
	lastStaleIdx := -1
	contiguous := true

	for i, ans := range prev.Answer {
		ip, ok := dnsAnswerIP(ans)
		if !ok || ip.IsUnspecified() || next.IncludeIp(ip) {
			continue
		}
		if firstStaleIdx == -1 {
			firstStaleIdx = i
		} else if i != lastStaleIdx+1 {
			contiguous = false
		}
		lastStaleIdx = i
		staleCount++
	}

	if staleCount == 0 {
		return nil
	}
	if contiguous {
		return &DnsCache{Answer: prev.Answer[firstStaleIdx : lastStaleIdx+1 : lastStaleIdx+1]}
	}

	staleAnswers := make([]dnsmessage.RR, 0, staleCount)
	for _, ans := range prev.Answer {
		ip, ok := dnsAnswerIP(ans)
		if !ok || ip.IsUnspecified() || next.IncludeIp(ip) {
			continue
		}
		staleAnswers = append(staleAnswers, ans)
	}
	return &DnsCache{Answer: staleAnswers}
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

		var staleSideEffects *DnsCache
		if oldValue, ok := c.dnsCache.Load(cacheKey); ok {
			if oldCache, ok := oldValue.(*DnsCache); ok {
				staleSideEffects = staleDnsSideEffects(oldCache, newCache)
			}
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
		if staleSideEffects != nil {
			staleSideEffects.RouteOwnerKey = cacheKey
			c.onBaseKeySideEffectsEvicted(baseKey, staleSideEffects)
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

type udpRequest struct {
	realSrc        netip.AddrPort
	realDst        netip.AddrPort
	src            netip.AddrPort
	lConn          *net.UDPConn
	routingResult  *bpfRoutingResult
	uploadRecord   func(int64)
	downloadRecord func(int64)
}

func (r *udpRequest) downloadRecorder() func(int64) {
	if r == nil {
		return RecordDownloadTraffic
	}
	return normalizeTrafficRecord(r.downloadRecord)
}

type dialArgument struct {
	l4proto      consts.L4ProtoStr
	ipversion    consts.IpVersionStr
	bestDialer   *dialer.Dialer
	bestOutbound *outbound.DialerGroup
	bestTarget   netip.AddrPort
	mark         uint32
	mptcp        bool
}

type dnsForwarderKey struct {
	upstream     string
	l4proto      consts.L4ProtoStr
	ipversion    consts.IpVersionStr
	dialerName   string
	outboundName string
	bestTarget   netip.AddrPort
	mark         uint32
	mptcp        bool
}

type cachedDnsForwarder struct {
	forwarder    DnsForwarder
	lastUsedNano atomic.Int64
	inFlight     atomic.Int32
	retired      atomic.Bool
	closeOnce    sync.Once
	// consecutiveErrors counts back-to-back failures.  A single success
	// resets the counter.  When it reaches maxConsecutiveForwardErrors the
	// forwarder is retired even for stream-based upstream schemes.
	consecutiveErrors atomic.Int32
}

const maxConsecutiveForwardErrors = 3

func newCachedDnsForwarder(forwarder DnsForwarder, now time.Time) *cachedDnsForwarder {
	entry := &cachedDnsForwarder{forwarder: forwarder}
	entry.touch(now)
	return entry
}

func (c *cachedDnsForwarder) touch(now time.Time) {
	c.lastUsedNano.Store(now.UnixNano())
}

func (c *cachedDnsForwarder) beginUse() bool {
	if c == nil || c.retired.Load() {
		return false
	}
	c.inFlight.Add(1)
	c.touch(time.Now())
	if !c.retired.Load() {
		return true
	}
	if c.inFlight.Add(-1) == 0 {
		_ = c.closeNow()
	}
	return false
}

func (c *cachedDnsForwarder) endUse() {
	if c == nil {
		return
	}
	c.touch(time.Now())
	if c.inFlight.Add(-1) == 0 && c.retired.Load() {
		_ = c.closeNow()
	}
}

func (c *cachedDnsForwarder) closeNow() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		if c.forwarder != nil {
			err = c.forwarder.Close()
		}
	})
	return err
}

func (c *cachedDnsForwarder) retire() error {
	if c == nil {
		return nil
	}
	c.retired.Store(true)
	if c.inFlight.Load() == 0 {
		return c.closeNow()
	}
	return nil
}

var dnsForwarderFactory = newDnsForwarder

func (c *DnsController) extractDnsForwarder(value any) DnsForwarder {
	switch v := value.(type) {
	case *cachedDnsForwarder:
		return v.forwarder
	case DnsForwarder:
		return v
	default:
		return nil
	}
}

func (c *DnsController) evictIdleDnsForwarders(now time.Time) {
	if c.dnsForwarderIdleTTL <= 0 {
		return
	}

	nowNano := now.UnixNano()
	idleNano := c.dnsForwarderIdleTTL.Nanoseconds()
	var toClose []DnsForwarder

	c.dnsForwarderCache.Range(func(key, value any) bool {
		k, ok := key.(dnsForwarderKey)
		if !ok {
			c.dnsForwarderCache.Delete(key)
			return true
		}

		entry, ok := value.(*cachedDnsForwarder)
		if !ok {
			if forwarder := c.extractDnsForwarder(value); forwarder != nil {
				if c.dnsForwarderCache.CompareAndDelete(k, value) {
					toClose = append(toClose, forwarder)
				}
			} else {
				c.dnsForwarderCache.Delete(k)
			}
			return true
		}

		if entry.inFlight.Load() > 0 {
			return true
		}
		lastUsedNano := entry.lastUsedNano.Load()
		if lastUsedNano == 0 || nowNano-lastUsedNano <= idleNano {
			return true
		}

		if c.dnsForwarderCache.CompareAndDelete(k, entry) {
			toClose = append(toClose, entry.forwarder)
		}
		return true
	})

	for _, forwarder := range toClose {
		if forwarder == nil {
			continue
		}
		if err := forwarder.Close(); err != nil && c.log != nil {
			c.log.WithError(err).Debugln("failed to close idle dns forwarder")
		}
	}
}

func (c *DnsController) reportDnsForwardFailure(dialArg *dialArgument, err error) {
	if dialArg == nil || err == nil {
		return
	}
	// Caller-driven cancellation should not mark a dialer as unavailable.
	if commonerrors.IsCanceledOrClosed(err) || errors.Is(err, ErrDNSUDPConnPoolExhausted) {
		return
	}
	if lifecycle, ok := newDnsUdpLifecycleContext(dialArg, UdpLifecycleProfile{}); ok {
		lifecycle.reportUnavailable(err)
	}
	if rt := c.runtime(); rt != nil && rt.timeoutExceedCallback != nil {
		rt.timeoutExceedCallback(dialArg, err)
	}
	notifyProxyDialerHealthCheck(dialArg.bestDialer, dialArg.l4proto, err)
}

func (c *DnsController) logDnsForwardFailure(upstream *dns.Upstream, dialArg *dialArgument, err error) {
	if c == nil || c.log == nil || err == nil {
		return
	}
	if commonerrors.IsCanceledOrClosed(err) || errors.Is(err, ErrDNSUDPConnPoolExhausted) {
		return
	}
	fields := logrus.Fields{}
	if upstream != nil {
		fields["upstream"] = upstream.String()
	}
	if dialArg != nil {
		fields["network"] = string(dialArg.l4proto) + "+" + string(dialArg.ipversion)
		if dialArg.bestTarget.IsValid() {
			fields["target"] = dialArg.bestTarget.String()
		}
		if dialArg.bestOutbound != nil {
			fields["outbound"] = dialArg.bestOutbound.Name
			fields["policy"] = dialArg.bestOutbound.GetSelectionPolicy()
		}
		if dialArg.bestDialer != nil && dialArg.bestDialer.Property() != nil {
			fields["dialer"] = dialArg.bestDialer.Property().Name
		}
	}
	c.log.WithError(err).WithFields(fields).Warn("DNS forward to upstream failed")
}

func (c *DnsController) shouldRetireCachedDnsForwarder(upstream *dns.Upstream, dialArg *dialArgument, entry *cachedDnsForwarder, err error) bool {
	if dialArg == nil || err == nil {
		return false
	}
	if commonerrors.IsCanceledOrClosed(err) || errors.Is(err, ErrDNSUDPConnPoolExhausted) {
		return false
	}
	// UDP forwarders keep pooled sockets whose state can be poisoned by a single
	// timeout or stale-response burst. Flush the whole cached forwarder so the
	// next query starts from a clean socket pool.
	if dialArg.l4proto == consts.L4ProtoStr_UDP {
		return true
	}
	if upstream == nil || !isProxyBackedDialer(dialArg.bestDialer) {
		return false
	}
	// Retire any forwarder that has failed too many times in a row, even
	// stream-style ones, to prevent a permanently broken instance from
	// accumulating retries without relief.
	if entry != nil && entry.consecutiveErrors.Load() >= maxConsecutiveForwardErrors {
		return true
	}
	switch upstream.Scheme {
	case dns.UpstreamScheme_TCP,
		dns.UpstreamScheme_TCP_UDP,
		dns.UpstreamScheme_TLS,
		dns.UpstreamScheme_HTTPS,
		dns.UpstreamScheme_H3,
		dns.UpstreamScheme_QUIC:
		// Stream-style forwarders already rebuild their own transport state on
		// request failures. Retiring the whole cached forwarder for an ordinary
		// timeout only forces extra cold starts and can amplify control-plane
		// DNS failures into repeated proxy-host re-resolution loops.
		return false
	default:
		return false
	}
}

func (c *DnsController) retireCachedDnsForwarder(key dnsForwarderKey, entry *cachedDnsForwarder) {
	if entry == nil {
		return
	}
	if !c.dnsForwarderCache.CompareAndDelete(key, entry) {
		return
	}
	if err := entry.retire(); err != nil && c.log != nil {
		c.log.WithError(err).Debugln("failed to close retired dns forwarder")
	}
}

func newDnsForwarderKey(upstream *dns.Upstream, dialArg *dialArgument) dnsForwarderKey {
	key := dnsForwarderKey{}
	if upstream != nil {
		key.upstream = upstream.String()
	}
	if dialArg == nil {
		return key
	}
	key.l4proto = dialArg.l4proto
	key.ipversion = dialArg.ipversion
	if dialArg.bestDialer != nil && dialArg.bestDialer.Property() != nil {
		key.dialerName = dialArg.bestDialer.Property().Name
	}
	if dialArg.bestOutbound != nil {
		key.outboundName = dialArg.bestOutbound.Name
	}
	key.bestTarget = dialArg.bestTarget
	key.mark = dialArg.mark
	key.mptcp = dialArg.mptcp
	return key
}

func (c *DnsController) getOrCreateDnsForwarder(upstream *dns.Upstream, dialArg *dialArgument) (*cachedDnsForwarder, error) {
	key := newDnsForwarderKey(upstream, dialArg)
	now := time.Now()

	for range 3 {
		if cached, ok := c.dnsForwarderCache.Load(key); ok {
			switch entry := cached.(type) {
			case *cachedDnsForwarder:
				entry.touch(now)
				return entry, nil
			case DnsForwarder:
				wrapped := newCachedDnsForwarder(entry, now)
				if c.dnsForwarderCache.CompareAndSwap(key, cached, wrapped) {
					return wrapped, nil
				}
				continue
			default:
				c.dnsForwarderCache.CompareAndDelete(key, cached)
				continue
			}
		}
		break
	}

	createdForwarder, createErr := dnsForwarderFactory(upstream, *dialArg, c.log)
	if createErr != nil {
		return nil, createErr
	}
	created := newCachedDnsForwarder(createdForwarder, now)

	actual, loaded := c.dnsForwarderCache.LoadOrStore(key, created)
	if loaded {
		// Another goroutine won the race; close the redundant instance.
		_ = createdForwarder.Close()
		if entry, ok := actual.(*cachedDnsForwarder); ok {
			entry.touch(now)
			return entry, nil
		}
		if old, ok := actual.(DnsForwarder); ok {
			wrapped := newCachedDnsForwarder(old, now)
			if c.dnsForwarderCache.CompareAndSwap(key, actual, wrapped) {
				return wrapped, nil
			}
			if latest, ok := c.dnsForwarderCache.Load(key); ok {
				if latestEntry, ok := latest.(*cachedDnsForwarder); ok {
					latestEntry.touch(now)
					return latestEntry, nil
				}
			}
		}
		return nil, fmt.Errorf("unexpected cached dns forwarder type: %T", actual)
	}
	return created, nil
}

func (c *DnsController) forwardWithDialArg(ctx context.Context, upstream *dns.Upstream, dialArg *dialArgument, data []byte) (*dnsmessage.Msg, error) {
	c.requireStore()
	key := newDnsForwarderKey(upstream, dialArg)
	for range 2 {
		entry, err := c.getOrCreateDnsForwarder(upstream, dialArg)
		if err != nil {
			return nil, err
		}
		if !entry.beginUse() {
			continue
		}

		respMsg, err := entry.forwarder.ForwardDNS(ctx, data)
		entry.endUse()
		if err != nil {
			// ErrDNSTruncated is a valid DNS protocol signal (response too
			// large for UDP), not a transport failure.  Propagate the error
			// so the caller can react (e.g. tcp+udp fallback, or TC=1 to
			// client), but do NOT retire the forwarder, penalise the dialer
			// or emit a misleading failure log.
			if !errors.Is(err, ErrDNSTruncated) {
				entry.consecutiveErrors.Add(1)
				if c.shouldRetireCachedDnsForwarder(upstream, dialArg, entry, err) {
					c.retireCachedDnsForwarder(key, entry)
				}
				c.logDnsForwardFailure(upstream, dialArg, err)
				c.reportDnsForwardFailure(dialArg, err)
			}
			return nil, err
		}
		entry.consecutiveErrors.Store(0)
		return respMsg, nil
	}
	return nil, fmt.Errorf("dns forwarder retired before request could start")
}

func (c *DnsController) forwardWithFallback(
	ctx context.Context, // Request-scoped context from dialSend/handler
	req *udpRequest,
	upstream *dns.Upstream,
	primaryDialArg *dialArgument,
	data []byte,
) (respMsg *dnsmessage.Msg, usedDialArg *dialArgument, err error) {
	// Per-attempt timeout derived from request context:
	// preserves cancel propagation while avoiding timeout reuse between UDP/TCP tries.
	primaryCtx, primaryCancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer primaryCancel()

	respMsg, err = c.forwardWithDialArg(primaryCtx, upstream, primaryDialArg, data)
	if err == nil {
		return respMsg, primaryDialArg, nil
	}

	primaryErr := err

	// For tcp+udp upstream, perform immediate same-request fallback:
	// prefer UDP, fallback to TCP on failure.
	if upstream == nil || upstream.Scheme != dns.UpstreamScheme_TCP_UDP || primaryDialArg.l4proto != consts.L4ProtoStr_UDP {
		return nil, primaryDialArg, primaryErr
	}

	fallbackUpstream := *upstream
	fallbackUpstream.Scheme = dns.UpstreamScheme_TCP

	fallbackDialArg, chooseErr := c.runtime().chooseBestDnsDialer(ctx, dnsRequestSnapshotFromUDPRequest(req), &fallbackUpstream)
	if chooseErr != nil {
		return nil, primaryDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback select failed: %v", primaryErr, chooseErr)
	}
	if fallbackDialArg == nil || fallbackDialArg.l4proto != consts.L4ProtoStr_TCP {
		return nil, primaryDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback select returned invalid network", primaryErr)
	}

	if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"upstream": upstream.String(),
			"from":     primaryDialArg.l4proto,
			"to":       fallbackDialArg.l4proto,
		}).Debugln("DNS fallback to TCP after UDP failure")
	}

	fallbackCtx, fallbackCancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer fallbackCancel()

	respMsg, err = c.forwardWithDialArg(fallbackCtx, upstream, fallbackDialArg, data)
	if err != nil {
		return nil, fallbackDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback failed: %v", primaryErr, err)
	}

	return respMsg, fallbackDialArg, nil
}

func (c *DnsController) Handle_(ctx context.Context, dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	return c.HandleWithResponseWriter_(ctx, dnsMessage, req, nil)
}

func (c *DnsController) HandleWithResponseWriter_(ctx context.Context, dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	c.requireStore()
	var upstreamIndex consts.DnsRequestOutboundIndex
	var upstream *dns.Upstream

	if cap(c.concurrencyLimiter) > 0 {
		select {
		case c.concurrencyLimiter <- struct{}{}:
			defer func() { <-c.concurrencyLimiter }()
		default:
			if responseWriter != nil || (req != nil && req.lConn != nil) {
				if sendErr := c.sendRefusedWithResponseWriter_(dnsMessage, req, responseWriter); sendErr != nil {
					return errors.Join(ErrDNSQueryConcurrencyLimitExceeded, sendErr)
				}
			}
			return ErrDNSQueryConcurrencyLimitExceeded
		}
	}

	// Prepare qname, qtype for cache lookup
	var qname string
	var qtype uint16
	var baseCacheKey string
	var responseCacheKey string
	if len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
		baseCacheKey = c.cacheKey(qname, qtype)
	}

	// Route request first, then check cache.
	// This ensures Reject rules are always applied, even if cache exists.
	// Cache lookup overhead (~1µs) is negligible compared to network latency (~ms).
	if baseCacheKey != "" && !dnsMessage.Response {
		// Route request to get upstream
		rt := c.runtime()
		if rt == nil || rt.routing == nil {
			return fmt.Errorf("dns routing is not configured")
		}
		var err error
		upstreamIndex, upstream, err = rt.routing.RequestSelect(ctx, qname, qtype)
		if err != nil {
			return err
		}
		responseCacheKey = c.responseCacheKey(baseCacheKey, req, upstreamIndex, upstream)

		if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
			c.RemoveDnsRespCacheFamily(baseCacheKey)
			return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
		}

		// Check cache after routing (non-reject case)
		if resp, needRefresh := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
			// Cache hit - return immediately without singleflight
			// OPTIMISTIC CACHE: resp may be stale, trigger background refresh if needed
			if needRefresh {
				// Background refresh - don't block the current request
				go c.backgroundRefresh(responseCacheKey, dnsMessage, req, upstreamIndex, upstream)
			}

			if err = c.writeCachedResponse(resp, dnsMessage.Id, req, responseWriter); err != nil {
				return err
			}
			// Log cache hit with dest addr for CI compatibility.
			// Format includes "-> dest:port" so CI grep can verify routing.
			if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Question) > 0 && req != nil {
				q := dnsMessage.Question[0]
				c.log.WithFields(logrus.Fields{
					"network": "udp(dns)",
					"_qname":  strings.ToLower(q.Name),
					"qtype":   QtypeToString(q.Qtype),
				}).Debugf("%v <-> %v (cache)",
					RefineSourceToShow(req.realSrc, req.realDst.Addr()),
					RefineAddrPortToShow(req.realDst),
				)
			}
			return nil
		}

		// Cache miss - use singleflight to coalesce concurrent requests
		// This prevents thundering herd on upstream DNS servers
		res, err, _ := c.sf.Do(responseCacheKey, func() (any, error) {
			// Shared singleflight resolution should ignore individual client
			// cancellation, but it must still stop promptly when the DNS
			// controller is closing during reload/shutdown.
			resCtx, resCancel := c.newWorkContext(5 * time.Second)
			defer resCancel()

			// This goroutine performs the actual resolution.
			// It returns the DNS response message, or an error.
			return c.resolveForSingleflight(resCtx, dnsMessage, req, upstreamIndex, upstream, responseCacheKey)
		})

		if err != nil {
			return err
		}

		// res is the *dnsmessage.Msg
		respMsg := res.(*dnsmessage.Msg)

		// Optimization: Try to get pre-packed response from cache after singleflight.
		// This avoids another Pack() call which is common in high-concurrency scenarios.
		if responseCacheKey != "" {
			if resp, _ := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
				if err = c.writeCachedResponse(resp, dnsMessage.Id, req, responseWriter); err != nil {
					return err
				}
				return nil
			}
		}

		// Write response.
		// For packet-send path, avoid deep-copying DNS message and just patch ID in packed bytes.
		if responseWriter != nil {
			respMsgUnique := respMsg.Copy()
			respMsgUnique.Id = dnsMessage.Id
			return responseWriter.WriteMsg(respMsgUnique)
		}

		// If no responseWriter (internal UDP path), pack and send directly.
		data, err := respMsg.Pack()
		if err != nil {
			return fmt.Errorf("pack DNS packet: %w", err)
		}
		if len(data) >= 2 {
			binary.BigEndian.PutUint16(data[:2], dnsMessage.Id)
		}
		if req == nil || req.lConn == nil {
			return fmt.Errorf("dns request connection is nil for singleflight response")
		}
		if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
			return err
		}
		return nil
	}

	return c.handleWithResponseWriterInternal(ctx, dnsMessage, req, responseWriter, upstreamIndex, upstream, responseCacheKey, baseCacheKey)
}

func (c *DnsController) resolveForSingleflight(
	ctx context.Context,
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	upstreamIndex consts.DnsRequestOutboundIndex,
	upstream *dns.Upstream,
	responseCacheKey string,
) (*dnsmessage.Msg, error) {
	// Preserve the second cache lookup from the former response-writer path.
	// Another request may have populated the entry after the outer cache miss
	// and before this singleflight leader starts upstream resolution.
	if resp, needRefresh := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
		if needRefresh {
			go c.backgroundRefresh(responseCacheKey, dnsMessage, req, upstreamIndex, upstream)
		}
		respMsg := new(dnsmessage.Msg)
		if err := respMsg.Unpack(resp); err != nil {
			return nil, fmt.Errorf("unpack cached DNS response: %w", err)
		}
		respMsg.Id = dnsMessage.Id
		return respMsg, nil
	}

	data, err := dnsMessage.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS packet: %w", err)
	}
	resolution, err := c.resolveDNSUpstream(ctx, 0, req, data, upstream)
	if err != nil {
		return nil, err
	}

	respMsg := resolution.response
	respMsg.Id = dnsMessage.Id
	respMsg.Compress = true
	if err := c.NormalizeAndCacheDnsResp_(respMsg, responseCacheKey); err != nil {
		if c.log != nil {
			c.log.Warnf("failed to cache DNS response: %v", err)
		}
	}
	return respMsg, nil
}

// handleWithResponseWriterInternal handles DNS requests with response writer.
// When ip_version_prefer is set, it implements RFC 8305 Happy Eyeballs
// Resolution Delay: wait briefly for preferred response type before responding.
//
// Renamed from HandleWithResponseWriter_ to internal to avoid recursion loop with SF.
func (c *DnsController) handleWithResponseWriterInternal(ctx context.Context, dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream, responseCacheKey string, baseCacheKey string) (err error) {
	if c.log.IsLevelEnabled(logrus.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		c.log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.realSrc, req.realDst.Addr()), req.realDst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		return fmt.Errorf("DNS request expected but DNS response received")
	}

	// Get qtype for preference handling (RFC 8305 Happy Eyeballs).
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		qtype = dnsMessage.Question[0].Qtype
	}

	// Fast path: no ip_version_prefer set, bypass all preference logic
	if c.currentQtypePrefer() == 0 {
		return c.handleWithResponseWriter_(ctx, dnsMessage, req, true, responseWriter, upstreamIndex, upstream, responseCacheKey, baseCacheKey)
	}

	// Only A and AAAA responses participate in preference waiting. The wait is
	// applied after upstream resolution so cached/direct non-address responses
	// keep the fast path.
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return c.handleWithResponseWriter_(ctx, dnsMessage, req, true, responseWriter, upstreamIndex, upstream, responseCacheKey, baseCacheKey)
	}

	return c.handleWithResponseWriter_(ctx, dnsMessage, req, true, responseWriter, upstreamIndex, upstream, responseCacheKey, baseCacheKey)
}

func (c *DnsController) handleWithResponseWriter_(
	ctx context.Context,
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
	responseWriter dnsmessage.ResponseWriter,
	upstreamIndex consts.DnsRequestOutboundIndex,
	upstream *dns.Upstream,
	responseCacheKey string,
	baseCacheKey string,
) (err error) {
	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
	}

	// Route request if not already routed.
	if upstream == nil && upstreamIndex == 0 {
		rt := c.runtime()
		if rt == nil || rt.routing == nil {
			return fmt.Errorf("dns routing is not configured")
		}
		upstreamIndex, upstream, err = rt.routing.RequestSelect(ctx, qname, qtype)
		if err != nil {
			return err
		}
	}

	if baseCacheKey == "" {
		baseCacheKey = c.cacheKey(qname, qtype)
	}
	if responseCacheKey == "" {
		responseCacheKey = c.responseCacheKey(baseCacheKey, req, upstreamIndex, upstream)
	}

	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		// Reject with empty answer.
		c.RemoveDnsRespCacheFamily(baseCacheKey)
		if !needResp {
			return nil
		}
		return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
	}

	if resp, needRefresh := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
		// Send cache to client directly.
		// OPTIMISTIC CACHE: Trigger background refresh if stale
		if needRefresh {
			go c.backgroundRefresh(responseCacheKey, dnsMessage, req, upstreamIndex, upstream)
		}

		if needResp {
			if err = c.writeCachedResponse(resp, dnsMessage.Id, req, responseWriter); err != nil {
				return err
			}
		}
		if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Question) > 0 {
			q := dnsMessage.Question[0]
			if req != nil {
				c.log.Debugf("UDP(DNS) %v <-> Cache: %v %v",
					RefineSourceToShow(req.realSrc, req.realDst.Addr()), strings.ToLower(q.Name), QtypeToString(q.Qtype),
				)
			} else {
				c.log.Debugf("UDP(DNS) Cache: %v %v", strings.ToLower(q.Name), QtypeToString(q.Qtype))
			}
		}
		return nil
	}

	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		upstreamName := upstreamIndex.String()
		if upstream != nil {
			upstreamName = upstream.String()
		}
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
			"upstream": upstreamName,
		}).Traceln("Request to DNS upstream")
	}

	// Re-pack DNS packet.
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	return c.dialSend(ctx, req, data, dnsMessage.Id, upstream, needResp, responseWriter, responseCacheKey)
}

// writeCachedResponse sends a cached DNS response to the client.
// OPTIMIZED: Uses pre-packed response with ID patching to avoid Pack() overhead.
// For responseWriter path, uses Unpack/WriteMsg (slower but handles ID correctly).
// For UDP path, patches the ID directly using buffer pool to avoid allocations.
func (c *DnsController) writeCachedResponse(resp []byte, reqId uint16, req *udpRequest, responseWriter dnsmessage.ResponseWriter) error {
	// Optimization: Patch ID directly in the packed buffer if possible.
	// For UDP, we can use Write() directly. For TCP, we might need WriteMsg or manual length.
	// However, most responseWriters here are either UDP or wrappers that handle message framing.

	if responseWriter != nil {
		var respMsg dnsmessage.Msg
		if err := respMsg.Unpack(resp); err != nil {
			return fmt.Errorf("failed to unpack DNS response: %w", err)
		}
		// Set the correct ID from the original request
		respMsg.Id = reqId
		return responseWriter.WriteMsg(&respMsg)
	}

	// For UDP path, directly send pre-packed response with patched ID
	if req == nil || req.lConn == nil {
		return fmt.Errorf("dns request connection is nil for cached response")
	}

	// OPTIMIZATION: Use buffer pool to avoid memory allocation on every cache hit.
	// DNS Message ID is in the first 2 bytes (big-endian).
	if len(resp) >= 2 && len(resp) <= 1024 {
		bufPtr := dnsResponseBufPool.Get().(*[]byte)
		defer dnsResponseBufPool.Put(bufPtr)

		patchedResp := (*bufPtr)[:len(resp)]
		copy(patchedResp, resp)
		binary.BigEndian.PutUint16(patchedResp[0:2], reqId)

		// Transparent DNS replies must preserve the original DNS server tuple.
		// sendPkt also carries the DNS port-conflict raw fallback for host-local
		// clients where binding the source address may fail transiently.
		if err := sendRuntimeTrackedPkt(c.log, patchedResp, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
			return fmt.Errorf("failed to write cached DNS resp: %w", err)
		}
		return nil
	}

	// Fallback for oversized responses (rare)
	patchedResp := make([]byte, len(resp))
	copy(patchedResp, resp)
	if len(resp) >= 2 {
		binary.BigEndian.PutUint16(patchedResp[0:2], reqId)
	}

	if err := sendRuntimeTrackedPkt(c.log, patchedResp, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
		return fmt.Errorf("failed to write oversized cached DNS resp: %w", err)
	}
	return nil
}

// sendDnsErrorResponse_ is the shared implementation for both sendRejectWithResponseWriter_
// and sendRefusedWithResponseWriter_. It sets the common response fields, logs at trace
// level, and sends the response via responseWriter or UDP.
func (c *DnsController) sendDnsErrorResponse_(
	dnsMessage *dnsmessage.Msg,
	rcode int,
	traceMsg string,
	req *udpRequest,
	responseWriter dnsmessage.ResponseWriter,
) (err error) {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = rcode
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = false
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln(traceMsg)
	}
	if responseWriter != nil {
		return responseWriter.WriteMsg(dnsMessage)
	}
	if req == nil || req.lConn == nil {
		return nil
	}
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
		return err
	}
	return nil
}

// sendRefusedWithResponseWriter_ sends REFUSED response when overload protection is triggered.
func (c *DnsController) sendRefusedWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	return c.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeRefused, "Refused due to concurrency limit", req, responseWriter)
}

func (c *DnsController) sendDnsTruncatedResponse_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) error {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = dnsmessage.RcodeSuccess
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = true
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln("Truncated")
	}
	if responseWriter != nil {
		return responseWriter.WriteMsg(dnsMessage)
	}
	if req == nil || req.lConn == nil {
		return nil
	}
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
		return err
	}
	return nil
}

// sendRejectWithResponseWriter_ send empty answer.
func (c *DnsController) sendRejectWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	return c.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeSuccess, "Reject", req, responseWriter)
}

// applyPreferenceWait implements RFC 8305 Happy Eyeballs Resolution Delay.
// When ip_version_prefer is set and a non-preferred A/AAAA response is received,
// wait briefly (50ms) for the preferred response to arrive before using this one.
//
// This function handles two scenarios:
// 1. Non-preferred response arrives (e.g., A when prefer=6): Register wait and wait for preferred
// 2. Preferred response arrives (e.g., AAAA when prefer=6): Notify any waiting requests
//
// The function returns the response to use (preferred if arrived during wait, otherwise original).
func (c *DnsController) applyPreferenceWait(respMsg *dnsmessage.Msg) *dnsmessage.Msg {
	c.requireStore()
	// Fast path: preference not enabled
	if c.currentQtypePrefer() == 0 {
		return respMsg
	}

	// Only handle A/AAAA responses
	if len(respMsg.Question) == 0 {
		return respMsg
	}
	q := respMsg.Question[0]
	if q.Qtype != dnsmessage.TypeA && q.Qtype != dnsmessage.TypeAAAA {
		return respMsg
	}

	// Get canonical qname for matching
	qname := dnsmessage.CanonicalName(q.Name)

	// Case 1: This is the preferred response type - notify waiting requests
	qtypePrefer := c.currentQtypePrefer()
	if isPreferredType(q.Qtype, qtypePrefer) {
		// Notify any waiting requests for this domain
		if c.prefWaitRegistry.notifyPreferred(qname, q.Qtype, qtypePrefer) {
			if c.log.IsLevelEnabled(logrus.TraceLevel) {
				c.log.Tracef("Preferred %v response for %v notified waiting request", QtypeToString(q.Qtype), qname)
			}
		}
		return respMsg
	}

	// Case 2: This is a non-preferred response - register wait and wait for preferred
	if wait := c.prefWaitRegistry.registerWait(qname, q.Qtype, qtypePrefer); wait != nil {
		// Non-preferred response arrived before preferred - wait briefly for preferred
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("Non-preferred %v response for %v, waiting %v for preferred %v",
				QtypeToString(q.Qtype), qname, PreferenceResolutionDelay, QtypeToString(qtypePrefer))
		}

		// Wait for preferred response or timeout
		preferred := wait.waitFor()

		// Clean up wait registry
		c.prefWaitRegistry.remove(qname)

		if preferred {
			if c.log.IsLevelEnabled(logrus.TraceLevel) {
				c.log.Tracef("Preferred %v response arrived for %v during wait for %v",
					QtypeToString(qtypePrefer), qname, QtypeToString(q.Qtype))
			}
		} else if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("Preferred %v response not arrived for %v within %v, using %v response",
				QtypeToString(qtypePrefer), qname, PreferenceResolutionDelay, QtypeToString(q.Qtype))
		}

		// Always return the original response. The wait only changes when we
		// release the response, not the DNS question/answer type pairing.
		return respMsg
	}

	return respMsg
}

type dnsUpstreamResolution struct {
	response      *dnsmessage.Msg
	networkType   *dialer.NetworkType
	upstreamIndex consts.DnsResponseOutboundIndex
	dialArgument  *dialArgument
}

// resolveDNSUpstream obtains a DNS response without writing it to the client
// or mutating the response cache. It owns response routing and recursive
// upstream fallback so delivery can be shared by UDP, TCP, and singleflight.
func (c *DnsController) resolveDNSUpstream(
	ctx context.Context,
	invokingDepth int,
	req *udpRequest,
	data []byte,
	upstream *dns.Upstream,
) (*dnsUpstreamResolution, error) {
	data = append([]byte(nil), data...) // defensive copy: callers may reuse the slice across recursive retries
	if invokingDepth >= MaxDnsLookupDepth {
		return nil, fmt.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
	}

	upstreamName := "asis"
	if upstream == nil {
		// As-is.

		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		var ip46 netutils.Ip46
		if req.realDst.Addr().Is4() {
			ip46.Ip4 = req.realDst.Addr()
		} else {
			ip46.Ip6 = req.realDst.Addr()
		}
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.realDst.Addr().String(),
			Port:     req.realDst.Port(),
			Ip46:     &ip46,
		}
	} else {
		upstreamName = upstream.String()
	}

	// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
	dialArg, err := c.runtime().chooseBestDnsDialer(ctx, dnsRequestSnapshotFromUDPRequest(req), upstream)
	if err != nil {
		return nil, err
	}

	// Dial and send.
	var respMsg *dnsmessage.Msg
	var usedDialArg *dialArgument
	respMsg, usedDialArg, err = c.forwardWithFallback(ctx, req, upstream, dialArg, data)
	if err != nil {
		return nil, err
	}

	networkType := &dialer.NetworkType{
		L4Proto:         usedDialArg.l4proto,
		IpVersion:       usedDialArg.ipversion,
		IsDns:           true,
		UdpHealthDomain: dialer.UdpHealthDomainDns,
	}

	// Route response.
	rt := c.runtime()
	if rt == nil || rt.routing == nil {
		return nil, fmt.Errorf("dns routing is not configured")
	}
	upstreamIndex, nextUpstream, err := rt.routing.ResponseSelect(ctx, respMsg, upstream)
	if err != nil {
		return nil, err
	}
	switch upstreamIndex {
	case consts.DnsResponseOutboundIndex_Accept:
		// Accept.
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Accept")
		}
	case consts.DnsResponseOutboundIndex_Reject:
		// Reject the request with empty answer.
		respMsg.Answer = nil
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Reject with empty answer")
		}
		// We also cache response reject.
	default:
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      respMsg.Question,
				"last_upstream": upstreamName,
				"next_upstream": nextUpstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		return c.resolveDNSUpstream(ctx, invokingDepth+1, req, data, nextUpstream)
	}

	// Apply preference wait logic for A/AAAA responses.
	// This must happen before logging and sending the response.
	respMsg = c.applyPreferenceWait(respMsg)

	return &dnsUpstreamResolution{
		response:      respMsg,
		networkType:   networkType,
		upstreamIndex: upstreamIndex,
		dialArgument:  usedDialArg,
	}, nil
}

func (c *DnsController) dialSend(
	ctx context.Context,
	req *udpRequest,
	data []byte,
	id uint16,
	upstream *dns.Upstream,
	needResp bool,
	responseWriter dnsmessage.ResponseWriter,
	responseCacheKey string,
) (err error) {
	resolution, err := c.resolveDNSUpstream(ctx, 0, req, data, upstream)
	if err != nil {
		return err
	}
	respMsg := resolution.response

	if resolution.upstreamIndex.IsReserved() && c.log.IsLevelEnabled(logrus.DebugLevel) {
		var (
			qname string
			qtype string
		)
		if len(respMsg.Question) > 0 {
			q := respMsg.Question[0]
			qname = strings.ToLower(q.Name)
			qtype = QtypeToString(q.Qtype)
		}
		fields := logrus.Fields{
			"network":  resolution.networkType.String(),
			"outbound": resolution.dialArgument.bestOutbound.Name,
			"policy":   resolution.dialArgument.bestOutbound.GetSelectionPolicy(),
			"dialer":   resolution.dialArgument.bestDialer.Property().Name,
			"_qname":   qname,
			"qtype":    qtype,
			"pid":      req.routingResult.Pid,
			"dscp":     req.routingResult.Dscp,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		switch resolution.upstreamIndex {
		case consts.DnsResponseOutboundIndex_Accept:
			c.log.WithFields(fields).Debugf("%v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr()), RefineAddrPortToShow(resolution.dialArgument.bestTarget))
		case consts.DnsResponseOutboundIndex_Reject:
			c.log.WithFields(fields).Debugf("%v -> reject", RefineSourceToShow(req.realSrc, req.realDst.Addr()))
		default:
			return fmt.Errorf("unknown upstream: %v", resolution.upstreamIndex.String())
		}
	}

	// Optimization: Send response first, then cache asynchronously.
	// This reduces client-perceived latency.
	//
	// Cache operations and BPF updates are fast, but doing them async is still beneficial:
	// - Reduces tail latency under load
	// - Follows "respond first, process later" best practice
	//
	// Trade-off: If caching fails, the response is still valid but won't be cached.
	// This is acceptable because:
	// - Cache failures are rare
	// - The response is already sent to the client
	// - Next request for same domain will just hit upstream again
	if needResp {
		// Keep the id the same with request.
		respMsg.Id = id
		respMsg.Compress = true
		// If responseWriter is provided, use it to write the response.
		if responseWriter != nil {
			// For responseWriter path, cache synchronously because
			// responseWriter may need the message after we return.
			if err = c.NormalizeAndCacheDnsResp_(respMsg, responseCacheKey); err != nil {
				c.log.Warnf("failed to cache DNS response: %v", err)
			}
			return responseWriter.WriteMsg(respMsg)
		}
		data, err = respMsg.Pack()
		if err != nil {
			return err
		}
		if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
			return err
		}

		// Cache asynchronously after sending response (UDP path only).
		// respMsg is owned by this function and won't be accessed after return,
		// so it's safe to use in goroutine without copying.
		go func() {
			defer func() {
				if r := recover(); r != nil {
					c.log.Errorf("panic in async DNS cache: %v", r)
				}
			}()
			if err := c.NormalizeAndCacheDnsResp_(respMsg, responseCacheKey); err != nil {
				c.log.Debugf("failed to cache DNS response (async): %v", err)
			}
		}()

		return nil
	}

	// No response needed, just cache synchronously
	if err = c.NormalizeAndCacheDnsResp_(respMsg, responseCacheKey); err != nil {
		return err
	}
	return nil
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
