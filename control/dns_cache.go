/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	dnsmessage "github.com/miekg/dns"
)

type DnsCache struct {
	Answer   dnsmessage.RR
	Deadline time.Time
	timer    *time.Timer
}

// Parse ips from DNS resp answers.
func GetIp(rr dnsmessage.RR) (netip.Addr, bool) {
	var (
		ip netip.Addr
		ok bool
	)
	switch body := rr.(type) {
	case *dnsmessage.A:
		ip, ok = netip.AddrFromSlice(body.A)
	case *dnsmessage.AAAA:
		ip, ok = netip.AddrFromSlice(body.AAAA)
	}
	if !ok || ip.IsUnspecified() {
		return ip, false
	}
	return ip, true
}

func FillInto(msg *dnsmessage.Msg, caches []*DnsCache) {
	for _, cache := range caches {
		if cache.Deadline.After(time.Now()) {
			cache.Answer.Header().Ttl = uint32(time.Until(cache.Deadline).Seconds())
			msg.Answer = append(msg.Answer, cache.Answer)
		}
	}
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
}

func IncludeAnyIpInMsg(msg *dnsmessage.Msg) bool {
	for _, ans := range msg.Answer {
		switch ans.(type) {
		case *dnsmessage.A, *dnsmessage.AAAA:
			return true
		}
	}
	return false
}

type commonDnsCache[K comparable] struct {
	cache map[K][]*DnsCache
	mu    sync.RWMutex
}

func newCommonDnsCache[K comparable]() *commonDnsCache[K] {
	return &commonDnsCache[K]{
		cache: make(map[K][]*DnsCache),
	}
}

func (c *commonDnsCache[K]) Get(cacheKey K) []*DnsCache {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if caches, ok := c.cache[cacheKey]; ok {
		return caches
	}
	return nil
}

func AllTimeout(caches []*DnsCache) bool {
	for _, cache := range caches {
		if cache.Deadline.After(time.Now()) {
			return false
		}
	}
	return true
}

func (c *commonDnsCache[K]) UpdateTtl(key K, answer dnsmessage.RR, ttl int) (cache *DnsCache) {
	deadline := time.Now().Add(time.Duration(ttl) * time.Second)

	c.mu.Lock()
	defer c.mu.Unlock()

	newDnsCache := func() *DnsCache {
		ret := &DnsCache{
			Answer:   answer,
			Deadline: deadline,
		}
		ret.timer = time.AfterFunc(time.Until(deadline), func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if caches, ok := c.cache[key]; ok {
				for i, cache := range caches {
					if cache == ret {
						caches = append(caches[:i], caches[i+1:]...)
						common.DnsCacheSize.Dec()
						break
					}
				}
				if len(caches) == 0 {
					delete(c.cache, key)
				} else {
					c.cache[key] = caches
				}
			}
		})
		common.DnsCacheSize.Inc()
		return ret
	}

	if caches, ok := c.cache[key]; ok {
		for _, c := range caches {
			if dnsmessage.IsDuplicate(c.Answer, answer) {
				c.timer.Reset(time.Until(deadline))
				c.Deadline = deadline
				return c
			}
		}
		cache = newDnsCache()
		c.cache[key] = append(caches, cache)
		return
	}
	cache = newDnsCache()
	c.cache[key] = []*DnsCache{cache}
	return
}
