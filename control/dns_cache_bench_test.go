/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func newBenchmarkDnsCache(t testing.TB) *DnsCache {
	t.Helper()
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "benchmark.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
			A:   net.IPv4(93, 184, 216, 34),
		},
		&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{Name: "benchmark.example.com.", Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 300},
			AAAA: []byte{
				0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0, 0x8, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x22,
			},
		},
	}
	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	if err := cache.PrepackResponse("benchmark.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatalf("PrepackResponse: %v", err)
	}
	return cache
}

func BenchmarkDnsCache_GetPackedResponse(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packed := cache.GetPackedResponse()
		if len(packed) == 0 {
			b.Fatal("empty packed response")
		}
	}
}

func BenchmarkDnsCache_GetPackedResponseWithApproximateTTL(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packed := cache.GetPackedResponseWithApproximateTTL("benchmark.example.com.", dnsmessage.TypeA, now)
		if len(packed) == 0 {
			b.Fatal("empty packed response")
		}
	}
}

func BenchmarkDnsCache_GetPackedResponseWithApproximateTTL_Stale(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	now := time.Now().Add(4*time.Minute + 45*time.Second)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packed := cache.GetPackedResponseWithApproximateTTL("benchmark.example.com.", dnsmessage.TypeA, now)
		if len(packed) == 0 {
			b.Fatal("empty packed response")
		}
	}
}

func BenchmarkDnsCache_FillInto(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := new(dnsmessage.Msg)
		req.SetQuestion("benchmark.example.com.", dnsmessage.TypeA)
		cache.FillInto(req)
	}
}

func BenchmarkDnsCache_FillIntoWithPacked(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := new(dnsmessage.Msg)
		req.SetQuestion("benchmark.example.com.", dnsmessage.TypeA)
		cache.FillIntoWithPacked(req)
	}
}

func BenchmarkDnsCache_FillIntoWithTTL(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := new(dnsmessage.Msg)
		req.SetQuestion("benchmark.example.com.", dnsmessage.TypeA)
		result := cache.FillIntoWithTTL(req, now)
		if result == nil {
			b.Fatal("nil result")
		}
	}
}

func BenchmarkDnsCache_ComputeBpfDataHash(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.ComputeBpfDataHash()
	}
}

func BenchmarkDnsCache_Clone(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cloned := cache.Clone()
		if cloned == nil {
			b.Fatal("nil clone")
		}
	}
}

func BenchmarkDnsCache_CloneForReload(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cloned := cache.CloneForReload()
		if cloned == nil {
			b.Fatal("nil clone")
		}
	}
}

func BenchmarkDnsController_ReuseForReloadUnchangedProjection(b *testing.B) {
	const cacheEntries = 10_000
	projectionHash := [32]byte{1}
	controller := newTestDnsController()
	b.Cleanup(func() { _ = controller.Close() })
	if err := controller.TryUpdateRuntime(&DnsControllerOption{
		RouteProjectionEpoch: 1,
		RouteProjectionHash:  projectionHash,
	}, nil); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < cacheEntries; i++ {
		controller.dnsCache.Store(i, &DnsCache{RouteProjectionEpoch: 1})
	}

	b.ReportAllocs()
	b.ReportMetric(cacheEntries, "cache_entries")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reused, err := controller.ReuseForReload(&DnsControllerOption{
			RouteProjectionEpoch: uint64(i) + 2,
			RouteProjectionHash:  projectionHash,
		}, nil)
		if err != nil {
			b.Fatal(err)
		}
		controller = reused
	}
}

func BenchmarkDnsController_CloneCacheForReload10000(b *testing.B) {
	const cacheEntries = 10_000
	controller := newTestDnsController()
	for i := 0; i < cacheEntries; i++ {
		key := "clone-" + strconv.Itoa(i)
		controller.dnsCache.Store(key, &DnsCache{RouteOwnerKey: key})
	}

	b.ReportAllocs()
	b.ReportMetric(cacheEntries, "cache_entries")
	b.ResetTimer()
	for range b.N {
		cloned := controller.CloneCacheForReload()
		if len(cloned) != cacheEntries {
			b.Fatalf("cloned %d entries, want %d", len(cloned), cacheEntries)
		}
		runtime.KeepAlive(cloned)
	}
}

func BenchmarkDnsCacheCapacityAdmission(b *testing.B) {
	for _, cacheEntries := range []int{1024, 65536} {
		b.Run(strconv.Itoa(cacheEntries), func(b *testing.B) {
			controller := newTestDnsController()
			controller.maxCacheSize.Store(int64(cacheEntries))
			deadline := time.Now().Add(time.Hour)
			for i := 0; i < cacheEntries; i++ {
				key := "resident-" + strconv.Itoa(i) + ".:1"
				cache := &DnsCache{RouteOwnerKey: key, OriginalDeadline: deadline}
				controller.storeDnsCache(key, cache)
				controller.rememberDnsKnowledge(dnsCacheBaseKey(key), deadline, true)
			}

			b.ReportAllocs()
			b.ReportMetric(float64(cacheEntries), "cache_entries")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := "incoming-" + strconv.Itoa(i) + ".:1"
				cache := &DnsCache{RouteOwnerKey: key, OriginalDeadline: deadline}
				controller.cacheProjectionMu.Lock()
				controller.enforceDnsCacheCapacityLocked(key)
				controller.storeDnsCache(key, cache)
				controller.rememberDnsKnowledge(dnsCacheBaseKey(key), deadline, true)
				controller.cacheProjectionMu.Unlock()
			}
		})
	}
}

func BenchmarkDnsCache_NeedsBpfUpdate(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	now := time.Now()
	cache.MarkBpfUpdated(now)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.NeedsBpfUpdate(now.Add(time.Duration(i) * time.Second))
	}
}

func BenchmarkBpfUpdateTaskCurrentOwnerLookup(b *testing.B) {
	controller := newTestDnsController()
	cache := &DnsCache{RouteOwnerKey: "benchmark-owner.example.:1", RouteProjectionEpoch: 7}
	controller.dnsCache.Store(cache.RouteOwnerKey, cache)
	task := &bpfUpdateTask{cache: cache, routeProjectionEpoch: 7}
	rt := &dnsControllerRuntimeState{
		routeProjectionEpoch: 7,
		cacheAccessCallback:  func(*DnsCache) error { return nil },
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if !controller.bpfUpdateTaskCurrent(task, rt) {
			b.Fatal("current owner task was rejected")
		}
	}
}

func BenchmarkDnsCache_ParallelGetPackedResponse(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			packed := cache.GetPackedResponse()
			if len(packed) == 0 {
				b.Fatal("empty packed response")
			}
		}
	})
}

func BenchmarkDnsCache_ParallelGetPackedResponseWithTTL(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			now := time.Unix(1_700_000_000, int64(i)*1e6)
			packed := cache.GetPackedResponseWithApproximateTTL("benchmark.example.com.", dnsmessage.TypeA, now)
			if len(packed) == 0 {
				b.Fatal("empty packed response")
			}
			i++
		}
	})
}
