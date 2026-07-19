/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/routing"
)

func TestRefreshDnsReloadCacheForCutoverUsesLatestSharedSnapshot(t *testing.T) {
	var calls atomic.Int32
	stale := &DnsCache{RouteOwnerKey: "stale.example.1"}
	latest := &DnsCache{RouteOwnerKey: "latest.example.1"}
	previousTracker := newDomainRoutingTracker()
	core := &controlPlaneCore{}
	core.routingEpochSlot.Store(1)
	core.domainRoutingSlots[1] = previousTracker
	plane := &ControlPlane{
		core:                   core,
		preparedDatapathCommit: true,
		sharedBpfReload:        true,
		pendingDnsReloadCache:  map[string]*DnsCache{stale.RouteOwnerKey: stale},
	}
	plane.SetReloadDnsCacheSource(func() map[string]*DnsCache {
		calls.Add(1)
		return map[string]*DnsCache{latest.RouteOwnerKey: latest}
	})

	refreshed, err := plane.refreshDnsReloadCacheForCutover()
	if err != nil {
		t.Fatalf("refreshDnsReloadCacheForCutover() error = %v", err)
	}
	if !refreshed {
		t.Fatal("refreshDnsReloadCacheForCutover() = false, want true")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cache source calls = %d, want 1", got)
	}
	if got := plane.pendingDnsReloadCache[latest.RouteOwnerKey]; got != latest {
		t.Fatalf("pending cache = %p, want latest cache %p", got, latest)
	}
	if _, ok := plane.pendingDnsReloadCache[stale.RouteOwnerKey]; ok {
		t.Fatal("stale preparation cache remained after cutover refresh")
	}
	if core.domainRoutingSlots[1] == previousTracker {
		t.Fatal("target domain routing tracker was not reset before projection")
	}
}

func TestRefreshDnsReloadCacheForCutoverStreamsWithoutRetainingSnapshot(t *testing.T) {
	identity, err := routing.NewPolicyIdentity(1, &routing.NormalizedProgram{Fallback: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	cache := &DnsCache{
		RouteOwnerKey: "stream.example.1",
		DomainBitmap:  make([]uint32, len(bpfDomainRouting{}.Bitmap)),
	}
	sourceController := newTestDnsController()
	sourceController.storeDnsCache(cache.RouteOwnerKey, cache)
	sourcePlane := &ControlPlane{controlPlaneDNSRuntime: controlPlaneDNSRuntime{dnsController: sourceController}}

	previousTracker := newDomainRoutingTracker()
	core := &controlPlaneCore{}
	core.routingEpochSlot.Store(1)
	core.domainRoutingSlots[1] = previousTracker
	plane := &ControlPlane{
		core:                   core,
		preparedDatapathCommit: true,
		sharedBpfReload:        true,
		pendingDnsReloadCache:  map[string]*DnsCache{"stale": {}},
		controlPlaneGenerationState: controlPlaneGenerationState{
			policyIdentity: identity,
		},
	}
	var calls atomic.Int32
	plane.SetReloadDnsCacheStreamSource(func(visit func(string, *DnsCache) error) error {
		calls.Add(1)
		return sourcePlane.StreamDnsCacheForReload(visit)
	}, identity.Hash())

	refreshed, err := plane.refreshDnsReloadCacheForCutover()
	if err != nil {
		t.Fatalf("refreshDnsReloadCacheForCutover() error = %v", err)
	}
	if !refreshed {
		t.Fatal("refreshDnsReloadCacheForCutover() = false, want true")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("stream source calls = %d, want 1", got)
	}
	if plane.pendingDnsReloadCache != nil {
		t.Fatal("streamed cutover retained a DNS cache snapshot")
	}
	if got, ok := sourceController.dnsCache.Load(cache.RouteOwnerKey); !ok || got != cache {
		t.Fatal("streamed cutover replaced the authoritative cache wrapper")
	}
	if core.domainRoutingSlots[1] == previousTracker {
		t.Fatal("target domain routing tracker was not reset before streamed projection")
	}
}

func TestClearReloadDnsCacheSourceReleasesSnapshotClosure(t *testing.T) {
	var calls atomic.Int32
	plane := &ControlPlane{
		preparedDatapathCommit: true,
		sharedBpfReload:        true,
	}
	plane.SetReloadDnsCacheSource(func() map[string]*DnsCache {
		calls.Add(1)
		return nil
	})

	if _, ok := plane.cloneDnsReloadCacheForCutover(); !ok {
		t.Fatal("cache source was not available before cleanup")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cache source calls = %d, want 1", got)
	}

	plane.ClearReloadDnsCacheSource()
	if _, ok := plane.cloneDnsReloadCacheForCutover(); ok {
		t.Fatal("cache source was retained after cleanup")
	}
	plane.SetReloadDnsCacheStreamSource(func(func(string, *DnsCache) error) error {
		return nil
	}, [32]byte{1})
	plane.ClearReloadDnsCacheSource()
	if _, _, ok := plane.dnsReloadCacheStreamForCutover(); ok {
		t.Fatal("stream cache source was retained after cleanup")
	}
}

func TestRefreshDnsReloadCacheForCutoverSkipsNonSharedReload(t *testing.T) {
	var calls atomic.Int32
	plane := &ControlPlane{
		core:                   &controlPlaneCore{},
		preparedDatapathCommit: true,
	}
	plane.SetReloadDnsCacheSource(func() map[string]*DnsCache {
		calls.Add(1)
		return nil
	})

	refreshed, err := plane.refreshDnsReloadCacheForCutover()
	if err != nil {
		t.Fatalf("refreshDnsReloadCacheForCutover() error = %v", err)
	}
	if refreshed {
		t.Fatal("refreshDnsReloadCacheForCutover() = true for non-shared reload")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("cache source calls = %d, want 0", got)
	}
}

func BenchmarkProjectDnsReloadCacheStream10000(b *testing.B) {
	controller := newTestDnsController()
	bitmap := make([]uint32, len(bpfDomainRouting{}.Bitmap))
	for i := 0; i < 10_000; i++ {
		key := "stream-" + strconv.Itoa(i)
		controller.dnsCache.Store(key, &DnsCache{RouteOwnerKey: key, DomainBitmap: bitmap})
	}
	sourcePlane := &ControlPlane{controlPlaneDNSRuntime: controlPlaneDNSRuntime{dnsController: controller}}
	core := &controlPlaneCore{}
	core.routingEpochSlot.Store(1)
	core.domainRoutingSlots[1] = newDomainRoutingTracker()
	plane := &ControlPlane{core: core}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		count, err := plane.projectDnsReloadCacheStream(sourcePlane.StreamDnsCacheForReload, true)
		if err != nil {
			b.Fatal(err)
		}
		if count != 10_000 {
			b.Fatalf("projected %d entries, want 10000", count)
		}
	}
}
