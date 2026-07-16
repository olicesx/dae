/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync/atomic"
	"testing"
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
