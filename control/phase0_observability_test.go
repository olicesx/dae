/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/routing"
)

func installPhase0ObservabilityForTest(t *testing.T) *phase0Observability {
	t.Helper()
	recorder := &phase0Observability{}
	previous := swapPhase0Observability(recorder)
	t.Cleanup(func() {
		activePhase0Observability.CompareAndSwap(recorder, previous)
	})
	return recorder
}

func TestPhase0ObservabilityIsDisabledByDefault(t *testing.T) {
	previous := swapPhase0Observability(nil)
	t.Cleanup(func() {
		activePhase0Observability.CompareAndSwap(nil, previous)
	})

	if recorder, startedAt := beginPhase0DNSProjectionObservation(); recorder != nil || !startedAt.IsZero() {
		t.Fatalf("beginPhase0DNSProjectionObservation() = (%v, %v), want (nil, zero)", recorder, startedAt)
	}
}

func TestPhase0ObservabilityRecordsRoutingEpochOutcomes(t *testing.T) {
	recorder := installPhase0ObservabilityForTest(t)
	core := &controlPlaneCore{}

	if _, err := core.PrepareRoutingEpoch(0, true); err == nil {
		t.Fatal("PrepareRoutingEpoch(0) error = nil, want error")
	}
	if got := recorder.routingEpochCount(phase0RoutingEpochPrepare, phase0ObservationFailure); got != 1 {
		t.Fatalf("prepare failure count = %d, want 1", got)
	}

	activeMap := newJanitorTestMap(t, "active_routing_epoch_map")
	epochMap := newJanitorTestMap(t, "routing_epoch_map")
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			ActiveRoutingEpochMap: activeMap,
			RoutingEpochMap:       epochMap,
		},
	})

	if _, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(23), true); err != nil {
		t.Fatalf("PrepareRoutingEpoch() error = %v", err)
	}
	if err := core.StageRoutingEpoch(); err != nil {
		t.Fatalf("StageRoutingEpoch() error = %v", err)
	}
	if err := core.PublishRoutingEpoch(); err != nil {
		t.Fatalf("PublishRoutingEpoch() error = %v", err)
	}
	if err := core.RollbackRoutingEpoch(); err != nil {
		t.Fatalf("RollbackRoutingEpoch() error = %v", err)
	}

	for _, operation := range []phase0RoutingEpochOperation{
		phase0RoutingEpochPrepare,
		phase0RoutingEpochStage,
		phase0RoutingEpochPublish,
		phase0RoutingEpochRollback,
	} {
		if got := recorder.routingEpochCount(operation, phase0ObservationSuccess); got != 1 {
			t.Fatalf("operation %d success count = %d, want 1", operation, got)
		}
	}
}

func TestPhase0ObservabilityRecordsDNSProjectionOutcomes(t *testing.T) {
	recorder := installPhase0ObservabilityForTest(t)
	controller := newTestDnsController()
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 2
		rt.cacheAccessCallback = func(*DnsCache) error { return nil }
	})

	startedAt := time.Now().Add(-2 * time.Second)
	if !controller.processBpfUpdateTask(&bpfUpdateTask{
		cache:                &DnsCache{RouteProjectionEpoch: 2},
		now:                  time.Now(),
		routeProjectionEpoch: 2,
		phase0Recorder:       recorder,
		phase0StartedAt:      startedAt,
	}, false) {
		t.Fatal("processBpfUpdateTask() = false, want true")
	}
	if got := recorder.dnsProjectionCount(phase0DNSProjectionAsync, phase0DNSProjectionApplied); got != 1 {
		t.Fatalf("async applied count = %d, want 1", got)
	}
	if got := recorder.dnsProjectionLagCount(phase0DNSProjectionAsync, phase0DNSProjectionApplied, phase0DNSProjectionLagAtLeastSecond); got != 1 {
		t.Fatalf("async applied >=1s lag count = %d, want 1", got)
	}

	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 2
		rt.cacheAccessCallback = func(*DnsCache) error { return stderrors.New("projection failed") }
	})
	controller.processBpfUpdateTask(&bpfUpdateTask{
		cache:                &DnsCache{RouteProjectionEpoch: 2},
		now:                  time.Now(),
		routeProjectionEpoch: 2,
		phase0Recorder:       recorder,
		phase0StartedAt:      time.Now().Add(-2 * time.Second),
	}, false)
	if got := recorder.dnsProjectionCount(phase0DNSProjectionAsync, phase0DNSProjectionFailed); got != 1 {
		t.Fatalf("async failed count = %d, want 1", got)
	}
	if got := recorder.dnsProjectionLagCount(phase0DNSProjectionAsync, phase0DNSProjectionFailed, phase0DNSProjectionLagAtLeastSecond); got != 1 {
		t.Fatalf("async failed >=1s lag count = %d, want 1", got)
	}

	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 3
		rt.cacheAccessCallback = func(*DnsCache) error { return nil }
	})
	controller.processBpfUpdateTask(&bpfUpdateTask{
		cache:                &DnsCache{RouteProjectionEpoch: 2},
		now:                  time.Now(),
		routeProjectionEpoch: 2,
		phase0Recorder:       recorder,
	}, false)
	if got := recorder.dnsProjectionCount(phase0DNSProjectionAsync, phase0DNSProjectionStale); got != 1 {
		t.Fatalf("async stale count = %d, want 1", got)
	}

	controller.bpfUpdateClosed.Store(true)
	if controller.sendBpfUpdateTask(&bpfUpdateTask{phase0Recorder: recorder}) {
		t.Fatal("sendBpfUpdateTask() = true, want queue rejection")
	}
	if got := recorder.dnsProjectionCount(phase0DNSProjectionAsync, phase0DNSProjectionQueueDrop); got != 1 {
		t.Fatalf("async queue drop count = %d, want 1", got)
	}

	syncController := newTestDnsController()
	setTestDnsControllerRuntime(syncController, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 4
		rt.cacheAccessCallback = func(*DnsCache) error { return nil }
	})
	entry := &DnsCache{RouteOwnerKey: "phase0-sync.example.1", Deadline: time.Now().Add(time.Minute)}
	if count, err := syncController.RestoreReloadCacheAndProject(map[string]*DnsCache{entry.RouteOwnerKey: entry}, nil, time.Now()); err != nil || count != 1 {
		t.Fatalf("RestoreReloadCacheAndProject() = (%d, %v), want (1, nil)", count, err)
	}
	if got := recorder.dnsProjectionCount(phase0DNSProjectionReloadSync, phase0DNSProjectionApplied); got != 1 {
		t.Fatalf("reload sync applied count = %d, want 1", got)
	}

	setTestDnsControllerRuntime(syncController, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 4
		rt.cacheAccessCallback = func(*DnsCache) error { return stderrors.New("reload projection failed") }
	})
	failingEntry := &DnsCache{RouteOwnerKey: "phase0-sync-failure.example.1", Deadline: time.Now().Add(time.Minute)}
	if _, err := syncController.RestoreReloadCacheAndProject(map[string]*DnsCache{failingEntry.RouteOwnerKey: failingEntry}, nil, time.Now()); err == nil {
		t.Fatal("RestoreReloadCacheAndProject() error = nil, want error")
	}
	if got := recorder.dnsProjectionCount(phase0DNSProjectionReloadSync, phase0DNSProjectionFailed); got != 1 {
		t.Fatalf("reload sync failed count = %d, want 1", got)
	}
}
