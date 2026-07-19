/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestDnsController_RuntimeWorkersSurviveContextCancel verifies that the BPF
// update worker, DNS cache janitor, and cache evictor do NOT exit when the old
// generation's lifecycle context is canceled during a staged reload.
//
// Regression test for: after reload, shared DnsController background workers
// keep watching the old generation's Done channel, exit during retirement, and
// stop maintaining DNS cache / domain_routing side effects after cutover.
func TestDnsController_RuntimeWorkersSurviveContextCancel(t *testing.T) {
	oldJanitorInterval := dnsCacheJanitorInterval
	dnsCacheJanitorInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		dnsCacheJanitorInterval = oldJanitorInterval
	})

	// Phase 1: Create DNS controller with the "old generation" context.
	oldCtx, oldCancel := context.WithCancel(context.Background())
	defer oldCancel()

	var bpfUpdateCount atomic.Int64
	var cacheRemoveCount atomic.Int64
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		LifecycleContext: oldCtx,
		CacheAccessCallback: func(cache *DnsCache) error {
			bpfUpdateCount.Add(1)
			return nil
		},
		CacheRemoveCallback: func(cache *DnsCache) error {
			cacheRemoveCount.Add(1)
			return nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, controller)
	defer func() { require.NoError(t, controller.Close()) }()

	// Trigger a BPF update to lazily start the worker.
	cache := &DnsCache{Deadline: time.Now().Add(time.Hour)}
	cache.MarkBpfUpdated(time.Time{}) // Force NeedsBpfUpdate to return true
	controller.triggerBpfUpdateIfNeeded(cache, time.Now().Add(-DnsCacheRouteRefreshInterval))
	// Wait for the worker to process the task.
	require.Eventually(t, func() bool { return bpfUpdateCount.Load() >= 1 }, 2*time.Second, 10*time.Millisecond,
		"BPF update worker should process initial task")

	// Phase 2: Simulate reload — UpdateRuntime with new context (as ReuseDNSControllerFrom does).
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()

	require.NoError(t, controller.TryUpdateRuntime(&DnsControllerOption{
		Log:              log,
		LifecycleContext: newCtx,
		CacheAccessCallback: func(cache *DnsCache) error {
			bpfUpdateCount.Add(1)
			return nil
		},
		CacheRemoveCallback: func(cache *DnsCache) error {
			cacheRemoveCount.Add(1)
			return nil
		},
	}, nil))

	// Phase 3: Cancel the OLD context (simulates old CP retirement).
	oldCancel()
	// Give goroutines time to react to the cancellation.
	time.Sleep(100 * time.Millisecond)

	// Phase 4: Verify the BPF update worker is still alive by sending another update.
	countBefore := bpfUpdateCount.Load()
	cache2 := &DnsCache{Deadline: time.Now().Add(time.Hour)}
	cache2.MarkBpfUpdated(time.Time{})
	controller.triggerBpfUpdateIfNeeded(cache2, time.Now().Add(-DnsCacheRouteRefreshInterval))

	require.Eventually(t, func() bool { return bpfUpdateCount.Load() > countBefore }, 2*time.Second, 10*time.Millisecond,
		"BPF update worker must survive old context cancellation and continue processing tasks")

	// Phase 5: Verify the DNS cache janitor is still alive by evicting an expired entry.
	expiredKey := "expired.example.com.A"
	controller.dnsCache.Store(expiredKey, &DnsCache{
		Deadline:         time.Now().Add(-time.Second),
		OriginalDeadline: time.Now().Add(-time.Second),
	})
	require.Eventually(t, func() bool {
		_, ok := controller.dnsCache.Load(expiredKey)
		return !ok
	}, 2*time.Second, 10*time.Millisecond,
		"DNS cache janitor must survive old context cancellation and continue evicting expired cache entries")

	// Phase 6: Verify the cache evictor is still alive by delivering side-effect removals.
	removeCountBefore := cacheRemoveCount.Load()
	controller.onDnsCacheEvicted(&DnsCache{Deadline: time.Now().Add(time.Hour)})
	require.Eventually(t, func() bool { return cacheRemoveCount.Load() > removeCountBefore }, 2*time.Second, 10*time.Millisecond,
		"cache evictor must survive old context cancellation and continue draining removal callbacks")
}

func TestDnsController_ReuseForReloadReturnsFreshFacadeSharingStore(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	defer oldCancel()
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              logrus.New(),
		LifecycleContext: oldCtx,
		FixedDomainTtl: map[string]int{
			"old.example": 10,
		},
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close()) }()

	controller.dnsCache.Store("reload.example.1", &DnsCache{Deadline: time.Now().Add(time.Minute)})

	reused, err := controller.ReuseForReload(&DnsControllerOption{
		Log:              logrus.New(),
		LifecycleContext: newCtx,
		FixedDomainTtl: map[string]int{
			"new.example": 30,
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, reused)
	require.NotSame(t, controller, reused)
	require.Same(t, controller.dnsControllerStore, reused.dnsControllerStore)

	_, ok := reused.dnsCache.Load("reload.example.1")
	require.True(t, ok, "reused facade should see shared cache state")

	originalRT := controller.runtime()
	reusedRT := reused.runtime()
	require.NotNil(t, originalRT)
	require.NotNil(t, reusedRT)
	require.Equal(t, newCtx, originalRT.lifecycleCtx)
	require.Equal(t, newCtx, reusedRT.lifecycleCtx)
	require.Equal(t, 30, reusedRT.fixedDomainTtl["new.example"])
	require.Nil(t, reusedRT.routing)
}

func TestDnsRuntimeReuseFailurePreservesReplacementController(t *testing.T) {
	oldController := newTestDnsController()
	replacementController := newTestDnsController()
	previous := &controlPlaneDNSRuntime{dnsController: oldController}
	current := &controlPlaneDNSRuntime{dnsController: replacementController}

	if current.reuseDNSControllerFrom(previous, &DnsControllerOption{IpVersionPrefer: 99}, nil, nil, nil) {
		t.Fatal("reuseDNSControllerFrom() = true for invalid runtime option")
	}
	if current.dnsController != replacementController {
		t.Fatal("failed reuse replaced the current DNS controller")
	}
	if replacementController.bpfUpdateClosed.Load() {
		t.Fatal("failed reuse closed the replacement DNS controller")
	}
	if previous.dnsController != oldController {
		t.Fatal("failed reuse detached the previous DNS controller")
	}
}

func TestDnsController_ReuseForReloadReprojectsCachedRoutes(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 1,
		ProjectCacheRoute: func(*DnsCache) []uint32 {
			return []uint32{1}
		},
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close()) }()

	original := &DnsCache{
		RouteOwnerKey:        "reload.example.1",
		RouteProjectionEpoch: 1,
		DomainBitmap:         []uint32{1},
		Deadline:             time.Now().Add(time.Minute),
	}
	controller.dnsCache.Store(original.RouteOwnerKey, original)

	reused, err := controller.ReuseForReload(&DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 2,
		ProjectCacheRoute: func(*DnsCache) []uint32 {
			return []uint32{2}
		},
	}, nil)
	require.NoError(t, err)

	value, ok := reused.dnsCache.Load(original.RouteOwnerKey)
	require.True(t, ok)
	remapped, ok := value.(*DnsCache)
	require.True(t, ok)
	require.NotSame(t, original, remapped)
	require.Equal(t, uint64(2), remapped.RouteProjectionEpoch)
	require.Equal(t, []uint32{2}, remapped.DomainBitmap)
}

func TestDnsController_ReuseForReloadSkipsUnchangedProjection(t *testing.T) {
	projectionHash := [32]byte{1}
	var projectionCalls atomic.Int64
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 11,
		RouteProjectionHash:  projectionHash,
		ProjectCacheRoute: func(*DnsCache) []uint32 {
			projectionCalls.Add(1)
			return []uint32{1}
		},
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close()) }()

	original := &DnsCache{
		RouteOwnerKey:        "unchanged.example.1",
		RouteProjectionEpoch: 11,
		DomainBitmap:         []uint32{1},
		Deadline:             time.Now().Add(time.Minute),
	}
	controller.dnsCache.Store(original.RouteOwnerKey, original)

	reused, err := controller.ReuseForReload(&DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 12,
		RouteProjectionHash:  projectionHash,
		ProjectCacheRoute: func(*DnsCache) []uint32 {
			projectionCalls.Add(1)
			return []uint32{2}
		},
	}, nil)
	require.NoError(t, err)
	require.Equal(t, int64(0), projectionCalls.Load())
	require.Equal(t, uint64(11), reused.runtime().routeProjectionEpoch)

	value, ok := reused.dnsCache.Load(original.RouteOwnerKey)
	require.True(t, ok)
	require.Same(t, original, value, "unchanged projection must not replace cache wrappers")
}

func TestDnsController_ReuseForReloadReprojectionSharesImmutablePayload(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 21,
		RouteProjectionHash:  [32]byte{1},
		ProjectCacheRoute: func(*DnsCache) []uint32 {
			return []uint32{1}
		},
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close()) }()

	original := &DnsCache{
		RouteOwnerKey:        "changed.example.1",
		RouteProjectionEpoch: 21,
		DomainBitmap:         []uint32{1},
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "changed.example.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		}},
		Deadline:         time.Now().Add(time.Minute),
		OriginalDeadline: time.Now().Add(time.Minute),
	}
	require.NoError(t, original.PrepackResponse("changed.example.", dnsmessage.TypeA))
	controller.dnsCache.Store(original.RouteOwnerKey, original)

	reused, err := controller.ReuseForReload(&DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 22,
		RouteProjectionHash:  [32]byte{2},
		ProjectCacheRoute: func(*DnsCache) []uint32 {
			return []uint32{2}
		},
	}, nil)
	require.NoError(t, err)

	value, ok := reused.dnsCache.Load(original.RouteOwnerKey)
	require.True(t, ok)
	remapped, ok := value.(*DnsCache)
	require.True(t, ok)
	require.NotSame(t, original, remapped)
	require.Equal(t, []uint32{2}, remapped.DomainBitmap)
	require.Equal(t, []uint32{1}, original.DomainBitmap)
	require.Same(t, original.Answer[0], remapped.Answer[0])
	require.Same(t, original.packedResponse.Load(), remapped.packedResponse.Load())
}

func TestDnsController_ReprojectCachedRoutesSkipsProjectionAfterRuntimeSwap(t *testing.T) {
	projectionStarted := make(chan struct{})
	allowProjection := make(chan struct{})
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 1,
		ProjectCacheRoute: func(*DnsCache) []uint32 {
			close(projectionStarted)
			<-allowProjection
			return []uint32{1}
		},
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close()) }()

	original := &DnsCache{
		RouteOwnerKey:        "reproject.example.1",
		RouteProjectionEpoch: 0,
		DomainBitmap:         []uint32{0},
		Deadline:             time.Now().Add(time.Minute),
	}
	controller.dnsCache.Store(original.RouteOwnerKey, original)

	oldRuntime := controller.runtime()
	done := make(chan struct{})
	go func() {
		controller.reprojectCachedRoutes(oldRuntime)
		close(done)
	}()

	select {
	case <-projectionStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("old route projection did not start")
	}

	require.NoError(t, controller.TryUpdateRuntime(&DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 2,
		ProjectCacheRoute: func(*DnsCache) []uint32 {
			return []uint32{2}
		},
	}, nil))
	close(allowProjection)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("old route projection did not finish")
	}

	value, ok := controller.dnsCache.Load(original.RouteOwnerKey)
	require.True(t, ok)
	require.Same(t, original, value)
	require.Equal(t, uint64(0), original.RouteProjectionEpoch)
	require.Equal(t, []uint32{0}, original.DomainBitmap)

	controller.reprojectCachedRoutes(controller.runtime())
	value, ok = controller.dnsCache.Load(original.RouteOwnerKey)
	require.True(t, ok)
	remapped, ok := value.(*DnsCache)
	require.True(t, ok)
	require.NotSame(t, original, remapped)
	require.Equal(t, uint64(2), remapped.RouteProjectionEpoch)
	require.Equal(t, []uint32{2}, remapped.DomainBitmap)
}

func TestDnsController_ProcessBpfUpdateTaskSkipsStaleRouteProjection(t *testing.T) {
	callbackCalled := false
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 2,
		CacheAccessCallback: func(*DnsCache) error {
			callbackCalled = true
			return nil
		},
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close()) }()

	cache := &DnsCache{RouteProjectionEpoch: 1}
	require.True(t, controller.processBpfUpdateTask(&bpfUpdateTask{
		cache:                cache,
		routeProjectionEpoch: 1,
	}, false))
	require.False(t, callbackCalled)

	// A task for the current runtime may run only after the cache entry has
	// been rebuilt with that runtime's projection epoch.
	cache.RouteProjectionEpoch = 2
	require.True(t, controller.processBpfUpdateTask(&bpfUpdateTask{
		cache:                cache,
		routeProjectionEpoch: 2,
	}, false))
	require.True(t, callbackCalled)
}

func TestDnsController_ReuseForReloadUpdatesBehaviorConfig(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                logrus.New(),
		IpVersionPrefer:    int(IpVersionPrefer_4),
		OptimisticCache:    false,
		OptimisticCacheTtl: 5,
		MaxCacheSize:       2,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close()) }()

	reused, err := controller.ReuseForReload(&DnsControllerOption{
		Log:                logrus.New(),
		IpVersionPrefer:    int(IpVersionPrefer_6),
		OptimisticCache:    true,
		OptimisticCacheTtl: 45,
		MaxCacheSize:       99,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, reused)

	require.Equal(t, dnsmessage.TypeAAAA, reused.currentQtypePrefer())
	enabled, ttl, maxCacheSize := reused.currentOptimisticCacheConfig()
	require.True(t, enabled)
	require.Equal(t, 45, ttl)
	require.Equal(t, 99, maxCacheSize)

	require.Equal(t, reused.currentQtypePrefer(), controller.currentQtypePrefer())
	ctrlEnabled, ctrlTTL, ctrlMaxCacheSize := controller.currentOptimisticCacheConfig()
	require.Equal(t, enabled, ctrlEnabled)
	require.Equal(t, ttl, ctrlTTL)
	require.Equal(t, maxCacheSize, ctrlMaxCacheSize)

	third, err := reused.ReuseForReload(&DnsControllerOption{
		Log:                logrus.New(),
		IpVersionPrefer:    int(IpVersionPrefer_4),
		OptimisticCache:    false,
		OptimisticCacheTtl: 15,
		MaxCacheSize:       7,
	}, nil)
	require.NoError(t, err)
	for name, facade := range map[string]*DnsController{
		"original": controller,
		"second":   reused,
		"third":    third,
	} {
		require.Equal(t, dnsmessage.TypeA, facade.currentQtypePrefer(), name)
		enabled, ttl, maxCacheSize := facade.currentOptimisticCacheConfig()
		require.False(t, enabled, name)
		require.Equal(t, 15, ttl, name)
		require.Equal(t, 7, maxCacheSize, name)
	}
}

func TestDnsController_UpdateRuntimeRejectsInvalidIpVersionPreference(t *testing.T) {
	controller := newTestDnsController()

	err := controller.TryUpdateRuntime(&DnsControllerOption{
		IpVersionPrefer: 12345,
	}, nil)
	require.Error(t, err)

	reused, reuseErr := controller.ReuseForReload(&DnsControllerOption{
		IpVersionPrefer: 12345,
	}, nil)
	require.Error(t, reuseErr)
	require.Nil(t, reused)
}

func TestDnsController_CloneAndRestoreReloadCache(t *testing.T) {
	controller := newTestDnsController()
	now := time.Now()
	answer := &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "reload.example.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    120,
		},
		A: net.IPv4(1, 2, 3, 4),
	}
	cache := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer:           []dnsmessage.RR{answer},
		Deadline:         now.Add(time.Minute),
		OriginalDeadline: now.Add(time.Minute),
	}
	cache.lastAccessNano.Store(now.UnixNano())
	require.NoError(t, cache.PrepackResponse("reload.example.", dnsmessage.TypeA))

	controller.dnsCache.Store("reload.example.1", cache)

	cloned := controller.CloneCacheForReload()
	require.Len(t, cloned, 1)
	clonedCache := cloned["reload.example.1"]
	require.NotNil(t, clonedCache)
	require.Same(t, cache.Answer[0], clonedCache.Answer[0], "reload clone should reuse immutable RR payload")
	require.Equal(t, cache.lastAccessNano.Load(), clonedCache.lastAccessNano.Load(), "reload clone should preserve LRU access time")

	restored := newTestDnsController()
	matchCalls := atomic.Int32{}
	count := restored.RestoreReloadCache(cloned, func(fqdn string) []uint32 {
		matchCalls.Add(1)
		require.Equal(t, "reload.example.", fqdn)
		return []uint32{9, 7}
	}, now)
	require.Equal(t, 1, count)
	require.EqualValues(t, 1, matchCalls.Load())

	value, ok := restored.dnsCache.Load("reload.example.1")
	require.True(t, ok)
	restoredCache := value.(*DnsCache)
	require.Equal(t, []uint32{9, 7}, restoredCache.DomainBitmap)
	require.True(t, restored.HasDnsKnowledge("reload.example.1"))
}

func TestDnsController_RestoreReloadCacheAndProjectCompletesBeforeReturn(t *testing.T) {
	now := time.Now()
	projected := make(chan *DnsCache, 1)
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 9,
		ProjectCacheRoute: func(*DnsCache) []uint32 {
			return []uint32{9}
		},
		CacheAccessCallback: func(cache *DnsCache) error {
			projected <- cache
			return nil
		},
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close()) }()

	entry := &DnsCache{
		RouteOwnerKey: "projected.example.1",
		Deadline:      now.Add(time.Minute),
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "projected.example.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    120,
			},
			A: net.IPv4(203, 0, 113, 9),
		}},
	}

	count, err := controller.RestoreReloadCacheAndProject(map[string]*DnsCache{
		entry.RouteOwnerKey: entry,
	}, nil, now)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	select {
	case cache := <-projected:
		require.NotSame(t, entry, cache)
		require.Equal(t, uint64(9), cache.RouteProjectionEpoch)
		require.Equal(t, []uint32{9}, cache.DomainBitmap)
	case <-time.After(time.Second):
		t.Fatal("synchronous reload projection did not finish before return")
	}
}

func TestDnsController_RestoreReloadCacheRetriesChangedRouteProjection(t *testing.T) {
	type update struct {
		epoch  uint64
		bitmap []uint32
	}

	updates := make(chan update, 2)
	var runtimeProjectionCalls atomic.Int32
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                  logrus.New(),
		RouteProjectionEpoch: 1,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close()) }()

	now := time.Now()
	entry := &DnsCache{
		RouteOwnerKey:        "reload.example.1",
		RouteProjectionEpoch: 1,
		DomainBitmap:         []uint32{7},
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "reload.example.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    120,
			},
			A: net.IPv4(1, 2, 3, 4),
		}},
		Deadline:         now.Add(time.Minute),
		OriginalDeadline: now.Add(time.Minute),
	}

	var matcherCalls atomic.Int32
	count := controller.RestoreReloadCache(map[string]*DnsCache{
		entry.RouteOwnerKey: entry,
	}, func(fqdn string) []uint32 {
		require.Equal(t, "reload.example.", fqdn)
		if matcherCalls.Add(1) == 1 {
			require.NoError(t, controller.TryUpdateRuntime(&DnsControllerOption{
				Log:                  logrus.New(),
				RouteProjectionEpoch: 2,
				ProjectCacheRoute: func(*DnsCache) []uint32 {
					runtimeProjectionCalls.Add(1)
					return []uint32{2}
				},
				CacheAccessCallback: func(cache *DnsCache) error {
					updates <- update{
						epoch:  cache.RouteProjectionEpoch,
						bitmap: slices.Clone(cache.DomainBitmap),
					}
					return nil
				},
			}, nil))
			return []uint32{1}
		}
		return []uint32{2}
	}, now)

	require.Equal(t, 1, count)
	require.EqualValues(t, 1, matcherCalls.Load())
	require.Equal(t, uint64(1), entry.RouteProjectionEpoch)
	require.Equal(t, []uint32{7}, entry.DomainBitmap)

	value, ok := controller.dnsCache.Load(entry.RouteOwnerKey)
	require.True(t, ok)
	restored, ok := value.(*DnsCache)
	require.True(t, ok)
	require.NotSame(t, entry, restored)
	require.Equal(t, uint64(2), restored.RouteProjectionEpoch)
	require.Equal(t, []uint32{2}, restored.DomainBitmap)

	require.EqualValues(t, 1, runtimeProjectionCalls.Load())
	controller.reprojectCachedRoutes(controller.runtime())
	require.EqualValues(t, 1, runtimeProjectionCalls.Load(), "already restored entries must not be reprojected again")

	var bpfUpdate update
	require.Eventually(t, func() bool {
		select {
		case bpfUpdate = <-updates:
			return true
		default:
			return false
		}
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(2), bpfUpdate.epoch)
	require.Equal(t, []uint32{2}, bpfUpdate.bitmap)
	select {
	case stale := <-updates:
		t.Fatalf("reload enqueued a stale or redundant route projection: %+v", stale)
	case <-time.After(100 * time.Millisecond):
	}
}
