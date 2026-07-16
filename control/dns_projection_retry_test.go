/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func TestDnsCacheUpdateRetriesFailedProjection(t *testing.T) {
	controller := newTestDnsController()
	var attempts atomic.Int32
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 7
		rt.newCache = func(string, []dnsmessage.RR, []dnsmessage.RR, []dnsmessage.RR, time.Time, time.Time) (*DnsCache, error) {
			return &DnsCache{}, nil
		}
		rt.cacheAccessCallback = func(*DnsCache) error {
			if attempts.Add(1) == 1 {
				return stderrors.New("initial projection failure")
			}
			return nil
		}
	})
	t.Cleanup(func() { _ = controller.Close() })

	if err := controller.UpdateDnsCacheTtl("retry-write.example", dnsmessage.TypeA, nil, nil, nil, 60); err == nil {
		t.Fatal("UpdateDnsCacheTtl() error = nil, want original projection error")
	}
	requireProjectionEventually(t, time.Second, func() bool {
		return attempts.Load() == 2
	})
}

func TestBpfProjectionWorkerFollowsConsecutiveReloadFacades(t *testing.T) {
	var firstCalls atomic.Int32
	controller, err := NewDnsController(nil, &DnsControllerOption{
		RouteProjectionEpoch: 1,
		CacheAccessCallback: func(*DnsCache) error {
			firstCalls.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewDnsController() error = %v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })

	firstCache := &DnsCache{RouteOwnerKey: "first.example.:1", RouteProjectionEpoch: 1}
	controller.dnsCache.Store(firstCache.RouteOwnerKey, firstCache)
	controller.triggerBpfUpdateIfNeeded(firstCache, time.Now())
	requireProjectionEventually(t, time.Second, func() bool {
		return firstCalls.Load() == 1
	})

	var thirdCalls atomic.Int32
	secondFacade, err := controller.ReuseForReload(&DnsControllerOption{
		RouteProjectionEpoch: 2,
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
	}, nil)
	if err != nil {
		t.Fatalf("first ReuseForReload() error = %v", err)
	}
	thirdFacade, err := secondFacade.ReuseForReload(&DnsControllerOption{
		RouteProjectionEpoch: 3,
		CacheAccessCallback: func(*DnsCache) error {
			thirdCalls.Add(1)
			return nil
		},
	}, nil)
	if err != nil {
		t.Fatalf("second ReuseForReload() error = %v", err)
	}

	thirdCache := &DnsCache{RouteOwnerKey: "third.example.:1", RouteProjectionEpoch: 3}
	thirdFacade.dnsCache.Store(thirdCache.RouteOwnerKey, thirdCache)
	thirdFacade.triggerBpfUpdateIfNeeded(thirdCache, time.Now())
	requireProjectionEventually(t, time.Second, func() bool {
		return thirdCalls.Load() == 1
	})
}

func TestBpfProjectionCompletesBeforeEvictionDeletesCache(t *testing.T) {
	controller := newTestDnsController()
	cache := &DnsCache{RouteOwnerKey: "evict.example.:1", RouteProjectionEpoch: 7}
	controller.dnsCache.Store(cache.RouteOwnerKey, cache)
	started := make(chan struct{})
	releaseProjection := make(chan struct{})
	evicted := make(chan struct{})
	var projectionFinished atomic.Bool
	var deletionAfterProjection atomic.Bool
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 7
		rt.cacheAccessCallback = func(*DnsCache) error {
			close(started)
			<-releaseProjection
			projectionFinished.Store(true)
			return nil
		}
		rt.cacheDeleteCallback = func(string, *DnsCache) error {
			deletionAfterProjection.Store(projectionFinished.Load())
			return nil
		}
	})
	t.Cleanup(func() { _ = controller.Close() })

	controller.triggerBpfUpdateIfNeeded(cache, time.Now())
	<-started
	go func() {
		controller.evictDnsRespCacheIfSame(cache.RouteOwnerKey, cache)
		close(evicted)
	}()
	select {
	case <-evicted:
		t.Fatal("eviction completed while projection callback was in flight")
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseProjection)
	select {
	case <-evicted:
	case <-time.After(time.Second):
		t.Fatal("eviction did not complete after projection callback")
	}
	if !deletionAfterProjection.Load() {
		t.Fatal("cache deletion callback ran before the in-flight projection completed")
	}
	if _, ok := controller.dnsCache.Load(cache.RouteOwnerKey); ok {
		t.Fatal("evicted cache remained in dns cache")
	}
}

func TestBpfProjectionRetryIntentSurvivesPrimaryQueueSaturation(t *testing.T) {
	controller := newTestDnsController()
	blocker := &DnsCache{RouteProjectionEpoch: 7}
	retryCache := &DnsCache{RouteOwnerKey: "saturated.example.:1", RouteProjectionEpoch: 7}
	controller.dnsCache.Store(retryCache.RouteOwnerKey, retryCache)
	started := make(chan struct{})
	releasePrimary := make(chan struct{})
	var retryCalls atomic.Int32
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 7
		rt.cacheAccessCallback = func(cache *DnsCache) error {
			switch cache {
			case blocker:
				close(started)
				<-releasePrimary
			case retryCache:
				retryCalls.Add(1)
			}
			return nil
		}
	})
	t.Cleanup(func() { _ = controller.Close() })

	controller.triggerBpfUpdateIfNeeded(blocker, time.Now())
	<-started
	for range 1024 {
		controller.triggerBpfUpdateIfNeeded(&DnsCache{RouteProjectionEpoch: 7}, time.Now())
	}
	controller.scheduleBpfProjectionRetry(&bpfUpdateTask{
		cache:                retryCache,
		cacheKey:             retryCache.RouteOwnerKey,
		runtime:              controller.runtime(),
		routeProjectionEpoch: 7,
	})
	close(releasePrimary)
	requireProjectionEventually(t, 2*time.Second, func() bool {
		return retryCalls.Load() == 1
	})
}

func TestBpfProjectionRetriesFailedCacheWithoutLaterLookup(t *testing.T) {
	controller := newTestDnsController()
	cache := &DnsCache{RouteOwnerKey: "retry.example.:1", RouteProjectionEpoch: 7}
	controller.dnsCache.Store(cache.RouteOwnerKey, cache)
	var attempts atomic.Int32
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 7
		rt.cacheAccessCallback = func(got *DnsCache) error {
			if got != cache {
				t.Errorf("projection cache = %p, want %p", got, cache)
			}
			if attempts.Add(1) == 1 {
				return stderrors.New("transient projection failure")
			}
			return nil
		}
	})
	t.Cleanup(func() { _ = controller.Close() })

	controller.triggerBpfUpdateIfNeeded(cache, time.Now())
	requireProjectionEventually(t, time.Second, func() bool {
		return attempts.Load() == 2
	})
}

func TestBpfProjectionRetryDropsReplacedCache(t *testing.T) {
	controller := newTestDnsController()
	cache := &DnsCache{RouteOwnerKey: "replace.example.:1", RouteProjectionEpoch: 7}
	controller.dnsCache.Store(cache.RouteOwnerKey, cache)
	var attempts atomic.Int32
	started := make(chan struct{})
	releaseFailure := make(chan struct{})
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 7
		rt.cacheAccessCallback = func(*DnsCache) error {
			if attempts.Add(1) == 1 {
				close(started)
				<-releaseFailure
				return stderrors.New("transient projection failure")
			}
			return nil
		}
	})
	t.Cleanup(func() { _ = controller.Close() })

	controller.triggerBpfUpdateIfNeeded(cache, time.Now())
	<-started
	controller.dnsCache.Store(cache.RouteOwnerKey, &DnsCache{RouteOwnerKey: cache.RouteOwnerKey, RouteProjectionEpoch: 7})
	close(releaseFailure)
	time.Sleep(3 * bpfProjectionRetryBaseDelay)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("projection attempts = %d, want stale retry dropped", got)
	}
}

func TestBpfProjectionRetryDropsOldEpochAndReprojectsCurrentEpoch(t *testing.T) {
	controller := newTestDnsController()
	cache := &DnsCache{RouteOwnerKey: "reload.example.:1", RouteProjectionEpoch: 7}
	controller.dnsCache.Store(cache.RouteOwnerKey, cache)
	var oldAttempts atomic.Int32
	var newAttempts atomic.Int32
	started := make(chan struct{})
	finished := make(chan struct{})
	releaseFailure := make(chan struct{})
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 7
		rt.cacheAccessCallback = func(*DnsCache) error {
			if oldAttempts.Add(1) == 1 {
				close(started)
				<-releaseFailure
				close(finished)
			}
			return stderrors.New("old epoch projection failure")
		}
	})
	t.Cleanup(func() { _ = controller.Close() })

	controller.triggerBpfUpdateIfNeeded(cache, time.Now())
	<-started
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 8
		rt.projectCacheRoute = func(*DnsCache) []uint32 { return []uint32{8} }
		rt.cacheAccessCallback = func(*DnsCache) error {
			newAttempts.Add(1)
			return nil
		}
	})
	close(releaseFailure)
	<-finished
	controller.reprojectCachedRoutes(controller.runtime())

	requireProjectionEventually(t, time.Second, func() bool {
		return newAttempts.Load() == 1
	})
	time.Sleep(3 * bpfProjectionRetryBaseDelay)
	if got := oldAttempts.Load(); got != 1 {
		t.Fatalf("old epoch projection attempts = %d, want stale retry dropped", got)
	}
}

func TestBpfProjectionCloseSuppressesFailedRetry(t *testing.T) {
	controller := newTestDnsController()
	cache := &DnsCache{RouteOwnerKey: "close.example.:1", RouteProjectionEpoch: 7}
	controller.dnsCache.Store(cache.RouteOwnerKey, cache)
	var attempts atomic.Int32
	started := make(chan struct{})
	releaseFailure := make(chan struct{})
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 7
		rt.cacheAccessCallback = func(*DnsCache) error {
			if attempts.Add(1) == 1 {
				close(started)
				<-releaseFailure
			}
			return stderrors.New("projection failure during close")
		}
	})

	controller.triggerBpfUpdateIfNeeded(cache, time.Now())
	<-started
	done := make(chan struct{})
	go func() {
		_ = controller.Close()
		close(done)
	}()
	requireProjectionEventually(t, time.Second, controller.bpfUpdateClosed.Load)
	close(releaseFailure)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DnsController.Close() did not finish")
	}
	time.Sleep(3 * bpfProjectionRetryBaseDelay)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("projection attempts after close = %d, want retry suppressed", got)
	}
}

func TestBpfProjectionCloseDropsDueRetry(t *testing.T) {
	controller := newTestDnsController()
	first := &DnsCache{RouteProjectionEpoch: 7}
	blocker := &DnsCache{RouteProjectionEpoch: 7}
	retryCache := &DnsCache{RouteOwnerKey: "due-close.example.:1", RouteProjectionEpoch: 7}
	controller.dnsCache.Store(retryCache.RouteOwnerKey, retryCache)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	blockerStarted := make(chan struct{})
	releaseBlocker := make(chan struct{})
	var retryCalls atomic.Int32
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 7
		rt.cacheAccessCallback = func(cache *DnsCache) error {
			switch cache {
			case first:
				close(firstStarted)
				<-releaseFirst
			case blocker:
				close(blockerStarted)
				<-releaseBlocker
			case retryCache:
				retryCalls.Add(1)
			}
			return nil
		}
	})
	t.Cleanup(func() { _ = controller.Close() })

	controller.triggerBpfUpdateIfNeeded(first, time.Now())
	<-firstStarted
	controller.scheduleBpfProjectionRetry(&bpfUpdateTask{
		cache:                retryCache,
		cacheKey:             retryCache.RouteOwnerKey,
		runtime:              controller.runtime(),
		routeProjectionEpoch: 7,
		retryAttempt:         bpfProjectionRetryLimit - 1,
	})
	close(releaseFirst)
	requireProjectionEventually(t, time.Second, func() bool {
		controller.bpfRetryMu.Lock()
		defer controller.bpfRetryMu.Unlock()
		return len(controller.bpfRetryPending) == 0
	})

	if !controller.sendBpfUpdateTask(&bpfUpdateTask{
		cache:                blocker,
		runtime:              controller.runtime(),
		routeProjectionEpoch: 7,
	}) {
		t.Fatal("sendBpfUpdateTask() = false, want blocker task queued")
	}
	<-blockerStarted
	time.Sleep(bpfProjectionRetryDelay(bpfProjectionRetryLimit) + bpfProjectionRetryBaseDelay)

	closed := make(chan struct{})
	go func() {
		_ = controller.Close()
		close(closed)
	}()
	requireProjectionEventually(t, time.Second, controller.bpfUpdateClosed.Load)
	close(releaseBlocker)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("DnsController.Close() did not finish")
	}
	if got := retryCalls.Load(); got != 0 {
		t.Fatalf("due retry callback count = %d, want 0 after close", got)
	}
}

func TestDnsCachePublicationWaitsForReloadEpoch(t *testing.T) {
	projectionStarted := make(chan struct{})
	releaseProjection := make(chan struct{})
	var oldCalls atomic.Int32
	var newCalls atomic.Int32
	controller, err := NewDnsController(nil, &DnsControllerOption{
		RouteProjectionEpoch: 7,
		NewCache: func(string, []dnsmessage.RR, []dnsmessage.RR, []dnsmessage.RR, time.Time, time.Time) (*DnsCache, error) {
			return &DnsCache{}, nil
		},
		CacheAccessCallback: func(*DnsCache) error {
			if oldCalls.Add(1) == 1 {
				close(projectionStarted)
				<-releaseProjection
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewDnsController() error = %v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })

	updateDone := make(chan error, 1)
	go func() {
		updateDone <- controller.UpdateDnsCacheTtl("publication.example", dnsmessage.TypeA, nil, nil, nil, 60)
	}()
	<-projectionStarted

	type reloadResult struct {
		controller *DnsController
		err        error
	}
	reloadDone := make(chan reloadResult, 1)
	go func() {
		next, reloadErr := controller.ReuseForReload(&DnsControllerOption{
			RouteProjectionEpoch: 8,
			NewCache: func(string, []dnsmessage.RR, []dnsmessage.RR, []dnsmessage.RR, time.Time, time.Time) (*DnsCache, error) {
				return &DnsCache{}, nil
			},
			ProjectCacheRoute: func(*DnsCache) []uint32 { return []uint32{8} },
			CacheAccessCallback: func(*DnsCache) error {
				newCalls.Add(1)
				return nil
			},
		}, nil)
		reloadDone <- reloadResult{controller: next, err: reloadErr}
	}()
	select {
	case result := <-reloadDone:
		t.Fatalf("ReuseForReload() returned early: controller=%v, err=%v", result.controller, result.err)
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseProjection)
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatalf("UpdateDnsCacheTtl() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UpdateDnsCacheTtl() did not finish")
	}
	var reloaded *DnsController
	select {
	case result := <-reloadDone:
		if result.err != nil {
			t.Fatalf("ReuseForReload() error = %v", result.err)
		}
		reloaded = result.controller
	case <-time.After(time.Second):
		t.Fatal("ReuseForReload() did not finish")
	}
	if reloaded == nil || reloaded.runtime().routeProjectionEpoch != 8 {
		t.Fatalf("reloaded runtime epoch = %v, want 8", reloaded.runtime())
	}
	requireProjectionEventually(t, time.Second, func() bool {
		return newCalls.Load() == 1
	})
}

func requireProjectionEventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true before timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
