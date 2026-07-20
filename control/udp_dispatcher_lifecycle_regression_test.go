// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"sync"
	"testing"
	"time"
)

func TestUDPDispatchersBoundWorkerCount(t *testing.T) {
	ordered := newUDPOrderedDispatcher(defaultUDPOrderedDispatcherWorkerCap+16, 1)
	reply := newUDPReplyDispatcher(defaultUDPReplyDispatcherWorkerCap+16, 1)
	t.Cleanup(func() {
		ordered.close()
		ordered.wait()
		reply.close()
		reply.wait()
	})

	if got := ordered.workerCount; got != defaultUDPOrderedDispatcherWorkerCap {
		t.Fatalf("ordered worker count = %d, want cap %d", got, defaultUDPOrderedDispatcherWorkerCap)
	}
	if got := reply.workerCount; got != defaultUDPReplyDispatcherWorkerCap {
		t.Fatalf("reply worker count = %d, want cap %d", got, defaultUDPReplyDispatcherWorkerCap)
	}
}

func TestUDPOrderedDispatcherQuantumYieldsToColdFlow(t *testing.T) {
	const quantum = 4
	dispatcher := newUDPOrderedDispatcher(1, quantum)
	t.Cleanup(func() { closeUDPOrderedDispatcherForTest(t, dispatcher) })

	hotKey := udpOrderedDispatcherTestKey(101)
	coldKey := udpOrderedDispatcherTestKey(102)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseFirst) }) })

	var mu sync.Mutex
	order := make([]string, 0, quantum*2+2)
	appendOrder := func(value string) {
		mu.Lock()
		order = append(order, value)
		mu.Unlock()
	}
	if !dispatcher.submit(hotKey, func() {
		close(firstStarted)
		<-releaseFirst
		appendOrder("hot")
	}, nil) {
		t.Fatal("submit first hot task")
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first hot task did not start")
	}
	for range quantum * 2 {
		if !dispatcher.submit(hotKey, func() { appendOrder("hot") }, nil) {
			t.Fatal("submit queued hot task")
		}
	}
	coldDone := make(chan struct{})
	if !dispatcher.submit(coldKey, func() {
		appendOrder("cold")
		close(coldDone)
	}, nil) {
		t.Fatal("submit cold task")
	}

	releaseOnce.Do(func() { close(releaseFirst) })
	select {
	case <-coldDone:
	case <-time.After(time.Second):
		t.Fatal("hot flow starved the cold flow")
	}

	mu.Lock()
	defer mu.Unlock()
	coldIndex := -1
	for index, value := range order {
		if value == "cold" {
			coldIndex = index
			break
		}
	}
	if coldIndex < 0 || coldIndex > quantum {
		t.Fatalf("cold task index = %d, want no later than quantum %d; order=%v", coldIndex, quantum, order)
	}
}

func TestUDPOrderedDispatcherCloseWaitsAfterIdleReuse(t *testing.T) {
	dispatcher := newUDPOrderedDispatcher(1, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		dispatcher.close()
		dispatcher.wait()
	})

	firstDone := make(chan struct{})
	if !dispatcher.submit(udpOrderedDispatcherTestKey(111), func() { close(firstDone) }, nil) {
		t.Fatal("submit initial task")
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("initial task did not complete")
	}
	waitForCondition(t, time.Second, "initial queue reclaimed", func() bool {
		return dispatcher.queueCount() == 0
	})

	started := make(chan struct{})
	if !dispatcher.submit(udpOrderedDispatcherTestKey(112), func() {
		close(started)
		<-release
	}, nil) {
		t.Fatal("submit task after idle reuse")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("reactivated task did not start")
	}

	dispatcher.close()
	waitDone := make(chan struct{})
	go func() {
		dispatcher.wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("wait returned while a reactivated worker was still running")
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("wait did not return after the reactivated task completed")
	}
}

func TestUDPReplyDispatcherCloseWaitsAfterIdleReuse(t *testing.T) {
	dispatcher := newUDPReplyDispatcher(1, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		dispatcher.close()
		dispatcher.wait()
	})

	first := &UdpEndpoint{}
	firstDone := make(chan struct{})
	if !dispatcher.submit(first, func() { close(firstDone) }, nil) {
		t.Fatal("submit initial reply")
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("initial reply did not complete")
	}
	waitForCondition(t, time.Second, "initial reply queue reclaimed", func() bool {
		return dispatcher.queueCount() == 0
	})

	second := &UdpEndpoint{}
	started := make(chan struct{})
	if !dispatcher.submit(second, func() {
		close(started)
		<-release
	}, nil) {
		t.Fatal("submit reply after idle reuse")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("reactivated reply did not start")
	}

	dispatcher.close()
	waitDone := make(chan struct{})
	go func() {
		dispatcher.wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("wait returned while a reactivated reply worker was still running")
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("wait did not return after the reactivated reply completed")
	}
}

func TestUDPOrderedDispatcherResetKeepsActiveFlowSerialized(t *testing.T) {
	dispatcher := newUDPOrderedDispatcher(2, 4)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		closeUDPOrderedDispatcherForTest(t, dispatcher)
	})

	key := udpOrderedDispatcherTestKey(121)
	started := make(chan struct{})
	if !dispatcher.submit(key, func() {
		close(started)
		<-release
	}, nil) {
		t.Fatal("submit active task")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("active task did not start")
	}

	dispatcher.reset()
	nextRan := make(chan struct{})
	if !dispatcher.submit(key, func() { close(nextRan) }, nil) {
		t.Fatal("submit same-flow task after reset")
	}
	select {
	case <-nextRan:
		t.Fatal("same-flow task ran concurrently with the pre-reset active task")
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-nextRan:
	case <-time.After(time.Second):
		t.Fatal("same-flow task did not run after the active task completed")
	}
}
