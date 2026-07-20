/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestUDPReplyDispatcherPreservesEndpointFIFOAndRunsIndependentEndpoints(t *testing.T) {
	dispatcher := newUDPReplyDispatcher(2, 1, 8)
	t.Cleanup(func() {
		dispatcher.close()
		dispatcher.wait()
	})

	first := &UdpEndpoint{}
	second := &UdpEndpoint{}
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var orderMu sync.Mutex
	var firstOrder []int

	if !dispatcher.submit(first, func() {
		orderMu.Lock()
		firstOrder = append(firstOrder, 0)
		orderMu.Unlock()
		close(firstStarted)
		<-releaseFirst
	}, nil) {
		t.Fatal("submit first endpoint task")
	}
	if !dispatcher.submit(first, func() {
		orderMu.Lock()
		firstOrder = append(firstOrder, 1)
		orderMu.Unlock()
	}, nil) {
		t.Fatal("submit second first-endpoint task")
	}
	if !dispatcher.submit(second, func() { close(secondStarted) }, nil) {
		t.Fatal("submit independent endpoint task")
	}

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first endpoint did not start")
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("independent endpoint did not run while first endpoint was blocked")
	}
	close(releaseFirst)
	dispatcher.closeInputAndWait(first)
	dispatcher.closeInputAndWait(second)

	orderMu.Lock()
	defer orderMu.Unlock()
	if len(firstOrder) != 2 || firstOrder[0] != 0 || firstOrder[1] != 1 {
		t.Fatalf("first endpoint reply order = %v, want [0 1]", firstOrder)
	}
}

func TestUDPReplyDispatcherAppliesPerEndpointBackpressure(t *testing.T) {
	// Backpressure is provided by UdpEndpoint.replyRuntime.slots, which the
	// production caller (submitReplyWithMode) acquires before invoking the
	// dispatcher. Test that path end-to-end with a capacity-1 runtime.
	dispatcher := newUDPReplyDispatcher(1, 1, udpEndpointReplyQueueSize)
	t.Cleanup(func() {
		dispatcher.close()
		dispatcher.wait()
	})

	endpoint := &UdpEndpoint{
		replyRuntime: newUdpEndpointReplyRuntime(dispatcher, newControlPlaneDrainTracker(), 1),
	}
	started := make(chan struct{})
	release := make(chan struct{})
	endpoint.handler = func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
		close(started)
		<-release
		return nil
	}

	// First reply takes the only runtime slot and blocks inside the handler.
	first := udpEndpointReply{data: []byte("first"), from: netip.MustParseAddrPort("198.51.100.1:1")}
	if accepted, _ := endpoint.submitReplyWithMode(first, nil, false); !accepted {
		t.Fatal("first submit rejected")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocking task did not start")
	}

	// Second reply must block on the runtime slot, not be accepted.
	secondAccepted := make(chan bool, 1)
	go func() {
		accepted, _ := endpoint.submitReplyWithMode(
			udpEndpointReply{data: []byte("second"), from: netip.MustParseAddrPort("198.51.100.1:1")},
			nil, false)
		secondAccepted <- accepted
	}()
	select {
	case result := <-secondAccepted:
		t.Fatalf("second submit completed before slot became available: %v", result)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case result := <-secondAccepted:
		if !result {
			t.Fatal("second submit rejected after slot became available")
		}
	case <-time.After(time.Second):
		t.Fatal("second submit remained blocked after first task completed")
	}
	dispatcher.closeInputAndWait(endpoint)
}

func TestUDPReplyDispatcherCloseInputDrainsAcceptedReplies(t *testing.T) {
	dispatcher := newUDPReplyDispatcher(1, 2, 8)
	t.Cleanup(func() {
		dispatcher.close()
		dispatcher.wait()
	})

	endpoint := &UdpEndpoint{}
	var mu sync.Mutex
	var ran []int
	var discarded []int
	for index := range 5 {
		index := index
		if !dispatcher.submit(endpoint, func() {
			mu.Lock()
			ran = append(ran, index)
			mu.Unlock()
		}, func() {
			mu.Lock()
			discarded = append(discarded, index)
			mu.Unlock()
		}) {
			t.Fatalf("submit task %d", index)
		}
	}
	dispatcher.closeInputAndWait(endpoint)
	if dispatcher.queueCount() != 0 {
		t.Fatalf("queue count after normal endpoint drain = %d, want 0", dispatcher.queueCount())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 5 {
		t.Fatalf("normal endpoint drain ran %d tasks, want 5", len(ran))
	}
	if len(discarded) != 0 {
		t.Fatalf("normal endpoint drain discarded replies = %v, want none", discarded)
	}
	for index := range ran {
		if ran[index] != index {
			t.Fatalf("normal endpoint reply order = %v, want FIFO", ran)
		}
	}
}

func TestUDPReplyDispatcherAbortReleasesPendingRepliesOnce(t *testing.T) {
	dispatcher := newUDPReplyDispatcher(1, 4, 8)
	t.Cleanup(func() {
		dispatcher.close()
		dispatcher.wait()
	})

	endpoint := &UdpEndpoint{}
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var ran []int
	discarded := make(map[int]int)
	if !dispatcher.submit(endpoint, func() {
		mu.Lock()
		ran = append(ran, 0)
		mu.Unlock()
		close(started)
		<-release
	}, nil) {
		t.Fatal("submit running task")
	}
	for index := 1; index <= 3; index++ {
		index := index
		if !dispatcher.submit(endpoint, func() {
			mu.Lock()
			ran = append(ran, index)
			mu.Unlock()
		}, func() {
			mu.Lock()
			discarded[index]++
			mu.Unlock()
		}) {
			t.Fatalf("submit pending task %d", index)
		}
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("running task did not start")
	}

	dispatcher.abortInput(endpoint)
	close(release)
	dispatcher.closeInputAndWait(endpoint)

	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 1 || ran[0] != 0 {
		t.Fatalf("abort ran replies = %v, want [0]", ran)
	}
	for index := 1; index <= 3; index++ {
		if discarded[index] != 1 {
			t.Fatalf("discarded[%d] = %d, want 1", index, discarded[index])
		}
	}
}

func TestUDPReplyDispatcherCloseReleasesPendingRepliesOnce(t *testing.T) {
	dispatcher := newUDPReplyDispatcher(1, 1, 8)
	endpoint := &UdpEndpoint{}
	started := make(chan struct{})
	release := make(chan struct{})
	if !dispatcher.submit(endpoint, func() {
		close(started)
		<-release
	}, nil) {
		t.Fatal("submit running task")
	}

	var mu sync.Mutex
	discarded := 0
	ranPending := 0
	if !dispatcher.submit(endpoint, func() {
		mu.Lock()
		ranPending++
		mu.Unlock()
	}, func() {
		mu.Lock()
		discarded++
		mu.Unlock()
	}) {
		t.Fatal("submit pending task")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("running task did not start")
	}

	dispatcher.close()
	close(release)
	closed := make(chan struct{})
	go func() {
		dispatcher.wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("dispatcher close did not wait for its active worker")
	}
	mu.Lock()
	defer mu.Unlock()
	if discarded != 1 {
		t.Fatalf("pending reply discard count = %d, want 1", discarded)
	}
	if ranPending != 0 {
		t.Fatalf("pending reply run count = %d, want 0 after dispatcher close", ranPending)
	}
}

func TestUDPReplyDispatcherRepeatedGenerationLifecycleReclaimsWorkers(t *testing.T) {
	for generation := 0; generation < 128; generation++ {
		dispatcher := newUDPReplyDispatcher(2, 4, 4)
		endpoint := &UdpEndpoint{}
		ran := make(chan struct{}, 1)
		if !dispatcher.submit(endpoint, func() { ran <- struct{}{} }, nil) {
			t.Fatalf("generation %d submit reply", generation)
		}
		dispatcher.closeInputAndWait(endpoint)
		select {
		case <-ran:
		case <-time.After(time.Second):
			t.Fatalf("generation %d reply did not run", generation)
		}
		if got := dispatcher.queueCount(); got != 0 {
			t.Fatalf("generation %d queue count = %d, want 0", generation, got)
		}
		dispatcher.close()
		dispatcher.wait()
	}
}

// TestUDPReplyDispatcherIdleConvoySelfExits guards against the goroutine leak
// where a convoy blocks forever on select after its endpoint stops receiving
// replies. The idle timer must retire the convoy and remove the queue so the
// next reply creates a fresh one.
func TestUDPReplyDispatcherIdleConvoySelfExits(t *testing.T) {
	dispatcher := newUDPReplyDispatcher(1, 1, 4)
	t.Cleanup(func() {
		dispatcher.close()
		dispatcher.wait()
	})

	endpoint := &UdpEndpoint{}
	if !dispatcher.submit(endpoint, func() {}, nil) {
		t.Fatal("submit initial reply")
	}
	// The convoy should self-exit after the aging idle window with no further
	// traffic. Poll queueCount rather than sleeping for the exact timeout.
	deadline := time.Now().Add(UdpTaskPoolAgingTime * 10)
	for time.Now().Before(deadline) {
		if dispatcher.queueCount() == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := dispatcher.queueCount(); got != 0 {
		t.Fatalf("idle convoy did not self-exit: queueCount = %d", got)
	}

	// A fresh reply after idle retirement must create a new queue/convoy.
	ran := make(chan struct{}, 1)
	if !dispatcher.submit(endpoint, func() { ran <- struct{}{} }, nil) {
		t.Fatal("submit after idle retirement")
	}
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("reply did not run after idle retirement")
	}
}

// TestUDPReplyDispatcherReleaseAndCleanupInvokesDiscard regression-tests the
// fix where releaseAndCleanup drained pending overflow without calling each
// task's discard hook, leaking the caller's runtime.slots / WaitGroup /
// drain-tracker bookkeeping.
func TestUDPReplyDispatcherReleaseAndCleanupInvokesDiscard(t *testing.T) {
	dispatcher := newUDPReplyDispatcher(1, 1, 8)
	t.Cleanup(func() {
		dispatcher.close()
		dispatcher.wait()
	})

	endpoint := &UdpEndpoint{}
	started := make(chan struct{})
	release := make(chan struct{})
	// Block the single convoy on the first task so subsequent submits
	// accumulate in the queue before we trigger abortInput.
	if !dispatcher.submit(endpoint, func() {
		close(started)
		<-release
	}, nil) {
		t.Fatal("submit blocking task")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocking task did not start")
	}

	var discardMu sync.Mutex
	discarded := make(map[int]int)
	for index := 1; index <= 4; index++ {
		index := index
		if !dispatcher.submit(endpoint, func() {}, func() {
			discardMu.Lock()
			discarded[index]++
			discardMu.Unlock()
		}) {
			t.Fatalf("submit pending task %d", index)
		}
	}

	// abortInput drains pending and must invoke each discard exactly once.
	dispatcher.abortInput(endpoint)
	close(release)
	dispatcher.closeInputAndWait(endpoint)

	discardMu.Lock()
	defer discardMu.Unlock()
	for index := 1; index <= 4; index++ {
		if discarded[index] != 1 {
			t.Fatalf("discarded[%d] = %d, want 1", index, discarded[index])
		}
	}
}
