/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
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
	dispatcher := newUDPReplyDispatcher(1, 1, 1)
	t.Cleanup(func() {
		dispatcher.close()
		dispatcher.wait()
	})

	endpoint := &UdpEndpoint{}
	started := make(chan struct{})
	release := make(chan struct{})
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

	accepted := make(chan bool, 1)
	go func() {
		accepted <- dispatcher.submit(endpoint, func() {}, nil)
	}()
	select {
	case result := <-accepted:
		t.Fatalf("second submit completed before queue capacity became available: %v", result)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case result := <-accepted:
		if !result {
			t.Fatal("second submit rejected after capacity became available")
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
