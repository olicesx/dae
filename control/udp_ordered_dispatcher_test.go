/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func udpOrderedDispatcherTestKey(index int) UdpFlowKey {
	src := netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{198, 51, byte(index >> 8), byte(index)}),
		uint16(10000+index%40000),
	)
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 1}), 27015)
	return NewUdpFlowKey(src, dst)
}

func closeUDPOrderedDispatcherForTest(t *testing.T, dispatcher *udpOrderedDispatcher) {
	t.Helper()
	dispatcher.close()
	select {
	case <-dispatcher.done:
	case <-time.After(time.Second):
		t.Fatal("UDP ordered dispatcher workers did not stop")
	}
}

func TestUDPOrderedDispatcherHighCardinalityUsesFixedWorkersWithoutDrops(t *testing.T) {
	dispatcher := newUDPOrderedDispatcher(3, 8)
	t.Cleanup(func() { closeUDPOrderedDispatcherForTest(t, dispatcher) })

	const (
		flowCount   = 256
		tasksPerKey = 4
	)
	want := int32(flowCount * tasksPerKey)
	var completed atomic.Int32
	var discarded atomic.Int32
	for flow := range flowCount {
		key := udpOrderedDispatcherTestKey(flow)
		for range tasksPerKey {
			if !dispatcher.submit(key, func() {
				completed.Add(1)
			}, func() {
				discarded.Add(1)
				completed.Add(1)
			}) {
				t.Fatalf("submit for flow %d returned false", flow)
			}
		}
	}

	waitForCondition(t, time.Second, "all high-cardinality UDP tasks complete", func() bool {
		return completed.Load() == want
	})
	if dispatcher.workerCount != 3 {
		t.Fatalf("worker count = %d, want 3", dispatcher.workerCount)
	}
	if discarded.Load() != 0 {
		t.Fatalf("discarded tasks = %d, want 0", discarded.Load())
	}
	waitForCondition(t, time.Second, "idle UDP queues reclaimed", func() bool {
		return dispatcher.queueCount() == 0
	})
}

func TestUDPOrderedDispatcherPreservesPerFlowFIFO(t *testing.T) {
	dispatcher := newUDPOrderedDispatcher(3, 8)
	t.Cleanup(func() { closeUDPOrderedDispatcherForTest(t, dispatcher) })

	const total = 256
	key := udpOrderedDispatcherTestKey(1)
	var mu sync.Mutex
	got := make([]int, 0, total)
	for index := range total {
		index := index
		if !dispatcher.submit(key, func() {
			mu.Lock()
			got = append(got, index)
			mu.Unlock()
		}, nil) {
			t.Fatalf("submit %d returned false", index)
		}
	}

	waitForCondition(t, time.Second, "FIFO tasks complete", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == total
	})
	mu.Lock()
	defer mu.Unlock()
	for index, actual := range got {
		if actual != index {
			t.Fatalf("FIFO task[%d] = %d, want %d", index, actual, index)
		}
	}
}

func TestUDPOrderedDispatcherRunsIndependentFlowsConcurrently(t *testing.T) {
	dispatcher := newUDPOrderedDispatcher(2, 4)
	t.Cleanup(func() { closeUDPOrderedDispatcherForTest(t, dispatcher) })

	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var completed atomic.Int32
	for flow := range 2 {
		if !dispatcher.submit(udpOrderedDispatcherTestKey(flow), func() {
			started <- struct{}{}
			<-release
			completed.Add(1)
		}, nil) {
			t.Fatalf("submit flow %d returned false", flow)
		}
	}

	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("independent UDP flow did not receive its own worker")
		}
	}
	releaseOnce.Do(func() { close(release) })
	waitForCondition(t, time.Second, "independent flow tasks complete", func() bool {
		return completed.Load() == 2
	})
}

func TestUDPOrderedDispatcherQuantumPreventsHotFlowStarvation(t *testing.T) {
	const quantum = 4
	dispatcher := newUDPOrderedDispatcher(1, quantum)
	t.Cleanup(func() { closeUDPOrderedDispatcherForTest(t, dispatcher) })

	hotKey := udpOrderedDispatcherTestKey(1)
	coldKey := udpOrderedDispatcherTestKey(2)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseFirst) }) })
	coldDone := make(chan struct{})
	var mu sync.Mutex
	var order []string

	if !dispatcher.submit(hotKey, func() {
		close(firstStarted)
		<-releaseFirst
		mu.Lock()
		order = append(order, "hot-0")
		mu.Unlock()
	}, nil) {
		t.Fatal("submit first hot task returned false")
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first hot task did not start")
	}
	for index := 1; index <= quantum*2; index++ {
		if !dispatcher.submit(hotKey, func() {
			mu.Lock()
			order = append(order, "hot")
			mu.Unlock()
		}, nil) {
			t.Fatalf("submit hot task %d returned false", index)
		}
	}
	if !dispatcher.submit(coldKey, func() {
		mu.Lock()
		order = append(order, "cold")
		mu.Unlock()
		close(coldDone)
	}, nil) {
		t.Fatal("submit cold task returned false")
	}

	releaseOnce.Do(func() { close(releaseFirst) })
	select {
	case <-coldDone:
	case <-time.After(time.Second):
		t.Fatal("hot flow starved the cold flow")
	}
	waitForCondition(t, time.Second, "all fairness tasks complete", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(order) == quantum*2+2
	})
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

func TestUDPOrderedDispatcherCloseDiscardsQueuedWorkAndStops(t *testing.T) {
	dispatcher := newUDPOrderedDispatcher(1, 1)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseFirst) })
		closeUDPOrderedDispatcherForTest(t, dispatcher)
	})
	firstFinished := make(chan struct{})
	queuedDiscarded := make(chan struct{})
	var queuedRan atomic.Bool
	key := udpOrderedDispatcherTestKey(1)

	if !dispatcher.submit(key, func() {
		close(firstStarted)
		<-releaseFirst
		close(firstFinished)
	}, nil) {
		t.Fatal("submit first task returned false")
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first task did not start")
	}
	if !dispatcher.submit(key, func() {
		queuedRan.Store(true)
	}, func() {
		close(queuedDiscarded)
	}) {
		t.Fatal("submit queued task returned false")
	}

	dispatcher.close()
	select {
	case <-queuedDiscarded:
	case <-time.After(time.Second):
		t.Fatal("Close did not discard queued work")
	}
	if dispatcher.submit(key, func() {}, nil) {
		t.Fatal("submit succeeded after Close")
	}
	releaseOnce.Do(func() { close(releaseFirst) })
	select {
	case <-firstFinished:
	case <-time.After(time.Second):
		t.Fatal("active task did not finish")
	}
	closeUDPOrderedDispatcherForTest(t, dispatcher)
	if queuedRan.Load() {
		t.Fatal("queued task ran after Close instead of being discarded")
	}
}

func TestUDPOrderedDispatcherResetDiscardsQueuedWorkAndContinues(t *testing.T) {
	dispatcher := newUDPOrderedDispatcher(1, 1)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseFirst) })
		closeUDPOrderedDispatcherForTest(t, dispatcher)
	})
	queuedDiscarded := make(chan struct{})
	continued := make(chan struct{})
	var queuedRan atomic.Bool
	key := udpOrderedDispatcherTestKey(1)

	if !dispatcher.submit(key, func() {
		close(firstStarted)
		<-releaseFirst
	}, nil) {
		t.Fatal("submit active task returned false")
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("active task did not start")
	}
	if !dispatcher.submit(key, func() {
		queuedRan.Store(true)
	}, func() {
		close(queuedDiscarded)
	}) {
		t.Fatal("submit queued task returned false")
	}

	dispatcher.reset()
	select {
	case <-queuedDiscarded:
	case <-time.After(time.Second):
		t.Fatal("Reset did not discard queued work")
	}
	releaseOnce.Do(func() { close(releaseFirst) })
	if !dispatcher.submit(udpOrderedDispatcherTestKey(2), func() {
		close(continued)
	}, nil) {
		t.Fatal("submit after reset returned false")
	}
	select {
	case <-continued:
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not accept work after reset")
	}
	if queuedRan.Load() {
		t.Fatal("queued task ran after reset")
	}
}

func TestUDPOrderedDispatcherConcurrentSubmitAndCloseSettlesAcceptedTasks(t *testing.T) {
	dispatcher := newUDPOrderedDispatcher(4, 8)
	const (
		producers        = 16
		tasksPerProducer = 128
	)
	start := make(chan struct{})
	firstAccepted := make(chan struct{})
	var firstAcceptedOnce sync.Once
	var accepted atomic.Int32
	var settled atomic.Int32
	var producersWG sync.WaitGroup
	for producer := range producers {
		producersWG.Add(1)
		go func(producer int) {
			defer producersWG.Done()
			<-start
			for task := range tasksPerProducer {
				if dispatcher.submit(udpOrderedDispatcherTestKey(producer*tasksPerProducer+task), func() {
					settled.Add(1)
				}, func() {
					settled.Add(1)
				}) {
					accepted.Add(1)
					firstAcceptedOnce.Do(func() { close(firstAccepted) })
				}
			}
		}(producer)
	}
	close(start)
	select {
	case <-firstAccepted:
	case <-time.After(time.Second):
		t.Fatal("concurrent submit did not accept a task")
	}
	dispatcher.close()
	producersWG.Wait()
	dispatcher.wait()
	if got, want := settled.Load(), accepted.Load(); got != want {
		t.Fatalf("settled accepted tasks = %d, want %d", got, want)
	}
}

func TestUDPOrderedDispatcherCloseDoesNotAffectPeerGeneration(t *testing.T) {
	oldDispatcher := newUDPOrderedDispatcher(1, 1)
	newDispatcher := newUDPOrderedDispatcher(1, 1)
	oldDispatcher.close()
	closeUDPOrderedDispatcherForTest(t, oldDispatcher)
	t.Cleanup(func() { closeUDPOrderedDispatcherForTest(t, newDispatcher) })

	done := make(chan struct{})
	if !newDispatcher.submit(udpOrderedDispatcherTestKey(2), func() {
		close(done)
	}, nil) {
		t.Fatal("new generation dispatcher rejected a task after old generation closed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("new generation dispatcher did not run its task")
	}
}

func TestControlPlaneStopRoutingEpochExecutionDiscardsQueuedUDPOrderedIngress(t *testing.T) {
	dispatcher := newUDPOrderedDispatcher(1, 1)
	plane := &ControlPlane{udpOrderedDispatcher: dispatcher}
	key := udpOrderedDispatcherTestKey(1)
	activeStarted := make(chan struct{})
	releaseActive := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseActive) })
		dispatcher.close()
		select {
		case <-dispatcher.done:
		case <-time.After(time.Second):
			t.Error("UDP ordered dispatcher did not stop during cleanup")
		}
	})
	queuedDiscarded := make(chan struct{})
	var queuedRan atomic.Bool

	if !plane.udpIngressAdmission.tryAcquire() {
		t.Fatal("acquire active ingress lease = false")
	}
	if !plane.submitOrderedUDPIngress(key, func() {
		close(activeStarted)
		<-releaseActive
		plane.udpIngressAdmission.release()
	}, func() {
		plane.udpIngressAdmission.release()
	}) {
		t.Fatal("submit active ingress task returned false")
	}
	select {
	case <-activeStarted:
	case <-time.After(time.Second):
		t.Fatal("active ingress task did not start")
	}

	if !plane.udpIngressAdmission.tryAcquire() {
		t.Fatal("acquire queued ingress lease = false")
	}
	if !plane.submitOrderedUDPIngress(key, func() {
		queuedRan.Store(true)
		plane.udpIngressAdmission.release()
	}, func() {
		close(queuedDiscarded)
		plane.udpIngressAdmission.release()
	}) {
		t.Fatal("submit queued ingress task returned false")
	}

	stopped := make(chan struct{})
	go func() {
		plane.StopRoutingEpochExecution()
		close(stopped)
	}()
	select {
	case <-queuedDiscarded:
	case <-time.After(time.Second):
		t.Fatal("StopRoutingEpochExecution did not discard queued ingress task")
	}
	select {
	case <-stopped:
		t.Fatal("StopRoutingEpochExecution returned before active ingress task released")
	default:
	}
	releaseOnce.Do(func() { close(releaseActive) })
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("StopRoutingEpochExecution did not complete after active task release")
	}
	dispatcher.wait()
	if queuedRan.Load() {
		t.Fatal("queued ingress task ran after dispatcher closure")
	}
}

func TestControlPlaneAbortConnectionsDiscardsQueuedUDPOrderedIngress(t *testing.T) {
	exerciseControlPlaneUDPOrderedDispatcherShutdown(t, func(plane *ControlPlane) error {
		return plane.AbortConnections()
	})
}

func TestControlPlaneCloseDiscardsQueuedUDPOrderedIngress(t *testing.T) {
	exerciseControlPlaneUDPOrderedDispatcherShutdown(t, func(plane *ControlPlane) error {
		return plane.Close()
	})
}

func exerciseControlPlaneUDPOrderedDispatcherShutdown(t *testing.T, shutdown func(*ControlPlane) error) {
	t.Helper()
	dispatcher := newUDPOrderedDispatcher(1, 1)
	plane := newShutdownTestControlPlane()
	plane.udpOrderedDispatcher = dispatcher
	key := udpOrderedDispatcherTestKey(3)
	activeStarted := make(chan struct{})
	releaseActive := make(chan struct{})
	var releaseOnce sync.Once
	queuedDiscarded := make(chan struct{})
	var queuedRan atomic.Bool
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseActive) })
		_ = plane.Close()
		dispatcher.close()
		select {
		case <-dispatcher.done:
		case <-time.After(time.Second):
			t.Error("UDP ordered dispatcher did not stop during cleanup")
		}
	})

	if !plane.udpIngressAdmission.tryAcquire() {
		t.Fatal("acquire active ingress lease = false")
	}
	if !plane.submitOrderedUDPIngress(key, func() {
		close(activeStarted)
		<-releaseActive
		plane.udpIngressAdmission.release()
	}, func() {
		plane.udpIngressAdmission.release()
	}) {
		t.Fatal("submit active ingress task returned false")
	}
	select {
	case <-activeStarted:
	case <-time.After(time.Second):
		t.Fatal("active ingress task did not start")
	}
	if !plane.udpIngressAdmission.tryAcquire() {
		t.Fatal("acquire queued ingress lease = false")
	}
	if !plane.submitOrderedUDPIngress(key, func() {
		queuedRan.Store(true)
		plane.udpIngressAdmission.release()
	}, func() {
		close(queuedDiscarded)
		plane.udpIngressAdmission.release()
	}) {
		t.Fatal("submit queued ingress task returned false")
	}

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- shutdown(plane)
	}()
	select {
	case <-queuedDiscarded:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not discard queued ingress task")
	}
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before active ingress task released: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(releaseActive) })
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdown error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not complete after active task release")
	}
	dispatcher.wait()
	if queuedRan.Load() {
		t.Fatal("queued ingress task ran after dispatcher closure")
	}
}
