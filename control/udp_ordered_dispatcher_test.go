/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"runtime"
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
	// In the convoy model each flow owns an independent goroutine, so a busy
	// hot flow cannot starve a cold flow. The test retains the "fairness"
	// intent of the original worker-pool quantum test: while the hot flow is
	// blocked, the cold flow must complete.
	dispatcher := newUDPOrderedDispatcher(1, 4)
	t.Cleanup(func() { closeUDPOrderedDispatcherForTest(t, dispatcher) })

	hotKey := udpOrderedDispatcherTestKey(1)
	coldKey := udpOrderedDispatcherTestKey(2)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseFirst) }) })
	coldDone := make(chan struct{})

	if !dispatcher.submit(hotKey, func() {
		close(firstStarted)
		<-releaseFirst
	}, nil) {
		t.Fatal("submit first hot task returned false")
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first hot task did not start")
	}
	for index := 1; index <= 8; index++ {
		if !dispatcher.submit(hotKey, func() {}, nil) {
			t.Fatalf("submit hot task %d returned false", index)
		}
	}
	if !dispatcher.submit(coldKey, func() {
		close(coldDone)
	}, nil) {
		t.Fatal("submit cold task returned false")
	}

	// The hot flow is still blocked, but the cold flow must complete because
	// it owns an independent convoy goroutine.
	select {
	case <-coldDone:
	case <-time.After(time.Second):
		t.Fatal("hot flow starved the cold flow")
	}
	releaseOnce.Do(func() { close(releaseFirst) })
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

func TestSessionManagerSharesUDPOrderedDispatcherAcrossGenerations(t *testing.T) {
	manager := NewSessionManager(context.Background())
	oldPlane := newShutdownTestControlPlane()
	oldPlane.semanticRefactorFeatures.UDPOrderedDispatcher = true
	oldPlane.udpOrderedDispatcher = newDefaultUDPOrderedDispatcher()
	successor := newShutdownTestControlPlane()
	successor.semanticRefactorFeatures.UDPOrderedDispatcher = true
	successor.udpOrderedDispatcher = newDefaultUDPOrderedDispatcher()
	t.Cleanup(func() {
		_ = oldPlane.Close()
		_ = successor.Close()
		_ = manager.Close()
	})

	if err := oldPlane.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(old) error = %v", err)
	}
	if err := successor.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(successor) error = %v", err)
	}
	if oldPlane.udpOrderedDispatcher == nil || oldPlane.udpOrderedDispatcher != successor.udpOrderedDispatcher {
		t.Fatal("reload generations did not share the process UDP ordered dispatcher")
	}
	if !oldPlane.udpOrderedDispatcherShared || !successor.udpOrderedDispatcherShared {
		t.Fatal("process UDP ordered dispatcher was not marked shared")
	}

	key := udpOrderedDispatcherTestKey(41)
	oldStarted := make(chan struct{})
	releaseOld := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseOld) }) })
	var orderMu sync.Mutex
	order := make([]string, 0, 3)
	appendOrder := func(value string) {
		orderMu.Lock()
		order = append(order, value)
		orderMu.Unlock()
	}

	if !oldPlane.udpIngressAdmission.tryAcquire() {
		t.Fatal("old generation ingress admission rejected initial task")
	}
	if !oldPlane.submitOrderedUDPIngress(key, func() {
		close(oldStarted)
		<-releaseOld
		appendOrder("old")
		oldPlane.udpIngressAdmission.release()
	}, func() {
		oldPlane.udpIngressAdmission.release()
	}) {
		t.Fatal("old generation ordered submit returned false")
	}
	select {
	case <-oldStarted:
	case <-time.After(time.Second):
		t.Fatal("old generation ordered task did not start")
	}

	if !successor.udpIngressAdmission.tryAcquire() {
		t.Fatal("successor ingress admission rejected task")
	}
	successorDone := make(chan struct{})
	if !successor.submitOrderedUDPIngress(key, func() {
		appendOrder("successor")
		successor.udpIngressAdmission.release()
		close(successorDone)
	}, func() {
		successor.udpIngressAdmission.release()
	}) {
		t.Fatal("successor ordered submit returned false")
	}

	retired := make(chan struct{})
	go func() {
		oldPlane.StopRoutingEpochExecution()
		close(retired)
	}()
	select {
	case <-retired:
		t.Fatal("old generation retired before its accepted task settled")
	default:
	}
	select {
	case <-successorDone:
		t.Fatal("same-flow successor task overtook the old generation task")
	default:
	}

	releaseOnce.Do(func() { close(releaseOld) })
	select {
	case <-retired:
	case <-time.After(time.Second):
		t.Fatal("old generation retirement did not settle")
	}
	select {
	case <-successorDone:
	case <-time.After(time.Second):
		t.Fatal("successor task did not run after old generation retirement")
	}

	if !successor.udpIngressAdmission.tryAcquire() {
		t.Fatal("successor admission closed with old generation")
	}
	lastDone := make(chan struct{})
	if !successor.submitOrderedUDPIngress(key, func() {
		appendOrder("last")
		successor.udpIngressAdmission.release()
		close(lastDone)
	}, func() {
		successor.udpIngressAdmission.release()
	}) {
		t.Fatal("shared dispatcher closed with retired generation")
	}
	select {
	case <-lastDone:
	case <-time.After(time.Second):
		t.Fatal("shared dispatcher stopped after old generation retirement")
	}

	orderMu.Lock()
	defer orderMu.Unlock()
	want := []string{"old", "successor", "last"}
	if len(order) != len(want) {
		t.Fatalf("ordered execution = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("ordered execution = %v, want %v", order, want)
		}
	}
}

func TestFailedCandidateDoesNotCloseProcessUDPOrderedDispatcher(t *testing.T) {
	manager := NewSessionManager(context.Background())
	active := newShutdownTestControlPlane()
	active.semanticRefactorFeatures.UDPOrderedDispatcher = true
	candidate := newShutdownTestControlPlane()
	candidate.semanticRefactorFeatures.UDPOrderedDispatcher = true
	t.Cleanup(func() {
		_ = active.Close()
		_ = candidate.Close()
		_ = manager.Close()
	})
	if err := active.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(active) error = %v", err)
	}
	if err := candidate.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(candidate) error = %v", err)
	}
	shared := active.udpOrderedDispatcher
	if shared == nil || candidate.udpOrderedDispatcher != shared {
		t.Fatal("candidate did not attach to active process dispatcher")
	}

	if err := candidate.Close(); err != nil {
		t.Fatalf("candidate Close() error = %v", err)
	}
	if shared.isClosed() {
		t.Fatal("failed candidate closed the active process dispatcher")
	}

	done := make(chan struct{})
	if !active.udpIngressAdmission.tryAcquire() {
		t.Fatal("active admission closed with failed candidate")
	}
	if !active.submitOrderedUDPIngress(udpOrderedDispatcherTestKey(42), func() {
		active.udpIngressAdmission.release()
		close(done)
	}, func() {
		active.udpIngressAdmission.release()
	}) {
		t.Fatal("active generation submit failed after candidate cleanup")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("active process dispatcher did not execute after candidate cleanup")
	}
}

func TestSessionManagerCloseStopsProcessUDPOrderedDispatcher(t *testing.T) {
	manager := NewSessionManager(context.Background())
	plane := &ControlPlane{
		semanticRefactorFeatures: SemanticRefactorFeatureSet{UDPOrderedDispatcher: true},
	}
	if err := plane.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager() error = %v", err)
	}
	dispatcher := plane.udpOrderedDispatcher
	if dispatcher == nil || !plane.udpOrderedDispatcherShared {
		t.Fatal("control plane did not receive a process ordered dispatcher")
	}

	key := udpOrderedDispatcherTestKey(43)
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		_ = manager.Close()
	})
	if !dispatcher.submit(key, func() {
		close(started)
		<-release
	}, nil) {
		t.Fatal("process dispatcher rejected active task")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("process dispatcher did not start active task")
	}
	discarded := make(chan struct{})
	if !dispatcher.submit(key, func() {
		t.Error("queued task ran during process shutdown")
	}, func() {
		close(discarded)
	}) {
		t.Fatal("process dispatcher rejected queued task")
	}

	closed := make(chan error, 1)
	go func() { closed <- manager.Close() }()
	select {
	case <-discarded:
	case <-time.After(time.Second):
		t.Fatal("SessionManager.Close did not discard queued process work")
	}
	select {
	case err := <-closed:
		t.Fatalf("SessionManager.Close returned before active work settled: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("SessionManager.Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SessionManager.Close did not wait for active process work")
	}
	if dispatcher.submit(key, func() {}, nil) {
		t.Fatal("process dispatcher accepted work after SessionManager.Close")
	}
}

func TestSessionManagerCloseQuiescesOrderedIngressBeforeFlows(t *testing.T) {
	manager := NewSessionManager(context.Background())
	plane := &ControlPlane{
		semanticRefactorFeatures: SemanticRefactorFeatureSet{UDPOrderedDispatcher: true},
	}
	if err := plane.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager() error = %v", err)
	}

	ingress, ingressPeer := net.Pipe()
	egress, egressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	defer func() { _ = egressPeer.Close() }()
	flow, err := manager.adoptTCP(ingress, egress, TcpFlowBinding{}, nil, nil)
	if err != nil {
		t.Fatalf("adoptTCP() error = %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	if !plane.udpOrderedDispatcher.submit(udpOrderedDispatcherTestKey(44), func() {
		close(started)
		<-release
	}, nil) {
		t.Fatal("process dispatcher rejected active task")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("ordered ingress task did not start")
	}

	closed := make(chan error, 1)
	go func() { closed <- manager.Close() }()
	deadline := time.Now().Add(time.Second)
	for !plane.udpOrderedDispatcher.isClosed() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if !plane.udpOrderedDispatcher.isClosed() {
		t.Fatal("SessionManager.Close did not close ordered ingress admission")
	}
	select {
	case <-flow.Context().Done():
		t.Fatal("flow was canceled while ordered ingress was still running")
	default:
	}
	select {
	case err := <-closed:
		t.Fatalf("SessionManager.Close returned before ordered ingress settled: %v", err)
	default:
	}

	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("SessionManager.Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SessionManager.Close did not finish after ordered ingress settled")
	}
	select {
	case <-flow.Context().Done():
	default:
		t.Fatal("flow remained active after SessionManager.Close")
	}
}

func TestSessionManagerPreservesLegacyUDPOrderedFeatureGate(t *testing.T) {
	manager := NewSessionManager(context.Background())
	enabled := &ControlPlane{
		semanticRefactorFeatures: SemanticRefactorFeatureSet{UDPOrderedDispatcher: true},
	}
	legacy := &ControlPlane{}
	t.Cleanup(func() { _ = manager.Close() })
	if err := enabled.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(enabled) error = %v", err)
	}
	if enabled.udpOrderedDispatcher == nil || !enabled.udpOrderedDispatcherShared {
		t.Fatal("enabled generation did not receive process ordered dispatcher")
	}
	if err := legacy.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(legacy) error = %v", err)
	}
	if legacy.udpOrderedDispatcher != nil || legacy.udpOrderedDispatcherShared {
		t.Fatal("legacy generation enabled the ordered dispatcher through a shared manager")
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
