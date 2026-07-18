/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

func newTestRuntimeGeneration() *runtimeGeneration {
	return &runtimeGeneration{
		controlPlane: &control.ControlPlane{},
		listener:     &control.Listener{},
		cancel:       func() {},
		conf:         &config.Config{},
	}
}

func TestRuntimeSupervisorPublishesOnlyPreparedCandidate(t *testing.T) {
	oldGeneration := newTestRuntimeGeneration()
	candidate := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(oldGeneration)

	if err := supervisor.installPrepared(candidate); err != nil {
		t.Fatalf("installPrepared() error = %v", err)
	}
	beforePublish := supervisor.snapshot()
	if beforePublish.active != oldGeneration {
		t.Fatal("candidate became active before publish")
	}
	if beforePublish.prepared != candidate {
		t.Fatal("prepared candidate is missing before publish")
	}

	if _, err := supervisor.publishPrepared(newTestRuntimeGeneration()); !errors.Is(err, errRuntimeSupervisorPreparedMismatch) {
		t.Fatalf("publishPrepared(wrong candidate) error = %v, want prepared mismatch", err)
	}
	stillPrepared := supervisor.snapshot()
	if stillPrepared.active != oldGeneration || stillPrepared.prepared != candidate {
		t.Fatal("failed publish changed the active or prepared generation")
	}

	retiring, err := supervisor.publishPrepared(candidate)
	if err != nil {
		t.Fatalf("publishPrepared() error = %v", err)
	}
	if retiring != oldGeneration {
		t.Fatal("publishPrepared() returned the wrong retiring generation")
	}
	afterPublish := supervisor.snapshot()
	if afterPublish.active != candidate || afterPublish.prepared != nil || afterPublish.retiring != oldGeneration {
		t.Fatalf("snapshot after publish = %#v, want active candidate and retiring old generation", afterPublish)
	}
}

func TestRuntimeGenerationCleanupIsIdempotent(t *testing.T) {
	var cancelCalls atomic.Int32
	generation := &runtimeGeneration{
		controlPlane: &control.ControlPlane{},
		listener:     &control.Listener{},
		cancel: func() {
			cancelCalls.Add(1)
		},
	}

	if err := generation.cleanup(); err != nil {
		t.Fatalf("first cleanup() error = %v", err)
	}
	if err := generation.cleanup(); err != nil {
		t.Fatalf("second cleanup() error = %v", err)
	}
	if got := cancelCalls.Load(); got != 1 {
		t.Fatalf("cancel calls = %d, want 1", got)
	}
}

func TestRuntimeGenerationConcurrentCleanupRunsOnce(t *testing.T) {
	var cancelCalls atomic.Int32
	generation := &runtimeGeneration{
		cancel: func() {
			cancelCalls.Add(1)
		},
	}

	const callers = 128
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := generation.cleanup(); err != nil {
				t.Errorf("concurrent cleanup() error = %v", err)
			}
		}()
	}
	wg.Wait()

	if got := cancelCalls.Load(); got != 1 {
		t.Fatalf("concurrent cancel calls = %d, want 1", got)
	}
}

func TestRollbackStagedHandoffCleansPreparedGenerationOnce(t *testing.T) {
	var cancelCalls atomic.Int32
	generation := &runtimeGeneration{
		controlPlane: &control.ControlPlane{},
		listener:     &control.Listener{},
		cancel: func() {
			cancelCalls.Add(1)
		},
	}
	handoff := &stagedReloadHandoff{
		preparedGeneration: generation,
		newControlPlane:    generation.controlPlane,
		newListener:        generation.listener,
		newCancel:          generation.cancel,
	}

	if err := rollbackStagedReloadHandoff(nil, handoff); err != nil {
		t.Fatalf("first rollback error = %v", err)
	}
	if err := rollbackStagedReloadHandoff(nil, handoff); err != nil {
		t.Fatalf("second rollback error = %v", err)
	}

	if got := cancelCalls.Load(); got != 1 {
		t.Fatalf("rollback cancel calls = %d, want 1", got)
	}
}

func TestRestoreStagedHandoffAggregatesEveryRestoreFailure(t *testing.T) {
	previousRestoreListenerSockets := restoreListenerSocketsFunc
	previousRestoreReloadDatapath := restoreReloadDatapathFunc
	previousRestoreDNSListener := restoreDNSListenerFunc
	t.Cleanup(func() {
		restoreListenerSocketsFunc = previousRestoreListenerSockets
		restoreReloadDatapathFunc = previousRestoreReloadDatapath
		restoreDNSListenerFunc = previousRestoreDNSListener
	})

	listenerErr := errors.New("listener restore failed")
	datapathErr := errors.New("datapath restore failed")
	dnsErr := errors.New("DNS restore failed")
	var calls []string
	restoreListenerSocketsFunc = func(*control.ControlPlane, *control.Listener) error {
		calls = append(calls, "listener")
		return listenerErr
	}
	restoreReloadDatapathFunc = func(*control.ControlPlane) error {
		calls = append(calls, "datapath")
		return datapathErr
	}
	restoreDNSListenerFunc = func(*control.ControlPlane) error {
		calls = append(calls, "dns")
		return dnsErr
	}

	err := restoreStagedReloadHandoff(nil, &stagedReloadHandoff{
		oldControlPlane: &control.ControlPlane{},
		oldListener:     &control.Listener{},
	})
	if !errors.Is(err, listenerErr) || !errors.Is(err, datapathErr) || !errors.Is(err, dnsErr) {
		t.Fatalf("restore error = %v, want all restore failures", err)
	}
	if got, want := fmt.Sprint(calls), "[listener datapath dns]"; got != want {
		t.Fatalf("restore calls = %s, want %s", got, want)
	}
}

func TestRuntimeSupervisorRollbackPreservesActiveGeneration(t *testing.T) {
	active := newTestRuntimeGeneration()
	candidate := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(active)

	if err := supervisor.installPrepared(candidate); err != nil {
		t.Fatalf("installPrepared() error = %v", err)
	}
	cleanup, rolledBack := supervisor.rollbackPrepared(candidate)
	if !rolledBack || cleanup != candidate {
		t.Fatalf("rollbackPrepared() = (%p, %t), want candidate and true", cleanup, rolledBack)
	}

	snapshot := supervisor.snapshot()
	if snapshot.active != active || snapshot.prepared != nil || snapshot.retiring != nil {
		t.Fatalf("snapshot after rollback = %#v, want unchanged active generation", snapshot)
	}
	if _, err := supervisor.publishPrepared(candidate); !errors.Is(err, errRuntimeSupervisorNoPrepared) {
		t.Fatalf("publishPrepared() after rollback error = %v, want no prepared generation", err)
	}
	if _, rolledBack := supervisor.rollbackPrepared(candidate); rolledBack {
		t.Fatal("second rollback unexpectedly succeeded")
	}
}

func TestRuntimeSupervisorReplaceActiveRequiresIdleState(t *testing.T) {
	first := newTestRuntimeGeneration()
	second := newTestRuntimeGeneration()
	candidate := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(first)

	if err := supervisor.replaceActive(second); err != nil {
		t.Fatalf("replaceActive() error = %v", err)
	}
	if snapshot := supervisor.snapshot(); snapshot.active != second {
		t.Fatal("replaceActive() did not replace the active generation")
	}

	if err := supervisor.installPrepared(candidate); err != nil {
		t.Fatalf("installPrepared() error = %v", err)
	}
	if err := supervisor.replaceActive(first); !errors.Is(err, errRuntimeSupervisorPrepared) {
		t.Fatalf("replaceActive() while prepared error = %v, want prepared error", err)
	}
	if _, err := supervisor.publishPrepared(candidate); err != nil {
		t.Fatalf("publishPrepared() error = %v", err)
	}
	if err := supervisor.replaceActive(first); !errors.Is(err, errRuntimeSupervisorRetiring) {
		t.Fatalf("replaceActive() while retiring error = %v, want retiring error", err)
	}
}

func TestRuntimeSupervisorBlocksPrepareWhileRetiring(t *testing.T) {
	oldGeneration := newTestRuntimeGeneration()
	newGeneration := newTestRuntimeGeneration()
	thirdGeneration := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(oldGeneration)

	if err := supervisor.installPrepared(newGeneration); err != nil {
		t.Fatalf("installPrepared(new generation) error = %v", err)
	}
	if _, err := supervisor.publishPrepared(newGeneration); err != nil {
		t.Fatalf("publishPrepared() error = %v", err)
	}
	if err := supervisor.installPrepared(thirdGeneration); !errors.Is(err, errRuntimeSupervisorRetiring) {
		t.Fatalf("installPrepared(third generation) error = %v, want retiring error", err)
	}
	if !supervisor.markRetirementComplete(oldGeneration) {
		t.Fatal("markRetirementComplete(old generation) = false, want true")
	}
	if err := supervisor.installPrepared(thirdGeneration); err != nil {
		t.Fatalf("installPrepared(third generation) after retirement error = %v", err)
	}
}

func TestRuntimeSupervisorIgnoresStaleRetirementCompletion(t *testing.T) {
	first := newTestRuntimeGeneration()
	second := newTestRuntimeGeneration()
	third := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(first)

	if err := supervisor.installPrepared(second); err != nil {
		t.Fatalf("installPrepared(second) error = %v", err)
	}
	if _, err := supervisor.publishPrepared(second); err != nil {
		t.Fatalf("publishPrepared(second) error = %v", err)
	}
	if !supervisor.markRetirementComplete(first) {
		t.Fatal("markRetirementComplete(first) = false, want true")
	}
	if err := supervisor.installPrepared(third); err != nil {
		t.Fatalf("installPrepared(third) error = %v", err)
	}
	if _, err := supervisor.publishPrepared(third); err != nil {
		t.Fatalf("publishPrepared(third) error = %v", err)
	}

	if supervisor.markRetirementComplete(first) {
		t.Fatal("stale retirement completion unexpectedly succeeded")
	}
	snapshot := supervisor.snapshot()
	if snapshot.active != third || snapshot.retiring != second {
		t.Fatalf("snapshot after stale completion = %#v, want third active and second retiring", snapshot)
	}
}

func TestRuntimeSupervisorShutdownReturnsPreparedCandidateForCleanup(t *testing.T) {
	active := newTestRuntimeGeneration()
	candidate := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(active)

	if err := supervisor.installPrepared(candidate); err != nil {
		t.Fatalf("installPrepared() error = %v", err)
	}
	cleanup := supervisor.shutdown()
	if cleanup.active != active || cleanup.prepared != candidate || cleanup.retiring != nil {
		t.Fatalf("shutdown() snapshot = %#v, want active and prepared candidate", cleanup)
	}

	snapshot := supervisor.snapshot()
	if snapshot.active != nil || snapshot.prepared != nil || snapshot.retiring != nil {
		t.Fatalf("snapshot after shutdown = %#v, want empty", snapshot)
	}
	if err := supervisor.installPrepared(newTestRuntimeGeneration()); !errors.Is(err, errRuntimeSupervisorClosed) {
		t.Fatalf("installPrepared() after shutdown error = %v, want closed error", err)
	}
}

func TestRuntimeSupervisorRepeatedLifecycleReleasesGenerationSlots(t *testing.T) {
	active := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(active)

	for iteration := 0; iteration < 256; iteration++ {
		candidate := newTestRuntimeGeneration()
		if err := supervisor.installPrepared(candidate); err != nil {
			t.Fatalf("iteration %d installPrepared() error = %v", iteration, err)
		}

		if iteration%3 == 0 {
			cleanup, rolledBack := supervisor.rollbackPrepared(candidate)
			if !rolledBack || cleanup != candidate {
				t.Fatalf("iteration %d rollback = (%p, %t), want candidate and true", iteration, cleanup, rolledBack)
			}
		} else {
			retiring, err := supervisor.publishPrepared(candidate)
			if err != nil {
				t.Fatalf("iteration %d publishPrepared() error = %v", iteration, err)
			}
			if retiring != active {
				t.Fatalf("iteration %d retiring generation = %p, want %p", iteration, retiring, active)
			}
			if !supervisor.markRetirementComplete(retiring) {
				t.Fatalf("iteration %d failed to release retiring generation", iteration)
			}
			active = candidate
		}

		snapshot := supervisor.snapshot()
		if snapshot.active != active || snapshot.prepared != nil || snapshot.retiring != nil {
			t.Fatalf("iteration %d retained stale generation ownership: %#v", iteration, snapshot)
		}
	}

	shutdown := supervisor.shutdown()
	if shutdown.active != active || shutdown.prepared != nil || shutdown.retiring != nil {
		t.Fatalf("shutdown snapshot = %#v, want only final active generation", shutdown)
	}
	if snapshot := supervisor.snapshot(); snapshot.active != nil || snapshot.prepared != nil || snapshot.retiring != nil {
		t.Fatalf("post-shutdown snapshot = %#v, want empty", snapshot)
	}
}

func TestRuntimeSupervisorFailureMatrixCleansEveryGenerationOnce(t *testing.T) {
	type trackedGeneration struct {
		generation  *runtimeGeneration
		cancelCalls atomic.Int32
	}

	newTracked := func() *trackedGeneration {
		tracked := &trackedGeneration{}
		tracked.generation = &runtimeGeneration{
			cancel: func() {
				tracked.cancelCalls.Add(1)
			},
		}
		return tracked
	}

	assertCleaned := func(t *testing.T, tracked *trackedGeneration) {
		t.Helper()
		if got := tracked.cancelCalls.Load(); got != 1 {
			t.Fatalf("generation cancel calls = %d, want 1", got)
		}
	}

	active := newTracked()
	all := []*trackedGeneration{active}
	supervisor := newRuntimeSupervisor(active.generation)

	for iteration := 0; iteration < 1024; iteration++ {
		candidate := newTracked()
		all = append(all, candidate)
		if err := supervisor.installPrepared(candidate.generation); err != nil {
			t.Fatalf("iteration %d installPrepared() error = %v", iteration, err)
		}

		if iteration%4 == 0 {
			rolledBack, ok := supervisor.rollbackPrepared(candidate.generation)
			if !ok || rolledBack != candidate.generation {
				t.Fatalf("iteration %d rollback = (%p, %t), want candidate and true", iteration, rolledBack, ok)
			}
			if err := rolledBack.cleanup(); err != nil {
				t.Fatalf("iteration %d rollback cleanup() error = %v", iteration, err)
			}
			assertCleaned(t, candidate)
			continue
		}

		retiring, err := supervisor.publishPrepared(candidate.generation)
		if err != nil {
			t.Fatalf("iteration %d publishPrepared() error = %v", iteration, err)
		}
		if retiring != active.generation {
			t.Fatalf("iteration %d retiring generation = %p, want %p", iteration, retiring, active.generation)
		}
		if err := retiring.cleanup(); err != nil {
			t.Fatalf("iteration %d retirement cleanup() error = %v", iteration, err)
		}
		if !supervisor.markRetirementComplete(retiring) {
			t.Fatalf("iteration %d markRetirementComplete() = false", iteration)
		}
		assertCleaned(t, active)
		active = candidate
	}

	shutdown := supervisor.shutdown()
	if shutdown.active != active.generation || shutdown.prepared != nil || shutdown.retiring != nil {
		t.Fatalf("shutdown snapshot = %#v, want final active generation only", shutdown)
	}
	if err := shutdown.active.cleanup(); err != nil {
		t.Fatalf("final active cleanup() error = %v", err)
	}
	assertCleaned(t, active)

	for _, tracked := range all {
		assertCleaned(t, tracked)
	}
}

func TestRuntimeSupervisorFailureMatrixRejectsUnresolvedOwnership(t *testing.T) {
	active := newTestRuntimeGeneration()
	candidate := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(active)

	if err := supervisor.installPrepared(candidate); err != nil {
		t.Fatalf("installPrepared() error = %v", err)
	}
	if err := supervisor.installPrepared(newTestRuntimeGeneration()); !errors.Is(err, errRuntimeSupervisorPrepared) {
		t.Fatalf("installPrepared() with unresolved candidate error = %v, want prepared error", err)
	}
	if _, err := supervisor.publishPrepared(newTestRuntimeGeneration()); !errors.Is(err, errRuntimeSupervisorPreparedMismatch) {
		t.Fatalf("publishPrepared() with wrong candidate error = %v, want mismatch", err)
	}

	shutdown := supervisor.shutdown()
	if shutdown.active != active || shutdown.prepared != candidate || shutdown.retiring != nil {
		t.Fatalf("shutdown snapshot = %#v, want active and prepared ownership", shutdown)
	}
	if _, err := supervisor.publishPrepared(candidate); !errors.Is(err, errRuntimeSupervisorClosed) {
		t.Fatalf("publishPrepared() after shutdown error = %v, want closed", err)
	}
	if _, ok := supervisor.rollbackPrepared(candidate); ok {
		t.Fatal("rollbackPrepared() after shutdown unexpectedly changed ownership")
	}
	if err := shutdown.active.cleanup(); err != nil {
		t.Fatalf("active cleanup() error = %v", err)
	}
	if err := shutdown.prepared.cleanup(); err != nil {
		t.Fatalf("prepared cleanup() error = %v", err)
	}
}

const runtimeSupervisorProcessHelperEnv = "DAE_RUNTIME_SUPERVISOR_PROCESS_HELPER"

func TestRuntimeSupervisorProcessBoundary(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestRuntimeSupervisorProcessHelper$")
	command.Env = append(os.Environ(), runtimeSupervisorProcessHelperEnv+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("supervisor process helper failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("runtime-supervisor-process-helper-ok")) {
		t.Fatalf("supervisor process helper did not report success: %s", output)
	}
}

func TestRuntimeSupervisorProcessHelper(t *testing.T) {
	if os.Getenv(runtimeSupervisorProcessHelperEnv) != "1" {
		t.Skip("child-process lifecycle helper")
	}

	type trackedGeneration struct {
		generation  *runtimeGeneration
		cancelCalls atomic.Int32
	}
	newTracked := func() *trackedGeneration {
		tracked := &trackedGeneration{}
		tracked.generation = &runtimeGeneration{
			cancel: func() {
				tracked.cancelCalls.Add(1)
			},
		}
		return tracked
	}
	assertCleaned := func(tracked *trackedGeneration) {
		t.Helper()
		if got := tracked.cancelCalls.Load(); got != 1 {
			t.Fatalf("generation cancel calls = %d, want 1", got)
		}
	}

	active := newTracked()
	all := []*trackedGeneration{active}
	supervisor := newRuntimeSupervisor(active.generation)

	for iteration := 0; iteration < 4096; iteration++ {
		candidate := newTracked()
		all = append(all, candidate)

		switch iteration % 7 {
		case 0:
			if err := supervisor.installPrepared(candidate.generation); err != nil {
				t.Fatalf("iteration %d installPrepared() error = %v", iteration, err)
			}
			rolledBack, ok := supervisor.rollbackPrepared(candidate.generation)
			if !ok || rolledBack != candidate.generation {
				t.Fatalf("iteration %d rollback = (%p, %t), want candidate and true", iteration, rolledBack, ok)
			}
			if err := rolledBack.cleanup(); err != nil {
				t.Fatalf("iteration %d rollback cleanup() error = %v", iteration, err)
			}
			assertCleaned(candidate)
		case 1:
			// Readiness failure before ownership registration remains caller-owned.
			if err := candidate.generation.cleanup(); err != nil {
				t.Fatalf("iteration %d failed-readiness cleanup() error = %v", iteration, err)
			}
			assertCleaned(candidate)
		default:
			if err := supervisor.installPrepared(candidate.generation); err != nil {
				t.Fatalf("iteration %d installPrepared() error = %v", iteration, err)
			}
			retiring, err := supervisor.publishPrepared(candidate.generation)
			if err != nil {
				t.Fatalf("iteration %d publishPrepared() error = %v", iteration, err)
			}
			if retiring != active.generation {
				t.Fatalf("iteration %d retiring generation = %p, want %p", iteration, retiring, active.generation)
			}
			if err := retiring.cleanup(); err != nil {
				t.Fatalf("iteration %d retirement cleanup() error = %v", iteration, err)
			}
			if !supervisor.markRetirementComplete(retiring) {
				t.Fatalf("iteration %d markRetirementComplete() = false", iteration)
			}
			assertCleaned(active)
			active = candidate
		}
	}

	pending := newTracked()
	all = append(all, pending)
	if err := supervisor.installPrepared(pending.generation); err != nil {
		t.Fatalf("final installPrepared() error = %v", err)
	}
	shutdown := supervisor.shutdown()
	if shutdown.active != active.generation || shutdown.prepared != pending.generation || shutdown.retiring != nil {
		t.Fatalf("shutdown snapshot = %#v, want active and prepared ownership", shutdown)
	}
	if err := shutdown.active.cleanup(); err != nil {
		t.Fatalf("active shutdown cleanup() error = %v", err)
	}
	if err := shutdown.prepared.cleanup(); err != nil {
		t.Fatalf("prepared shutdown cleanup() error = %v", err)
	}

	for _, tracked := range all {
		assertCleaned(tracked)
	}
	_, _ = fmt.Fprintln(os.Stdout, "runtime-supervisor-process-helper-ok")
}

func TestRuntimeSupervisorConcurrentPublishRollbackAndShutdown(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		oldGeneration := newTestRuntimeGeneration()
		candidate := newTestRuntimeGeneration()
		supervisor := newRuntimeSupervisor(oldGeneration)
		if err := supervisor.installPrepared(candidate); err != nil {
			t.Fatalf("iteration %d installPrepared() error = %v", iteration, err)
		}

		start := make(chan struct{})
		publishResult := make(chan error, 1)
		rollbackResult := make(chan bool, 1)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := supervisor.publishPrepared(candidate)
			publishResult <- err
		}()
		go func() {
			defer wg.Done()
			<-start
			_, rolledBack := supervisor.rollbackPrepared(candidate)
			rollbackResult <- rolledBack
		}()
		close(start)
		wg.Wait()
		publishErr := <-publishResult
		rolledBack := <-rollbackResult

		snapshot := supervisor.snapshot()
		switch {
		case publishErr == nil:
			if rolledBack || snapshot.active != candidate || snapshot.prepared != nil || snapshot.retiring != oldGeneration {
				t.Fatalf("iteration %d publish winner state = %#v, rollback=%t", iteration, snapshot, rolledBack)
			}
			if !supervisor.markRetirementComplete(oldGeneration) {
				t.Fatalf("iteration %d failed to complete published retirement", iteration)
			}
		case rolledBack:
			if snapshot.active != oldGeneration || snapshot.prepared != nil || snapshot.retiring != nil {
				t.Fatalf("iteration %d rollback winner state = %#v", iteration, snapshot)
			}
		default:
			t.Fatalf("iteration %d neither publish nor rollback won: err=%v state=%#v", iteration, publishErr, snapshot)
		}

		if snapshot := supervisor.snapshot(); snapshot.prepared != nil || snapshot.retiring != nil {
			t.Fatalf("iteration %d retained non-active ownership after resolution: %#v", iteration, snapshot)
		}
	}

	active := newTestRuntimeGeneration()
	candidate := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(active)
	if err := supervisor.installPrepared(candidate); err != nil {
		t.Fatalf("shutdown race installPrepared() error = %v", err)
	}
	start := make(chan struct{})
	shutdownResult := make(chan runtimeSupervisorSnapshot, 1)
	publishResult := make(chan error, 1)
	go func() {
		<-start
		shutdownResult <- supervisor.shutdown()
	}()
	go func() {
		<-start
		_, err := supervisor.publishPrepared(candidate)
		publishResult <- err
	}()
	close(start)
	shutdownSnapshot := <-shutdownResult
	publishErr := <-publishResult
	if after := supervisor.snapshot(); after.active != nil || after.prepared != nil || after.retiring != nil {
		t.Fatalf("shutdown race left managed generations: %#v", after)
	}
	if publishErr == nil {
		if shutdownSnapshot.active != candidate || shutdownSnapshot.prepared != nil || shutdownSnapshot.retiring != active {
			t.Fatalf("publish winner shutdown snapshot = %#v", shutdownSnapshot)
		}
	} else if !errors.Is(publishErr, errRuntimeSupervisorClosed) {
		t.Fatalf("shutdown race publish error = %v, want closed or success", publishErr)
	}
}
