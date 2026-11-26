/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <yum456d5>
 */

package control

import (
	"bytes"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// TestIngressGateCloseAndWaitUntilGivesUpAtDeadline pins the bounded form of
// the gate's wait on its own: a holder that never leaves must not pin the
// caller past the deadline, the gate stays sealed, and a holder that leaves
// later lets the next wait through.
func TestIngressGateCloseAndWaitUntilGivesUpAtDeadline(t *testing.T) {
	var gate routingEpochIngressGate
	if !gate.tryAcquire() {
		t.Fatal("admission refused before the gate was sealed")
	}

	if gate.closeAndWaitUntil(time.Now().Add(20 * time.Millisecond)) {
		t.Fatal("reported drained while a holder was still inside")
	}
	if gate.tryAcquire() {
		t.Fatal("admission granted after the gate was sealed")
	}

	gate.release()
	if !gate.closeAndWaitUntil(time.Now().Add(time.Second)) {
		t.Fatal("not drained after the holder left")
	}
}

// TestStopRoutingEpochExecutionTimeoutContinuesWhileAdmissionIsHeld pins the
// bound on the wait that comes first. A UDP ingress task stuck before its
// release holds admission, and it is the generation's cancellation, which runs
// after this step, that unblocks it: waiting without a bound here waited for
// the step that could only come later, and retirement never finished.
func TestStopRoutingEpochExecutionTimeoutContinuesWhileAdmissionIsHeld(t *testing.T) {
	logBuf := bytes.NewBuffer(nil)
	logger := logrus.New()
	logger.SetOutput(logBuf)
	logger.SetLevel(logrus.WarnLevel)
	c := newOwnershipTestPlane()
	c.log = logger
	if !c.udpIngressAdmission.tryAcquire() {
		t.Fatal("admission refused on a fresh plane")
	}

	started := time.Now()
	done := make(chan struct{})
	go func() {
		c.StopRoutingEpochExecutionWithTimeout(30 * time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StopRoutingEpochExecutionWithTimeout blocked past the bound")
	}
	if time.Since(started) > 400*time.Millisecond {
		t.Fatalf("timeout path took %v, want ~30ms", time.Since(started))
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("routing epoch admission wait timed out; continuing retirement")) {
		t.Fatalf("timeout warn missing, log=%q", logBuf.String())
	}
}

// TestStopRoutingEpochExecutionSharesOneDeadline pins that the two waits
// split one budget instead of each taking the whole of it.
func TestStopRoutingEpochExecutionSharesOneDeadline(t *testing.T) {
	c := newOwnershipTestPlane()
	if !c.udpIngressAdmission.tryAcquire() {
		t.Fatal("admission refused on a fresh plane")
	}
	hold := c.drainTracker.Acquire()
	t.Cleanup(hold)

	started := time.Now()
	c.StopRoutingEpochExecutionWithTimeout(40 * time.Millisecond)
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("two held waits took %v, want about one 40ms budget", elapsed)
	}
}
