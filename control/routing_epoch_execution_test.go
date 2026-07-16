/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net"
	"testing"
	"time"
)

func newRoutingEpochExecutionTestPlane(slot uint32) *ControlPlane {
	core := &controlPlaneCore{}
	core.routingEpochSlot.Store(slot)
	return &ControlPlane{
		core:         core,
		drainTracker: newControlPlaneDrainTracker(),
	}
}

func TestRoutingEpochExecutionOwnerUsesOnlyLinkedPeer(t *testing.T) {
	first := newRoutingEpochExecutionTestPlane(0)
	second := newRoutingEpochExecutionTestPlane(1)
	if err := first.LinkRoutingEpochPeer(second); err != nil {
		t.Fatalf("LinkRoutingEpochPeer() error = %v", err)
	}
	t.Cleanup(func() { first.UnlinkRoutingEpochPeer(second) })

	owner, err := first.routingEpochExecutionOwner(&bpfRoutingResult{
		RoutingEpochSlot: bpfRoutingEpochSlot1Encoded,
	})
	if err != nil {
		t.Fatalf("routingEpochExecutionOwner() error = %v", err)
	}
	if owner != second {
		t.Fatalf("routingEpochExecutionOwner() = %p, want linked second plane %p", owner, second)
	}

	owner, err = first.routingEpochExecutionOwner(&bpfRoutingResult{
		RoutingEpochSlot: bpfRoutingEpochSlotUnknown,
	})
	if err != nil {
		t.Fatalf("routingEpochExecutionOwner() for unknown slot error = %v", err)
	}
	if owner != first {
		t.Fatalf("routingEpochExecutionOwner() for unknown slot = %p, want source plane %p", owner, first)
	}

	first.UnlinkRoutingEpochPeer(second)
	_, err = first.routingEpochExecutionOwner(&bpfRoutingResult{
		RoutingEpochSlot: bpfRoutingEpochSlot1Encoded,
	})
	if !stderrors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("routingEpochExecutionOwner() after unlink error = %v, want unavailable owner", err)
	}
}

func TestIncomingConnectionLeaseTransfersAbortOwnership(t *testing.T) {
	previous := newRoutingEpochExecutionTestPlane(0)
	successor := newRoutingEpochExecutionTestPlane(1)
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})

	lease, ok := previous.acquireIncomingConnectionLease(conn)
	if !ok {
		t.Fatal("acquireIncomingConnectionLease() = false")
	}
	defer lease.release()
	if previous.ActiveSessionCount() != 1 {
		t.Fatalf("previous active sessions = %d, want 1", previous.ActiveSessionCount())
	}
	if !lease.transfer(successor) {
		t.Fatal("transfer() = false")
	}
	if previous.ActiveSessionCount() != 0 {
		t.Fatalf("previous active sessions after transfer = %d, want 0", previous.ActiveSessionCount())
	}
	if successor.ActiveSessionCount() != 1 {
		t.Fatalf("successor active sessions after transfer = %d, want 1", successor.ActiveSessionCount())
	}
	if _, ok := previous.inConnections.Load(conn); ok {
		t.Fatal("previous control plane still tracks transferred connection")
	}
	if _, ok := successor.inConnections.Load(conn); !ok {
		t.Fatal("successor control plane does not track transferred connection")
	}

	if err := previous.AbortConnections(); err != nil {
		t.Fatalf("previous AbortConnections() error = %v", err)
	}
	writeResult := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte{1})
		writeResult <- err
	}()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var data [1]byte
	if _, err := conn.Read(data[:]); err != nil {
		t.Fatalf("transferred connection was closed by previous abort: %v", err)
	}
	if err := <-writeResult; err != nil {
		t.Fatalf("write to transferred connection: %v", err)
	}
}

func TestRoutingEpochExecutionLeaseRejectsRetiringPlane(t *testing.T) {
	plane := newRoutingEpochExecutionTestPlane(0)
	plane.StopRoutingEpochExecution()
	if release, ok := plane.acquireRoutingEpochExecutionLease(); ok {
		release()
		t.Fatal("acquireRoutingEpochExecutionLease() = true after execution stop")
	}
}

func TestStopRoutingEpochExecutionWaitsForExistingLease(t *testing.T) {
	plane := newRoutingEpochExecutionTestPlane(0)
	release, ok := plane.acquireRoutingEpochExecutionLease()
	if !ok {
		t.Fatal("acquireRoutingEpochExecutionLease() = false")
	}
	done := make(chan struct{})
	go func() {
		plane.StopRoutingEpochExecution()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("StopRoutingEpochExecution() returned before existing lease released")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StopRoutingEpochExecution() did not finish after lease release")
	}
}

func TestAcquireRoutingEpochExecutionOwnerCoordinatesRetirement(t *testing.T) {
	first := newRoutingEpochExecutionTestPlane(0)
	second := newRoutingEpochExecutionTestPlane(1)
	if err := first.LinkRoutingEpochPeer(second); err != nil {
		t.Fatalf("LinkRoutingEpochPeer() error = %v", err)
	}
	t.Cleanup(func() { first.UnlinkRoutingEpochPeer(second) })

	owner, release, err := first.acquireRoutingEpochExecutionOwner(&bpfRoutingResult{
		RoutingEpochSlot: bpfRoutingEpochSlot1Encoded,
	})
	if err != nil {
		t.Fatalf("acquireRoutingEpochExecutionOwner() error = %v", err)
	}
	if owner != second {
		t.Fatalf("acquireRoutingEpochExecutionOwner() owner = %p, want second owner %p", owner, second)
	}
	if release == nil {
		t.Fatal("acquireRoutingEpochExecutionOwner() returned a nil lease")
	}

	done := make(chan struct{})
	go func() {
		second.StopRoutingEpochExecution()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("StopRoutingEpochExecution() returned before delegated lease released")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StopRoutingEpochExecution() did not finish after delegated lease release")
	}

	_, _, err = first.acquireRoutingEpochExecutionOwner(&bpfRoutingResult{
		RoutingEpochSlot: bpfRoutingEpochSlot1Encoded,
	})
	if !stderrors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("acquireRoutingEpochExecutionOwner() after retirement error = %v, want unavailable owner", err)
	}
}

func TestRoutingEpochIngressGateAccountsForQueuedPacket(t *testing.T) {
	var gate routingEpochIngressGate
	if !gate.tryAcquire() {
		t.Fatal("tryAcquire() = false")
	}
	done := make(chan struct{})
	go func() {
		gate.closeAndWait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("closeAndWait() returned before queued packet released")
	case <-time.After(50 * time.Millisecond):
	}
	gate.release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closeAndWait() did not finish after queued packet release")
	}
	if gate.tryAcquire() {
		gate.release()
		t.Fatal("tryAcquire() = true after ingress admission closed")
	}
}
