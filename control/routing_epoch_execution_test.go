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

func setRoutingEpochExecutionTestGeneration(plane *ControlPlane, generation uint16) {
	if plane != nil && plane.core != nil {
		plane.core.datapathGeneration.Store(uint32(generation))
	}
}

func markRoutingEpochExecutionTestPlaneReady(plane *ControlPlane) {
	if plane == nil {
		return
	}
	plane.ready = make(chan struct{})
	close(plane.ready)
}

func assertRoutingEpochExecutionOwnerRegistry(
	t *testing.T,
	wantActive *ControlPlane,
	wantOwners map[*ControlPlane]routingEpochExecutionOwnerPublication,
) {
	t.Helper()

	activeControlPlanePublication.mu.RLock()
	gotActive := activeControlPlanePublication.plane.Load()
	gotOwners := make(map[*ControlPlane]routingEpochExecutionOwnerPublication, len(activeControlPlanePublication.owners))
	for owner, publication := range activeControlPlanePublication.owners {
		gotOwners[owner] = publication
	}
	activeControlPlanePublication.mu.RUnlock()

	if gotActive != wantActive {
		t.Fatalf("active control plane = %p, want %p", gotActive, wantActive)
	}
	if len(gotOwners) != len(wantOwners) {
		t.Fatalf("routing epoch owner registry size = %d, want %d", len(gotOwners), len(wantOwners))
	}
	for owner, wantPublication := range wantOwners {
		gotPublication, ok := gotOwners[owner]
		if !ok {
			t.Fatalf("routing epoch owner registry does not contain %p", owner)
		}
		if gotPublication != wantPublication {
			t.Fatalf("routing epoch owner %p publication = %d, want %d", owner, gotPublication, wantPublication)
		}
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

func TestRoutingEpochExecutionOwnerRejectsFreshSameSlotGenerationAlias(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	current := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(current, 2)

	oldResult := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 1,
	}
	if _, err := current.routingEpochExecutionOwner(oldResult); !stderrors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("routingEpochExecutionOwner() error = %v, want unavailable old datapath generation", err)
	}

	newResult := *oldResult
	newResult.DatapathGeneration = 2
	owner, err := current.routingEpochExecutionOwner(&newResult)
	if err != nil {
		t.Fatalf("routingEpochExecutionOwner() current generation error = %v", err)
	}
	if owner != current {
		t.Fatalf("routingEpochExecutionOwner() = %p, want current %p", owner, current)
	}
}

func TestFreshPublicationKeepsPreviousTCPExecutionOwnerUntilRetirement(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	previous := newRoutingEpochExecutionTestPlane(0)
	candidate := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(previous, 11)
	setRoutingEpochExecutionTestGeneration(candidate, 12)
	previous.publishActiveControlPlane()

	oldResult := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 11,
	}
	newResult := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 12,
	}
	owner, release, err := candidate.acquireRoutingEpochExecutionOwner(oldResult)
	if err != nil {
		t.Fatalf("candidate acquire old published owner error = %v", err)
	}
	if owner != previous || release == nil {
		t.Fatalf("candidate owner = (%p, %v), want previous %p with lease", owner, release != nil, previous)
	}
	release()
	if _, _, err := previous.acquireRoutingEpochExecutionOwner(newResult); !stderrors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("previous acquire unpublished candidate error = %v, want unavailable", err)
	}

	candidate.publishActiveControlPlane()
	owner, release, err = candidate.acquireRoutingEpochExecutionOwner(oldResult)
	if err != nil {
		t.Fatalf("candidate acquire previous owner after publication error = %v", err)
	}
	if owner != previous || release == nil {
		t.Fatalf("candidate owner after publication = (%p, %v), want previous %p with lease", owner, release != nil, previous)
	}
	release()

	owner, release, err = previous.acquireRoutingEpochExecutionOwner(newResult)
	if err != nil {
		t.Fatalf("previous acquire newly published owner error = %v", err)
	}
	if owner != candidate || release == nil {
		t.Fatalf("previous owner = (%p, %v), want candidate %p with lease", owner, release != nil, candidate)
	}
	release()
}

func TestFreshPublicationKeepsPreviousUDPExecutionOwnerUntilRetirement(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	previous := newRoutingEpochExecutionTestPlane(0)
	candidate := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(previous, 31)
	setRoutingEpochExecutionTestGeneration(candidate, 32)
	previous.publishActiveControlPlane()
	candidate.publishActiveControlPlane()

	oldUDPResult := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 31,
	}
	owner, release, err := candidate.acquireRoutingEpochExecutionOwner(oldUDPResult)
	if err != nil {
		t.Fatalf("candidate acquire previous UDP owner error = %v", err)
	}
	if owner != previous || release == nil {
		t.Fatalf("candidate UDP owner = (%p, %v), want previous %p with lease", owner, release != nil, previous)
	}
	release()
}

func TestFreshProvisionalOwnerBridgesHookFlipBeforePublication(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	previous := newRoutingEpochExecutionTestPlane(0)
	candidate := newRoutingEpochExecutionTestPlane(0)
	candidate.core.isReload = true
	markRoutingEpochExecutionTestPlaneReady(candidate)
	setRoutingEpochExecutionTestGeneration(previous, 51)
	setRoutingEpochExecutionTestGeneration(candidate, 52)
	previous.publishActiveControlPlane()

	newResult := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 52,
	}
	if _, _, err := previous.acquireRoutingEpochExecutionOwner(newResult); !stderrors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("previous acquire unregistered candidate error = %v, want unavailable", err)
	}
	if err := candidate.RegisterProvisionalRoutingEpochExecutionOwner(); err != nil {
		t.Fatalf("RegisterProvisionalRoutingEpochExecutionOwner() error = %v", err)
	}
	if active := activeControlPlanePublication.plane.Load(); active != previous {
		t.Fatalf("active plane after provisional registration = %p, want previous %p", active, previous)
	}
	owner, release, err := previous.acquireRoutingEpochExecutionOwner(newResult)
	if err != nil {
		t.Fatalf("previous acquire provisional candidate error = %v", err)
	}
	if owner != candidate || release == nil {
		t.Fatalf("previous provisional owner = (%p, %v), want candidate %p with lease", owner, release != nil, candidate)
	}
	release()

	candidate.UnregisterProvisionalRoutingEpochExecutionOwner()
	candidate.UnregisterProvisionalRoutingEpochExecutionOwner()
	if _, _, err := previous.acquireRoutingEpochExecutionOwner(newResult); !stderrors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("previous acquire cleaned provisional candidate error = %v, want unavailable", err)
	}
}

func TestFreshProvisionalOwnerRequiresReadyIsolatedCandidate(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	candidate := newRoutingEpochExecutionTestPlane(0)
	candidate.core.isReload = true
	candidate.ready = make(chan struct{})
	setRoutingEpochExecutionTestGeneration(candidate, 61)
	if err := candidate.RegisterProvisionalRoutingEpochExecutionOwner(); err == nil {
		t.Fatal("RegisterProvisionalRoutingEpochExecutionOwner() error = nil for unready candidate")
	}
	close(candidate.ready)
	candidate.sharedBpfReload = true
	if err := candidate.RegisterProvisionalRoutingEpochExecutionOwner(); err == nil {
		t.Fatal("RegisterProvisionalRoutingEpochExecutionOwner() error = nil for shared-BPF candidate")
	}
}

func TestFreshProvisionalOwnerIsRemovedWhenExecutionCloses(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	previous := newRoutingEpochExecutionTestPlane(0)
	candidate := newRoutingEpochExecutionTestPlane(0)
	candidate.core.isReload = true
	markRoutingEpochExecutionTestPlaneReady(candidate)
	setRoutingEpochExecutionTestGeneration(previous, 71)
	setRoutingEpochExecutionTestGeneration(candidate, 72)
	previous.publishActiveControlPlane()
	if err := candidate.RegisterProvisionalRoutingEpochExecutionOwner(); err != nil {
		t.Fatalf("RegisterProvisionalRoutingEpochExecutionOwner() error = %v", err)
	}

	candidate.closeRoutingEpochExecution()
	newResult := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 72,
	}
	if _, _, err := previous.acquireRoutingEpochExecutionOwner(newResult); !stderrors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("previous acquire closed provisional candidate error = %v, want unavailable", err)
	}
}

func TestFreshPublicationUnregistersPreviousOwnerAtRetirement(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	previous := newRoutingEpochExecutionTestPlane(0)
	candidate := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(previous, 41)
	setRoutingEpochExecutionTestGeneration(candidate, 42)
	previous.publishActiveControlPlane()
	candidate.publishActiveControlPlane()

	oldResult := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 41,
	}
	previous.closeRoutingEpochExecution()
	if _, _, err := candidate.acquireRoutingEpochExecutionOwner(oldResult); !stderrors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("candidate acquire retired owner error = %v, want unavailable", err)
	}

	activeControlPlanePublication.mu.RLock()
	_, retained := activeControlPlanePublication.owners[previous]
	activeControlPlanePublication.mu.RUnlock()
	if retained {
		t.Fatal("retired previous owner remains in publication registry")
	}
}

func TestFreshProvisionalOwnerRegistryDoesNotLeakAcrossSixtyFiveRollbacks(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	active := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(active, 1)
	active.publishActiveControlPlane()
	stableOwners := map[*ControlPlane]routingEpochExecutionOwnerPublication{
		active: routingEpochExecutionOwnerPublished,
	}
	assertRoutingEpochExecutionOwnerRegistry(t, active, stableOwners)

	for cycle := 1; cycle <= 65; cycle++ {
		candidate := newRoutingEpochExecutionTestPlane(0)
		candidate.core.isReload = true
		markRoutingEpochExecutionTestPlaneReady(candidate)
		setRoutingEpochExecutionTestGeneration(candidate, uint16(cycle+1))
		if err := candidate.RegisterProvisionalRoutingEpochExecutionOwner(); err != nil {
			t.Fatalf("cycle %d RegisterProvisionalRoutingEpochExecutionOwner() error = %v", cycle, err)
		}
		assertRoutingEpochExecutionOwnerRegistry(t, active, map[*ControlPlane]routingEpochExecutionOwnerPublication{
			active:    routingEpochExecutionOwnerPublished,
			candidate: routingEpochExecutionOwnerProvisional,
		})

		candidate.UnregisterProvisionalRoutingEpochExecutionOwner()
		candidate.closeRoutingEpochExecution()
		assertRoutingEpochExecutionOwnerRegistry(t, active, stableOwners)
	}

	assertRoutingEpochExecutionOwnerRegistry(t, active, stableOwners)
}

func TestFreshPublishedOwnerRegistryDoesNotLeakAcrossSixtyFivePromotions(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	active := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(active, 1)
	active.publishActiveControlPlane()
	assertRoutingEpochExecutionOwnerRegistry(t, active, map[*ControlPlane]routingEpochExecutionOwnerPublication{
		active: routingEpochExecutionOwnerPublished,
	})

	for cycle := 1; cycle <= 65; cycle++ {
		candidate := newRoutingEpochExecutionTestPlane(0)
		candidate.core.isReload = true
		markRoutingEpochExecutionTestPlaneReady(candidate)
		setRoutingEpochExecutionTestGeneration(candidate, uint16(cycle+1))
		if err := candidate.RegisterProvisionalRoutingEpochExecutionOwner(); err != nil {
			t.Fatalf("cycle %d RegisterProvisionalRoutingEpochExecutionOwner() error = %v", cycle, err)
		}
		assertRoutingEpochExecutionOwnerRegistry(t, active, map[*ControlPlane]routingEpochExecutionOwnerPublication{
			active:    routingEpochExecutionOwnerPublished,
			candidate: routingEpochExecutionOwnerProvisional,
		})

		candidate.publishActiveControlPlane()
		assertRoutingEpochExecutionOwnerRegistry(t, candidate, map[*ControlPlane]routingEpochExecutionOwnerPublication{
			active:    routingEpochExecutionOwnerPublished,
			candidate: routingEpochExecutionOwnerPublished,
		})
		active.closeRoutingEpochExecution()
		active = candidate
		assertRoutingEpochExecutionOwnerRegistry(t, active, map[*ControlPlane]routingEpochExecutionOwnerPublication{
			active: routingEpochExecutionOwnerPublished,
		})
	}

	assertRoutingEpochExecutionOwnerRegistry(t, active, map[*ControlPlane]routingEpochExecutionOwnerPublication{
		active: routingEpochExecutionOwnerPublished,
	})
}

func TestLinkRoutingEpochPeerSynchronizesAndValidatesDatapathGeneration(t *testing.T) {
	first := newRoutingEpochExecutionTestPlane(0)
	second := newRoutingEpochExecutionTestPlane(1)
	setRoutingEpochExecutionTestGeneration(first, 23)
	if err := first.LinkRoutingEpochPeer(second); err != nil {
		t.Fatalf("LinkRoutingEpochPeer() error = %v", err)
	}
	if got := uint16(second.core.datapathGeneration.Load()); got != 23 {
		t.Fatalf("peer datapath generation = %d, want 23", got)
	}
	first.UnlinkRoutingEpochPeer(second)

	setRoutingEpochExecutionTestGeneration(second, 24)
	if err := first.LinkRoutingEpochPeer(second); err == nil {
		t.Fatal("LinkRoutingEpochPeer() accepted different datapath generations")
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

func TestRoutingEpochExecutionLeaseRechecksGenerationAndSlot(t *testing.T) {
	previous := newRoutingEpochExecutionTestPlane(0)
	successor := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(previous, 81)
	setRoutingEpochExecutionTestGeneration(successor, 82)
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

	mismatch := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 83,
	}
	if lease.transferRoutingEpoch(successor, mismatch) {
		t.Fatal("transferRoutingEpoch() accepted a mismatched datapath generation")
	}
	if release, ok := successor.acquireRoutingEpochExecutionLeaseFor(mismatch); ok {
		release()
		t.Fatal("acquireRoutingEpochExecutionLeaseFor() accepted a mismatched datapath generation")
	}

	matching := *mismatch
	matching.DatapathGeneration = 82
	if !lease.transferRoutingEpoch(successor, &matching) {
		t.Fatal("transferRoutingEpoch() rejected the matching datapath generation and slot")
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
