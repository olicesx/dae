/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/routing"
)

func newRoutingEpochTestCore(t *testing.T) (*controlPlaneCore, *ebpf.Map) {
	t.Helper()

	activeMap := newJanitorTestMap(t, "active_routing_epoch_map")
	epochMap := newJanitorTestMap(t, "routing_epoch_map")
	core := &controlPlaneCore{}
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			ActiveRoutingEpochMap: activeMap,
			RoutingEpochMap:       epochMap,
		},
	})
	return core, activeMap
}

func newRoutingEpochProjectionTestCore(t *testing.T) (*controlPlaneCore, *ebpf.Map, *ebpf.Map) {
	t.Helper()

	core, activeMap := newRoutingEpochTestCore(t)
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	core.PeekBpf().DomainRoutingMap = domainMap
	core.domainRouting = newDomainRoutingTracker()
	core.domainRoutingSlots[0] = core.domainRouting
	core.domainRoutingSlots[1] = newDomainRoutingTracker()
	core.routingEpochSlot.Store(0)
	core.routingEpochPreviousSlot.Store(routingEpochSlotUnset)
	return core, activeMap, domainMap
}

func routingEpochDomainProjection(t *testing.T, domainMap *ebpf.Map, slot uint32, ip netip.Addr) bpfDomainRouting {
	t.Helper()

	ip16 := ip.As16()
	key := bpfRoutingEpochIp{
		Slot: slot,
		Addr: common.Ipv6ByteSliceToUint32Array(ip16[:]),
	}
	var projection bpfDomainRouting
	if err := domainMap.Lookup(&key, &projection); err != nil {
		t.Fatalf("lookup domain projection for slot %d: %v", slot, err)
	}
	return projection
}

func assertActiveRoutingEpochSlot(t *testing.T, activeMap *ebpf.Map, want uint32) {
	t.Helper()

	var active uint32
	if err := activeMap.Lookup(uint32(0), &active); err != nil {
		t.Fatalf("lookup active routing epoch slot: %v", err)
	}
	if active != want {
		t.Fatalf("active routing epoch slot = %d, want %d", active, want)
	}
}

func TestRoutingEpochPublishRequiresStagedTarget(t *testing.T) {
	core, activeMap := newRoutingEpochTestCore(t)

	slot, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(17), true)
	if err != nil {
		t.Fatalf("PrepareRoutingEpoch() error = %v", err)
	}
	if err := core.PublishRoutingEpoch(); err == nil {
		t.Fatal("PublishRoutingEpoch() error = nil, want unstaged target error")
	}

	var active uint32
	if err := activeMap.Lookup(uint32(0), &active); err != nil {
		t.Fatalf("lookup active slot after rejected publish: %v", err)
	}
	if active != 0 {
		t.Fatalf("active slot after rejected publish = %d, want 0", active)
	}
	if slot != 1 {
		t.Fatalf("prepared slot = %d, want inactive slot 1", slot)
	}
}

func TestRoutingEpochPrepareInvalidatesPriorStage(t *testing.T) {
	core, activeMap := newRoutingEpochTestCore(t)

	if _, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(17), true); err != nil {
		t.Fatalf("first PrepareRoutingEpoch() error = %v", err)
	}
	if err := core.StageRoutingEpoch(); err != nil {
		t.Fatalf("StageRoutingEpoch() error = %v", err)
	}
	if _, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(18), true); err != nil {
		t.Fatalf("second PrepareRoutingEpoch() error = %v", err)
	}
	if err := core.PublishRoutingEpoch(); err == nil {
		t.Fatal("PublishRoutingEpoch() error = nil, want stale stage error")
	}

	var active uint32
	if err := activeMap.Lookup(uint32(0), &active); err != nil {
		t.Fatalf("lookup active slot after rejected publish: %v", err)
	}
	if active != 0 {
		t.Fatalf("active slot after rejected publish = %d, want 0", active)
	}
}

func TestRoutingEpochFailedStageCannotPublish(t *testing.T) {
	core, activeMap := newRoutingEpochTestCore(t)

	if _, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(17), true); err != nil {
		t.Fatalf("PrepareRoutingEpoch() error = %v", err)
	}
	if err := core.PeekBpf().RoutingEpochMap.Close(); err != nil {
		t.Fatalf("close routing epoch map: %v", err)
	}
	if err := core.StageRoutingEpoch(); err == nil {
		t.Fatal("StageRoutingEpoch() error = nil, want closed map error")
	}
	if err := core.PublishRoutingEpoch(); err == nil {
		t.Fatal("PublishRoutingEpoch() error = nil, want failed stage error")
	}

	var active uint32
	if err := activeMap.Lookup(uint32(0), &active); err != nil {
		t.Fatalf("lookup active slot after rejected publish: %v", err)
	}
	if active != 0 {
		t.Fatalf("active slot after rejected publish = %d, want 0", active)
	}
}

func TestRoutingEpochPreparePublishAndRollback(t *testing.T) {
	core, activeMap := newRoutingEpochTestCore(t)
	epochMap := core.PeekBpf().RoutingEpochMap

	slot, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(17), true)
	if err != nil {
		t.Fatalf("PrepareRoutingEpoch() error = %v", err)
	}
	if slot != 1 {
		t.Fatalf("prepared slot = %d, want inactive slot 1", slot)
	}
	if err := core.StageRoutingEpoch(); err != nil {
		t.Fatalf("StageRoutingEpoch() error = %v", err)
	}

	var epoch uint64
	if err := epochMap.Lookup(slot, &epoch); err != nil {
		t.Fatalf("lookup staged epoch: %v", err)
	}
	if epoch != 17 {
		t.Fatalf("staged epoch = %d, want 17", epoch)
	}

	var active uint32
	if err := activeMap.Lookup(uint32(0), &active); err != nil {
		t.Fatalf("lookup active slot before publish: %v", err)
	}
	if active != 0 {
		t.Fatalf("active slot before publish = %d, want 0", active)
	}

	if err := core.PublishRoutingEpoch(); err != nil {
		t.Fatalf("PublishRoutingEpoch() error = %v", err)
	}
	if err := activeMap.Lookup(uint32(0), &active); err != nil {
		t.Fatalf("lookup active slot after publish: %v", err)
	}
	if active != slot {
		t.Fatalf("active slot after publish = %d, want %d", active, slot)
	}

	if got, ok, err := core.RoutingEpochForSlot(slot); err != nil || !ok || got != 17 {
		t.Fatalf("RoutingEpochForSlot() = (%d, %v, %v), want (17, true, nil)", got, ok, err)
	}
	if err := core.RollbackRoutingEpoch(); err != nil {
		t.Fatalf("RollbackRoutingEpoch() error = %v", err)
	}
	if err := activeMap.Lookup(uint32(0), &active); err != nil {
		t.Fatalf("lookup active slot after rollback: %v", err)
	}
	if active != 0 {
		t.Fatalf("active slot after rollback = %d, want 0", active)
	}

	if err := core.PublishRoutingEpoch(); err != nil {
		t.Fatalf("PublishRoutingEpoch() after rollback error = %v", err)
	}
	if err := activeMap.Lookup(uint32(0), &active); err != nil {
		t.Fatalf("lookup active slot after republish: %v", err)
	}
	if active != slot {
		t.Fatalf("active slot after republish = %d, want %d", active, slot)
	}
}

func TestRoutingEpochFailuresPreserveActiveDomainProjection(t *testing.T) {
	const ipText = "203.0.113.91"
	ip := netip.MustParseAddr(ipText)

	t.Run("preparation failure", func(t *testing.T) {
		core, activeMap, domainMap := newRoutingEpochProjectionTestCore(t)
		activeCache := domainRoutingACache("active-owner", ipText, domainRoutingBitmap(0x1))
		if err := core.BatchUpdateDomainRouting(activeCache); err != nil {
			t.Fatalf("project active domain routing: %v", err)
		}

		if _, err := core.PrepareRoutingEpoch(0, true); err == nil {
			t.Fatal("PrepareRoutingEpoch() error = nil, want invalid epoch error")
		}
		assertActiveRoutingEpochSlot(t, activeMap, 0)
		if got := routingEpochDomainProjection(t, domainMap, 0, ip); got.Bitmap[0] != 0x1 {
			t.Fatalf("active domain projection bitmap = %#x, want %#x", got.Bitmap[0], uint32(0x1))
		}
	})

	t.Run("cutover failure rolls back selector without mixing projections", func(t *testing.T) {
		core, activeMap, domainMap := newRoutingEpochProjectionTestCore(t)
		activeCache := domainRoutingACache("active-owner", ipText, domainRoutingBitmap(0x1))
		if err := core.BatchUpdateDomainRouting(activeCache); err != nil {
			t.Fatalf("project active domain routing: %v", err)
		}

		slot, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(17), true)
		if err != nil {
			t.Fatalf("PrepareRoutingEpoch() error = %v", err)
		}
		if slot != 1 {
			t.Fatalf("prepared routing epoch slot = %d, want 1", slot)
		}
		stagedCache := domainRoutingACache("staged-owner", ipText, domainRoutingBitmap(0x2))
		if err := core.BatchUpdateDomainRouting(stagedCache); err != nil {
			t.Fatalf("project staged domain routing: %v", err)
		}
		if err := core.StageRoutingEpoch(); err != nil {
			t.Fatalf("StageRoutingEpoch() error = %v", err)
		}
		if err := core.PublishRoutingEpoch(); err != nil {
			t.Fatalf("PublishRoutingEpoch() error = %v", err)
		}
		assertActiveRoutingEpochSlot(t, activeMap, 1)

		previousFlip := atomic.SwapInt32(&coreFlip, 1)
		t.Cleanup(func() { atomic.StoreInt32(&coreFlip, previousFlip) })
		core.flipPending = true
		core.flipBase = 0
		core.flip = 1
		if err := core.commitBpfHookFlip(); err == nil {
			t.Fatal("commitBpfHookFlip() error = nil, want conflict")
		}
		if err := core.RollbackRoutingEpoch(); err != nil {
			t.Fatalf("RollbackRoutingEpoch() error = %v", err)
		}

		assertActiveRoutingEpochSlot(t, activeMap, 0)
		if got := routingEpochDomainProjection(t, domainMap, 0, ip); got.Bitmap[0] != 0x1 {
			t.Fatalf("active slot domain projection bitmap = %#x, want %#x", got.Bitmap[0], uint32(0x1))
		}
		if got := routingEpochDomainProjection(t, domainMap, 1, ip); got.Bitmap[0] != 0x2 {
			t.Fatalf("staged slot domain projection bitmap = %#x, want %#x", got.Bitmap[0], uint32(0x2))
		}
	})
}

func TestRoutingEpochHookFlipFailureRestoresPreviousGenerationForRebuild(t *testing.T) {
	oldCore, activeMap := newRoutingEpochTestCore(t)
	if _, err := oldCore.PrepareRoutingEpoch(routing.PolicyEpoch(41), false); err != nil {
		t.Fatalf("prepare previous generation epoch: %v", err)
	}
	if err := oldCore.StageRoutingEpoch(); err != nil {
		t.Fatalf("stage previous generation epoch: %v", err)
	}
	if err := oldCore.PublishRoutingEpoch(); err != nil {
		t.Fatalf("publish previous generation epoch: %v", err)
	}
	assertActiveRoutingEpochSlot(t, activeMap, 0)

	candidate := &controlPlaneCore{}
	candidate.bpf.Store(oldCore.PeekBpf())
	candidate.routingEpochSlot.Store(routingEpochSlotUnset)
	candidate.routingEpochPreviousSlot.Store(routingEpochSlotUnset)
	candidate.routingEpochStagedSlot = routingEpochSlotUnset
	if _, err := candidate.PrepareRoutingEpoch(routing.PolicyEpoch(42), true); err != nil {
		t.Fatalf("prepare candidate epoch: %v", err)
	}
	if err := candidate.StageRoutingEpoch(); err != nil {
		t.Fatalf("stage candidate epoch: %v", err)
	}
	if err := candidate.PublishRoutingEpoch(); err != nil {
		t.Fatalf("publish candidate epoch: %v", err)
	}
	assertActiveRoutingEpochSlot(t, activeMap, 1)

	previousFlip := atomic.SwapInt32(&coreFlip, 1)
	t.Cleanup(func() { atomic.StoreInt32(&coreFlip, previousFlip) })
	candidate.flipPending = true
	candidate.flipBase = 0
	candidate.flip = 1
	if err := candidate.commitBpfHookFlip(); err == nil {
		t.Fatal("commitBpfHookFlip() error = nil, want conflict after candidate selector publish")
	}

	// CommitPreparedDatapath rolls this selector back immediately. The outer
	// staged rollback calls it again before rebuilding the previous generation,
	// so both operations must preserve the old slot for RebuildReloadDatapath.
	if err := candidate.RollbackRoutingEpoch(); err != nil {
		t.Fatalf("rollback candidate selector after hook failure: %v", err)
	}
	if err := candidate.RollbackRoutingEpoch(); err != nil {
		t.Fatalf("outer staged rollback selector restore: %v", err)
	}
	assertActiveRoutingEpochSlot(t, activeMap, 0)

	if err := oldCore.PublishRoutingEpoch(); err != nil {
		t.Fatalf("rebuild previous generation publish: %v", err)
	}
	oldCore.flip = 0
	oldCore.activateBpfHookFlip()
	assertActiveRoutingEpochSlot(t, activeMap, 0)
	if got := atomic.LoadInt32(&coreFlip) & 1; got != 0 {
		t.Fatalf("rebuild previous generation hook flip = %d, want 0", got)
	}
	if got, ok, err := oldCore.RoutingEpochForSlot(0); err != nil || !ok || got != 41 {
		t.Fatalf("previous generation epoch after rebuild = (%d, %v, %v), want (41, true, nil)", got, ok, err)
	}
}

func TestRoutingEpochPostCommitReadinessFailureRestoresPreviousGeneration(t *testing.T) {
	oldCore, activeMap := newRoutingEpochTestCore(t)
	if _, err := oldCore.PrepareRoutingEpoch(routing.PolicyEpoch(51), false); err != nil {
		t.Fatalf("prepare previous generation epoch: %v", err)
	}
	if err := oldCore.StageRoutingEpoch(); err != nil {
		t.Fatalf("stage previous generation epoch: %v", err)
	}
	if err := oldCore.PublishRoutingEpoch(); err != nil {
		t.Fatalf("publish previous generation epoch: %v", err)
	}

	candidateCore := &controlPlaneCore{}
	candidateCore.bpf.Store(oldCore.PeekBpf())
	candidateCore.routingEpochSlot.Store(routingEpochSlotUnset)
	candidateCore.routingEpochPreviousSlot.Store(routingEpochSlotUnset)
	candidateCore.routingEpochStagedSlot = routingEpochSlotUnset
	if _, err := candidateCore.PrepareRoutingEpoch(routing.PolicyEpoch(52), true); err != nil {
		t.Fatalf("prepare candidate epoch: %v", err)
	}
	if err := candidateCore.StageRoutingEpoch(); err != nil {
		t.Fatalf("stage candidate epoch: %v", err)
	}
	if err := candidateCore.PublishRoutingEpoch(); err != nil {
		t.Fatalf("publish candidate epoch: %v", err)
	}

	previousFlip := atomic.SwapInt32(&coreFlip, 0)
	t.Cleanup(func() { atomic.StoreInt32(&coreFlip, previousFlip) })
	candidateCore.flipPending = true
	candidateCore.flipBase = 0
	candidateCore.flip = 1
	if err := candidateCore.commitBpfHookFlip(); err != nil {
		t.Fatalf("commit candidate hook flip: %v", err)
	}
	assertActiveRoutingEpochSlot(t, activeMap, 1)
	if got := atomic.LoadInt32(&coreFlip) & 1; got != 1 {
		t.Fatalf("candidate hook flip = %d, want 1", got)
	}

	// This models a listener publication or DNS warmup failure after
	// CommitPreparedDatapath has completed but before the runtime supervisor
	// publishes the candidate. rollbackStagedReloadHandoff uses this public
	// rollback method before RebuildReloadDatapath restores the old owner.
	candidate := &ControlPlane{core: candidateCore}
	if err := candidate.RollbackPreparedRoutingEpoch(); err != nil {
		t.Fatalf("rollback prepared candidate after readiness failure: %v", err)
	}
	if err := oldCore.PublishRoutingEpoch(); err != nil {
		t.Fatalf("rebuild previous generation publish: %v", err)
	}
	oldCore.flip = 0
	oldCore.activateBpfHookFlip()

	assertActiveRoutingEpochSlot(t, activeMap, 0)
	if got := atomic.LoadInt32(&coreFlip) & 1; got != 0 {
		t.Fatalf("previous generation hook flip after readiness rollback = %d, want 0", got)
	}
	if got, ok, err := oldCore.RoutingEpochForSlot(0); err != nil || !ok || got != 51 {
		t.Fatalf("previous generation epoch after readiness rollback = (%d, %v, %v), want (51, true, nil)", got, ok, err)
	}
}
