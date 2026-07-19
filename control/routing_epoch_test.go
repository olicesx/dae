/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

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

func TestFreshRoutingEpochHasNoPreviousProjectionToRetire(t *testing.T) {
	core, activeMap := newRoutingEpochTestCore(t)

	slot, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(17), false)
	if err != nil {
		t.Fatalf("PrepareRoutingEpoch() error = %v", err)
	}
	if slot != 0 {
		t.Fatalf("prepared slot = %d, want fresh slot 0", slot)
	}
	if previous := core.routingEpochPreviousSlot.Load(); previous != routingEpochSlotUnset {
		t.Fatalf("previous slot = %d, want unset", previous)
	}
	if err := core.StageRoutingEpoch(); err != nil {
		t.Fatalf("StageRoutingEpoch() error = %v", err)
	}
	if err := core.PublishRoutingEpoch(); err != nil {
		t.Fatalf("PublishRoutingEpoch() error = %v", err)
	}

	cleanupCalls := 0
	if err := core.finalizePreviousRoutingEpochWithCleanup(func(*bpfObjects, uint32) error {
		cleanupCalls++
		return nil
	}); err != nil {
		t.Fatalf("finalizePreviousRoutingEpochWithCleanup() error = %v", err)
	}
	if cleanupCalls != 0 {
		t.Fatalf("fresh projection cleanup calls = %d, want 0", cleanupCalls)
	}
	assertActiveRoutingEpochSlot(t, activeMap, 0)
	if got, ok, err := core.RoutingEpochForSlot(0); err != nil || !ok || got != 17 {
		t.Fatalf("RoutingEpochForSlot(0) = (%d, %v, %v), want (17, true, nil)", got, ok, err)
	}
}

func TestSharedRoutingEpochKeepsPreviousProjectionForRetirement(t *testing.T) {
	core, activeMap := newRoutingEpochTestCore(t)

	slot, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(18), true)
	if err != nil {
		t.Fatalf("PrepareRoutingEpoch() error = %v", err)
	}
	if slot != 1 {
		t.Fatalf("prepared slot = %d, want shared inactive slot 1", slot)
	}
	if previous := core.routingEpochPreviousSlot.Load(); previous != 0 {
		t.Fatalf("previous slot = %d, want active slot 0", previous)
	}
	if err := core.StageRoutingEpoch(); err != nil {
		t.Fatalf("StageRoutingEpoch() error = %v", err)
	}
	if err := core.PublishRoutingEpoch(); err != nil {
		t.Fatalf("PublishRoutingEpoch() error = %v", err)
	}

	cleanupCalls := 0
	var cleanedSlot uint32
	if err := core.finalizePreviousRoutingEpochWithCleanup(func(_ *bpfObjects, slot uint32) error {
		cleanupCalls++
		cleanedSlot = slot
		return nil
	}); err != nil {
		t.Fatalf("finalizePreviousRoutingEpochWithCleanup() error = %v", err)
	}
	if cleanupCalls != 1 || cleanedSlot != 0 {
		t.Fatalf("shared projection cleanup = (%d, %d), want (1, 0)", cleanupCalls, cleanedSlot)
	}
	assertActiveRoutingEpochSlot(t, activeMap, 1)
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

func TestRoutingEpochRetirementReleasesPreviousDomainProjection(t *testing.T) {
	const ipText = "203.0.113.92"
	ip := netip.MustParseAddr(ipText)
	core, activeMap, domainMap := newRoutingEpochProjectionTestCore(t)
	core.PeekBpf().RoutingMetaMap = newJanitorTestMap(t, "routing_meta_map")

	previousCache := domainRoutingACache("previous-owner", ipText, domainRoutingBitmap(0x1))
	if err := core.BatchUpdateDomainRouting(previousCache); err != nil {
		t.Fatalf("project previous domain routing: %v", err)
	}
	previousTracker := core.domainRoutingSlots[0]

	if _, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(18), true); err != nil {
		t.Fatalf("prepare next routing epoch: %v", err)
	}
	currentCache := domainRoutingACache("current-owner", ipText, domainRoutingBitmap(0x2))
	if err := core.BatchUpdateDomainRouting(currentCache); err != nil {
		t.Fatalf("project current domain routing: %v", err)
	}
	if err := core.StageRoutingEpoch(); err != nil {
		t.Fatalf("stage next routing epoch: %v", err)
	}
	if err := core.PublishRoutingEpoch(); err != nil {
		t.Fatalf("publish next routing epoch: %v", err)
	}

	(&ControlPlane{core: core}).RunReloadRetirementCleanup(0)
	assertActiveRoutingEpochSlot(t, activeMap, 1)
	if core.routingEpochPreviousSlot.Load() != routingEpochSlotUnset {
		t.Fatalf("previous routing epoch slot = %d, want unset", core.routingEpochPreviousSlot.Load())
	}
	if core.domainRoutingSlots[0] == previousTracker {
		t.Fatal("previous userspace domain projection tracker was retained")
	}

	ip16 := ip.As16()
	previousKey := bpfRoutingEpochIp{Slot: 0, Addr: common.Ipv6ByteSliceToUint32Array(ip16[:])}
	var previousProjection bpfDomainRouting
	if err := domainMap.Lookup(&previousKey, &previousProjection); err == nil {
		t.Fatalf("previous kernel domain projection still exists: %#v", previousProjection)
	}
	if got := routingEpochDomainProjection(t, domainMap, 1, ip); got.Bitmap[0] != 0x2 {
		t.Fatalf("active domain projection bitmap = %#x, want %#x", got.Bitmap[0], uint32(0x2))
	}
	if got, ok, err := core.RoutingEpochForSlot(0); err != nil || ok || got != 0 {
		t.Fatalf("retired RoutingEpochForSlot(0) = (%d, %v, %v), want (0, false, nil)", got, ok, err)
	}
	var previousRuleCount uint32
	if err := core.PeekBpf().RoutingMetaMap.Lookup(uint32(0), &previousRuleCount); err != nil {
		t.Fatalf("lookup retired routing metadata: %v", err)
	}
	if previousRuleCount != 0 {
		t.Fatalf("retired routing metadata length = %d, want 0", previousRuleCount)
	}
	if err := core.RollbackRoutingEpoch(); err != nil {
		t.Fatalf("rollback after retirement: %v", err)
	}
	assertActiveRoutingEpochSlot(t, activeMap, 1)
}

func TestRoutingEpochRetirementRejectsUnpublishedTarget(t *testing.T) {
	const ipText = "203.0.113.93"
	ip := netip.MustParseAddr(ipText)
	core, activeMap, domainMap := newRoutingEpochProjectionTestCore(t)
	cache := domainRoutingACache("active-owner", ipText, domainRoutingBitmap(0x1))
	if err := core.BatchUpdateDomainRouting(cache); err != nil {
		t.Fatalf("project active domain routing: %v", err)
	}
	if _, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(19), true); err != nil {
		t.Fatalf("prepare unpublished routing epoch: %v", err)
	}

	if err := core.finalizePreviousRoutingEpoch(); err == nil {
		t.Fatal("finalizePreviousRoutingEpoch() error = nil before target publication")
	}
	assertActiveRoutingEpochSlot(t, activeMap, 0)
	if core.routingEpochPreviousSlot.Load() != 0 {
		t.Fatalf("previous slot changed after rejected retirement: %d", core.routingEpochPreviousSlot.Load())
	}
	if got := routingEpochDomainProjection(t, domainMap, 0, ip); got.Bitmap[0] != 0x1 {
		t.Fatalf("active projection changed after rejected retirement: %#x", got.Bitmap[0])
	}
}

func TestRoutingEpochRetirementRetriesKernelCleanupAfterFailure(t *testing.T) {
	core, activeMap, _ := newRoutingEpochProjectionTestCore(t)
	core.PeekBpf().RoutingMetaMap = newJanitorTestMap(t, "routing_meta_map")

	if _, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(20), true); err != nil {
		t.Fatalf("prepare next routing epoch: %v", err)
	}
	if err := core.StageRoutingEpoch(); err != nil {
		t.Fatalf("stage next routing epoch: %v", err)
	}
	if err := core.PublishRoutingEpoch(); err != nil {
		t.Fatalf("publish next routing epoch: %v", err)
	}
	var (
		cleanupCalls int
		waitDelays   []time.Duration
	)
	wantErr := stderrors.New("injected partial cleanup failure")
	cleanup := func(bpf *bpfObjects, previous uint32) error {
		cleanupCalls++
		err := clearPreviousRoutingEpochMaps(bpf, previous)
		if cleanupCalls == 1 {
			return stderrors.Join(err, wantErr)
		}
		return err
	}
	err := retryPreviousRoutingEpochCleanup(
		context.Background(),
		func() error {
			return core.finalizePreviousRoutingEpochWithCleanup(cleanup)
		},
		func(_ context.Context, delay time.Duration) error {
			waitDelays = append(waitDelays, delay)
			if got := core.routingEpochPreviousSlot.Load(); got != 0 {
				t.Fatalf("cleanup retry slot = %d, want 0", got)
			}
			if !core.routingEpochRollbackOff.Load() {
				t.Fatal("rollback remained enabled after retirement cleanup started")
			}
			if err := core.RollbackRoutingEpoch(); err != nil {
				t.Fatalf("disabled rollback returned error: %v", err)
			}
			assertActiveRoutingEpochSlot(t, activeMap, 1)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("retryPreviousRoutingEpochCleanup(): %v", err)
	}
	if cleanupCalls != 2 {
		t.Fatalf("cleanup calls = %d, want 2", cleanupCalls)
	}
	if len(waitDelays) != 1 || waitDelays[0] != routingEpochCleanupInitialRetryDelay {
		t.Fatalf("retry delays = %v, want [%v]", waitDelays, routingEpochCleanupInitialRetryDelay)
	}
	if got := core.routingEpochPreviousSlot.Load(); got != routingEpochSlotUnset {
		t.Fatalf("cleanup retry slot after success = %d, want unset", got)
	}
}

func TestRoutingEpochRetirementRetryIsBounded(t *testing.T) {
	wantErr := stderrors.New("persistent cleanup failure")
	var (
		cleanupCalls int
		waitDelays   []time.Duration
	)
	err := retryPreviousRoutingEpochCleanup(
		context.Background(),
		func() error {
			cleanupCalls++
			return wantErr
		},
		func(_ context.Context, delay time.Duration) error {
			waitDelays = append(waitDelays, delay)
			return nil
		},
	)
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("retry error = %v, want persistent cleanup failure", err)
	}
	if cleanupCalls != routingEpochCleanupMaxAttempts {
		t.Fatalf("cleanup calls = %d, want %d", cleanupCalls, routingEpochCleanupMaxAttempts)
	}
	if len(waitDelays) != routingEpochCleanupMaxAttempts-1 {
		t.Fatalf("retry wait count = %d, want %d", len(waitDelays), routingEpochCleanupMaxAttempts-1)
	}
	wantDelays := [...]time.Duration{
		25 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
	}
	for attempt, delay := range waitDelays {
		want := wantDelays[attempt]
		if delay != want {
			t.Fatalf("retry delay %d = %v, want %v", attempt+1, delay, want)
		}
	}
}

func TestRoutingEpochRetirementRetryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wantErr := stderrors.New("cleanup failure")
	cleanupCalls := 0
	waitCalls := 0
	err := retryPreviousRoutingEpochCleanup(
		ctx,
		func() error {
			cleanupCalls++
			return wantErr
		},
		func(ctx context.Context, _ time.Duration) error {
			waitCalls++
			cancel()
			return ctx.Err()
		},
	)
	if !stderrors.Is(err, context.Canceled) {
		t.Fatalf("retry error = %v, want context cancellation", err)
	}
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("retry error = %v, want last cleanup failure", err)
	}
	if cleanupCalls != 1 || waitCalls != 1 {
		t.Fatalf("cleanup/wait calls = %d/%d, want 1/1", cleanupCalls, waitCalls)
	}
}

func TestRunReloadRetirementCleanupHonorsCanceledContext(t *testing.T) {
	core, activeMap, _ := newRoutingEpochProjectionTestCore(t)
	if _, err := core.PrepareRoutingEpoch(routing.PolicyEpoch(21), true); err != nil {
		t.Fatalf("prepare next routing epoch: %v", err)
	}
	if err := core.StageRoutingEpoch(); err != nil {
		t.Fatalf("stage next routing epoch: %v", err)
	}
	if err := core.PublishRoutingEpoch(); err != nil {
		t.Fatalf("publish next routing epoch: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	(&ControlPlane{core: core, ctx: ctx}).RunReloadRetirementCleanup(0)

	if got := core.routingEpochPreviousSlot.Load(); got != 0 {
		t.Fatalf("previous routing epoch slot = %d, want retained slot 0", got)
	}
	if core.routingEpochRollbackOff.Load() {
		t.Fatal("rollback disabled even though canceled cleanup never started")
	}
	assertActiveRoutingEpochSlot(t, activeMap, 1)
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

func TestCommittedBpfHookFlipRollbackAllowsNextFreshCandidate(t *testing.T) {
	previousFlip := atomic.SwapInt32(&coreFlip, 0)
	t.Cleanup(func() { atomic.StoreInt32(&coreFlip, previousFlip) })

	first := &controlPlaneCore{
		isReload:    true,
		flip:        1,
		flipBase:    0,
		flipPending: true,
	}
	if err := first.commitBpfHookFlip(); err != nil {
		t.Fatalf("first commitBpfHookFlip() error = %v", err)
	}
	if got := atomic.LoadInt32(&coreFlip) & 1; got != 1 {
		t.Fatalf("committed hook flip = %d, want 1", got)
	}
	if err := first.rollbackCommittedBpfHookFlip(); err != nil {
		t.Fatalf("rollbackCommittedBpfHookFlip() error = %v", err)
	}
	if got := atomic.LoadInt32(&coreFlip) & 1; got != 0 {
		t.Fatalf("rolled back hook flip = %d, want 0", got)
	}

	second := &controlPlaneCore{
		isReload:    true,
		flip:        1,
		flipBase:    atomic.LoadInt32(&coreFlip) & 1,
		flipPending: true,
	}
	if err := second.commitBpfHookFlip(); err != nil {
		t.Fatalf("second commitBpfHookFlip() error = %v", err)
	}
	if got := atomic.LoadInt32(&coreFlip) & 1; got != 1 {
		t.Fatalf("second committed hook flip = %d, want 1", got)
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
