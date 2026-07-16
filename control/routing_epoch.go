/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/component/routing"
)

const (
	routingEpochSlotCount = 2
	routingEpochSlotUnset = ^uint32(0)
)

func validRoutingEpochSlot(slot uint32) bool {
	return slot < routingEpochSlotCount
}

func (c *controlPlaneCore) hasRoutingEpochMaps(bpf *bpfObjects) bool {
	return bpf != nil && bpf.ActiveRoutingEpochMap != nil && bpf.RoutingEpochMap != nil
}

func (c *controlPlaneCore) clearStagedRoutingEpochLocked() {
	c.routingEpochStaged = false
	c.routingEpochStagedSlot = routingEpochSlotUnset
	c.routingEpochStagedEpoch = 0
}

func (c *controlPlaneCore) hasStagedRoutingEpochLocked(slot uint32, epoch uint64) bool {
	return c.routingEpochStaged && c.routingEpochStagedSlot == slot && c.routingEpochStagedEpoch == epoch
}

func (c *controlPlaneCore) readActiveRoutingEpochSlot() (uint32, error) {
	if c == nil {
		return 0, nil
	}
	bpf := c.PeekBpf()
	if !c.hasRoutingEpochMaps(bpf) {
		return 0, nil
	}
	var slot uint32
	if err := bpf.ActiveRoutingEpochMap.Lookup(uint32(0), &slot); err != nil {
		return 0, fmt.Errorf("lookup active routing epoch slot: %w", err)
	}
	if !validRoutingEpochSlot(slot) {
		return 0, fmt.Errorf("active routing epoch slot %d is invalid", slot)
	}
	return slot, nil
}

// PrepareRoutingEpoch reserves the route-plan slot used by this control-plane
// generation. Shared BPF reloads prepare the inactive slot; fresh datapaths
// use their zero-initialized active slot.
func (c *controlPlaneCore) PrepareRoutingEpoch(epoch routing.PolicyEpoch, sharedReload bool) (uint32, error) {
	if c == nil {
		return 0, nil
	}
	phase1Recorder, phase1StartedAt := beginPhase1BPFPublishObservation()
	if epoch == 0 {
		observePhase0RoutingEpoch(phase0RoutingEpochPrepare, phase0ObservationFailure)
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishPrepare, phase1BPFPublishFailure)
		return 0, fmt.Errorf("routing policy epoch must be non-zero")
	}

	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()
	c.clearStagedRoutingEpochLocked()

	active, err := c.readActiveRoutingEpochSlot()
	if err != nil {
		observePhase0RoutingEpoch(phase0RoutingEpochPrepare, phase0ObservationFailure)
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishPrepare, phase1BPFPublishFailure)
		return 0, err
	}
	target := active
	if sharedReload {
		target ^= 1
	}
	c.routingEpochPreviousSlot.Store(active)
	c.routingEpochSlot.Store(target)
	c.routingEpochPolicyEpoch.Store(uint64(epoch))
	observePhase0RoutingEpoch(phase0RoutingEpochPrepare, phase0ObservationSuccess)
	endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishPrepare, phase1BPFPublishSuccess)
	return target, nil
}

func (c *controlPlaneCore) RoutingEpochSlot() uint32 {
	if c == nil {
		return 0
	}
	if slot := c.routingEpochSlot.Load(); validRoutingEpochSlot(slot) {
		return slot
	}
	return 0
}

func (c *controlPlaneCore) routingEpochEnabled() bool {
	if c == nil {
		return false
	}
	return c.hasRoutingEpochMaps(c.PeekBpf()) && validRoutingEpochSlot(c.routingEpochSlot.Load())
}

// StageRoutingEpoch records the policy epoch for this generation's prepared
// slot. The selector is deliberately not changed here.
func (c *controlPlaneCore) StageRoutingEpoch() error {
	if c == nil {
		return nil
	}
	phase1Recorder, phase1StartedAt := beginPhase1BPFPublishObservation()
	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()
	c.clearStagedRoutingEpochLocked()

	bpf := c.PeekBpf()
	if !c.hasRoutingEpochMaps(bpf) {
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishStage, phase1BPFPublishSuccess)
		return nil
	}
	slot := c.routingEpochSlot.Load()
	epoch := c.routingEpochPolicyEpoch.Load()
	if !validRoutingEpochSlot(slot) {
		observePhase0RoutingEpoch(phase0RoutingEpochStage, phase0ObservationFailure)
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishStage, phase1BPFPublishFailure)
		return fmt.Errorf("routing epoch slot %d is invalid", slot)
	}
	if epoch == 0 {
		observePhase0RoutingEpoch(phase0RoutingEpochStage, phase0ObservationFailure)
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishStage, phase1BPFPublishFailure)
		return fmt.Errorf("routing epoch slot %d has no policy epoch", slot)
	}
	if err := bpf.RoutingEpochMap.Update(slot, epoch, ebpf.UpdateAny); err != nil {
		observePhase0RoutingEpoch(phase0RoutingEpochStage, phase0ObservationFailure)
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishStage, phase1BPFPublishFailure)
		return fmt.Errorf("stage routing epoch %d in slot %d: %w", epoch, slot, err)
	}
	c.routingEpochStaged = true
	c.routingEpochStagedSlot = slot
	c.routingEpochStagedEpoch = epoch
	observePhase0RoutingEpoch(phase0RoutingEpochStage, phase0ObservationSuccess)
	endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishStage, phase1BPFPublishSuccess)
	return nil
}

// PublishRoutingEpoch atomically changes the slot consulted by route(). Call
// it only after the selected slot's rules, LPM tries, and domain projection
// have all been prepared.
func (c *controlPlaneCore) PublishRoutingEpoch() error {
	if c == nil {
		return nil
	}
	phase1Recorder, phase1StartedAt := beginPhase1BPFPublishObservation()
	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()

	bpf := c.PeekBpf()
	if !c.hasRoutingEpochMaps(bpf) {
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishPublish, phase1BPFPublishSuccess)
		return nil
	}
	slot := c.routingEpochSlot.Load()
	epoch := c.routingEpochPolicyEpoch.Load()
	if !validRoutingEpochSlot(slot) || epoch == 0 || !c.hasStagedRoutingEpochLocked(slot, epoch) {
		observePhase0RoutingEpoch(phase0RoutingEpochPublish, phase0ObservationFailure)
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishPublish, phase1BPFPublishFailure)
		return fmt.Errorf("routing epoch slot %d with policy epoch %d has not been staged", slot, epoch)
	}
	if err := bpf.ActiveRoutingEpochMap.Update(uint32(0), slot, ebpf.UpdateAny); err != nil {
		observePhase0RoutingEpoch(phase0RoutingEpochPublish, phase0ObservationFailure)
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishPublish, phase1BPFPublishFailure)
		return fmt.Errorf("publish routing epoch slot %d: %w", slot, err)
	}
	observePhase0RoutingEpoch(phase0RoutingEpochPublish, phase0ObservationSuccess)
	endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishPublish, phase1BPFPublishSuccess)
	return nil
}

// RollbackRoutingEpoch restores the slot that was active when this generation
// began preparation. It does not mutate either plan's maps.
func (c *controlPlaneCore) RollbackRoutingEpoch() error {
	if c == nil {
		return nil
	}
	phase1Recorder, phase1StartedAt := beginPhase1BPFPublishObservation()
	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()

	bpf := c.PeekBpf()
	if !c.hasRoutingEpochMaps(bpf) {
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishRollback, phase1BPFPublishSuccess)
		return nil
	}
	previous := c.routingEpochPreviousSlot.Load()
	if !validRoutingEpochSlot(previous) {
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishRollback, phase1BPFPublishSuccess)
		return nil
	}
	if err := bpf.ActiveRoutingEpochMap.Update(uint32(0), previous, ebpf.UpdateAny); err != nil {
		observePhase0RoutingEpoch(phase0RoutingEpochRollback, phase0ObservationFailure)
		endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishRollback, phase1BPFPublishFailure)
		return fmt.Errorf("rollback routing epoch slot %d: %w", previous, err)
	}
	observePhase0RoutingEpoch(phase0RoutingEpochRollback, phase0ObservationSuccess)
	endPhase1BPFPublishObservation(phase1Recorder, phase1StartedAt, phase1BPFPublishRollback, phase1BPFPublishSuccess)
	return nil
}

// RoutingEpochForSlot returns metadata for diagnostics and replay. It never
// participates in a forwarding decision.
func (c *controlPlaneCore) RoutingEpochForSlot(slot uint32) (routing.PolicyEpoch, bool, error) {
	if c == nil || !validRoutingEpochSlot(slot) {
		return 0, false, nil
	}
	bpf := c.PeekBpf()
	if !c.hasRoutingEpochMaps(bpf) {
		return 0, false, nil
	}
	var epoch uint64
	if err := bpf.RoutingEpochMap.Lookup(slot, &epoch); err != nil {
		if stderrors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("lookup routing epoch slot %d: %w", slot, err)
	}
	if epoch == 0 {
		return 0, false, nil
	}
	return routing.PolicyEpoch(epoch), true, nil
}

func (c *controlPlaneCore) domainRoutingTrackerForSlot(slot uint32) *domainRoutingTracker {
	if c == nil || !validRoutingEpochSlot(slot) {
		return nil
	}
	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()
	if slot == 0 && c.domainRouting != nil && c.domainRoutingSlots[slot] == nil {
		c.domainRoutingSlots[slot] = c.domainRouting
	}
	if c.domainRoutingSlots[slot] == nil {
		c.domainRoutingSlots[slot] = newDomainRoutingTracker()
		if slot == 0 {
			c.domainRouting = c.domainRoutingSlots[slot]
		}
	}
	return c.domainRoutingSlots[slot]
}

func (c *controlPlaneCore) resetDomainRoutingSlot(slot uint32) {
	if c == nil || !validRoutingEpochSlot(slot) {
		return
	}
	c.routingEpochMu.Lock()
	c.domainRoutingSlots[slot] = newDomainRoutingTracker()
	if slot == 0 {
		c.domainRouting = c.domainRoutingSlots[slot]
	}
	c.routingEpochMu.Unlock()
}

func (c *controlPlaneCore) clearDomainRoutingSlot(slot uint32) error {
	if c == nil || !validRoutingEpochSlot(slot) {
		return nil
	}
	c.domainRoutingProjectionMu[slot].Lock()
	defer c.domainRoutingProjectionMu[slot].Unlock()
	if err := clearReloadDomainRoutingMapSlot(c.PeekBpf(), slot); err != nil {
		return err
	}
	c.resetDomainRoutingSlot(slot)
	return nil
}
