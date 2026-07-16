/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "github.com/daeuniverse/dae/component/routing"

// PolicySnapshot returns the immutable routing policy for this control-plane generation.
func (c *ControlPlane) PolicySnapshot() *routing.PolicySnapshot {
	if c == nil {
		return nil
	}
	return c.policySnapshot
}

// RoutingEpochForSlot returns kernel-plan metadata for diagnostics and replay.
// It does not participate in routing or alter any control-plane state.
func (c *ControlPlane) RoutingEpochForSlot(slot uint32) (routing.PolicyEpoch, bool, error) {
	if c == nil || c.core == nil {
		return 0, false, nil
	}
	return c.core.RoutingEpochForSlot(slot)
}

// RollbackPreparedRoutingEpoch restores the previously active kernel plan
// before a failed prepared generation releases its slot-owned resources.
func (c *ControlPlane) RollbackPreparedRoutingEpoch() error {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.RollbackRoutingEpoch()
}

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -tags "!dae_stub_ebpf" -target "$BPF_TARGET" -type port_range -type tuples_key bpf kern/tproxy.c -- -I./headers
