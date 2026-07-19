/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func putUDPConnStateForEpochFallbackTest(t *testing.T, connMap *ebpf.Map, keys []bpfTuplesKey) {
	t.Helper()
	for _, key := range keys {
		state := bpfConnState{
			LastSeenNs:         1,
			RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
			DatapathGeneration: 1,
		}
		state.Meta.Data.HasRouting = 1
		state.Meta.Data.Outbound = 3
		if err := connMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update conn-state: %v", err)
		}
	}
}

func assertUDPConnStatePresentForEpochFallbackTest(t *testing.T, connMap *ebpf.Map, keys []bpfTuplesKey) {
	t.Helper()
	for _, key := range keys {
		var state bpfConnState
		if err := connMap.Lookup(&key, &state); err != nil {
			t.Fatalf("conn-state lookup failed: %v", err)
		}
	}
}

func TestUnownedUDPCurrentPolicyFallbackDecisionBoundary(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	connMap := newJanitorTestMap(t, "conn_state_map")
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connMap}})

	src := netip.MustParseAddrPort("192.0.2.47:53007")
	dst := netip.MustParseAddrPort("198.51.100.47:443")
	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_UDP),
		bpfTuplesKeyFromAddrPorts(dst, src, unix.IPPROTO_UDP),
	}
	stale := &bpfRoutingResult{
		Mark:               91,
		Must:               1,
		Outbound:           3,
		Pid:                47,
		Dscp:               46,
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 1,
	}
	active := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(active, 2)
	active.sessionManager = manager
	active.publishActiveControlPlane()

	if _, _, ownerErr := active.acquireRoutingEpochExecutionOwner(stale); !stderrors.Is(ownerErr, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("owner error = %v, want unavailable stale generation", ownerErr)
	}
	putUDPConnStateForEpochFallbackTest(t, connMap, keys)
	fallbackResult, fallback, err := active.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale)
	if err != nil || !fallback {
		t.Fatalf("active unowned fallback = (%v, %v), want (true, nil)", fallback, err)
	}
	if fallbackResult == nil || fallbackResult.Outbound != uint8(consts.OutboundControlPlaneRouting) || fallbackResult.Mark != 0 ||
		fallbackResult.Must != 0 || fallbackResult.DatapathGeneration != 0 || fallbackResult.Pid != stale.Pid {
		t.Fatalf("current-policy fallback result = %+v", fallbackResult)
	}
	for _, key := range keys {
		var state bpfConnState
		if err := connMap.Lookup(&key, &state); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("unowned conn-state error = %v, want %v", err, ebpf.ErrKeyNotExist)
		}
	}

	putUDPConnStateForEpochFallbackTest(t, connMap, keys)
	manager.RetainUdpConnStateTuples(keys)
	if _, fallback, err := active.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale); err != nil || fallback {
		t.Fatalf("active pinned fallback = (%v, %v), want (false, nil)", fallback, err)
	}
	assertUDPConnStatePresentForEpochFallbackTest(t, connMap, keys)
	if err := manager.ReleaseUdpConnStateTuples(keys); err != nil {
		t.Fatalf("release pinned conn-state: %v", err)
	}

	putUDPConnStateForEpochFallbackTest(t, connMap, keys)
	retired := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(retired, 1)
	retired.sessionManager = manager
	if _, fallback, err := retired.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale); err != nil || fallback {
		t.Fatalf("retired fallback = (%v, %v), want (false, nil)", fallback, err)
	}
	assertUDPConnStatePresentForEpochFallbackTest(t, connMap, keys)
}

func TestProvisionalRoutingEpochOwnerCannotUseCurrentPolicyFallbackUntilPublished(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	connMap := newJanitorTestMap(t, "conn_state_map")
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connMap}})

	src := netip.MustParseAddrPort("192.0.2.48:53008")
	dst := netip.MustParseAddrPort("198.51.100.48:443")
	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_UDP),
		bpfTuplesKeyFromAddrPorts(dst, src, unix.IPPROTO_UDP),
	}
	stale := &bpfRoutingResult{
		Outbound:           3,
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 1,
	}

	previous := newRoutingEpochExecutionTestPlane(0)
	setRoutingEpochExecutionTestGeneration(previous, 1)
	previous.publishActiveControlPlane()

	candidate := newRoutingEpochExecutionTestPlane(0)
	candidate.core.isReload = true
	markRoutingEpochExecutionTestPlaneReady(candidate)
	setRoutingEpochExecutionTestGeneration(candidate, 2)
	candidate.sessionManager = manager
	if err := candidate.RegisterProvisionalRoutingEpochExecutionOwner(); err != nil {
		t.Fatalf("RegisterProvisionalRoutingEpochExecutionOwner() error = %v", err)
	}
	if active := activeControlPlanePublication.plane.Load(); active != previous {
		t.Fatalf("active plane after provisional registration = %p, want previous %p", active, previous)
	}

	putUDPConnStateForEpochFallbackTest(t, connMap, keys)
	if _, fallback, err := candidate.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale); err != nil || fallback {
		t.Fatalf("provisional candidate fallback = (%v, %v), want (false, nil)", fallback, err)
	}
	assertUDPConnStatePresentForEpochFallbackTest(t, connMap, keys)

	candidate.publishActiveControlPlane()
	candidate.UnregisterProvisionalRoutingEpochExecutionOwner()
	if active := activeControlPlanePublication.plane.Load(); active != candidate {
		t.Fatalf("active plane after promotion = %p, want candidate %p", active, candidate)
	}
	if _, fallback, err := candidate.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale); err != nil || !fallback {
		t.Fatalf("published candidate fallback = (%v, %v), want (true, nil)", fallback, err)
	}
	for _, key := range keys {
		var state bpfConnState
		if err := connMap.Lookup(&key, &state); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("published fallback conn-state error = %v, want %v", err, ebpf.ErrKeyNotExist)
		}
	}
}
