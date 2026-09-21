/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

// A retained (old-epoch) session applies the same per-peer liveness gate as a
// current-epoch one: a peer whose mapping the far end has forgotten has to be
// promoted to its own session instead of being written into a hole, while the
// peers that still answer keep using the retained session until its epoch
// drains.
func TestRetainedUDPEndpointDeclinesShortcutForReapedPeer(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()

	cp := newUdpReuseSimulationControlPlane(nil)
	cp.sessionManager = manager

	src := netip.MustParseAddrPort("10.0.0.1:4444")
	peerA := netip.MustParseAddrPort("10.0.0.2:5000")
	peerB := netip.MustParseAddrPort("10.0.0.3:5000")
	now := time.Now()
	droughtAt := now.Add(-udpEndpointReplyDroughtWindow - time.Second)

	ue := newTestEndpoint(&mockPacketConn{})
	ue.Dialer = newTestEndpointDialer(&mockPacketConn{})
	ue.poolKey = UdpEndpointKey{Src: src}
	ue.hasSent.Store(true)
	ue.notePeerReply(peerA, droughtAt.UnixNano())
	ue.notePeerReply(peerB, droughtAt.UnixNano())
	// Peer A's upstream is answering; peer B's has been silent for a drought.
	ue.notePeerReply(peerA, now.Add(-time.Second).UnixNano())
	for range 20 {
		ue.notePeerWrite(peerB.String(), now)
	}
	if !ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("precondition: the reaped peer must need its own session")
	}

	manager.generationsMu.Lock()
	manager.appendUDPFlowSourceLocked(src, &UDPFlowRuntime{
		manager:  manager,
		endpoint: ue,
		binding:  UdpFlowBinding{Route: UdpRouteBinding{PolicyEpoch: routing.PolicyEpoch(7)}},
	})
	manager.generationsMu.Unlock()

	// The lookup itself must succeed, or the test would pass for the wrong
	// reason: the handler has to decline deliberately, not miss the session.
	if _, ok := manager.retainedUDPEndpoint(src, peerB, &bpfRoutingResult{}, cp.PolicyEpoch()); !ok {
		t.Fatal("precondition: the stale-epoch session must be found as retained")
	}
	if cp.handleRetainedUDPEndpoint([]byte("hello"), src, peerB, &bpfRoutingResult{}, UdpFlowDecision{}) {
		t.Fatal("the retained path consumed a reaped peer's datagram: the promotion below the lookup would never run")
	}
	if !cp.handleRetainedUDPEndpoint([]byte("hello"), src, peerA, &bpfRoutingResult{}, UdpFlowDecision{}) {
		t.Fatal("a healthy peer must keep being served by the retained session")
	}
}

// The production packet path is handlePktWithPrefetch, which tries the retained
// shortcut and only then dials. The helper test above pins the decline; this
// one drives the whole chain: a reaped peer on a stale-epoch session must not
// be written into that session, must cause a current-epoch dial, and a healthy
// peer on the same retained session must keep using it.
func TestHandlePktWithPrefetch_RetainedReapedPeerDialsOnNormalPath(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	t.Cleanup(func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	})

	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()

	newConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	t.Cleanup(func() { _ = newConn.Close() })
	d, underlay := newCountingProxyEndpointDialer("socks5", "proxy.example:1080", newConn)
	group := newTestFixedOutboundGroup(d)
	cp := newUdpReuseSimulationControlPlane(group)
	cp.sessionManager = manager

	src := netip.MustParseAddrPort("10.0.0.1:4444")
	peerA := netip.MustParseAddrPort("10.0.0.2:5000")
	peerB := netip.MustParseAddrPort("10.0.0.3:5000")
	now := time.Now()
	droughtAt := now.Add(-udpEndpointReplyDroughtWindow - time.Second)

	var retainedWrites atomic.Int32
	var retainedWriteToB atomic.Int32
	retainedConn := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			retainedWrites.Add(1)
			if addr == peerB.String() {
				retainedWriteToB.Add(1)
			}
			return len(p), nil
		},
	}

	ue := newTestEndpoint(retainedConn)
	ue.Dialer = d
	ue.Outbound = group
	ue.poolKey = UdpEndpointKey{Src: src}
	ue.hasSent.Store(true)
	ue.notePeerReply(peerA, droughtAt.UnixNano())
	ue.notePeerReply(peerB, droughtAt.UnixNano())
	ue.notePeerReply(peerA, now.Add(-time.Second).UnixNano())
	for range 20 {
		ue.notePeerWrite(peerB.String(), now)
	}
	if !ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("precondition: the reaped peer must need its own session")
	}

	manager.generationsMu.Lock()
	manager.appendUDPFlowSourceLocked(src, &UDPFlowRuntime{
		manager:  manager,
		endpoint: ue,
		binding:  UdpFlowBinding{Route: UdpRouteBinding{PolicyEpoch: routing.PolicyEpoch(7)}},
	})
	manager.generationsMu.Unlock()

	if _, ok := manager.retainedUDPEndpoint(src, peerB, &bpfRoutingResult{}, cp.PolicyEpoch()); !ok {
		t.Fatal("precondition: the stale-epoch session must be found as retained")
	}

	routingResult := &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin)}
	flowB := ClassifyUdpFlow(src, peerB, []byte("b-promote"))
	flowA := ClassifyUdpFlow(src, peerA, []byte("a-keep"))

	if err := cp.handlePktWithPrefetch([]byte("b-promote"), src, peerB, routingResult, flowB, nil, UdpEndpointKey{}, false); err != nil {
		t.Fatalf("reaped peer handlePktWithPrefetch: %v", err)
	}
	if got := retainedWriteToB.Load(); got != 0 {
		t.Fatalf("the retained session accepted %d writes for the reaped peer, want 0", got)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls = %d, want 1 (current-epoch session for the reaped peer)", got)
	}
	if DefaultUdpEndpointPool.Len() == 0 {
		t.Fatal("the normal path must have dialed a current-epoch session for the reaped peer")
	}

	beforeA := retainedWrites.Load()
	if err := cp.handlePktWithPrefetch([]byte("a-keep"), src, peerA, routingResult, flowA, nil, UdpEndpointKey{}, false); err != nil {
		t.Fatalf("healthy peer handlePktWithPrefetch: %v", err)
	}
	if retainedWrites.Load() != beforeA+1 {
		t.Fatalf("healthy peer must keep being served by the retained session (writes %d -> %d)", beforeA, retainedWrites.Load())
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("healthy peer must not dial a new session (DialContext calls = %d)", got)
	}
}
