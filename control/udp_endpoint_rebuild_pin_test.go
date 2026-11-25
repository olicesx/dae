/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org
 */

package control

import (
	"context"
	stderrors "errors"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	daeerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"golang.org/x/sys/unix"
)

func udpPairKeys(src, dst netip.AddrPort) []bpfTuplesKey {
	return []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP)),
		bpfTuplesKeyFromAddrPorts(dst, src, uint8(unix.IPPROTO_UDP)),
	}
}

// requirePinnedUDPRefs fails unless every key has exactly want references.
func requirePinnedUDPRefs(t *testing.T, m *SessionManager, keys []bpfTuplesKey, want int, when string) {
	t.Helper()
	for _, key := range keys {
		if got := pinnedUDPRefs(m, key); got != want {
			t.Fatalf("refs for %+v %s = %d, want %d", key, when, got, want)
		}
	}
}

// newDroughtTrackedEndpoint builds an established endpoint whose upstream
// stopped replying while the client kept sending, with src -> dst tracked. Its
// next write retires it, which is the fork's stale-session rebuild.
func newDroughtTrackedEndpoint(manager *SessionManager, src, dst netip.AddrPort) *UdpEndpoint {
	ue := newTestEndpoint(&mockPacketConn{})
	ue.udpConnStateOwner = manager
	ue.hasReply.Store(true)
	ue.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())
	ue.writesSinceReply.Store(300)
	ue.TrackUdpConnStateTuplePair(src, dst)
	return ue
}

// Regression for daeuniverse/dae#1137: retiring a stale endpoint must keep
// the flow's conn-state until the replacement endpoint retains it.
func TestUdpEndpointDroughtRebuildPinsConnStateUntilReplacementTracks(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	src := netip.MustParseAddrPort("192.0.2.51:3074")
	dst := netip.MustParseAddrPort("198.51.100.51:3074")
	keys := udpPairKeys(src, dst)

	stale := newDroughtTrackedEndpoint(manager, src, dst)
	requirePinnedUDPRefs(t, manager, keys, 1, "before the rebuild")
	_, err := stale.WriteTo([]byte("round two"), dst.String())
	if !stderrors.Is(err, daeerrors.ErrClosedConnection) {
		t.Fatalf("expected ErrClosedConnection on a reply drought, got: %v", err)
	}
	if !stale.dead.Load() {
		t.Fatal("the endpoint must be retired")
	}
	pin := takeUdpEndpointRebuildPin(err)
	if pin == nil {
		t.Fatal("a drought rebuild must hand over a conn-state pin")
	}
	if again := takeUdpEndpointRebuildPin(err); again != nil {
		t.Fatal("the pin must be handed out only once")
	}
	requirePinnedUDPRefs(t, manager, keys, 1, "after the retirement (the rebuild pin)")

	replacement := &UdpEndpoint{conn: &mockPacketConn{}, udpConnStateOwner: manager}
	replacement.TrackUdpConnStateTuplePair(src, dst)
	pin()
	requirePinnedUDPRefs(t, manager, keys, 1, "after the handover (the replacement)")

	replacement.releaseTrackedUdpConnState()
	requirePinnedUDPRefs(t, manager, keys, 0, "after the replacement is released")
}

// Without a replacement, unpinning releases the tuples as before.
func TestUdpEndpointDroughtRebuildPinReleasesWithoutReplacement(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	src := netip.MustParseAddrPort("192.0.2.52:3074")
	dst := netip.MustParseAddrPort("198.51.100.52:3074")

	stale := newDroughtTrackedEndpoint(manager, src, dst)
	_, err := stale.WriteTo([]byte("round two"), dst.String())
	pin := takeUdpEndpointRebuildPin(err)
	if pin == nil {
		t.Fatalf("a drought rebuild must hand over a conn-state pin, err=%v", err)
	}
	pin()
	requirePinnedUDPRefs(t, manager, udpPairKeys(src, dst), 0, "after unpinning without a replacement")
}

// Nothing tracked, nothing to hand over: the rebuild error is still the
// normal-close classification the caller retries on.
func TestUdpEndpointDroughtRebuildHandsOverNoPinWithoutTrackedState(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.53:3074")
	dst := netip.MustParseAddrPort("198.51.100.53:3074")
	for _, tc := range []struct {
		name    string
		prepare func(ue *UdpEndpoint, manager *SessionManager)
	}{
		{name: "no owner", prepare: func(ue *UdpEndpoint, _ *SessionManager) {}},
		{name: "owner without a tracked pair", prepare: func(ue *UdpEndpoint, manager *SessionManager) {
			ue.udpConnStateOwner = manager
		}},
		{name: "tracked pair already released", prepare: func(ue *UdpEndpoint, manager *SessionManager) {
			ue.udpConnStateOwner = manager
			ue.TrackUdpConnStateTuplePair(src, dst)
			ue.releaseTrackedUdpConnState()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewSessionManager(context.Background())
			defer func() { _ = manager.Close() }()
			ue := newTestEndpoint(&mockPacketConn{})
			ue.hasReply.Store(true)
			ue.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())
			ue.writesSinceReply.Store(300)
			tc.prepare(ue, manager)

			_, err := ue.WriteTo([]byte("round two"), dst.String())
			if !stderrors.Is(err, daeerrors.ErrClosedConnection) {
				t.Fatalf("expected ErrClosedConnection on a reply drought, got: %v", err)
			}
			if pin := takeUdpEndpointRebuildPin(err); pin != nil {
				pin()
				t.Fatal("nothing was tracked, so the rebuild must not hand over a pin")
			}
			requirePinnedUDPRefs(t, manager, udpPairKeys(src, dst), 0, "after the rebuild")
		})
	}
}

// The retained path declines the shortcut instead of carrying the pin on, so
// it must give the pin back at once. A pin left here would outlive the flow.
func TestRetainedUDPEndpointUnpinsDroughtRebuildHandoff(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()

	cp := newUdpReuseSimulationControlPlane(nil)
	cp.sessionManager = manager

	src := netip.MustParseAddrPort("10.0.0.1:4444")
	dst := netip.MustParseAddrPort("10.0.0.3:5000")

	ue := newDroughtTrackedEndpoint(manager, src, dst)
	ue.Dialer = newTestEndpointDialer(&mockPacketConn{})
	ue.poolKey = UdpEndpointKey{Src: src}
	ue.hasSent.Store(true)
	manager.generationsMu.Lock()
	manager.appendUDPFlowSourceLocked(src, &UDPFlowRuntime{
		manager:  manager,
		endpoint: ue,
		binding:  UdpFlowBinding{Route: UdpRouteBinding{PolicyEpoch: routing.PolicyEpoch(7)}},
	})
	manager.generationsMu.Unlock()

	// The lookup itself must succeed, or the handler would decline by
	// missing the session rather than by its write-error policy.
	if _, ok := manager.retainedUDPEndpoint(src, dst, &bpfRoutingResult{}, cp.PolicyEpoch()); !ok {
		t.Fatal("precondition: the stale-epoch session must be found as retained")
	}
	keys := udpPairKeys(src, dst)
	requirePinnedUDPRefs(t, manager, keys, 1, "before the write")

	if cp.handleRetainedUDPEndpoint([]byte("hello"), src, dst, &bpfRoutingResult{}, UdpFlowDecision{}) {
		t.Fatal("a retired endpoint must make the retained path decline the shortcut")
	}
	requirePinnedUDPRefs(t, manager, keys, 0, "after the retained path declined")
}

// pooledUdpEndpointsExcept returns every endpoint left in the default pool.
func pooledUdpEndpointsExcept(dead *UdpEndpoint) []*UdpEndpoint {
	var live []*UdpEndpoint
	for i := range udpEndpointCreateShardCount {
		shard := &DefaultUdpEndpointPool.shards[i]
		shard.mu.RLock()
		for _, ue := range shard.pool {
			if ue != dead {
				live = append(live, ue)
			}
		}
		shard.mu.RUnlock()
	}
	return live
}

// End to end through handlePkt, on both write paths: the live session, the
// rebuild and the replacement all run with a session manager as the
// conn-state owner. When the call returns, the replacement holds exactly one
// reference: a dropped or leaked handover pin would leave zero or two.
func TestE2ERealSocks5DroughtRebuildHandsConnStateToReplacement(t *testing.T) {
	const (
		fastPathLog = "Failed to write UDP fast-path packet. Remove stale endpoint and rebuild."
		slowPathLog = "Failed to write UDP packet request. Try to remove old UDP endpoint and retry."
	)
	for _, tc := range []struct {
		name     string
		fastPath bool
	}{
		{name: "slow path"},
		{name: "QUIC fast path", fastPath: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := startReapEchoTarget(t)
			srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{},
				map[netip.AddrPort]netip.AddrPort{flowDstA: target.addrPort(t)})
			e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)
			manager := NewSessionManager(context.Background())
			t.Cleanup(func() { _ = manager.Close() })
			e.cp.sessionManager = manager
			// The write-failure log names the path that retired the endpoint.
			hook := test.NewLocal(e.cp.log)
			e.cp.log.SetLevel(logrus.DebugLevel)

			ue1, port1 := e.establish(target)
			keys := udpPairKeys(e.src, e.dst)
			requirePinnedUDPRefs(t, manager, keys, 1, "after the first round trip")

			if reaped := target.reap(); !slices.Contains(reaped, port1) {
				t.Fatalf("reaped ports = %v, want %s", reaped, port1)
			}
			const sent = 70 // >= udpEndpointReplyDroughtMinRate * window
			for i := 0; i < sent; i++ {
				e.mustSend("dead-" + strconv.Itoa(i))
			}
			if e.endpoint() != ue1 {
				t.Fatal("the endpoint was replaced before the drought window elapsed")
			}
			requirePinnedUDPRefs(t, manager, keys, 1, "after the silent phase")

			// Compress the clock: the last real reply is now older than the window.
			ue1.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())
			target.setEcho(false)
			if tc.fastPath {
				// A pooled endpoint that carries a sniffed domain is written by
				// the fast path. The name survives the failed write and becomes
				// the replacement's dial target, so it has to be one the test
				// relay still maps to the target: the target's own address.
				ue1.SniffedDomain = e.dst.Addr().String()
			}
			hook.Reset()
			e.mustSend("rebuild")

			// An endpoint with a sniffed domain is pooled under its own key, so the
			// replacement is taken from the pool rather than looked up by the flow key.
			live := pooledUdpEndpointsExcept(ue1)
			if !ue1.dead.Load() || len(live) != 1 {
				t.Fatalf("the drought rebuild must leave exactly one replacement: old dead=%v, replacements=%d", ue1.dead.Load(), len(live))
			}
			ue2 := live[0]
			if ue2.udpConnStateOwner == nil {
				t.Fatal("precondition: the replacement must track conn-state")
			}
			fast, slow := 0, 0
			for _, entry := range hook.AllEntries() {
				switch entry.Message {
				case fastPathLog:
					fast++
				case slowPathLog:
					slow++
				}
			}
			if tc.fastPath && (fast != 1 || slow != 0) {
				t.Fatalf("fast-path rebuild logged fast=%d slow=%d, want 1 and 0", fast, slow)
			}
			if !tc.fastPath && (fast != 0 || slow != 1) {
				t.Fatalf("slow-path rebuild logged fast=%d slow=%d, want 0 and 1", fast, slow)
			}
			requirePinnedUDPRefs(t, manager, keys, 1, "after the rebuild (held by the replacement)")
		})
	}
}

func TestChainUdpConnStatePins(t *testing.T) {
	if chainUdpConnStatePins(nil, nil) != nil {
		t.Fatal("two nil pins must chain to nil")
	}
	var order []int
	first := func() { order = append(order, 1) }
	second := func() { order = append(order, 2) }
	chainUdpConnStatePins(first, nil)()
	chainUdpConnStatePins(nil, second)()
	chainUdpConnStatePins(first, second)()
	want := []int{1, 2, 2, 1}
	if len(order) != len(want) {
		t.Fatalf("release order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("release order = %v, want %v", order, want)
		}
	}
}

// End to end through handlePkt: when no replacement can be dialed, the pin
// taken for the rebuild must go back. handlePktOwned owns it from the failing
// write to the end of the call, and every way out releases it.
func TestE2ERealSocks5DroughtRebuildReleasesPinWhenNoReplacementIsMade(t *testing.T) {
	target := startReapEchoTarget(t)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{},
		map[netip.AddrPort]netip.AddrPort{flowDstA: target.addrPort(t)})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	e.cp.sessionManager = manager

	ue1, _ := e.establish(target)
	keys := udpPairKeys(e.src, e.dst)
	requirePinnedUDPRefs(t, manager, keys, 1, "after the first round trip")

	// The client keeps transmitting into the reaped session, so the rebuild
	// gate has its send-rate evidence (see TestE2ERealSocks5ReplyDroughtRebuildsAndRecovers).
	if reaped := target.reap(); len(reaped) == 0 {
		t.Fatalf("reaped ports = %v, want the session egress", reaped)
	}
	const sent = 70 // >= udpEndpointReplyDroughtMinRate * window
	for i := 0; i < sent; i++ {
		e.mustSend("dead-" + strconv.Itoa(i))
	}
	requirePinnedUDPRefs(t, manager, keys, 1, "after the silent phase")

	// Compress the clock: the next write retires the session ...
	ue1.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())
	// ... and the replacement cannot be dialed.
	failing, _ := newTestEndpointErrorDialer("socks5", "127.0.0.1:1", stderrors.New("dial failed on purpose"))
	e.cp.outbounds[consts.OutboundUserDefinedMin] = newTestFixedOutboundGroup(failing)

	if err := e.send("rebuild"); err == nil {
		t.Fatal("precondition: the rebuild must fail when the replacement cannot be dialed")
	}
	requirePinnedUDPRefs(t, manager, keys, 0, "after a rebuild without a replacement")
}
