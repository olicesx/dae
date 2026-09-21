/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// peerTestEndpoint returns a full-cone (source-keyed) test endpoint with two
// established peers: peerA answered a moment ago and stays healthy, peerB
// answered a full drought ago and its forwarding mapping is presumed reaped.
func peerTestEndpoint(t *testing.T) (*UdpEndpoint, netip.AddrPort, netip.AddrPort, time.Time) {
	t.Helper()
	ue := newTestEndpoint(&mockPacketConn{})
	now := time.Now()
	peerA := netip.MustParseAddrPort("10.0.0.1:5000")
	peerB := netip.MustParseAddrPort("10.0.0.2:5000")
	droughtAt := now.Add(-udpEndpointReplyDroughtWindow - time.Second)
	ue.notePeerReply(peerA, droughtAt.UnixNano())
	ue.notePeerReply(peerB, droughtAt.UnixNano())
	// Peer A's upstream is answering: a reply a second ago.
	ue.notePeerReply(peerA, now.Add(-time.Second).UnixNano())
	return ue, peerA, peerB, now
}

// One session serving several peers must not let a healthy peer mask a reaped
// one: the reaped peer is what gets its own session, and the healthy peer is
// left alone.
func TestUdpEndpointPeerDroughtPromotesOnlyTheReapedPeer(t *testing.T) {
	ue, peerA, peerB, now := peerTestEndpoint(t)

	// The client keeps transmitting to the reaped peer while it answers
	// nothing: a burst that its lifetime average dilutes below the threshold.
	for i := range 20 {
		ue.notePeerWrite(peerB.String(), now)
		_ = i
	}
	if !ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("the reaped peer must be promoted to its own session")
	}
	if ue.peerNeedsDedicatedSession(peerA, now) {
		t.Fatal("the healthy peer must keep the shared session")
	}
}

// The promotion is sticky: once the peer is served elsewhere its evidence stops
// growing, and falling back to the shared session would re-key it back onto the
// reaped path.
func TestUdpEndpointPeerPromotionIsSticky(t *testing.T) {
	ue, _, peerB, now := peerTestEndpoint(t)
	for range 20 {
		ue.notePeerWrite(peerB.String(), now)
	}
	if !ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("precondition: the reaped peer must be promoted")
	}
	// Long after the burst, with no further writes, the peer must still be
	// routed to its dedicated session.
	if !ue.peerNeedsDedicatedSession(peerB, now.Add(10*time.Minute)) {
		t.Fatal("the promotion must be sticky, not evidence-dependent")
	}
}

// A session with a single peer has nothing to attribute: the endpoint-level
// drought gate owns it, and per-peer bookkeeping would be pure overhead.
func TestUdpEndpointPeerPromotionNeedsTwoPeers(t *testing.T) {
	ue := newTestEndpoint(&mockPacketConn{})
	now := time.Now()
	peer := netip.MustParseAddrPort("10.0.0.1:5000")
	ue.notePeerReply(peer, now.Add(-udpEndpointReplyDroughtWindow-time.Second).UnixNano())
	if ue.multiPeer.Load() {
		t.Fatal("a single peer must not enable per-peer bookkeeping")
	}
	for range 50 {
		ue.notePeerWrite(peer.String(), now)
	}
	if ue.peerNeedsDedicatedSession(peer, now) {
		t.Fatal("a single-peer session is the endpoint-level gate's business")
	}
}

// Symmetric sessions carry exactly one destination by construction.
func TestUdpEndpointPeerPromotionSkipsSymmetricSessions(t *testing.T) {
	ue, _, peerB, now := peerTestEndpoint(t)
	ue.poolKey.Dst = peerB
	for range 20 {
		ue.notePeerWrite(peerB.String(), now)
	}
	if ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("a symmetric session must never be split")
	}
}

// The per-peer gate must honour the same lifecycle profile as the endpoint
// gate: a profile that forbids inference-driven replacement must not be able to
// reach it through one peer.
func TestUdpEndpointPeerPromotionRespectsLifecycleProfile(t *testing.T) {
	ue, _, peerB, now := peerTestEndpoint(t)
	profile := newDataSessionLifecycleProfile(nil)
	profile.RebuildOnReplyDrought = false
	ue.lifecycleProfile = profile
	for range 20 {
		ue.notePeerWrite(peerB.String(), now)
	}
	if ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("a profile without reply-drought replacement must not promote peers")
	}
}

// A promotion is not a retirement: the shared session keeps serving its other
// peers, and the key's recovery budget stays unspent. Only a drought rebuild
// spends budget, so a peer that recovers on its own session never costs the
// peers that stayed.
func TestUdpEndpointPeerPromotionIsNotARetirement(t *testing.T) {
	pool := &UdpEndpointPool{}
	ue, _, peerB, now := peerTestEndpoint(t)
	ue.poolRef = pool
	ue.poolKey = UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:40000")}

	for range 20 {
		ue.notePeerWrite(peerB.String(), now)
	}
	if !ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("the reaped peer must be promoted to its own session")
	}
	if ue.dead.Load() {
		t.Fatal("a promotion must leave the shared session alive for its other peers")
	}
	if ue.retiredByReplyDrought.Load() {
		t.Fatal("a promotion is not a retirement")
	}
	if got := pool.droughtRebuildGeneration(ue.poolKey); got != 0 {
		t.Fatalf("generation = %d, want 0: a promotion must not spend the key's recovery budget", got)
	}
}

// The recovery budget has to be visible the moment a session is flagged as
// drought-retired: a concurrent replacement can observe that flag, remove the
// stale pool entry and dial before the retirement itself finishes. Recording
// the budget inside the removal would leave that replacement reading a
// fresh-flow generation, silently skipping one recovery.
func TestUdpEndpointDroughtBudgetIsRecordedBeforeRetirement(t *testing.T) {
	pool := &UdpEndpointPool{}
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:40000")}
	window := udpEndpointReplyDroughtWindow + time.Second
	sampled := 0

	// Enough attempts that an observer is very likely to sample the window
	// between the flag store and the ledger write if the order ever regresses.
	// The invariant can only be violated, never flakily satisfied, so a run
	// that never observes the flag still passes and says so.
	for attempt := range 20 {
		// Closing the transport is part of retirement, so a deliberately slow
		// close widens the window this test is about from sub-microsecond to
		// milliseconds: a run that records the budget inside the removal has to
		// be caught here, not sampled by luck.
		mock := &mockPacketConn{closeFn: func() error {
			time.Sleep(2 * time.Millisecond)
			return nil
		}}
		ue := newTestEndpoint(mock)
		ue.hasReply.Store(true)
		ue.lastReplyNano.Store(time.Now().Add(-window).UnixNano())
		ue.writesSinceReply.Store(300)
		ue.poolRef = pool
		ue.poolKey = key
		var sawFlag atomic.Bool
		done := make(chan struct{})
		violated := make(chan struct{})
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				if ue.retiredByReplyDrought.Load() {
					sawFlag.Store(true)
					if pool.droughtRebuildGeneration(key) == 0 {
						close(violated)
						return
					}
				}
			}
		}()
		_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
		close(done)
		select {
		case <-violated:
			t.Fatalf("attempt %d: the retirement flag was visible while the key's recovery budget was still missing", attempt)
		default:
		}
		if sawFlag.Load() {
			sampled++
		}
		if err == nil {
			t.Fatal("a session in a reply drought with plenty of sends must retire")
		}
		pool.Reset()
	}
	if sampled == 0 {
		t.Log("the observer never sampled a retirement window; the invariant held but was not exercised on this run")
	}
}

// Writing to a destination that never answered must not invent a peer: the
// promotion gate is about a peer whose liveness was established and then lost.
func TestUdpEndpointPeerWritesDoNotInventPeers(t *testing.T) {
	ue, _, peerB, now := peerTestEndpoint(t)
	stranger := netip.MustParseAddrPort("10.0.0.9:5000")
	strangerKey := stranger.String()
	ue.notePeerWrite(strangerKey, now)
	ue.peerMu.Lock()
	_, tracked := ue.peers[strangerKey]
	ue.peerMu.Unlock()
	if tracked {
		t.Fatal("a write must not create peer state")
	}
	if ue.peerNeedsDedicatedSession(stranger, now) {
		t.Fatal("a stranger has no liveness evidence to act on")
	}
	// And a peer that was established but is being written to without any
	// drought stays where it is.
	ue.notePeerWrite(peerB.String(), now.Add(-time.Minute))
	if ue.peerNeedsDedicatedSession(peerB, now.Add(-time.Minute)) {
		t.Fatal("a peer inside its window must not be promoted")
	}
}

// Silence is not evidence: a peer that stopped being written to is a pause, not
// a reaped mapping, and must keep its session (the same rule as the
// endpoint-level gate).
func TestUdpEndpointPeerSilenceDoesNotPromote(t *testing.T) {
	ue, _, peerB, now := peerTestEndpoint(t)
	if ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("a long silence with no client traffic must not promote a peer")
	}
	// One sparse datagram is still not traffic worth re-keying a session for.
	ue.notePeerWrite(peerB.String(), now)
	if ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("a sparse datagram must not promote a peer")
	}
}

// A burst recorded in an aged probe window is not current activity. Without
// the freshness check, a burst right after the peer's last reply followed by a
// long quiet pause would let the first post-pause datagram stick a promotion,
// which the shared session can never undo.
func TestUdpEndpointPeerPromotionIgnoresStaleRecentBucket(t *testing.T) {
	ue, _, peerB, now := peerTestEndpoint(t)
	for range udpEndpointReplyDroughtMinRate * int(udpEndpointReplyDroughtProbeWindow/time.Second) {
		ue.notePeerWrite(peerB.String(), now.Add(-udpEndpointReplyDroughtWindow-time.Second))
	}
	if ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("an aged recent bucket must not promote a peer on one post-pause datagram")
	}
	ue.peerMu.Lock()
	promoted := ue.peers[peerB.String()].promoted
	ue.peerMu.Unlock()
	if promoted {
		t.Fatal("the promotion latch must stay unset without current-window evidence")
	}

	// Control: the same burst inside the current window still promotes, which
	// is the whole point of the second measurement.
	ue2, _, peerB2, now2 := peerTestEndpoint(t)
	for range udpEndpointReplyDroughtMinRate * int(udpEndpointReplyDroughtProbeWindow/time.Second) {
		ue2.notePeerWrite(peerB2.String(), now2)
	}
	if !ue2.peerNeedsDedicatedSession(peerB2, now2) {
		t.Fatal("a burst in the current window must still promote a reaped peer")
	}
}

// The per-peer ledger is bounded: past the limit the endpoint keeps serving the
// session and simply stops tracking new peers, which is the safe direction.
func TestUdpEndpointPeerStateIsBounded(t *testing.T) {
	ue := newTestEndpoint(&mockPacketConn{})
	now := time.Now()
	for i := range udpEndpointPeerStateLimit {
		ue.notePeerReply(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), uint16(1024+i)), now.UnixNano())
	}
	if got := len(ue.peers); got != udpEndpointPeerStateLimit {
		t.Fatalf("tracked peers = %d, want the limit %d", got, udpEndpointPeerStateLimit)
	}
	overflow := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), uint16(1024+udpEndpointPeerStateLimit))
	ue.notePeerReply(overflow, now.UnixNano())
	if got := len(ue.peers); got != udpEndpointPeerStateLimit {
		t.Fatalf("tracked peers = %d, want the ledger to stay bounded at %d", got, udpEndpointPeerStateLimit)
	}
}

// A batched transport must attribute its accepted flush per peer as well: the
// Hysteria2-style path owns the only true "what left the socket" count.
func TestUdpEndpointPeerBatchWritesAreAttributed(t *testing.T) {
	ue, peerA, peerB, now := peerTestEndpoint(t)
	ue.noteBatchPeerWrites([]udpEndpointPeerWrite{
		{addr: peerB.String(), datagrams: 20},
		{addr: peerA.String(), datagrams: 1},
	}, now)
	if !ue.peerNeedsDedicatedSession(peerB, now) {
		t.Fatal("a batched burst to a reaped peer must promote it")
	}
	if ue.peerNeedsDedicatedSession(peerA, now) {
		t.Fatal("a batched datagram to a healthy peer must not promote it")
	}
	ue.peerMu.Lock()
	got := ue.peers[peerB.String()].writesSinceReply
	ue.peerMu.Unlock()
	if got != 20 {
		t.Fatalf("peer B writesSinceReply = %d, want the 20 flushed datagrams", got)
	}
}

// The recovery budget: a session that already replaced one that died of a reply
// drought must prove two-way health before it may spend another recovery,
// while a flow's first session is never held back.
func TestUdpEndpointDroughtRebuildBudget(t *testing.T) {
	write := func(t *testing.T, ue *UdpEndpoint) error {
		t.Helper()
		_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
		return err
	}
	t.Run("first_session_is_never_held_back", func(t *testing.T) {
		ue, _ := establishedWithDrought(t, udpEndpointReplyDroughtWindow+time.Second, 300)
		if ue.droughtRebuildGeneration != 0 {
			t.Fatalf("generation = %d, want 0 for a fresh flow", ue.droughtRebuildGeneration)
		}
		if err := write(t, ue); err == nil {
			t.Fatal("the first session of a flow must be free to recover")
		}
	})
	t.Run("replacement_needs_health_proof", func(t *testing.T) {
		// agedEvidence puts the session in a drought with plenty of sends, so
		// that only the recovery budget can hold it back.
		agedEvidence := func(ue *UdpEndpoint) {
			ue.writesSinceReply.Store(300)
			ue.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())
			ue.hasReply.Store(true)
		}
		ue, _ := establishedWithDrought(t, udpEndpointReplyDroughtWindow+time.Second, 300)
		ue.droughtRebuildGeneration = 1
		for range udpEndpointReplyDroughtMinHealthyReplies - 1 {
			ue.markReplied(time.Now().UnixNano(), netip.AddrPort{})
		}
		agedEvidence(ue)
		if err := write(t, ue); err != nil {
			t.Fatalf("a replacement with too few replies must not rebuild again: %v", err)
		}
		if ue.dead.Load() {
			t.Fatal("the recovery budget must keep the session")
		}
		// Once the session proves two-way health, the gate may act again.
		for range udpEndpointReplyDroughtMinHealthyReplies {
			ue.markReplied(time.Now().UnixNano(), netip.AddrPort{})
		}
		agedEvidence(ue)
		if err := write(t, ue); err == nil {
			t.Fatal("a replacement that proved two-way health must be allowed to recover")
		}
	})
}

// The generation has to survive the pool's remove-and-redial gap, otherwise
// every replacement would look like a fresh flow and the budget would never
// apply.
func TestUdpEndpointPoolCarriesDroughtGeneration(t *testing.T) {
	pool := &UdpEndpointPool{}
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:40000")}
	if got := pool.droughtRebuildGeneration(key); got != 0 {
		t.Fatalf("generation = %d, want 0 before any rebuild", got)
	}
	pool.rememberDroughtRebuild(key, 1)
	if got := pool.droughtRebuildGeneration(key); got != 1 {
		t.Fatalf("generation = %d, want 1 after one rebuild", got)
	}
	pool.rememberDroughtRebuild(key, 2)
	if got := pool.droughtRebuildGeneration(key); got != 2 {
		t.Fatalf("generation = %d, want 2 after two rebuilds", got)
	}
	// A spent budget must not outlive its window: once the ledger entry ages
	// out, a flow that reuses the key starts with a fresh flow's budget instead
	// of inheriting a recovery the previous flow already spent.
	// The window only has to cover one remove-and-redial gap. Keep it there: a
	// longer window is what lets an unrelated flow that reuses the key inherit
	// a budget it never spent.
	if udpEndpointDroughtSuccessorTTL > time.Minute {
		t.Fatalf("recovery budget window = %s, want at most a minute: it only has to cover the dial gap of one key",
			udpEndpointDroughtSuccessorTTL)
	}
	pool.droughtSuccessorsMu.Lock()
	entry := pool.droughtSuccessors[key]
	entry.recordedAt = time.Now().Add(-2 * udpEndpointDroughtSuccessorTTL)
	pool.droughtSuccessors[key] = entry
	pool.droughtSuccessorsMu.Unlock()
	if got := pool.droughtRebuildGeneration(key); got != 0 {
		t.Fatalf("generation = %d after the budget aged out, want 0", got)
	}

	// A generation is one key's business only.
	if got := pool.droughtRebuildGeneration(UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:40001")}); got != 0 {
		t.Fatalf("generation = %d for an unrelated key, want 0", got)
	}
	// And the ledger stays bounded whatever the traffic does.
	for i := range udpEndpointDroughtSuccessorLimit * 2 {
		pool.rememberDroughtRebuild(UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(40002+i))}, 1)
	}
	pool.droughtSuccessorsMu.Lock()
	size := len(pool.droughtSuccessors)
	pool.droughtSuccessorsMu.Unlock()
	if size > udpEndpointDroughtSuccessorLimit {
		t.Fatalf("ledger holds %d entries, want at most %d", size, udpEndpointDroughtSuccessorLimit)
	}
}
