/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"time"
)

// udpEndpointPeerStateLimit bounds the per-peer bookkeeping one full-cone
// session keeps. A source-keyed session can serve an unbounded number of
// destinations, and liveness is only worth tracking per peer while that set is
// still small: beyond the limit the endpoint falls back to its endpoint-level
// behaviour, which means no per-peer promotion. Falling back is the safe
// direction — the shared session keeps serving the peers it can, exactly as
// before this bookkeeping existed.
//
// The limit also bounds what one client source can hold: at most one shared
// session plus one dedicated session per tracked peer, so at most 33 sessions
// per source address and route scope. Reaching the limit needs a peer that was
// answered once and is still being written to, which is not something a remote
// peer can force on its own.
const udpEndpointPeerStateLimit = 32

// udpEndpointPeerState is the per-destination liveness evidence of a full-cone
// (source-keyed) session. It mirrors the endpoint-level evidence — writes since
// the last reply plus the recent probe window — for a single peer, because one
// session can serve several peers whose fates are independent: a healthy peer
// keeps the endpoint-level reply clock fresh and would otherwise mask a peer
// whose forwarding mapping the far end reaped.
type udpEndpointPeerState struct {
	lastReplyNano      int64
	writesSinceReply   int64
	recentBucket       int64
	recentBucketWrites int64
	// promoted records that this peer was moved to its own symmetric session.
	// The decision is sticky by design: once the peer is served elsewhere it
	// stops writing through the shared session, so without this the evidence
	// would decay and the next datagram would fall back to the reaped path.
	promoted bool
}

// udpEndpointPeerWrite is one peer's share of a batched flush.
type udpEndpointPeerWrite struct {
	addr      string
	datagrams int
}

// notePeerReply records an upstream reply from one peer of a full-cone session
// and, on the second distinct peer, turns on per-peer bookkeeping for that
// endpoint. Replies are the only place peers are learned: a peer that never
// replied has no liveness evidence to act on, so the common single-peer
// full-cone flow keeps paying nothing for a pattern it does not have.
//
// A peer is identified by the address the transport reports for the reply,
// which has to match the address the client wrote to. Transports that rewrite
// one but not the other therefore never promote anyone: the failure direction
// is "no promotion", never "promote the wrong peer".
func (ue *UdpEndpoint) notePeerReply(from netip.AddrPort, nowNano int64) {
	if ue == nil || !from.IsValid() || ue.poolKey.Dst.IsValid() {
		// Symmetric sessions have exactly one peer by construction, and an
		// unparsable reply address carries no identity to track.
		return
	}
	if nowNano == 0 {
		nowNano = time.Now().UnixNano()
	}
	key := from.String()
	ue.peerMu.Lock()
	defer ue.peerMu.Unlock()
	state, ok := ue.peers[key]
	if !ok {
		if len(ue.peers) >= udpEndpointPeerStateLimit {
			return
		}
		if ue.peers == nil {
			ue.peers = make(map[string]*udpEndpointPeerState, 2)
		}
		state = &udpEndpointPeerState{}
		ue.peers[key] = state
		if len(ue.peers) > 1 {
			ue.multiPeer.Store(true)
		}
	}
	state.lastReplyNano = nowNano
	state.writesSinceReply = 0
	state.recentBucket = 0
	state.recentBucketWrites = 0
}

// notePeerWrite records one accepted datagram sent to one peer. It only updates
// peers already learned from a reply: creating state for a destination that
// never answered would invent evidence, and the promotion gate requires a peer
// that was established at least once.
func (ue *UdpEndpoint) notePeerWrite(addr string, now time.Time) {
	if ue == nil || addr == "" {
		return
	}
	ue.peerMu.Lock()
	defer ue.peerMu.Unlock()
	state, ok := ue.peers[addr]
	if !ok {
		return
	}
	ue.addPeerWritesLocked(state, 1, now)
}

// noteBatchPeerWrites records the accepted prefix of a batched flush, which is
// the only place a batched endpoint knows what the transport really sent. One
// flush is one instant, so every datagram of a peer's group lands in the same
// probe window.
func (ue *UdpEndpoint) noteBatchPeerWrites(writes []udpEndpointPeerWrite, now time.Time) {
	if ue == nil || len(writes) == 0 || !ue.multiPeer.Load() {
		return
	}
	ue.peerMu.Lock()
	defer ue.peerMu.Unlock()
	for _, write := range writes {
		state, ok := ue.peers[write.addr]
		if !ok {
			continue
		}
		ue.addPeerWritesLocked(state, write.datagrams, now)
	}
}

func (ue *UdpEndpoint) addPeerWritesLocked(state *udpEndpointPeerState, datagrams int, now time.Time) {
	if datagrams <= 0 {
		return
	}
	state.writesSinceReply += int64(datagrams)
	bucket := now.UnixNano() / int64(udpEndpointReplyDroughtProbeWindow)
	if state.recentBucket != bucket {
		state.recentBucket = bucket
		state.recentBucketWrites = 0
	}
	state.recentBucketWrites += int64(datagrams)
}

// peerNeedsDedicatedSession reports whether one peer of a full-cone session
// stopped being answered while the client kept writing to it.
//
// The shared session must not be rebuilt for that peer: it is demonstrably
// alive for the others, and retiring it would re-key every one of them. The
// peer is instead escalated to its own symmetric session — the same
// evidence-based escalation dae already applies to sniffed domains and
// confirmed QUIC flows — which hands it a fresh forwarding source port without
// touching the shared one.
//
// Reporting a drought also records the promotion, so the caller must be about
// to route that peer to its own session. The answer stays true from then on,
// which is what keeps the peer off the reaped path once its live evidence
// stops growing — the peer stops writing through the shared session, so
// without the record the next datagram would fall back to the reaped path.
//
// The record is made when the drought is judged, before the dedicated session
// exists. For a truly reaped peer that order does not matter (the alternative
// was a black hole), and for a peer that was merely quiet the dedicated session
// re-keys its traffic; a dial that fails after a judgement leaves that peer on
// its own key until the shared session is replaced, which is the same
// direction, not a new failure mode.
func (ue *UdpEndpoint) peerNeedsDedicatedSession(dst netip.AddrPort, now time.Time) bool {
	if ue == nil || !dst.IsValid() || ue.poolKey.Dst.IsValid() || !ue.multiPeer.Load() ||
		!ue.rebuildsOnReplyDrought() {
		// The profile decides whether inference-driven session replacement is
		// allowed at all; the per-peer gate must not be a back door around it.
		return false
	}
	key := dst.String()
	ue.peerMu.Lock()
	defer ue.peerMu.Unlock()
	state, ok := ue.peers[key]
	if !ok {
		return false
	}
	if state.promoted {
		return true
	}
	if state.lastReplyNano == 0 {
		// Probing for this peer: no reply has ever been observed from it, so
		// there is no drought to reason about.
		return false
	}
	drought := now.UnixNano() - state.lastReplyNano
	if drought < int64(udpEndpointReplyDroughtWindow) {
		return false
	}
	// Only a count from the current probe window is evidence of activity now.
	// Without the freshness check, a burst right after the peer's last reply
	// could be mistaken for traffic after a long quiet pause and stick a
	// promotion on one datagram.
	recent := int64(0)
	if state.recentBucket == now.UnixNano()/int64(udpEndpointReplyDroughtProbeWindow) {
		recent = state.recentBucketWrites
	}
	if droughtSendRateFrom(state.writesSinceReply, drought, recent) < float64(udpEndpointReplyDroughtMinRate) {
		return false
	}
	state.promoted = true
	return true
}

// droughtSendRateFrom is the two-measurement rate rule shared by the
// endpoint-level and per-peer gates: the lifetime average over the drought and
// the datagrams counted in the current probe window, whichever is larger. The
// average keeps a steady flow actionable over its whole drought; the window is
// what makes a burst visible to a flow whose average stays below the
// threshold, and it is short enough that a sparse keepalive cannot fake a rate
// through it. Callers must only pass a count that belongs to the current
// window; an aged bucket is not evidence of activity now.
func droughtSendRateFrom(writes, droughtNano, recentBucketWrites int64) float64 {
	if droughtNano <= 0 {
		return 0
	}
	rate := float64(writes) / (float64(droughtNano) / float64(time.Second))
	if recent := float64(recentBucketWrites) / udpEndpointReplyDroughtProbeWindow.Seconds(); recent > rate {
		return recent
	}
	return rate
}
