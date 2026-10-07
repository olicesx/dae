/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"

	"golang.org/x/sys/unix"
)

// snapshotPinnedTCPInto fills scratch (cleared first) with the set of pinned
// TCP tuples for lock-free batch queries, reusing the janitor-owned map
// across scan cycles instead of allocating a fresh snapshot per scan; a nil
// scratch is created on first use and must be stored back by the caller.
// Shards are read one at a time, so the result is a union over a short
// window rather than one instant — sufficient for janitor scans. The caller
// must finish consuming the returned map before the next call; the janitor
// is the only caller and runs scans sequentially.
func (m *SessionManager) snapshotPinnedTCPInto(scratch map[bpfTuplesKey]struct{}) map[bpfTuplesKey]struct{} {
	if m == nil {
		return nil
	}
	if scratch == nil {
		scratch = make(map[bpfTuplesKey]struct{})
	}
	clear(scratch)
	for i := range m.pinnedShards {
		shard := &m.pinnedShards[i]
		shard.mu.Lock()
		for k := range shard.keys {
			scratch[k] = struct{}{}
		}
		shard.mu.Unlock()
	}
	return scratch
}

func (m *SessionManager) isRedirectTrackPinned(key bpfRedirectTuple) bool {
	if m == nil {
		return false
	}
	shard := &m.refShards[redirectShardIndex(&key)]
	shard.mu.Lock()
	refs := shard.keys[key]
	shard.mu.Unlock()
	return refs > 0
}

// RetainUdpConnStateTuples pins established UDP state against reload cleanup.
//
// Only udpStateMu is taken: pinnedUDP is its exclusive domain, the redirect
// refcounts synchronize through their own shards, and generationsMu guards
// nothing this path reads or writes. Endpoint writes re-Retain tuples, so
// these spans must stay mutually exclusive with the delete inside
// ReleaseUdpConnStateTuples — udpStateMu provides exactly that.
func (m *SessionManager) RetainUdpConnStateTuples(keys []bpfTuplesKey) {
	if m == nil || len(keys) == 0 {
		return
	}
	m.udpStateMu.Lock()
	for _, key := range keys {
		m.pinnedUDP[key]++
		redirectKey := redirectTupleForFlow(key)
		refShard := &m.refShards[redirectShardIndex(&redirectKey)]
		refShard.pin(redirectKey)
	}
	m.udpStateMu.Unlock()
}

// ReleaseUdpConnStateTuples drops tuple references and removes entries after
// the final process-owned endpoint releases them.
//
// The BpfMapBatchDelete intentionally stays inside udpStateMu: a concurrent
// Retain (endpoint writes re-pin tuples) must not slip between the refcount
// dropping to zero and the physical delete, or it would lose a live entry.
func (m *SessionManager) ReleaseUdpConnStateTuples(keys []bpfTuplesKey) error {
	if m == nil || len(keys) == 0 {
		return nil
	}
	m.udpStateMu.Lock()
	deleteKeys := make([]bpfTuplesKey, 0, len(keys))
	for _, key := range keys {
		switch refs := m.pinnedUDP[key]; {
		case refs > 1:
			m.pinnedUDP[key] = refs - 1
		case refs == 1:
			delete(m.pinnedUDP, key)
			deleteKeys = append(deleteKeys, key)
		}
		redirectKey := redirectTupleForFlow(key)
		refShard := &m.refShards[redirectShardIndex(&redirectKey)]
		refShard.unpin(redirectKey)
	}
	var err error
	if bpf := m.udpBPF.Load(); bpf != nil && bpf.ConnStateMap != nil && len(deleteKeys) > 0 {
		_, err = BpfMapBatchDelete(bpf.ConnStateMap, deleteKeys)
	}
	m.udpStateMu.Unlock()
	return err
}

// snapshotPinnedUDPInto fills scratch (cleared first) with the set of pinned
// UDP tuples for lock-free batch queries, reusing the janitor-owned map
// across scan cycles instead of allocating a fresh snapshot per scan; a nil
// scratch is created on first use and must be stored back by the caller.
// The snapshot is atomic with respect to retain/release. See
// snapshotPinnedTCPInto for the single-consumer contract.
func (m *SessionManager) snapshotPinnedUDPInto(scratch map[bpfTuplesKey]struct{}) map[bpfTuplesKey]struct{} {
	if m == nil {
		return nil
	}
	if scratch == nil {
		scratch = make(map[bpfTuplesKey]struct{})
	}
	m.udpStateMu.RLock()
	clear(scratch)
	for k := range m.pinnedUDP {
		scratch[k] = struct{}{}
	}
	m.udpStateMu.RUnlock()
	return scratch
}

// retireUnpinnedUDPConnState removes stale kernel routing attribution before
// the active generation treats the packet as a new flow. The pin check and
// deletion share one lock with endpoint retain/release, so a process-owned UDP
// runtime can never lose its conn-state entry in this fallback path.
func (m *SessionManager) retireUnpinnedUDPConnState(src, dst netip.AddrPort) (bool, error) {
	if m == nil || !src.IsValid() || !dst.IsValid() {
		return false, nil
	}
	keys := [2]bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP)),
		bpfTuplesKeyFromAddrPorts(dst, src, uint8(unix.IPPROTO_UDP)),
	}

	m.udpStateMu.Lock()
	defer m.udpStateMu.Unlock()
	for _, key := range keys {
		if m.pinnedUDP[key] > 0 {
			return false, nil
		}
	}
	bpf := m.udpBPF.Load()
	if bpf == nil || bpf.ConnStateMap == nil {
		return true, nil
	}
	_, err := BpfMapBatchDelete(bpf.ConnStateMap, keys[:])
	return true, err
}

func redirectTupleForFlow(key bpfTuplesKey) bpfRedirectTuple {
	var redirect bpfRedirectTuple
	copy(redirect.Sip.U6Addr8[:], key.Sip.U6Addr8[:])
	copy(redirect.Dip.U6Addr8[:], key.Dip.U6Addr8[:])
	return redirect
}
