/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// scrubRecorder captures the physical conn_state deletions releaseFlow issues
// through the connStateScrubDelete seam.
type scrubRecorder struct {
	mu    sync.Mutex
	calls []scrubCall
}

type scrubCall struct {
	target *ebpf.Map
	keys   []bpfTuplesKey
}

func (r *scrubRecorder) record(target *ebpf.Map, keys interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tupleKeys, _ := keys.([]bpfTuplesKey)
	r.calls = append(r.calls, scrubCall{target: target, keys: append([]bpfTuplesKey(nil), tupleKeys...)})
}

func (r *scrubRecorder) snapshot() []scrubCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]scrubCall(nil), r.calls...)
}

// withScrubRecorder installs the seam for one test.
func withScrubRecorder(t *testing.T) *scrubRecorder {
	t.Helper()
	rec := &scrubRecorder{}
	prev := connStateScrubDelete
	connStateScrubDelete = func(_ *ebpf.Map, keys interface{}) (int, error) {
		rec.record(nil, keys)
		return 0, nil
	}
	t.Cleanup(func() { connStateScrubDelete = prev })
	return rec
}

// TestReleaseFlowMigratedMapScrubIsRefcountGated is the P2-2 regression: the
// migrated-map scrub in releaseFlow must be gated on the shared pin refcount
// reaching zero, inside the same generationsMu critical section as the unpin.
// Before the fix the scrub deleted the flow's whole pinKeys set
// unconditionally and outside generationsMu, so the flow that finished first
// removed conn_state entries that a still-live same-tuple flow pins.
func TestReleaseFlowMigratedMapScrubIsRefcountGated(t *testing.T) {
	primary := &ebpf.Map{}
	migrated := &ebpf.Map{}
	rec := withScrubRecorder(t)

	manager := NewSessionManager(context.Background())
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: primary}})

	d := lifecycleTestDialer("p22-regression")
	rtA := lifecycleTestRuntime(d)
	rtB := lifecycleTestRuntime(d)

	key := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.77:42077"),
		netip.MustParseAddrPort("198.51.100.77:443"), unix.IPPROTO_TCP)

	binding := TcpFlowBinding{}
	binding.Egress.Dialer = d

	// Two live flows on the same tuple. This is legal: both register their own
	// pin on the shared tuple, which is exactly why an unconditional delete is
	// wrong.
	flowA, err := manager.adoptTCP(&memoryLayoutConn{id: 1}, nil, binding, rtA, []bpfTuplesKey{key})
	if err != nil {
		t.Fatalf("adopt flow A: %v", err)
	}
	flowB, err := manager.adoptTCP(&memoryLayoutConn{id: 2}, nil, binding, rtB, []bpfTuplesKey{key})
	if err != nil {
		t.Fatalf("adopt flow B: %v", err)
	}

	// Seed the migration bookkeeping that migrate() +
	// repinConnStateMapsForRollback record when a flow re-pins into the new
	// generation's map: one extra shard pin plus the migrated map remembered on
	// the flow. Seeding it directly keeps this regression runnable in the
	// dae_stub_ebpf build, where the production re-pin's Lookup/Update need a
	// real kernel map (MigrateGeneration's own accounting is covered by the
	// real-map probe).
	shard := &manager.pinnedShards[tuplesShardIndex(&key)]
	shard.pin(key)
	shard.pin(key)
	flowA.migratedBpf = []*bpfObjects{{bpfMaps: bpfMaps{ConnStateMap: migrated}}}
	flowB.migratedBpf = []*bpfObjects{{bpfMaps: bpfMaps{ConnStateMap: migrated}}}

	shard.mu.Lock()
	refs := shard.keys[key]
	shard.mu.Unlock()
	if refs != 4 {
		// 2 registrations + 2 migration re-pins.
		t.Fatalf("pinned refs after two same-tuple flows migrated = %d, want 4", refs)
	}

	flowA.finish()
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("P2-2 regression: the first finishing flow issued %d physical deletion(s) "+
			"while a live same-tuple flow still pins the tuple (keys=%+v)", len(calls), calls)
	}
	shard.mu.Lock()
	refs = shard.keys[key]
	shard.mu.Unlock()
	if refs != 2 {
		t.Fatalf("pinned refs after the first flow finished = %d, want 2 (the live flow's pins)", refs)
	}

	// The last owner drops: both the primary and the migrated map must be
	// scrubbed with exactly the released key.
	flowB.finish()
	calls := rec.snapshot()
	if len(calls) != 2 {
		t.Fatalf("physical deletions after the last pin dropped = %d, want 2 (primary + migrated)", len(calls))
	}
	for _, call := range calls {
		if len(call.keys) != 1 || call.keys[0] != key {
			t.Fatalf("scrub keys = %+v, want exactly the released tuple %+v", call.keys, key)
		}
	}
	shard.mu.Lock()
	refs = shard.keys[key]
	shard.mu.Unlock()
	if refs != 0 {
		t.Fatalf("pinned refs after the last flow finished = %d, want 0", refs)
	}
}

// TestCountConnStateScrubErrorCountsAndLogs pins the "no silent degradation"// contract that replaced the discarded batch-delete errors: failures are
// counted, and a nil error is not counted at all.
func TestCountConnStateScrubErrorCountsAndLogs(t *testing.T) {
	before := connStateScrubErrorCount.Load()
	countConnStateScrubError("primary", nil)
	if got := connStateScrubErrorCount.Load(); got != before {
		t.Fatalf("nil error must not be counted: %d -> %d", before, got)
	}
	countConnStateScrubError("primary", context.Canceled)
	countConnStateScrubError("migrated", context.DeadlineExceeded)
	if got := connStateScrubErrorCount.Load(); got != before+2 {
		t.Fatalf("scrub error count = %d, want %d", got, before+2)
	}
}

// TestReleaseFlowMigratedMapDeleteKeepsLiveEntry is the entry-level form of the
// same regression, run against real (kernel) conn_state maps: after migration
// the first finishing flow must leave the tuple present in BOTH maps while a
// live same-tuple flow still pins it. It skips in the dae_stub_ebpf build,
// where no kernel map can be created.
func TestReleaseFlowMigratedMapDeleteKeepsLiveEntry(t *testing.T) {
	oldMap := newJanitorTestMap(t, "conn_state_map")
	newMap := newJanitorTestMap(t, "conn_state_map")
	manager := NewSessionManager(context.Background())
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: oldMap}})

	d := lifecycleTestDialer("p22-entry-level")
	rtA := lifecycleTestRuntime(d)
	rtB := lifecycleTestRuntime(d)

	key := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.78:42078"),
		netip.MustParseAddrPort("198.51.100.78:443"), unix.IPPROTO_TCP)
	value := bpfConnState{LastSeenNs: 1, State: 0}
	value.Meta.Data.HasRouting = 1
	if err := oldMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed old conn_state: %v", err)
	}

	binding := TcpFlowBinding{}
	binding.Egress.Dialer = d

	flowA, err := manager.adoptTCP(&memoryLayoutConn{id: 11}, nil, binding, rtA, []bpfTuplesKey{key})
	if err != nil {
		t.Fatalf("adopt flow A: %v", err)
	}
	flowB, err := manager.adoptTCP(&memoryLayoutConn{id: 12}, nil, binding, rtB, []bpfTuplesKey{key})
	if err != nil {
		t.Fatalf("adopt flow B: %v", err)
	}
	migrated, remaining := manager.MigrateGeneration(0, 1,
		&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: newMap}}, rtB)
	if migrated != 2 || remaining != 0 {
		t.Fatalf("MigrateGeneration = %d/%d, want 2/0", migrated, remaining)
	}
	if !connStateExists(newMap, key) {
		t.Fatal("migration did not re-pin the tuple into the new generation's map")
	}

	flowA.finish()
	if !connStateExists(newMap, key) {
		t.Fatal("P2-2 regression: the finishing flow deleted a migrated conn_state entry that a live same-tuple flow pins")
	}
	if !connStateExists(oldMap, key) {
		t.Fatal("P2-2 regression: the finishing flow deleted the primary conn_state entry that a live same-tuple flow pins")
	}

	flowB.finish()
	if connStateExists(newMap, key) {
		t.Fatal("conn_state entry leaked in the migrated map after the last pin dropped")
	}
	if connStateExists(oldMap, key) {
		t.Fatal("conn_state entry leaked in the primary map after the last pin dropped")
	}
}
