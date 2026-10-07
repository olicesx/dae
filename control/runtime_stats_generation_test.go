/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

// TestGenerationBoundMeteringFollowsOwningStore pins the accounting rule of
// runtimeUploadRecorder/runtimeDownloadRecorder: a generation-owned UDP endpoint
// meters into the store of the plane that created it, even after a successor
// plane published its own store. The bytes of a retired generation therefore
// stop being visible in SnapshotRuntimeStats once its store is unpublished; that
// is a deliberate trade-off (its traffic must not be attributed to a successor
// generation), not an accident. Paths whose lifetime outlives a reload use
// RecordUploadTraffic/RecordDownloadTraffic, which do land in the published
// store.
func TestGenerationBoundMeteringFollowsOwningStore(t *testing.T) {
	retiring := &ControlPlane{runtimeStats: newRuntimeStats()}
	successor := newRuntimeStats()
	publishRuntimeStatsStore(successor)
	t.Cleanup(func() { unpublishRuntimeStatsStore(successor) })

	retiring.recordUploadTraffic(11)
	retiring.recordDownloadTraffic(13)

	if got := retiring.runtimeStats.uploadTotal.Load(); got != 11 {
		t.Fatalf("plane-bound upload metering recorded %d bytes, want 11", got)
	}
	if got := retiring.runtimeStats.downloadTotal.Load(); got != 13 {
		t.Fatalf("plane-bound download metering recorded %d bytes, want 13", got)
	}
	if got := successor.uploadTotal.Load(); got != 0 {
		t.Fatalf("retiring generation attributed %d upload bytes to the published successor store", got)
	}
	if got := successor.downloadTotal.Load(); got != 0 {
		t.Fatalf("retiring generation attributed %d download bytes to the published successor store", got)
	}

	RecordUploadTraffic(17)
	RecordDownloadTraffic(19)
	if got := successor.uploadTotal.Load(); got != 17 {
		t.Fatalf("published-store upload metering recorded %d bytes, want 17", got)
	}
	if got := successor.downloadTotal.Load(); got != 19 {
		t.Fatalf("published-store download metering recorded %d bytes, want 19", got)
	}
}
