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

// TestRetiredGenerationLeavesTheSnapshot pins the observable half of the same
// rule through the production API: a plane publishes its store and meters
// through its own recorders, a successor publishes its own store, and the
// successor's snapshot no longer carries the retired generation's bytes. The
// retired plane still accounts for its own traffic — what changed is that
// nothing publishes that store any more.
func TestRetiredGenerationLeavesTheSnapshot(t *testing.T) {
	retiring := &ControlPlane{runtimeStats: newRuntimeStats()}
	retiring.publishRuntimeStats()
	retiring.recordUploadTraffic(11)
	retiring.recordDownloadTraffic(13)
	if got := retiring.SnapshotRuntimeStats(60, 60); got.UploadTotal != 11 || got.DownloadTotal != 13 {
		t.Fatalf("published plane snapshot = %d/%d bytes, want 11/13", got.UploadTotal, got.DownloadTotal)
	}

	successor := &ControlPlane{runtimeStats: newRuntimeStats()}
	successor.publishRuntimeStats()
	t.Cleanup(successor.unpublishRuntimeStats)
	retiring.unpublishRuntimeStats()

	if got := successor.SnapshotRuntimeStats(60, 60); got.UploadTotal != 0 || got.DownloadTotal != 0 {
		t.Fatalf("retired generation still contributes %d/%d bytes to the successor snapshot", got.UploadTotal, got.DownloadTotal)
	}
	if got := retiring.SnapshotRuntimeStats(60, 60); got.UploadTotal != 11 || got.DownloadTotal != 13 {
		t.Fatalf("retired plane snapshot = %d/%d bytes, want its own 11/13", got.UploadTotal, got.DownloadTotal)
	}
	RecordUploadTraffic(17)
	if got := successor.SnapshotRuntimeStats(60, 60); got.UploadTotal != 17 {
		t.Fatalf("published-store metering after the swap = %d bytes, want 17", got.UploadTotal)
	}
}
