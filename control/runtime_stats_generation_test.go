/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

// resetRuntimeStatsHandoff detaches these tests from the process-global totals
// handoff. Publishing a store inherits the lifetime totals of the last
// published one (see inheritTotalsFrom), and the pointer outlives an
// unpublish; an earlier test's store must not surface as inherited bytes.
func resetRuntimeStatsHandoff(t *testing.T) {
	t.Helper()
	lastPublishedRuntimeStats.Store(nil)
	t.Cleanup(func() { lastPublishedRuntimeStats.Store(nil) })
}

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
	resetRuntimeStatsHandoff(t)

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
// through its own recorders, a successor publishes its own store, and every
// byte the retired plane meters from then on stays out of the successor's
// snapshot. What the retired plane had accumulated at the handoff crosses over
// exactly once, as lifetime totals (see
// TestLifetimeTotalsSurviveGenerationHandoff).
func TestRetiredGenerationLeavesTheSnapshot(t *testing.T) {
	resetRuntimeStatsHandoff(t)

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

	// The retired plane still accounts for its own traffic; nothing forwards it
	// to the published store any more.
	retiring.recordUploadTraffic(1000)
	retiring.recordDownloadTraffic(1000)
	if got := successor.SnapshotRuntimeStats(60, 60); got.UploadTotal != 11 || got.DownloadTotal != 13 {
		t.Fatalf("successor snapshot = %d/%d bytes, want only the handed-over 11/13: the retired generation's later bytes leaked in", got.UploadTotal, got.DownloadTotal)
	}
	if got := retiring.SnapshotRuntimeStats(60, 60); got.UploadTotal != 1011 || got.DownloadTotal != 1013 {
		t.Fatalf("retired plane snapshot = %d/%d bytes, want its own 1011/1013", got.UploadTotal, got.DownloadTotal)
	}

	RecordUploadTraffic(17)
	if got := successor.SnapshotRuntimeStats(60, 60); got.UploadTotal != 28 {
		t.Fatalf("published-store metering after the swap = %d bytes, want 28 (11 handed over + 17)", got.UploadTotal)
	}
}

// TestLifetimeTotalsSurviveGenerationHandoff pins why the retired plane's
// totals cross over: a reload builds a fresh generation-local store, and the
// reported totals must not drop to zero at the handoff while runtime/outbounds
// keep counting for the whole process. Only the lifetime totals are inherited;
// the successor's traffic history starts empty.
func TestLifetimeTotalsSurviveGenerationHandoff(t *testing.T) {
	resetRuntimeStatsHandoff(t)

	retiring := &ControlPlane{runtimeStats: newRuntimeStats()}
	retiring.publishRuntimeStats()
	retiring.recordUploadTraffic(11)
	retiring.recordDownloadTraffic(13)

	successor := &ControlPlane{runtimeStats: newRuntimeStats()}
	successor.publishRuntimeStats()
	t.Cleanup(successor.unpublishRuntimeStats)

	if successor.runtimeStats.historyLen != 0 {
		t.Fatalf("successor inherited %d history buckets; the traffic history is per generation", successor.runtimeStats.historyLen)
	}
	if got := successor.SnapshotRuntimeStats(60, 60); got.UploadTotal != 11 || got.DownloadTotal != 13 {
		t.Fatalf("successor snapshot = %d/%d bytes right after the handoff, want the lifetime 11/13", got.UploadTotal, got.DownloadTotal)
	}
	successor.recordUploadTraffic(5)
	if got := successor.SnapshotRuntimeStats(60, 60); got.UploadTotal != 16 {
		t.Fatalf("successor snapshot = %d bytes after its own 5, want 16", got.UploadTotal)
	}
}
