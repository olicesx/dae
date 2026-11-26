/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

// A dashboard polls at its own cadence, which never lines up with the 250ms
// bucket grid. The reported one-second rate must still match the traffic that
// actually flowed, no matter when snapshots happen.
func TestRuntimeStatsRateMatchesTrafficAtPollingCadence(t *testing.T) {
	for _, pollInterval := range []time.Duration{
		100 * time.Millisecond,
		300 * time.Millisecond,
		1 * time.Second,
		1300 * time.Millisecond,
		2 * time.Second,
		5 * time.Second,
	} {
		t.Run(pollInterval.String(), func(t *testing.T) {
			store := newRuntimeStats()
			start := time.Unix(1_700_000_000, 0)
			const bytesPerSecond = 1_000_000
			const step = 10 * time.Millisecond

			store.snapshot(0, 0, 3600, 180, start, true)

			var nextPoll time.Duration
			checked := 0
			for elapsed := time.Duration(0); elapsed <= 6*time.Second; elapsed += step {
				now := start.Add(elapsed)
				// Production rotates the in-flight bucket from the sampler, not
				// from the write path; the test drives that rotation explicitly.
				store.advanceBucket(now)
				store.record(uint64(bytesPerSecond*step/time.Second), 0)
				if elapsed < nextPoll {
					continue
				}
				nextPoll = elapsed + pollInterval
				snapshot := store.snapshot(0, 0, 3600, 180, now, true)
				totals := store.snapshot(0, 0, 0, 0, now, false)
				if totals.Samples != nil || totals.UploadRate != snapshot.UploadRate || totals.DownloadRate != snapshot.DownloadRate ||
					totals.UploadTotal != snapshot.UploadTotal || totals.DownloadTotal != snapshot.DownloadTotal {
					t.Fatalf("totals snapshot differs at %v: %+v", elapsed, totals)
				}
				if elapsed < time.Second {
					continue
				}
				checked++
				got := float64(snapshot.UploadRate)
				want := float64(bytesPerSecond)
				if got < want*0.85 || got > want*1.15 {
					t.Fatalf("upload rate at %v = %.0f B/s, want ~%.0f B/s", elapsed, got, want)
				}
			}
			if checked == 0 {
				t.Fatal("no rate samples were checked")
			}
		})
	}
}

// record runs on the relay hot path; the bucket rotation must stay cheap.
func BenchmarkRuntimeStatsRecord(b *testing.B) {
	store := newRuntimeStats()
	store.record(1, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		store.record(1024, 1024)
	}
}

func TestRuntimeHistoryDecimatesWrappedRingWithoutAggregating(t *testing.T) {
	store, now := fullRuntimeHistory()
	for _, tc := range []struct {
		window, limit int
	}{
		{1800, 180},
		{3600, 1},
		{1, 180},
	} {
		snapshot := store.snapshot(0, 0, tc.window, tc.limit, now, true)
		// The newest bucket ends at now and the cutoff is inclusive.
		available := min(maxRuntimeHistoryBuckets(), tc.window*4+1)
		stride := (available + tc.limit - 1) / tc.limit
		wantCount := (available + stride - 1) / stride
		if got := len(snapshot.Samples); got != wantCount {
			t.Fatalf("window=%d limit=%d: samples=%d, want %d", tc.window, tc.limit, got, wantCount)
		}
		for i, sample := range snapshot.Samples {
			age := (wantCount - 1 - i) * stride
			if at := now.Add(-time.Duration(age) * runtimeBucketDuration); !sample.Timestamp.Equal(at) || sample.UploadRate != uint64(age*4) || sample.DownloadRate != uint64(age*8) {
				t.Fatalf("window=%d limit=%d sample=%d: %+v, want original bucket at %s", tc.window, tc.limit, i, sample, at)
			}
		}
	}
}

func TestRuntimeHistoryKeepsInFlightOutOfSamples(t *testing.T) {
	store, newest := fullRuntimeHistory()
	store.record(1024, 2048)
	now := newest.Add(runtimeBucketDuration / 2)
	snapshot := store.snapshot(0, 0, 1800, 180, now, true)
	last := snapshot.Samples[len(snapshot.Samples)-1]
	if !last.Timestamp.Equal(newest) || last.UploadRate != 0 || last.DownloadRate != 0 {
		t.Fatalf("newest completed sample = %+v, want zero-byte bucket at %s", last, newest)
	}
	if snapshot.UploadRate != 1028 || snapshot.DownloadRate != 2057 {
		t.Fatalf("headline rate = %d/%d, want 1028/2057 including the partial bucket", snapshot.UploadRate, snapshot.DownloadRate)
	}
}

func fullRuntimeHistory() (*runtimeStats, time.Time) {
	store := newRuntimeStats()
	now := time.Unix(1_700_000_000, 0)
	store.currentBucketStartUnixNano.Store(now.UnixNano())
	for i := maxRuntimeHistoryBuckets() + 7; i >= 0; i-- {
		store.pushHistoryBucket(runtimeBucket{
			Timestamp: now.Add(-time.Duration(i) * runtimeBucketDuration),
			Duration:  runtimeBucketDuration, UploadBytes: uint64(i), DownloadBytes: uint64(2 * i),
		})
	}
	return store, now
}

func BenchmarkRuntimeHistorySnapshot(b *testing.B) {
	store, now := fullRuntimeHistory()
	b.ReportAllocs()
	for b.Loop() {
		store.snapshot(0, 0, 1800, 180, now, true)
	}
}
