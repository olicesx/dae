/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxRuntimeHistorySeconds = 60 * 60
	defaultRuntimeWindowSec  = 30 * 60
	defaultRuntimeMaxPoints  = 180
	runtimeBucketDuration    = 250 * time.Millisecond
	runtimeRateWindow        = time.Second
)

// RuntimeSampleInterval is the recorder interval of traffic history samples.
const RuntimeSampleInterval = runtimeBucketDuration

// RuntimeTrafficSample contains one upload/download rate point.
type RuntimeTrafficSample struct {
	Timestamp    time.Time
	UploadRate   uint64
	DownloadRate uint64
}

// RuntimeStatsSnapshot preserves the traffic-latency branch's exported API.
type RuntimeStatsSnapshot struct {
	UpdatedAt     time.Time
	UploadRate    uint64
	DownloadRate  uint64
	UploadTotal   uint64
	DownloadTotal uint64
	// The totals are userspace payload bytes only: the datapath no longer
	// counts the flows it forwards without the relay, so there is one plane.
	ActiveConnections int
	UDPSessions       int
	Samples           []RuntimeTrafficSample
}

type runtimeBucket struct {
	Timestamp     time.Time
	UploadBytes   uint64
	DownloadBytes uint64
	Duration      time.Duration
}

type runtimeStats struct {
	mu sync.Mutex

	currentBucketStartUnixNano atomic.Int64
	currentUploadBytes         atomic.Uint64
	currentDownloadBytes       atomic.Uint64

	uploadTotal   atomic.Uint64
	downloadTotal atomic.Uint64

	history      []runtimeBucket
	historyStart int
	historyLen   int
}

var (
	// globalRuntimeStats is the single, process-lifetime store. Traffic history
	// and lifetime totals are process facts, not generation facts: flows that
	// survive a reload keep their recorders and must keep landing in the store
	// the dashboard reads. A per-generation store made those flows write into an
	// orphaned store, so `/runtime` froze at the handoff value and the rate read
	// zero until the old flows closed.
	globalRuntimeStats = newRuntimeStats()
	activeRuntimeStats atomic.Pointer[runtimeStats]
	// lastPublishedRuntimeStats keeps the previous generation's store reachable
	// for the totals handoff even while no store is active (a reload gap).
	lastPublishedRuntimeStats atomic.Pointer[runtimeStats]
)

// processRuntimeStatsStore returns the process-lifetime store every generation
// records into.
func processRuntimeStatsStore() *runtimeStats {
	return globalRuntimeStats
}

func newRuntimeStats() *runtimeStats {
	return &runtimeStats{}
}

func maxRuntimeHistoryBuckets() int {
	return int((time.Duration(maxRuntimeHistorySeconds) * time.Second) / runtimeBucketDuration)
}

func currentRuntimeStatsStore() *runtimeStats {
	if active := activeRuntimeStats.Load(); active != nil {
		return active
	}
	return globalRuntimeStats
}

func publishRuntimeStatsStore(s *runtimeStats) {
	if s == nil {
		return
	}
	if prev := lastPublishedRuntimeStats.Load(); prev != nil {
		s.inheritTotalsFrom(prev)
	}
	activeRuntimeStats.Store(s)
	lastPublishedRuntimeStats.Store(s)
}

// inheritTotalsFrom carries the process-lifetime byte totals across a
// generation handoff.
//
// A reload builds a fresh generation-local store. Without this the reported
// totals dropped to zero on every reload while runtime/outbounds kept counting
// in its process-level registry, so the two resources disagreed by the whole
// process history - which reads as "the API numbers are wrong".
func (s *runtimeStats) inheritTotalsFrom(prev *runtimeStats) {
	if s == nil || prev == nil || s == prev {
		return
	}
	s.uploadTotal.Add(prev.uploadTotal.Load())
	s.downloadTotal.Add(prev.downloadTotal.Load())
}

func unpublishRuntimeStatsStore(s *runtimeStats) {
	if s == nil {
		return
	}
	activeRuntimeStats.CompareAndSwap(s, nil)
}

// RecordUploadTraffic records upload bytes into the store published by the
// active control plane (globalRuntimeStats while no plane is published).
// Generation-owned UDP endpoints meter into their own plane's store instead;
// see ControlPlane.runtimeUploadRecorder.
func RecordUploadTraffic(n int64) {
	if n <= 0 {
		return
	}
	if store := currentRuntimeStatsStore(); store != nil {
		store.record(uint64(n), 0)
	}
}

// RecordDownloadTraffic records download bytes into the store published by the
// active control plane (globalRuntimeStats while no plane is published).
// Generation-owned UDP endpoints meter into their own plane's store instead;
// see ControlPlane.runtimeDownloadRecorder.
func RecordDownloadTraffic(n int64) {
	if n <= 0 {
		return
	}
	if store := currentRuntimeStatsStore(); store != nil {
		store.record(0, uint64(n))
	}
}

func (c *ControlPlane) publishRuntimeStats() {
	if c == nil {
		return
	}
	publishRuntimeStatsStore(c.runtimeStats)
}

func (c *ControlPlane) unpublishRuntimeStats() {
	if c == nil {
		return
	}
	unpublishRuntimeStatsStore(c.runtimeStats)
}

// record is the single writer of the bucket and the lifetime totals, so the two
// can never drift apart.
func (s *runtimeStats) record(upload uint64, download uint64) {
	if s == nil || (upload == 0 && download == 0) {
		return
	}
	// No clock read here. A dedicated sampler rotates the in-flight bucket on a
	// fixed cadence, so the forwarding path pays one atomic add per record
	// instead of a time.Now() (and a possible lock) on every relay write. The
	// sampler is the reason rotation no longer has to ride a dashboard poll.
	if upload > 0 {
		s.currentUploadBytes.Add(upload)
		s.uploadTotal.Add(upload)
	}
	if download > 0 {
		s.currentDownloadBytes.Add(download)
		s.downloadTotal.Add(download)
	}
}

// startRuntimeStatsSampler rotates the in-flight bucket on a fixed cadence for
// the process-lifetime store. It runs at most once per process and only rotates:
// it adds no traffic, so an idle daemon does one atomic load per tick.
//
// Rotation has to be time-driven rather than poll-driven: a dashboard polls at
// its own cadence, and bytes recorded between two polls would otherwise land in
// the first finished bucket, which scales the one-second rate by that bucket's
// share of the window and under-reports it. Snapshot still rotates as a guard
// for the case where the sampler has not started yet.
func startRuntimeStatsSampler(store *runtimeStats) {
	if store == nil {
		return
	}
	runtimeStatsSamplerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(RuntimeSampleInterval)
			defer ticker.Stop()
			for now := range ticker.C {
				store.advanceBucket(now)
			}
		}()
	})
}

var runtimeStatsSamplerOnce sync.Once

// advanceBucket rotates the in-flight bucket once its boundary has passed.
// The common case is one atomic load and compare; only a crossing takes the
// lock, so the burst path never contends with a reader.
func (s *runtimeStats) advanceBucket(now time.Time) {
	if s == nil {
		return
	}
	start := timeFromUnixNano(s.currentBucketStartUnixNano.Load())
	if !start.IsZero() && !bucketStart(now).After(start) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollLocked(now)
}

func (s *runtimeStats) snapshot(activeConnections, udpSessions, windowSec, maxPoints int, now time.Time, history bool) RuntimeStatsSnapshot {
	if s == nil {
		return RuntimeStatsSnapshot{
			UpdatedAt:         now,
			ActiveConnections: activeConnections,
			UDPSessions:       udpSessions,
		}
	}
	if windowSec <= 0 {
		windowSec = defaultRuntimeWindowSec
	}
	if maxPoints <= 0 {
		maxPoints = defaultRuntimeMaxPoints
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.rollLocked(now)

	// Only buckets ending within the rate window can contribute to the
	// headline rate. The chart below selects completed samples separately.
	rateStart := now.Add(-runtimeRateWindow)
	firstRecent := sort.Search(s.historyLen, func(i int) bool {
		return s.historyBucket(i).Timestamp.After(rateStart)
	})
	var recentStorage [int(runtimeRateWindow/runtimeBucketDuration) + 2]runtimeBucket
	recent := recentStorage[:0]
	for i := firstRecent; i < s.historyLen; i++ {
		recent = append(recent, s.historyBucket(i))
	}
	if duration := now.Sub(s.currentBucketStartLocked()); duration > 0 {
		recent = append(recent, runtimeBucket{
			Timestamp:     now,
			UploadBytes:   s.currentUploadBytes.Load(),
			DownloadBytes: s.currentDownloadBytes.Load(),
			Duration:      duration,
		})
	}
	uploadRate, downloadRate := ratesFromBuckets(recent, now, runtimeRateWindow)

	var samples []RuntimeTrafficSample
	if history {
		start := now.Add(-time.Duration(windowSec) * time.Second)
		first := sort.Search(s.historyLen, func(i int) bool {
			return !s.historyBucket(i).Timestamp.Before(start)
		})
		count := s.historyLen - first
		stride := historySampleStride(count, maxPoints)
		samples = make([]RuntimeTrafficSample, 0, (count+stride-1)/stride)
		if count > 0 {
			// Anchor decimation at the newest completed bucket, preserving
			// the original rates and timestamps of the retained samples.
			for i := first + (count-1)%stride; i < s.historyLen; i += stride {
				bucket := s.historyBucket(i)
				samples = append(samples, RuntimeTrafficSample{
					Timestamp:    bucket.Timestamp,
					UploadRate:   rateFromBytes(bucket.UploadBytes, bucket.Duration),
					DownloadRate: rateFromBytes(bucket.DownloadBytes, bucket.Duration),
				})
			}
		}
	}

	return RuntimeStatsSnapshot{
		UpdatedAt:         now,
		UploadRate:        uploadRate,
		DownloadRate:      downloadRate,
		UploadTotal:       s.uploadTotal.Load(),
		DownloadTotal:     s.downloadTotal.Load(),
		ActiveConnections: activeConnections,
		UDPSessions:       udpSessions,
		Samples:           samples,
	}
}

func (s *runtimeStats) currentBucketStartLocked() time.Time {
	return timeFromUnixNano(s.currentBucketStartUnixNano.Load())
}

func (s *runtimeStats) rollLocked(now time.Time) {
	targetBucketStart := bucketStart(now)
	currentBucketStart := s.currentBucketStartLocked()
	if currentBucketStart.IsZero() {
		s.currentBucketStartUnixNano.Store(targetBucketStart.UnixNano())
		return
	}
	if !targetBucketStart.After(currentBucketStart) {
		return
	}

	uploadBytes := s.currentUploadBytes.Swap(0)
	downloadBytes := s.currentDownloadBytes.Swap(0)
	if uploadBytes == 0 && downloadBytes == 0 && s.historyLen == 0 {
		s.currentBucketStartUnixNano.Store(targetBucketStart.UnixNano())
		return
	}
	// An idle gap longer than the retention ring cannot be materialized bucket
	// by bucket; jump to the oldest bucket that can still be retained so the
	// rotation stays bounded after a long pause.
	if gap := targetBucketStart.Sub(currentBucketStart); gap > time.Duration(maxRuntimeHistoryBuckets())*runtimeBucketDuration {
		currentBucketStart = targetBucketStart.Add(-time.Duration(maxRuntimeHistoryBuckets()) * runtimeBucketDuration)
	}
	for nextBucketStart := currentBucketStart.Add(runtimeBucketDuration); !nextBucketStart.After(targetBucketStart); nextBucketStart = nextBucketStart.Add(runtimeBucketDuration) {
		s.pushHistoryBucket(runtimeBucket{
			Timestamp:     nextBucketStart,
			UploadBytes:   uploadBytes,
			DownloadBytes: downloadBytes,
			Duration:      runtimeBucketDuration,
		})
		uploadBytes = 0
		downloadBytes = 0
		currentBucketStart = nextBucketStart
		s.currentBucketStartUnixNano.Store(currentBucketStart.UnixNano())
	}
}

func (s *runtimeStats) pushHistoryBucket(bucket runtimeBucket) {
	if s == nil {
		return
	}
	if len(s.history) == 0 {
		s.history = make([]runtimeBucket, maxRuntimeHistoryBuckets())
	}
	if s.historyLen < len(s.history) {
		idx := (s.historyStart + s.historyLen) % len(s.history)
		s.history[idx] = bucket
		s.historyLen++
		return
	}
	s.history[s.historyStart] = bucket
	s.historyStart = (s.historyStart + 1) % len(s.history)
}

func timeFromUnixNano(unixNano int64) time.Time {
	if unixNano == 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano)
}

// runtimeStatsStore returns the store this plane snapshots.
func (c *ControlPlane) runtimeStatsStore() *runtimeStats {
	if c == nil || c.runtimeStats == nil {
		return globalRuntimeStats
	}
	return c.runtimeStats
}

// The recorders below meter against the plane's own store rather than the
// published one: UDP endpoints and their datapath sessions belong to the
// generation that created them, so its bytes must not be attributed to a
// successor generation (see the retained-endpoint rationale in udp.go). The
// consequence is deliberate: once the plane is retired and its store is
// unpublished, its counters are no longer part of SnapshotRuntimeStats.
// Long-lived TCP relays meter through RecordUploadTraffic/RecordDownloadTraffic,
// which target the published store, so their bytes follow whichever generation
// is current when they flow.
func (c *ControlPlane) runtimeUploadRecorder() func(int64) {
	return c.recordUploadTraffic
}

func (c *ControlPlane) runtimeDownloadRecorder() func(int64) {
	return c.recordDownloadTraffic
}

func (c *ControlPlane) recordUploadTraffic(n int64) {
	if n <= 0 {
		return
	}
	c.runtimeStatsStore().record(uint64(n), 0)
}

func (c *ControlPlane) recordDownloadTraffic(n int64) {
	if n <= 0 {
		return
	}
	c.runtimeStatsStore().record(0, uint64(n))
}

func (c *ControlPlane) SnapshotRuntimeStats(windowSec int, maxPoints int) RuntimeStatsSnapshot {
	return c.snapshotRuntimeStats(windowSec, maxPoints, true)
}

// SnapshotRuntimeTotals returns current rates and totals without building traffic history.
func (c *ControlPlane) SnapshotRuntimeTotals() RuntimeStatsSnapshot {
	return c.snapshotRuntimeStats(0, 0, false)
}

func (c *ControlPlane) snapshotRuntimeStats(windowSec, maxPoints int, history bool) RuntimeStatsSnapshot {
	activeConnections := 0
	udpSessions := 0
	if c != nil {
		activeConnections = c.ActiveTCPConnections()
		udpSessions = DefaultUdpEndpointPool.Len()
	}
	return c.runtimeStatsStore().snapshot(activeConnections, udpSessions, windowSec, maxPoints, time.Now(), history)
}

// historySampleStride selects at most maxPoints from a newest-anchored series.
func historySampleStride(count, maxPoints int) int {
	if maxPoints <= 0 || count <= maxPoints {
		return 1
	}
	return (count-1)/maxPoints + 1
}

func (s *runtimeStats) historyBucket(index int) runtimeBucket {
	return s.history[(s.historyStart+index)%len(s.history)]
}

func bucketStart(now time.Time) time.Time {
	return now.Truncate(runtimeBucketDuration)
}

func rateFromBytes(bytes uint64, duration time.Duration) uint64 {
	if duration <= 0 {
		return 0
	}
	return uint64(float64(bytes) * float64(time.Second) / float64(duration))
}

func ratesFromBuckets(buckets []runtimeBucket, now time.Time, window time.Duration) (uploadRate uint64, downloadRate uint64) {
	if len(buckets) == 0 {
		return 0, 0
	}

	windowStart := now.Add(-window)
	var (
		totalUpload   uint64
		totalDownload uint64
		totalDuration time.Duration
	)

	for _, bucket := range buckets {
		bucketEnd := bucket.Timestamp
		bucketStart := bucketEnd.Add(-bucket.Duration)
		if !bucketEnd.After(windowStart) {
			continue
		}

		effectiveStart := bucketStart
		if effectiveStart.Before(windowStart) {
			effectiveStart = windowStart
		}
		effectiveDuration := bucketEnd.Sub(effectiveStart)
		if effectiveDuration <= 0 {
			continue
		}

		ratio := float64(effectiveDuration) / float64(bucket.Duration)
		totalUpload += uint64(float64(bucket.UploadBytes) * ratio)
		totalDownload += uint64(float64(bucket.DownloadBytes) * ratio)
		totalDuration += effectiveDuration
	}

	if totalDuration <= 0 {
		return 0, 0
	}

	return rateFromBytes(totalUpload, totalDuration), rateFromBytes(totalDownload, totalDuration)
}
