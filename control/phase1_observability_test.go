/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

func installPhase1ObservabilityForTest(t *testing.T, sampleEvery uint64) *phase1Observability {
	t.Helper()
	recorder := newPhase1Observability(sampleEvery)
	previous := swapPhase1Observability(recorder)
	t.Cleanup(func() {
		activePhase1Observability.CompareAndSwap(recorder, previous)
	})
	return recorder
}

func TestPhase1ObservabilityIsDisabledByDefault(t *testing.T) {
	previous := swapPhase1Observability(nil)
	t.Cleanup(func() {
		activePhase1Observability.CompareAndSwap(nil, previous)
	})

	if recorder := phase1SampledRecorder(phase1ObservationRoutingLookup); recorder != nil {
		t.Fatalf("phase1SampledRecorder() = %p, want nil", recorder)
	}

	observePhase1RoutingLookup(phase1RoutingLookupEmbedded, phase1RoutingLookupHit)
	observePhase1UserspaceRematch(phase1TransportTCP, phase1UserspaceRematchSuccess)
	observePhase1UDPKeyProbe(phase1UDPKeyProbePrimary, phase1UDPKeyProbeHit)
	observePhase1DNSCache(phase1DNSCacheHit, time.Millisecond)
	observePhase1BPFPublish(phase1BPFPublishPublish, phase1BPFPublishSuccess, time.Millisecond)
	observePhase1ReloadDrain(phase1ReloadDrainCompleted, time.Millisecond)
	observePhase1Dial(phase1DialOperationConnectInitial, phase1TransportTCP, phase1DialOutcomeSuccess)
}

func TestPhase1ObservabilityRecordsFixedDimensions(t *testing.T) {
	recorder := installPhase1ObservabilityForTest(t, 1)

	observePhase1RoutingLookup(phase1RoutingLookupEmbedded, phase1RoutingLookupHit)
	observePhase1UserspaceRematch(phase1TransportUDP, phase1UserspaceRematchFailure)
	observePhase1UDPKeyProbe(phase1UDPKeyProbeSibling, phase1UDPKeyProbeTargetMismatch)
	observePhase1DNSCache(phase1DNSCacheStale, 15*time.Millisecond)
	observePhase1BPFPublish(phase1BPFPublishStage, phase1BPFPublishFailure, 500*time.Millisecond)
	observePhase1ReloadDrain(phase1ReloadDrainTimedOut, 2*time.Second)
	observePhase1Dial(phase1DialOperationConnectRetry, phase1TransportTCP, phase1DialOutcomeSuccess)

	if got := recorder.routingLookupCount(phase1RoutingLookupEmbedded, phase1RoutingLookupHit); got != 1 {
		t.Fatalf("routing lookup count = %d, want 1", got)
	}
	if got := recorder.userspaceRematchCount(phase1TransportUDP, phase1UserspaceRematchFailure); got != 1 {
		t.Fatalf("userspace rematch count = %d, want 1", got)
	}
	if got := recorder.udpKeyProbeCount(phase1UDPKeyProbeSibling, phase1UDPKeyProbeTargetMismatch); got != 1 {
		t.Fatalf("UDP key-probe count = %d, want 1", got)
	}
	if got := recorder.dnsCacheCount(phase1DNSCacheStale); got != 1 {
		t.Fatalf("DNS cache count = %d, want 1", got)
	}
	if got := recorder.dnsCacheLatencyCount(phase1DNSCacheStale, phase1LatencyUnderHundredMilliseconds); got != 1 {
		t.Fatalf("DNS cache latency count = %d, want 1", got)
	}
	if got := recorder.bpfPublishCount(phase1BPFPublishStage, phase1BPFPublishFailure); got != 1 {
		t.Fatalf("BPF publish count = %d, want 1", got)
	}
	if got := recorder.bpfPublishLatencyCount(phase1BPFPublishStage, phase1BPFPublishFailure, phase1LatencyUnderSecond); got != 1 {
		t.Fatalf("BPF publish latency count = %d, want 1", got)
	}
	if got := recorder.reloadDrainCount(phase1ReloadDrainTimedOut); got != 1 {
		t.Fatalf("reload drain count = %d, want 1", got)
	}
	if got := recorder.reloadDrainLatencyCount(phase1ReloadDrainTimedOut, phase1LatencyAtLeastSecond); got != 1 {
		t.Fatalf("reload drain latency count = %d, want 1", got)
	}
	if got := recorder.dialCount(phase1DialOperationConnectRetry, phase1TransportTCP, phase1DialOutcomeSuccess); got != 1 {
		t.Fatalf("dial count = %d, want 1", got)
	}
}

func TestPhase1ObservabilitySamplingIsDeterministicPerFamily(t *testing.T) {
	recorder := installPhase1ObservabilityForTest(t, 3)

	for range 7 {
		observePhase1RoutingLookup(phase1RoutingLookupHandoff, phase1RoutingLookupHit)
		observePhase1Dial(phase1DialOperationSelectPrimary, phase1TransportUDP, phase1DialOutcomeSuccess)
	}

	if got := recorder.routingLookupCount(phase1RoutingLookupHandoff, phase1RoutingLookupHit); got != 3 {
		t.Fatalf("sampled routing lookup count = %d, want 3", got)
	}
	if got := recorder.dialCount(phase1DialOperationSelectPrimary, phase1TransportUDP, phase1DialOutcomeSuccess); got != 3 {
		t.Fatalf("sampled dial count = %d, want 3", got)
	}
}

func TestPhase1ObservabilityLatencyBucketsAndValidation(t *testing.T) {
	tests := []struct {
		name    string
		elapsed time.Duration
		bucket  phase1LatencyBucket
		valid   bool
	}{
		{name: "negative", elapsed: -time.Nanosecond},
		{name: "sub-millisecond", elapsed: time.Nanosecond, bucket: phase1LatencyUnderMillisecond, valid: true},
		{name: "millisecond", elapsed: time.Millisecond, bucket: phase1LatencyUnderTenMilliseconds, valid: true},
		{name: "ten-milliseconds", elapsed: 10 * time.Millisecond, bucket: phase1LatencyUnderHundredMilliseconds, valid: true},
		{name: "hundred-milliseconds", elapsed: 100 * time.Millisecond, bucket: phase1LatencyUnderSecond, valid: true},
		{name: "second", elapsed: time.Second, bucket: phase1LatencyAtLeastSecond, valid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, ok := phase1LatencyBucketFor(tt.elapsed)
			if ok != tt.valid || (ok && bucket != tt.bucket) {
				t.Fatalf("phase1LatencyBucketFor(%s) = (%d, %v), want (%d, %v)", tt.elapsed, bucket, ok, tt.bucket, tt.valid)
			}
		})
	}

	recorder := installPhase1ObservabilityForTest(t, 1)
	observePhase1DNSCache(phase1DNSCacheHit, -time.Nanosecond)
	observePhase1DNSCache(phase1DNSCacheOutcomeCount, time.Millisecond)
	observePhase1Dial(phase1DialOperationCount, phase1TransportTCP, phase1DialOutcomeSuccess)

	if got := recorder.dnsCacheCount(phase1DNSCacheHit); got != 1 {
		t.Fatalf("DNS cache count with negative latency = %d, want 1", got)
	}
	if got := recorder.dnsCacheLatencyCount(phase1DNSCacheHit, phase1LatencyUnderMillisecond); got != 0 {
		t.Fatalf("DNS cache negative-latency bucket count = %d, want 0", got)
	}
	if got := recorder.dnsCacheCount(phase1DNSCacheOutcomeCount); got != 0 {
		t.Fatalf("invalid DNS cache count = %d, want 0", got)
	}
	if got := recorder.dialCount(phase1DialOperationCount, phase1TransportTCP, phase1DialOutcomeSuccess); got != 0 {
		t.Fatalf("invalid dial count = %d, want 0", got)
	}
}

func TestPhase1TransportForNetwork(t *testing.T) {
	tests := map[string]phase1Transport{
		"tcp":     phase1TransportTCP,
		"udp":     phase1TransportUDP,
		"unknown": phase1TransportOther,
	}
	for network, want := range tests {
		if got := phase1TransportForNetwork(network); got != want {
			t.Fatalf("phase1TransportForNetwork(%q) = %d, want %d", network, got, want)
		}
	}
}
