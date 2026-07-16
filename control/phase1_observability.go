/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync/atomic"
	"time"
)

// Phase 1 observations use fixed enum dimensions rather than labels. The
// recorder is nil by default, and sampling is deterministic per observation
// family so recording cannot influence routing, DNS, reload, or dial results.
type phase1ObservationKind uint8

const (
	phase1ObservationRoutingLookup phase1ObservationKind = iota
	phase1ObservationUserspaceRematch
	phase1ObservationUDPKeyProbe
	phase1ObservationDNSCache
	phase1ObservationBPFPublish
	phase1ObservationReloadDrain
	phase1ObservationDial
	phase1ObservationKindCount
)

type phase1Transport uint8

const (
	phase1TransportTCP phase1Transport = iota
	phase1TransportUDP
	phase1TransportOther
	phase1TransportCount
)

func phase1TransportForNetwork(network string) phase1Transport {
	switch network {
	case "tcp":
		return phase1TransportTCP
	case "udp":
		return phase1TransportUDP
	default:
		return phase1TransportOther
	}
}

type phase1RoutingLookupSource uint8

const (
	phase1RoutingLookupEmbedded phase1RoutingLookupSource = iota
	phase1RoutingLookupHandoff
	phase1RoutingLookupUnavailable
	phase1RoutingLookupSourceCount
)

type phase1RoutingLookupOutcome uint8

const (
	phase1RoutingLookupHit phase1RoutingLookupOutcome = iota
	phase1RoutingLookupMiss
	phase1RoutingLookupFailure
	phase1RoutingLookupOutcomeCount
)

type phase1UserspaceRematchOutcome uint8

const (
	phase1UserspaceRematchSuccess phase1UserspaceRematchOutcome = iota
	phase1UserspaceRematchFailure
	phase1UserspaceRematchOutcomeCount
)

type phase1UDPKeyProbeStage uint8

const (
	phase1UDPKeyProbePrimary phase1UDPKeyProbeStage = iota
	phase1UDPKeyProbeSibling
	phase1UDPKeyProbeFallback
	phase1UDPKeyProbeStageCount
)

type phase1UDPKeyProbeOutcome uint8

const (
	phase1UDPKeyProbeHit phase1UDPKeyProbeOutcome = iota
	phase1UDPKeyProbeMiss
	phase1UDPKeyProbeTargetMismatch
	phase1UDPKeyProbeOutcomeCount
)

type phase1DNSCacheOutcome uint8

const (
	phase1DNSCacheHit phase1DNSCacheOutcome = iota
	phase1DNSCacheMiss
	phase1DNSCacheStale
	phase1DNSCacheUnavailable
	phase1DNSCacheFailure
	phase1DNSCacheOutcomeCount
)

type phase1BPFPublishPhase uint8

const (
	phase1BPFPublishPrepare phase1BPFPublishPhase = iota
	phase1BPFPublishStage
	phase1BPFPublishPublish
	phase1BPFPublishRollback
	phase1BPFPublishPhaseCount
)

type phase1BPFPublishOutcome uint8

const (
	phase1BPFPublishSuccess phase1BPFPublishOutcome = iota
	phase1BPFPublishFailure
	phase1BPFPublishOutcomeCount
)

type phase1ReloadDrainOutcome uint8

const (
	phase1ReloadDrainCompleted phase1ReloadDrainOutcome = iota
	phase1ReloadDrainCanceled
	phase1ReloadDrainTimedOut
	phase1ReloadDrainFailed
	phase1ReloadDrainOutcomeCount
)

type phase1DialOperation uint8

const (
	phase1DialOperationSelectPrimary phase1DialOperation = iota
	phase1DialOperationSelectAlternateFamily
	phase1DialOperationConnectInitial
	phase1DialOperationConnectRetry
	phase1DialOperationCount
)

type phase1DialOutcome uint8

const (
	phase1DialOutcomeSuccess phase1DialOutcome = iota
	phase1DialOutcomeNoAlive
	phase1DialOutcomeFailure
	phase1DialOutcomeCount
)

type phase1LatencyBucket uint8

const (
	phase1LatencyUnderMillisecond phase1LatencyBucket = iota
	phase1LatencyUnderTenMilliseconds
	phase1LatencyUnderHundredMilliseconds
	phase1LatencyUnderSecond
	phase1LatencyAtLeastSecond
	phase1LatencyBucketCount
)

type phase1Observability struct {
	// sampleEvery is immutable after publication. A zero value means sample every event.
	sampleEvery    uint64
	sampleSequence [phase1ObservationKindCount]atomic.Uint64

	routingLookup      [phase1RoutingLookupSourceCount][phase1RoutingLookupOutcomeCount]atomic.Uint64
	userspaceRematch   [phase1TransportCount][phase1UserspaceRematchOutcomeCount]atomic.Uint64
	udpKeyProbe        [phase1UDPKeyProbeStageCount][phase1UDPKeyProbeOutcomeCount]atomic.Uint64
	dnsCache           [phase1DNSCacheOutcomeCount]atomic.Uint64
	dnsCacheLatency    [phase1DNSCacheOutcomeCount][phase1LatencyBucketCount]atomic.Uint64
	bpfPublish         [phase1BPFPublishPhaseCount][phase1BPFPublishOutcomeCount]atomic.Uint64
	bpfPublishLatency  [phase1BPFPublishPhaseCount][phase1BPFPublishOutcomeCount][phase1LatencyBucketCount]atomic.Uint64
	reloadDrain        [phase1ReloadDrainOutcomeCount]atomic.Uint64
	reloadDrainLatency [phase1ReloadDrainOutcomeCount][phase1LatencyBucketCount]atomic.Uint64
	dial               [phase1DialOperationCount][phase1TransportCount][phase1DialOutcomeCount]atomic.Uint64
}

var activePhase1Observability atomic.Pointer[phase1Observability]

func newPhase1Observability(sampleEvery uint64) *phase1Observability {
	return &phase1Observability{sampleEvery: sampleEvery}
}

// swapPhase1Observability is an internal test and rollout seam. Passing nil
// disables all Phase 1 observation without changing runtime decisions.
func swapPhase1Observability(recorder *phase1Observability) *phase1Observability {
	return activePhase1Observability.Swap(recorder)
}

func observePhase1RoutingLookup(source phase1RoutingLookupSource, outcome phase1RoutingLookupOutcome) {
	if source >= phase1RoutingLookupSourceCount || outcome >= phase1RoutingLookupOutcomeCount {
		return
	}
	if recorder := phase1SampledRecorder(phase1ObservationRoutingLookup); recorder != nil {
		recorder.routingLookup[source][outcome].Add(1)
	}
}

func observePhase1UserspaceRematch(transport phase1Transport, outcome phase1UserspaceRematchOutcome) {
	if transport >= phase1TransportCount || outcome >= phase1UserspaceRematchOutcomeCount {
		return
	}
	if recorder := phase1SampledRecorder(phase1ObservationUserspaceRematch); recorder != nil {
		recorder.userspaceRematch[transport][outcome].Add(1)
	}
}

func observePhase1UDPKeyProbe(stage phase1UDPKeyProbeStage, outcome phase1UDPKeyProbeOutcome) {
	if stage >= phase1UDPKeyProbeStageCount || outcome >= phase1UDPKeyProbeOutcomeCount {
		return
	}
	if recorder := phase1SampledRecorder(phase1ObservationUDPKeyProbe); recorder != nil {
		recorder.udpKeyProbe[stage][outcome].Add(1)
	}
}

func observePhase1DNSCache(outcome phase1DNSCacheOutcome, elapsed time.Duration) {
	if outcome >= phase1DNSCacheOutcomeCount {
		return
	}
	if recorder := phase1SampledRecorder(phase1ObservationDNSCache); recorder != nil {
		recorder.recordDNSCache(outcome, elapsed)
	}
}

// beginPhase1DNSCacheObservation selects a cache lookup before taking its
// timestamp so disabled and unsampled lookups do not read the clock.
func beginPhase1DNSCacheObservation() (*phase1Observability, time.Time) {
	recorder := phase1SampledRecorder(phase1ObservationDNSCache)
	if recorder == nil {
		return nil, time.Time{}
	}
	return recorder, time.Now()
}

func endPhase1DNSCacheObservation(recorder *phase1Observability, startedAt time.Time, outcome phase1DNSCacheOutcome) {
	if recorder == nil || outcome >= phase1DNSCacheOutcomeCount {
		return
	}
	if startedAt.IsZero() {
		recorder.recordDNSCache(outcome, -1)
		return
	}
	recorder.recordDNSCache(outcome, time.Since(startedAt))
}

func observePhase1BPFPublish(phase phase1BPFPublishPhase, outcome phase1BPFPublishOutcome, elapsed time.Duration) {
	if phase >= phase1BPFPublishPhaseCount || outcome >= phase1BPFPublishOutcomeCount {
		return
	}
	if recorder := phase1SampledRecorder(phase1ObservationBPFPublish); recorder != nil {
		recorder.recordBPFPublish(phase, outcome, elapsed)
	}
}

// beginPhase1BPFPublishObservation selects a publish operation before taking
// its timestamp so disabled and unsampled operations do not read the clock.
func beginPhase1BPFPublishObservation() (*phase1Observability, time.Time) {
	recorder := phase1SampledRecorder(phase1ObservationBPFPublish)
	if recorder == nil {
		return nil, time.Time{}
	}
	return recorder, time.Now()
}

func endPhase1BPFPublishObservation(recorder *phase1Observability, startedAt time.Time, phase phase1BPFPublishPhase, outcome phase1BPFPublishOutcome) {
	if recorder == nil || phase >= phase1BPFPublishPhaseCount || outcome >= phase1BPFPublishOutcomeCount {
		return
	}
	if startedAt.IsZero() {
		recorder.recordBPFPublish(phase, outcome, -1)
		return
	}
	recorder.recordBPFPublish(phase, outcome, time.Since(startedAt))
}

func observePhase1ReloadDrain(outcome phase1ReloadDrainOutcome, elapsed time.Duration) {
	if outcome >= phase1ReloadDrainOutcomeCount {
		return
	}
	if recorder := phase1SampledRecorder(phase1ObservationReloadDrain); recorder != nil {
		recorder.recordReloadDrain(outcome, elapsed)
	}
}

func observePhase1Dial(operation phase1DialOperation, transport phase1Transport, outcome phase1DialOutcome) {
	if operation >= phase1DialOperationCount || transport >= phase1TransportCount || outcome >= phase1DialOutcomeCount {
		return
	}
	if recorder := phase1SampledRecorder(phase1ObservationDial); recorder != nil {
		recorder.dial[operation][transport][outcome].Add(1)
	}
}

func (o *phase1Observability) recordDNSCache(outcome phase1DNSCacheOutcome, elapsed time.Duration) {
	if o == nil || outcome >= phase1DNSCacheOutcomeCount {
		return
	}
	o.dnsCache[outcome].Add(1)
	if bucket, ok := phase1LatencyBucketFor(elapsed); ok {
		o.dnsCacheLatency[outcome][bucket].Add(1)
	}
}

func (o *phase1Observability) recordBPFPublish(phase phase1BPFPublishPhase, outcome phase1BPFPublishOutcome, elapsed time.Duration) {
	if o == nil || phase >= phase1BPFPublishPhaseCount || outcome >= phase1BPFPublishOutcomeCount {
		return
	}
	o.bpfPublish[phase][outcome].Add(1)
	if bucket, ok := phase1LatencyBucketFor(elapsed); ok {
		o.bpfPublishLatency[phase][outcome][bucket].Add(1)
	}
}

func (o *phase1Observability) recordReloadDrain(outcome phase1ReloadDrainOutcome, elapsed time.Duration) {
	if o == nil || outcome >= phase1ReloadDrainOutcomeCount {
		return
	}
	o.reloadDrain[outcome].Add(1)
	if bucket, ok := phase1LatencyBucketFor(elapsed); ok {
		o.reloadDrainLatency[outcome][bucket].Add(1)
	}
}

func (o *phase1Observability) routingLookupCount(source phase1RoutingLookupSource, outcome phase1RoutingLookupOutcome) uint64 {
	if o == nil || source >= phase1RoutingLookupSourceCount || outcome >= phase1RoutingLookupOutcomeCount {
		return 0
	}
	return o.routingLookup[source][outcome].Load()
}

func (o *phase1Observability) userspaceRematchCount(transport phase1Transport, outcome phase1UserspaceRematchOutcome) uint64 {
	if o == nil || transport >= phase1TransportCount || outcome >= phase1UserspaceRematchOutcomeCount {
		return 0
	}
	return o.userspaceRematch[transport][outcome].Load()
}

func (o *phase1Observability) udpKeyProbeCount(stage phase1UDPKeyProbeStage, outcome phase1UDPKeyProbeOutcome) uint64 {
	if o == nil || stage >= phase1UDPKeyProbeStageCount || outcome >= phase1UDPKeyProbeOutcomeCount {
		return 0
	}
	return o.udpKeyProbe[stage][outcome].Load()
}

func (o *phase1Observability) dnsCacheCount(outcome phase1DNSCacheOutcome) uint64 {
	if o == nil || outcome >= phase1DNSCacheOutcomeCount {
		return 0
	}
	return o.dnsCache[outcome].Load()
}

func (o *phase1Observability) dnsCacheLatencyCount(outcome phase1DNSCacheOutcome, bucket phase1LatencyBucket) uint64 {
	if o == nil || outcome >= phase1DNSCacheOutcomeCount || bucket >= phase1LatencyBucketCount {
		return 0
	}
	return o.dnsCacheLatency[outcome][bucket].Load()
}

func (o *phase1Observability) bpfPublishCount(phase phase1BPFPublishPhase, outcome phase1BPFPublishOutcome) uint64 {
	if o == nil || phase >= phase1BPFPublishPhaseCount || outcome >= phase1BPFPublishOutcomeCount {
		return 0
	}
	return o.bpfPublish[phase][outcome].Load()
}

func (o *phase1Observability) bpfPublishLatencyCount(phase phase1BPFPublishPhase, outcome phase1BPFPublishOutcome, bucket phase1LatencyBucket) uint64 {
	if o == nil || phase >= phase1BPFPublishPhaseCount || outcome >= phase1BPFPublishOutcomeCount || bucket >= phase1LatencyBucketCount {
		return 0
	}
	return o.bpfPublishLatency[phase][outcome][bucket].Load()
}

func (o *phase1Observability) reloadDrainCount(outcome phase1ReloadDrainOutcome) uint64 {
	if o == nil || outcome >= phase1ReloadDrainOutcomeCount {
		return 0
	}
	return o.reloadDrain[outcome].Load()
}

func (o *phase1Observability) reloadDrainLatencyCount(outcome phase1ReloadDrainOutcome, bucket phase1LatencyBucket) uint64 {
	if o == nil || outcome >= phase1ReloadDrainOutcomeCount || bucket >= phase1LatencyBucketCount {
		return 0
	}
	return o.reloadDrainLatency[outcome][bucket].Load()
}

func (o *phase1Observability) dialCount(operation phase1DialOperation, transport phase1Transport, outcome phase1DialOutcome) uint64 {
	if o == nil || operation >= phase1DialOperationCount || transport >= phase1TransportCount || outcome >= phase1DialOutcomeCount {
		return 0
	}
	return o.dial[operation][transport][outcome].Load()
}

func phase1LatencyBucketFor(elapsed time.Duration) (phase1LatencyBucket, bool) {
	if elapsed < 0 {
		return 0, false
	}
	switch {
	case elapsed < time.Millisecond:
		return phase1LatencyUnderMillisecond, true
	case elapsed < 10*time.Millisecond:
		return phase1LatencyUnderTenMilliseconds, true
	case elapsed < 100*time.Millisecond:
		return phase1LatencyUnderHundredMilliseconds, true
	case elapsed < time.Second:
		return phase1LatencyUnderSecond, true
	default:
		return phase1LatencyAtLeastSecond, true
	}
}

func phase1SampledRecorder(kind phase1ObservationKind) *phase1Observability {
	if kind >= phase1ObservationKindCount {
		return nil
	}
	recorder := activePhase1Observability.Load()
	if recorder == nil || !recorder.shouldSample(kind) {
		return nil
	}
	return recorder
}

func (o *phase1Observability) shouldSample(kind phase1ObservationKind) bool {
	if o == nil || kind >= phase1ObservationKindCount {
		return false
	}
	every := o.sampleEvery
	if every <= 1 {
		return true
	}
	sequence := o.sampleSequence[kind].Add(1)
	return (sequence-1)%every == 0
}
