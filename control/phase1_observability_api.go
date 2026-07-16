/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import stderrors "errors"

var (
	// ErrPhase1ObservabilityInvalidSampleEvery reports an invalid sampling interval.
	ErrPhase1ObservabilityInvalidSampleEvery = stderrors.New("phase 1 observability sample interval must be greater than zero")
	// ErrPhase1ObservabilityAlreadyEnabled reports an attempt to replace an active recorder.
	ErrPhase1ObservabilityAlreadyEnabled = stderrors.New("phase 1 observability is already enabled")
)

const (
	// Phase1RoutingLookupSourceCount is the number of routing lookup sources.
	Phase1RoutingLookupSourceCount = int(phase1RoutingLookupSourceCount)
	// Phase1RoutingLookupOutcomeCount is the number of routing lookup outcomes.
	Phase1RoutingLookupOutcomeCount = int(phase1RoutingLookupOutcomeCount)
	// Phase1TransportCount is the number of transport categories.
	Phase1TransportCount = int(phase1TransportCount)
	// Phase1UserspaceRematchOutcomeCount is the number of rematch outcomes.
	Phase1UserspaceRematchOutcomeCount = int(phase1UserspaceRematchOutcomeCount)
	// Phase1UDPKeyProbeStageCount is the number of UDP key probe stages.
	Phase1UDPKeyProbeStageCount = int(phase1UDPKeyProbeStageCount)
	// Phase1UDPKeyProbeOutcomeCount is the number of UDP key probe outcomes.
	Phase1UDPKeyProbeOutcomeCount = int(phase1UDPKeyProbeOutcomeCount)
	// Phase1DNSCacheOutcomeCount is the number of DNS cache outcomes.
	Phase1DNSCacheOutcomeCount = int(phase1DNSCacheOutcomeCount)
	// Phase1BPFPublishPhaseCount is the number of BPF publication phases.
	Phase1BPFPublishPhaseCount = int(phase1BPFPublishPhaseCount)
	// Phase1BPFPublishOutcomeCount is the number of BPF publication outcomes.
	Phase1BPFPublishOutcomeCount = int(phase1BPFPublishOutcomeCount)
	// Phase1ReloadDrainOutcomeCount is the number of reload drain outcomes.
	Phase1ReloadDrainOutcomeCount = int(phase1ReloadDrainOutcomeCount)
	// Phase1DialOperationCount is the number of dial operations.
	Phase1DialOperationCount = int(phase1DialOperationCount)
	// Phase1DialOutcomeCount is the number of dial outcomes.
	Phase1DialOutcomeCount = int(phase1DialOutcomeCount)
	// Phase1LatencyBucketCount is the number of fixed latency buckets.
	Phase1LatencyBucketCount = int(phase1LatencyBucketCount)
)

const (
	// Phase1RoutingLookupEmbedded indexes embedded connection-state lookups.
	Phase1RoutingLookupEmbedded = int(phase1RoutingLookupEmbedded)
	// Phase1RoutingLookupHandoff indexes routing handoff lookups.
	Phase1RoutingLookupHandoff = int(phase1RoutingLookupHandoff)
	// Phase1RoutingLookupUnavailable indexes unavailable routing lookups.
	Phase1RoutingLookupUnavailable = int(phase1RoutingLookupUnavailable)

	// Phase1RoutingLookupHit indexes a successful routing lookup.
	Phase1RoutingLookupHit = int(phase1RoutingLookupHit)
	// Phase1RoutingLookupMiss indexes a missing routing lookup.
	Phase1RoutingLookupMiss = int(phase1RoutingLookupMiss)
	// Phase1RoutingLookupFailure indexes a failed routing lookup.
	Phase1RoutingLookupFailure = int(phase1RoutingLookupFailure)

	// Phase1TransportTCP indexes TCP observations.
	Phase1TransportTCP = int(phase1TransportTCP)
	// Phase1TransportUDP indexes UDP observations.
	Phase1TransportUDP = int(phase1TransportUDP)
	// Phase1TransportOther indexes non-TCP/UDP observations.
	Phase1TransportOther = int(phase1TransportOther)

	// Phase1UserspaceRematchSuccess indexes successful userspace rematches.
	Phase1UserspaceRematchSuccess = int(phase1UserspaceRematchSuccess)
	// Phase1UserspaceRematchFailure indexes failed userspace rematches.
	Phase1UserspaceRematchFailure = int(phase1UserspaceRematchFailure)

	// Phase1UDPKeyProbePrimary indexes a primary UDP endpoint lookup.
	Phase1UDPKeyProbePrimary = int(phase1UDPKeyProbePrimary)
	// Phase1UDPKeyProbeSibling indexes a sibling UDP endpoint lookup.
	Phase1UDPKeyProbeSibling = int(phase1UDPKeyProbeSibling)
	// Phase1UDPKeyProbeFallback indexes a fallback UDP endpoint lookup.
	Phase1UDPKeyProbeFallback = int(phase1UDPKeyProbeFallback)

	// Phase1UDPKeyProbeHit indexes a successful UDP key probe.
	Phase1UDPKeyProbeHit = int(phase1UDPKeyProbeHit)
	// Phase1UDPKeyProbeMiss indexes a missing UDP key probe.
	Phase1UDPKeyProbeMiss = int(phase1UDPKeyProbeMiss)
	// Phase1UDPKeyProbeTargetMismatch indexes a target-mismatched UDP key probe.
	Phase1UDPKeyProbeTargetMismatch = int(phase1UDPKeyProbeTargetMismatch)

	// Phase1DNSCacheHit indexes a fresh DNS cache hit.
	Phase1DNSCacheHit = int(phase1DNSCacheHit)
	// Phase1DNSCacheMiss indexes a DNS cache miss.
	Phase1DNSCacheMiss = int(phase1DNSCacheMiss)
	// Phase1DNSCacheStale indexes a stale DNS cache hit.
	Phase1DNSCacheStale = int(phase1DNSCacheStale)
	// Phase1DNSCacheUnavailable indexes an unavailable DNS cache.
	Phase1DNSCacheUnavailable = int(phase1DNSCacheUnavailable)
	// Phase1DNSCacheFailure indexes a failed DNS cache lookup.
	Phase1DNSCacheFailure = int(phase1DNSCacheFailure)

	// Phase1BPFPublishPrepare indexes BPF epoch preparation.
	Phase1BPFPublishPrepare = int(phase1BPFPublishPrepare)
	// Phase1BPFPublishStage indexes BPF epoch staging.
	Phase1BPFPublishStage = int(phase1BPFPublishStage)
	// Phase1BPFPublishPublish indexes BPF epoch publication.
	Phase1BPFPublishPublish = int(phase1BPFPublishPublish)
	// Phase1BPFPublishRollback indexes BPF epoch rollback.
	Phase1BPFPublishRollback = int(phase1BPFPublishRollback)

	// Phase1BPFPublishSuccess indexes a successful BPF epoch operation.
	Phase1BPFPublishSuccess = int(phase1BPFPublishSuccess)
	// Phase1BPFPublishFailure indexes a failed BPF epoch operation.
	Phase1BPFPublishFailure = int(phase1BPFPublishFailure)

	// Phase1DialOperationSelectPrimary indexes primary dialer selection.
	Phase1DialOperationSelectPrimary = int(phase1DialOperationSelectPrimary)
	// Phase1DialOperationSelectAlternateFamily indexes alternate-family dialer selection.
	Phase1DialOperationSelectAlternateFamily = int(phase1DialOperationSelectAlternateFamily)
	// Phase1DialOperationConnectInitial indexes initial dial attempts.
	Phase1DialOperationConnectInitial = int(phase1DialOperationConnectInitial)
	// Phase1DialOperationConnectRetry indexes retry dial attempts.
	Phase1DialOperationConnectRetry = int(phase1DialOperationConnectRetry)

	// Phase1DialOutcomeSuccess indexes successful dial operations.
	Phase1DialOutcomeSuccess = int(phase1DialOutcomeSuccess)
	// Phase1DialOutcomeNoAlive indexes dialer selection with no healthy dialer.
	Phase1DialOutcomeNoAlive = int(phase1DialOutcomeNoAlive)
	// Phase1DialOutcomeFailure indexes failed dial operations.
	Phase1DialOutcomeFailure = int(phase1DialOutcomeFailure)

	// Phase1LatencyUnderMillisecond indexes latencies below one millisecond.
	Phase1LatencyUnderMillisecond = int(phase1LatencyUnderMillisecond)
	// Phase1LatencyUnderTenMilliseconds indexes latencies below ten milliseconds.
	Phase1LatencyUnderTenMilliseconds = int(phase1LatencyUnderTenMilliseconds)
	// Phase1LatencyUnderHundredMilliseconds indexes latencies below one hundred milliseconds.
	Phase1LatencyUnderHundredMilliseconds = int(phase1LatencyUnderHundredMilliseconds)
	// Phase1LatencyUnderSecond indexes latencies below one second.
	Phase1LatencyUnderSecond = int(phase1LatencyUnderSecond)
	// Phase1LatencyAtLeastSecond indexes latencies of at least one second.
	Phase1LatencyAtLeastSecond = int(phase1LatencyAtLeastSecond)
)

// Phase1ObservabilitySnapshot is a value-only copy of the active fixed-cardinality
// Phase 1 counters. Its arrays use the matching exported Phase1* constants as
// indexes, and mutating a returned snapshot cannot affect the active recorder.
type Phase1ObservabilitySnapshot struct {
	SampleEvery uint64

	RoutingLookup      [Phase1RoutingLookupSourceCount][Phase1RoutingLookupOutcomeCount]uint64
	UserspaceRematch   [Phase1TransportCount][Phase1UserspaceRematchOutcomeCount]uint64
	UDPKeyProbe        [Phase1UDPKeyProbeStageCount][Phase1UDPKeyProbeOutcomeCount]uint64
	DNSCache           [Phase1DNSCacheOutcomeCount]uint64
	DNSCacheLatency    [Phase1DNSCacheOutcomeCount][Phase1LatencyBucketCount]uint64
	BPFPublish         [Phase1BPFPublishPhaseCount][Phase1BPFPublishOutcomeCount]uint64
	BPFPublishLatency  [Phase1BPFPublishPhaseCount][Phase1BPFPublishOutcomeCount][Phase1LatencyBucketCount]uint64
	ReloadDrain        [Phase1ReloadDrainOutcomeCount]uint64
	ReloadDrainLatency [Phase1ReloadDrainOutcomeCount][Phase1LatencyBucketCount]uint64
	Dial               [Phase1DialOperationCount][Phase1TransportCount][Phase1DialOutcomeCount]uint64
}

// Phase1ObservabilityHandle owns one process-wide Phase 1 recorder.
type Phase1ObservabilityHandle struct {
	recorder *phase1Observability
}

// EnablePhase1Observability installs a process-wide sampled recorder.
// sampleEvery must be positive: one records every observation and values above
// one record every Nth observation independently for each observation family.
func EnablePhase1Observability(sampleEvery uint64) (*Phase1ObservabilityHandle, error) {
	if sampleEvery == 0 {
		return nil, ErrPhase1ObservabilityInvalidSampleEvery
	}

	recorder := newPhase1Observability(sampleEvery)
	if !activePhase1Observability.CompareAndSwap(nil, recorder) {
		return nil, ErrPhase1ObservabilityAlreadyEnabled
	}
	return &Phase1ObservabilityHandle{recorder: recorder}, nil
}

// DisablePhase1Observability disables only the recorder owned by handle.
// It returns false when another owner has replaced it or it was already disabled.
func DisablePhase1Observability(handle *Phase1ObservabilityHandle) bool {
	if handle == nil || handle.recorder == nil {
		return false
	}
	return activePhase1Observability.CompareAndSwap(handle.recorder, nil)
}

// Disable disables only the recorder owned by this handle.
func (h *Phase1ObservabilityHandle) Disable() bool {
	return DisablePhase1Observability(h)
}

// SnapshotPhase1Observability returns a value-only snapshot of the active
// recorder. The returned boolean is false when observability is disabled.
func SnapshotPhase1Observability() (Phase1ObservabilitySnapshot, bool) {
	recorder := activePhase1Observability.Load()
	if recorder == nil {
		return Phase1ObservabilitySnapshot{}, false
	}
	return recorder.snapshot(), true
}

func (o *phase1Observability) snapshot() Phase1ObservabilitySnapshot {
	if o == nil {
		return Phase1ObservabilitySnapshot{}
	}

	snapshot := Phase1ObservabilitySnapshot{SampleEvery: o.sampleEvery}
	for source := phase1RoutingLookupSource(0); source < phase1RoutingLookupSourceCount; source++ {
		for outcome := phase1RoutingLookupOutcome(0); outcome < phase1RoutingLookupOutcomeCount; outcome++ {
			snapshot.RoutingLookup[source][outcome] = o.routingLookup[source][outcome].Load()
		}
	}
	for transport := phase1Transport(0); transport < phase1TransportCount; transport++ {
		for outcome := phase1UserspaceRematchOutcome(0); outcome < phase1UserspaceRematchOutcomeCount; outcome++ {
			snapshot.UserspaceRematch[transport][outcome] = o.userspaceRematch[transport][outcome].Load()
		}
	}
	for stage := phase1UDPKeyProbeStage(0); stage < phase1UDPKeyProbeStageCount; stage++ {
		for outcome := phase1UDPKeyProbeOutcome(0); outcome < phase1UDPKeyProbeOutcomeCount; outcome++ {
			snapshot.UDPKeyProbe[stage][outcome] = o.udpKeyProbe[stage][outcome].Load()
		}
	}
	for outcome := phase1DNSCacheOutcome(0); outcome < phase1DNSCacheOutcomeCount; outcome++ {
		snapshot.DNSCache[outcome] = o.dnsCache[outcome].Load()
		for bucket := phase1LatencyBucket(0); bucket < phase1LatencyBucketCount; bucket++ {
			snapshot.DNSCacheLatency[outcome][bucket] = o.dnsCacheLatency[outcome][bucket].Load()
		}
	}
	for phase := phase1BPFPublishPhase(0); phase < phase1BPFPublishPhaseCount; phase++ {
		for outcome := phase1BPFPublishOutcome(0); outcome < phase1BPFPublishOutcomeCount; outcome++ {
			snapshot.BPFPublish[phase][outcome] = o.bpfPublish[phase][outcome].Load()
			for bucket := phase1LatencyBucket(0); bucket < phase1LatencyBucketCount; bucket++ {
				snapshot.BPFPublishLatency[phase][outcome][bucket] = o.bpfPublishLatency[phase][outcome][bucket].Load()
			}
		}
	}
	for outcome := phase1ReloadDrainOutcome(0); outcome < phase1ReloadDrainOutcomeCount; outcome++ {
		snapshot.ReloadDrain[outcome] = o.reloadDrain[outcome].Load()
		for bucket := phase1LatencyBucket(0); bucket < phase1LatencyBucketCount; bucket++ {
			snapshot.ReloadDrainLatency[outcome][bucket] = o.reloadDrainLatency[outcome][bucket].Load()
		}
	}
	for operation := phase1DialOperation(0); operation < phase1DialOperationCount; operation++ {
		for transport := phase1Transport(0); transport < phase1TransportCount; transport++ {
			for outcome := phase1DialOutcome(0); outcome < phase1DialOutcomeCount; outcome++ {
				snapshot.Dial[operation][transport][outcome] = o.dial[operation][transport][outcome].Load()
			}
		}
	}
	return snapshot
}
