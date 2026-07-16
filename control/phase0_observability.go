/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync/atomic"
	"time"
)

// Phase 0 observations intentionally use fixed enum dimensions rather than
// labels. The recorder is nil by default, so observation is disabled until an
// internal owner installs it. Recording never returns an error or influences a
// routing, DNS, or reload decision.
type phase0RoutingEpochOperation uint8

const (
	phase0RoutingEpochPrepare phase0RoutingEpochOperation = iota
	phase0RoutingEpochStage
	phase0RoutingEpochPublish
	phase0RoutingEpochRollback
	phase0RoutingEpochOperationCount
)

type phase0ObservationOutcome uint8

const (
	phase0ObservationSuccess phase0ObservationOutcome = iota
	phase0ObservationFailure
	phase0ObservationOutcomeCount
)

type phase0DNSProjectionMode uint8

const (
	phase0DNSProjectionAsync phase0DNSProjectionMode = iota
	phase0DNSProjectionReloadSync
	phase0DNSProjectionModeCount
)

type phase0DNSProjectionOutcome uint8

const (
	phase0DNSProjectionApplied phase0DNSProjectionOutcome = iota
	phase0DNSProjectionFailed
	phase0DNSProjectionStale
	phase0DNSProjectionQueueDrop
	phase0DNSProjectionOutcomeCount
)

type phase0DNSProjectionLagBucket uint8

const (
	phase0DNSProjectionLagUnderMillisecond phase0DNSProjectionLagBucket = iota
	phase0DNSProjectionLagUnderTenMilliseconds
	phase0DNSProjectionLagUnderHundredMilliseconds
	phase0DNSProjectionLagUnderSecond
	phase0DNSProjectionLagAtLeastSecond
	phase0DNSProjectionLagBucketCount
)

type phase0Observability struct {
	routingEpoch     [phase0RoutingEpochOperationCount][phase0ObservationOutcomeCount]atomic.Uint64
	dnsProjection    [phase0DNSProjectionModeCount][phase0DNSProjectionOutcomeCount]atomic.Uint64
	dnsProjectionLag [phase0DNSProjectionModeCount][phase0DNSProjectionOutcomeCount][phase0DNSProjectionLagBucketCount]atomic.Uint64
}

var activePhase0Observability atomic.Pointer[phase0Observability]

// swapPhase0Observability is an internal test and rollout seam. Passing nil
// disables all Phase 0 observation without changing any runtime decision.
func swapPhase0Observability(recorder *phase0Observability) *phase0Observability {
	return activePhase0Observability.Swap(recorder)
}

func observePhase0RoutingEpoch(operation phase0RoutingEpochOperation, outcome phase0ObservationOutcome) {
	if recorder := activePhase0Observability.Load(); recorder != nil {
		recorder.recordRoutingEpoch(operation, outcome)
	}
}

func beginPhase0DNSProjectionObservation() (*phase0Observability, time.Time) {
	recorder := activePhase0Observability.Load()
	if recorder == nil {
		return nil, time.Time{}
	}
	return recorder, time.Now()
}

func (o *phase0Observability) recordRoutingEpoch(operation phase0RoutingEpochOperation, outcome phase0ObservationOutcome) {
	if o == nil || operation >= phase0RoutingEpochOperationCount || outcome >= phase0ObservationOutcomeCount {
		return
	}
	o.routingEpoch[operation][outcome].Add(1)
}

func (o *phase0Observability) recordDNSProjection(mode phase0DNSProjectionMode, outcome phase0DNSProjectionOutcome, startedAt time.Time) {
	if o == nil || mode >= phase0DNSProjectionModeCount || outcome >= phase0DNSProjectionOutcomeCount {
		return
	}
	o.dnsProjection[mode][outcome].Add(1)

	if startedAt.IsZero() || (outcome != phase0DNSProjectionApplied && outcome != phase0DNSProjectionFailed) {
		return
	}
	if bucket, ok := phase0DNSProjectionLagBucketFor(time.Since(startedAt)); ok {
		o.dnsProjectionLag[mode][outcome][bucket].Add(1)
	}
}

func (o *phase0Observability) routingEpochCount(operation phase0RoutingEpochOperation, outcome phase0ObservationOutcome) uint64 {
	if o == nil || operation >= phase0RoutingEpochOperationCount || outcome >= phase0ObservationOutcomeCount {
		return 0
	}
	return o.routingEpoch[operation][outcome].Load()
}

func (o *phase0Observability) dnsProjectionCount(mode phase0DNSProjectionMode, outcome phase0DNSProjectionOutcome) uint64 {
	if o == nil || mode >= phase0DNSProjectionModeCount || outcome >= phase0DNSProjectionOutcomeCount {
		return 0
	}
	return o.dnsProjection[mode][outcome].Load()
}

func (o *phase0Observability) dnsProjectionLagCount(mode phase0DNSProjectionMode, outcome phase0DNSProjectionOutcome, bucket phase0DNSProjectionLagBucket) uint64 {
	if o == nil || mode >= phase0DNSProjectionModeCount || outcome >= phase0DNSProjectionOutcomeCount || bucket >= phase0DNSProjectionLagBucketCount {
		return 0
	}
	return o.dnsProjectionLag[mode][outcome][bucket].Load()
}

func phase0DNSProjectionLagBucketFor(elapsed time.Duration) (phase0DNSProjectionLagBucket, bool) {
	if elapsed < 0 {
		return 0, false
	}
	switch {
	case elapsed < time.Millisecond:
		return phase0DNSProjectionLagUnderMillisecond, true
	case elapsed < 10*time.Millisecond:
		return phase0DNSProjectionLagUnderTenMilliseconds, true
	case elapsed < 100*time.Millisecond:
		return phase0DNSProjectionLagUnderHundredMilliseconds, true
	case elapsed < time.Second:
		return phase0DNSProjectionLagUnderSecond, true
	default:
		return phase0DNSProjectionLagAtLeastSecond, true
	}
}
