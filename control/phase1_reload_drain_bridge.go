/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "time"

// Phase1ReloadDrainOutcome is the fixed outcome vocabulary for a control-plane
// retirement drain.
type Phase1ReloadDrainOutcome uint8

const (
	// Phase1ReloadDrainCompleted records a graceful drain or a successful
	// immediate retirement.
	Phase1ReloadDrainCompleted Phase1ReloadDrainOutcome = iota
	// Phase1ReloadDrainCanceled records a drain interrupted by its context.
	Phase1ReloadDrainCanceled
	// Phase1ReloadDrainTimedOut records a drain that exceeded its budget.
	Phase1ReloadDrainTimedOut
	// Phase1ReloadDrainFailed records an ignored retirement abort error.
	Phase1ReloadDrainFailed
)

// Phase1ReloadDrainObservation is an opaque, zero-allocation observation
// handle when Phase 1 observability is disabled or the operation is unsampled.
type Phase1ReloadDrainObservation struct {
	recorder  *phase1Observability
	startedAt time.Time
}

// BeginPhase1ReloadDrainObservation starts a sampled reload-drain observation.
// Its zero-value result is a no-op, so ordinary runtime behavior remains
// unchanged while no recorder is installed.
func BeginPhase1ReloadDrainObservation() Phase1ReloadDrainObservation {
	recorder := phase1SampledRecorder(phase1ObservationReloadDrain)
	if recorder == nil {
		return Phase1ReloadDrainObservation{}
	}
	return Phase1ReloadDrainObservation{
		recorder:  recorder,
		startedAt: time.Now(),
	}
}

// End records the terminal reload-drain outcome for this observation.
func (o Phase1ReloadDrainObservation) End(outcome Phase1ReloadDrainOutcome) {
	internalOutcome, ok := phase1ReloadDrainOutcomeFromBridge(outcome)
	if !ok || o.recorder == nil {
		return
	}
	if o.startedAt.IsZero() {
		o.recorder.recordReloadDrain(internalOutcome, -1)
		return
	}
	o.recorder.recordReloadDrain(internalOutcome, time.Since(o.startedAt))
}

// Phase1ReloadDrainTestRecorder exposes only reload-drain counts for callers
// outside this package that need to verify the no-op bridge in focused tests.
type Phase1ReloadDrainTestRecorder struct {
	recorder *phase1Observability
}

// InstallPhase1ReloadDrainRecorderForTest installs an all-sampled recorder and
// returns a restore function. It is intended only for tests; normal runtime
// leaves Phase 1 observability disabled.
func InstallPhase1ReloadDrainRecorderForTest() (*Phase1ReloadDrainTestRecorder, func()) {
	recorder := newPhase1Observability(1)
	previous := swapPhase1Observability(recorder)
	return &Phase1ReloadDrainTestRecorder{recorder: recorder}, func() {
		activePhase1Observability.CompareAndSwap(recorder, previous)
	}
}

// Count returns the recorded count for one terminal reload-drain outcome.
func (r *Phase1ReloadDrainTestRecorder) Count(outcome Phase1ReloadDrainOutcome) uint64 {
	internalOutcome, ok := phase1ReloadDrainOutcomeFromBridge(outcome)
	if !ok || r == nil {
		return 0
	}
	return r.recorder.reloadDrainCount(internalOutcome)
}

func phase1ReloadDrainOutcomeFromBridge(outcome Phase1ReloadDrainOutcome) (phase1ReloadDrainOutcome, bool) {
	switch outcome {
	case Phase1ReloadDrainCompleted:
		return phase1ReloadDrainCompleted, true
	case Phase1ReloadDrainCanceled:
		return phase1ReloadDrainCanceled, true
	case Phase1ReloadDrainTimedOut:
		return phase1ReloadDrainTimedOut, true
	case Phase1ReloadDrainFailed:
		return phase1ReloadDrainFailed, true
	default:
		return 0, false
	}
}
