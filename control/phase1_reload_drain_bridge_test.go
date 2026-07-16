/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

func TestPhase1ReloadDrainBridgeIsDisabledByDefault(t *testing.T) {
	previous := swapPhase1Observability(nil)
	t.Cleanup(func() {
		activePhase1Observability.CompareAndSwap(nil, previous)
	})

	observation := BeginPhase1ReloadDrainObservation()
	if observation.recorder != nil || !observation.startedAt.IsZero() {
		t.Fatalf("disabled observation = %+v, want zero value", observation)
	}
	observation.End(Phase1ReloadDrainCompleted)
}

func TestPhase1ReloadDrainBridgeRecordsTerminalOutcome(t *testing.T) {
	recorder, restore := InstallPhase1ReloadDrainRecorderForTest()
	t.Cleanup(restore)

	observation := BeginPhase1ReloadDrainObservation()
	observation.End(Phase1ReloadDrainTimedOut)

	if got := recorder.Count(Phase1ReloadDrainTimedOut); got != 1 {
		t.Fatalf("timed-out drain count = %d, want 1", got)
	}

	var latencySamples uint64
	for bucket := phase1LatencyBucket(0); bucket < phase1LatencyBucketCount; bucket++ {
		latencySamples += recorder.recorder.reloadDrainLatencyCount(phase1ReloadDrainTimedOut, bucket)
	}
	if latencySamples != 1 {
		t.Fatalf("timed-out drain latency samples = %d, want 1", latencySamples)
	}
}
