/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

func TestActiveControlPlanePublicationHandoff(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)

	oldPlane := testControlPlaneWithDecisionShadow(3, 3)
	newPlane := testControlPlaneWithDecisionShadow(7, 7)

	oldPlane.publishActiveControlPlane()
	assertActiveDecisionShadowSampled(t, 3)

	newPlane.publishActiveControlPlane()
	assertActiveDecisionShadowSampled(t, 7)
}

func TestActiveControlPlaneStaleUnpublishKeepsSuccessor(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)

	oldPlane := testControlPlaneWithDecisionShadow(3, 3)
	newPlane := testControlPlaneWithDecisionShadow(7, 7)
	oldPlane.publishActiveControlPlane()
	newPlane.publishActiveControlPlane()

	oldPlane.unpublishActiveControlPlane()
	assertActiveDecisionShadowSampled(t, 7)

	newPlane.unpublishActiveControlPlane()
	if _, enabled := SnapshotActivePhase4DecisionShadow(); enabled {
		t.Fatal("decision shadow remains enabled after active generation unpublish")
	}
}

func testControlPlaneWithDecisionShadow(sampled, matched uint64) *ControlPlane {
	shadow := &phase4DecisionShadow{
		sampleEvery:  1,
		processState: &phase4DecisionShadowProcessState{},
	}
	shadow.sampled.Store(sampled)
	shadow.matched.Store(matched)
	return &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			decisionShadow: shadow,
		},
	}
}

func assertActiveDecisionShadowSampled(t *testing.T, want uint64) {
	t.Helper()
	snapshot, enabled := SnapshotActivePhase4DecisionShadow()
	if !enabled {
		t.Fatal("active decision shadow is disabled")
	}
	if snapshot.Sampled != want {
		t.Fatalf("active decision shadow Sampled = %d, want %d", snapshot.Sampled, want)
	}
}

func resetActiveControlPlanePublicationForTest(t *testing.T) {
	t.Helper()
	activeControlPlanePublication.mu.Lock()
	previous := activeControlPlanePublication.plane.Swap(nil)
	previousOwners := activeControlPlanePublication.owners
	activeControlPlanePublication.owners = nil
	activeControlPlanePublication.mu.Unlock()
	t.Cleanup(func() {
		activeControlPlanePublication.mu.Lock()
		activeControlPlanePublication.plane.Store(previous)
		activeControlPlanePublication.owners = previousOwners
		activeControlPlanePublication.mu.Unlock()
	})
}
