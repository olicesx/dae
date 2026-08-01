/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"testing"
)

func TestSemanticRefactorFeatureGateDefaultsDisabled(t *testing.T) {
	if got := semanticRefactorFeatureGateSnapshot(); got != (SemanticRefactorFeatureSet{}) {
		t.Fatalf("semanticRefactorFeatureGateSnapshot() = %+v, want all disabled", got)
	}
}

func TestSemanticRefactorFeatureGateOwnership(t *testing.T) {
	handle, err := EnableSemanticRefactorFeatures(SemanticRefactorFeatureUDPOrderedDispatcher)
	if err != nil {
		t.Fatalf("EnableSemanticRefactorFeatures() error = %v", err)
	}
	t.Cleanup(handle.Disable)
	if got := semanticRefactorFeatureGateSnapshot(); !got.UDPOrderedDispatcher || got.UDPReplyDispatcher {
		t.Fatalf("semanticRefactorFeatureGateSnapshot() = %+v, want only the ordered dispatcher", got)
	}
	if !handle.Enabled(SemanticRefactorFeatureUDPOrderedDispatcher) ||
		handle.Enabled(SemanticRefactorFeatureUDPReplyDispatcher) ||
		handle.Enabled("unknown") {
		t.Fatal("SemanticRefactorFeatureGateHandle.Enabled() did not report its owned features")
	}
	if _, err := EnableSemanticRefactorFeatures(SemanticRefactorFeatureUDPReplyDispatcher); !stderrors.Is(err, ErrSemanticRefactorFeatureAlreadyEnabled) {
		t.Fatalf("second EnableSemanticRefactorFeatures() error = %v, want ownership error", err)
	}
	handle.Disable()
	if handle.Enabled(SemanticRefactorFeatureUDPOrderedDispatcher) {
		t.Fatal("SemanticRefactorFeatureGateHandle.Enabled() = true after Disable()")
	}
	if got := semanticRefactorFeatureGateSnapshot(); got != (SemanticRefactorFeatureSet{}) {
		t.Fatalf("feature snapshot after Disable() = %+v, want all disabled", got)
	}
}

func TestSemanticRefactorFeatureGateGenerationSnapshotSurvivesOwnerDisable(t *testing.T) {
	handle, err := EnableSemanticRefactorFeatures(
		SemanticRefactorFeatureUDPOrderedDispatcher,
		SemanticRefactorFeatureUDPReplyDispatcher,
	)
	if err != nil {
		t.Fatalf("EnableSemanticRefactorFeatures() error = %v", err)
	}
	features := semanticRefactorFeatureGateSnapshot()
	handle.Disable()

	if got := semanticRefactorFeatureGateSnapshot(); got != (SemanticRefactorFeatureSet{}) {
		t.Fatalf("global feature snapshot after owner disable = %+v, want all disabled", got)
	}
	want := SemanticRefactorFeatureSet{
		UDPOrderedDispatcher: true,
		UDPReplyDispatcher:   true,
	}
	if features != want {
		t.Fatalf("captured generation features = %+v, want %+v", features, want)
	}

	// A generation owns a value copy, so its enabled paths remain available
	// while a subsequent process owner is free to install a different gate.
	ordered := newUDPOrderedDispatcherForFeatures(features)
	reply := newUDPReplyDispatcherForFeatures(features)
	if ordered == nil || reply == nil {
		t.Fatalf("captured generation dispatchers = (%p, %p), want both enabled", ordered, reply)
	}
	plane := &ControlPlane{
		semanticRefactorFeatures: features,
		controlPlaneUDPRuntime: controlPlaneUDPRuntime{
			udpOrderedDispatcher: ordered,
			udpReplyDispatcher:   reply,
		},
	}
	if err := plane.Close(); err != nil {
		t.Fatalf("captured generation ControlPlane.Close() error = %v", err)
	}
}

func TestParseSemanticRefactorFeature(t *testing.T) {
	for _, feature := range []SemanticRefactorFeature{
		SemanticRefactorFeatureRoutingEpoch,
		SemanticRefactorFeatureUDPOrderedDispatcher,
		SemanticRefactorFeatureUDPReplyDispatcher,
	} {
		got, err := ParseSemanticRefactorFeature(string(feature))
		if err != nil || got != feature {
			t.Fatalf("ParseSemanticRefactorFeature(%q) = (%q, %v), want (%q, nil)", feature, got, err, feature)
		}
	}
	// Names of migration paths that have since been collapsed into the single
	// production path must not silently parse into a no-op gate.
	for _, retired := range []string{"compiled-policy", "dns-resolver", "unknown"} {
		if _, err := ParseSemanticRefactorFeature(retired); err == nil {
			t.Fatalf("ParseSemanticRefactorFeature(%q) error = nil, want rejection", retired)
		}
	}
}

func TestUDPOrderedDispatcherUsesGenerationFeatureGate(t *testing.T) {
	legacy := newUDPOrderedDispatcherForFeatures(SemanticRefactorFeatureSet{})
	if legacy != nil {
		t.Fatal("legacy feature set created a UDP ordered dispatcher")
	}

	refactored := newUDPOrderedDispatcherForFeatures(SemanticRefactorFeatureSet{UDPOrderedDispatcher: true})
	if refactored == nil {
		t.Fatal("UDP ordered dispatcher feature did not create a dispatcher")
	}
	t.Cleanup(func() {
		refactored.close()
		refactored.wait()
	})
}

func TestUDPReplyDispatcherUsesGenerationFeatureGate(t *testing.T) {
	legacy := newUDPReplyDispatcherForFeatures(SemanticRefactorFeatureSet{})
	if legacy != nil {
		t.Fatal("legacy feature set created a UDP reply dispatcher")
	}

	refactored := newUDPReplyDispatcherForFeatures(SemanticRefactorFeatureSet{UDPReplyDispatcher: true})
	if refactored == nil {
		t.Fatal("UDP reply dispatcher feature did not create a dispatcher")
	}
	t.Cleanup(func() {
		refactored.close()
		refactored.wait()
	})
}
