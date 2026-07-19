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
	handle, err := EnableSemanticRefactorFeatures(SemanticRefactorFeatureCompiledPolicy, SemanticRefactorFeatureDNSResolver)
	if err != nil {
		t.Fatalf("EnableSemanticRefactorFeatures() error = %v", err)
	}
	t.Cleanup(handle.Disable)
	if got := semanticRefactorFeatureGateSnapshot(); !got.CompiledPolicy || got.RoutingEpoch || !got.DNSResolver || got.UDPOrderedDispatcher || got.UDPReplyDispatcher {
		t.Fatalf("semanticRefactorFeatureGateSnapshot() = %+v, want compiled policy and DNS resolver", got)
	}
	if !handle.Enabled(SemanticRefactorFeatureCompiledPolicy) || handle.Enabled(SemanticRefactorFeatureRoutingEpoch) || !handle.Enabled(SemanticRefactorFeatureDNSResolver) || handle.Enabled(SemanticRefactorFeatureUDPOrderedDispatcher) || handle.Enabled(SemanticRefactorFeatureUDPReplyDispatcher) || handle.Enabled("unknown") {
		t.Fatal("SemanticRefactorFeatureGateHandle.Enabled() did not report its owned features")
	}
	if _, err := EnableSemanticRefactorFeatures(SemanticRefactorFeatureRoutingEpoch); !stderrors.Is(err, ErrSemanticRefactorFeatureAlreadyEnabled) {
		t.Fatalf("second EnableSemanticRefactorFeatures() error = %v, want ownership error", err)
	}
	handle.Disable()
	if handle.Enabled(SemanticRefactorFeatureCompiledPolicy) {
		t.Fatal("SemanticRefactorFeatureGateHandle.Enabled() = true after Disable()")
	}
	if got := semanticRefactorFeatureGateSnapshot(); got != (SemanticRefactorFeatureSet{}) {
		t.Fatalf("feature snapshot after Disable() = %+v, want all disabled", got)
	}
}

func TestSemanticRefactorFeatureGateGenerationSnapshotSurvivesOwnerDisable(t *testing.T) {
	handle, err := EnableSemanticRefactorFeatures(
		SemanticRefactorFeatureCompiledPolicy,
		SemanticRefactorFeatureRoutingEpoch,
		SemanticRefactorFeatureDNSResolver,
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
		CompiledPolicy:       true,
		RoutingEpoch:         true,
		DNSResolver:          true,
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
		udpOrderedDispatcher:     ordered,
		udpReplyDispatcher:       reply,
	}
	if option := plane.dnsControllerOption(); option == nil || !option.UseResolvePipeline {
		t.Fatalf("captured generation DNS option = %+v, want resolver pipeline enabled", option)
	}
	if err := plane.Close(); err != nil {
		t.Fatalf("captured generation ControlPlane.Close() error = %v", err)
	}
}

func TestParseSemanticRefactorFeature(t *testing.T) {
	for _, feature := range []SemanticRefactorFeature{
		SemanticRefactorFeatureCompiledPolicy,
		SemanticRefactorFeatureRoutingEpoch,
		SemanticRefactorFeatureDNSResolver,
		SemanticRefactorFeatureUDPOrderedDispatcher,
		SemanticRefactorFeatureUDPReplyDispatcher,
	} {
		got, err := ParseSemanticRefactorFeature(string(feature))
		if err != nil || got != feature {
			t.Fatalf("ParseSemanticRefactorFeature(%q) = (%q, %v), want (%q, nil)", feature, got, err, feature)
		}
	}
	if _, err := ParseSemanticRefactorFeature("unknown"); err == nil {
		t.Fatal("ParseSemanticRefactorFeature(unknown) error = nil")
	}
}

func TestDnsControllerOptionUsesGenerationFeatureGate(t *testing.T) {
	legacy := (&ControlPlane{}).dnsControllerOption()
	if legacy == nil || legacy.UseResolvePipeline {
		t.Fatalf("legacy DNS controller option = %+v, want Resolve pipeline disabled", legacy)
	}
	refactored := (&ControlPlane{
		semanticRefactorFeatures: SemanticRefactorFeatureSet{DNSResolver: true},
	}).dnsControllerOption()
	if refactored == nil || !refactored.UseResolvePipeline {
		t.Fatalf("refactored DNS controller option = %+v, want Resolve pipeline enabled", refactored)
	}
}

func TestFullPolicySnapshotRequirements(t *testing.T) {
	shadow := &phase4DecisionShadowSetting{sampleEvery: 1}
	for _, tc := range []struct {
		name     string
		features SemanticRefactorFeatureSet
		shadow   *phase4DecisionShadowSetting
		want     bool
	}{
		{name: "legacy"},
		{name: "routing epoch identity only", features: SemanticRefactorFeatureSet{RoutingEpoch: true}},
		{name: "unrelated features", features: SemanticRefactorFeatureSet{DNSResolver: true, UDPOrderedDispatcher: true, UDPReplyDispatcher: true}},
		{name: "compiled policy", features: SemanticRefactorFeatureSet{CompiledPolicy: true}, want: true},
		{name: "decision shadow", shadow: shadow, want: true},
		{name: "compiled policy and decision shadow", features: SemanticRefactorFeatureSet{CompiledPolicy: true}, shadow: shadow, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := requiresFullPolicySnapshot(tc.features, tc.shadow); got != tc.want {
				t.Fatalf("requiresFullPolicySnapshot() = %v, want %v", got, tc.want)
			}
		})
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
