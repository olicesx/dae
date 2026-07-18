/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"

	"github.com/daeuniverse/dae/control"
)

func TestSemanticRefactorFeaturesFromValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		present bool
		want    []control.SemanticRefactorFeature
		enabled bool
		wantErr bool
	}{
		{name: "unset"},
		{name: "empty", present: true},
		{name: "one", value: "compiled-policy", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureCompiledPolicy}, enabled: true},
		{name: "udp ordered dispatcher", value: "udp-ordered-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureUDPOrderedDispatcher}, enabled: true},
		{name: "udp reply dispatcher", value: "udp-reply-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureUDPReplyDispatcher}, enabled: true},
		{name: "multiple", value: "compiled-policy,dns-resolver", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureCompiledPolicy, control.SemanticRefactorFeatureDNSResolver}, enabled: true},
		{name: "multiple including udp ordered dispatcher", value: "compiled-policy,udp-ordered-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureCompiledPolicy, control.SemanticRefactorFeatureUDPOrderedDispatcher}, enabled: true},
		{name: "multiple including udp reply dispatcher", value: "compiled-policy,udp-reply-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureCompiledPolicy, control.SemanticRefactorFeatureUDPReplyDispatcher}, enabled: true},
		{name: "unknown", value: "unknown", present: true, wantErr: true},
		{name: "duplicate", value: "routing-epoch,routing-epoch", present: true, wantErr: true},
		{name: "whitespace", value: "compiled-policy, dns-resolver", present: true, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, enabled, err := semanticRefactorFeaturesFromValue(tc.value, tc.present)
			if (err != nil) != tc.wantErr {
				t.Fatalf("semanticRefactorFeaturesFromValue(%q, %v) error = %v, want error=%v", tc.value, tc.present, err, tc.wantErr)
			}
			if enabled != tc.enabled || len(got) != len(tc.want) {
				t.Fatalf("semanticRefactorFeaturesFromValue(%q, %v) = (%v, %v), want (%v, %v)", tc.value, tc.present, got, enabled, tc.want, tc.enabled)
			}
			for index := range got {
				if got[index] != tc.want[index] {
					t.Fatalf("feature[%d] = %q, want %q", index, got[index], tc.want[index])
				}
			}
		})
	}
}

func TestShouldUseStagedHotHandoff(t *testing.T) {
	tests := []struct {
		name                string
		freshDatapathReload bool
		listenerPresent     bool
		want                bool
	}{
		{name: "same port reload", listenerPresent: true, want: true},
		{name: "fresh datapath reload", freshDatapathReload: true, listenerPresent: true},
		{name: "no listener"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := shouldUseStagedHotHandoff(tc.freshDatapathReload, tc.listenerPresent)
			if got != tc.want {
				t.Fatalf("shouldUseStagedHotHandoff(%v, %v) = %v, want %v", tc.freshDatapathReload, tc.listenerPresent, got, tc.want)
			}
		})
	}
}
