/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"

	"github.com/daeuniverse/dae/control"
)

// RoutingEpoch is enabled by default for zero-loss reload. Adding a feature
// here means it carries production traffic for every user by default.
func TestDefaultSemanticRefactorFeatures(t *testing.T) {
	got := defaultSemanticRefactorFeatures()
	if len(got) != 1 || got[0] != control.SemanticRefactorFeatureRoutingEpoch {
		t.Fatalf("defaultSemanticRefactorFeatures() = %v, want [routing-epoch]", got)
	}
}

func TestSemanticRefactorFeaturesFromValue(t *testing.T) {
	defaults := defaultSemanticRefactorFeatures()
	tests := []struct {
		name    string
		value   string
		present bool
		want    []control.SemanticRefactorFeature
		enabled bool
		wantErr bool
	}{
		{name: "unset", want: defaults, enabled: true},
		{name: "empty", present: true, want: defaults, enabled: true},
		{name: "disable none", value: "none", present: true},
		{name: "udp ordered dispatcher", value: "udp-ordered-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureUDPOrderedDispatcher}, enabled: true},
		{name: "udp reply dispatcher", value: "udp-reply-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureUDPReplyDispatcher}, enabled: true},
		{name: "multiple", value: "udp-ordered-dispatcher,udp-reply-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureUDPOrderedDispatcher, control.SemanticRefactorFeatureUDPReplyDispatcher}, enabled: true},
		{name: "unknown", value: "unknown", present: true, wantErr: true},
		// Paths that have been collapsed into the single production path must
		// fail loudly rather than being accepted and silently doing nothing.
		{name: "routing epoch", value: "routing-epoch", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureRoutingEpoch}, enabled: true},
		{name: "retired compiled-policy", value: "compiled-policy", present: true, wantErr: true},
		{name: "retired dns-resolver", value: "dns-resolver", present: true, wantErr: true},
		{name: "duplicate", value: "udp-reply-dispatcher,udp-reply-dispatcher", present: true, wantErr: true},
		{name: "whitespace", value: "udp-ordered-dispatcher, udp-reply-dispatcher", present: true, wantErr: true},
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
		routingEpochEnabled bool
		freshDatapathReload bool
		listenerPresent     bool
		want                bool
	}{
		{name: "same port reload", routingEpochEnabled: true, listenerPresent: true, want: true},
		{name: "fresh datapath reload", routingEpochEnabled: true, freshDatapathReload: true, listenerPresent: true},
		{name: "no listener", routingEpochEnabled: true},
		// The staged path overlaps two generations publishing routing state;
		// without the epoch's prepared slot there is nothing keeping the kernel
		// from reading a half-written rule set, so it must stay off.
		{name: "routing epoch disabled", listenerPresent: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldUseStagedHotHandoff(tc.routingEpochEnabled, tc.freshDatapathReload, tc.listenerPresent)
			if got != tc.want {
				t.Fatalf("shouldUseStagedHotHandoff(%v, %v, %v) = %v, want %v",
					tc.routingEpochEnabled, tc.freshDatapathReload, tc.listenerPresent, got, tc.want)
			}
		})
	}
}

func TestShouldStreamStagedDnsCache(t *testing.T) {
	tests := []struct {
		name                         string
		stagedHotHandoff             bool
		dnsConfigUnchanged           bool
		ipVersionPreferenceUnchanged bool
		want                         bool
	}{
		{
			name:                         "reusable staged handoff",
			stagedHotHandoff:             true,
			dnsConfigUnchanged:           true,
			ipVersionPreferenceUnchanged: true,
			want:                         true,
		},
		{name: "fresh datapath", dnsConfigUnchanged: true, ipVersionPreferenceUnchanged: true},
		{name: "changed DNS config", stagedHotHandoff: true, ipVersionPreferenceUnchanged: true},
		{name: "changed IP preference", stagedHotHandoff: true, dnsConfigUnchanged: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldStreamStagedDnsCache(
				tc.stagedHotHandoff,
				tc.dnsConfigUnchanged,
				tc.ipVersionPreferenceUnchanged,
			)
			if got != tc.want {
				t.Fatalf("shouldStreamStagedDnsCache() = %v, want %v", got, tc.want)
			}
		})
	}
}
