/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"

	"github.com/daeuniverse/dae/control"
)

// Migration paths stay opt-in. Adding one here means it carries production
// traffic for every user by default, so it needs its own justification rather
// than inheriting one from the migration it belongs to.
func TestDefaultSemanticRefactorFeaturesAreOptIn(t *testing.T) {
	if got := defaultSemanticRefactorFeatures(); len(got) != 0 {
		t.Fatalf("defaultSemanticRefactorFeatures() = %v, want none enabled by default", got)
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
		{name: "unset", want: defaults},
		{name: "empty", present: true, want: defaults},
		{name: "disable none", value: "none", present: true},
		{name: "udp ordered dispatcher", value: "udp-ordered-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureUDPOrderedDispatcher}, enabled: true},
		{name: "udp reply dispatcher", value: "udp-reply-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureUDPReplyDispatcher}, enabled: true},
		{name: "multiple", value: "udp-ordered-dispatcher,udp-reply-dispatcher", present: true, want: []control.SemanticRefactorFeature{control.SemanticRefactorFeatureUDPOrderedDispatcher, control.SemanticRefactorFeatureUDPReplyDispatcher}, enabled: true},
		{name: "unknown", value: "unknown", present: true, wantErr: true},
		// Paths that have been collapsed into the single production path must
		// fail loudly rather than being accepted and silently doing nothing.
		{name: "retired compiled-policy", value: "compiled-policy", present: true, wantErr: true},
		{name: "retired routing-epoch", value: "routing-epoch", present: true, wantErr: true},
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
		freshDatapathReload bool
		listenerPresent     bool
		want                bool
	}{
		{name: "same port reload", listenerPresent: true, want: true},
		{name: "fresh datapath reload", freshDatapathReload: true, listenerPresent: true},
		{name: "no listener"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldUseStagedHotHandoff(tc.freshDatapathReload, tc.listenerPresent)
			if got != tc.want {
				t.Fatalf("shouldUseStagedHotHandoff(%v, %v) = %v, want %v",
					tc.freshDatapathReload, tc.listenerPresent, got, tc.want)
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
