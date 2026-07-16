/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import "testing"

func TestPhase4DecisionShadowSampleEveryFromValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		present bool
		want    uint64
		enabled bool
		wantErr bool
	}{
		{name: "unset", want: 0},
		{name: "empty", value: "", present: true, want: 0},
		{name: "positive", value: "17", present: true, want: 17, enabled: true},
		{name: "zero", value: "0", present: true, wantErr: true},
		{name: "invalid", value: "many", present: true, wantErr: true},
		{name: "whitespace", value: " 2", present: true, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, enabled, err := phase4DecisionShadowSampleEveryFromValue(tc.value, tc.present)
			if tc.wantErr {
				if err == nil {
					t.Fatal("phase4DecisionShadowSampleEveryFromValue() error = nil")
				}
				return
			}
			if err != nil || got != tc.want || enabled != tc.enabled {
				t.Fatalf("phase4DecisionShadowSampleEveryFromValue() = (%d,%v,%v), want (%d,%v,nil)", got, enabled, err, tc.want, tc.enabled)
			}
		})
	}
}
