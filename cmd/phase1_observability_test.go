/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"

	"github.com/daeuniverse/dae/control"
)

func TestPhase1SampleEveryFromValue(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		present    bool
		wantSample uint64
		wantOn     bool
		wantErr    bool
	}{
		{name: "unset"},
		{name: "empty", value: "", present: true},
		{name: "sample every event", value: "1", present: true, wantSample: 1, wantOn: true},
		{name: "sample every three events", value: "3", present: true, wantSample: 3, wantOn: true},
		{name: "zero", value: "0", present: true, wantErr: true},
		{name: "negative", value: "-1", present: true, wantErr: true},
		{name: "text", value: "often", present: true, wantErr: true},
		{name: "space", value: " 1", present: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSample, gotOn, err := phase1SampleEveryFromValue(tt.value, tt.present)
			if (err != nil) != tt.wantErr {
				t.Fatalf("phase1SampleEveryFromValue(%q, %v) error = %v, want error=%v", tt.value, tt.present, err, tt.wantErr)
			}
			if gotSample != tt.wantSample || gotOn != tt.wantOn {
				t.Fatalf("phase1SampleEveryFromValue(%q, %v) = (%d, %v), want (%d, %v)", tt.value, tt.present, gotSample, gotOn, tt.wantSample, tt.wantOn)
			}
		})
	}
}

func TestEnablePhase1ObservabilityFromEnvironment(t *testing.T) {
	t.Setenv(phase1SampleEveryEnv, "5")

	handle, err := enablePhase1ObservabilityFromEnvironment()
	if err != nil {
		t.Fatalf("enablePhase1ObservabilityFromEnvironment() error = %v", err)
	}
	if handle == nil {
		t.Fatal("enablePhase1ObservabilityFromEnvironment() handle = nil")
	}
	t.Cleanup(func() {
		handle.Disable()
	})

	snapshot, enabled := control.SnapshotPhase1Observability()
	if !enabled || snapshot.SampleEvery != 5 {
		t.Fatalf("Phase 1 snapshot = (%+v, %v), want sample interval 5 and enabled", snapshot, enabled)
	}
}
