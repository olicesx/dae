/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestPolicySnapshotDoesNotAliasSourceOrCompilerProgram(t *testing.T) {
	program, err := NewNormalizedProgram([]*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "domain",
				Params: []*config_parser.Param{{Key: "suffix", Val: "example.com"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}

	snapshot, err := NewPolicySnapshot(7, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	originalHash := snapshot.Hash()

	program.Rules[0].AndFunctions[0].Params[0].Val = "mutated.example"
	if got := snapshot.Hash(); got != originalHash {
		t.Fatal("snapshot hash changed after source program mutation")
	}

	compilerProgram, err := snapshot.CloneProgram()
	if err != nil {
		t.Fatalf("CloneProgram() error = %v", err)
	}
	compilerProgram.Rules[0].AndFunctions[0].Params[0].Val = "compiler-mutated.example"
	if got := snapshot.Hash(); got != originalHash {
		t.Fatal("snapshot hash changed after compiler program mutation")
	}
}

func TestPolicySnapshotHashIgnoresEpochAndTracksContent(t *testing.T) {
	newProgram := func(domain string) *NormalizedProgram {
		program, err := NewNormalizedProgram([]*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{{
					Name:   "domain",
					Params: []*config_parser.Param{{Key: "suffix", Val: domain}},
				}},
				Outbound: config_parser.Function{Name: "proxy"},
			},
		}, config.FunctionOrString("direct"))
		if err != nil {
			t.Fatalf("NewNormalizedProgram() error = %v", err)
		}
		return program
	}

	first, err := NewPolicySnapshot(1, newProgram("example.com"))
	if err != nil {
		t.Fatalf("NewPolicySnapshot(first) error = %v", err)
	}
	second, err := NewPolicySnapshot(2, newProgram("example.com"))
	if err != nil {
		t.Fatalf("NewPolicySnapshot(second) error = %v", err)
	}
	changed, err := NewPolicySnapshot(3, newProgram("changed.example"))
	if err != nil {
		t.Fatalf("NewPolicySnapshot(changed) error = %v", err)
	}

	if first.Hash() != second.Hash() {
		t.Fatal("identical policy content produced different hashes")
	}
	if first.Hash() == changed.Hash() {
		t.Fatal("different policy content produced the same hash")
	}
	if first.Epoch() != 1 || second.Epoch() != 2 {
		t.Fatalf("unexpected epochs: %d, %d", first.Epoch(), second.Epoch())
	}
}
