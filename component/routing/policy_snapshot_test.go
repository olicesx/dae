/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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

func TestPolicyIdentityMatchesOwnedSnapshot(t *testing.T) {
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

	identity, err := NewPolicyIdentity(7, program)
	if err != nil {
		t.Fatalf("NewPolicyIdentity() error = %v", err)
	}
	snapshot, err := NewPolicySnapshotFromOwnedProgram(7, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshotFromOwnedProgram() error = %v", err)
	}
	if identity != snapshot.Identity() {
		t.Fatalf("identity = %+v, snapshot identity = %+v", identity, snapshot.Identity())
	}
	if identity.Epoch() != 7 || identity.RuleCount() != 1 {
		t.Fatalf("identity metadata = (epoch=%d, rules=%d)", identity.Epoch(), identity.RuleCount())
	}

	clone, err := snapshot.CloneProgram()
	if err != nil {
		t.Fatalf("CloneProgram() error = %v", err)
	}
	clone.Rules[0].AndFunctions[0].Params[0].Val = "changed.example"
	if snapshot.Hash() != identity.Hash() {
		t.Fatal("snapshot identity changed after clone mutation")
	}
}

func TestPolicyIdentityHashIncludesNestedSemanticFields(t *testing.T) {
	newProgram := func() *NormalizedProgram {
		program, err := NewNormalizedProgram([]*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{{
					Name: "domain",
					Not:  true,
					Params: []*config_parser.Param{{
						Key: "suffix",
						Val: "example.com",
						AndFunctions: []*config_parser.Function{{
							Name:   "port",
							Params: []*config_parser.Param{{Val: "443"}},
						}},
						Annotation: []*config_parser.Param{{Key: "source", Val: "fixture"}},
					}},
				}},
				Outbound: config_parser.Function{
					Name:   "proxy",
					Params: []*config_parser.Param{{Key: "mark", Val: "7"}},
				},
			},
		}, &config_parser.Function{Name: "direct", Params: []*config_parser.Param{{Val: "must"}}})
		if err != nil {
			t.Fatalf("NewNormalizedProgram() error = %v", err)
		}
		return program
	}

	base, err := NewPolicyIdentity(1, newProgram())
	if err != nil {
		t.Fatalf("NewPolicyIdentity(base) error = %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*NormalizedProgram)
	}{
		{name: "function not", mutate: func(program *NormalizedProgram) { program.Rules[0].AndFunctions[0].Not = false }},
		{name: "nested function", mutate: func(program *NormalizedProgram) {
			program.Rules[0].AndFunctions[0].Params[0].AndFunctions[0].Name = "source_port"
		}},
		{name: "annotation", mutate: func(program *NormalizedProgram) {
			program.Rules[0].AndFunctions[0].Params[0].Annotation[0].Val = "changed"
		}},
		{name: "outbound params", mutate: func(program *NormalizedProgram) { program.Rules[0].Outbound.Params[0].Val = "8" }},
		{name: "fallback", mutate: func(program *NormalizedProgram) {
			program.Fallback.(*config_parser.Function).Name = "block"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := newProgram()
			tc.mutate(program)
			changed, err := NewPolicyIdentity(2, program)
			if err != nil {
				t.Fatalf("NewPolicyIdentity(changed) error = %v", err)
			}
			if changed.Hash() == base.Hash() {
				t.Fatal("semantic mutation did not change policy hash")
			}
		})
	}
}

func BenchmarkPolicySnapshotConstruction(b *testing.B) {
	rules := make([]*config_parser.RoutingRule, 1024)
	for index := range rules {
		rules[index] = &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{{
				Name: "domain",
				Params: []*config_parser.Param{{
					Key: "suffix",
					Val: fmt.Sprintf("domain-%d.example", index),
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}
	}
	program, err := NewNormalizedProgram(rules, config.FunctionOrString("direct"))
	if err != nil {
		b.Fatalf("NewNormalizedProgram() error = %v", err)
	}

	b.Run("copy", func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			if _, err := NewPolicySnapshot(7, program); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("owned", func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			if _, err := NewPolicySnapshotFromOwnedProgram(7, program); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("identity", func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			if _, err := NewPolicyIdentity(7, program); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("buffered-json-baseline", func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			encoded, err := json.Marshal(struct {
				Rules    any `json:"rules"`
				Fallback any `json:"fallback"`
			}{
				Rules:    program.Rules,
				Fallback: program.Fallback,
			})
			if err != nil {
				b.Fatal(err)
			}
			policyHashBenchmarkSink = sha256.Sum256(encoded)
		}
	})
}

var policyHashBenchmarkSink [sha256.Size]byte
