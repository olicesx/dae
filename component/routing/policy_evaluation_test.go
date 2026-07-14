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

func newPolicyEvaluationSnapshot(t *testing.T, rules []*config_parser.RoutingRule) *PolicySnapshot {
	t.Helper()
	program, err := NewNormalizedProgram(rules, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	snapshot, err := NewPolicySnapshot(11, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	return snapshot
}

func TestPolicySnapshotEvaluateDefersBeforeLaterMatch(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{Name: "domain"}},
			Outbound:     config_parser.Function{Name: "direct"},
		},
		{
			AndFunctions: []*config_parser.Function{{Name: "port"}},
			Outbound:     config_parser.Function{Name: "proxy"},
		},
	})

	evaluation, err := snapshot.Evaluate(func(ruleIndex, _ int) Truth {
		if ruleIndex == 0 {
			return TruthUnknown
		}
		return TruthTrue
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if evaluation.State != DecisionDeferred || evaluation.RuleIndex != 0 {
		t.Fatalf("evaluation = %+v, want deferred at rule 0", evaluation)
	}
}

func TestPolicySnapshotEvaluateFalseDefeatsUnknownWithinRule(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{Name: "domain"}, {Name: "port"}},
			Outbound:     config_parser.Function{Name: "direct"},
		},
		{
			AndFunctions: []*config_parser.Function{{Name: "proto"}},
			Outbound:     config_parser.Function{Name: "proxy"},
		},
	})

	evaluation, err := snapshot.Evaluate(func(ruleIndex, functionIndex int) Truth {
		if ruleIndex == 0 && functionIndex == 0 {
			return TruthUnknown
		}
		return TruthFalse
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if evaluation.State != DecisionResolved || evaluation.RuleIndex != 2 {
		t.Fatalf("evaluation = %+v, want fallback", evaluation)
	}
}

func TestPolicySnapshotEvaluateNegatedUnknownAndOutboundClone(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{Name: "domain", Not: true}},
			Outbound:     config_parser.Function{Name: "proxy"},
		},
	})

	evaluation, err := snapshot.Evaluate(func(int, int) Truth { return TruthUnknown })
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if evaluation.State != DecisionDeferred {
		t.Fatalf("evaluation = %+v, want deferred", evaluation)
	}

	resolved, err := snapshot.Evaluate(func(int, int) Truth { return TruthFalse })
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	outbound, err := snapshot.OutboundFor(resolved)
	if err != nil {
		t.Fatalf("OutboundFor() error = %v", err)
	}
	if outbound.Name != "proxy" {
		t.Fatalf("outbound = %q, want proxy", outbound.Name)
	}
	outbound.Name = "mutated"
	second, err := snapshot.OutboundFor(resolved)
	if err != nil {
		t.Fatalf("OutboundFor() second error = %v", err)
	}
	if second.Name != "proxy" {
		t.Fatalf("snapshot outbound was mutated: %q", second.Name)
	}
}

func TestPolicySnapshotEvaluateSkipsEmptyLegacyRule(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{Outbound: config_parser.Function{Name: "proxy"}},
		{
			AndFunctions: []*config_parser.Function{{Name: "port"}},
			Outbound:     config_parser.Function{Name: "direct"},
		},
	})

	evaluation, err := snapshot.Evaluate(func(int, int) Truth { return TruthTrue })
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if evaluation.State != DecisionResolved || evaluation.RuleIndex != 1 {
		t.Fatalf("evaluation = %+v, want rule 1", evaluation)
	}
}
