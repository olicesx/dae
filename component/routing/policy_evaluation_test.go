/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
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
	if err := snapshot.ValidateContinuation(evaluation.Continuation); err != nil {
		t.Fatalf("ValidateContinuation() error = %v", err)
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

func TestPolicySnapshotEvaluateGroupsDefersBeforeLaterMatch(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "domain",
				Params: []*config_parser.Param{{Key: "suffix", Val: "example.com"}},
			}},
			Outbound: config_parser.Function{Name: "direct"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "port",
				Params: []*config_parser.Param{{Val: "443"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	})

	evaluation, err := snapshot.EvaluateGroups(func(group PredicateGroup) Truth {
		if group.RuleIndex == 0 {
			return TruthUnknown
		}
		return TruthTrue
	})
	if err != nil {
		t.Fatalf("EvaluateGroups() error = %v", err)
	}
	if evaluation.State != DecisionDeferred || evaluation.RuleIndex != 0 {
		t.Fatalf("evaluation = %+v, want deferred at rule 0", evaluation)
	}
}

func TestPolicySnapshotEvaluateGroupsNegatesCombinedParameterKeys(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name: "domain",
				Not:  true,
				Params: []*config_parser.Param{
					{Key: "full", Val: "api.example.com"},
					{Key: "suffix", Val: "example.com"},
				},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	})

	var groups []PredicateGroup
	evaluation, err := snapshot.EvaluateGroups(func(group PredicateGroup) Truth {
		groups = append(groups, group)
		switch group.Key {
		case "full":
			return TruthFalse
		case "suffix":
			return TruthTrue
		default:
			t.Fatalf("unexpected parameter key %q", group.Key)
			return TruthFalse
		}
	})
	if err != nil {
		t.Fatalf("EvaluateGroups() error = %v", err)
	}
	if evaluation.State != DecisionResolved || evaluation.RuleIndex != 1 {
		t.Fatalf("evaluation = %+v, want fallback", evaluation)
	}
	if len(groups) != 2 || groups[0].Values[0] != "api.example.com" || groups[1].Values[0] != "example.com" {
		t.Fatalf("predicate groups = %+v, want independent full and suffix groups", groups)
	}

	groups[0].Values[0] = "mutated"
	evaluation, err = snapshot.EvaluateGroups(func(group PredicateGroup) Truth {
		if group.Key == "full" && group.Values[0] != "api.example.com" {
			t.Fatalf("snapshot leaked mutable predicate group values: %q", group.Values[0])
		}
		return TruthFalse
	})
	if err != nil {
		t.Fatalf("second EvaluateGroups() error = %v", err)
	}
	if evaluation.RuleIndex != 0 {
		t.Fatalf("second evaluation = %+v, want rule 0", evaluation)
	}
}

func TestPolicySnapshotEvaluateGroupsORsParameterKeys(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name: consts.Function_Domain,
			Params: []*config_parser.Param{
				{Key: string(consts.RoutingDomainKey_Full), Val: "first.key.test"},
				{Key: string(consts.RoutingDomainKey_Suffix), Val: "middle.key.test"},
				{Key: string(consts.RoutingDomainKey_Keyword), Val: "last-key"},
			},
		}},
		Outbound: config_parser.Function{Name: "proxy"},
	}})

	tests := []struct {
		name      string
		results   map[string]Truth
		wantRule  int
		wantCalls []string
	}{
		{
			name:      "first_key_matches",
			results:   map[string]Truth{"full": TruthTrue, "suffix": TruthUnknown, "keyword": TruthUnknown},
			wantRule:  0,
			wantCalls: []string{"full"},
		},
		{
			name:      "middle_key_matches",
			results:   map[string]Truth{"full": TruthFalse, "suffix": TruthTrue, "keyword": TruthUnknown},
			wantRule:  0,
			wantCalls: []string{"full", "suffix"},
		},
		{
			name:      "last_key_matches",
			results:   map[string]Truth{"full": TruthFalse, "suffix": TruthFalse, "keyword": TruthTrue},
			wantRule:  0,
			wantCalls: []string{"full", "suffix", "keyword"},
		},
		{
			name:      "no_key_matches",
			results:   map[string]Truth{"full": TruthFalse, "suffix": TruthFalse, "keyword": TruthFalse},
			wantRule:  1,
			wantCalls: []string{"full", "suffix", "keyword"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			evaluation, err := snapshot.EvaluateGroups(func(group PredicateGroup) Truth {
				calls = append(calls, group.Key)
				return tc.results[group.Key]
			})
			if err != nil {
				t.Fatalf("EvaluateGroups() error = %v", err)
			}
			if evaluation.State != DecisionResolved || evaluation.RuleIndex != tc.wantRule {
				t.Fatalf("evaluation = %+v, want resolved rule %d", evaluation, tc.wantRule)
			}
			if len(calls) != len(tc.wantCalls) {
				t.Fatalf("resolver calls = %v, want %v", calls, tc.wantCalls)
			}
			for index, want := range tc.wantCalls {
				if calls[index] != want {
					t.Fatalf("resolver call %d = %q, want %q", index, calls[index], want)
				}
			}
		})
	}
}

func TestPolicySnapshotEvaluateGroupsNegatedParameterKeysShortCircuit(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name: consts.Function_Domain,
			Not:  true,
			Params: []*config_parser.Param{
				{Key: string(consts.RoutingDomainKey_Full), Val: "first.key.test"},
				{Key: string(consts.RoutingDomainKey_Suffix), Val: "middle.key.test"},
				{Key: string(consts.RoutingDomainKey_Keyword), Val: "last-key"},
			},
		}},
		Outbound: config_parser.Function{Name: "proxy"},
	}})

	tests := []struct {
		name      string
		results   map[string]Truth
		wantRule  int
		wantCalls []string
	}{
		{
			name:      "first_key_matches",
			results:   map[string]Truth{"full": TruthTrue, "suffix": TruthUnknown, "keyword": TruthUnknown},
			wantRule:  1,
			wantCalls: []string{"full"},
		},
		{
			name:      "middle_key_matches",
			results:   map[string]Truth{"full": TruthFalse, "suffix": TruthTrue, "keyword": TruthUnknown},
			wantRule:  1,
			wantCalls: []string{"full", "suffix"},
		},
		{
			name:      "all_keys_false_selects_negated_rule",
			results:   map[string]Truth{"full": TruthFalse, "suffix": TruthFalse, "keyword": TruthFalse},
			wantRule:  0,
			wantCalls: []string{"full", "suffix", "keyword"},
		},
		{
			name:      "later_true_masks_earlier_unknown",
			results:   map[string]Truth{"full": TruthUnknown, "suffix": TruthTrue, "keyword": TruthUnknown},
			wantRule:  1,
			wantCalls: []string{"full", "suffix"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			evaluation, err := snapshot.EvaluateGroups(func(group PredicateGroup) Truth {
				calls = append(calls, group.Key)
				return tc.results[group.Key]
			})
			if err != nil {
				t.Fatalf("EvaluateGroups() error = %v", err)
			}
			if evaluation.State != DecisionResolved || evaluation.RuleIndex != tc.wantRule {
				t.Fatalf("evaluation = %+v, want resolved rule %d", evaluation, tc.wantRule)
			}
			if len(calls) != len(tc.wantCalls) {
				t.Fatalf("resolver calls = %v, want %v", calls, tc.wantCalls)
			}
			for index, want := range tc.wantCalls {
				if calls[index] != want {
					t.Fatalf("resolver call %d = %q, want %q", index, calls[index], want)
				}
			}
		})
	}
}

func TestPolicySnapshotEvaluateGroupsNegatedParameterKeysTrackUnknown(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name: consts.Function_Domain,
			Not:  true,
			Params: []*config_parser.Param{
				{Key: string(consts.RoutingDomainKey_Full), Val: "first.key.test"},
				{Key: string(consts.RoutingDomainKey_Suffix), Val: "middle.key.test"},
				{Key: string(consts.RoutingDomainKey_Keyword), Val: "last-key"},
			},
		}},
		Outbound: config_parser.Function{Name: "proxy"},
	}})

	evaluation, err := snapshot.EvaluateGroups(func(group PredicateGroup) Truth {
		switch group.Key {
		case string(consts.RoutingDomainKey_Full):
			return TruthUnknown
		default:
			return TruthFalse
		}
	})
	if err != nil {
		t.Fatalf("EvaluateGroups() error = %v", err)
	}
	if evaluation.State != DecisionDeferred || evaluation.Continuation.InstructionID != 0 {
		t.Fatalf("evaluation = %+v, want deferred at instruction 0", evaluation)
	}
	if err := snapshot.ValidateContinuation(evaluation.Continuation); err != nil {
		t.Fatalf("ValidateContinuation() error = %v", err)
	}
}

func TestPolicySnapshotEvaluateGroupsORsParameterKeysAndTracksRelevantUnknown(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name: consts.Function_Domain,
			Params: []*config_parser.Param{
				{Key: string(consts.RoutingDomainKey_Full), Val: "first.key.test"},
				{Key: string(consts.RoutingDomainKey_Suffix), Val: "middle.key.test"},
				{Key: string(consts.RoutingDomainKey_Keyword), Val: "last-key"},
			},
		}},
		Outbound: config_parser.Function{Name: "proxy"},
	}})

	tests := []struct {
		name            string
		results         map[string]Truth
		wantState       DecisionState
		wantInstruction int
	}{
		{
			name:            "later_true_masks_earlier_unknown",
			results:         map[string]Truth{"full": TruthUnknown, "suffix": TruthTrue, "keyword": TruthFalse},
			wantState:       DecisionResolved,
			wantInstruction: -1,
		},
		{
			name:            "first_unknown_remains_relevant",
			results:         map[string]Truth{"full": TruthUnknown, "suffix": TruthFalse, "keyword": TruthFalse},
			wantState:       DecisionDeferred,
			wantInstruction: 0,
		},
		{
			name:            "middle_unknown_remains_relevant",
			results:         map[string]Truth{"full": TruthFalse, "suffix": TruthUnknown, "keyword": TruthFalse},
			wantState:       DecisionDeferred,
			wantInstruction: 1,
		},
		{
			name:            "last_unknown_remains_relevant",
			results:         map[string]Truth{"full": TruthFalse, "suffix": TruthFalse, "keyword": TruthUnknown},
			wantState:       DecisionDeferred,
			wantInstruction: 2,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			evaluation, err := snapshot.EvaluateGroups(func(group PredicateGroup) Truth {
				return tc.results[group.Key]
			})
			if err != nil {
				t.Fatalf("EvaluateGroups() error = %v", err)
			}
			if evaluation.State != tc.wantState {
				t.Fatalf("evaluation state = %v, want %v", evaluation.State, tc.wantState)
			}
			if tc.wantState == DecisionDeferred {
				if evaluation.Continuation.InstructionID != tc.wantInstruction {
					t.Fatalf("continuation instruction = %d, want %d", evaluation.Continuation.InstructionID, tc.wantInstruction)
				}
				if err := snapshot.ValidateContinuation(evaluation.Continuation); err != nil {
					t.Fatalf("ValidateContinuation() error = %v", err)
				}
			}
		})
	}
}

func TestPolicySnapshotEvaluateMustRulesContinuesAndCarriesMust(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{Name: "process_name"}},
			Outbound:     config_parser.Function{Name: "must_rules"},
		},
		{
			AndFunctions: []*config_parser.Function{{Name: "domain"}},
			Outbound:     config_parser.Function{Name: "proxy"},
		},
	})

	evaluation, err := snapshot.Evaluate(func(ruleIndex, _ int) Truth {
		if ruleIndex == 0 {
			return TruthTrue
		}
		return TruthTrue
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if evaluation.State != DecisionResolved || evaluation.RuleIndex != 1 || !evaluation.inheritedMust {
		t.Fatalf("evaluation = %+v, want resolved rule 1 with inherited must", evaluation)
	}

	outbound, err := snapshot.OutboundFor(evaluation)
	if err != nil {
		t.Fatalf("OutboundFor() error = %v", err)
	}
	parsed, err := ParseOutbound(outbound)
	if err != nil {
		t.Fatalf("ParseOutbound() error = %v", err)
	}
	if parsed.Name != "proxy" || !parsed.Must {
		t.Fatalf("outbound = %+v, want proxy with must", parsed)
	}

	fallback, err := snapshot.Evaluate(func(ruleIndex, _ int) Truth {
		if ruleIndex == 0 {
			return TruthTrue
		}
		return TruthFalse
	})
	if err != nil {
		t.Fatalf("fallback Evaluate() error = %v", err)
	}
	if fallback.RuleIndex != snapshot.RuleCount() || !fallback.inheritedMust {
		t.Fatalf("fallback evaluation = %+v, want fallback with inherited must", fallback)
	}
	fallbackOutbound, err := snapshot.OutboundFor(fallback)
	if err != nil {
		t.Fatalf("fallback OutboundFor() error = %v", err)
	}
	parsedFallback, err := ParseOutbound(fallbackOutbound)
	if err != nil {
		t.Fatalf("ParseOutbound(fallback) error = %v", err)
	}
	if parsedFallback.Name != "direct" || !parsedFallback.Must {
		t.Fatalf("fallback outbound = %+v, want direct with must", parsedFallback)
	}
}

func TestPolicySnapshotEvaluateGroupsMustRulesContinuation(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "process_name",
				Params: []*config_parser.Param{{Val: "dnsmasq"}},
			}},
			Outbound: config_parser.Function{Name: "must_rules"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "domain",
				Params: []*config_parser.Param{{Key: "suffix", Val: "example.com"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	})

	evaluation, err := snapshot.EvaluateGroups(func(group PredicateGroup) Truth {
		if group.RuleIndex == 0 {
			return TruthTrue
		}
		return TruthTrue
	})
	if err != nil {
		t.Fatalf("EvaluateGroups() error = %v", err)
	}
	if evaluation.State != DecisionResolved || evaluation.RuleIndex != 1 || !evaluation.inheritedMust {
		t.Fatalf("evaluation = %+v, want resolved rule 1 with inherited must", evaluation)
	}

	outbound, err := snapshot.OutboundFor(evaluation)
	if err != nil {
		t.Fatalf("OutboundFor() error = %v", err)
	}
	parsed, err := ParseOutbound(outbound)
	if err != nil {
		t.Fatalf("ParseOutbound() error = %v", err)
	}
	if !parsed.Must {
		t.Fatalf("outbound = %+v, want inherited must", parsed)
	}

	deferred, err := snapshot.EvaluateGroups(func(group PredicateGroup) Truth {
		if group.RuleIndex == 0 {
			return TruthTrue
		}
		return TruthUnknown
	})
	if err != nil {
		t.Fatalf("deferred EvaluateGroups() error = %v", err)
	}
	if deferred.State != DecisionDeferred || deferred.RuleIndex != 1 || !deferred.inheritedMust {
		t.Fatalf("deferred evaluation = %+v, want rule 1 with inherited must", deferred)
	}
}
