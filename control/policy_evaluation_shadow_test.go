/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

const (
	phase2PredicateTrueOutbound  = "__phase2_predicate_true__"
	phase2PredicateFalseOutbound = "__phase2_predicate_false__"
)

type phase2PredicateKey struct {
	ruleIndex     int
	functionIndex int
	groupIndex    int
}

type phase2PredicateMatcher struct {
	matcher       *RoutingMatcher
	trueOutbound  consts.OutboundIndex
	falseOutbound consts.OutboundIndex
}

// TestPhase2PolicySnapshotEvaluationMatchesLegacyCorpus keeps the legacy
// matcher authoritative while verifying the snapshot's group-level truth
// composition against every complete Phase 0 routing fixture. Each predicate
// group is evaluated by an isolated legacy matcher, so a failure identifies
// the three-valued ordering or lowering-boundary semantics rather than a live
// routing behavior change.
func TestPhase2PolicySnapshotEvaluationMatchesLegacyCorpus(t *testing.T) {
	for _, fixture := range RoutingCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
			if err != nil {
				t.Fatalf("NewNormalizedProgram() error = %v", err)
			}
			snapshot, err := routing.NewPolicySnapshot(21, program)
			if err != nil {
				t.Fatalf("NewPolicySnapshot() error = %v", err)
			}

			evaluate := newPhase2CorpusPolicyEvaluator(t, fixture, snapshot)
			for _, tc := range fixture.Cases {
				tc := tc
				t.Run(tc.Name, func(t *testing.T) {
					evaluation := evaluate(tc.Input)
					if evaluation.State != routing.DecisionResolved {
						t.Fatalf("evaluation = %+v, want resolved complete-fact result", evaluation)
					}

					outboundFunction, err := snapshot.OutboundFor(evaluation)
					if err != nil {
						t.Fatalf("OutboundFor() error = %v", err)
					}
					outbound, err := routing.ParseOutbound(outboundFunction)
					if err != nil {
						t.Fatalf("ParseOutbound() error = %v", err)
					}
					outboundID, ok := fixture.OutboundIDs[outbound.Name]
					if !ok {
						t.Fatalf("outbound %q is not present in fixture IDs", outbound.Name)
					}
					if got := consts.OutboundIndex(outboundID); got != tc.Expected.Outbound {
						t.Fatalf("outbound = %v, want legacy %v", got, tc.Expected.Outbound)
					}
					if outbound.Mark != tc.Expected.Mark {
						t.Fatalf("mark = %d, want legacy %d", outbound.Mark, tc.Expected.Mark)
					}
					if outbound.Must != tc.Expected.Must {
						t.Fatalf("must = %v, want legacy %v", outbound.Must, tc.Expected.Must)
					}
				})
			}
		})
	}
}

func newPhase2CorpusPolicyEvaluator(t *testing.T, fixture CorpusFixture, snapshot *routing.PolicySnapshot) func(CorpusInput) routing.PolicyEvaluation {
	t.Helper()
	predicateMatchers := make(map[phase2PredicateKey]*phase2PredicateMatcher)

	return func(input CorpusInput) routing.PolicyEvaluation {
		t.Helper()
		evaluation, err := snapshot.EvaluateGroups(func(group routing.PredicateGroup) routing.Truth {
			key := phase2PredicateKey{
				ruleIndex:     group.RuleIndex,
				functionIndex: group.FunctionIndex,
				groupIndex:    group.GroupIndex,
			}
			matcher, ok := predicateMatchers[key]
			if !ok {
				var buildErr error
				matcher, buildErr = newPhase2PredicateMatcher(fixture, group)
				if buildErr != nil {
					t.Fatalf("build predicate matcher for %+v: %v", group, buildErr)
					return routing.TruthFalse
				}
				predicateMatchers[key] = matcher
			}
			truth, truthErr := matcher.truth(input)
			if truthErr != nil {
				t.Fatalf("evaluate predicate group %+v: %v", group, truthErr)
				return routing.TruthFalse
			}
			return truth
		})
		if err != nil {
			t.Fatalf("EvaluateGroups() error = %v", err)
		}
		return evaluation
	}
}

func newPhase2PredicateMatcher(fixture CorpusFixture, group routing.PredicateGroup) (*phase2PredicateMatcher, error) {
	outboundIDs, trueOutbound, falseOutbound, err := phase2PredicateOutboundIDs(fixture.OutboundIDs)
	if err != nil {
		return nil, err
	}

	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		[]*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{phase2PositivePredicate(group)},
			Outbound:     config_parser.Function{Name: phase2PredicateTrueOutbound},
		}},
		outboundIDs,
		nil,
		config.FunctionOrString(phase2PredicateFalseOutbound),
	)
	if err != nil {
		return nil, err
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, err
	}
	return &phase2PredicateMatcher{
		matcher:       matcher,
		trueOutbound:  trueOutbound,
		falseOutbound: falseOutbound,
	}, nil
}

func phase2PredicateOutboundIDs(existing map[string]uint8) (map[string]uint8, consts.OutboundIndex, consts.OutboundIndex, error) {
	outboundIDs := make(map[string]uint8, len(existing)+2)
	used := make(map[uint8]struct{}, len(existing))
	for name, id := range existing {
		outboundIDs[name] = id
		used[id] = struct{}{}
	}
	if _, exists := outboundIDs[phase2PredicateTrueOutbound]; exists {
		return nil, 0, 0, fmt.Errorf("reserved predicate outbound name %q is already configured", phase2PredicateTrueOutbound)
	}
	if _, exists := outboundIDs[phase2PredicateFalseOutbound]; exists {
		return nil, 0, 0, fmt.Errorf("reserved predicate outbound name %q is already configured", phase2PredicateFalseOutbound)
	}

	available := make([]uint8, 0, 2)
	for id := int(consts.OutboundUserDefinedMax); id >= int(consts.OutboundUserDefinedMin); id-- {
		candidate := uint8(id)
		if _, exists := used[candidate]; exists {
			continue
		}
		available = append(available, candidate)
		if len(available) == 2 {
			break
		}
	}
	if len(available) != 2 {
		return nil, 0, 0, fmt.Errorf("not enough free outbound IDs for predicate shadowing")
	}

	outboundIDs[phase2PredicateTrueOutbound] = available[0]
	outboundIDs[phase2PredicateFalseOutbound] = available[1]
	return outboundIDs, consts.OutboundIndex(available[0]), consts.OutboundIndex(available[1]), nil
}

func phase2PositivePredicate(group routing.PredicateGroup) *config_parser.Function {
	function := &config_parser.Function{
		Name:   group.Name,
		Params: make([]*config_parser.Param, 0, len(group.Values)+1),
	}
	for _, value := range group.Values {
		function.Params = append(function.Params, &config_parser.Param{Key: group.Key, Val: value})
	}
	if group.Not && group.Name == consts.Function_Mac {
		// The legacy negative-MAC lowerer also excludes the all-zero MAC.
		function.Params = append(function.Params, &config_parser.Param{Key: group.Key, Val: "00:00:00:00:00:00"})
	}
	return function
}

func (m *phase2PredicateMatcher) truth(input CorpusInput) (routing.Truth, error) {
	outbound, _, _, err := matchCorpusInput(m.matcher, input)
	if err != nil {
		return routing.TruthUnknown, err
	}
	switch outbound {
	case m.trueOutbound:
		return routing.TruthTrue, nil
	case m.falseOutbound:
		return routing.TruthFalse, nil
	default:
		return routing.TruthUnknown, fmt.Errorf("predicate matcher returned unexpected outbound %v", outbound)
	}
}
