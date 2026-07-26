/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// TestPolicyFactsShadowMatchesLegacyRoutingCorpus keeps RoutingMatcher.Match
// authoritative while verifying that complete facts resolve through the
// fact-aware policy evaluator to exactly the same outbound, mark, and must.
func TestPolicyFactsShadowMatchesLegacyRoutingCorpus(t *testing.T) {
	for _, fixture := range RoutingCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
			if err != nil {
				t.Fatalf("NewNormalizedProgram() error = %v", err)
			}
			snapshot, err := routing.NewPolicySnapshot(51, program)
			if err != nil {
				t.Fatalf("NewPolicySnapshot() error = %v", err)
			}
			evaluate := newPolicyFactsCorpusEvaluator(t, fixture, snapshot)
			matcher := fixture.BuildMatcher(t)

			for _, tc := range fixture.Cases {
				tc := tc
				t.Run(tc.Name, func(t *testing.T) {
					legacyOutbound, legacyMark, legacyMust, err := matchCorpusInput(matcher, tc.Input)
					if err != nil {
						t.Fatalf("legacy Match() error = %v", err)
					}
					evaluation := evaluate(tc.Input, routing.PolicyFacts{
						DomainKnown: true,
						Domain:      tc.Input.Domain,
						Evidence:    routing.EvidenceTLSSNI,
					})
					if evaluation.State != routing.DecisionResolved {
						t.Fatalf("evaluation = %+v, want resolved with complete facts", evaluation)
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
						t.Fatalf("outbound %q is absent from fixture IDs", outbound.Name)
					}
					if got := consts.OutboundIndex(outboundID); got != legacyOutbound || outbound.Mark != legacyMark || outbound.Must != legacyMust {
						t.Fatalf("fact-aware tuple = (%v,%d,%v), legacy = (%v,%d,%v)", got, outbound.Mark, outbound.Must, legacyOutbound, legacyMark, legacyMust)
					}
				})
			}
		})
	}
}

// TestPolicyFactsShadowDefersUnknownDomain shows the unsafe legacy outcome
// without changing forwarding: a later port rule currently resolves direct,
// whereas the shadow evaluator retains a continuation until domain evidence
// arrives and can then resume on the immutable snapshot.
func TestPolicyFactsShadowDefersUnknownDomain(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Domain,
				Params: []*config_parser.Param{{Key: string(consts.RoutingDomainKey_Suffix), Val: "example.test"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Port,
				Params: []*config_parser.Param{{Val: "443"}},
			}},
			Outbound: config_parser.Function{Name: "direct"},
		},
	}
	program, err := routing.NewNormalizedProgram(rules, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	snapshot, err := routing.NewPolicySnapshot(52, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	outboundIDs := map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"proxy":  uint8(consts.OutboundUserDefinedMin),
	}
	legacyBuilder, err := NewRoutingMatcherBuilderFromProgram(logrus.New(), program, outboundIDs, nil)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilderFromProgram() error = %v", err)
	}
	legacyMatcher, err := legacyBuilder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace() error = %v", err)
	}
	input := CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP}
	legacyOutbound, _, _, err := matchCorpusInput(legacyMatcher, input)
	if err != nil {
		t.Fatalf("legacy Match() error = %v", err)
	}
	if legacyOutbound != consts.OutboundDirect {
		t.Fatalf("legacy outbound = %v, want later direct rule", legacyOutbound)
	}

	evaluate := newPolicyFactsCorpusEvaluator(t, CorpusFixture{OutboundIDs: outboundIDs}, snapshot)
	deferred := evaluate(input, routing.PolicyFacts{})
	if deferred.State != routing.DecisionDeferred || deferred.RuleIndex != 0 {
		t.Fatalf("missing-domain evaluation = %+v, want deferred rule 0", deferred)
	}
	if err := snapshot.ValidateContinuation(deferred.Continuation); err != nil {
		t.Fatalf("ValidateContinuation() error = %v", err)
	}

	// A flow that outlives the generation which routed it keeps resolving its
	// deferred continuation against the snapshot it captured. The generation
	// must therefore never drop the snapshot out from under such a flow.
	generation := controlPlaneGenerationState{policySnapshot: snapshot}
	retainedSnapshot := generation.policySnapshot
	if retainedSnapshot == nil {
		t.Fatal("generation lost its policy snapshot")
	}
	resumed, err := retainedSnapshot.ResumeFacts(
		deferred.Continuation,
		routing.PolicyFacts{DomainKnown: true, Domain: "api.example.test", Evidence: routing.EvidenceTLSSNI},
		func(group routing.PredicateGroup, facts routing.PolicyFacts) routing.Truth {
			switch group.Name {
			case consts.Function_Domain:
				if facts.Domain == "api.example.test" {
					return routing.TruthTrue
				}
				return routing.TruthFalse
			case consts.Function_Port:
				return routing.TruthTrue
			default:
				return routing.TruthFalse
			}
		},
	)
	if err != nil {
		t.Fatalf("ResumeFacts() error = %v", err)
	}
	if resumed.State != routing.DecisionResolved || resumed.RuleIndex != 0 {
		t.Fatalf("resumed evaluation = %+v, want resolved domain rule", resumed)
	}
}

func newPolicyFactsCorpusEvaluator(t *testing.T, fixture CorpusFixture, snapshot *routing.PolicySnapshot) func(CorpusInput, routing.PolicyFacts) routing.PolicyEvaluation {
	t.Helper()
	predicateMatchers := make(map[phase2PredicateKey]*phase2PredicateMatcher)

	return func(input CorpusInput, facts routing.PolicyFacts) routing.PolicyEvaluation {
		t.Helper()
		evaluation, err := snapshot.EvaluateFacts(facts, func(group routing.PredicateGroup, observed routing.PolicyFacts) routing.Truth {
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
			matchInput := input
			if observed.DomainKnown {
				matchInput.Domain = observed.Domain
			}
			truth, truthErr := matcher.truth(matchInput)
			if truthErr != nil {
				t.Fatalf("evaluate predicate group %+v: %v", group, truthErr)
				return routing.TruthFalse
			}
			return truth
		})
		if err != nil {
			t.Fatalf("EvaluateFacts() error = %v", err)
		}
		return evaluation
	}
}
