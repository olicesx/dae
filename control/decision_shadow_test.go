/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

// TestDecisionShadowMatchesLegacyRoutingCorpus keeps RoutingMatcher.Match
// authoritative while proving that every complete corpus result has an
// equivalent immutable Decision. The adapter is intentionally not wired into
// ControlPlane.Route or any forwarding path.
func TestDecisionShadowMatchesLegacyRoutingCorpus(t *testing.T) {
	const epoch = routing.PolicyEpoch(31)

	for _, fixture := range RoutingCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
			if err != nil {
				t.Fatalf("NewNormalizedProgram() error = %v", err)
			}
			snapshot, err := routing.NewPolicySnapshot(epoch, program)
			if err != nil {
				t.Fatalf("NewPolicySnapshot() error = %v", err)
			}
			matcher := fixture.BuildMatcher(t)
			evaluate := newPhase2CorpusPolicyEvaluator(t, fixture, snapshot)

			for _, tc := range fixture.Cases {
				tc := tc
				t.Run(tc.Name, func(t *testing.T) {
					outbound, mark, must, err := matchCorpusInput(matcher, tc.Input)
					if err != nil {
						t.Fatalf("legacy Match() error = %v", err)
					}

					evidence := evidenceForCorpusInput(tc.Input)
					facts := executionFactsForCorpusInput(tc.Input)
					evaluation := evaluate(tc.Input)
					if evaluation.State != routing.DecisionResolved {
						t.Fatalf("policy evaluation = %+v, want resolved complete-fact result", evaluation)
					}
					decision, err := AdaptLegacyRouteOutcome(snapshot, evaluation, LegacyRouteOutcome{
						Outbound: outbound,
						Mark:     mark,
						Must:     must,
					}, facts, evidence)
					if err != nil {
						t.Fatalf("AdaptLegacyRouteOutcome() error = %v", err)
					}
					if err := decision.Validate(); err != nil {
						t.Fatalf("decision.Validate() error = %v", err)
					}
					if decision.State != routing.DecisionResolved {
						t.Fatalf("decision state = %v, want resolved", decision.State)
					}
					if decision.Epoch != epoch {
						t.Fatalf("decision epoch = %d, want %d", decision.Epoch, epoch)
					}
					if decision.Outbound != outbound || decision.Mark != mark || decision.Must != must {
						t.Fatalf("decision tuple = (%v, %d, %v), legacy tuple = (%v, %d, %v)",
							decision.Outbound, decision.Mark, decision.Must, outbound, mark, must)
					}
					if decision.Evidence != evidence {
						t.Fatalf("decision evidence = %v, want %v", decision.Evidence, evidence)
					}
					if decision.Rule.RuleIndex != evaluation.RuleIndex || decision.Rule.RuleCount != snapshot.RuleCount() {
						t.Fatalf("decision rule location = %+v, evaluation = %+v, rule count = %d",
							decision.Rule, evaluation, snapshot.RuleCount())
					}
					if decision.Rule.IsFallback() != (evaluation.RuleIndex == snapshot.RuleCount()) {
						t.Fatalf("decision fallback = %v, evaluation rule index = %d, rule count = %d",
							decision.Rule.IsFallback(), evaluation.RuleIndex, snapshot.RuleCount())
					}
					wantBinding, err := routing.BindingProfileFor(outbound)
					if err != nil {
						t.Fatalf("BindingProfileFor(%v) error = %v", outbound, err)
					}
					if decision.Binding != wantBinding {
						t.Fatalf("decision binding = %v, want %v", decision.Binding, wantBinding)
					}
					if want := expectedExecutionForLegacyCorpus(outbound, mark, must, facts); decision.Execution != want {
						t.Fatalf("decision execution = %v, want %v", decision.Execution, want)
					}
				})
			}
		})
	}
}

func TestAdaptLegacyRouteOutcomeSeparatesPolicyAndExecution(t *testing.T) {
	program, err := routing.NewNormalizedProgram(nil, "direct")
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	snapshot, err := routing.NewPolicySnapshot(7, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	evaluation := routing.PolicyEvaluation{
		Epoch:     snapshot.Epoch(),
		State:     routing.DecisionResolved,
		RuleIndex: snapshot.RuleCount(),
	}

	tests := []struct {
		name      string
		outcome   LegacyRouteOutcome
		facts     LegacyRouteExecutionFacts
		wantExec  routing.ExecutionRequirement
		wantError bool
	}{
		{
			name:     "unmarked_direct_uses_kernel",
			outcome:  LegacyRouteOutcome{Outbound: consts.OutboundDirect},
			facts:    LegacyRouteExecutionFacts{DstPort: 443, L4Proto: consts.L4ProtoType_TCP},
			wantExec: routing.ExecutionKernel,
		},
		{
			name:     "tcp_dns_direct_uses_userspace",
			outcome:  LegacyRouteOutcome{Outbound: consts.OutboundDirect},
			facts:    LegacyRouteExecutionFacts{DstPort: 53, L4Proto: consts.L4ProtoType_TCP},
			wantExec: routing.ExecutionUserspace,
		},
		{
			name:     "udp_dns_direct_uses_userspace",
			outcome:  LegacyRouteOutcome{Outbound: consts.OutboundDirect},
			facts:    LegacyRouteExecutionFacts{DstPort: 53, L4Proto: consts.L4ProtoType_UDP},
			wantExec: routing.ExecutionUserspace,
		},
		{
			name:     "must_direct_dns_uses_kernel",
			outcome:  LegacyRouteOutcome{Outbound: consts.OutboundDirect, Must: true},
			facts:    LegacyRouteExecutionFacts{DstPort: 53, L4Proto: consts.L4ProtoType_TCP},
			wantExec: routing.ExecutionKernel,
		},
		{
			name:     "marked_direct_uses_userspace",
			outcome:  LegacyRouteOutcome{Outbound: consts.OutboundDirect, Mark: 42, Must: true},
			wantExec: routing.ExecutionUserspace,
		},
		{
			name:     "block_uses_kernel",
			outcome:  LegacyRouteOutcome{Outbound: consts.OutboundBlock},
			wantExec: routing.ExecutionKernel,
		},
		{
			name:     "proxy_uses_userspace",
			outcome:  LegacyRouteOutcome{Outbound: consts.OutboundUserDefinedMin},
			wantExec: routing.ExecutionUserspace,
		},
		{
			name:      "reroute_is_not_terminal",
			outcome:   LegacyRouteOutcome{Outbound: consts.OutboundControlPlaneRouting},
			wantError: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			decision, err := AdaptLegacyRouteOutcome(snapshot, evaluation, tc.outcome, tc.facts, routing.EvidenceDNSAssociation)
			if tc.wantError {
				if err == nil {
					t.Fatal("AdaptLegacyRouteOutcome() error = nil, want non-terminal outcome rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("AdaptLegacyRouteOutcome() error = %v", err)
			}
			if decision.Execution != tc.wantExec {
				t.Fatalf("decision execution = %v, want %v", decision.Execution, tc.wantExec)
			}
			if decision.Outbound != tc.outcome.Outbound || decision.Mark != tc.outcome.Mark || decision.Must != tc.outcome.Must {
				t.Fatalf("decision = %+v, outcome = %+v", decision, tc.outcome)
			}
			if decision.Evidence != routing.EvidenceDNSAssociation {
				t.Fatalf("decision evidence = %v, want DNS association", decision.Evidence)
			}
			if !decision.Rule.IsFallback() {
				t.Fatalf("decision rule location = %+v, want fallback", decision.Rule)
			}
		})
	}
}

func TestAdaptLegacyRouteOutcomeRejectsMismatchedPolicyEvaluation(t *testing.T) {
	program, err := routing.NewNormalizedProgram(nil, "direct")
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	snapshot, err := routing.NewPolicySnapshot(7, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}

	_, err = AdaptLegacyRouteOutcome(
		snapshot,
		routing.PolicyEvaluation{Epoch: snapshot.Epoch() + 1, State: routing.DecisionResolved, RuleIndex: 0},
		LegacyRouteOutcome{Outbound: consts.OutboundDirect},
		LegacyRouteExecutionFacts{DstPort: 443, L4Proto: consts.L4ProtoType_TCP},
		routing.EvidenceNone,
	)
	if err == nil {
		t.Fatal("AdaptLegacyRouteOutcome() error = nil, want epoch mismatch")
	}
}

func evidenceForCorpusInput(input CorpusInput) routing.EvidenceSource {
	if input.Domain == "" {
		return routing.EvidenceNone
	}
	// Corpus domain facts are complete observations. Their source is supplied
	// only to exercise provenance preservation; the adapter does not infer it.
	return routing.EvidenceTLSSNI
}

func executionFactsForCorpusInput(input CorpusInput) LegacyRouteExecutionFacts {
	return LegacyRouteExecutionFacts{
		DstPort: input.Dst.Port(),
		L4Proto: input.L4Proto,
	}
}

func expectedExecutionForLegacyCorpus(outbound consts.OutboundIndex, mark uint32, must bool, facts LegacyRouteExecutionFacts) routing.ExecutionRequirement {
	if outbound == consts.OutboundDirect && mark == 0 && (must || !facts.isDNSQuery()) || outbound == consts.OutboundBlock {
		return routing.ExecutionKernel
	}
	return routing.ExecutionUserspace
}
