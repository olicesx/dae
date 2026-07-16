/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestPolicySnapshotEvaluateFactsDefersBeforeLaterPortRule(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "domain",
				Params: []*config_parser.Param{{Key: "suffix", Val: "example.test"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "port",
				Params: []*config_parser.Param{{Val: "443"}},
			}},
			Outbound: config_parser.Function{Name: "direct"},
		},
	})

	missingDomain, err := snapshot.EvaluateFacts(PolicyFacts{}, func(group PredicateGroup, _ PolicyFacts) Truth {
		if group.Name == "domain" {
			t.Fatal("domain resolver was called without domain evidence")
		}
		return TruthTrue
	})
	if err != nil {
		t.Fatalf("EvaluateFacts() error = %v", err)
	}
	if missingDomain.State != DecisionDeferred || missingDomain.RuleIndex != 0 {
		t.Fatalf("missing-domain evaluation = %+v, want deferred rule 0", missingDomain)
	}
	if missingDomain.Continuation.SnapshotHash != snapshot.Hash() || missingDomain.Continuation.InstructionID != 0 {
		t.Fatalf("continuation = %+v, want snapshot-bound predicate instruction", missingDomain.Continuation)
	}
	if err := snapshot.ValidateContinuation(missingDomain.Continuation); err != nil {
		t.Fatalf("ValidateContinuation() error = %v", err)
	}
	forged := missingDomain.Continuation
	forged.InstructionID = -1
	if err := snapshot.ValidateContinuation(forged); err == nil {
		t.Fatal("ValidateContinuation() error = nil, want missing instruction rejection")
	}

	matched, err := snapshot.EvaluateFacts(PolicyFacts{DomainKnown: true, Domain: "api.example.test"}, domainAndPortFactsResolver)
	if err != nil {
		t.Fatalf("matched EvaluateFacts() error = %v", err)
	}
	if matched.State != DecisionResolved || matched.RuleIndex != 0 {
		t.Fatalf("matched evaluation = %+v, want resolved domain rule", matched)
	}
	matchedOutbound, err := snapshot.OutboundFor(matched)
	if err != nil {
		t.Fatalf("matched OutboundFor() error = %v", err)
	}
	if matchedOutbound.Name != "proxy" {
		t.Fatalf("matched outbound = %q, want proxy", matchedOutbound.Name)
	}

	missed, err := snapshot.EvaluateFacts(PolicyFacts{DomainKnown: true, Domain: "other.test"}, domainAndPortFactsResolver)
	if err != nil {
		t.Fatalf("missed EvaluateFacts() error = %v", err)
	}
	if missed.State != DecisionResolved || missed.RuleIndex != 1 {
		t.Fatalf("missed evaluation = %+v, want resolved later port rule", missed)
	}
}

func TestPolicySnapshotEvaluateFactsKeepsNegatedDomainUnknown(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "domain",
				Not:    true,
				Params: []*config_parser.Param{{Key: "suffix", Val: "example.test"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "port",
				Params: []*config_parser.Param{{Val: "443"}},
			}},
			Outbound: config_parser.Function{Name: "direct"},
		},
	})

	unknown, err := snapshot.EvaluateFacts(PolicyFacts{}, domainAndPortFactsResolver)
	if err != nil {
		t.Fatalf("missing-domain EvaluateFacts() error = %v", err)
	}
	if unknown.State != DecisionDeferred || unknown.RuleIndex != 0 {
		t.Fatalf("missing-domain evaluation = %+v, want deferred negated domain rule", unknown)
	}

	knownMatch, err := snapshot.EvaluateFacts(PolicyFacts{DomainKnown: true, Domain: "api.example.test"}, domainAndPortFactsResolver)
	if err != nil {
		t.Fatalf("known-match EvaluateFacts() error = %v", err)
	}
	if knownMatch.RuleIndex != 1 {
		t.Fatalf("known matching domain evaluation = %+v, want later direct rule", knownMatch)
	}

	knownMiss, err := snapshot.EvaluateFacts(PolicyFacts{DomainKnown: true, Domain: "other.test"}, domainAndPortFactsResolver)
	if err != nil {
		t.Fatalf("known-miss EvaluateFacts() error = %v", err)
	}
	if knownMiss.RuleIndex != 0 {
		t.Fatalf("known non-matching domain evaluation = %+v, want negated domain rule", knownMiss)
	}
}

func TestPolicySnapshotEvaluateContinuationTracksFirstUnknownFunction(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{
			{Name: "port", Params: []*config_parser.Param{{Val: "443"}}},
			{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: "example.test"}}},
		},
		Outbound: config_parser.Function{Name: "proxy"},
	}})

	evaluation, err := snapshot.Evaluate(func(_ int, functionIndex int) Truth {
		if functionIndex == 0 {
			return TruthTrue
		}
		return TruthUnknown
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if evaluation.State != DecisionDeferred || evaluation.Continuation.InstructionID != 1 {
		t.Fatalf("evaluation = %+v, want continuation at second predicate instruction", evaluation)
	}
	if err := snapshot.ValidateContinuation(evaluation.Continuation); err != nil {
		t.Fatalf("ValidateContinuation() error = %v", err)
	}
}

func TestPolicySnapshotResumeFactsValidatesSnapshotAndPreservesMustRules(t *testing.T) {
	snapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "port",
				Params: []*config_parser.Param{{Val: "443"}},
			}},
			Outbound: config_parser.Function{Name: "must_rules"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   "domain",
				Params: []*config_parser.Param{{Key: "suffix", Val: "example.test"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	})

	deferred, err := snapshot.EvaluateFacts(PolicyFacts{}, domainAndPortFactsResolver)
	if err != nil {
		t.Fatalf("EvaluateFacts() error = %v", err)
	}
	if deferred.State != DecisionDeferred || deferred.RuleIndex != 1 || !deferred.inheritedMust {
		t.Fatalf("deferred evaluation = %+v, want deferred domain after must-rules", deferred)
	}

	resumed, err := snapshot.ResumeFacts(deferred.Continuation, PolicyFacts{DomainKnown: true, Domain: "other.test"}, domainAndPortFactsResolver)
	if err != nil {
		t.Fatalf("ResumeFacts() error = %v", err)
	}
	if resumed.State != DecisionResolved || resumed.RuleIndex != snapshot.RuleCount() || !resumed.inheritedMust {
		t.Fatalf("resumed evaluation = %+v, want fallback with inherited must", resumed)
	}
	outbound, err := snapshot.OutboundFor(resumed)
	if err != nil {
		t.Fatalf("resumed OutboundFor() error = %v", err)
	}
	parsed, err := ParseOutbound(outbound)
	if err != nil {
		t.Fatalf("ParseOutbound() error = %v", err)
	}
	if parsed.Name != "direct" || !parsed.Must {
		t.Fatalf("resumed outbound = %+v, want direct with inherited must", parsed)
	}

	wrongSnapshot := newPolicyEvaluationSnapshot(t, []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{Name: "port", Params: []*config_parser.Param{{Val: "443"}}}},
		Outbound:     config_parser.Function{Name: "proxy"},
	}})
	if _, err := wrongSnapshot.ResumeFacts(deferred.Continuation, PolicyFacts{}, domainAndPortFactsResolver); err == nil {
		t.Fatal("ResumeFacts() error = nil, want snapshot identity rejection")
	}
}

func domainAndPortFactsResolver(group PredicateGroup, facts PolicyFacts) Truth {
	switch group.Name {
	case "domain":
		if strings.HasSuffix(facts.Domain, group.Values[0]) {
			return TruthTrue
		}
		return TruthFalse
	case "port":
		return TruthTrue
	default:
		return TruthFalse
	}
}
