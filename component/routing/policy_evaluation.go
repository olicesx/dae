/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/mohae/deepcopy"
)

// PredicateResult resolves one normalized function within a policy snapshot.
// The returned value is for the positive function; PolicySnapshot applies the
// function's configured negation before evaluating the containing rule.
type PredicateResult func(ruleIndex, functionIndex int) Truth

// PolicyEvaluation is the ordered-rule result before an outbound is adapted to
// a concrete data-plane action. RuleIndex equal to RuleCount denotes fallback.
type PolicyEvaluation struct {
	Epoch        PolicyEpoch
	State        DecisionState
	RuleIndex    int
	Continuation Continuation
}

// Evaluate applies strong Kleene logic to the immutable normalized program.
// A later true rule cannot bypass an earlier unknown rule, while an unknown
// predicate within a rule is still defeated by a false predicate in that rule.
func (s *PolicySnapshot) Evaluate(resolve PredicateResult) (PolicyEvaluation, error) {
	if s == nil || s.program == nil {
		return PolicyEvaluation{}, fmt.Errorf("nil policy snapshot")
	}
	if resolve == nil {
		return PolicyEvaluation{}, fmt.Errorf("nil predicate resolver")
	}

	for ruleIndex, rule := range s.program.Rules {
		// The legacy lowerer emits no match set for an empty rule, so it has no
		// observable routing effect and must not become an implicit true rule.
		if len(rule.AndFunctions) == 0 {
			continue
		}
		ruleResult := TruthTrue
		for functionIndex, function := range rule.AndFunctions {
			result := resolve(ruleIndex, functionIndex)
			if function.Not {
				result = result.Not()
			}
			ruleResult = And(ruleResult, result)
			if ruleResult == TruthFalse {
				break
			}
		}

		switch ruleResult {
		case TruthTrue:
			return PolicyEvaluation{
				Epoch:     s.epoch,
				State:     DecisionResolved,
				RuleIndex: ruleIndex,
			}, nil
		case TruthUnknown:
			return PolicyEvaluation{
				Epoch:     s.epoch,
				State:     DecisionDeferred,
				RuleIndex: ruleIndex,
				Continuation: Continuation{
					Epoch:     s.epoch,
					RuleIndex: ruleIndex,
				},
			}, nil
		}
	}

	return PolicyEvaluation{
		Epoch:     s.epoch,
		State:     DecisionResolved,
		RuleIndex: len(s.program.Rules),
	}, nil
}

// OutboundFor returns an independent outbound function for an evaluation
// result. The fallback is selected when evaluation.RuleIndex equals RuleCount.
func (s *PolicySnapshot) OutboundFor(evaluation PolicyEvaluation) (*config_parser.Function, error) {
	if s == nil || s.program == nil {
		return nil, fmt.Errorf("nil policy snapshot")
	}
	if evaluation.Epoch != s.epoch {
		return nil, fmt.Errorf("evaluation epoch %d does not match snapshot epoch %d", evaluation.Epoch, s.epoch)
	}
	if evaluation.State != DecisionResolved {
		return nil, fmt.Errorf("deferred evaluation has no outbound")
	}

	if evaluation.RuleIndex == len(s.program.Rules) {
		fallback, err := config.ParseFunctionOrString(s.program.Fallback)
		if err != nil {
			return nil, fmt.Errorf("parse fallback outbound: %w", err)
		}
		return cloneRoutingFunction(fallback), nil
	}
	if evaluation.RuleIndex < 0 || evaluation.RuleIndex >= len(s.program.Rules) {
		return nil, fmt.Errorf("evaluation rule index out of range: %d", evaluation.RuleIndex)
	}
	return cloneRoutingFunction(&s.program.Rules[evaluation.RuleIndex].Outbound), nil
}

func cloneRoutingFunction(function *config_parser.Function) *config_parser.Function {
	if function == nil {
		return nil
	}
	return deepcopy.Copy(function).(*config_parser.Function)
}
