/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/mohae/deepcopy"
)

// PredicateResult resolves one normalized function within a policy snapshot.
// The returned value is for the positive function; PolicySnapshot applies the
// function's configured negation before evaluating the containing rule.
//
// EvaluateGroups is the compatibility-oriented alternative for callers that
// need the legacy lowerer's parameter-key grouping behavior.
type PredicateResult func(ruleIndex, functionIndex int) Truth

// PredicateGroup is one parameter-key match set produced by the legacy rule
// lowerer. Values is an independent copy and may be retained or modified by
// the resolver without changing the immutable policy snapshot.
type PredicateGroup struct {
	RuleIndex     int
	FunctionIndex int
	GroupIndex    int
	InstructionID int
	Name          string
	Key           string
	Values        []string
	Not           bool
}

// PredicateGroupResult resolves the positive result of one lowered predicate
// group. EvaluateGroups ORs groups within a function, then applies the
// function's configured negation once.
type PredicateGroupResult func(PredicateGroup) Truth

// PolicyFacts carries explicitly observed facts for shadow policy evaluation.
// DomainKnown distinguishes an unavailable domain observation from a known
// empty/non-matching domain value.
type PolicyFacts struct {
	DomainKnown bool
	Domain      string
	Evidence    EvidenceSource
}

// FactPredicateGroupResult resolves an observed predicate group using the
// current facts. Missing domain evidence is handled by EvaluateFacts before
// this callback is invoked.
type FactPredicateGroupResult func(PredicateGroup, PolicyFacts) Truth

// PolicyEvaluation is the ordered-rule result before an outbound is adapted to
// a concrete data-plane action. RuleIndex equal to RuleCount denotes fallback.
type PolicyEvaluation struct {
	Epoch         PolicyEpoch
	State         DecisionState
	RuleIndex     int
	inheritedMust bool
	Continuation  Continuation
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

	inheritedMust := false
	for ruleIndex, rule := range s.program.Rules {
		// The legacy lowerer emits no match set for an empty rule, so it has no
		// observable routing effect and must not become an implicit true rule.
		if len(rule.AndFunctions) == 0 {
			continue
		}
		ruleResult := TruthTrue
		firstUnknownFunctionIndex := -1
		for functionIndex, function := range rule.AndFunctions {
			result := resolve(ruleIndex, functionIndex)
			if result == TruthUnknown && firstUnknownFunctionIndex == -1 {
				firstUnknownFunctionIndex = functionIndex
			}
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
			if isMustRulesOutbound(rule.Outbound.Name) {
				inheritedMust = true
				continue
			}
			return PolicyEvaluation{
				Epoch:         s.epoch,
				State:         DecisionResolved,
				RuleIndex:     ruleIndex,
				inheritedMust: inheritedMust,
			}, nil
		case TruthUnknown:
			return PolicyEvaluation{
				Epoch:         s.epoch,
				State:         DecisionDeferred,
				RuleIndex:     ruleIndex,
				inheritedMust: inheritedMust,
				Continuation:  s.newContinuation(ruleIndex, s.firstPredicateInstruction(ruleIndex, firstUnknownFunctionIndex)),
			}, nil
		}
	}

	return PolicyEvaluation{
		Epoch:         s.epoch,
		State:         DecisionResolved,
		RuleIndex:     len(s.program.Rules),
		inheritedMust: inheritedMust,
	}, nil
}

// EvaluateGroups applies strong Kleene logic at the same parameter-key group
// boundary used by the legacy lowerer. Groups within one function combine with
// OR, that function's negation applies once, and functions within a rule
// combine with AND. This is the evaluator to use for compatibility shadowing.
func (s *PolicySnapshot) EvaluateGroups(resolve PredicateGroupResult) (PolicyEvaluation, error) {
	if resolve == nil {
		return PolicyEvaluation{}, fmt.Errorf("nil predicate group resolver")
	}
	return s.evaluateGroups(resolve)
}

// EvaluateFacts evaluates predicate groups with explicit observed facts. A
// domain predicate stays Unknown until DomainKnown is true, including when the
// configured predicate is negated. This prevents a later non-domain rule from
// becoming terminal before domain evidence is available.
func (s *PolicySnapshot) EvaluateFacts(facts PolicyFacts, resolve FactPredicateGroupResult) (PolicyEvaluation, error) {
	if resolve == nil {
		return PolicyEvaluation{}, fmt.Errorf("nil fact predicate group resolver")
	}
	return s.evaluateGroups(func(group PredicateGroup) Truth {
		if group.Name == consts.Function_Domain && !facts.DomainKnown {
			return TruthUnknown
		}
		return resolve(group, facts)
	})
}

// ResumeFacts validates a deferred continuation against this immutable
// snapshot, then recomputes from the first rule so inherited must-rules state
// and higher-priority facts remain correct.
func (s *PolicySnapshot) ResumeFacts(continuation Continuation, facts PolicyFacts, resolve FactPredicateGroupResult) (PolicyEvaluation, error) {
	if err := s.ValidateContinuation(continuation); err != nil {
		return PolicyEvaluation{}, err
	}
	return s.EvaluateFacts(facts, resolve)
}

// ResumeGroups validates a deferred continuation and recomputes group results
// from the immutable snapshot. New fact-aware callers should prefer
// ResumeFacts so missing domain evidence is handled automatically.
func (s *PolicySnapshot) ResumeGroups(continuation Continuation, resolve PredicateGroupResult) (PolicyEvaluation, error) {
	if err := s.ValidateContinuation(continuation); err != nil {
		return PolicyEvaluation{}, err
	}
	return s.EvaluateGroups(resolve)
}

// ValidateContinuation verifies that a continuation belongs to this immutable
// snapshot and identifies a predicate instruction in its recorded rule.
func (s *PolicySnapshot) ValidateContinuation(continuation Continuation) error {
	if s == nil || s.program == nil {
		return fmt.Errorf("nil policy snapshot")
	}
	if continuation.Epoch != s.epoch {
		return fmt.Errorf("continuation epoch %d does not match snapshot epoch %d", continuation.Epoch, s.epoch)
	}
	if continuation.SnapshotHash != s.hash {
		return fmt.Errorf("continuation snapshot hash does not match policy snapshot")
	}
	if continuation.RuleIndex < 0 || continuation.RuleIndex >= len(s.program.Rules) {
		return fmt.Errorf("continuation rule index %d is outside policy rules", continuation.RuleIndex)
	}
	if continuation.InstructionID < -1 {
		return fmt.Errorf("continuation instruction %d is invalid", continuation.InstructionID)
	}
	if continuation.InstructionID == -1 && s.predicateGroupCount(continuation.RuleIndex) != 0 {
		return fmt.Errorf("continuation for rule %d omits a predicate instruction", continuation.RuleIndex)
	}
	if continuation.InstructionID >= 0 && s.ruleIndexForPredicateInstruction(continuation.InstructionID) != continuation.RuleIndex {
		return fmt.Errorf("continuation instruction %d does not belong to rule %d", continuation.InstructionID, continuation.RuleIndex)
	}
	return nil
}

func (s *PolicySnapshot) evaluateGroups(resolve PredicateGroupResult) (PolicyEvaluation, error) {
	if s == nil || s.program == nil {
		return PolicyEvaluation{}, fmt.Errorf("nil policy snapshot")
	}

	inheritedMust := false
	for ruleIndex, rule := range s.program.Rules {
		ruleResult := TruthTrue
		groupCount := 0
		firstUnknownInstruction := -1
		for functionIndex, function := range rule.AndFunctions {
			valueGroups, keyOrder := groupParamValuesByKey(function.Params)
			if len(keyOrder) == 0 {
				continue
			}

			groupCount += len(keyOrder)
			functionResult := TruthFalse
			firstUnknownInFunction := -1
			for groupIndex, key := range keyOrder {
				group := PredicateGroup{
					RuleIndex:     ruleIndex,
					FunctionIndex: functionIndex,
					GroupIndex:    groupIndex,
					InstructionID: s.predicateInstructionID(ruleIndex, functionIndex, groupIndex),
					Name:          function.Name,
					Key:           key,
					Values:        append([]string(nil), valueGroups[key]...),
					Not:           function.Not,
				}
				result := resolve(group)
				if result == TruthUnknown && firstUnknownInFunction == -1 {
					firstUnknownInFunction = group.InstructionID
				}
				functionResult = Or(functionResult, result)
				if functionResult == TruthTrue {
					break
				}
			}
			if function.Not {
				functionResult = functionResult.Not()
			}
			if functionResult == TruthUnknown && firstUnknownInstruction == -1 {
				firstUnknownInstruction = firstUnknownInFunction
			}
			ruleResult = And(ruleResult, functionResult)
			if ruleResult == TruthFalse {
				break
			}
		}

		// An empty rule (or one containing only empty functions) emits no
		// match set in the legacy lowerer and therefore has no routing effect.
		if groupCount == 0 {
			continue
		}
		switch ruleResult {
		case TruthTrue:
			if isMustRulesOutbound(rule.Outbound.Name) {
				inheritedMust = true
				continue
			}
			return PolicyEvaluation{
				Epoch:         s.epoch,
				State:         DecisionResolved,
				RuleIndex:     ruleIndex,
				inheritedMust: inheritedMust,
			}, nil
		case TruthUnknown:
			return PolicyEvaluation{
				Epoch:         s.epoch,
				State:         DecisionDeferred,
				RuleIndex:     ruleIndex,
				inheritedMust: inheritedMust,
				Continuation:  s.newContinuation(ruleIndex, firstUnknownInstruction),
			}, nil
		}
	}

	return PolicyEvaluation{
		Epoch:         s.epoch,
		State:         DecisionResolved,
		RuleIndex:     len(s.program.Rules),
		inheritedMust: inheritedMust,
	}, nil
}

func (s *PolicySnapshot) newContinuation(ruleIndex, instructionID int) Continuation {
	return Continuation{
		Epoch:         s.epoch,
		SnapshotHash:  s.hash,
		RuleIndex:     ruleIndex,
		InstructionID: instructionID,
	}
}

func (s *PolicySnapshot) firstPredicateInstruction(ruleIndex, functionIndex int) int {
	if ruleIndex < 0 || ruleIndex >= len(s.program.Rules) {
		return -1
	}
	if functionIndex < 0 || functionIndex >= len(s.program.Rules[ruleIndex].AndFunctions) {
		return -1
	}
	function := s.program.Rules[ruleIndex].AndFunctions[functionIndex]
	_, keyOrder := groupParamValuesByKey(function.Params)
	if len(keyOrder) > 0 {
		return s.predicateInstructionID(ruleIndex, functionIndex, 0)
	}
	return -1
}

func (s *PolicySnapshot) predicateInstructionID(ruleIndex, functionIndex, groupIndex int) int {
	instructionID := 0
	for currentRuleIndex, rule := range s.program.Rules {
		for currentFunctionIndex, function := range rule.AndFunctions {
			_, keyOrder := groupParamValuesByKey(function.Params)
			if currentRuleIndex == ruleIndex && currentFunctionIndex == functionIndex {
				if groupIndex >= 0 && groupIndex < len(keyOrder) {
					return instructionID + groupIndex
				}
				return -1
			}
			instructionID += len(keyOrder)
		}
	}
	return -1
}

func (s *PolicySnapshot) ruleIndexForPredicateInstruction(instructionID int) int {
	if instructionID < 0 {
		return -1
	}
	nextInstructionID := 0
	for ruleIndex, rule := range s.program.Rules {
		for _, function := range rule.AndFunctions {
			_, keyOrder := groupParamValuesByKey(function.Params)
			if instructionID >= nextInstructionID && instructionID < nextInstructionID+len(keyOrder) {
				return ruleIndex
			}
			nextInstructionID += len(keyOrder)
		}
	}
	return -1
}

func (s *PolicySnapshot) predicateGroupCount(ruleIndex int) int {
	count := 0
	for _, function := range s.program.Rules[ruleIndex].AndFunctions {
		_, keyOrder := groupParamValuesByKey(function.Params)
		count += len(keyOrder)
	}
	return count
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
		return applyInheritedMust(cloneRoutingFunction(fallback), evaluation.inheritedMust), nil
	}
	if evaluation.RuleIndex < 0 || evaluation.RuleIndex >= len(s.program.Rules) {
		return nil, fmt.Errorf("evaluation rule index out of range: %d", evaluation.RuleIndex)
	}
	return applyInheritedMust(cloneRoutingFunction(&s.program.Rules[evaluation.RuleIndex].Outbound), evaluation.inheritedMust), nil
}

func isMustRulesOutbound(name string) bool {
	return name == consts.OutboundMustRules.String()
}

func applyInheritedMust(outbound *config_parser.Function, inherited bool) *config_parser.Function {
	if outbound == nil || !inherited {
		return outbound
	}
	for _, param := range outbound.Params {
		if param != nil && param.Key == "" && param.Val == "must" {
			return outbound
		}
	}
	outbound.Params = append(outbound.Params, &config_parser.Param{Val: "must"})
	return outbound
}

func cloneRoutingFunction(function *config_parser.Function) *config_parser.Function {
	if function == nil {
		return nil
	}
	return deepcopy.Copy(function).(*config_parser.Function)
}
