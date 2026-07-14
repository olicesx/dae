/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

// Truth represents a predicate result when required routing facts may not yet
// be available. Unknown must remain distinct from false so a later fact cannot
// cause an earlier routing rule to be skipped.
type Truth uint8

const (
	TruthUnknown Truth = iota
	TruthFalse
	TruthTrue
)

// Not returns the three-valued negation of v.
func (v Truth) Not() Truth {
	switch v {
	case TruthTrue:
		return TruthFalse
	case TruthFalse:
		return TruthTrue
	default:
		return TruthUnknown
	}
}

// And combines predicate values using strong Kleene three-valued logic.
func And(values ...Truth) Truth {
	unknown := false
	for _, value := range values {
		switch value {
		case TruthFalse:
			return TruthFalse
		case TruthUnknown:
			unknown = true
		}
	}
	if unknown {
		return TruthUnknown
	}
	return TruthTrue
}

// Or combines predicate values using strong Kleene three-valued logic.
func Or(values ...Truth) Truth {
	unknown := false
	for _, value := range values {
		switch value {
		case TruthTrue:
			return TruthTrue
		case TruthUnknown:
			unknown = true
		}
	}
	if unknown {
		return TruthUnknown
	}
	return TruthFalse
}

// RuleResolution describes whether ordered rule evaluation selected a rule or
// must wait for facts needed by an earlier rule.
type RuleResolution struct {
	RuleIndex int
	Terminal  bool
}

// ResolveOrderedRules returns the first terminal true rule. If an earlier
// rule is unknown, it returns that rule as a non-terminal continuation point.
// Rules after an unknown rule cannot safely determine the routing result.
func ResolveOrderedRules(ruleResults []Truth) RuleResolution {
	for index, result := range ruleResults {
		switch result {
		case TruthTrue:
			return RuleResolution{RuleIndex: index, Terminal: true}
		case TruthUnknown:
			return RuleResolution{RuleIndex: index}
		}
	}
	return RuleResolution{RuleIndex: len(ruleResults), Terminal: true}
}
