/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import "testing"

func TestTruthOperators(t *testing.T) {
	tests := []struct {
		name string
		got  Truth
		want Truth
	}{
		{name: "not unknown", got: TruthUnknown.Not(), want: TruthUnknown},
		{name: "not false", got: TruthFalse.Not(), want: TruthTrue},
		{name: "and false dominates unknown", got: And(TruthUnknown, TruthFalse), want: TruthFalse},
		{name: "and unknown", got: And(TruthTrue, TruthUnknown), want: TruthUnknown},
		{name: "or true dominates unknown", got: Or(TruthUnknown, TruthTrue), want: TruthTrue},
		{name: "or unknown", got: Or(TruthFalse, TruthUnknown), want: TruthUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("got %v, want %v", test.got, test.want)
			}
		})
	}
}

func TestResolveOrderedRulesDefersAtEarliestUnknown(t *testing.T) {
	resolution := ResolveOrderedRules([]Truth{TruthUnknown, TruthTrue, TruthTrue})
	if resolution.Terminal || resolution.RuleIndex != 0 {
		t.Fatalf("resolution = %+v, want non-terminal rule 0", resolution)
	}

	resolution = ResolveOrderedRules([]Truth{TruthFalse, TruthTrue, TruthUnknown})
	if !resolution.Terminal || resolution.RuleIndex != 1 {
		t.Fatalf("resolution = %+v, want terminal rule 1", resolution)
	}

	resolution = ResolveOrderedRules([]Truth{TruthFalse, TruthFalse})
	if !resolution.Terminal || resolution.RuleIndex != 2 {
		t.Fatalf("resolution = %+v, want terminal fallback position 2", resolution)
	}
}
