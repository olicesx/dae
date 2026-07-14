/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
)

// TestPhase0RoutingCorpus_LegacyBaseline runs the Phase 0 routing corpus
// against the legacy userspace RoutingMatcher and asserts that each case
// produces its declared expected (outbound, mark, must) tuple.
//
// This test pins the legacy baseline. Future phases (PolicySnapshot,
// three-valued evaluation, Decision shadow) MUST produce byte-identical
// results against the same corpus, otherwise the refactor's Semantic Contract
// is violated and the phase cannot become authoritative.
//
// See docs/en/semantic-architecture-refactor-plan.md Phase 0 acceptance: every
// routing function, boolean combination, priority position, mark, must rule,
// fallback, and reserved outbound has fixture coverage.
func TestPhase0RoutingCorpus_LegacyBaseline(t *testing.T) {
	for _, fixture := range RoutingCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			matcher := fixture.BuildMatcher(t)
			Replay(t, matcher, fixture)
		})
	}
}

// TestPhase0RoutingCorpus_PolicySnapshotEquivalent runs the same corpus against
// a RoutingMatcher built from a PolicySnapshot clone of the same program and
// asserts byte-identical results. This is the Phase 1 acceptance check
// ("Lowering a snapshot produces the same legacy kernel and userspace plans")
// applied to the full corpus, not just a hand-picked domain case.
//
// If this test fails, PolicySnapshot is not a faithful immutable view of the
// normalized program and Phase 1 cannot become authoritative.
func TestPhase0RoutingCorpus_PolicySnapshotEquivalent(t *testing.T) {
	for _, fixture := range RoutingCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
			if err != nil {
				t.Fatalf("%s: NewNormalizedProgram() error = %v", fixture.Name, err)
			}
			snapshot, err := routing.NewPolicySnapshot(1, program)
			if err != nil {
				t.Fatalf("%s: NewPolicySnapshot() error = %v", fixture.Name, err)
			}
			snapshotProgram, err := snapshot.CloneProgram()
			if err != nil {
				t.Fatalf("%s: CloneProgram() error = %v", fixture.Name, err)
			}
			builder, err := NewRoutingMatcherBuilderFromProgram(
				logrus.New(), snapshotProgram, fixture.OutboundIDs, nil,
			)
			if err != nil {
				t.Fatalf("%s: NewRoutingMatcherBuilderFromProgram() error = %v", fixture.Name, err)
			}
			matcher, err := builder.BuildUserspace()
			if err != nil {
				t.Fatalf("%s: BuildUserspace() error = %v", fixture.Name, err)
			}
			Replay(t, matcher, fixture)
		})
	}
}
