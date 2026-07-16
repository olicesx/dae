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

// TestPhase2ProductionMatcherSnapshotCorpusDifferential compares the
// authoritative ControlPlane.Route path with PolicySnapshot.EvaluateGroups.
// The snapshot resolver reads the same live RoutingMatcher predicate data; it
// does not construct an isolated matcher for every predicate group.
func TestPhase2ProductionMatcherSnapshotCorpusDifferential(t *testing.T) {
	for _, fixture := range RoutingCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
			if err != nil {
				t.Fatalf("NewNormalizedProgram() error = %v", err)
			}
			snapshot, err := routing.NewPolicySnapshot(61, program)
			if err != nil {
				t.Fatalf("NewPolicySnapshot() error = %v", err)
			}

			t.Run("program", func(t *testing.T) {
				snapshotProgram, err := snapshot.CloneProgram()
				if err != nil {
					t.Fatalf("CloneProgram() error = %v", err)
				}
				builder, err := NewRoutingMatcherBuilderFromProgram(logrus.New(), snapshotProgram, fixture.OutboundIDs, nil)
				if err != nil {
					t.Fatalf("NewRoutingMatcherBuilderFromProgram() error = %v", err)
				}
				matcher, err := builder.BuildUserspace()
				if err != nil {
					t.Fatalf("BuildUserspace() error = %v", err)
				}
				assertPhase2MatcherSnapshotDifferential(t, fixture, snapshot, matcher)
			})

			t.Run("compiled_policy", func(t *testing.T) {
				compiled, err := snapshot.Compile(logrus.New(), fixture.OutboundIDs)
				if err != nil {
					t.Fatalf("Compile() error = %v", err)
				}
				builder, err := NewRoutingMatcherBuilderFromCompiledPolicy(logrus.New(), compiled, nil)
				if err != nil {
					t.Fatalf("NewRoutingMatcherBuilderFromCompiledPolicy() error = %v", err)
				}
				matcher, err := builder.BuildUserspace()
				if err != nil {
					t.Fatalf("BuildUserspace() error = %v", err)
				}
				assertPhase2MatcherSnapshotDifferential(t, fixture, snapshot, matcher)
			})
		})
	}
}

func assertPhase2MatcherSnapshotDifferential(t *testing.T, fixture CorpusFixture, snapshot *routing.PolicySnapshot, matcher *RoutingMatcher) {
	t.Helper()
	plane := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			policySnapshot: snapshot,
			routingMatcher: matcher,
		},
	}

	for _, tc := range fixture.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			legacyOutbound, legacyMark, legacyMust, err := plane.Route(
				tc.Input.Src,
				tc.Input.Dst,
				tc.Input.Domain,
				tc.Input.L4Proto,
				&bpfRoutingResult{
					Pname: tc.Input.ProcessName,
					Dscp:  tc.Input.Dscp,
					Mac:   tc.Input.Mac,
				},
			)
			if err != nil {
				t.Fatalf("ControlPlane.Route() error = %v", err)
			}

			facts, err := matcher.newFacts(
				tc.Input.Src.Addr().As16(),
				tc.Input.Dst.Addr().As16(),
				tc.Input.Src.Port(),
				tc.Input.Dst.Port(),
				ipVersionForAddr(tc.Input.Dst.Addr()),
				tc.Input.L4Proto,
				tc.Input.Domain,
				tc.Input.ProcessName,
				tc.Input.Dscp,
				corpusMAC16(tc.Input.Mac),
			)
			if err != nil {
				t.Fatalf("newFacts() error = %v", err)
			}
			resolver := newRoutingMatcherGroupResolver(matcher, facts)
			evaluation, err := snapshot.EvaluateGroups(resolver.Resolve)
			if err != nil {
				t.Fatalf("EvaluateGroups() error = %v", err)
			}
			if err := resolver.Err(); err != nil {
				t.Fatalf("live predicate resolver error = %v", err)
			}
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
				t.Fatalf("outbound %q is absent from fixture IDs", outbound.Name)
			}

			if got := uint8(legacyOutbound); got != outboundID || outbound.Mark != legacyMark || outbound.Must != legacyMust {
				t.Fatalf(
					"snapshot tuple = (%d,%d,%v), legacy tuple = (%d,%d,%v)",
					outboundID,
					outbound.Mark,
					outbound.Must,
					legacyOutbound,
					legacyMark,
					legacyMust,
				)
			}
		})
	}
}

func corpusMAC16(mac [6]uint8) [16]uint8 {
	var mac16 [16]uint8
	copy(mac16[10:], mac[:])
	return mac16
}
