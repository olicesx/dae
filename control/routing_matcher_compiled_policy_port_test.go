/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestCompiledPolicyPortRangeAdapterPreservesUserspaceMatch verifies that a
// port range survives plan lowering and adapter reconstruction.
func TestCompiledPolicyPortRangeAdapterPreservesUserspaceMatch(t *testing.T) {
	fixture := portFixture()
	program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
	require.NoError(t, err)
	snapshot, err := routing.NewPolicySnapshot(1, program)
	require.NoError(t, err)
	policy, err := snapshot.Compile(logrus.New(), fixture.OutboundIDs)
	require.NoError(t, err)

	plan := policy.UserspacePlan()
	require.Len(t, plan.Matches, 2)
	require.Equal(t, uint16(80), plan.Matches[0].PortStart)
	require.Equal(t, uint16(443), plan.Matches[0].PortEnd)

	builder, err := NewRoutingMatcherBuilderFromCompiledPolicy(logrus.New(), policy, nil)
	require.NoError(t, err)
	require.Len(t, builder.compiledRules, 2)
	require.Equal(t, uint16(80), builder.compiledRules[0].portStart)
	require.Equal(t, uint16(443), builder.compiledRules[0].portEnd)

	matcher, err := builder.BuildUserspace()
	require.NoError(t, err)
	Replay(t, matcher, fixture)
}
