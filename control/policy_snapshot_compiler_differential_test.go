/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestCompiledPolicyPlansMatchLegacyBuilderCorpus holds the legacy matcher
// builder authoritative while checking that PolicySnapshot.Compile produces
// equivalent kernel and userspace plans for every Phase 0 routing fixture.
// The comparison happens before BuildUserspace releases the builder's lowered
// state, so it covers the physical match-set order as well as replay results.
func TestCompiledPolicyPlansMatchLegacyBuilderCorpus(t *testing.T) {
	for _, fixture := range RoutingCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
			require.NoError(t, err)

			snapshot, err := routing.NewPolicySnapshot(37, program)
			require.NoError(t, err)

			compiled, err := snapshot.Compile(logrus.New(), fixture.OutboundIDs)
			require.NoError(t, err)
			require.Equal(t, snapshot.Epoch(), compiled.Epoch())
			require.Equal(t, snapshot.Hash(), compiled.SourceHash())
			require.Equal(t, legacyCompiledPolicyOutboundIDs(fixture.OutboundIDs), compiled.OutboundIDs())

			snapshotProgram, err := snapshot.CloneProgram()
			require.NoError(t, err)
			builder, err := NewRoutingMatcherBuilderFromProgram(
				logrus.New(), snapshotProgram, fixture.OutboundIDs, nil,
			)
			require.NoError(t, err)

			legacyKernelPlan := legacyKernelPlanFromBuilder(t, builder)
			legacyUserspacePlan := legacyUserspacePlanFromBuilder(t, builder)
			require.Equal(t, legacyKernelPlan, compiled.KernelPlan())
			require.Equal(t, legacyUserspacePlan, compiled.UserspacePlan())

			compiledBuilder, err := NewRoutingMatcherBuilderFromCompiledPolicy(logrus.New(), compiled, nil)
			require.NoError(t, err)
			require.Equal(t, legacyKernelPlan, legacyKernelPlanFromBuilder(t, compiledBuilder))
			require.Equal(t, legacyUserspacePlan, legacyUserspacePlanFromBuilder(t, compiledBuilder))

			legacyMatcher, err := builder.BuildUserspace()
			require.NoError(t, err)
			compiledMatcher, err := compiledBuilder.BuildUserspace()
			require.NoError(t, err)
			Replay(t, legacyMatcher, fixture)
			Replay(t, compiledMatcher, fixture)
		})
	}
}

func legacyKernelPlanFromBuilder(t *testing.T, builder *RoutingMatcherBuilder) routing.CompiledPolicyPlan {
	t.Helper()
	plan := legacyCompiledPolicyPlanBase(builder)
	domains := legacyDomainSetsByMatchIndex(t, builder)
	plan.Matches = make([]routing.LoweredMatch, len(builder.rules))

	for index, raw := range builder.rules {
		match := routing.LoweredMatch{
			Type:     consts.MatchType(raw.Type),
			Not:      raw.Not != 0,
			Outbound: consts.OutboundIndex(raw.Outbound),
			Mark:     raw.Mark,
			Must:     raw.Must != 0,
		}
		populateLegacyPlanMatch(t, &match, index, raw.Value, domains)
		plan.Matches[index] = match
	}
	return plan
}

func legacyUserspacePlanFromBuilder(t *testing.T, builder *RoutingMatcherBuilder) routing.CompiledPolicyPlan {
	t.Helper()
	require.Equal(t, len(builder.rules), len(builder.compiledRules))

	plan := legacyCompiledPolicyPlanBase(builder)
	domains := legacyDomainSetsByMatchIndex(t, builder)
	plan.Matches = make([]routing.LoweredMatch, len(builder.compiledRules))

	for index, raw := range builder.compiledRules {
		match := routing.LoweredMatch{
			Type:     raw.matchType,
			Not:      raw.not,
			Outbound: raw.outbound,
			Mark:     raw.mark,
			Must:     raw.must,
		}
		switch raw.matchType {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			match.PrefixSetIndex = raw.lpmIndex
		case consts.MatchType_Port, consts.MatchType_SourcePort:
			match.PortStart = raw.portStart
			match.PortEnd = raw.portEnd
		case consts.MatchType_IpVersion, consts.MatchType_L4Proto:
			match.Mask = raw.mask
		case consts.MatchType_ProcessName:
			match.ProcessName = raw.pname
		case consts.MatchType_Dscp:
			match.DSCP = raw.dscp
		case consts.MatchType_DomainSet:
			populateLegacyDomainPlanMatch(t, &match, index, domains)
		case consts.MatchType_Fallback:
		default:
			t.Fatalf("unknown legacy userspace match type %v at index %d", raw.matchType, index)
		}
		plan.Matches[index] = match
	}
	return plan
}

func legacyCompiledPolicyPlanBase(builder *RoutingMatcherBuilder) routing.CompiledPolicyPlan {
	plan := routing.CompiledPolicyPlan{
		PrefixSets:                 make([][]netip.Prefix, len(builder.simulatedLpmTries)),
		DeduplicatedPrefixSetCount: len(builder.lpmDedup),
		PacketMetadataSensitive:    builder.UsesPacketMetadataRouting(),
	}
	if len(builder.predicateGroups) > 0 {
		plan.PredicateGroups = make([]routing.PredicateGroupSpan, len(builder.predicateGroups))
		for index, group := range builder.predicateGroups {
			plan.PredicateGroups[index] = routing.PredicateGroupSpan{
				Name:  group.name,
				Key:   group.key,
				Not:   group.not,
				Start: group.start,
				End:   group.end,
			}
		}
	}
	for index, prefixes := range builder.simulatedLpmTries {
		plan.PrefixSets[index] = append([]netip.Prefix(nil), prefixes...)
	}
	for outbound := range builder.GetReferencedOutbounds() {
		plan.ReferencedOutbounds = append(plan.ReferencedOutbounds, outbound)
	}
	sort.Strings(plan.ReferencedOutbounds)
	return plan
}

func legacyDomainSetsByMatchIndex(t *testing.T, builder *RoutingMatcherBuilder) map[int]routing.DomainSet {
	t.Helper()
	domains := make(map[int]routing.DomainSet, len(builder.simulatedDomainSet))
	for _, domainSet := range builder.simulatedDomainSet {
		if _, exists := domains[domainSet.RuleIndex]; exists {
			t.Fatalf("duplicate legacy domain set at match index %d", domainSet.RuleIndex)
		}
		domains[domainSet.RuleIndex] = domainSet
	}
	return domains
}

func populateLegacyPlanMatch(
	t *testing.T,
	match *routing.LoweredMatch,
	index int,
	value [16]uint8,
	domains map[int]routing.DomainSet,
) {
	t.Helper()
	switch match.Type {
	case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
		match.PrefixSetIndex = binary.LittleEndian.Uint32(value[:4])
	case consts.MatchType_Port, consts.MatchType_SourcePort:
		match.PortStart, match.PortEnd = ParsePortRange(value[:])
	case consts.MatchType_IpVersion, consts.MatchType_L4Proto:
		match.Mask = value[0]
	case consts.MatchType_ProcessName:
		copy(match.ProcessName[:], value[:])
	case consts.MatchType_Dscp:
		match.DSCP = value[0]
	case consts.MatchType_DomainSet:
		populateLegacyDomainPlanMatch(t, match, index, domains)
	case consts.MatchType_Fallback:
	default:
		t.Fatalf("unknown legacy kernel match type %v at index %d", match.Type, index)
	}
}

func populateLegacyDomainPlanMatch(
	t *testing.T,
	match *routing.LoweredMatch,
	index int,
	domains map[int]routing.DomainSet,
) {
	t.Helper()
	domainSet, ok := domains[index]
	if !ok {
		t.Fatalf("missing legacy domain set at match index %d", index)
	}
	match.DomainKey = domainSet.Key
	match.Domains = append([]string(nil), domainSet.Domains...)
}

func legacyCompiledPolicyOutboundIDs(outboundName2ID map[string]uint8) []routing.OutboundID {
	outbounds := make([]routing.OutboundID, 0, len(outboundName2ID))
	for name, id := range outboundName2ID {
		outbounds = append(outbounds, routing.OutboundID{
			Name: name,
			ID:   consts.OutboundIndex(id),
		})
	}
	sort.Slice(outbounds, func(i, j int) bool {
		return outbounds[i].Name < outbounds[j].Name
	})
	return outbounds
}
