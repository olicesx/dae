/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
)

// NewRoutingMatcherBuilderFromCompiledPolicy adapts an immutable routing plan
// to the legacy kernel and userspace matcher representations. BPF allocation
// and map loading remain the responsibility of RoutingMatcherBuilder.
func NewRoutingMatcherBuilderFromCompiledPolicy(log *logrus.Logger, policy *routing.CompiledPolicy, bpf *bpfObjects) (*RoutingMatcherBuilder, error) {
	if policy == nil {
		return nil, fmt.Errorf("compiled routing policy is nil")
	}
	if log == nil {
		log = logrus.New()
	}

	plan := policy.KernelPlan()
	if len(plan.Matches) == 0 {
		return nil, fmt.Errorf("compiled routing policy has no matches")
	}
	if len(plan.Matches) > consts.MaxMatchSetLen {
		return nil, fmt.Errorf("too many routing rules: %d > %d", len(plan.Matches), consts.MaxMatchSetLen)
	}
	if plan.Matches[len(plan.Matches)-1].Type != consts.MatchType_Fallback {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}

	b := &RoutingMatcherBuilder{
		log:                            log,
		outboundName2Id:                make(map[string]uint8),
		bpf:                            bpf,
		lpmDedup:                       make(map[uint64]lpmDedupEntry, plan.DeduplicatedPrefixSetCount),
		referencedOutbounds:            make(map[string]struct{}, len(plan.ReferencedOutbounds)),
		packetMetadataSensitiveRouting: plan.PacketMetadataSensitive,
	}
	for _, binding := range policy.OutboundIDs() {
		b.outboundName2Id[binding.Name] = uint8(binding.ID)
	}
	for _, name := range plan.ReferencedOutbounds {
		b.referencedOutbounds[name] = struct{}{}
	}
	for index := 0; index < plan.DeduplicatedPrefixSetCount; index++ {
		b.lpmDedup[uint64(index)] = lpmDedupEntry{}
	}
	b.simulatedLpmTries = cloneCompiledPrefixSets(plan.PrefixSets)

	for index, match := range plan.Matches {
		set, err := loweredMatchToBPFMatchSet(match, len(plan.PrefixSets))
		if err != nil {
			return nil, fmt.Errorf("compile routing match[%d]: %w", index, err)
		}
		compiled, err := compileRoutingMatch(set)
		if err != nil {
			return nil, fmt.Errorf("compile userspace routing match[%d]: %w", index, err)
		}
		if match.Type == consts.MatchType_DomainSet {
			b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
				Key:       match.DomainKey,
				RuleIndex: index,
				Domains:   append([]string(nil), match.Domains...),
			})
		}
		b.appendRule(set, compiled)
	}
	predicateGroups, err := predicateGroupsFromCompiledPlan(plan.PredicateGroups, len(plan.Matches))
	if err != nil {
		return nil, err
	}
	b.predicateGroups = predicateGroups

	return b, nil
}

func predicateGroupsFromCompiledPlan(groups []routing.PredicateGroupSpan, matchCount int) ([]routingMatcherPredicateGroupSpan, error) {
	if matchCount == 0 {
		return nil, fmt.Errorf("compiled routing policy has no matches")
	}
	if len(groups) == 0 {
		if matchCount == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("compiled routing policy omits predicate group spans")
	}

	spans := make([]routingMatcherPredicateGroupSpan, len(groups))
	nextStart := 0
	for index, group := range groups {
		if group.Start != nextStart || group.Start < 0 || group.End <= group.Start || group.End >= matchCount {
			return nil, fmt.Errorf("compiled predicate group %d has invalid span [%d,%d)", index, group.Start, group.End)
		}
		spans[index] = routingMatcherPredicateGroupSpan{
			name:  group.Name,
			key:   group.Key,
			not:   group.Not,
			start: group.Start,
			end:   group.End,
		}
		nextStart = group.End
	}
	if nextStart != matchCount-1 {
		return nil, fmt.Errorf("compiled predicate groups end at %d, want %d before fallback", nextStart, matchCount-1)
	}
	return spans, nil
}

func loweredMatchToBPFMatchSet(match routing.LoweredMatch, prefixSetCount int) (bpfMatchSet, error) {
	set := bpfMatchSet{
		Type:     uint8(match.Type),
		Not:      bpfBool(match.Not),
		Outbound: uint8(match.Outbound),
		Mark:     match.Mark,
		Must:     bpfBool(match.Must),
	}

	switch match.Type {
	case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
		if match.PrefixSetIndex >= uint32(prefixSetCount) {
			return bpfMatchSet{}, fmt.Errorf("prefix set index %d is out of range %d", match.PrefixSetIndex, prefixSetCount)
		}
		binary.LittleEndian.PutUint32(set.Value[:], match.PrefixSetIndex)
	case consts.MatchType_Port, consts.MatchType_SourcePort:
		set.Value = bpfPortRange{PortStart: match.PortStart, PortEnd: match.PortEnd}.Encode()
	case consts.MatchType_IpVersion, consts.MatchType_L4Proto:
		set.Value[0] = match.Mask
	case consts.MatchType_ProcessName:
		copy(set.Value[:], match.ProcessName[:])
	case consts.MatchType_Dscp:
		set.Value[0] = match.DSCP
	case consts.MatchType_DomainSet, consts.MatchType_Fallback:
		// These matches carry no fixed-width payload in the BPF ABI.
	default:
		return bpfMatchSet{}, fmt.Errorf("unknown match type: %v", match.Type)
	}
	return set, nil
}

func cloneCompiledPrefixSets(prefixSets [][]netip.Prefix) [][]netip.Prefix {
	cloned := make([][]netip.Prefix, len(prefixSets))
	for index, prefixes := range prefixSets {
		cloned[index] = append([]netip.Prefix(nil), prefixes...)
	}
	return cloned
}
