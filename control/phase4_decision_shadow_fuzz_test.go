/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
)

// FuzzPhase4DecisionShadowCompleteFactsEquivalence keeps the legacy matcher
// authoritative while exercising the sampled Decision shadow with bounded,
// complete fact vectors. Each seed starts from the Phase 0 corpus and retains
// its source and destination address family; mutations only vary the facts
// that both routing paths consume.
func FuzzPhase4DecisionShadowCompleteFactsEquivalence(f *testing.F) {
	fixtures := RoutingCorpusFixtures()
	for fixtureIndex, fixture := range fixtures {
		for caseIndex, tc := range fixture.Cases {
			f.Add(
				byte(fixtureIndex),
				byte(caseIndex),
				[]byte(tc.Input.Domain),
				uint16(tc.Input.Src.Port()),
				uint16(tc.Input.Dst.Port()),
				byte(tc.Input.L4Proto),
				tc.Input.Dscp,
				append(tc.Input.ProcessName[:0:0], tc.Input.ProcessName[:]...),
				append(tc.Input.Mac[:0:0], tc.Input.Mac[:]...),
			)
		}
	}

	f.Fuzz(func(t *testing.T,
		fixtureIndex byte,
		caseIndex byte,
		domainBytes []byte,
		srcPort uint16,
		dstPort uint16,
		l4ProtoByte byte,
		dscp byte,
		processName []byte,
		mac []byte,
	) {
		fixture := fixtures[int(fixtureIndex)%len(fixtures)]
		base := fixture.Cases[int(caseIndex)%len(fixture.Cases)].Input

		if len(domainBytes) > phase4DecisionShadowMaxDomainBytes {
			domainBytes = domainBytes[:phase4DecisionShadowMaxDomainBytes]
		}
		domain := string(domainBytes)
		if domain != "" {
			domain = sanitizeDomain(domain)
		}

		input := base
		if len(processName) > len(input.ProcessName) {
			processName = processName[:len(input.ProcessName)]
		}
		if len(mac) > len(input.Mac) {
			mac = mac[:len(input.Mac)]
		}
		input.Src = netip.AddrPortFrom(base.Src.Addr(), srcPort)
		input.Dst = netip.AddrPortFrom(base.Dst.Addr(), dstPort)
		input.Domain = domain
		input.L4Proto = consts.L4ProtoType(l4ProtoByte)
		switch input.L4Proto {
		case consts.L4ProtoType_TCP, consts.L4ProtoType_UDP:
		default:
			input.L4Proto = consts.L4ProtoType_TCP
		}
		input.Dscp = dscp
		copy(input.ProcessName[:], processName)
		copy(input.Mac[:], mac)

		legacyOutbound, legacyMark, legacyMust, err := matchCorpusInput(fixture.BuildMatcher(t), input)
		if err != nil {
			t.Fatalf("legacy Match() error = %v (input=%+v)", err, input)
		}

		program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
		if err != nil {
			t.Fatalf("NewNormalizedProgram() error = %v", err)
		}
		snapshot, err := routing.NewPolicySnapshot(71, program)
		if err != nil {
			t.Fatalf("NewPolicySnapshot() error = %v", err)
		}
		compiled, err := snapshot.Compile(logrus.New(), fixture.OutboundIDs)
		if err != nil {
			t.Fatalf("Compile() error = %v", err)
		}
		shadow, err := newPhase4DecisionShadow(snapshot, compiled, 1)
		if err != nil {
			t.Fatalf("newPhase4DecisionShadow() error = %v", err)
		}

		shadow.Observe(phase4DecisionShadowInput{
			source:      input.Src,
			destination: input.Dst,
			l4Proto:     input.L4Proto,
			domain:      input.Domain,
			domainKnown: true,
			evidence:    evidenceForCorpusInput(input),
			processName: input.ProcessName,
			dscp:        input.Dscp,
			mac:         input.Mac,
		}, LegacyRouteOutcome{Outbound: legacyOutbound, Mark: legacyMark, Must: legacyMust})

		got := shadow.Snapshot()
		if got.Sampled != 1 || got.Matched != 1 || got.Deferred != 0 || got.Diverged != 0 || got.Errors != 0 || !got.CutoverEligible || len(got.Evidence) != 0 {
			t.Fatalf("shadow snapshot = %+v, want one matching complete-fact observation (input=%+v)", got, input)
		}
	})
}
