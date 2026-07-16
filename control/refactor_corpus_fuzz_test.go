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

// This file satisfies the Phase 2 acceptance clause: the immutable compiled
// policy plan must preserve the legacy userspace matcher's decisions for every
// complete fact vector the fuzzer generates.
//
// Seed corpus is derived from RoutingCorpusFixtures so the fuzzer starts from
// known-reachable input vectors (matched domains, in-range ports, etc.) and
// explores mutations around them. A mutated fixture selector is reduced modulo
// the corpus length, so every fuzz input exercises a real routing program.

// FuzzPolicySnapshotEquivalence is the canonical compiled-policy fuzz target.
// For each seed + mutation it builds the legacy matcher and compiled adapter
// from the SAME fixture, then asserts:
//
//  1. Equivalence: both matchers return identical (outbound, mark, must) when
//     neither errors.
//  2. Alias-safety: mutation of the source program after compilation cannot
//     change the compiled matcher result.
//  3. Hash stability: the fixture's PolicySnapshot hash is constant across
//     equivalent programs at different epochs.
func FuzzPolicySnapshotEquivalence(f *testing.F) {
	fixtures := RoutingCorpusFixtures()
	for fixtureIndex, fixture := range fixtures {
		for _, tc := range fixture.Cases {
			f.Add(
				byte(fixtureIndex),
				[]byte(tc.Input.Domain),
				tc.Input.Src.Port(),
				tc.Input.Dst.Port(),
				byte(tc.Input.L4Proto),
				tc.Input.Dscp,
				append(tc.Input.ProcessName[:0:0], tc.Input.ProcessName[:]...),
				append(tc.Input.Mac[:0:0], tc.Input.Mac[:]...),
			)
		}
	}

	f.Fuzz(func(t *testing.T,
		fixtureIndex byte,
		domainBytes []byte,
		srcPort uint16,
		dstPort uint16,
		l4ProtoByte byte,
		dscp byte,
		procName []byte,
		mac []byte,
	) {
		fixture := fixtures[int(fixtureIndex)%len(fixtures)]

		// Bound the mutation surface so the fuzzer spends cycles on semantic
		// changes rather than pathological allocations. Domain is capped to a
		// realistic length; process name is fixed-size per kernel ABI.
		if len(domainBytes) > 253 {
			domainBytes = domainBytes[:253]
		}
		domain := sanitizeDomain(string(domainBytes))

		var proc [16]uint8
		copy(proc[:], procName)

		var mac6 [6]uint8
		copy(mac6[:], mac)

		input := CorpusInput{
			Src:         netip.AddrPortFrom(staticSrcV4().Addr(), srcPort),
			Dst:         netip.AddrPortFrom(staticDstV4().Addr(), dstPort),
			Domain:      domain,
			L4Proto:     consts.L4ProtoType(l4ProtoByte),
			ProcessName: proc,
			Dscp:        dscp,
			Mac:         mac6,
		}

		// Clamp L4Proto to the two valid values so the fuzzer explores the
		// meaningful branch space (TCP/UDP) rather than dying on an unknown
		// proto code which both sides reject identically.
		switch input.L4Proto {
		case consts.L4ProtoType_TCP, consts.L4ProtoType_UDP:
		default:
			input.L4Proto = consts.L4ProtoType_TCP
		}

		// 1. Equivalence on the happy path.
		legacyOut, legacyMark, legacyMust, legacyErr :=
			matchCorpusInput(fixture.BuildMatcher(t), input)

		program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
		if err != nil {
			t.Fatalf("NewNormalizedProgram() error = %v", err)
		}
		snapshot, err := routing.NewPolicySnapshot(1, program)
		if err != nil {
			t.Fatalf("NewPolicySnapshot() error = %v", err)
		}
		compiled, err := snapshot.Compile(logrus.New(), fixture.OutboundIDs)
		if err != nil {
			t.Fatalf("Compile() error = %v", err)
		}

		// 3. Hash stability: hash depends on content, not on epoch or
		// transient clone state. Build a second snapshot at a different epoch
		// from a fresh normalization of the same fixture; its hash must match.
		program2, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
		if err != nil {
			t.Fatalf("second NewNormalizedProgram() error = %v", err)
		}
		snapshot2, err := routing.NewPolicySnapshot(2, program2)
		if err != nil {
			t.Fatalf("second NewPolicySnapshot() error = %v", err)
		}
		if snapshot.Hash() != snapshot2.Hash() {
			t.Fatalf("PolicySnapshot hash drifted: epoch1=%x epoch2=%x",
				snapshot.Hash(), snapshot2.Hash())
		}

		// Mutating the original normalization after compilation must not affect
		// the immutable compiled policy or the matcher built from it.
		if len(program.Rules) > 0 && len(program.Rules[0].AndFunctions) > 0 {
			program.Rules[0].AndFunctions[0].Name = "corrupted-after-snapshot"
		}

		snapMatcher, err := buildMatcherFromCompiledPolicy(compiled)
		if err != nil {
			t.Fatalf("buildMatcherFromCompiledPolicy() error = %v", err)
		}
		snapOut, snapMark, snapMust, snapErr :=
			matchCorpusInput(snapMatcher, input)

		// 2. Both matchers must agree for every complete fact vector.
		if (legacyErr == nil) != (snapErr == nil) {
			t.Fatalf("error mismatch: legacy=%v snap=%v (input=%+v)", legacyErr, snapErr, input)
		}
		if legacyErr != nil {
			return
		}

		if legacyOut != snapOut {
			t.Fatalf("outbound mismatch: legacy=%v snap=%v (input=%+v)", legacyOut, snapOut, input)
		}
		if legacyMark != snapMark {
			t.Fatalf("mark mismatch: legacy=%d snap=%d (input=%+v)", legacyMark, snapMark, input)
		}
		if legacyMust != snapMust {
			t.Fatalf("must mismatch: legacy=%v snap=%v (input=%+v)", legacyMust, snapMust, input)
		}
	})
}

// buildMatcherFromCompiledPolicy adapts the immutable policy plan for the
// fuzz target without touching a live BPF runtime.
func buildMatcherFromCompiledPolicy(compiled *routing.CompiledPolicy) (*RoutingMatcher, error) {
	builder, err := NewRoutingMatcherBuilderFromCompiledPolicy(logrus.New(), compiled, nil)
	if err != nil {
		return nil, err
	}
	return builder.BuildUserspace()
}

// sanitizeDomain strips bytes that would force the matcher down an error path
// unrelated to equivalence (NULs in particular). The goal is to keep the
// fuzzer focused on semantic mutations rather than string-validation noise.
func sanitizeDomain(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0 {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return "x"
	}
	return string(out)
}
