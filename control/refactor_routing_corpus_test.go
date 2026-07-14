/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// This file is the Phase 0 compatibility corpus for the semantic architecture
// refactor (see docs/en/semantic-architecture-refactor-plan.md). It captures
// authoritative input/output pairs for the legacy userspace routing matcher so
// that subsequent phases (PolicySnapshot evaluation, three-valued evaluation,
// Decision adapter shadow mode, etc.) can prove they produce byte-identical
// results.
//
// Each fixture declares a routing program plus a set of cases. A case provides
// the full input vector accepted by RoutingMatcher.Match and the expected
// (outbound, mark, must) tuple. Cases are derived from observed legacy
// behavior, not from the refactor in progress; they form the golden baseline.

// CorpusInput is the full input vector for a routing decision. Field order
// matches RoutingMatcher.Match parameters to keep replay reads obvious.
type CorpusInput struct {
	Src         netip.AddrPort
	Dst         netip.AddrPort
	Domain      string
	L4Proto     consts.L4ProtoType
	ProcessName [16]uint8
	Dscp        uint8
	Mac         [6]uint8
}

// CorpusExpected is the observable routing result for a corpus case.
type CorpusExpected struct {
	Outbound consts.OutboundIndex
	Mark     uint32
	Must     bool
}

// CorpusCase pairs a single input vector with its expected legacy result.
type CorpusCase struct {
	Name     string
	Input    CorpusInput
	Expected CorpusExpected
}

// CorpusFixture bundles a routing program with the outbound name table and the
// cases that exercise it.
type CorpusFixture struct {
	Name        string
	Description string
	Rules       []*config_parser.RoutingRule
	Fallback    config.FunctionOrString
	OutboundIDs map[string]uint8
	Cases       []CorpusCase
}

// BuildMatcher constructs a userspace RoutingMatcher from a fixture. It mirrors
// the helper used by policy_snapshot_integration_test.go so corpus and
// equivalence tests share the same construction path.
func (f CorpusFixture) BuildMatcher(t *testing.T) *RoutingMatcher {
	t.Helper()
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		f.Rules,
		f.OutboundIDs,
		nil,
		f.Fallback,
	)
	if err != nil {
		t.Fatalf("%s: NewRoutingMatcherBuilder() error = %v", f.Name, err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("%s: BuildUserspace() error = %v", f.Name, err)
	}
	return matcher
}

// Replay runs the corpus against the supplied matcher. It is the single entry
// point used by both the legacy baseline test and future shadow-mode
// equivalence checks. mismatches are reported via t.Fatalf with the case name
// so failures point straight at the offending fixture.
func Replay(t *testing.T, matcher *RoutingMatcher, fixture CorpusFixture) {
	t.Helper()
	for _, tc := range fixture.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			gotOutbound, gotMark, gotMust, err := matchCorpusInput(matcher, tc.Input)
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			if gotOutbound != tc.Expected.Outbound {
				t.Fatalf("outbound = %v, want %v", gotOutbound, tc.Expected.Outbound)
			}
			if gotMark != tc.Expected.Mark {
				t.Fatalf("mark = %d, want %d", gotMark, tc.Expected.Mark)
			}
			if gotMust != tc.Expected.Must {
				t.Fatalf("must = %v, want %v", gotMust, tc.Expected.Must)
			}
		})
	}
}

// matchCorpusInput translates CorpusInput into the [16]uint8 / uint16 vector
// expected by RoutingMatcher.Match. MAC addresses are padded to 16 bytes the
// same way ControlPlane.Route does (low 6 bytes carry the real MAC).
func matchCorpusInput(matcher *RoutingMatcher, in CorpusInput) (consts.OutboundIndex, uint32, bool, error) {
	var mac16 [16]uint8
	copy(mac16[10:], in.Mac[:])
	return matcher.Match(
		in.Src.Addr().As16(),
		in.Dst.Addr().As16(),
		in.Src.Port(),
		in.Dst.Port(),
		ipVersionForAddr(in.Dst.Addr()),
		in.L4Proto,
		in.Domain,
		in.ProcessName,
		in.Dscp,
		mac16,
	)
}

func ipVersionForAddr(addr netip.Addr) consts.IpVersionType {
	if addr.Is4() || addr.Is4In6() {
		return consts.IpVersion_4
	}
	return consts.IpVersion_6
}

// stdOutboundIDs returns the canonical outbound name table used by most
// fixtures: direct, block, and a single user-defined "proxy" outbound. Tests
// that need additional outbounds override the entries they care about.
func stdOutboundIDs() map[string]uint8 {
	return map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"block":  uint8(consts.OutboundBlock),
		"proxy":  uint8(consts.OutboundUserDefinedMin),
		"myapp":  uint8(consts.OutboundUserDefinedMin) + 1,
	}
}

// staticSrcV4 / staticDstV4 / staticSrcV6 / staticDstV6 keep fixtures readable
// while still exercising the full [16]uint8 conversion path. The actual values
// are arbitrary TEST-NET addresses and documentation prefix IPs.
func staticSrcV4() netip.AddrPort { return netip.MustParseAddrPort("192.0.2.10:50000") }
func staticDstV4() netip.AddrPort { return netip.MustParseAddrPort("198.51.100.20:443") }
func staticSrcV6() netip.AddrPort { return netip.MustParseAddrPort("[2001:db8::10]:50000") }
func staticDstV6() netip.AddrPort { return netip.MustParseAddrPort("[2001:db8:1::20]:443") }

// pname fills a 16-byte process name buffer from a string, NUL-padded on the
// right just like the kernel-side metadata.
func pname(s string) [16]uint8 {
	var b [16]uint8
	copy(b[:], []byte(s))
	return b
}

// netMustParseAddrPort is a tiny wrapper around netip.MustParseAddrPort so the
// fixtures file does not need to import netip itself. It panics on malformed
// input, which is fine for hand-authored test fixtures.
func netMustParseAddrPort(s string) netip.AddrPort {
	return netip.MustParseAddrPort(s)
}
