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
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestPolicySnapshotBuildsLegacyEquivalentUserspaceMatcher(t *testing.T) {
	program, err := routing.NewNormalizedProgram([]*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Suffix),
					Val: "example.com",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy", Params: []*config_parser.Param{{Key: "mark", Val: "42"}}},
		},
	}, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}

	snapshot, err := routing.NewPolicySnapshot(1, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	snapshotProgram, err := snapshot.CloneProgram()
	if err != nil {
		t.Fatalf("CloneProgram() error = %v", err)
	}

	legacy := buildUserspaceMatcherForPolicySnapshotTest(t, program)
	fromSnapshot := buildUserspaceMatcherForPolicySnapshotTest(t, snapshotProgram)

	for _, domain := range []string{"www.example.com", "other.example"} {
		legacyResult := matchPolicySnapshotTestDomain(t, legacy, domain)
		snapshotResult := matchPolicySnapshotTestDomain(t, fromSnapshot, domain)
		if legacyResult != snapshotResult {
			t.Fatalf("domain %q: snapshot result = %+v, legacy result = %+v", domain, snapshotResult, legacyResult)
		}
	}
}

type policySnapshotMatchResult struct {
	outbound consts.OutboundIndex
	mark     uint32
	must     bool
}

func buildUserspaceMatcherForPolicySnapshotTest(t *testing.T, program *routing.NormalizedProgram) *RoutingMatcher {
	t.Helper()
	builder, err := NewRoutingMatcherBuilderFromProgram(logrus.New(), program, map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"proxy":  2,
	}, nil)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilderFromProgram() error = %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace() error = %v", err)
	}
	return matcher
}

func matchPolicySnapshotTestDomain(t *testing.T, matcher *RoutingMatcher, domain string) policySnapshotMatchResult {
	t.Helper()
	source := netip.MustParseAddr("192.0.2.1").As16()
	destination := netip.MustParseAddr("198.51.100.1").As16()
	outbound, mark, must, err := matcher.Match(
		source,
		destination,
		50000,
		443,
		consts.IpVersion_4,
		consts.L4ProtoType_TCP,
		domain,
		[16]uint8{},
		0,
		[16]uint8{},
	)
	if err != nil {
		t.Fatalf("Match(%q) error = %v", domain, err)
	}
	return policySnapshotMatchResult{outbound: outbound, mark: mark, must: must}
}
