/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

// TestCompiledPolicyMatchesLegacySanitizedConfigReplay verifies the compiler
// against a parsed, de-identified dae configuration rather than only
// programmatic rules. The fixture intentionally contains no credentials or
// external network endpoints.
func TestCompiledPolicyMatchesLegacySanitizedConfigReplay(t *testing.T) {
	configuration := loadSanitizedRoutingConfig(t)
	program, err := routing.NewNormalizedProgram(
		configuration.Routing.Rules,
		configuration.Routing.Fallback,
		&routing.AliasOptimizer{},
	)
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	const epoch = routing.PolicyEpoch(41)
	snapshot, err := routing.NewPolicySnapshot(epoch, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	outboundIDs := map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"block":  uint8(consts.OutboundBlock),
		"proxy":  uint8(consts.OutboundUserDefinedMin),
	}
	compiled, err := snapshot.Compile(logrus.New(), outboundIDs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	legacy, err := NewRoutingMatcherBuilderFromProgram(logrus.New(), program, outboundIDs, nil)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilderFromProgram() error = %v", err)
	}
	compiledBuilder, err := NewRoutingMatcherBuilderFromCompiledPolicy(logrus.New(), compiled, nil)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilderFromCompiledPolicy() error = %v", err)
	}
	legacyMatcher, err := legacy.BuildUserspace()
	if err != nil {
		t.Fatalf("legacy BuildUserspace() error = %v", err)
	}
	compiledMatcher, err := compiledBuilder.BuildUserspace()
	if err != nil {
		t.Fatalf("compiled BuildUserspace() error = %v", err)
	}

	for _, tc := range []struct {
		name     string
		input    CorpusInput
		expected sanitizedConfigRouteOutcome
	}{
		{
			name:     "domain_and_port_mark_must",
			input:    CorpusInput{Src: sanitizedConfigSrcV4(), Dst: staticDstV4(), Domain: "asset.cdn.example.net", L4Proto: consts.L4ProtoType_TCP},
			expected: sanitizedConfigRouteOutcome{outbound: consts.OutboundUserDefinedMin, mark: 17, must: true},
		},
		{
			name:     "destination_ip_direct",
			input:    CorpusInput{Src: sanitizedConfigSrcV4(), Dst: mustAddrPort("198.51.100.9:443"), L4Proto: consts.L4ProtoType_TCP},
			expected: sanitizedConfigRouteOutcome{outbound: consts.OutboundDirect},
		},
		{
			name:     "source_ip_block",
			input:    CorpusInput{Src: mustAddrPort("192.0.2.9:42000"), Dst: mustAddrPort("203.0.113.20:443"), L4Proto: consts.L4ProtoType_TCP},
			expected: sanitizedConfigRouteOutcome{outbound: consts.OutboundBlock},
		},
		{
			name:     "udp_dscp_proxy",
			input:    CorpusInput{Src: sanitizedConfigSrcV4(), Dst: mustAddrPort("203.0.113.20:443"), L4Proto: consts.L4ProtoType_UDP, Dscp: 46},
			expected: sanitizedConfigRouteOutcome{outbound: consts.OutboundUserDefinedMin},
		},
		{
			name:     "process_name_proxy",
			input:    CorpusInput{Src: sanitizedConfigSrcV4(), Dst: mustAddrPort("203.0.113.20:443"), L4Proto: consts.L4ProtoType_TCP, ProcessName: processName16("sync-agent")},
			expected: sanitizedConfigRouteOutcome{outbound: consts.OutboundUserDefinedMin},
		},
		{
			name:     "source_mac_direct",
			input:    CorpusInput{Src: sanitizedConfigSrcV4(), Dst: mustAddrPort("203.0.113.20:443"), L4Proto: consts.L4ProtoType_TCP, Mac: [6]uint8{2, 0, 0, 0, 0, 1}},
			expected: sanitizedConfigRouteOutcome{outbound: consts.OutboundDirect},
		},
		{
			name:     "ip_version_proxy",
			input:    CorpusInput{Src: sanitizedConfigSrcV4(), Dst: mustAddrPort("203.0.113.20:443"), L4Proto: consts.L4ProtoType_TCP},
			expected: sanitizedConfigRouteOutcome{outbound: consts.OutboundUserDefinedMin},
		},
		{
			name:     "fallback_direct_ipv6",
			input:    CorpusInput{Src: staticSrcV6(), Dst: staticDstV6(), L4Proto: consts.L4ProtoType_TCP},
			expected: sanitizedConfigRouteOutcome{outbound: consts.OutboundDirect},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			legacyOutcome, legacyErr := sanitizedConfigMatch(legacyMatcher, tc.input)
			compiledOutcome, compiledErr := sanitizedConfigMatch(compiledMatcher, tc.input)
			if (legacyErr == nil) != (compiledErr == nil) {
				t.Fatalf("error mismatch: legacy=%v compiled=%v", legacyErr, compiledErr)
			}
			if legacyErr != nil {
				return
			}
			if legacyOutcome != tc.expected {
				t.Fatalf("legacy outcome = %+v, want %+v", legacyOutcome, tc.expected)
			}
			if legacyOutcome != compiledOutcome {
				t.Fatalf("compiled outcome = %+v, want legacy %+v", compiledOutcome, legacyOutcome)
			}
		})
	}
}

type sanitizedConfigRouteOutcome struct {
	outbound consts.OutboundIndex
	mark     uint32
	must     bool
}

func sanitizedConfigMatch(matcher *RoutingMatcher, input CorpusInput) (sanitizedConfigRouteOutcome, error) {
	outbound, mark, must, err := matchCorpusInput(matcher, input)
	if err != nil {
		return sanitizedConfigRouteOutcome{}, err
	}
	return sanitizedConfigRouteOutcome{outbound: outbound, mark: mark, must: must}, nil
}

func loadSanitizedRoutingConfig(t *testing.T) *config.Config {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "phase2_sanitized_config.dae"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "sanitized.dae")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	sections, _, err := config.NewMerger(path).Merge()
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	configuration, err := config.New(sections)
	if err != nil {
		t.Fatalf("config.New() error = %v", err)
	}
	return configuration
}

func mustAddrPort(value string) netip.AddrPort {
	return netip.MustParseAddrPort(value)
}

func processName16(name string) [consts.TaskCommLen]uint8 {
	var processName [consts.TaskCommLen]uint8
	copy(processName[:], name)
	return processName
}

func sanitizedConfigSrcV4() netip.AddrPort {
	return mustAddrPort("203.0.113.10:50000")
}
