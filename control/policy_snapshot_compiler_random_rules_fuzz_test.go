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

const (
	randomRulesFuzzMaxSeedBytes        = 96
	randomRulesFuzzMaxRules            = 4
	randomRulesFuzzMaxFunctionsPerRule = 3
	randomRulesFuzzFactsPerProgram     = 4
)

var randomRulesFuzzFunctionNames = []string{
	consts.Function_Domain,
	consts.Function_Ip,
	consts.Function_SourceIp,
	consts.Function_Port,
	consts.Function_SourcePort,
	consts.Function_L4Proto,
	consts.Function_IpVersion,
	consts.Function_Mac,
	consts.Function_ProcessName,
	consts.Function_Dscp,
}

var randomRulesFuzzDomainKeys = []consts.RoutingDomainKey{
	consts.RoutingDomainKey_Full,
	consts.RoutingDomainKey_Suffix,
	consts.RoutingDomainKey_Keyword,
	consts.RoutingDomainKey_Regex,
}

var randomRulesFuzzDomainValues = map[consts.RoutingDomainKey][]string{
	consts.RoutingDomainKey_Full: {
		"api.example.test",
		"edge.example.test",
	},
	consts.RoutingDomainKey_Suffix: {
		"example.test",
		"service.test",
	},
	consts.RoutingDomainKey_Keyword: {
		"api",
		"edge",
		"cdn",
	},
	consts.RoutingDomainKey_Regex: {
		"^edge-[0-9]+[.]example[.]test$",
		"^api[.]example[.]test$",
	},
}

var randomRulesFuzzIPValues = []string{
	"192.0.2.0/24",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"2001:db8::/32",
	"2001:db8:1::/48",
}

var randomRulesFuzzPortValues = []string{
	"53",
	"80",
	"443",
	"1024-2048",
	"65535",
}

var randomRulesFuzzL4ProtoValues = []string{"tcp", "udp"}
var randomRulesFuzzIPVersionValues = []string{"4", "6"}
var randomRulesFuzzMACValues = []string{
	"00:11:22:33:44:55",
	"02:00:00:00:00:01",
	"02:42:ac:11:00:02",
}
var randomRulesFuzzProcessNames = []string{
	"curl",
	"mosdns",
	"sync-agent",
	"dae",
}
var randomRulesFuzzDSCPValues = []string{"0", "10", "46", "63", "64", "255"}

var randomRulesFuzzSourceAddrs = []netip.Addr{
	netip.MustParseAddr("192.0.2.10"),
	netip.MustParseAddr("203.0.113.9"),
	netip.MustParseAddr("2001:db8::10"),
	netip.MustParseAddr("2001:db8:1::10"),
}

var randomRulesFuzzDestinationAddrs = []netip.Addr{
	netip.MustParseAddr("198.51.100.20"),
	netip.MustParseAddr("203.0.113.10"),
	netip.MustParseAddr("2001:db8::20"),
	netip.MustParseAddr("2001:db8:1::20"),
}

var randomRulesFuzzFactDomains = []string{
	"api.example.test",
	"edge.example.test",
	"edge-42.example.test",
	"cdn.service.test",
	"unmatched.invalid",
}

var randomRulesFuzzFactMACs = [][6]uint8{
	{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
}

// FuzzCompiledPolicyRandomRulesEquivalence synthesizes bounded, valid routing
// programs and complete fact vectors. The legacy lowering path remains the
// oracle; the compiled-policy adapter must return the same observable tuple.
func FuzzCompiledPolicyRandomRulesEquivalence(f *testing.F) {
	for functionIndex := range randomRulesFuzzFunctionNames {
		f.Add(
			[]byte{0, 0, byte(functionIndex), 0, 0, 0, 0, 0, 0, 0, 0, 0},
			uint16(50000),
			uint16(443),
			byte(functionIndex),
			byte(46),
		)
	}
	f.Add([]byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4}, uint16(53), uint16(53), byte(7), byte(0))
	f.Add([]byte{255, 255, 255, 255, 255, 255, 255, 255}, uint16(0), uint16(65535), byte(255), byte(255))

	f.Fuzz(func(t *testing.T, programSeed []byte, sourcePort, destinationPort uint16, factSeed, dscp byte) {
		if len(programSeed) > randomRulesFuzzMaxSeedBytes {
			programSeed = programSeed[:randomRulesFuzzMaxSeedBytes]
		}

		programCursor := newRandomRulesFuzzCursor(programSeed, 0x7f4a7c15)
		rules, fallback := randomRulesFuzzProgram(programCursor)
		outboundIDs := randomRulesFuzzOutboundIDs()

		program, err := routing.NewNormalizedProgram(rules, fallback)
		if err != nil {
			t.Fatalf("NewNormalizedProgram() error = %v (seed=%x)", err, programSeed)
		}
		snapshot, err := routing.NewPolicySnapshot(41, program)
		if err != nil {
			t.Fatalf("NewPolicySnapshot() error = %v (seed=%x)", err, programSeed)
		}

		legacyProgram, err := snapshot.CloneProgram()
		if err != nil {
			t.Fatalf("CloneProgram() error = %v (seed=%x)", err, programSeed)
		}
		legacyBuilder, err := NewRoutingMatcherBuilderFromProgram(logrus.New(), legacyProgram, outboundIDs, nil)
		if err != nil {
			t.Fatalf("legacy builder error = %v (seed=%x)", err, programSeed)
		}
		legacyMatcher, err := legacyBuilder.BuildUserspace()
		if err != nil {
			t.Fatalf("legacy BuildUserspace() error = %v (seed=%x)", err, programSeed)
		}

		compiled, err := snapshot.Compile(logrus.New(), outboundIDs)
		if err != nil {
			t.Fatalf("PolicySnapshot.Compile() error = %v (seed=%x)", err, programSeed)
		}
		compiledBuilder, err := NewRoutingMatcherBuilderFromCompiledPolicy(logrus.New(), compiled, nil)
		if err != nil {
			t.Fatalf("compiled builder error = %v (seed=%x)", err, programSeed)
		}
		compiledMatcher, err := compiledBuilder.BuildUserspace()
		if err != nil {
			t.Fatalf("compiled BuildUserspace() error = %v (seed=%x)", err, programSeed)
		}

		factCursor := newRandomRulesFuzzCursor(programSeed, uint64(factSeed)<<32|uint64(dscp))
		factCursor.offset = int(factSeed)
		for factIndex := 0; factIndex < randomRulesFuzzFactsPerProgram; factIndex++ {
			input := randomRulesFuzzPacket(factCursor, sourcePort, destinationPort, dscp, factIndex)
			legacyOutbound, legacyMark, legacyMust, legacyErr := matchCorpusInput(legacyMatcher, input)
			compiledOutbound, compiledMark, compiledMust, compiledErr := matchCorpusInput(compiledMatcher, input)
			if legacyErr != nil || compiledErr != nil {
				t.Fatalf(
					"match error mismatch: legacy=%v compiled=%v seed=%x fact=%d input=%+v",
					legacyErr,
					compiledErr,
					programSeed,
					factIndex,
					input,
				)
			}
			if legacyOutbound != compiledOutbound || legacyMark != compiledMark || legacyMust != compiledMust {
				t.Fatalf(
					"decision mismatch: legacy=(%v,%d,%v) compiled=(%v,%d,%v) seed=%x fact=%d input=%+v",
					legacyOutbound,
					legacyMark,
					legacyMust,
					compiledOutbound,
					compiledMark,
					compiledMust,
					programSeed,
					factIndex,
					input,
				)
			}
		}
	})
}

type randomRulesFuzzCursor struct {
	data   []byte
	offset int
	state  uint64
}

func newRandomRulesFuzzCursor(data []byte, state uint64) *randomRulesFuzzCursor {
	return &randomRulesFuzzCursor{data: data, state: state}
}

func (c *randomRulesFuzzCursor) next() byte {
	if len(c.data) != 0 {
		value := c.data[c.offset%len(c.data)]
		c.offset++
		return value
	}
	c.state = c.state*6364136223846793005 + 1442695040888963407
	return byte(c.state >> 56)
}

func (c *randomRulesFuzzCursor) choose(count int) int {
	return int(c.next()) % count
}

func randomRulesFuzzProgram(c *randomRulesFuzzCursor) ([]*config_parser.RoutingRule, config.FunctionOrString) {
	ruleCount := 1 + c.choose(randomRulesFuzzMaxRules)
	rules := make([]*config_parser.RoutingRule, 0, ruleCount)
	for ruleIndex := 0; ruleIndex < ruleCount; ruleIndex++ {
		functionCount := 1 + c.choose(randomRulesFuzzMaxFunctionsPerRule)
		rule := &config_parser.RoutingRule{
			AndFunctions: make([]*config_parser.Function, 0, functionCount),
		}
		for functionIndex := 0; functionIndex < functionCount; functionIndex++ {
			rule.AndFunctions = append(rule.AndFunctions, randomRulesFuzzFunction(c))
		}
		rule.Outbound = randomRulesFuzzRuleOutbound(c)
		rules = append(rules, rule)
	}
	return rules, config.FunctionOrString(randomRulesFuzzFallbackNames[c.choose(len(randomRulesFuzzFallbackNames))])
}

var randomRulesFuzzFallbackNames = []string{"direct", "block", "proxy", "myapp"}
var randomRulesFuzzRuleOutboundNames = []string{
	"direct",
	"block",
	"proxy",
	"myapp",
	consts.OutboundMustRules.String(),
}
var randomRulesFuzzMarkValues = []string{"0", "1", "42", "0x2e"}

func randomRulesFuzzRuleOutbound(c *randomRulesFuzzCursor) config_parser.Function {
	name := randomRulesFuzzRuleOutboundNames[c.choose(len(randomRulesFuzzRuleOutboundNames))]
	outbound := config_parser.Function{Name: name}
	if name == consts.OutboundMustRules.String() {
		return outbound
	}
	switch c.choose(4) {
	case 1:
		outbound.Params = []*config_parser.Param{{Key: consts.OutboundParam_Mark, Val: randomRulesFuzzMarkValues[c.choose(len(randomRulesFuzzMarkValues))]}}
	case 2:
		outbound.Params = []*config_parser.Param{{Val: "must"}}
	case 3:
		outbound.Params = []*config_parser.Param{
			{Key: consts.OutboundParam_Mark, Val: randomRulesFuzzMarkValues[c.choose(len(randomRulesFuzzMarkValues))]},
			{Val: "must"},
		}
	}
	return outbound
}

func randomRulesFuzzFunction(c *randomRulesFuzzCursor) *config_parser.Function {
	name := randomRulesFuzzFunctionNames[c.choose(len(randomRulesFuzzFunctionNames))]
	function := &config_parser.Function{Name: name, Not: c.next()&1 != 0}
	switch name {
	case consts.Function_Domain:
		function.Params = randomRulesFuzzDomainParams(c)
	case consts.Function_Ip, consts.Function_SourceIp:
		function.Params = randomRulesFuzzValueParams(c, randomRulesFuzzIPValues)
	case consts.Function_Port, consts.Function_SourcePort:
		function.Params = randomRulesFuzzValueParams(c, randomRulesFuzzPortValues)
	case consts.Function_L4Proto:
		function.Params = randomRulesFuzzValueParams(c, randomRulesFuzzL4ProtoValues)
	case consts.Function_IpVersion:
		function.Params = randomRulesFuzzValueParams(c, randomRulesFuzzIPVersionValues)
	case consts.Function_Mac:
		function.Params = randomRulesFuzzValueParams(c, randomRulesFuzzMACValues)
	case consts.Function_ProcessName:
		function.Params = randomRulesFuzzValueParams(c, randomRulesFuzzProcessNames)
	case consts.Function_Dscp:
		function.Params = randomRulesFuzzValueParams(c, randomRulesFuzzDSCPValues)
	}
	return function
}

func randomRulesFuzzDomainParams(c *randomRulesFuzzCursor) []*config_parser.Param {
	groupCount := 1 + c.choose(2)
	keyStart := c.choose(len(randomRulesFuzzDomainKeys))
	params := make([]*config_parser.Param, 0, groupCount*2)
	for groupIndex := 0; groupIndex < groupCount; groupIndex++ {
		key := randomRulesFuzzDomainKeys[(keyStart+groupIndex)%len(randomRulesFuzzDomainKeys)]
		values := randomRulesFuzzDomainValues[key]
		valueCount := 1 + c.choose(2)
		for valueIndex := 0; valueIndex < valueCount; valueIndex++ {
			params = append(params, &config_parser.Param{
				Key: string(key),
				Val: values[c.choose(len(values))],
			})
		}
	}
	return params
}

func randomRulesFuzzValueParams(c *randomRulesFuzzCursor, values []string) []*config_parser.Param {
	valueCount := 1 + c.choose(2)
	params := make([]*config_parser.Param, 0, valueCount)
	for valueIndex := 0; valueIndex < valueCount; valueIndex++ {
		params = append(params, &config_parser.Param{Val: values[c.choose(len(values))]})
	}
	return params
}

func randomRulesFuzzOutboundIDs() map[string]uint8 {
	return map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"block":  uint8(consts.OutboundBlock),
		"proxy":  uint8(consts.OutboundUserDefinedMin),
		"myapp":  uint8(consts.OutboundUserDefinedMin) + 1,
	}
}

func randomRulesFuzzPacket(
	c *randomRulesFuzzCursor,
	sourcePortSeed uint16,
	destinationPortSeed uint16,
	dscpSeed byte,
	factIndex int,
) CorpusInput {
	sourcePort := sourcePortSeed + uint16(factIndex*257) + uint16(c.next())
	destinationPort := destinationPortSeed + uint16(factIndex*131) + uint16(c.next())
	var processName [consts.TaskCommLen]uint8
	copy(processName[:], randomRulesFuzzProcessNames[c.choose(len(randomRulesFuzzProcessNames))])
	protocols := []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP}
	return CorpusInput{
		Src:         netip.AddrPortFrom(randomRulesFuzzSourceAddrs[c.choose(len(randomRulesFuzzSourceAddrs))], sourcePort),
		Dst:         netip.AddrPortFrom(randomRulesFuzzDestinationAddrs[c.choose(len(randomRulesFuzzDestinationAddrs))], destinationPort),
		Domain:      randomRulesFuzzFactDomains[c.choose(len(randomRulesFuzzFactDomains))],
		L4Proto:     protocols[c.choose(len(protocols))],
		ProcessName: processName,
		Dscp:        dscpSeed ^ c.next(),
		Mac:         randomRulesFuzzFactMACs[c.choose(len(randomRulesFuzzFactMACs))],
	}
}
