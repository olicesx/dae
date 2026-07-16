/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// RoutingCorpusFixtures returns the full Phase 0 routing corpus. Each fixture
// is self-contained: it declares a routing program, the outbound name table it
// relies on, and the cases that exercise the program. Adding a fixture here is
// the canonical way to extend coverage; downstream phases (PolicySnapshot,
// three-valued evaluation, Decision shadow) replay the same slice and must
// produce byte-identical results.
//
// Categories covered (per Phase 0 acceptance clause 1):
//   - every routing function (Domain in all key modes, IpSet, SourceIpSet,
//     Port, SourcePort, L4Proto, IpVersion, ProcessName, Dscp, Mac, Fallback)
//   - boolean combinations (AND within a rule, OR across rules, NOT inversion)
//   - priority position (first match wins, fallback at tail)
//   - mark, must, reserved outbounds (direct, block)
func RoutingCorpusFixtures() []CorpusFixture {
	return []CorpusFixture{
		domainSuffixFixture(),
		domainFullFixture(),
		domainKeywordFixture(),
		domainRegexFixture(),
		ipSetFixture(),
		sourceIpSetFixture(),
		portFixture(),
		sourcePortFixture(),
		l4ProtoFixture(),
		ipVersionFixture(),
		processNameFixture(),
		dscpFixture(),
		macFixture(),
		andCombinationFixture(),
		orAcrossRulesFixture(),
		notInversionFixture(),
		multiKeyPositiveFixture(),
		multiKeyNegationFixture(),
		markRuleFixture(),
		mustRuleFixture(),
		mustRulesContinuationFixture(),
		reservedOutboundFixture(),
		priorityFirstWinsFixture(),
		fallbackOnlyFixture(),
	}
}

// --- Domain ---------------------------------------------------------------

func domainSuffixFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "domain_suffix",
		Description: "RoutingDomainKey_Suffix matches a tail label and lets it fall through otherwise",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Suffix),
					Val: "example.com",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "subdomain_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "exact_apex_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "unrelated_domain_falls_back",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "other.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func domainFullFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "domain_full",
		Description: "RoutingDomainKey_Full matches only the literal domain, not subdomains",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Full),
					Val: "api.example.com",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "literal_match",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "api.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "subdomain_does_not_match",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "v2.api.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func domainKeywordFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "domain_keyword",
		Description: "RoutingDomainKey_Keyword matches any substring occurrence",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Keyword),
					Val: "secure",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "keyword_in_middle",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "my-secure-login.example", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "no_keyword_falls_back",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "plain.example", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func domainRegexFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "domain_regex",
		Description: "RoutingDomainKey_Regex matches the complete configured regular expression",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Regex),
					Val: `^edge-[0-9]+\.example\.test$`,
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "numeric_edge_domain_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "edge-42.example.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "non_numeric_edge_domain_falls_back",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "edge-blue.example.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

// --- IP / SourceIp --------------------------------------------------------

func ipSetFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "ip_set",
		Description: "Function_Ip matches when the destination falls inside a CIDR",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Ip,
				Params: []*config_parser.Param{{
					Val: "198.51.100.0/24",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "destination_in_cidr",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "destination_outside_cidr",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: netMustParseAddrPort("203.0.113.5:443"), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func sourceIpSetFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "source_ip_set",
		Description: "Function_SourceIp matches when the source falls inside a CIDR",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_SourceIp,
				Params: []*config_parser.Param{{
					Val: "192.0.2.0/24",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "source_in_cidr",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "source_outside_cidr",
				Input:    CorpusInput{Src: netMustParseAddrPort("203.0.113.50:50000"), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

// --- Port / SourcePort ----------------------------------------------------

func portFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "port_range",
		Description: "Function_Port matches when the destination port is inside a range",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Port,
				Params: []*config_parser.Param{{
					Val: "80-443",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "dst_port_inside_range",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "dst_port_below_range",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: netMustParseAddrPort("198.51.100.20:53"), L4Proto: consts.L4ProtoType_UDP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func sourcePortFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "source_port_range",
		Description: "Function_SourcePort matches when the source port is inside a range",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_SourcePort,
				Params: []*config_parser.Param{{
					Val: "40000-60000",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "src_port_inside_range",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "src_port_above_range",
				Input:    CorpusInput{Src: netMustParseAddrPort("192.0.2.10:65000"), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

// --- L4Proto / IpVersion --------------------------------------------------

func l4ProtoFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "l4proto_tcp",
		Description: "Function_L4Proto matches only the configured protocol",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_L4Proto,
				Params: []*config_parser.Param{{
					Val: "tcp",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "tcp_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "udp_does_not_match",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_UDP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func ipVersionFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "ip_version_4",
		Description: "Function_IpVersion discriminates between v4 and v6 traffic",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_IpVersion,
				Params: []*config_parser.Param{{
					Val: "4",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "v4_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "v6_falls_back",
				Input:    CorpusInput{Src: staticSrcV6(), Dst: staticDstV6(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

// --- ProcessName / Dscp / Mac ---------------------------------------------

func processNameFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "process_name",
		Description: "Function_ProcessName matches the kernel-supplied task comm",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_ProcessName,
				Params: []*config_parser.Param{{
					Val: "curl",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "matching_pname",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP, ProcessName: pname("curl")},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "non_matching_pname",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP, ProcessName: pname("wget")},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
			{
				Name:     "empty_pname_does_not_match",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func dscpFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "dscp",
		Description: "Function_Dscp matches the DSCP/TOS field carried in metadata",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Dscp,
				Params: []*config_parser.Param{{
					Val: "46",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "dscp_46_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP, Dscp: 46},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "dscp_0_falls_back",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP, Dscp: 0},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func macFixture() CorpusFixture {
	matchMac := [6]uint8{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}
	return CorpusFixture{
		Name:        "source_mac",
		Description: "Function_Mac matches the source MAC captured at the kernel hook",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Mac,
				Params: []*config_parser.Param{{
					Val: "02:42:ac:11:00:02",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "mac_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP, Mac: matchMac},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "different_mac_falls_back",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), L4Proto: consts.L4ProtoType_TCP, Mac: [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

// --- Boolean combinations -------------------------------------------------

func andCombinationFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "and_combination",
		Description: "Two functions in the same rule require both predicates to match",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "example.com",
					}},
				},
				{
					Name: consts.Function_L4Proto,
					Params: []*config_parser.Param{{
						Val: "tcp",
					}},
				},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "both_match",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "domain_only_does_not_match",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_UDP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
			{
				Name:     "proto_only_does_not_match",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "other.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func orAcrossRulesFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "or_via_multiple_rules",
		Description: "Two rules with the same outbound express OR; either predicate suffices",
		Rules: []*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "example.com",
					}},
				}},
				Outbound: config_parser.Function{Name: "proxy"},
			},
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Port,
					Params: []*config_parser.Param{{
						Val: "53",
					}},
				}},
				Outbound: config_parser.Function{Name: "proxy"},
			},
		},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "first_rule_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "second_rule_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: netMustParseAddrPort("198.51.100.20:53"), Domain: "other.test", L4Proto: consts.L4ProtoType_UDP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "neither_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "other.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func notInversionFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "not_inversion",
		Description: "A function with Not=true inverts its predicate within an AND rule",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "example.com",
					}},
				},
				{
					Name: consts.Function_L4Proto,
					Not:  true,
					Params: []*config_parser.Param{{
						Val: "udp",
					}},
				},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "domain_and_not_udp",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "domain_but_udp_excluded",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_UDP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func multiKeyPositiveFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "multi_key_domain_positive",
		Description: "Parameter keys in one positive domain function are ORed in legacy lowering order",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{
					{Key: string(consts.RoutingDomainKey_Full), Val: "first.key.test"},
					{Key: string(consts.RoutingDomainKey_Suffix), Val: "middle.key.test"},
					{Key: string(consts.RoutingDomainKey_Keyword), Val: "last-key"},
				},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "first_key_full_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "first.key.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "middle_key_suffix_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.middle.key.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "last_key_keyword_matches",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "edge-last-key.example", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name:     "no_key_matches_falls_back",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "other.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
		},
	}
}

func multiKeyNegationFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "multi_key_domain_negation",
		Description: "Negated domain parameter keys and values all exclude the first rule before ordered later rules compete",
		Rules: []*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{
					{
						Name: consts.Function_Domain,
						Not:  true,
						Params: []*config_parser.Param{
							{Key: string(consts.RoutingDomainKey_Full), Val: "api.example.com"},
							{Key: string(consts.RoutingDomainKey_Suffix), Val: "example.com"},
						},
					},
					{
						Name: consts.Function_Domain,
						Not:  true,
						Params: []*config_parser.Param{
							{Key: string(consts.RoutingDomainKey_Suffix), Val: "blocked.example"},
							{Key: string(consts.RoutingDomainKey_Suffix), Val: "denied.example"},
						},
					},
				},
				Outbound: config_parser.Function{Name: "proxy"},
			},
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Full),
						Val: "api.example.com",
					}},
				}},
				Outbound: config_parser.Function{Name: "block"},
			},
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "example.com",
					}},
				}},
				Outbound: config_parser.Function{Name: "myapp"},
			},
		},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "full_and_suffix_match_reaches_exact_competitor",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "api.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundBlock},
			},
			{
				Name:     "suffix_match_reaches_later_suffix_competitor",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin + 1},
			},
			{
				Name:     "first_same_key_value_excludes_negated_rule",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "cdn.blocked.example", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
			{
				Name:     "second_same_key_value_excludes_negated_rule",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "cdn.denied.example", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
			{
				Name:     "unrelated_domain_uses_first_negated_rule",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "other.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
		},
	}
}

// --- mark / must / reserved / priority / fallback -------------------------

func markRuleFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "mark_rule",
		Description: "Outbound params with mark= set the fwmark on the decision",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Suffix),
					Val: "example.com",
				}},
			}},
			Outbound: config_parser.Function{
				Name:   "proxy",
				Params: []*config_parser.Param{{Key: "mark", Val: "42"}},
			},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "matching_rule_carries_mark",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin, Mark: 42},
			},
			{
				Name:     "fallback_has_zero_mark",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "other.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect, Mark: 0},
			},
		},
	}
}

func mustRuleFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "must_rule",
		Description: "Outbound param 'must' marks the decision as required for this flow",
		Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Suffix),
					Val: "example.com",
				}},
			}},
			Outbound: config_parser.Function{
				Name:   "proxy",
				Params: []*config_parser.Param{{Val: "must"}},
			},
		}},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "matching_rule_is_must",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin, Must: true},
			},
			{
				Name:     "fallback_is_not_must",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "other.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect, Must: false},
			},
		},
	}
}

func mustRulesContinuationFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "must_rules_continuation",
		Description: "must_rules carries must into a later rule or fallback, while direct(must) remains terminal",
		Rules: []*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{
					{
						Name: consts.Function_ProcessName,
						Params: []*config_parser.Param{{
							Val: "mosdns",
						}},
					},
					{
						Name: consts.Function_L4Proto,
						Params: []*config_parser.Param{{
							Val: "udp",
						}},
					},
					{
						Name: consts.Function_Port,
						Params: []*config_parser.Param{{
							Val: "53",
						}},
					},
				},
				Outbound: config_parser.Function{Name: consts.OutboundMustRules.String()},
			},
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "route.example",
					}},
				}},
				Outbound: config_parser.Function{Name: "proxy"},
			},
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "must-direct.example",
					}},
				}},
				Outbound: config_parser.Function{
					Name:   "direct",
					Params: []*config_parser.Param{{Val: "must"}},
				},
			},
		},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name: "sentinel_continues_to_later_rule",
				Input: CorpusInput{
					Src:         staticSrcV4(),
					Dst:         netMustParseAddrPort("198.51.100.20:53"),
					Domain:      "api.route.example",
					L4Proto:     consts.L4ProtoType_UDP,
					ProcessName: pname("mosdns"),
				},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin, Must: true},
			},
			{
				Name: "sentinel_carries_must_into_fallback",
				Input: CorpusInput{
					Src:         staticSrcV4(),
					Dst:         netMustParseAddrPort("198.51.100.20:53"),
					Domain:      "other.test",
					L4Proto:     consts.L4ProtoType_UDP,
					ProcessName: pname("mosdns"),
				},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect, Must: true},
			},
			{
				Name: "non_matching_sentinel_does_not_set_must",
				Input: CorpusInput{
					Src:         staticSrcV4(),
					Dst:         netMustParseAddrPort("198.51.100.20:53"),
					Domain:      "api.route.example",
					L4Proto:     consts.L4ProtoType_UDP,
					ProcessName: pname("curl"),
				},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name: "sentinel_is_scoped_to_udp_dns",
				Input: CorpusInput{
					Src:         staticSrcV4(),
					Dst:         netMustParseAddrPort("198.51.100.20:53"),
					Domain:      "api.route.example",
					L4Proto:     consts.L4ProtoType_TCP,
					ProcessName: pname("mosdns"),
				},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
			{
				Name: "terminal_must_direct_does_not_require_sentinel",
				Input: CorpusInput{
					Src:     staticSrcV4(),
					Dst:     staticDstV4(),
					Domain:  "api.must-direct.example",
					L4Proto: consts.L4ProtoType_TCP,
				},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect, Must: true},
			},
		},
	}
}

func reservedOutboundFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "reserved_outbound",
		Description: "Rules targeting 'direct' or 'block' select the corresponding reserved index",
		Rules: []*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "direct.test",
					}},
				}},
				Outbound: config_parser.Function{Name: "direct"},
			},
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "block.test",
					}},
				}},
				Outbound: config_parser.Function{Name: "block"},
			},
		},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "matches_direct_rule",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "x.direct.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundDirect},
			},
			{
				Name:     "matches_block_rule",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "y.block.test", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundBlock},
			},
		},
	}
}

func priorityFirstWinsFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "priority_first_match_wins",
		Description: "When two rules could match, the earlier rule's outbound wins",
		Rules: []*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "example.com",
					}},
				}},
				Outbound: config_parser.Function{Name: "proxy"},
			},
			{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "example.com",
					}},
				}},
				Outbound: config_parser.Function{Name: "myapp"},
			},
		},
		Fallback:    config.FunctionOrString("direct"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "earlier_proxy_wins_over_later_myapp",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "www.example.com", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundUserDefinedMin},
			},
		},
	}
}

func fallbackOnlyFixture() CorpusFixture {
	return CorpusFixture{
		Name:        "fallback_only",
		Description: "With no rules, every input falls through to the fallback outbound",
		Rules:       nil,
		Fallback:    config.FunctionOrString("block"),
		OutboundIDs: stdOutboundIDs(),
		Cases: []CorpusCase{
			{
				Name:     "no_rules_yields_fallback",
				Input:    CorpusInput{Src: staticSrcV4(), Dst: staticDstV4(), Domain: "anything", L4Proto: consts.L4ProtoType_TCP},
				Expected: CorpusExpected{Outbound: consts.OutboundBlock},
			},
		},
	}
}
