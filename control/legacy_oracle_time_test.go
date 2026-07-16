/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

// legacyOracleTimedDNSTrace uses legacyOracleFacts.At as a replay input for
// the cache's TTL projection. This keeps timeline facts in the oracle rather
// than treating them as documentation attached to a routing vector.
type legacyOracleTimedDNSTrace struct {
	Name      string
	QueryWire []byte
	Facts     legacyOracleFacts
	CacheTTL  uint32
	Want      legacyOracleActionTrace
}

func legacyOracleTimedDNSTraces() []legacyOracleTimedDNSTrace {
	return []legacyOracleTimedDNSTrace{{
		Name: "cache_ttl_at_twenty_seconds_projects_forty_second_response",
		QueryWire: []byte{
			0x0d, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x0a, 'o', 'r', 'a', 'c', 'l', 'e', '-', 'd', 'n', 's',
			0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01,
		},
		Facts: legacyOracleFacts{
			DNSAnswer: legacyDNSAnswer{
				Question: "oracle-dns.test.",
				RCode:    dnsmessage.RcodeSuccess,
				Answers:  []netip.Addr{netip.MustParseAddr("198.51.100.80")},
				Wire: []byte{
					0x0d, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
					0x00, 0x00, 0x00, 0x00, 0x0a, 'o', 'r', 'a', 'c', 'l', 'e', '-', 'd', 'n', 's',
					0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01,
					0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
					0x00, 0x3c, 0x00, 0x04, 0xc6, 0x33, 0x64, 0x50,
				},
			},
			At: 20 * time.Second,
		},
		CacheTTL: 60,
		Want: legacyOracleActionTrace{
			L4Proto:       consts.L4ProtoType_UDP,
			AddressFamily: consts.IpVersion_4,
			DNSResponseWire: []byte{
				0x0d, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x0a, 'o', 'r', 'a', 'c', 'l', 'e', '-', 'd', 'n', 's',
				0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01,
				0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x28, 0x00, 0x04, 0xc6, 0x33, 0x64, 0x50,
			},
			ExecutionResolved: true,
		},
	}}
}

func validateLegacyOracleTimedDNSTrace(trace legacyOracleTimedDNSTrace) error {
	if trace.Name == "" || len(trace.QueryWire) == 0 || trace.CacheTTL == 0 {
		return fmt.Errorf("timed DNS trace input is incomplete")
	}
	if trace.Facts.At <= 0 || trace.Facts.At >= time.Duration(trace.CacheTTL)*time.Second {
		return fmt.Errorf("event time %s is outside the cache TTL", trace.Facts.At)
	}
	if trace.Facts.DNSAnswer.Question == "" || len(trace.Facts.DNSAnswer.Wire) == 0 || len(trace.Want.DNSResponseWire) == 0 {
		return fmt.Errorf("timed DNS trace wire facts are incomplete")
	}
	return nil
}

func (o LegacyOracle) replayTimedDNS(t *testing.T, trace legacyOracleTimedDNSTrace) (legacyOracleActionTrace, error) {
	t.Helper()

	var query dnsmessage.Msg
	if err := query.Unpack(trace.QueryWire); err != nil {
		return legacyOracleActionTrace{}, fmt.Errorf("unpack query wire: %w", err)
	}
	var answer dnsmessage.Msg
	if err := answer.Unpack(trace.Facts.DNSAnswer.Wire); err != nil {
		return legacyOracleActionTrace{}, fmt.Errorf("unpack recorded answer wire: %w", err)
	}
	if len(query.Question) != 1 || len(answer.Question) != 1 || query.Question[0].Name != trace.Facts.DNSAnswer.Question || answer.Question[0].Name != trace.Facts.DNSAnswer.Question {
		return legacyOracleActionTrace{}, fmt.Errorf("recorded DNS question does not match its wires")
	}
	if len(answer.Answer) != len(trace.Facts.DNSAnswer.Answers) {
		return legacyOracleActionTrace{}, fmt.Errorf("recorded DNS answer count does not match its wire")
	}

	baseTime := time.Unix(1_700_000_000, 0)
	deadline := baseTime.Add(time.Duration(trace.CacheTTL) * time.Second)
	cache := &DnsCache{
		Answer:           copyLegacyOracleDNSRRs(answer.Answer),
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}
	wire := cache.FillIntoWithTTL(&query, baseTime.Add(trace.Facts.At))
	if len(wire) == 0 {
		return legacyOracleActionTrace{}, fmt.Errorf("timed cache replay returned no response")
	}
	return legacyOracleActionTrace{
		L4Proto:           consts.L4ProtoType_UDP,
		AddressFamily:     consts.IpVersion_4,
		DNSResponseWire:   wire,
		ExecutionResolved: true,
	}, nil
}

func copyLegacyOracleDNSRRs(rrs []dnsmessage.RR) []dnsmessage.RR {
	clone := make([]dnsmessage.RR, len(rrs))
	for i, rr := range rrs {
		clone[i] = dnsmessage.Copy(rr)
	}
	return clone
}
