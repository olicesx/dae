/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// legacyOracleDNSTrace replays a recorded DNS request and upstream response
// through DnsController. Both input wires and the expected client response
// wire are immutable literals so this test does not derive its golden from the
// implementation under test.
type legacyOracleDNSTrace struct {
	Name      string
	QueryWire []byte
	DNSAnswer legacyDNSAnswer
	Want      legacyOracleActionTrace
}

func legacyOracleDNSTraces() []legacyOracleDNSTrace {
	return []legacyOracleDNSTrace{{
		Name: "udp_named_upstream_returns_recorded_answer_wire",
		QueryWire: []byte{
			0x0d, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x0a, 'o', 'r', 'a', 'c', 'l', 'e', '-', 'd', 'n', 's',
			0x04, 't', 'e', 's', 't', 0x00,
			0x00, 0x01, 0x00, 0x01,
		},
		DNSAnswer: legacyDNSAnswer{
			Question: "oracle-dns.test.",
			RCode:    dnsmessage.RcodeSuccess,
			Answers:  []netip.Addr{netip.MustParseAddr("198.51.100.80")},
			Wire: []byte{
				0x0d, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x0a, 'o', 'r', 'a', 'c', 'l', 'e', '-', 'd', 'n', 's',
				0x04, 't', 'e', 's', 't', 0x00,
				0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
				0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
				0xc6, 0x33, 0x64, 0x50,
			},
		},
		Want: legacyOracleActionTrace{
			L4Proto:       consts.L4ProtoType_UDP,
			AddressFamily: consts.IpVersion_4,
			DNSResponseWire: []byte{
				0x0d, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x0a, 'o', 'r', 'a', 'c', 'l', 'e', '-', 'd', 'n', 's',
				0x04, 't', 'e', 's', 't', 0x00,
				0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
				0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
				0xc6, 0x33, 0x64, 0x50,
			},
			ExecutionResolved: true,
		},
	}}
}

func validateLegacyOracleDNSTrace(trace legacyOracleDNSTrace) error {
	if trace.Name == "" || len(trace.QueryWire) == 0 || len(trace.DNSAnswer.Wire) == 0 {
		return fmt.Errorf("DNS trace input is incomplete")
	}
	if trace.DNSAnswer.Question == "" || len(trace.DNSAnswer.Answers) == 0 {
		return fmt.Errorf("recorded DNS answer is incomplete")
	}
	if len(trace.Want.DNSResponseWire) == 0 {
		return fmt.Errorf("DNS response wire golden is empty")
	}

	var query dnsmessage.Msg
	if err := query.Unpack(trace.QueryWire); err != nil {
		return fmt.Errorf("unpack query wire: %w", err)
	}
	if len(query.Question) != 1 || query.Question[0].Name != trace.DNSAnswer.Question {
		return fmt.Errorf("query does not match recorded answer question")
	}
	var answer dnsmessage.Msg
	if err := answer.Unpack(trace.DNSAnswer.Wire); err != nil {
		return fmt.Errorf("unpack answer wire: %w", err)
	}
	if uint16(answer.Rcode) != trace.DNSAnswer.RCode || len(answer.Answer) != len(trace.DNSAnswer.Answers) {
		return fmt.Errorf("recorded answer metadata disagrees with its wire")
	}
	return nil
}

func (o LegacyOracle) replayDNS(t *testing.T, trace legacyOracleDNSTrace) (legacyOracleActionTrace, error) {
	t.Helper()

	ctrl := newCorpusDnsController(t, &config.Dns{
		Upstream: []config.KeyableString{"oracle:udp://192.0.2.53:53"},
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("oracle")},
			Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
		},
	})
	setScopedBestDialerChooser(ctrl, func(_ context.Context, req *udpRequest, _ *componentdns.Upstream) (*dialArgument, error) {
		return &dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestTarget: req.realDst,
		}, nil
	})

	var query dnsmessage.Msg
	if err := query.Unpack(trace.QueryWire); err != nil {
		return legacyOracleActionTrace{}, fmt.Errorf("unpack query: %w", err)
	}
	var upstreamAnswer dnsmessage.Msg
	if err := upstreamAnswer.Unpack(trace.DNSAnswer.Wire); err != nil {
		return legacyOracleActionTrace{}, fmt.Errorf("unpack recorded answer: %w", err)
	}

	previousFactory := dnsForwarderFactory
	t.Cleanup(func() { dnsForwarderFactory = previousFactory })
	forwardCalls := 0
	dnsForwarderFactory = func(upstream *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		if upstream == nil || upstream.Hostname != "192.0.2.53" {
			return nil, fmt.Errorf("unexpected DNS upstream %#v", upstream)
		}
		forwardCalls++
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return upstreamAnswer.Copy(), nil
		}}, nil
	}

	writer := &dnsCorpusCaptureWriter{}
	if err := ctrl.HandleWithResponseWriter_(context.Background(), &query, defaultUdpRequest(), writer); err != nil {
		return legacyOracleActionTrace{}, fmt.Errorf("HandleWithResponseWriter_: %w", err)
	}
	if forwardCalls != 1 {
		return legacyOracleActionTrace{}, fmt.Errorf("DNS forward calls = %d, want 1", forwardCalls)
	}
	if writer.Message() == nil {
		return legacyOracleActionTrace{}, fmt.Errorf("DNS controller did not write a response")
	}
	return legacyOracleActionTrace{
		L4Proto:           consts.L4ProtoType_UDP,
		AddressFamily:     consts.IpVersion_4,
		DNSResponseWire:   writer.Wire(),
		ExecutionResolved: true,
	}, nil
}
