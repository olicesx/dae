/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"

	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// Regression coverage for upstream replies that carry a terminal error code but
// no question section.
//
// DNSPod (119.29.29.29) answers NXDOMAIN with QUERY:0 for Bonjour/DNS-SD
// reverse lookups (*._dns-sd._udp.*.in-addr.arpa, qtype PTR). Without the
// relaxed path in resolveDNSUpstream such a reply is dropped by the RFC 5452
// echo check and the client sees SERVFAIL (in practice a 5s timeout).
//
// The relaxed path is deliberately narrow: only NXDOMAIN, REFUSED, or SERVFAIL
// with an empty answer section, an empty authority section, and no additional
// records other than EDNS OPT inherits the request's question. Positive
// answers, NOERROR/NODATA, an authority SOA, and any other additional record
// must still echo the question or they stay dropped.

// questionlessTestDnsConfig mirrors the corpus fixtures: nothing matches the
// request routing, so it is forwarded as-is and the upstream reply is accepted.
func questionlessTestDnsConfig() *config.Dns {
	return &config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "asis"},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	}
}

// questionlessUpstreamReply builds an upstream reply with no question section,
// the shape DNSPod returns for a terminal error.
func questionlessUpstreamReply(rcode int, answers, ns, extra []dnsmessage.RR) *dnsmessage.Msg {
	msg := new(dnsmessage.Msg)
	msg.SetReply(&dnsmessage.Msg{})
	msg.Question = nil
	msg.Rcode = rcode
	msg.Answer = answers
	msg.Ns = ns
	msg.Extra = extra
	return msg
}

// runQuestionlessUpstreamReply drives one client query through the controller
// with a canned upstream reply and returns what was handed to the client (nil
// when nothing was written) plus the transport error.
func runQuestionlessUpstreamReply(t *testing.T, reply, query *dnsmessage.Msg) (*dnsmessage.Msg, error) {
	t.Helper()
	installCorpusDnsForwarderFactory(t, func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return reply.Copy(), nil
		}}, nil
	})
	ctrl := newCorpusControllerWithDefaultChooser(t, questionlessTestDnsConfig())
	writer := &dnsCorpusCaptureWriter{}
	err := ctrl.HandleWithResponseWriter_(context.Background(), query, defaultUdpRequest(), writer)
	return writer.Message(), err
}

func TestQuestionlessTerminalUpstreamReplyIsDelivered(t *testing.T) {
	// The real trigger: an Apple device's Bonjour/DNS-SD reverse lookup.
	const qname = "db._dns-sd._udp.0.5.168.192.in-addr.arpa."

	opt := &dnsmessage.OPT{Hdr: dnsmessage.RR_Header{Name: ".", Rrtype: dnsmessage.TypeOPT, Class: 1232}}
	soa := &dnsmessage.SOA{
		Hdr:  dnsmessage.RR_Header{Name: "in-addr.arpa.", Rrtype: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, Ttl: 60},
		Ns:   "ns.example.com.",
		Mbox: "hostmaster.example.com.",
	}
	cases := []struct {
		name    string
		rcode   int
		answers []dnsmessage.RR
		ns      []dnsmessage.RR
		extra   []dnsmessage.RR
		wantErr bool
	}{
		{
			name:  "nxdomain_without_question_is_delivered",
			rcode: dnsmessage.RcodeNameError,
		},
		{
			name:  "refused_without_question_is_delivered",
			rcode: dnsmessage.RcodeRefused,
		},
		{
			name:  "servfail_without_question_is_delivered",
			rcode: dnsmessage.RcodeServerFailure,
		},
		{
			name:  "nxdomain_with_only_edns_opt_is_delivered",
			rcode: dnsmessage.RcodeNameError,
			extra: []dnsmessage.RR{opt},
		},
		{
			name:    "positive_answer_without_question_is_still_dropped",
			rcode:   dnsmessage.RcodeSuccess,
			answers: dnsAResponseMsg(qname, "203.0.113.7").Answer,
			wantErr: true,
		},
		{
			name:    "nodata_without_question_is_still_dropped",
			rcode:   dnsmessage.RcodeSuccess,
			wantErr: true,
		},
		{
			name:    "nxdomain_with_authority_soa_is_still_dropped",
			rcode:   dnsmessage.RcodeNameError,
			ns:      []dnsmessage.RR{soa},
			wantErr: true,
		},
		{
			name:    "nxdomain_with_additional_address_is_still_dropped",
			rcode:   dnsmessage.RcodeNameError,
			extra:   dnsAResponseMsg(qname, "203.0.113.7").Answer,
			wantErr: true,
		},
		{
			name:    "formerr_without_records_is_still_dropped",
			rcode:   dnsmessage.RcodeFormatError,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query := corpusDnsQuery(0x4242, qname, dnsmessage.TypePTR)
			resp, err := runQuestionlessUpstreamReply(t, questionlessUpstreamReply(tc.rcode, tc.answers, tc.ns, tc.extra), query)

			if tc.wantErr {
				require.Error(t, err, "the echo check must keep dropping this reply")
				if resp != nil {
					require.NotEqual(t, dnsmessage.RcodeSuccess, resp.Rcode,
						"a dropped upstream reply must not surface to the client as success")
					require.Empty(t, resp.Answer, "no upstream record may leak into the client response")
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp, "a question-less terminal error must reach the client")
			require.Equal(t, query.Id, resp.Id)
			require.Equal(t, tc.rcode, resp.Rcode)
			require.Empty(t, resp.Answer)
			require.Len(t, resp.Question, 1,
				"the request question is restored so the reply is a valid response to this query")
			require.Equal(t, dnsmessage.CanonicalName(qname), dnsmessage.CanonicalName(resp.Question[0].Name))
			require.Equal(t, dnsmessage.TypePTR, resp.Question[0].Qtype)
			require.Equal(t, query.Question[0].Qclass, resp.Question[0].Qclass)
		})
	}
}
