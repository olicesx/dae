/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// These tests pin the RFC 7766 §5 truncation contract on both sides of the
// controller: a truncated (TC=1) upstream answer must be retried over TCP no
// matter which transport carried the first attempt, and when that retry cannot
// deliver the answer the client must receive TC=1 rather than a fabricated
// SERVFAIL.

func truncatedTestConfig() *config.Dns {
	return &config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("asis")},
			Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
		},
	}
}

// tcpAwareChooser mirrors the production scheme choice: UDP for udp-ish
// upstreams, TCP for the scheme the fallback rewrites to.
func tcpAwareChooser(t *testing.T, udpTarget, tcpTarget netip.AddrPort) func(context.Context, DnsRequestSnapshot, *componentdns.Upstream) (*dialArgument, error) {
	t.Helper()
	return func(_ context.Context, _ DnsRequestSnapshot, upstream *componentdns.Upstream) (*dialArgument, error) {
		switch upstream.Scheme {
		case componentdns.UpstreamScheme_UDP:
			return &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4, bestTarget: udpTarget}, nil
		case componentdns.UpstreamScheme_TCP:
			return &dialArgument{l4proto: consts.L4ProtoStr_TCP, ipversion: consts.IpVersionStr_4, bestTarget: tcpTarget}, nil
		default:
			return nil, fmt.Errorf("unexpected upstream scheme %q", upstream.Scheme)
		}
	}
}

// TestUDPUpstreamTruncatedAnswerUpgradesToTCP drives the full TCP client
// ingress: the upstream answers TC=1 over UDP, and the controller must retry the
// same query over TCP and deliver the complete answer.
func TestUDPUpstreamTruncatedAnswerUpgradesToTCP(t *testing.T) {
	const queryName = "truncated-upgrade.test."
	var udpCalls, tcpCalls atomic.Int32

	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		switch dialArg.l4proto {
		case consts.L4ProtoStr_UDP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				udpCalls.Add(1)
				return nil, ErrDNSTruncated
			}}, nil
		case consts.L4ProtoStr_TCP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				tcpCalls.Add(1)
				return dnsAResponseMsg(queryName, "198.51.100.77"), nil
			}}, nil
		default:
			return nil, fmt.Errorf("unexpected transport %q", dialArg.l4proto)
		}
	})

	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	setScopedBestDialerChooser(ctrl, tcpAwareChooser(t,
		netip.MustParseAddrPort("198.51.100.53:53"), netip.MustParseAddrPort("198.51.100.53:53")))

	response := runTCPDNSIngressQuery(t, ctrl, queryName, 0x5a01)
	if response.Rcode != dnsmessage.RcodeSuccess || response.Truncated {
		t.Fatalf("response header = %+v, want a complete NOERROR answer", response.MsgHdr)
	}
	if got := dnsAnswerIPv4(t, response); got != "198.51.100.77" {
		t.Fatalf("answer = %s, want the TCP-retried answer", got)
	}
	if got := udpCalls.Load(); got != 1 {
		t.Fatalf("UDP forward calls = %d, want 1", got)
	}
	if got := tcpCalls.Load(); got != 1 {
		t.Fatalf("TCP forward calls = %d, want 1", got)
	}
	if got := ctrl.dnsUdpTruncatedUpgrades.Load(); got != 1 {
		t.Fatalf("truncated upgrade counter = %d, want 1", got)
	}
	if got := ctrl.dnsUdpTruncatedUpgradeFailures.Load(); got != 0 {
		t.Fatalf("truncated upgrade failure counter = %d, want 0", got)
	}
}

// TestUDPUpstreamTruncatedAnswerWithFailedRetryReturnsTC covers the visible
// failure path: the TCP retry fails, so the client must receive TC=1 (RFC 7766
// §5) instead of SERVFAIL, and the failure must be counted.
func TestUDPUpstreamTruncatedAnswerWithFailedRetryReturnsTC(t *testing.T) {
	const queryName = "truncated-fallback-fail.test."
	var tcpCalls atomic.Int32

	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		switch dialArg.l4proto {
		case consts.L4ProtoStr_UDP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				return nil, ErrDNSTruncated
			}}, nil
		case consts.L4ProtoStr_TCP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				tcpCalls.Add(1)
				return nil, fmt.Errorf("tcp retry failed")
			}}, nil
		default:
			return nil, fmt.Errorf("unexpected transport %q", dialArg.l4proto)
		}
	})

	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	setScopedBestDialerChooser(ctrl, tcpAwareChooser(t,
		netip.MustParseAddrPort("198.51.100.53:53"), netip.MustParseAddrPort("198.51.100.53:53")))

	response := runTCPDNSIngressQuery(t, ctrl, queryName, 0x5a02)
	if response.Rcode != dnsmessage.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR with TC=1 instead of SERVFAIL", response.Rcode)
	}
	if !response.Truncated {
		t.Fatal("the response must carry TC=1 so the client knows the answer did not fit")
	}
	if len(response.Answer) != 0 {
		t.Fatalf("a truncated response must not carry an answer, got %d records", len(response.Answer))
	}
	if got := tcpCalls.Load(); got != 1 {
		t.Fatalf("TCP forward calls = %d, want 1", got)
	}
	if got := ctrl.dnsUdpTruncatedUpgradeFailures.Load(); got != 1 {
		t.Fatalf("truncated upgrade failure counter = %d, want 1", got)
	}
	if got := ctrl.dnsTruncatedRepliesToClient.Load(); got != 1 {
		t.Fatalf("truncated client reply counter = %d, want 1", got)
	}
}

// TestTruncatedAnswerDoesNotUpgradeOtherSchemes proves the widened fallback
// criterion stays scoped to `udp://`: a UDP-transported scheme that is not
// `udp://` (here DoQ) must keep its declared transport contract.
func TestTruncatedAnswerDoesNotUpgradeOtherSchemes(t *testing.T) {
	var forwardCalls atomic.Int32
	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			forwardCalls.Add(1)
			return nil, ErrDNSTruncated
		}}, nil
	})

	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	setScopedBestDialerChooser(ctrl, func(_ context.Context, _ DnsRequestSnapshot, _ *componentdns.Upstream) (*dialArgument, error) {
		return &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4, bestTarget: netip.MustParseAddrPort("198.51.100.53:853")}, nil
	})

	upstream := &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_QUIC,
		Hostname: "dns.example",
		Port:     853,
	}
	primary := &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4, bestTarget: netip.MustParseAddrPort("198.51.100.53:853")}

	queryWire, err := corpusDnsQuery(0x5a03, "doq.test.", dnsmessage.TypeA).Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	if _, _, err := ctrl.forwardWithFallback(context.Background(), defaultUdpRequest(), upstream, primary, queryWire, false); err == nil {
		t.Fatal("a non-udp scheme must not silently gain a TCP fallback")
	}
	if got := forwardCalls.Load(); got != 1 {
		t.Fatalf("forward calls = %d, want 1 (no retry)", got)
	}
}

// TestUDPUpstreamNonTruncatedFailureDoesNotFallBack keeps the pre-existing
// contract for `udp://`: only the truncation signal triggers the upgrade, not
// arbitrary failures.
func TestUDPUpstreamNonTruncatedFailureDoesNotFallBack(t *testing.T) {
	var forwardCalls atomic.Int32
	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			forwardCalls.Add(1)
			return nil, fmt.Errorf("udp transport failed")
		}}, nil
	})

	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	setScopedBestDialerChooser(ctrl, tcpAwareChooser(t,
		netip.MustParseAddrPort("198.51.100.53:53"), netip.MustParseAddrPort("198.51.100.53:53")))

	upstream := &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_UDP,
		Hostname: "198.51.100.53",
		Port:     53,
	}
	primary := &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4, bestTarget: netip.MustParseAddrPort("198.51.100.53:53")}

	if _, _, err := ctrl.forwardWithFallback(context.Background(), defaultUdpRequest(), upstream, primary, []byte{0, 1, 2, 3}, false); err == nil {
		t.Fatal("a non-truncated UDP failure must still be reported to the caller")
	}
	if got := forwardCalls.Load(); got != 1 {
		t.Fatalf("forward calls = %d, want 1 (no TCP retry for a plain UDP failure)", got)
	}
}

// runTCPDNSIngressQuery sends one DNS/TCP query through the real TCP fast path
// and returns the decoded response.
func runTCPDNSIngressQuery(t *testing.T, ctrl *DnsController, queryName string, queryID uint16) *dnsmessage.Msg {
	t.Helper()

	log := logrus.New()
	log.SetOutput(io.Discard)
	plane := &ControlPlane{
		log: log,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: ctrl,
		},
	}
	resetActiveControlPlanePublicationForTest(t)
	plane.publishActiveControlPlane()
	t.Cleanup(plane.unpublishActiveControlPlane)

	query := new(dnsmessage.Msg)
	query.SetQuestion(queryName, dnsmessage.TypeA)
	query.Id = queryID
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatalf("query Pack() error = %v", err)
	}
	queryFrame := make([]byte, 2+len(queryWire))
	queryFrame[0] = byte(len(queryWire) >> 8)
	queryFrame[1] = byte(len(queryWire))
	copy(queryFrame[2:], queryWire)

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })
	t.Cleanup(func() { _ = clientConn.Close() })
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("clientConn.SetDeadline() error = %v", err)
	}

	go func() {
		_, _ = plane.handleTCPDnsFastPathOwned(
			context.Background(),
			serverConn,
			bufio.NewReader(serverConn),
			netip.MustParseAddrPort("192.0.2.10:42424"),
			netip.MustParseAddrPort("198.51.100.53:53"),
			&bpfRoutingResult{},
			nil,
		)
	}()

	if _, err := clientConn.Write(queryFrame); err != nil {
		t.Fatalf("client query frame Write() error = %v", err)
	}
	_, responseWire := readPhase0TCPDnsFrame(t, clientConn)

	var response dnsmessage.Msg
	if err := response.Unpack(responseWire); err != nil {
		t.Fatalf("response Unpack() error = %v", err)
	}
	if response.Id != queryID {
		t.Fatalf("response id = %#x, want %#x", response.Id, queryID)
	}
	return &response
}
