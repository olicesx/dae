/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// These tests pin the dropped-datagram contract on the `udp://` scheme. A
// dropped datagram and a TC=1 answer are two spellings of the same operator
// situation - the UDP attempt produced no usable answer - so a declared
// `udp://` upstream retries over TCP for both. The drop stays soft everywhere
// else: no dialer health, no forwarder retirement. A transparent as-is
// destination stays verbatim, like the truncation contract already does.

// droppedDatagramError is the typed error a transport produces when it drained
// one oversized or unattributable datagram and kept the session usable.
func droppedDatagramError() error {
	return netproxy.DatagramDropped(io.ErrShortBuffer)
}

// TestConfiguredUDPUpstreamDroppedDatagramUpgradesToTCP drives the full TCP
// client ingress: the `udp://` upstream drops the datagram, the controller
// retries the same query over TCP and delivers the answer, and the drop
// counters record the retry without touching the truncation counters.
func TestConfiguredUDPUpstreamDroppedDatagramUpgradesToTCP(t *testing.T) {
	const queryName = truncatedUpstreamProbeQName
	var tcpCalls atomic.Int32

	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		switch dialArg.l4proto {
		case consts.L4ProtoStr_UDP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				return nil, droppedDatagramError()
			}}, nil
		case consts.L4ProtoStr_TCP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				tcpCalls.Add(1)
				return dnsAResponseMsg(queryName, "198.51.100.81"), nil
			}}, nil
		default:
			return nil, fmt.Errorf("unexpected transport %q", dialArg.l4proto)
		}
	})

	ctrl := newTruncatedUpstreamController(t, "u:udp://192.0.2.11:53")
	setScopedBestDialerChooser(ctrl, tcpAwareChooser(t,
		netip.MustParseAddrPort("192.0.2.11:53"), netip.MustParseAddrPort("192.0.2.11:53")))

	response := runTCPDNSIngressQuery(t, ctrl, queryName, 0x5b01)
	if response.Rcode != dnsmessage.RcodeSuccess || response.Truncated {
		t.Fatalf("response header = %+v, want a complete NOERROR answer", response.MsgHdr)
	}
	if got := dnsAnswerIPv4(t, response); got != "198.51.100.81" {
		t.Fatalf("answer = %s, want the TCP-retried answer", got)
	}
	if got := tcpCalls.Load(); got != 1 {
		t.Fatalf("TCP forward calls = %d, want 1", got)
	}
	if got := ctrl.dnsDroppedDatagrams.Load(); got != 1 {
		t.Fatalf("dropped datagram counter = %d, want 1", got)
	}
	if got := ctrl.dnsDroppedRetries.Load(); got != 1 {
		t.Fatalf("drop retry counter = %d, want 1", got)
	}
	if got := ctrl.dnsDroppedRetryFailures.Load(); got != 0 {
		t.Fatalf("drop retry failure counter = %d, want 0", got)
	}
	if got := ctrl.dnsUdpTruncatedUpgrades.Load(); got != 0 {
		t.Fatalf("truncation upgrade counter = %d, want 0 (a drop is not a TC=1 answer)", got)
	}
	if got := ctrl.dnsUdpTruncatedUpgradeFailures.Load(); got != 0 {
		t.Fatalf("truncation upgrade failure counter = %d, want 0", got)
	}
}

// TestConfiguredUDPUpstreamDroppedDatagramWithFailedRetryFailsTheQuery is the
// same row with a retry that cannot deliver: the caller sees a real failure
// (the client gets SERVFAIL, not TC=1 - a drop carries no evidence about the
// client's buffer), the failure is counted as a drop-retry failure, and the
// composed error keeps the drop cause so the query still does not blame the
// node's dialer health.
func TestConfiguredUDPUpstreamDroppedDatagramWithFailedRetryFailsTheQuery(t *testing.T) {
	const queryName = truncatedUpstreamProbeQName
	var tcpCalls atomic.Int32

	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		switch dialArg.l4proto {
		case consts.L4ProtoStr_UDP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				return nil, droppedDatagramError()
			}}, nil
		case consts.L4ProtoStr_TCP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				tcpCalls.Add(1)
				return nil, io.ErrUnexpectedEOF
			}}, nil
		default:
			return nil, fmt.Errorf("unexpected transport %q", dialArg.l4proto)
		}
	})

	ctrl := newTruncatedUpstreamController(t, "u:udp://192.0.2.11:53")
	setScopedBestDialerChooser(ctrl, tcpAwareChooser(t,
		netip.MustParseAddrPort("192.0.2.11:53"), netip.MustParseAddrPort("192.0.2.11:53")))

	response := runTCPDNSIngressQuery(t, ctrl, queryName, 0x5b02)
	if response.Rcode != dnsmessage.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL: a drop is not a truncation signal", response.Rcode)
	}
	if response.Truncated {
		t.Fatal("a failed drop retry must not fabricate TC=1")
	}
	if got := tcpCalls.Load(); got != 1 {
		t.Fatalf("TCP forward calls = %d, want 1", got)
	}
	if got := ctrl.dnsDroppedRetries.Load(); got != 0 {
		t.Fatalf("drop retry counter = %d, want 0 (the retry failed)", got)
	}
	if got := ctrl.dnsDroppedRetryFailures.Load(); got != 1 {
		t.Fatalf("drop retry failure counter = %d, want 1", got)
	}

	// The error contract itself, without the ingress in between: the composed
	// error must keep the drop cause and must not claim truncation.
	queryWire, err := corpusDnsQuery(0x5b03, queryName, dnsmessage.TypeA).Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	upstream := &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_UDP,
		Hostname: "192.0.2.11",
		Port:     53,
	}
	primary := &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4, bestTarget: netip.MustParseAddrPort("192.0.2.11:53")}
	_, _, err = ctrl.forwardWithFallback(context.Background(), defaultUdpRequest(), upstream, primary, queryWire, false)
	if err == nil {
		t.Fatal("a drop with a failed TCP retry must be reported to the caller")
	}
	if errors.Is(err, ErrDNSTruncated) {
		t.Fatalf("error %v claims truncation, want the drop cause", err)
	}
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("error %v lost the drop cause, want io.ErrShortBuffer in the chain", err)
	}
}

// TestConfiguredTCPAndUDPUpstreamDroppedDatagramStillRetries pins the
// pre-existing `tcp+udp://` behavior on the new counters: that scheme retried
// on every UDP failure before this contract existed, and its retries now count
// as drop retries instead of disappearing into the truncation family.
func TestConfiguredTCPAndUDPUpstreamDroppedDatagramStillRetries(t *testing.T) {
	const queryName = truncatedUpstreamProbeQName
	var tcpCalls atomic.Int32

	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		switch dialArg.l4proto {
		case consts.L4ProtoStr_UDP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				return nil, droppedDatagramError()
			}}, nil
		case consts.L4ProtoStr_TCP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				tcpCalls.Add(1)
				return dnsAResponseMsg(queryName, "198.51.100.82"), nil
			}}, nil
		default:
			return nil, fmt.Errorf("unexpected transport %q", dialArg.l4proto)
		}
	})

	ctrl := newTruncatedUpstreamController(t, "u:tcp+udp://192.0.2.11:53")
	setScopedBestDialerChooser(ctrl, tcpAwareChooser(t,
		netip.MustParseAddrPort("192.0.2.11:53"), netip.MustParseAddrPort("192.0.2.11:53")))

	response := runTCPDNSIngressQuery(t, ctrl, queryName, 0x5b04)
	if response.Rcode != dnsmessage.RcodeSuccess || response.Truncated {
		t.Fatalf("response header = %+v, want a complete NOERROR answer", response.MsgHdr)
	}
	if got := dnsAnswerIPv4(t, response); got != "198.51.100.82" {
		t.Fatalf("answer = %s, want the TCP-retried answer", got)
	}
	if got := tcpCalls.Load(); got != 1 {
		t.Fatalf("TCP forward calls = %d, want 1", got)
	}
	if got := ctrl.dnsDroppedRetries.Load(); got != 1 {
		t.Fatalf("drop retry counter = %d, want 1", got)
	}
}

// TestDroppedDatagramDoesNotUpgradeOtherSchemes keeps the widened criterion
// scoped to `udp://`: a non-TCP-capable scheme (here DoQ) must not silently
// gain a TCP fallback just because a datagram was dropped.
func TestDroppedDatagramDoesNotUpgradeOtherSchemes(t *testing.T) {
	var forwardCalls atomic.Int32
	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			forwardCalls.Add(1)
			return nil, droppedDatagramError()
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

	queryWire, err := corpusDnsQuery(0x5b05, "doq.test.", dnsmessage.TypeA).Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	if _, _, err := ctrl.forwardWithFallback(context.Background(), defaultUdpRequest(), upstream, primary, queryWire, false); err == nil {
		t.Fatal("a non-udp scheme must not silently gain a TCP fallback for a dropped datagram")
	}
	if got := forwardCalls.Load(); got != 1 {
		t.Fatalf("forward calls = %d, want 1 (no retry)", got)
	}
	if got := ctrl.dnsDroppedRetries.Load(); got != 0 {
		t.Fatalf("drop retry counter = %d, want 0 (no retry was attempted)", got)
	}
}
