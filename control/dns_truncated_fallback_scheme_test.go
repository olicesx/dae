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
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// The sibling truncation tests stub the forwarder factory whole, which is what
// let a broken TCP retry hide: the retry path handed the *pre-rewrite* upstream
// to the factory, where the production constructor rejects a TCP dial argument
// paired with a "udp" scheme ("unexpected scheme: udp"). These tests keep the
// real constructor in the loop and only stub the transport, so the scheme the
// retry is built from is part of what is asserted.

// constructionCheckedFactory asserts the (upstream, dial argument) pair can be
// built by the production constructor, then serves it from a canned forwarder.
type constructionCheckedFactory struct {
	seen []string
	// serve is invoked with the transport that the controller selected.
	serve func(l4proto consts.L4ProtoStr) (*dnsmessage.Msg, error)
}

func (f *constructionCheckedFactory) install(t *testing.T) {
	t.Helper()
	installCorpusDnsForwarderFactory(t, func(upstream *componentdns.Upstream, dialArg dialArgument, log *logrus.Logger) (DnsForwarder, error) {
		f.seen = append(f.seen, fmt.Sprintf("%s/%s", upstream.Scheme, dialArg.l4proto))
		if _, err := newDnsForwarder(upstream, dialArg, log); err != nil {
			return nil, err
		}
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return f.serve(dialArg.l4proto)
		}}, nil
	})
}

// TestTruncatedAsIsUpgradeBuildsRetryFromTheTCPScheme drives the as-is ingress
// path (the request-routing fallback in truncatedTestConfig resolves to an
// as-is destination) end to end: the UDP attempt answers TC=1, so the retry
// must be constructed as a TCP upstream and deliver the full answer.
func TestTruncatedAsIsUpgradeBuildsRetryFromTheTCPScheme(t *testing.T) {
	const queryName = "asis-truncated-upgrade.test."

	factory := &constructionCheckedFactory{
		serve: func(l4proto consts.L4ProtoStr) (*dnsmessage.Msg, error) {
			switch l4proto {
			case consts.L4ProtoStr_UDP:
				return nil, ErrDNSTruncated
			case consts.L4ProtoStr_TCP:
				return dnsAResponseMsg(queryName, "198.51.100.88"), nil
			default:
				return nil, fmt.Errorf("unexpected transport %q", l4proto)
			}
		},
	}
	factory.install(t)

	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	setScopedBestDialerChooser(ctrl, tcpAwareChooser(t,
		netip.MustParseAddrPort("198.51.100.53:53"), netip.MustParseAddrPort("198.51.100.53:53")))

	response := runTCPDNSIngressQuery(t, ctrl, queryName, 0x5a10)
	if response.Rcode != dnsmessage.RcodeSuccess || response.Truncated {
		t.Fatalf("response header = %+v, want a complete NOERROR answer", response.MsgHdr)
	}
	if got := dnsAnswerIPv4(t, response); got != "198.51.100.88" {
		t.Fatalf("answer = %s, want the TCP-retried answer", got)
	}
	if len(factory.seen) != 2 || factory.seen[0] != "udp/udp" || factory.seen[1] != "tcp/tcp" {
		t.Fatalf("forwarder construction = %v, want [udp/udp tcp/tcp]", factory.seen)
	}
	if got := ctrl.dnsUdpTruncatedUpgrades.Load(); got != 1 {
		t.Fatalf("truncated upgrade counter = %d, want 1", got)
	}
	if got := ctrl.dnsUdpTruncatedUpgradeFailures.Load(); got != 0 {
		t.Fatalf("truncated upgrade failure counter = %d, want 0", got)
	}
}

// TestTruncatedConfiguredUDPUpstreamUpgradesOverTCP is the same contract for an
// explicitly configured `udp://` upstream, which is the spelling the docs use.
func TestTruncatedConfiguredUDPUpstreamUpgradesOverTCP(t *testing.T) {
	const queryName = "udp-upstream-truncated-upgrade.test."

	factory := &constructionCheckedFactory{
		serve: func(l4proto consts.L4ProtoStr) (*dnsmessage.Msg, error) {
			switch l4proto {
			case consts.L4ProtoStr_UDP:
				return nil, ErrDNSTruncated
			case consts.L4ProtoStr_TCP:
				return dnsAResponseMsg(queryName, "198.51.100.89"), nil
			default:
				return nil, fmt.Errorf("unexpected transport %q", l4proto)
			}
		},
	}
	factory.install(t)

	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	setScopedBestDialerChooser(ctrl, tcpAwareChooser(t,
		netip.MustParseAddrPort("198.51.100.53:53"), netip.MustParseAddrPort("198.51.100.53:53")))

	upstream := &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_UDP,
		Hostname: "198.51.100.53",
		Port:     53,
	}
	primary := &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4, bestTarget: netip.MustParseAddrPort("198.51.100.53:53")}
	queryWire, err := corpusDnsQuery(0x5a11, queryName, dnsmessage.TypeA).Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	respMsg, usedDialArg, err := ctrl.forwardWithFallback(context.Background(), defaultUdpRequest(), upstream, primary, queryWire, false)
	if err != nil {
		t.Fatalf("forwardWithFallback() error = %v, want a TCP-upgraded answer", err)
	}
	if usedDialArg == nil || usedDialArg.l4proto != consts.L4ProtoStr_TCP {
		t.Fatalf("used dial argument = %+v, want the TCP retry", usedDialArg)
	}
	if respMsg == nil || len(respMsg.Answer) != 1 {
		t.Fatalf("response = %+v, want one answer record", respMsg)
	}
	if len(factory.seen) != 2 || factory.seen[0] != "udp/udp" || factory.seen[1] != "tcp/tcp" {
		t.Fatalf("forwarder construction = %v, want [udp/udp tcp/tcp]", factory.seen)
	}
	if got := ctrl.dnsUdpTruncatedUpgrades.Load(); got != 1 {
		t.Fatalf("truncated upgrade counter = %d, want 1", got)
	}
}
