/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// This file is the Phase 0 DNS compatibility corpus for the semantic
// architecture refactor. It mirrors the routing corpus pattern: each fixture
// declares a DNS routing program plus a set of cases that exercise a specific
// behaviour, and the ReplayDns driver runs the fixture against the current
// DnsController implementation to pin the observable result.
//
// Coverage target (per Phase 0 acceptance clause 2):
//   - UDP transport: cache miss / cache hit / cache stale + background refresh
//   - TCP transport: UDP failure triggering TCP fallback
//   - Reject-before-cache: routing-level reject must short-circuit cache hits
//   - QUIC sniffing: response routing driven by sniffed SNI (planned; needs
//     sniffing pipeline hook)
//   - Concurrency cap: REFUSED on overload
//
// Future phases (DNS projection split, three-valued response routing, etc.)
// MUST keep these corpus tests passing byte-for-byte. Any observable change
// in the captured response (rcode, answer count, answer data, rcode) is a
// semantic regression and blocks phase promotion.

// DnsCorpusCase captures a single DNS request and the observable response
// shape the corpus is pinning. The shape is intentionally coarse (rcode,
// answer count, optional data checks) so we do not over-constrain the
// refactor on byte-for-byte DNS message layout, which is already validated
// by the per-message unit tests.
type DnsCorpusCase struct {
	Name       string
	Query      func() *dnsmessage.Msg
	Request    func() *udpRequest
	PreState   func(t *testing.T, ctrl *DnsController)
	PostAssert func(t *testing.T, ctrl *DnsController, response *dnsmessage.Msg)
	Expected   DnsCorpusExpected
}

// DnsCorpusExpected describes the observable response shape. HasRcode and
// HasAnswerCount make zero-valued DNS semantics assertable: both NOERROR and
// an empty answer are meaningful compatibility outcomes.
type DnsCorpusExpected struct {
	HasRcode       bool
	Rcode          int
	HasAnswerCount bool
	AnswerCount    int
	AnswerIPv4     string // empty = no assertion
	AnswerIPv6     string // empty = no assertion
}

// DnsCorpusFixture bundles a DNS routing configuration with cases.
type DnsCorpusFixture struct {
	Name        string
	Description string
	BuildConfig func() *config.Dns
	// BestDialerChooser lets each fixture decide how the dial argument is
	// built. The default corpus chooser just returns the request's realDst.
	BestDialerChooser func(ctx context.Context, req *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error)
	// ForwarderFactory lets each fixture decide how upstream traffic is
	// served. Most fixtures inject a canned response, occasionally gated on
	// l4proto to simulate UDP failure / TCP fallback.
	ForwarderFactory func(upstream *componentdns.Upstream, dialArg dialArgument, log *logrus.Logger) (DnsForwarder, error)
	Cases            []DnsCorpusCase
}

// DnsCorpusFixtures returns the full Phase 0 DNS corpus. Add a constructor
// here to extend coverage; downstream refactor phases replay the same slice
// and must produce byte-identical observable results.
func DnsCorpusFixtures() []DnsCorpusFixture {
	return []DnsCorpusFixture{
		udpCacheMissFixture(),
		udpCacheHitFixture(),
		udpCacheStaleOptimisticFixture(),
		rejectBeforeCacheFixture(),
	}
}

// ReplayDns runs a fixture against a fresh DnsController. The driver:
//
//  1. Builds a controller from the fixture's config.
//  2. Installs the fixture's best-dialer chooser and forwarder factory.
//  3. For each case: optionally invokes PreState, then HandleWithResponseWriter_,
//     and asserts the captured response matches the expected shape.
//
// The factory swap is restored via t.Cleanup so the test does not leak
// global state into siblings.
func ReplayDns(t *testing.T, fixture DnsCorpusFixture) {
	t.Helper()
	originalFactory := dnsForwarderFactory
	t.Cleanup(func() { dnsForwarderFactory = originalFactory })

	ctrl := newCorpusDnsController(t, fixture.BuildConfig())

	chooser := fixture.BestDialerChooser
	if chooser == nil {
		chooser = defaultCorpusChooser
	}
	setScopedBestDialerChooser(ctrl, chooser)

	if fixture.ForwarderFactory != nil {
		dnsForwarderFactory = fixture.ForwarderFactory
	}

	for _, tc := range fixture.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			if tc.PreState != nil {
				tc.PreState(t, ctrl)
			}
			writer := &captureResponseWriter{}
			var req *udpRequest
			if tc.Request != nil {
				req = tc.Request()
			} else {
				req = defaultUdpRequest()
			}
			query := tc.Query()
			if query == nil {
				t.Fatalf("%s: nil Query in case %s", fixture.Name, tc.Name)
			}
			if err := ctrl.HandleWithResponseWriter_(context.Background(), query, req, writer); err != nil {
				t.Fatalf("HandleWithResponseWriter_ error = %v", err)
			}
			msg := writer.Message()
			if msg == nil {
				t.Fatalf("no response captured")
			}
			assertDnsShape(t, tc.Expected, msg)
			if tc.PostAssert != nil {
				tc.PostAssert(t, ctrl, msg)
			}
		})
	}
}

// newCorpusDnsController builds a controller from a Dns config the same way
// that newScopedDnsController does, but accepts the fixture-provided config.
func newCorpusDnsController(t *testing.T, cfg *config.Dns) *DnsController {
	t.Helper()
	if cfg == nil {
		t.Fatalf("fixture returned nil Dns config")
	}
	routing, err := componentdns.New(cfg, &componentdns.NewOption{
		Logger: logrus.New(),
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	require.NoError(t, err)

	ctrl, err := NewDnsController(routing, &DnsControllerOption{
		Log:                logrus.New(),
		LifecycleContext:   context.Background(),
		OptimisticCache:    true,
		OptimisticCacheTtl: 60,
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(*DnsCache) error {
			return nil
		},
		NewCache: func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				NS:               ns,
				Extra:            extra,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctrl.Close() })
	return ctrl
}

// defaultCorpusChooser matches the request's destination (UDP/IPv4). Sufficient
// for fixtures that do not need to dial a specific upstream host.
func defaultCorpusChooser(ctx context.Context, req *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error) {
	return &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestTarget: req.realDst,
	}, nil
}

// defaultUdpRequest is the placeholder request for cases that do not need
// specific source/destination addresses.
func defaultUdpRequest() *udpRequest {
	return &udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.10:41000"),
		realDst:       netip.MustParseAddrPort("1.1.1.1:53"),
		routingResult: &bpfRoutingResult{},
	}
}

// assertDnsShape checks only the explicitly asserted fields.
func assertDnsShape(t *testing.T, want DnsCorpusExpected, got *dnsmessage.Msg) {
	t.Helper()
	if want.HasRcode && got.Rcode != want.Rcode {
		t.Fatalf("rcode = %d, want %d", got.Rcode, want.Rcode)
	}
	if want.HasAnswerCount && len(got.Answer) != want.AnswerCount {
		t.Fatalf("answer count = %d, want %d", len(got.Answer), want.AnswerCount)
	}
	if want.AnswerIPv4 != "" {
		ip := dnsAnswerIPv4(t, got)
		if ip != want.AnswerIPv4 {
			t.Fatalf("answer IPv4 = %s, want %s", ip, want.AnswerIPv4)
		}
	}
	if want.AnswerIPv6 != "" {
		ip := dnsAnswerIPv6(t, got)
		if ip != want.AnswerIPv6 {
			t.Fatalf("answer IPv6 = %s, want %s", ip, want.AnswerIPv6)
		}
	}
}

// dnsAnswerIPv6 extracts the first AAAA answer canonical form. Mirrors the
// shape of dnsAnswerIPv4 so corpus fixtures can assert either family without
// duplicating parsing logic.
func dnsAnswerIPv6(t *testing.T, msg *dnsmessage.Msg) string {
	t.Helper()
	if msg == nil {
		t.Fatalf("nil response message")
	}
	if len(msg.Answer) == 0 {
		t.Fatalf("no answer records")
	}
	aaaa, ok := msg.Answer[0].(*dnsmessage.AAAA)
	if !ok {
		t.Fatalf("first answer is %T, want *AAAA", msg.Answer[0])
	}
	return netip.MustParseAddr(aaaa.AAAA.String()).String()
}
