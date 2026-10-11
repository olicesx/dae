/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

// newTestSniConsultPlane builds a ControlPlane with just enough state for the
// consult gate: a routing matcher (domain rules) and a dial mode. The DNS
// controller stays nil (ActiveDnsController handles that) and the real-domain
// cache stays empty, which resolveDomainDialMode treats as "unknown domain".
func newTestSniConsultPlane(t *testing.T, dialMode consts.DialMode, matcher *RoutingMatcher) *ControlPlane {
	t.Helper()
	return &ControlPlane{
		log: logrus.New(),
		controlPlaneGenerationState: controlPlaneGenerationState{
			dialMode:       dialMode,
			routingMatcher: matcher,
		},
	}
}

// newTestSniConsultMatcher mirrors newTestSniMatcher but gives the direct
// rule to pay.example so the D11b preview has a terminal verdict to catch.
func newTestSniConsultMatcher(t *testing.T) *RoutingMatcher {
	t.Helper()
	dm := domain_matcher.NewAhocorasickSlimtrie(logrus.New(), consts.MaxMatchSetLen)
	dm.AddSet(0, []string{"pay.example"}, consts.RoutingDomainKey_Suffix)
	dm.AddSet(1, []string{"group.example"}, consts.RoutingDomainKey_Suffix)
	if err := dm.Build(); err != nil {
		t.Fatalf("build domain matcher: %v", err)
	}
	compiled := []compiledRoutingMatch{
		{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundDirect},
		{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundLogicalAnd},
		{matchType: consts.MatchType_IpSet, outbound: testSniGroupOutbound},
		{matchType: consts.MatchType_Fallback, outbound: testSniGroupOutbound},
	}
	return &RoutingMatcher{
		domainMatcher:      dm,
		compiledMatches:    compiled,
		needs:              computeRoutingMatcherNeeds(compiled),
		terminalDomainMask: buildTerminalDomainMask(compiled),
	}
}

func consultPlaneWithLearning(t *testing.T, dialMode consts.DialMode) (*ControlPlane, *sniLearning, *fakeSniMapWriter) {
	t.Helper()
	core := &controlPlaneCore{}
	const epoch = uint64(11)
	core.routingEpochPolicyEpoch.Store(epoch)
	core.routingEpochSlot.Store(0)
	global := &config.Global{SniLearning: true, SniLearningTtl: 300 * time.Second}
	s := newSniLearning(core, newTestSniConsultMatcher(t), logrus.New(), global, 30*time.Millisecond, dialMode, epoch)
	if s == nil {
		t.Fatal("newSniLearning returned nil")
	}
	fake := newFakeSniMapWriter()
	s.writerOverride = fake
	plane := newTestSniConsultPlane(t, dialMode, s.matcher)
	plane.sniLearning = s
	return plane, s, fake
}

func TestSniConsultMatrix(t *testing.T) {
	plane, s, _ := consultPlaneWithLearning(t, consts.DialMode_DomainCao)
	addr := testAddr(t, "2001:db8::20")
	src := netip.AddrPortFrom(addr, 40000)
	dst := netip.AddrPortFrom(addr, 443)
	result := &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}
	now := time.Now()

	// No owner: plain miss, no counter movement.
	if _, ok := plane.SniConsultDomain(result, src, dst, now); ok {
		t.Fatal("consult must miss with no owners")
	}
	if got := s.Stats(); got.ConsultHit != 0 || got.ConsultAmbig != 0 || got.ConsultStale != 0 {
		t.Fatalf("counters moved on a plain miss: %+v", got)
	}

	// Single fresh owner: adopt (the domain routes to a group, gate passes).
	learnAt(t, s, addr, "a.group.example")
	now = time.Now()
	if domain, ok := plane.SniConsultDomain(result, src, dst, now); !ok || domain != "a.group.example" {
		t.Fatalf("consult = (%q, %v), want adopt of a.group.example", domain, ok)
	}
	if got := s.Stats().ConsultHit; got != 1 {
		t.Fatalf("consultHit = %d, want 1", got)
	}

	// Stale sample: the owner was verified more than one interval ago, so
	// this connection must pay the real sniff instead.
	staleNow := now.Add(sniConsultVerifyInterval + time.Second)
	if _, ok := plane.SniConsultDomain(result, src, dst, staleNow); ok {
		t.Fatal("consult must miss on a stale sample")
	}
	if got := s.Stats().ConsultStale; got != 1 {
		t.Fatalf("consultStale = %d, want 1", got)
	}

	// Second live owner: ambiguity guard.
	learnAt(t, s, addr, "b.group.example")
	if _, ok := plane.SniConsultDomain(result, src, dst, staleNow); ok {
		t.Fatal("consult must miss with two live owners")
	}
	if got := s.Stats().ConsultAmbig; got != 1 {
		t.Fatalf("consultAmbig = %d, want 1", got)
	}
}

func TestSniConsultSamplingRefresh(t *testing.T) {
	plane, s, _ := consultPlaneWithLearning(t, consts.DialMode_DomainCao)
	addr := testAddr(t, "2001:db8::21")
	src := netip.AddrPortFrom(addr, 40000)
	dst := netip.AddrPortFrom(addr, 443)
	result := &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}

	learnAt(t, s, addr, "a.group.example")
	verified := time.Now()

	// Within the sample window the consult keeps adopting...
	if _, ok := plane.SniConsultDomain(result, src, dst, verified.Add(sniConsultVerifyInterval-time.Second)); !ok {
		t.Fatal("consult must adopt inside the sample window")
	}
	// ...but adopting does not refresh the sample (TTL起点规则: only real
	// sniffs refresh), so past the window it misses...
	if _, ok := plane.SniConsultDomain(result, src, dst, verified.Add(sniConsultVerifyInterval+time.Second)); ok {
		t.Fatal("consult must miss once the sample is stale")
	}
	// ...until a real sniff (processTask) re-verifies it.
	learnAt(t, s, addr, "a.group.example")
	if _, ok := plane.SniConsultDomain(result, src, dst, time.Now().Add(sniConsultVerifyInterval-time.Second)); !ok {
		t.Fatal("consult must adopt again after the sampled real sniff")
	}
}

func TestSniConsultGateRejectsTerminalOutbound(t *testing.T) {
	// dial_mode=domain++ and the learned domain's rules resolve to direct:
	// the preview must refuse the adoption so the real sniff decides.
	plane, s, _ := consultPlaneWithLearning(t, consts.DialMode_DomainCao)
	addr := testAddr(t, "2001:db8::22")
	src := netip.AddrPortFrom(addr, 40000)
	dst := netip.AddrPortFrom(addr, 443)
	result := &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}

	learnAt(t, s, addr, "a.pay.example")
	if _, ok := plane.SniConsultDomain(result, src, dst, time.Now()); ok {
		t.Fatal("gate must reject a cached domain that routes to direct")
	}
	if got := s.Stats().ConsultGate; got != 1 {
		t.Fatalf("consultGate = %d, want 1", got)
	}
	if got := s.Stats().ConsultHit; got != 0 {
		t.Fatalf("consultHit = %d, want 0 after a gate rejection", got)
	}
}

func TestSniConsultDomainPlusSkipsPreview(t *testing.T) {
	// domain+ never re-routes through the userspace matcher, so the cached
	// domain has no path to a terminal verdict and no preview is needed.
	plane, s, _ := consultPlaneWithLearning(t, consts.DialMode_DomainPlus)
	addr := testAddr(t, "2001:db8::23")
	result := &bpfRoutingResult{Outbound: uint8(testSniGroupOutbound)}

	learnAt(t, s, addr, "a.pay.example")
	if domain, ok := plane.SniConsultDomain(result, netip.AddrPortFrom(addr, 40000), netip.AddrPortFrom(addr, 443), time.Now()); !ok || domain != "a.pay.example" {
		t.Fatalf("domain+ consult = (%q, %v), want adopt without preview", domain, ok)
	}
	if got := s.Stats().ConsultGate; got != 0 {
		t.Fatalf("consultGate = %d, want 0 in domain+ mode", got)
	}
}

func TestResolveDomainDialModeParity(t *testing.T) {
	// The shared verdict must reproduce ChooseDialTarget's historical
	// behavior for every dial mode with an empty DNS/real-domain cache:
	// ip -> never; domain (unknown domain) -> dial-by-IP this call;
	// domain+ -> dial by domain, no reroute; domain++ -> dial and reroute.
	dst := netip.AddrPortFrom(testAddr(t, "2001:db8::24"), 443)
	group := testSniGroupOutbound
	cases := []struct {
		mode         consts.DialMode
		dialDomain   bool
		shouldRerout bool
	}{
		{consts.DialMode_Ip, false, false},
		{consts.DialMode_Domain, false, false},
		{consts.DialMode_DomainPlus, true, false},
		{consts.DialMode_DomainCao, true, true},
	}
	for _, tc := range cases {
		plane := newTestSniConsultPlane(t, tc.mode, newTestSniConsultMatcher(t))
		dialDomain, reroute := plane.resolveDomainDialMode(group, dst, "a.group.example", false)
		if dialDomain != tc.dialDomain || reroute != tc.shouldRerout {
			t.Fatalf("mode %v: resolveDomainDialMode = (%v,%v), want (%v,%v)",
				tc.mode, dialDomain, reroute, tc.dialDomain, tc.shouldRerout)
		}
		// ChooseDialTarget (the production call, warm=true) must agree. The
		// Domain row is excluded: its unknown-domain branch warms the async
		// real-domain probe, which must not run inside a unit test.
		if tc.mode != consts.DialMode_Domain {
			_, prodReroute, _ := plane.ChooseDialTarget(group, dst, "a.group.example")
			if prodReroute != tc.shouldRerout {
				t.Fatalf("mode %v: ChooseDialTarget reroute = %v, want %v", tc.mode, prodReroute, tc.shouldRerout)
			}
		}
	}

	// Reserved outbounds (punt/direct/block) never dial by domain.
	plane := newTestSniConsultPlane(t, consts.DialMode_DomainCao, newTestSniConsultMatcher(t))
	if dialDomain, reroute := plane.resolveDomainDialMode(consts.OutboundControlPlaneRouting, dst, "a.group.example", false); dialDomain || reroute {
		t.Fatalf("reserved outbound: (%v,%v), want (false,false)", dialDomain, reroute)
	}
}

func TestResolveDomainDialModeNoSideEffects(t *testing.T) {
	// The preview variant must not touch the real-domain knowledge: the
	// unknown-domain branch would warm the async probe in the production
	// call, and the preview must return the same CURRENT verdict without
	// scheduling anything.
	plane := newTestSniConsultPlane(t, consts.DialMode_Domain, newTestSniConsultMatcher(t))
	dst := netip.AddrPortFrom(testAddr(t, "2001:db8::25"), 443)
	if dialDomain, reroute := plane.resolveDomainDialMode(testSniGroupOutbound, dst, "never.seen.example", false); dialDomain || reroute {
		t.Fatalf("preview on an unknown domain = (%v,%v), want (false,false)", dialDomain, reroute)
	}
	plane.muRealDomainSet.RLock()
	_, known := plane.realDomainSet["never.seen.example"]
	plane.muRealDomainSet.RUnlock()
	if known {
		t.Fatal("preview must not publish real-domain knowledge")
	}
}

// learnAt drives one real-sniff learn event synchronously.
func learnAt(t *testing.T, s *sniLearning, addr netip.Addr, domain string) {
	t.Helper()
	s.LearnSniffed(addr, domain, sniffing.SniffProtocolTLS)
	s.processTask(<-s.queue)
}
