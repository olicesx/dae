/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

// fakeSniMapWriter records projection operations for assertions.
type fakeSniMapWriter struct {
	mu   sync.Mutex
	puts map[bpfRoutingEpochIp]bpfDomainRouting
	putN int
	dels map[bpfRoutingEpochIp]int
}

func newFakeSniMapWriter() *fakeSniMapWriter {
	return &fakeSniMapWriter{
		puts: make(map[bpfRoutingEpochIp]bpfDomainRouting),
		dels: make(map[bpfRoutingEpochIp]int),
	}
}

func (w *fakeSniMapWriter) put(key bpfRoutingEpochIp, value bpfDomainRouting) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.puts[key] = value
	w.putN++
	return nil
}

func (w *fakeSniMapWriter) del(key bpfRoutingEpochIp) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dels[key]++
	return nil
}

func (w *fakeSniMapWriter) snapshot() (puts map[bpfRoutingEpochIp]bpfDomainRouting, putN int, dels map[bpfRoutingEpochIp]int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	puts = make(map[bpfRoutingEpochIp]bpfDomainRouting, len(w.puts))
	for k, v := range w.puts {
		puts[k] = v
	}
	dels = make(map[bpfRoutingEpochIp]int, len(w.dels))
	for k, v := range w.dels {
		dels[k] = v
	}
	return puts, w.putN, dels
}

// newTestSniMatcher builds a matcher whose compiled match_set layout mirrors
// the post-optimizer shapes the terminal mask must handle:
//
//	[0] domain(suffix:pay.example)           -> direct  (single-function rule)
//	[1] domain(suffix:group.example) And(0xFF)          |
//	[2] ip(10.0.0.0/8)                       -> group 10 (multi-function rule;
//	                                                 domain sorts first)
//	[3] fallback                             -> direct
const testSniGroupOutbound = consts.OutboundIndex(10)

func newTestSniMatcher(t *testing.T) *RoutingMatcher {
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
		{matchType: consts.MatchType_Fallback, outbound: consts.OutboundDirect},
	}
	return &RoutingMatcher{
		domainMatcher:      dm,
		compiledMatches:    compiled,
		needs:              computeRoutingMatcherNeeds(compiled),
		terminalDomainMask: buildTerminalDomainMask(compiled),
	}
}

func newTestSniLearning(t *testing.T, allowTerminal bool) (*sniLearning, *fakeSniMapWriter, *controlPlaneCore) {
	t.Helper()
	core := &controlPlaneCore{}
	const epoch = uint64(7)
	core.routingEpochPolicyEpoch.Store(epoch)
	core.routingEpochSlot.Store(0)
	global := &config.Global{
		SniLearning:       true,
		SniLearningTtl:    300 * time.Second,
		SniLearningDirect: allowTerminal,
	}
	s := newSniLearning(core, newTestSniMatcher(t), logrus.New(), global, 30*time.Millisecond, consts.DialMode_Domain, epoch)
	if s == nil {
		t.Fatal("newSniLearning returned nil for an enabled configuration")
	}
	fake := newFakeSniMapWriter()
	s.writerOverride = fake
	return s, fake, core
}

func bitSet(bitmap bpfDomainRouting, i int) bool {
	return bitmap.Bitmap[i>>5]&(1<<(i%32)) != 0
}

func testAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	return addr
}

func TestSniLearningLearnsTlsIntoActiveSlot(t *testing.T) {
	s, fake, _ := newTestSniLearning(t, false)
	addr := testAddr(t, "2001:db8::1")
	s.LearnSniffed(addr, "a.group.example", sniffing.SniffProtocolTLS)

	s.processTask(<-s.queue)

	puts, _, dels := fake.snapshot()
	if len(puts) != 1 || len(dels) != 0 {
		t.Fatalf("puts = %v, dels = %v; want exactly one put", puts, dels)
	}
	for key, value := range puts {
		if key.Slot != 0 {
			t.Fatalf("put slot = %d, want the active slot 0", key.Slot)
		}
		if !bitSet(value, 1) {
			t.Fatalf("group.example bit (match_set 1) not projected: %+v", value)
		}
	}
	stats := s.Stats()
	if stats.Enqueued != 1 || stats.MapWritten != 1 {
		t.Fatalf("stats = %+v, want Enqueued=MapWritten=1", stats)
	}
}

func TestSniLearningGatesTerminalOutboundBits(t *testing.T) {
	s, fake, _ := newTestSniLearning(t, false)
	addr := testAddr(t, "2001:db8::2")
	// pay.example matches the single-function domain -> direct rule.
	s.LearnSniffed(addr, "a.pay.example", sniffing.SniffProtocolTLS)
	s.processTask(<-s.queue)

	puts, _, _ := fake.snapshot()
	if len(puts) != 0 {
		t.Fatalf("terminal direct bit must not be projected by default, got puts = %v", puts)
	}
	// The owner is still authoritative bookkeeping: a later group-domain
	// learn on the same IP must not be blocked by the earlier zero write.
	s.LearnSniffed(addr, "b.group.example", sniffing.SniffProtocolTLS)
	s.processTask(<-s.queue)
	puts, _, _ = fake.snapshot()
	if len(puts) != 1 || !bitSet(puts[bpfRoutingEpochIp{Slot: 0, Addr: sniRoutingKey(addr)}], 1) {
		t.Fatalf("group bit not projected after terminal-gated learn: %+v", puts)
	}
}

func TestSniLearningOptInProjectsTerminalBits(t *testing.T) {
	s, fake, _ := newTestSniLearning(t, true)
	addr := testAddr(t, "2001:db8::3")
	s.LearnSniffed(addr, "a.pay.example", sniffing.SniffProtocolTLS)
	s.processTask(<-s.queue)

	puts, _, _ := fake.snapshot()
	if len(puts) != 1 || !bitSet(puts[bpfRoutingEpochIp{Slot: 0, Addr: sniRoutingKey(addr)}], 0) {
		t.Fatalf("opt-in must project the direct-rule bit, got %+v", puts)
	}
}

func TestSniLearningNonTlsAndEmptyDomainNeverLearn(t *testing.T) {
	s, _, _ := newTestSniLearning(t, false)
	addr := testAddr(t, "2001:db8::4")
	s.LearnSniffed(addr, "a.group.example", sniffing.SniffProtocolHTTP)
	s.LearnSniffed(addr, "", sniffing.SniffProtocolTLS)
	if got := s.Stats().Enqueued; got != 0 {
		t.Fatalf("enqueued = %d, want 0 (only non-empty TLS learns)", got)
	}
}

func TestSniLearningZeroBitmapRecordsOwnerSkipsMapWrite(t *testing.T) {
	s, fake, _ := newTestSniLearning(t, false)
	addr := testAddr(t, "2001:db8::5")
	// unknown.example matches no rule, so the gated bitmap is zero.
	s.LearnSniffed(addr, "unknown.example", sniffing.SniffProtocolTLS)
	s.processTask(<-s.queue)

	if puts, putN, _ := fake.snapshot(); putN != 0 || len(puts) != 0 {
		t.Fatalf("zero bitmap must skip the map write, got %+v", puts)
	}
	s.trackerMu.Lock()
	_, ownerAlive := s.owners["unknown.example"]
	s.trackerMu.Unlock()
	if !ownerAlive {
		t.Fatal("zero-bitmap owner must still be recorded in the tracker")
	}
}

func TestSniLearningQueueFullDropsAndCounts(t *testing.T) {
	s, _, _ := newTestSniLearning(t, false)
	addr := testAddr(t, "2001:db8::6")
	for i := 0; i < sniLearningQueueSize; i++ {
		s.queue <- sniLearnTask{addr: sniRoutingKey(addr), domain: "a.group.example", epoch: s.policyEpoch}
	}
	s.LearnSniffed(addr, "overflow.group.example", sniffing.SniffProtocolTLS)
	if got := s.Stats().Dropped; got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
}

func TestSniLearningMultiOwnerOrMerge(t *testing.T) {
	s, fake, _ := newTestSniLearning(t, false)
	addr := testAddr(t, "2001:db8::7")
	s.LearnSniffed(addr, "a.group.example", sniffing.SniffProtocolTLS)
	s.LearnSniffed(addr, "optin.pay.example", sniffing.SniffProtocolTLS)
	s.processTask(<-s.queue)
	s.processTask(<-s.queue)

	puts, _, _ := fake.snapshot()
	key := bpfRoutingEpochIp{Slot: 0, Addr: sniRoutingKey(addr)}
	if len(puts) != 1 {
		t.Fatalf("want a single merged entry, got %d", len(puts))
	}
	value := puts[key]
	if !bitSet(value, 1) {
		t.Fatalf("group bit missing from merged bitmap: %+v", value)
	}
	// pay.example's direct bit is terminal-gated by default.
	if bitSet(value, 0) {
		t.Fatalf("terminal direct bit leaked into the merged bitmap: %+v", value)
	}
}

func TestSniLearningSweepExpiresOwnerAndDeletesBothSlots(t *testing.T) {
	s, fake, _ := newTestSniLearning(t, false)
	addr := testAddr(t, "2001:db8::8")
	s.LearnSniffed(addr, "a.group.example", sniffing.SniffProtocolTLS)
	s.processTask(<-s.queue)

	learnedAt := time.Now()
	s.sweep(learnedAt.Add(s.ttl + time.Second))

	_, _, dels := fake.snapshot()
	key0 := bpfRoutingEpochIp{Slot: 0, Addr: sniRoutingKey(addr)}
	key1 := bpfRoutingEpochIp{Slot: 1, Addr: sniRoutingKey(addr)}
	if dels[key0] == 0 || dels[key1] == 0 {
		t.Fatalf("expiry must delete both slots, dels = %+v", dels)
	}
	if got := s.Stats().ExpiredOwners; got != 1 {
		t.Fatalf("expired owners = %d, want 1", got)
	}
	s.trackerMu.Lock()
	_, alive := s.owners["a.group.example"]
	s.trackerMu.Unlock()
	if alive {
		t.Fatal("expired owner still present in tracker")
	}
}

func TestSniLearningReSniffRefreshesTtl(t *testing.T) {
	s, fake, _ := newTestSniLearning(t, false)
	addr := testAddr(t, "2001:db8::9")
	s.LearnSniffed(addr, "a.group.example", sniffing.SniffProtocolTLS)
	s.processTask(<-s.queue)
	firstLearn := time.Now()

	// At firstLearn + ttl - 1s the owner is still live, and a re-sniff at
	// that moment pushes its expiry one full ttl further out.
	refreshAt := firstLearn.Add(s.ttl - time.Second)
	s.trackerMu.Lock()
	owner := s.owners["a.group.example"]
	s.trackerMu.Unlock()
	owner.learnedAt = refreshAt
	owner.expiresAt = refreshAt.Add(s.ttl)
	s.sweep(refreshAt.Add(s.ttl - time.Second))
	if got := s.Stats().ExpiredOwners; got != 0 {
		t.Fatalf("owner expired despite TTL refresh, expired = %d", got)
	}
	_, _, dels := fake.snapshot()
	if len(dels) != 0 {
		t.Fatalf("no deletions expected before expiry, got %+v", dels)
	}
}

func TestSniLearningStaleEpochTaskIsDropped(t *testing.T) {
	s, fake, core := newTestSniLearning(t, false)
	addr := testAddr(t, "2001:db8::a")
	// The plane reloads: the core moves to a new policy epoch.
	core.routingEpochPolicyEpoch.Store(s.policyEpoch + 1)
	s.LearnSniffed(addr, "a.group.example", sniffing.SniffProtocolTLS)
	s.processTask(<-s.queue)

	if puts, putN, _ := fake.snapshot(); putN != 0 || len(puts) != 0 {
		t.Fatalf("stale-epoch task must not write, got %+v", puts)
	}
	if got := s.Stats().StaleDropped; got != 1 {
		t.Fatalf("staleDropped = %d, want 1", got)
	}
}

func TestSniLearningDisabledWhenNoDomainRules(t *testing.T) {
	core := &controlPlaneCore{}
	compiled := []compiledRoutingMatch{
		{matchType: consts.MatchType_IpSet, outbound: consts.OutboundDirect},
		{matchType: consts.MatchType_Fallback, outbound: consts.OutboundDirect},
	}
	matcher := &RoutingMatcher{
		compiledMatches:    compiled,
		needs:              computeRoutingMatcherNeeds(compiled),
		terminalDomainMask: buildTerminalDomainMask(compiled),
	}
	global := &config.Global{SniLearning: true, SniLearningTtl: 300 * time.Second}
	if s := newSniLearning(core, matcher, logrus.New(), global, 30*time.Millisecond, consts.DialMode_Domain, 1); s != nil {
		t.Fatal("SNI learning must stay inert without domain match sets")
	}
}

func TestBuildTerminalDomainMaskCoversRuleShapes(t *testing.T) {
	compiled := []compiledRoutingMatch{
		// domain(a) -> must-rules: bits 0 belongs to a must rule.
		{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundMustRules},
		// port(443) Or | domain(b) -> group: bits 1-2 belong to a group rule.
		{matchType: consts.MatchType_Port, outbound: consts.OutboundLogicalOr},
		{matchType: consts.MatchType_DomainSet, outbound: testSniGroupOutbound},
		// dip && domain(c) -> direct: bits 3-4 belong to a direct rule
		// (domain sorts first and carries the And marker).
		{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundLogicalAnd},
		{matchType: consts.MatchType_IpSet, outbound: consts.OutboundDirect},
		// sniff-punt line: selector && domain(d) -> control-plane routing.
		{matchType: consts.MatchType_Mac, outbound: consts.OutboundLogicalAnd},
		{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundControlPlaneRouting},
		// fallback -> block.
		{matchType: consts.MatchType_Fallback, outbound: consts.OutboundBlock},
	}
	mask := buildTerminalDomainMask(compiled)
	// Only the dip&&domain->direct rule (bits 3-4) and the fallback (bit 7)
	// resolve to terminal outbounds.
	for i, want := range []bool{false, false, false, true, true, false, false, true} {
		if got := bitSet(mask, i); got != want {
			t.Fatalf("mask bit %d = %v, want %v", i, got, want)
		}
	}
}

func TestGateTerminalDomainBitsIsLinearOverOr(t *testing.T) {
	// (a | b) &^ m == (a &^ m) | (b &^ m): gating after the merge must equal
	// gating per owner, which is what allows the tracker to store raw
	// bitmaps and gate only at projection time.
	merged := bpfDomainRouting{}
	merged.Bitmap[0] = 0b1011
	mask := bpfDomainRouting{}
	mask.Bitmap[0] = 0b0011
	m := &RoutingMatcher{terminalDomainMask: mask}
	m.gateTerminalDomainBits(&merged)
	if merged.Bitmap[0] != 0b1000 {
		t.Fatalf("gated = %b, want 1000", merged.Bitmap[0])
	}
}

func TestValidateSniLearningTtlBounds(t *testing.T) {
	for _, ttl := range []time.Duration{sniLearningTtlFloor - time.Second, sniLearningTtlCeiling + time.Second} {
		if err := ValidateSniLearningTtl(ttl); err == nil {
			t.Fatalf("ttl %v must be rejected", ttl)
		}
	}
	for _, ttl := range []time.Duration{sniLearningTtlFloor, sniLearningTtlCeiling} {
		if err := ValidateSniLearningTtl(ttl); err != nil {
			t.Fatalf("ttl %v must be accepted: %v", ttl, err)
		}
	}
}
