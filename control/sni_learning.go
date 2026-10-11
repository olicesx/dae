/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

// SNI learning: after a successful TLS ClientHello sniff, project the
// "destination IP -> domain-rule bitmap" knowledge into sni_routing_map so
// that later connections to the same IP can be routed by domain rules in the
// kernel. The kern side consults that map only where the DNS projection
// (domain_routing_map) misses, so DNS knowledge stays strictly authoritative.
// See SNI-CACHE-DESIGN-R13.md for the full contract; the load-bearing
// invariants are:
//
//   - Only real sniff successes learn (never negative cache hits, failures,
//     or skips), and only TLS; the first connection to an unknown IP always
//     pays the real sniff.
//   - The userspace tracker below is authoritative: it keeps domain strings
//     and per-owner TTLs, while the map holds merged bitmaps and is a cache.
//   - Terminal-outbound gate (D11a): unless the user opted in via
//     sni_learning_direct, bits whose owning rule resolves to direct/block
//     are never projected, because those verdicts are terminal in the kernel
//     and a mis-learned shared-IP domain could not self-heal.
//   - Writers take the same projection mutex family as the DNS projection
//     and re-verify epoch/slot inside the lock, mirroring the
//     ROUTING-EPOCH-2 discipline in control/routing_epoch.go.

// sniLearningTtlFloor/Ceiling bound the configurable owner TTL.
const (
	sniLearningTtlFloor   = 30 * time.Second
	sniLearningTtlCeiling = 3600 * time.Second
	// sniLearningQueueSize bounds the asynchronous learn channel. Learning is
	// opportunistic: a dropped task only costs one extra sniff on the next
	// connection to that IP, so the queue is lossy by design (D10).
	sniLearningQueueSize = 1024
)

// sniRoutingMapWriter abstracts sni_routing_map writes so unit tests can
// intercept projection without a kernel datapath.
type sniRoutingMapWriter interface {
	put(key bpfRoutingEpochIp, value bpfDomainRouting) error
	del(key bpfRoutingEpochIp) error
}

// ebpfSniRoutingMapWriter adapts the production map; a nil map is a no-op
// (stub builds have no live objects).
type ebpfSniRoutingMapWriter struct {
	m *ebpf.Map
}

func (w ebpfSniRoutingMapWriter) put(key bpfRoutingEpochIp, value bpfDomainRouting) error {
	if w.m == nil {
		return nil
	}
	return w.m.Update(key, value, ebpf.UpdateAny)
}

func (w ebpfSniRoutingMapWriter) del(key bpfRoutingEpochIp) error {
	if w.m == nil {
		return nil
	}
	if err := w.m.Delete(key); err != nil && !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// sniLearnTask is one asynchronous learning event. epoch is the plane's
// policy epoch (same source as the DNS projection tasks).
type sniLearnTask struct {
	addr   [4]uint32
	domain string
	epoch  uint64
}

// sniOwner is one learned domain: every IP it was sniffed on, plus its TTL.
// The bitmap is cached because it only depends on the plane's immutable
// routing matcher; re-sniffing the same domain refreshes the TTL.
type sniOwner struct {
	bitmap    bpfDomainRouting
	ips       map[[4]uint32]struct{}
	learnedAt time.Time
	expiresAt time.Time
}

// SniLearningStats is a point-in-time snapshot of the subsystem counters.
type SniLearningStats struct {
	Enqueued      uint64
	Dropped       uint64
	MapWritten    uint64
	MapDeleted    uint64
	ExpiredOwners uint64
	StaleDropped  uint64
}

type sniLearning struct {
	enabled       bool
	allowTerminal bool
	ttl           time.Duration
	queue         chan sniLearnTask
	log           *logrus.Logger
	core          *controlPlaneCore
	matcher       *RoutingMatcher
	policyEpoch   uint64
	// writerOverride lets unit tests intercept map projection without a
	// kernel datapath; nil in production.
	writerOverride sniRoutingMapWriter

	// trackerMu guards the authoritative owner/IP bookkeeping. It is
	// deliberately not the projection mutex: map writes serialize on the
	// routing-epoch projection mutex family, while the tracker only needs
	// internal consistency.
	trackerMu sync.Mutex
	owners    map[string]*sniOwner
	ips       map[[4]uint32]map[string]struct{}

	enqueued      atomic.Uint64
	dropped       atomic.Uint64
	mapWritten    atomic.Uint64
	mapDeleted    atomic.Uint64
	expiredOwners atomic.Uint64
	staleDropped  atomic.Uint64
}

// newSniLearning builds the per-plane learning subsystem. It returns nil when
// disabled so every caller can be nil-safe: the configuration switch, the
// sniffing preconditions (sniffing_timeout > 0 and dial_mode != ip), and the
// existence of at least one domain match_set (without one, every bitmap is
// zero and there is nothing to project).
func newSniLearning(
	core *controlPlaneCore,
	matcher *RoutingMatcher,
	log *logrus.Logger,
	global *config.Global,
	sniffingTimeout time.Duration,
	dialMode consts.DialMode,
	policyEpoch uint64,
) *sniLearning {
	if global == nil || !global.SniLearning {
		return nil
	}
	if matcher == nil || matcher.domainMatcher == nil || !matcher.needs.domainBitmap {
		return nil
	}
	if sniffingTimeout <= 0 || dialMode == consts.DialMode_Ip {
		return nil
	}
	return &sniLearning{
		enabled:       true,
		allowTerminal: global.SniLearningDirect,
		ttl:           global.SniLearningTtl,
		queue:         make(chan sniLearnTask, sniLearningQueueSize),
		log:           log,
		core:          core,
		matcher:       matcher,
		policyEpoch:   policyEpoch,
		owners:        make(map[string]*sniOwner),
		ips:           make(map[[4]uint32]map[string]struct{}),
	}
}

func sniRoutingKey(addr netip.Addr) [4]uint32 {
	b := addr.As16()
	return common.Ipv6ByteSliceToUint32Array(b[:])
}

// sniRoutingKeyAddr renders a routing key back into an address for logs.
func sniRoutingKeyAddr(key [4]uint32) netip.Addr {
	var b [16]byte
	for i, w := range key {
		binary.BigEndian.PutUint32(b[i*4:], w)
	}
	return netip.AddrFrom16(b)
}

// enqueue hands one sniff success to the worker. Non-blocking by design.
func (s *sniLearning) enqueue(addr netip.Addr, domain string) {
	if s == nil || !s.enabled || domain == "" {
		return
	}
	task := sniLearnTask{
		addr:   sniRoutingKey(addr),
		domain: domain,
		epoch:  s.policyEpoch,
	}
	select {
	case s.queue <- task:
		s.enqueued.Add(1)
	default:
		n := s.dropped.Add(1)
		if n&(1<<10-1) == 1 {
			s.log.Warnf("SNI learning queue full; %d learn tasks dropped so far", n)
		}
	}
}

// serve drains the learn queue until the plane context is cancelled.
func (s *sniLearning) serve(ctx context.Context) {
	if s == nil || !s.enabled {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-s.queue:
			s.processTask(task)
		}
	}
}

func (s *sniLearning) processTask(task sniLearnTask) {
	raw := s.rawOwnerBitmap(task.domain)
	s.trackerMu.Lock()
	now := time.Now()
	owner := s.owners[task.domain]
	if owner == nil {
		owner = &sniOwner{
			bitmap: raw,
			ips:    make(map[[4]uint32]struct{}),
		}
		s.owners[task.domain] = owner
	}
	// Re-sniffing the same domain refreshes its TTL only: the bitmap is
	// matcher-derived and cannot change within one plane, and old IPs stay
	// until their owner expires (domains move; stale IPs age out with it).
	owner.ips[task.addr] = struct{}{}
	owner.learnedAt = now
	owner.expiresAt = now.Add(s.ttl)
	domains := s.ips[task.addr]
	if domains == nil {
		domains = make(map[string]struct{})
		s.ips[task.addr] = domains
	}
	domains[task.domain] = struct{}{}
	merged := s.mergedBitmapLocked(task.addr)
	s.trackerMu.Unlock()

	if s.log.IsLevelEnabled(logrus.DebugLevel) {
		s.log.WithFields(logrus.Fields{
			"addr":   sniRoutingKeyAddr(task.addr).String(),
			"domain": task.domain,
			"ttl":    s.ttl.String(),
		}).Debug("SNI learned")
	}
	s.projectAddr(task.addr, merged, task.epoch)
}

// rawOwnerBitmap computes the un-gated domain bitmap for one domain.
func (s *sniLearning) rawOwnerBitmap(domain string) bpfDomainRouting {
	var raw bpfDomainRouting
	words := s.matcher.domainMatcher.MatchDomainBitmap(domain)
	if len(words) != len(raw.Bitmap) {
		// Out of sync with the kern program; refuse to project a bitmap of
		// the wrong width rather than write a partial one.
		return raw
	}
	copy(raw.Bitmap[:], words)
	return raw
}

// mergedBitmapLocked returns the OR of all live owners' raw bitmaps for one
// IP. Caller holds trackerMu.
func (s *sniLearning) mergedBitmapLocked(addr [4]uint32) bpfDomainRouting {
	var merged bpfDomainRouting
	for domain := range s.ips[addr] {
		if owner := s.owners[domain]; owner != nil {
			orDomainRoutingBitmap(&merged, owner.bitmap)
		}
	}
	return merged
}

func (s *sniLearning) writer() sniRoutingMapWriter {
	if s.writerOverride != nil {
		return s.writerOverride
	}
	bpf := s.core.PeekBpf()
	if bpf == nil || bpf.SniRoutingMap == nil {
		s.log.Warnf("SNI learning: sni_routing_map unavailable in the loaded datapath")
		return ebpfSniRoutingMapWriter{}
	}
	return ebpfSniRoutingMapWriter{m: bpf.SniRoutingMap}
}

// verifySlotLocked re-validates, under the projection mutex, that this plane's
// policy epoch still owns the given slot. Mirrors the DNS projection writer
// discipline (control/routing_epoch.go, ROUTING-EPOCH-2 contract).
func (s *sniLearning) verifySlotLocked(slot uint32, epoch uint64) bool {
	if epoch != s.core.routingEpochPolicyEpoch.Load() {
		return false
	}
	current := s.core.routingEpochSlot.Load()
	if current != slot || !validRoutingEpochSlot(current) {
		return false
	}
	active, err := s.core.readActiveRoutingEpochSlot()
	if err != nil || active != current {
		return false
	}
	return true
}

// projectAddr writes (or removes) one IP's merged entry in the active slot.
func (s *sniLearning) projectAddr(addr [4]uint32, merged bpfDomainRouting, epoch uint64) {
	if !s.allowTerminal {
		s.matcher.gateTerminalDomainBits(&merged)
	}
	slot := s.core.routingEpochSlot.Load()
	s.core.domainRoutingProjectionMu[slot].Lock()
	defer s.core.domainRoutingProjectionMu[slot].Unlock()
	if !s.verifySlotLocked(slot, epoch) {
		s.staleDropped.Add(1)
		// Expected during reload windows: the task simply re-learns on the
		// next connection. Debug, not a warning.
		s.log.Debugf("SNI learning: dropped stale task (epoch/slot mismatch) for addr %v", sniRoutingKeyAddr(addr))
		return
	}
	writer := s.writer()
	if writer == nil {
		s.log.Warnf("SNI learning: no map writer available")
		return
	}
	if isZeroDomainRoutingBitmap(merged) {
		// Zero gated bitmap: identical to a map miss for the kernel, so skip
		// the entry and keep the capacity.
		if err := writer.del(bpfRoutingEpochIp{Slot: slot, Addr: addr}); err != nil {
			s.log.Warnf("SNI learning: delete sni_routing_map entry: %v", err)
		}
		s.mapDeleted.Add(1)
		return
	}
	if err := writer.put(bpfRoutingEpochIp{Slot: slot, Addr: addr}, merged); err != nil {
		s.log.Warnf("SNI learning: update sni_routing_map: %v", err)
		return
	}
	s.mapWritten.Add(1)
	if s.log.IsLevelEnabled(logrus.DebugLevel) {
		s.log.Debugf("SNI projected slot=%d addr=%v", slot, sniRoutingKeyAddr(addr))
	}
}

// sweep is the janitor: expire owners whose TTL elapsed, then refresh or drop
// their IPs' map entries. Mounted on the same periodic cleanup as the DNS and
// sniff-negative caches. Deletions run on both slots; updates only ever
// target the current active slot, because writing into a retired slot could
// resurrect an entry the epoch finalize path already cleared.
func (s *sniLearning) sweep(now time.Time) {
	if s == nil || !s.enabled {
		return
	}
	type addrOp struct {
		addr     [4]uint32
		merged   bpfDomainRouting
		hasOwner bool
	}
	s.trackerMu.Lock()
	var affected map[[4]uint32]struct{}
	for domain, owner := range s.owners {
		if now.Before(owner.expiresAt) {
			continue
		}
		delete(s.owners, domain)
		s.expiredOwners.Add(1)
		for addr := range owner.ips {
			if domains := s.ips[addr]; domains != nil {
				delete(domains, domain)
				if len(domains) == 0 {
					delete(s.ips, addr)
				}
			}
			if affected == nil {
				affected = make(map[[4]uint32]struct{})
			}
			affected[addr] = struct{}{}
		}
	}
	if len(affected) == 0 {
		s.trackerMu.Unlock()
		return
	}
	ops := make([]addrOp, 0, len(affected))
	for addr := range affected {
		op := addrOp{addr: addr}
		if _, ok := s.ips[addr]; ok {
			op.hasOwner = true
			op.merged = s.mergedBitmapLocked(addr)
		}
		ops = append(ops, op)
	}
	s.trackerMu.Unlock()

	for _, op := range ops {
		active := s.core.routingEpochSlot.Load()
		for slot := uint32(0); slot < routingEpochSlotCount; slot++ {
			s.core.domainRoutingProjectionMu[slot].Lock()
			if op.hasOwner && slot == active && s.policyEpoch == s.core.routingEpochPolicyEpoch.Load() {
				merged := op.merged
				if !s.allowTerminal {
					s.matcher.gateTerminalDomainBits(&merged)
				}
				if !isZeroDomainRoutingBitmap(merged) {
					if err := s.writer().put(bpfRoutingEpochIp{Slot: slot, Addr: op.addr}, merged); err != nil {
						s.log.Warnf("SNI learning: refresh sni_routing_map: %v", err)
					} else {
						s.mapWritten.Add(1)
					}
					s.core.domainRoutingProjectionMu[slot].Unlock()
					continue
				}
			}
			if err := s.writer().del(bpfRoutingEpochIp{Slot: slot, Addr: op.addr}); err != nil {
				s.log.Warnf("SNI learning: sweep sni_routing_map: %v", err)
			} else {
				s.mapDeleted.Add(1)
			}
			s.core.domainRoutingProjectionMu[slot].Unlock()
		}
	}
}

// Stats returns the subsystem counters (nil-safe).
func (s *sniLearning) Stats() SniLearningStats {
	if s == nil {
		return SniLearningStats{}
	}
	return SniLearningStats{
		Enqueued:      s.enqueued.Load(),
		Dropped:       s.dropped.Load(),
		MapWritten:    s.mapWritten.Load(),
		MapDeleted:    s.mapDeleted.Load(),
		ExpiredOwners: s.expiredOwners.Load(),
		StaleDropped:  s.staleDropped.Load(),
	}
}

// LearnSniffed is the hook the TCP relay path calls on every sniff success.
// Kept as a method so tests can drive the subsystem without a connection.
func (s *sniLearning) LearnSniffed(addr netip.Addr, domain string, proto sniffing.SniffProtocol) {
	if proto != sniffing.SniffProtocolTLS {
		return
	}
	s.enqueue(addr, domain)
}

// ValidateSniLearningTtl checks the configured owner TTL bounds.
func ValidateSniLearningTtl(ttl time.Duration) error {
	if ttl < sniLearningTtlFloor || ttl > sniLearningTtlCeiling {
		return fmt.Errorf("sni_learning_ttl must be within [%v, %v], got %v",
			sniLearningTtlFloor, sniLearningTtlCeiling, ttl)
	}
	return nil
}
