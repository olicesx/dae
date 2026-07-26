/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	dnsmessage "github.com/miekg/dns"
)

func domainRoutingBitmap(words ...uint32) []uint32 {
	bitmap := make([]uint32, len(bpfDomainRouting{}.Bitmap))
	copy(bitmap, words)
	return bitmap
}

func domainRoutingACache(ownerKey string, ip string, bitmap []uint32) *DnsCache {
	return &DnsCache{
		RouteOwnerKey: ownerKey,
		DomainBitmap:  bitmap,
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "shared.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(ip).To4(),
			},
		},
	}
}

func TestDomainRoutingTrackerMergesSharedIPAcrossOwners(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	core := &controlPlaneCore{
		domainRouting: newDomainRoutingTracker(),
	}
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			DomainRoutingMap: domainMap,
		},
	})

	cacheA := domainRoutingACache("cache-a", "203.0.113.10", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("cache-b", "203.0.113.10", domainRoutingBitmap(0x2))
	ip := netip.MustParseAddr("203.0.113.10")
	ip16 := ip.As16()
	ipKey := bpfRoutingEpochIp{Slot: 0, Addr: common.Ipv6ByteSliceToUint32Array(ip16[:])}

	if err := core.BatchUpdateDomainRouting(cacheA); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheA): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(cacheB); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheB): %v", err)
	}

	var got bpfDomainRouting
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(shared ip): %v", err)
	}
	if got.Bitmap[0] != 0x3 {
		t.Fatalf("merged bitmap[0] = %#x, want %#x", got.Bitmap[0], uint32(0x3))
	}

	if err := core.BatchRemoveDomainRouting(cacheA); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(cacheA): %v", err)
	}
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(shared ip after remove A): %v", err)
	}
	if got.Bitmap[0] != 0x2 {
		t.Fatalf("bitmap after removing A = %#x, want %#x", got.Bitmap[0], uint32(0x2))
	}

	if err := core.BatchRemoveDomainRouting(cacheB); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(cacheB): %v", err)
	}
	if err := domainMap.Lookup(&ipKey, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(shared ip after remove B) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func TestDomainRoutingTrackerReplacesOwnerSnapshotWithoutLeakingRefs(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	core := &controlPlaneCore{
		domainRouting: newDomainRoutingTracker(),
	}
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			DomainRoutingMap: domainMap,
		},
	})

	first := &DnsCache{
		RouteOwnerKey: "cache-owner",
		DomainBitmap:  domainRoutingBitmap(0x4),
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "replace.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("203.0.113.20").To4(),
			},
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "replace.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("203.0.113.21").To4(),
			},
		},
	}
	second := domainRoutingACache("cache-owner", "203.0.113.20", domainRoutingBitmap(0x4))

	ip20Addr := netip.MustParseAddr("203.0.113.20")
	ip20Bytes := ip20Addr.As16()
	ip20 := bpfRoutingEpochIp{Slot: 0, Addr: common.Ipv6ByteSliceToUint32Array(ip20Bytes[:])}
	ip21Addr := netip.MustParseAddr("203.0.113.21")
	ip21Bytes := ip21Addr.As16()
	ip21 := bpfRoutingEpochIp{Slot: 0, Addr: common.Ipv6ByteSliceToUint32Array(ip21Bytes[:])}

	if err := core.BatchUpdateDomainRouting(first); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(first): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(second); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(second): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(second); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(second repeat): %v", err)
	}

	var got bpfDomainRouting
	if err := domainMap.Lookup(&ip20, &got); err != nil {
		t.Fatalf("Lookup(ip20): %v", err)
	}
	if got.Bitmap[0] != 0x4 {
		t.Fatalf("bitmap for ip20 = %#x, want %#x", got.Bitmap[0], uint32(0x4))
	}
	if err := domainMap.Lookup(&ip21, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(ip21) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}

	if err := core.BatchRemoveDomainRouting(second); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(second): %v", err)
	}
	if err := domainMap.Lookup(&ip20, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(ip20 after remove) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func TestDomainRoutingTrackerKeepsEpochSlotsIndependent(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	core := &controlPlaneCore{
		domainRouting: newDomainRoutingTracker(),
	}
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			DomainRoutingMap: domainMap,
		},
	})

	cache := domainRoutingACache("shared-owner", "203.0.113.30", domainRoutingBitmap(0x1))
	ip := netip.MustParseAddr("203.0.113.30")
	ipBytes := ip.As16()
	addr := common.Ipv6ByteSliceToUint32Array(ipBytes[:])

	core.routingEpochSlot.Store(0)
	if err := core.BatchUpdateDomainRouting(cache); err != nil {
		t.Fatalf("slot zero BatchUpdateDomainRouting() error = %v", err)
	}

	cache.DomainBitmap = domainRoutingBitmap(0x2)
	core.routingEpochSlot.Store(1)
	if err := core.BatchUpdateDomainRouting(cache); err != nil {
		t.Fatalf("slot one BatchUpdateDomainRouting() error = %v", err)
	}

	var got bpfDomainRouting
	key0 := bpfRoutingEpochIp{Slot: 0, Addr: addr}
	if err := domainMap.Lookup(&key0, &got); err != nil {
		t.Fatalf("Lookup(slot zero): %v", err)
	}
	if got.Bitmap[0] != 0x1 {
		t.Fatalf("slot zero bitmap = %#x, want %#x", got.Bitmap[0], uint32(0x1))
	}
	key1 := bpfRoutingEpochIp{Slot: 1, Addr: addr}
	if err := domainMap.Lookup(&key1, &got); err != nil {
		t.Fatalf("Lookup(slot one): %v", err)
	}
	if got.Bitmap[0] != 0x2 {
		t.Fatalf("slot one bitmap = %#x, want %#x", got.Bitmap[0], uint32(0x2))
	}

	if err := core.BatchRemoveDomainRouting(cache); err != nil {
		t.Fatalf("slot one BatchRemoveDomainRouting() error = %v", err)
	}
	if err := domainMap.Lookup(&key1, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(slot one after remove) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if err := domainMap.Lookup(&key0, &got); err != nil {
		t.Fatalf("Lookup(slot zero after slot one remove): %v", err)
	}
	if got.Bitmap[0] != 0x1 {
		t.Fatalf("slot zero bitmap after slot one remove = %#x, want %#x", got.Bitmap[0], uint32(0x1))
	}
}

// A saturated domain_routing_map must stay distinguishable from a real failure:
// the DNS path degrades to userspace routing on ErrBpfMapFull instead of
// failing the answer, so misclassifying it either takes DNS down for every new
// domain or silently hides a genuine map error.
func TestIsBpfMapFullErrorClassifiesInsertionFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "e2big", err: fmt.Errorf("batch update: %w", syscall.E2BIG), want: true},
		{name: "enospc", err: fmt.Errorf("batch update: %w", syscall.ENOSPC), want: true},
		{name: "einval", err: fmt.Errorf("batch update: %w", syscall.EINVAL), want: false},
		{name: "plain", err: stderrors.New("batch update failed"), want: false},
		{name: "nil", err: nil, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBpfMapFullError(tc.err); got != tc.want {
				t.Fatalf("isBpfMapFullError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}

	wrapped := fmt.Errorf("update domain_routing_map: %w: %w", ErrBpfMapFull, syscall.E2BIG)
	if !stderrors.Is(wrapped, ErrBpfMapFull) {
		t.Fatal("wrapped map-full error is not detectable via errors.Is")
	}
	if !stderrors.Is(wrapped, syscall.E2BIG) {
		t.Fatal("wrapped map-full error lost the underlying errno")
	}
}
