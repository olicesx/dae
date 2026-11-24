/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.io>
 */

package control

import (
	"fmt"
	"io"
	"testing"

	"github.com/daeuniverse/dae/component/dns"
	"github.com/sirupsen/logrus"
)

// TestCloseTailReleasesReloadSatellites pins the retirement-time releases that
// keep seamless reloads from accumulating a generation's worth of state per
// reload. Established-flow goroutines deliberately outlive a retired generation
// (see releaseRetainedState), so the retired ControlPlane stays reachable for an
// unbounded time and every reference left in closeTail is retained once per
// reload.
func TestCloseTailReleasesReloadSatellites(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	plane := &ControlPlane{log: logger}

	ran := 0
	plane.deferFuncs = []func() error{
		func() error {
			ran++
			return nil
		},
	}

	// Populate at production capacity: the value of the release is the backing
	// storage, so a two-entry fixture would let clear() (which keeps the
	// 8192-slot map buckets) and ord[:0] (which keeps the ord array) pass. Map
	// buckets are not observable, so the identity check below catches a
	// retained map while the ord capacity check catches a trim in place.
	plane.muRealDomainSet.Lock()
	plane.realDomainSet = make(map[string]struct{}, realDomainSetCapacity)
	plane.realDomainOrd = make([]string, 0, realDomainSetCapacity)
	for i := 0; i < realDomainSetCapacity; i++ {
		domain := fmt.Sprintf("gen-%d.example", i)
		plane.realDomainSet[domain] = struct{}{}
		plane.realDomainOrd = append(plane.realDomainOrd, domain)
	}
	plane.muRealDomainSet.Unlock()
	beforeMap := fmt.Sprintf("%p", plane.realDomainSet)
	plane.dnsRouting = &dns.Dns{}

	// New-connection-only satellites. Live flows pin the plane itself, so
	// these would otherwise ride along once per reload even though they can
	// never serve an established flow.
	plane.core = &controlPlaneCore{}
	plane.core.domainRoutingSlots[0] = newDomainRoutingTracker()
	plane.core.domainRoutingSlots[0].owners["gen.example"] = domainRoutingOwnerSnapshot{}
	plane.core.domainRouting = plane.core.domainRoutingSlots[0]
	plane.routingKernspaceSnapshot = &routingKernspaceSnapshot{rules: []bpfMatchSet{{}}}
	plane.sniLearning = &sniLearning{
		owners: map[string]*sniOwner{"gen.example": {}},
		ips:    map[[4]uint32]map[string]struct{}{{1, 2, 3, 4}: {"gen.example": {}}},
	}

	if err := plane.closeTail(); err != nil {
		t.Fatalf("closeTail: %v", err)
	}

	if ran != 1 {
		t.Fatalf("deferred closures ran %d times, want 1", ran)
	}
	if plane.deferFuncs != nil {
		t.Fatalf("deferFuncs retained after closeTail: %d entries", len(plane.deferFuncs))
	}

	plane.muRealDomainSet.RLock()
	setLen, ordCap := len(plane.realDomainSet), cap(plane.realDomainOrd)
	plane.muRealDomainSet.RUnlock()
	if setLen != 0 || ordCap != 0 {
		t.Fatalf("confirmed-real-domain cache retained after closeTail: set=%d ordCap=%d", setLen, ordCap)
	}
	if now := fmt.Sprintf("%p", plane.realDomainSet); now == beforeMap {
		t.Fatal("closeTail kept the preallocated map; it must assign a fresh map (clear() retains the buckets)")
	}
	if plane.dnsRouting != nil {
		t.Fatal("dnsRouting retained after closeTail")
	}
	for slot, tracker := range plane.core.domainRoutingSlots {
		if tracker != nil {
			t.Fatalf("domain routing tracker slot %d retained after closeTail", slot)
		}
	}
	if plane.core.domainRouting != nil {
		t.Fatal("domain routing alias retained after closeTail")
	}
	if plane.routingKernspaceSnapshot != nil {
		t.Fatal("routing kernspace snapshot retained after closeTail")
	}
	plane.sniLearning.trackerMu.Lock()
	sniOwners, sniIPs := len(plane.sniLearning.owners), len(plane.sniLearning.ips)
	plane.sniLearning.trackerMu.Unlock()
	if sniOwners != 0 || sniIPs != 0 {
		t.Fatalf("SNI learning tables retained after closeTail: owners=%d ips=%d", sniOwners, sniIPs)
	}

	// The BPF object outlives the plane (the successor owns it), so a DNS
	// answer that lands after retirement still finds one. It must not rebuild
	// a tracker and project into the retired slot.
	plane.core.InjectBpf(&bpfObjects{})
	late := &DnsCache{
		RouteOwnerKey: "late.example",
		DomainBitmap:  make([]uint32, len(bpfDomainRouting{}.Bitmap)),
	}
	if err := plane.core.BatchUpdateDomainRouting(late); err != nil {
		t.Fatalf("BatchUpdateDomainRouting after closeTail: %v", err)
	}
	if err := plane.core.BatchRemoveDomainRouting(late); err != nil {
		t.Fatalf("BatchRemoveDomainRouting after closeTail: %v", err)
	}
	for slot, tracker := range plane.core.domainRoutingSlots {
		if tracker != nil {
			t.Fatalf("late DNS answer rebuilt domain routing tracker slot %d after closeTail", slot)
		}
	}
	if plane.core.domainRouting != nil {
		t.Fatal("late DNS answer rebuilt the domain routing alias after closeTail")
	}

	// The replacement map exists precisely so a dial that is still in flight
	// when retirement lands can record without panicking on a nil map.
	plane.muRealDomainSet.Lock()
	plane.rememberRealDomain("late.example")
	plane.muRealDomainSet.Unlock()
	if known, real := plane.lookupRealDomainCache("late.example"); !known || !real {
		t.Fatalf("post-close record lost: known=%v real=%v", known, real)
	}
}
