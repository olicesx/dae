/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// The scenarios below reproduce the production defect observed on a user
// router (2026-10-09, dae.log): a node whose per-attempt probes keep
// succeeding (isolated, spaced connections pass on an intermittently
// degraded path) while production DNS forwards through it fail continuously.
// The node held the DNS health domain for the whole log because:
//
//  1. Transactional failures only feed a consecutive-strike counter
//     (threshold 3) and every failure also triggers a targeted probe whose
//     success resets the counter, so an interleaved 2-fails-1-success
//     pattern never evicts, however long it runs.
//  2. Any single probe success calls markAvailable, which flips the class
//     back alive immediately, so even a successful eviction is undone within
//     one emergency-probe interval, and min-latency selection returns to the
//     fast-but-broken node.
//
// Desired behaviour asserted here:
//   - An interleaved failure storm must evict the node from the DNS health
//     domain on accumulated evidence, not on consecutive strikes.
//   - A single probe success must not revive an evidence-evicted node;
//     revival requires consecutive probe confirmations.
//   - A genuinely healthy node with sporadic failures must stay selected.

func newTestUdpDnsNetworkType() *NetworkType {
	return &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		IsDns:           true,
		UdpHealthDomain: UdpHealthDomainDns,
	}
}

// probeSuccess drives one probe success the way the daemon's check loop
// does: markAvailable plus the group update the real caller always delivers.
func probeSuccess(d *Dialer, typ *NetworkType, latency time.Duration) {
	update, _ := d.markAvailable(typ, latency)
	d.informDialerGroupUpdate(update)
}

// dnsStormGroup builds the two-node group shared by the storm scenarios:
// fastFlaky answers probes at fastLatency but its DNS forwards fail, while
// slowStable answers probes at slowLatency and forwards fine. Both start
// alive and measured, so selection is purely latency-keyed.
func dnsStormGroup(t *testing.T, fastLatency, slowLatency time.Duration) (fastFlaky, slowStable *Dialer, set *AliveDialerSet, typ *NetworkType) {
	t.Helper()
	typ = newTestUdpDnsNetworkType()
	fastFlaky = newNamedTestDialer(t, "storm-fast-flaky")
	slowStable = newNamedTestDialer(t, "storm-slow-stable")

	probeSuccess(fastFlaky, typ, fastLatency)
	probeSuccess(slowStable, typ, slowLatency)

	set = NewAliveDialerSet(
		fastFlaky.Log,
		"storm-group",
		typ,
		0,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		[]*Dialer{fastFlaky, slowStable},
		[]*Annotation{{}, {}},
		func(bool) {},
		true,
	)
	fastFlaky.RegisterAliveDialerSet(set)
	slowStable.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		fastFlaky.UnregisterAliveDialerSet(set)
		slowStable.UnregisterAliveDialerSet(set)
	})
	return fastFlaky, slowStable, set, typ
}

// stormRound models one production round on the degraded path: two DNS
// forward failures (reported transactionally) and one successful probe — the
// failure-triggered targeted probe passing on the intermittently working
// path. Three consecutive failures never occur, so the strike counter alone
// can never evict.
func stormRound(fastFlaky *Dialer, typ *NetworkType, fastLatency time.Duration) {
	err := errors.New("EOF")
	fastFlaky.ReportUnavailableTransactional(typ, err)
	fastFlaky.ReportUnavailableTransactional(typ, err)
	probeSuccess(fastFlaky, typ, fastLatency)
}

// TestInterleavedDnsFailureStormEvictsProbePassingNode pins the eviction
// half of the fix: accumulated transactional failure evidence must evict the
// node even while isolated probes keep passing, and the group must fall back
// to the stable node.
func TestInterleavedDnsFailureStormEvictsProbePassingNode(t *testing.T) {
	fastFlaky, slowStable, set, typ := dnsStormGroup(t, 130*time.Millisecond, 350*time.Millisecond)

	if got, _ := set.GetMinLatency(nil); got != fastFlaky {
		t.Fatalf("setup: selected %v, want the fast node", got.property.Name)
	}

	// Forty failures interleaved with twenty passing probes: the strike
	// counter never reaches three, yet the evidence is overwhelming.
	for range 20 {
		stormRound(fastFlaky, typ, 130*time.Millisecond)
	}

	if fastFlaky.MustGetAlive(typ) {
		t.Fatal("interleaved failure storm (40 transactional failures, 0 consecutive triples) never evicted the node: " +
			"eviction must key on accumulated evidence, not on consecutive strikes")
	}
	if got, _ := set.GetMinLatency(nil); got != slowStable {
		t.Fatalf("selected %v after the storm, want the stable fallback", got.property.Name)
	}
}

// TestSingleProbeSuccessDoesNotReviveEvidenceEvictedNode pins the revival
// half of the fix: after eviction, one passing probe must not hand the class
// back (that single-success revival is what turned eviction into a livelock
// in production); consecutive confirmations are required.
func TestSingleProbeSuccessDoesNotReviveEvidenceEvictedNode(t *testing.T) {
	fastFlaky, _, _, typ := dnsStormGroup(t, 130*time.Millisecond, 350*time.Millisecond)

	for range 20 {
		stormRound(fastFlaky, typ, 130*time.Millisecond)
	}
	if fastFlaky.MustGetAlive(typ) {
		t.Fatal("setup: the storm must have evicted the node first")
	}

	// One emergency-probe success on the intermittently working path.
	probeSuccess(fastFlaky, typ, 130*time.Millisecond)

	if fastFlaky.MustGetAlive(typ) {
		t.Fatal("a single probe success revived the evidence-evicted node: " +
			"revival must require consecutive probe confirmations")
	}
}

// TestEvictedNodeRevivesOnConsecutiveProbeSuccesses pins the honest-recovery
// direction: once the failure storm stops, the emergency-probe cadence must
// still bring an evidence-evicted node back within the bounded
// evidenceRevivalConfirmations confirmations.
func TestEvictedNodeRevivesOnConsecutiveProbeSuccesses(t *testing.T) {
	fastFlaky, _, _, typ := dnsStormGroup(t, 130*time.Millisecond, 350*time.Millisecond)

	for range 20 {
		stormRound(fastFlaky, typ, 130*time.Millisecond)
	}
	if fastFlaky.MustGetAlive(typ) {
		t.Fatal("setup: the storm must have evicted the node first")
	}
	// The storm's trailing probe already banked one confirmation; one more
	// transactional failure resets the chain so the count below starts at
	// zero, matching an honest recovery that begins after the last failure.
	fastFlaky.ReportUnavailableTransactional(typ, errors.New("EOF"))

	for i := 1; i < evidenceRevivalConfirmations; i++ {
		probeSuccess(fastFlaky, typ, 130*time.Millisecond)
		if fastFlaky.MustGetAlive(typ) {
			t.Fatalf("probe success #%d revived the node early: revival needs %d consecutive confirmations",
				i, evidenceRevivalConfirmations)
		}
	}
	probeSuccess(fastFlaky, typ, 130*time.Millisecond)
	if !fastFlaky.MustGetAlive(typ) {
		t.Fatalf("the node did not revive after %d consecutive probe successes", evidenceRevivalConfirmations)
	}
	// Revival restores eligibility, not the crown: the eviction fed the
	// backoff penalty, so the snapshot latency (130ms + penalty) still loses
	// to the stable node until periodic wash-white decays the penalty. That
	// ordering is the system's built-in selection hysteresis; this test only
	// pins that the revived node is back in the selectable set.
	if fastFlaky.mustGetCollection(typ).Alive.Load() != true {
		t.Fatal("revived node must be selectable again")
	}
}

// TestTransactionFailuresBreakProbeConfirmationChain pins the tiebreak rule
// between the two evidence sources: probes keep passing at their own cadence
// while real traffic keeps failing, so the confirmation chain must never
// complete and the eviction must hold for as long as the disagreement does.
func TestTransactionFailuresBreakProbeConfirmationChain(t *testing.T) {
	fastFlaky, _, _, typ := dnsStormGroup(t, 130*time.Millisecond, 350*time.Millisecond)

	err := errors.New("EOF")
	// Thirty rounds of one failure plus one passing probe: without the
	// chain-break rule, every third probe would revive the node and restart
	// the cycle forever.
	for range 30 {
		fastFlaky.ReportUnavailableTransactional(typ, err)
		probeSuccess(fastFlaky, typ, 130*time.Millisecond)
	}

	if fastFlaky.MustGetAlive(typ) {
		t.Fatal("a 1:1 failure-to-probe-success ratio kept the node alive: " +
			"transactional failures must break the probe-confirmation chain")
	}
}

// TestForwardSuccessStreamRevivesEvidenceEvictedNode pins the traffic-driven
// revival leg: real query successes recover the ring, and a recovered ring
// revives the class without waiting for probes.
func TestForwardSuccessStreamRevivesEvidenceEvictedNode(t *testing.T) {
	fastFlaky, _, _, typ := dnsStormGroup(t, 130*time.Millisecond, 350*time.Millisecond)

	for range 20 {
		stormRound(fastFlaky, typ, 130*time.Millisecond)
	}
	if fastFlaky.MustGetAlive(typ) {
		t.Fatal("setup: the storm must have evicted the node first")
	}

	// Enough real successes to rotate the failing samples out of the ring.
	for !fastFlaky.MustGetAlive(typ) {
		fastFlaky.ReportAvailableTransactional(typ)
	}
	if fastFlaky.MustGetAlive(typ) != true {
		t.Fatal("a stream of real forward successes must revive the evidence-evicted node")
	}
}

// TestProbeFailureBreaksConfirmationChain pins the "consecutive" in
// consecutive confirmations: a failing probe between two passing ones must
// restart the chain, so a genuinely dead path cannot stagger back on
// alternating probe outcomes.
func TestProbeFailureBreaksConfirmationChain(t *testing.T) {
	fastFlaky, _, _, typ := dnsStormGroup(t, 130*time.Millisecond, 350*time.Millisecond)

	for range 20 {
		stormRound(fastFlaky, typ, 130*time.Millisecond)
	}
	fastFlaky.ReportUnavailableTransactional(typ, errors.New("EOF"))
	if fastFlaky.MustGetAlive(typ) {
		t.Fatal("setup: the storm must have evicted the node first")
	}

	for round := 0; round < 4; round++ {
		for i := 1; i < evidenceRevivalConfirmations; i++ {
			probeSuccess(fastFlaky, typ, 130*time.Millisecond)
		}
		// One failed probe before the would-be final confirmation.
		fastFlaky.informDialerGroupUpdate(fastFlaky.markUnavailable(typ))
	}
	probeSuccess(fastFlaky, typ, 130*time.Millisecond)
	if fastFlaky.MustGetAlive(typ) {
		t.Fatal("a failing probe between confirmations must restart the chain: the node revived without consecutive successes")
	}
}

// TestSporadicDnsFailureKeepsHealthyNodeSelected guards the opposite
// direction: a healthy node whose real query stream fails one attempt in
// eight must stay alive and selected — evidence eviction must tolerate
// isolated blips.
func TestSporadicDnsFailureKeepsHealthyNodeSelected(t *testing.T) {
	fastFlaky, _, set, typ := dnsStormGroup(t, 130*time.Millisecond, 350*time.Millisecond)

	err := errors.New("EOF")
	for range 24 {
		fastFlaky.ReportUnavailableTransactional(typ, err)
		for range 7 {
			fastFlaky.ReportAvailableTransactional(typ)
		}
	}

	if !fastFlaky.MustGetAlive(typ) {
		t.Fatal("a 1-in-8 sporadic failure rate evicted a healthy node: " +
			"evidence eviction must tolerate isolated blips")
	}
	if got, _ := set.GetMinLatency(nil); got != fastFlaky {
		t.Fatalf("selected %v, want the healthy fast node to keep the class", got.property.Name)
	}
}
