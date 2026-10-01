/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// TestUnmeasuredDialerNeverOutranksMeasured pins the selection rule that an
// alive dialer with no latency measurement must never win against a measured
// one, however negative its add_latency offset is. The ranking key of an
// unmeasured dialer used to be raw(0)+offset, so a negative offset produced a
// phantom key that beat real measurements and the group re-selected onto an
// unprobed node.
func TestUnmeasuredDialerNeverOutranksMeasured(t *testing.T) {
	networkType := newTestNetworkType()
	measured := newNamedTestDialer(t, "unmeasured-measured")
	unmeasured := newNamedTestDialer(t, "unmeasured-phantom")

	appendLatencyLocked(measured, networkType, 100*time.Millisecond)

	set := NewAliveDialerSet(
		measured.Log,
		"unmeasured-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{measured, unmeasured},
		[]*Annotation{{}, {AddLatency: -500 * time.Millisecond}},
		func(bool) {},
		true,
	)
	measured.RegisterAliveDialerSet(set)
	unmeasured.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		measured.UnregisterAliveDialerSet(set)
		unmeasured.UnregisterAliveDialerSet(set)
	})

	if got, key := set.GetMinLatency(nil); got != measured {
		t.Fatalf("best dialer is the unmeasured one (key %v), want the measured 100ms dialer: "+
			"an absent measurement must not outrank a real one", key)
	}
}

// TestMeasuredDialerHoldsSelectionAgainstUnmeasuredTie reproduces the
// production shape behind the "Group re-selects dialer" churn: a measured
// dialer whose add_latency offset (-500ms) places its key next to an unmeasured
// dialer's phantom key (-180ms), with the moving average following the probe
// across that boundary. Before the fix each rising sample handed the selection
// to the unmeasured dialer via calcMinLatency's plain minimum scan, so the
// group flapped on every couple of samples.
func TestMeasuredDialerHoldsSelectionAgainstUnmeasuredTie(t *testing.T) {
	networkType := newTestNetworkType()
	measured := newNamedTestDialer(t, "tie-measured")
	unmeasured := newNamedTestDialer(t, "tie-unmeasured")

	measured.collectionFineMu.Lock()
	measured.mustGetCollection(networkType).MovingAverage = 320 * time.Millisecond
	measured.collectionFineMu.Unlock()

	set := NewAliveDialerSet(
		measured.Log,
		"tie-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		[]*Dialer{measured, unmeasured},
		[]*Annotation{
			{AddLatency: -500 * time.Millisecond},
			{AddLatency: -180 * time.Millisecond},
		},
		func(bool) {},
		true,
	)
	measured.RegisterAliveDialerSet(set)
	unmeasured.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		measured.UnregisterAliveDialerSet(set)
		unmeasured.UnregisterAliveDialerSet(set)
	})

	samples := []time.Duration{340 * time.Millisecond, 300 * time.Millisecond}
	for i := range 6 {
		measured.collectionFineMu.Lock()
		measured.mustGetCollection(networkType).MovingAverage = samples[i%len(samples)]
		measured.collectionFineMu.Unlock()
		set.NotifyLatencyChange(measured, true)

		if got, key := set.GetMinLatency(nil); got != measured {
			t.Fatalf("iteration %d: selection switched to the unmeasured dialer (key %v); "+
				"a phantom key must not re-select the group", i, key)
		}
	}
}

// TestMeasuredDialerReplacesUnmeasuredIncumbentDespiteTolerance pins the class
// boundary against the configured hysteresis: check_tolerance damps jitter
// between comparable measurements, it must not keep an unmeasured incumbent.
// Replacing it is a correction (a real measurement arrived), not noise.
func TestMeasuredDialerReplacesUnmeasuredIncumbentDespiteTolerance(t *testing.T) {
	networkType := newTestNetworkType()
	unmeasured := newNamedTestDialer(t, "tolerance-unmeasured")
	measured := newNamedTestDialer(t, "tolerance-measured")

	appendLatencyLocked(measured, networkType, 100*time.Millisecond)

	set := NewAliveDialerSet(
		unmeasured.Log,
		"tolerance-group",
		networkType,
		time.Second, // check_tolerance: far larger than the measurement
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{unmeasured, measured},
		[]*Annotation{{}, {}},
		func(bool) {},
		true,
	)
	unmeasured.RegisterAliveDialerSet(set)
	measured.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		unmeasured.UnregisterAliveDialerSet(set)
		measured.UnregisterAliveDialerSet(set)
	})

	if got, key := set.GetMinLatency(nil); got != measured {
		t.Fatalf("best dialer is still the unmeasured one (key %v), want the measured "+
			"dialer: check_tolerance must not preserve the absence of a measurement", key)
	}
}

// TestIncumbentLosingItsMeasurementIsReconciled pins the class bookkeeping for
// an incumbent that is still alive but reports no measurement (for example a
// health restore replaced the live latency ring). Its recorded class must drop
// to unmeasured together with its entry, so a measured peer takes over instead
// of the incumbent keeping a stale class and a stale latency.
func TestIncumbentLosingItsMeasurementIsReconciled(t *testing.T) {
	networkType := newTestNetworkType()
	stale := newNamedTestDialer(t, "stale-incumbent")
	measured := newNamedTestDialer(t, "measured-peer")

	setMovingAverage := func(d *Dialer, v time.Duration) {
		d.collectionFineMu.Lock()
		d.mustGetCollection(networkType).MovingAverage = v
		d.collectionFineMu.Unlock()
	}
	setMovingAverage(stale, 100*time.Millisecond)
	setMovingAverage(measured, 500*time.Millisecond)

	set := NewAliveDialerSet(
		stale.Log,
		"reconcile-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		[]*Dialer{stale, measured},
		[]*Annotation{{}, {}},
		func(bool) {},
		true,
	)
	stale.RegisterAliveDialerSet(set)
	measured.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		stale.UnregisterAliveDialerSet(set)
		measured.UnregisterAliveDialerSet(set)
	})

	if got, _ := set.GetMinLatency(nil); got != stale {
		t.Fatalf("initial best dialer is not the 100ms dialer; the fixture is wrong")
	}

	// The incumbent loses its measurement while staying alive.
	setMovingAverage(stale, 0)
	set.NotifyLatencyChange(stale, true)

	if got, key := set.GetMinLatency(nil); got != measured {
		t.Fatalf("best dialer is still the dialer without a measurement (key %v), want the "+
			"measured peer: the incumbent's recorded class must follow its entry", key)
	}
}

// TestHugeAddLatencyKeepsAliveDialerSelectable pins the fallback scan
// semantics that the measurement-class change made explicit: the "time.Hour"
// scan initializer is not a floor. Asking for the best dialer other than the
// incumbent must still return a live dialer whose key is at or above one hour
// (a large configured add_latency or an additive backoff penalty) instead of
// reporting that no dialer is alive.
func TestHugeAddLatencyKeepsAliveDialerSelectable(t *testing.T) {
	networkType := newTestNetworkType()
	incumbent := newNamedTestDialer(t, "huge-offset-incumbent")
	far := newNamedTestDialer(t, "huge-offset-peer")

	appendLatencyLocked(incumbent, networkType, 100*time.Millisecond)
	appendLatencyLocked(far, networkType, 100*time.Millisecond)

	set := NewAliveDialerSet(
		incumbent.Log,
		"huge-offset-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{incumbent, far},
		[]*Annotation{{}, {AddLatency: 2 * time.Hour}},
		func(bool) {},
		true,
	)
	incumbent.RegisterAliveDialerSet(set)
	far.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		incumbent.UnregisterAliveDialerSet(set)
		far.UnregisterAliveDialerSet(set)
	})

	if got, _ := set.GetMinLatency(nil); got != incumbent {
		t.Fatalf("initial best dialer is not the 100ms dialer; the fixture is wrong")
	}

	// Excluding the incumbent forces the fallback scan instead of the cached
	// incumbent lookup. The peer is alive, so it must be returned even though
	// its key is above one hour.
	got, key := set.GetMinLatency(incumbent)
	if got != far {
		t.Fatalf("best non-incumbent dialer = %v (key %v), want the alive peer even though its "+
			"key is above one hour", got, key)
	}
}

// TestAllUnmeasuredStillHonorsAddLatency guards the documented manual-weight
// contract: for network types without an active latency probe (e.g. data-UDP
// without a borrowed DNS latency) every dialer is unmeasured, so add_latency is
// the only ranking signal and must keep re-ranking the group. This is the
// behavior the class-primary rule must preserve rather than replace.
func TestAllUnmeasuredStillHonorsAddLatency(t *testing.T) {
	networkType := newTestNetworkType()
	plain := newNamedTestDialer(t, "weight-plain")
	preferred := newNamedTestDialer(t, "weight-preferred")

	set := NewAliveDialerSet(
		plain.Log,
		"weight-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		[]*Dialer{plain, preferred},
		[]*Annotation{{}, {AddLatency: -500 * time.Millisecond}},
		func(bool) {},
		true,
	)
	plain.RegisterAliveDialerSet(set)
	preferred.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		plain.UnregisterAliveDialerSet(set)
		preferred.UnregisterAliveDialerSet(set)
	})

	if got, _ := set.GetMinLatency(nil); got != preferred {
		t.Fatal("add_latency no longer ranks unmeasured dialers; the manual-weight fallback " +
			"for probe-less network types is broken")
	}
}
