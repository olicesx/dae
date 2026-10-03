/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// lockProbeWriter fails the test when the latency listing is rendered while
// the set's write lock is held. It only inspects writes that belong to the
// listing, because the same logger also emits a "Group selects dialer" line
// (a scalar logrus.Fields write, not the list render). The render itself is
// debug-level (see printLatenciesOutOfLock): it is per-dialer detail, while
// the milestone line above it is the info-level event.
type lockProbeWriter struct {
	set     *AliveDialerSet
	mu      sync.Mutex
	renders int
	locked  []string
}

func (w *lockProbeWriter) Write(p []byte) (int, error) {
	text := string(p)
	if strings.Contains(text, "Group '") {
		w.mu.Lock()
		w.renders++
		w.mu.Unlock()
		if w.set.mu.TryLock() {
			// TryLock acquired: the render really ran without the lock.
			w.set.mu.Unlock()
		} else {
			w.mu.Lock()
			w.locked = append(w.locked, text)
			w.mu.Unlock()
		}
	}
	return len(p), nil
}

func (w *lockProbeWriter) countsRenders() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.renders
}

func (w *lockProbeWriter) counts() (renders int, locked []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.renders, append([]string(nil), w.locked...)
}

// TestNotifyLatencyDoesNotHoldWriteLockDuringFormatting is the P2-27
// regression: the latency listing used to be sorted and written to the log
// while holding AliveDialerSet.mu, so every other latency update (and the 30s
// health cycle for the whole group) queued behind a full-list render plus a
// log write. The probe asserts the invariant directly instead of relying on
// timing.
func TestNotifyLatencyDoesNotHoldWriteLockDuringFormatting(t *testing.T) {
	networkType := newTestNetworkType()
	d1 := newNamedTestDialer(t, "print-1")
	d2 := newNamedTestDialer(t, "print-2")

	// Seed both dialers before construction so the initial ranking is real
	// (d1 100ms, d2 500ms) rather than an optimistic 0-latency key: a dialer
	// without a measurement can no longer outrank a measured one.
	d1.collectionFineMu.Lock()
	d1.mustGetCollection(networkType).Latencies10.AppendLatency(100 * time.Millisecond)
	d1.collectionFineMu.Unlock()
	d2.collectionFineMu.Lock()
	d2.mustGetCollection(networkType).Latencies10.AppendLatency(500 * time.Millisecond)
	d2.collectionFineMu.Unlock()

	set := NewAliveDialerSet(
		d1.Log,
		"print-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{d1, d2},
		[]*Annotation{{}, {}},
		func(bool) {},
		false,
	)
	d1.RegisterAliveDialerSet(set)
	d2.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		d1.UnregisterAliveDialerSet(set)
		d2.UnregisterAliveDialerSet(set)
	})

	probe := &lockProbeWriter{set: set}
	d1.Log.SetOutput(probe)
	// Debug is where the listing is emitted; the invariant (no render while
	// the set lock is held) is the same at either level, so the test drives
	// the level that actually reaches the renderer.
	d1.Log.SetLevel(logrus.DebugLevel)

	// A better real latency for d2 re-ranks the measured group, which is the
	// path that renders the listing.
	before := probe.countsRenders()
	d2.collectionFineMu.Lock()
	d2.mustGetCollection(networkType).Latencies10.AppendLatency(50 * time.Millisecond)
	d2.collectionFineMu.Unlock()
	set.NotifyLatencyChange(d2, true)
	if probe.countsRenders() == before {
		t.Fatal("the latency listing was not rendered; the probe observed nothing")
	}

	_, locked := probe.counts()
	if len(locked) > 0 {
		t.Fatalf("latency listing was rendered while the set write lock was held:\n%s", locked[0])
	}
}

// TestLatencyTableShowsClassTiers pins the mixed-class render: the debug table
// is ordered by the selection comparator (measurement class first, then key)
// and carries each row's class, so an operator reading why a measured dialer
// was selected over a lower offset-only key sees the class tier spelled out.
// Sorting by the raw key alone used to rank the unmeasured row first.
func TestLatencyTableShowsClassTiers(t *testing.T) {
	networkType := newTestNetworkType()
	measured := newNamedTestDialer(t, "m-node")
	unmeasured := newNamedTestDialer(t, "u-node")

	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	measured.Log = logger
	unmeasured.Log = logger

	appendLatencyLocked(measured, networkType, 500*time.Millisecond)

	set := NewAliveDialerSet(
		logger,
		"tier-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{measured, unmeasured},
		[]*Annotation{{}, {AddLatency: -100 * time.Millisecond}},
		func(bool) {},
		true,
	)
	measured.RegisterAliveDialerSet(set)
	unmeasured.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		measured.UnregisterAliveDialerSet(set)
		unmeasured.UnregisterAliveDialerSet(set)
	})

	snap, ok := set.snapshotLatenciesLocked()
	if !ok {
		t.Fatal("latency snapshot was not built at debug level")
	}
	set.printLatenciesOutOfLock(snap)

	var table string
	for _, entry := range hook.AllEntries() {
		if strings.Contains(entry.Message, "Group 'tier-group'") {
			table = entry.Message
		}
	}
	if table == "" {
		t.Fatal("latency table was not rendered")
	}
	var measuredRow, unmeasuredRow = -1, -1
	for i, line := range strings.Split(table, "\n") {
		switch {
		case strings.Contains(line, "m-node"):
			measuredRow = i
			if !strings.Contains(line, "measured") {
				t.Fatalf("measured row lacks its class: %v", line)
			}
		case strings.Contains(line, "u-node"):
			unmeasuredRow = i
			if !strings.Contains(line, "unmeasured") {
				t.Fatalf("unmeasured row lacks its class: %v", line)
			}
		}
	}
	if measuredRow < 0 || unmeasuredRow < 0 {
		t.Fatalf("table is missing a row (measured=%d unmeasured=%d):\n%v", measuredRow, unmeasuredRow, table)
	}
	if measuredRow > unmeasuredRow {
		t.Fatalf("table ranks the unmeasured row above the measured one despite the "+
			"class tier:\n%v", table)
	}
}

// TestLatencySnapshotIsByValue guards the hard requirement behind P2-27: the
// snapshot must copy everything the renderer needs, because aliveEntries is
// mutated in place (append / swap-remove) and dialerToLatency is replaced
// wholesale by recomputeSelectionStateLocked. Under -race, leaking either
// reference into the out-of-lock render makes this loop report a data race.
func TestLatencySnapshotIsByValue(t *testing.T) {
	networkType := newTestNetworkType()
	d1 := newNamedTestDialer(t, "snap-1")
	d2 := newNamedTestDialer(t, "snap-2")

	d1.collectionFineMu.Lock()
	d1.mustGetCollection(networkType).Latencies10.AppendLatency(10 * time.Millisecond)
	d1.collectionFineMu.Unlock()
	d2.collectionFineMu.Lock()
	d2.mustGetCollection(networkType).Latencies10.AppendLatency(20 * time.Millisecond)
	d2.collectionFineMu.Unlock()

	set := NewAliveDialerSet(
		d1.Log,
		"snap-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{d1, d2},
		[]*Annotation{{}, {}},
		func(bool) {},
		true,
	)
	set.log.SetLevel(logrus.InfoLevel)
	set.log.SetOutput(&lockProbeWriter{set: set})

	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			// recomputeSelectionStateLocked replaces dialerToLatency wholesale.
			if i%2 == 0 {
				set.SetSelectionPolicy(consts.DialerSelectionPolicy_MinAverage10Latencies)
			} else {
				set.SetSelectionPolicy(consts.DialerSelectionPolicy_MinMovingAverageLatencies)
			}
		}
	})

	for i := range 200 {
		// aliveEntries is appended to / swap-removed here, and the render runs
		// outside the lock.
		set.NotifyLatencyChange(d1, i%2 == 0)
		set.NotifyLatencyChange(d2, i%3 != 0)
	}
	close(done)
	wg.Wait()
}
