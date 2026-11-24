/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// tcpBackstopEntry builds the conn_state value the janitor sees for a TCP
// entry last seen age ago on the CLOCK_MONOTONIC base. A negative age leaves
// LastSeenNs unstamped. The thresholds come from the production values, so
// the tests fail if a backstop or a branch changes meaning.
func tcpBackstopEntry(nowNano int64, age time.Duration, state uint8, hasRouting bool, outbound consts.OutboundIndex) bpfConnState {
	value := bpfConnState{State: state}
	if age >= 0 {
		value.LastSeenNs = uint64(nowNano - int64(age))
	}
	if hasRouting {
		value.Meta.Data.HasRouting = 1
	}
	value.Meta.Data.Outbound = uint8(outbound)
	return value
}

func TestTCPConnStateExpired(t *testing.T) {
	const (
		sec     = time.Second
		active  = 0 // ACTIVE is the zero value of conn_state.state
		nowNano = int64(1) << 40
	)
	backstops := tcpConnStateBackstopsFor(false)
	// Any index past DIRECT and BLOCK is a routed, forwarded verdict.
	forwarded := consts.OutboundUserDefinedMin

	cases := []struct {
		name    string
		value   bpfConnState
		expired bool
	}{
		{"established, seen just now", tcpBackstopEntry(nowNano, 0, active, true, forwarded), false},
		{"closing inside its grace", tcpBackstopEntry(nowNano, backstops.closing-sec, tcpConnStateClosing, true, forwarded), false},
		{"closing past its grace", tcpBackstopEntry(nowNano, backstops.closing+sec, tcpConnStateClosing, true, forwarded), true},
		{"routing-less inside its backstop", tcpBackstopEntry(nowNano, backstops.routingless/2, active, false, consts.OutboundDirect), false},
		{"routing-less past its backstop", tcpBackstopEntry(nowNano, backstops.routingless+sec, active, false, consts.OutboundDirect), true},
		{"blocked inside its backstop", tcpBackstopEntry(nowNano, backstops.blocked-sec, active, true, consts.OutboundBlock), false},
		// Still inside the unpinned backstop: BLOCK brings its own, shorter age.
		{"blocked past its backstop", tcpBackstopEntry(nowNano, backstops.blocked+sec, active, true, consts.OutboundBlock), true},
		{"forwarded unpinned inside its backstop", tcpBackstopEntry(nowNano, backstops.unpinned-sec, active, true, forwarded), false},
		{"forwarded unpinned past its backstop", tcpBackstopEntry(nowNano, backstops.unpinned+sec, active, true, forwarded), true},
		{"direct past the unpinned backstop", tcpBackstopEntry(nowNano, backstops.unpinned+sec, active, true, consts.OutboundDirect), false},
		{"direct idle for a day", tcpBackstopEntry(nowNano, 24*time.Hour, active, true, consts.OutboundDirect), false},
		{"never stamped", tcpBackstopEntry(nowNano, -1, active, true, forwarded), true},
	}
	for _, tc := range cases {
		if got := tcpConnStateExpired(&tc.value, nowNano, backstops); got != tc.expired {
			t.Errorf("%s: tcpConnStateExpired = %v, want %v", tc.name, got, tc.expired)
		}
	}
}

func TestTCPConnStateBackstopsHalveUnderPressure(t *testing.T) {
	const nowNano = int64(1) << 40
	steady := tcpConnStateBackstopsFor(false)
	pressure := tcpConnStateBackstopsFor(true)
	for name, pair := range map[string][2]time.Duration{
		"closing":     {steady.closing, pressure.closing},
		"routingless": {steady.routingless, pressure.routingless},
		"blocked":     {steady.blocked, pressure.blocked},
		"unpinned":    {steady.unpinned, pressure.unpinned},
	} {
		if pair[1] != pair[0]/2 {
			t.Errorf("%s backstop under pressure = %v, want half of %v", name, pair[1], pair[0])
		}
	}

	blocked := tcpBackstopEntry(nowNano, steady.blocked-time.Second, 0, true, consts.OutboundBlock)
	if tcpConnStateExpired(&blocked, nowNano, steady) {
		t.Error("inside the steady blocked backstop the entry must stay")
	}
	if !tcpConnStateExpired(&blocked, nowNano, pressure) {
		t.Error("past the halved blocked backstop the entry must retire")
	}
}

func TestConnStateStale(t *testing.T) {
	cases := []struct {
		name          string
		lastSeenNs    uint64
		staleBeforeNs uint64
		stale         bool
	}{
		{"no threshold disables the check", 0, 0, false},
		{"never stamped counts as stale", 0, 100, true},
		{"seen before the threshold", 99, 100, true},
		{"seen at the threshold", 100, 100, false},
		{"seen after the threshold", 101, 100, false},
	}
	for _, tc := range cases {
		value := bpfConnState{LastSeenNs: tc.lastSeenNs}
		if got := connStateStale(&value, tc.staleBeforeNs); got != tc.stale {
			t.Errorf("%s: connStateStale = %v, want %v", tc.name, got, tc.stale)
		}
	}
}

// TestConnStateUsagePercent covers the number both the pressure state machine
// and the capacity warning are driven by: 90% of the default 65536 entries is
// the warning threshold.
func TestConnStateUsagePercent(t *testing.T) {
	cases := []struct {
		name string
		udp  mapCleanupStats
		tcp  mapCleanupStats
		want int
	}{
		{"unknown capacity", mapCleanupStats{entries: 10}, mapCleanupStats{entries: 5}, 0},
		{"one below the warning threshold", mapCleanupStats{entries: 58982, maxEntries: 65536}, mapCleanupStats{maxEntries: 65536}, 89},
		{"at the warning threshold", mapCleanupStats{entries: 58983, maxEntries: 65536}, mapCleanupStats{maxEntries: 65536}, 90},
		{"udp and tcp share one map", mapCleanupStats{entries: 30000, maxEntries: 65536}, mapCleanupStats{entries: 30000, maxEntries: 65536}, 91},
	}
	for _, tc := range cases {
		got := connStateUsagePercent(tc.udp, tc.tcp)
		if got != tc.want {
			t.Errorf("%s: connStateUsagePercent = %d, want %d", tc.name, got, tc.want)
		}
	}
	if low, high := connStateUsagePercent(cases[1].udp, cases[1].tcp), connStateUsagePercent(cases[2].udp, cases[2].tcp); low >= connStateJanitorUsageWarnPercent || high < connStateJanitorUsageWarnPercent {
		t.Errorf("the warning gate must open at %d entries, got low=%d high=%d", cases[2].udp.entries, low, high)
	}
}
