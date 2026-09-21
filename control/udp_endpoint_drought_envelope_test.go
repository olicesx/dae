/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

// TestUdpEndpointDroughtThresholdEnvelope pins the shape of the send-rate
// evidence the reply-drought gate acts on, and checks the shipped thresholds
// against realistic client patterns with the window and the minimum rate moved
// across their plausible range.
//
// The evidence is the larger of the lifetime average over the drought and the
// datagrams of the current probe window. That makes the decision a plateau for
// flows that are clearly interactive or clearly sparse instead of a knife edge:
// only a pattern sitting within a factor of two of the threshold can be decided
// either way, and those patterns are listed here as ambiguous rather than
// swept. The constants are therefore a choice inside a documented envelope, not
// a measured operating point; what would move them is field data on the
// distributions, and this test records exactly which decisions such data could
// change.
//
// Falsifier: if real traces show interactive flows clustering near 2 packets/s
// over 30s, udpEndpointReplyDroughtMinRate and/or
// udpEndpointReplyDroughtWindow must be retuned. The ambiguous patterns
// (threshold_2pps, just_under_2pps) are exactly the decisions that data would
// move. The invariant patterns (interactive ≥5 pps vs sparse ≤0.2 pps) would
// not. This file is the contract for that residual; it does not pretend a
// field capture exists.
func TestUdpEndpointDroughtThresholdEnvelope(t *testing.T) {
	type pattern struct {
		name      string
		pps       float64 // steady datagram rate the client writes at
		promote   bool    // decision every swept combination must produce
		shipped   bool    // decision at the shipped window and minimum rate
		ambiguous bool    // sits next to the threshold: not invariant
	}
	patterns := []pattern{
		{name: "quic_60pps", pps: 60, promote: true, shipped: true},
		{name: "game_30pps", pps: 30, promote: true, shipped: true},
		{name: "one_way_stream_10pps", pps: 10, promote: true, shipped: true},
		{name: "video_5pps", pps: 5, promote: true, shipped: true},
		{name: "burst_then_quiet_0.2pps", pps: 0.2, promote: false, shipped: false},
		{name: "dns_like_0.07pps", pps: 0.07, promote: false, shipped: false},
		{name: "wireguard_keepalive_0.04pps", pps: 0.04, promote: false, shipped: false},
		// The boundary itself: exactly at the minimum rate promotes, just under
		// it does not. These two pin the shipped constant, which the sweep is
		// deliberately insensitive to.
		{name: "threshold_2pps", pps: 2, ambiguous: true, shipped: true},
		{name: "just_under_2pps", pps: 1.9, ambiguous: true, shipped: false},
	}
	windows := []time.Duration{20 * time.Second, udpEndpointReplyDroughtWindow, 45 * time.Second}
	minRates := []int{1, udpEndpointReplyDroughtMinRate, 3, 4}

	for _, p := range patterns {
		// The shipped constants decide the pattern once, at the shipped window.
		shippedRate := droughtSendRateFrom(
			int64(p.pps*udpEndpointReplyDroughtWindow.Seconds()),
			udpEndpointReplyDroughtWindow.Nanoseconds(),
			int64(p.pps*udpEndpointReplyDroughtProbeWindow.Seconds()),
		)
		if got := shippedRate >= float64(udpEndpointReplyDroughtMinRate); got != p.shipped {
			t.Fatalf("%s at the shipped thresholds: evidence %.3f/s promotes=%v, want %v",
				p.name, shippedRate, got, p.shipped)
		}
		decisions := map[bool]int{}
		for _, window := range windows {
			datagrams := int(p.pps * window.Seconds())
			recent := int(p.pps * udpEndpointReplyDroughtProbeWindow.Seconds())
			rate := droughtSendRateFrom(int64(datagrams), window.Nanoseconds(), int64(recent))
			// The evidence is bounded by the flow's own average and peak rates,
			// which is what keeps a burst from being read as a steady flow and
			// a steady flow from decaying to nothing.
			if rate < float64(datagrams)/window.Seconds() {
				t.Fatalf("%s at window %s: evidence %.3f/s is below the flow's average", p.name, window, rate)
			}
			if recent > 0 {
				peak := float64(recent) / udpEndpointReplyDroughtProbeWindow.Seconds()
				if rate > peak && rate > float64(datagrams)/window.Seconds() {
					t.Fatalf("%s at window %s: evidence %.3f/s exceeds both the average and the peak", p.name, window, rate)
				}
			}
			for _, minRate := range minRates {
				promotes := rate >= float64(minRate)
				decisions[promotes]++
				if p.ambiguous {
					continue
				}
				if promotes != p.promote {
					t.Fatalf("%s at window %s and minimum rate %d: evidence %.3f/s promotes=%v, want %v",
						p.name, window, minRate, rate, promotes, p.promote)
				}
			}
		}
		if p.ambiguous && len(decisions) < 2 {
			t.Fatalf("%s is documented as ambiguous but every swept combination decided the same way", p.name)
		}
	}
}
