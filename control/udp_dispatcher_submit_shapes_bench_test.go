// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"net/netip"
	"testing"
)

// BenchmarkUDPOrderedSubmitShapes simulates the ingress call-site shapes.
// discard_closure mirrors the old per-packet discard closure; submit_owned
// carries admission ownership in the task value and must not allocate.
func BenchmarkUDPOrderedSubmitShapes(b *testing.B) {
	d := newUDPOrderedDispatcher(2, 32)
	b.Cleanup(func() {
		d.close()
		d.wait()
	})
	key := UdpFlowKey{
		Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
		Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53),
	}
	run := func() {}
	var admission routingEpochIngressGate

	b.Run("discard_closure", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			discard := func() { admission.release() }
			if !d.submit(key, run, discard) {
				discard()
			}
		}
	})
	b.Run("submit_owned", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !d.submitOwned(key, run, nil, &admission) {
				admission.release()
			}
		}
	})
}
