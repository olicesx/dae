/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type udpConnStateOwnerProbe struct {
	retainCalls atomic.Int64
	retained    atomic.Int64
}

func (p *udpConnStateOwnerProbe) RetainUdpConnStateTuples(keys []bpfTuplesKey) {
	p.retainCalls.Add(1)
	p.retained.Add(int64(len(keys)))
}

func (*udpConnStateOwnerProbe) TransferRetainedUdpConnStateTuplesFrom(udpConnStateOwner, []bpfTuplesKey) {
}

func (*udpConnStateOwnerProbe) ReleaseUdpConnStateTuples([]bpfTuplesKey) error {
	return nil
}

func TestUdpEndpointTrackUdpConnStateTuplePairFastHitAndFullConeRefs(t *testing.T) {
	owner := new(udpConnStateOwnerProbe)
	endpoint := &UdpEndpoint{udpConnStateOwner: owner}
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	firstDst := netip.MustParseAddrPort("198.51.100.20:443")
	secondDst := netip.MustParseAddrPort("203.0.113.30:3478")

	endpoint.TrackUdpConnStateTuplePair(src, firstDst)
	if got := owner.retainCalls.Load(); got != 1 {
		t.Fatalf("retain calls after first pair = %d, want 1", got)
	}
	if got := owner.retained.Load(); got != 2 {
		t.Fatalf("retained keys after first pair = %d, want 2", got)
	}

	endpoint.udpConnStateMu.Lock()
	fastHitDone := make(chan struct{})
	go func() {
		endpoint.TrackUdpConnStateTuplePair(firstDst, src)
		close(fastHitDone)
	}()
	select {
	case <-fastHitDone:
	case <-time.After(time.Second):
		endpoint.udpConnStateMu.Unlock()
		t.Fatal("cached tuple-pair hit waited for endpoint conn-state mutex")
	}
	endpoint.udpConnStateMu.Unlock()

	for range 32 {
		endpoint.TrackUdpConnStateTuplePair(src, firstDst)
	}
	endpoint.TrackUdpConnStateTuplePair(src, secondDst)
	for range 32 {
		endpoint.TrackUdpConnStateTuplePair(src, secondDst)
		endpoint.TrackUdpConnStateTuplePair(src, firstDst)
	}
	if got := owner.retainCalls.Load(); got != 2 {
		t.Fatalf("retain calls after repeated full-cone pairs = %d, want 2", got)
	}
	if got := owner.retained.Load(); got != 4 {
		t.Fatalf("retained keys after repeated full-cone pairs = %d, want 4", got)
	}
	if got := len(endpoint.udpConnStateTuples); got != 4 {
		t.Fatalf("tracked full-cone tuple count = %d, want 4", got)
	}
}

func TestUdpEndpointTrackUdpConnStateTuplePairHitAllocations(t *testing.T) {
	endpoint := &UdpEndpoint{udpConnStateOwner: new(udpConnStateOwnerProbe)}
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	endpoint.TrackUdpConnStateTuplePair(src, dst)

	allocs := testing.AllocsPerRun(1000, func() {
		endpoint.TrackUdpConnStateTuplePair(src, dst)
	})
	if allocs != 0 {
		t.Fatalf("cached tuple-pair hit allocations = %v, want 0", allocs)
	}
}

func BenchmarkUdpEndpointTrackConnStateTuplePair(b *testing.B) {
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	firstDst := netip.MustParseAddrPort("198.51.100.20:443")
	secondDst := netip.MustParseAddrPort("203.0.113.30:3478")

	b.Run("cached_pair_hit", func(b *testing.B) {
		endpoint := &UdpEndpoint{udpConnStateOwner: new(udpConnStateOwnerProbe)}
		endpoint.TrackUdpConnStateTuplePair(src, firstDst)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			endpoint.TrackUdpConnStateTuplePair(src, firstDst)
		}
	})
	b.Run("fullcone_alternating_tracked_pairs", func(b *testing.B) {
		endpoint := &UdpEndpoint{udpConnStateOwner: new(udpConnStateOwnerProbe)}
		endpoint.TrackUdpConnStateTuplePair(src, firstDst)
		endpoint.TrackUdpConnStateTuplePair(src, secondDst)
		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			if i&1 == 0 {
				endpoint.TrackUdpConnStateTuplePair(src, firstDst)
			} else {
				endpoint.TrackUdpConnStateTuplePair(src, secondDst)
			}
		}
	})
}
