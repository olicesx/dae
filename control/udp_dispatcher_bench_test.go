// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

// BenchmarkUDPReplyDispatcherSubmitDrain measures the steady-state cost of
// dispatching replies across N concurrent endpoints. It guards the bounded
// worker scheduler and per-endpoint queue path against throughput and
// allocation regressions.
func BenchmarkUDPReplyDispatcherSubmitDrain(b *testing.B) {
	cases := []struct {
		endpoints int
		producers int
	}{
		{endpoints: 1, producers: 1},
		{endpoints: 64, producers: 1},
		{endpoints: 64, producers: 8},
		{endpoints: 1024, producers: 8},
	}
	for _, tc := range cases {
		b.Run(fmt.Sprintf("e=%d_p=%d", tc.endpoints, tc.producers), func(b *testing.B) {
			dispatcher := newDefaultUDPReplyDispatcher()
			b.Cleanup(func() {
				dispatcher.close()
				dispatcher.wait()
			})

			endpoints := make([]*UdpEndpoint, tc.endpoints)
			for i := range endpoints {
				endpoints[i] = &UdpEndpoint{}
			}
			task := func() {}

			b.ReportAllocs()
			b.ResetTimer()

			runProducers(b, tc.producers, func(workerID int, op int) {
				ep := endpoints[op%len(endpoints)]
				if !dispatcher.submit(ep, task, nil) {
					b.Fatalf("submit rejected on op %d", op)
				}
			})
		})
	}
}

// BenchmarkUDPOrderedDispatcherSubmitDrain measures the steady-state cost of
// dispatching a high packet rate across N concurrent UDP flows. It compares
// the bounded worker scheduler with the legacy per-flow convoy pool so submit
// and drain overhead remain visible.
func BenchmarkUDPOrderedDispatcherSubmitDrain(b *testing.B) {
	cases := []struct {
		flows     int
		producers int
	}{
		{flows: 1, producers: 1},
		{flows: 64, producers: 1},
		{flows: 64, producers: 8},
		{flows: 1024, producers: 8},
	}
	for _, tc := range cases {
		for _, impl := range []struct {
			name string
			run  func(b *testing.B)
		}{
			{"legacy_pool", benchLegacyUDPPoolSubmitDrain(tc.flows, tc.producers)},
			{"new_dispatcher", benchNewUDPOrderedDispatcherSubmitDrain(tc.flows, tc.producers)},
		} {
			b.Run(fmt.Sprintf("%s/f=%d_p=%d", impl.name, tc.flows, tc.producers), impl.run)
		}
	}
}

func benchLegacyUDPPoolSubmitDrain(flows, producers int) func(*testing.B) {
	return func(b *testing.B) {
		pool := NewUdpTaskPool()
		b.Cleanup(func() { pool.Close() })

		keys := make([]UdpFlowKey, flows)
		for i := range keys {
			keys[i] = UdpFlowKey{
				Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, byte(i >> 8)}), uint16(i&0xffff)),
				Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53),
			}
		}
		task := func() {}

		b.ReportAllocs()
		b.ResetTimer()

		runProducers(b, producers, func(workerID int, op int) {
			key := keys[op%len(keys)]
			if !pool.EmitTask(key, task) {
				b.Fatalf("EmitTask rejected on op %d", op)
			}
		})
	}
}

func benchNewUDPOrderedDispatcherSubmitDrain(flows, producers int) func(*testing.B) {
	return func(b *testing.B) {
		d := newDefaultUDPOrderedDispatcher()
		b.Cleanup(func() {
			d.close()
			d.wait()
		})

		keys := make([]UdpFlowKey, flows)
		for i := range keys {
			keys[i] = UdpFlowKey{
				Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, byte(i >> 8)}), uint16(i&0xffff)),
				Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53),
			}
		}
		task := func() {}

		b.ReportAllocs()
		b.ResetTimer()

		runProducers(b, producers, func(workerID int, op int) {
			key := keys[op%len(keys)]
			if !d.submit(key, task, nil) {
				b.Fatalf("submit rejected on op %d", op)
			}
		})
	}
}

// runProducers distributes b.N operations across `producers` goroutines. Each
// produced task is immediately drainable by the dispatcher workers, so the
// benchmark measures submit+execute throughput rather than queue backlog.
func runProducers(b *testing.B, producers int, emit func(workerID int, op int)) {
	if producers <= 1 {
		for op := range b.N {
			emit(0, op)
		}
		return
	}
	opsPerProducer := b.N / producers
	remainder := b.N % producers
	var wg sync.WaitGroup
	wg.Add(producers)
	for worker := range producers {
		count := opsPerProducer
		if worker == 0 {
			count += remainder
		}
		go func(workerID, count int) {
			defer wg.Done()
			for op := range count {
				emit(workerID, op)
			}
		}(worker, count)
	}
	wg.Wait()
}

// BenchmarkUDPDispatcherClosedCheck isolates the cost of the shutdown-state
// check on the hot path. Before the atomic.Bool conversion the new dispatcher
// took d.mu on every check; the legacy pool used an atomic load. This
// microbenchmark keeps the regression visible without setting up flows.
func BenchmarkUDPDispatcherClosedCheck(b *testing.B) {
	b.Run("legacy_pool/atomic", func(b *testing.B) {
		pool := &UdpTaskPool{}
		_ = pool.closed.Load()
		b.ReportAllocs()
		b.ResetTimer()
		var sink bool
		for range b.N {
			sink = pool.closed.Load()
		}
		_ = sink
	})

	b.Run("new_dispatcher/atomic", func(b *testing.B) {
		d := &udpOrderedDispatcher{}
		_ = d.closed.Load()
		b.ReportAllocs()
		b.ResetTimer()
		var sink bool
		for range b.N {
			sink = d.closed.Load()
		}
		_ = sink
	})

	// Mutex baseline so the atomic conversion stays visibly justified.
	b.Run("mutex_baseline", func(b *testing.B) {
		var mu sync.Mutex
		var closed bool
		b.ReportAllocs()
		b.ResetTimer()
		var sink bool
		for range b.N {
			mu.Lock()
			sink = closed
			mu.Unlock()
		}
		_ = sink
	})
}
