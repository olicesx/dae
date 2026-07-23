// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

const udpDispatcherBenchmarkMaxInFlight = UdpTaskQueueLength / 2

// BenchmarkUDPReplyDispatcherSubmitDrain measures completed scheduler work
// across N concurrent endpoints. It does not include endpoint admission or
// transport writes.
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
			runBoundedUDPDispatcherBenchmark(b, tc.producers, func(workerID, localOp int, task UdpTask) bool {
				ep := endpoints[((localOp%len(endpoints))*tc.producers+workerID)%len(endpoints)]
				return dispatcher.submit(ep, task, nil)
			})
		})
	}
}

// BenchmarkUDPOrderedDispatcherSubmitDrain compares completed scheduler work
// under the same bounded in-flight load. It stays below both queue capacities,
// so overload policy is not part of the comparison.
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

		keys := udpDispatcherBenchmarkKeys(flows)
		runBoundedUDPDispatcherBenchmark(b, producers, func(workerID, localOp int, task UdpTask) bool {
			key := keys[udpDispatcherBenchmarkKeyIndex(localOp, workerID, producers, len(keys))]
			return pool.EmitTask(key, task)
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

		keys := udpDispatcherBenchmarkKeys(flows)
		runBoundedUDPDispatcherBenchmark(b, producers, func(workerID, localOp int, task UdpTask) bool {
			key := keys[udpDispatcherBenchmarkKeyIndex(localOp, workerID, producers, len(keys))]
			return d.submit(key, task, nil)
		})
	}
}

func udpDispatcherBenchmarkKeys(flows int) []UdpFlowKey {
	keys := make([]UdpFlowKey, flows)
	for i := range keys {
		keys[i] = UdpFlowKey{
			Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, byte(i >> 8)}), uint16(i&0xffff)),
			Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53),
		}
	}
	return keys
}

func runBoundedUDPDispatcherBenchmark(b *testing.B, producers int, submit func(workerID, localOp int, task UdpTask) bool) {
	permits := make(chan struct{}, udpDispatcherBenchmarkMaxInFlight)
	for range udpDispatcherBenchmarkMaxInFlight {
		permits <- struct{}{}
	}

	var completed sync.WaitGroup
	completed.Add(b.N)
	var rejected atomic.Bool
	task := func() {
		permits <- struct{}{}
		completed.Done()
	}

	b.ReportAllocs()
	b.ResetTimer()
	runProducers(b, producers, func(workerID, localOp int) {
		<-permits
		if submit(workerID, localOp, task) {
			return
		}
		permits <- struct{}{}
		completed.Done()
		rejected.Store(true)
	})
	completed.Wait()
	b.StopTimer()
	if rejected.Load() {
		b.Fatal("bounded benchmark submission was rejected")
	}
}

func udpDispatcherBenchmarkKeyIndex(localOp, workerID, producers, flowCount int) int {
	return ((localOp%flowCount)*producers + workerID) % flowCount
}

// runProducers distributes b.N operations across `producers` goroutines. Each
// task is submitted by exactly one producer and completed by the dispatcher.
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
		if worker < remainder {
			count++
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
