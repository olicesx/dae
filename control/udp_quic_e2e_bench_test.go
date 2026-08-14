// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
)

// udpQuicE2EBenchmarkCases parameterizes the QUIC end-to-end benchmark across
// the cardinalities that matter for ordered-ingress roll-out: a single
// producer pinning one flow at a time, and multiple producers each driving
// their own flows. The fan-out mirrors the production ingress pattern where one
// eBPF callback may submit several QUIC Initials concurrently.
var udpQuicE2EBenchmarkCases = []struct {
	producers int
}{
	{producers: 1},
	{producers: 8},
}

// udpQuicE2EBenchmarkMaxInFlight bounds concurrent QUIC Initial lifecycles so
// neither dispatcher hits its maxPending ceiling; overload policy stays out of
// the comparison, matching the philosophy of udpDispatcherBenchmarkMaxInFlight.
//
// Note: the ordered dispatcher's endpoint-create admission gate
// (defaultUDPOrderedDispatcherMaxCompensatingWorkers = 64) can still saturate
// under high cold-flow concurrency because the simulation's instant dial lets
// producers outrun the compensating-worker retirement. That is an artifact of
// in-memory transport, not a production regression (real dials are
// network-bound and far slower). handlePkt silently drops a packet whose dial
// is rejected (returns nil on errUdpEndpointCreateAdmissionFull), so the
// sanity checks below only assert the path executed at least once rather than
// once per op.
const udpQuicE2EBenchmarkMaxInFlight = udpDispatcherBenchmarkMaxInFlight

// BenchmarkQuicInitialEndToEnd measures the full QUIC Initial lifecycle under
// the production dispatch path:
//
//	submitOrderedUDPIngress -> convoy -> handlePkt -> proxy DialContext ->
//	first-packet WriteTo -> endpoint creation.
//
// It compares the legacy fallback (DefaultUdpTaskPool + per-endpoint reply
// goroutine) against the ordered ingress dispatcher backed by the shared
// udpReplyDispatcher. This is the end-to-end coverage the SLO gate in
// cmd/semantic_refactor_features.go was waiting on: the existing
// BenchmarkUDPOrderedDispatcherSubmitDrain deliberately excludes endpoint
// admission and transport writes, so it could not justify flipping the default.
//
// Each iteration targets a fresh flow (unique source port) so the pool takes
// the cache-miss slow path and actually performs a proxy dial. This mirrors
// the cold-start cost that dominates QUIC Initial handling in production.
//
// In-flight work is bounded by a permit semaphore (mirroring
// runBoundedUDPDispatcherBenchmark) so neither dispatcher hits its
// maxPending ceiling and overload policy stays out of the comparison.
func BenchmarkQuicInitialEndToEnd(b *testing.B) {
	for _, tc := range udpQuicE2EBenchmarkCases {
		for _, impl := range []struct {
			name    string
			ordered bool
		}{
			{name: "legacy_pool", ordered: false},
			{name: "ordered_ingress", ordered: true},
		} {
			b.Run(impl.name, func(b *testing.B) {
				b.Run("p="+strconv.Itoa(tc.producers), func(b *testing.B) {
					runQuicInitialEndToEndBenchmark(b, tc.producers, impl.ordered)
				})
			})
		}
	}
}

func runQuicInitialEndToEndBenchmark(b *testing.B, producers int, ordered bool) {
	restore := setupQuicInitialRegressionTestState(b)
	b.Cleanup(restore)

	var dispatcher *udpOrderedDispatcher
	var reply *udpReplyDispatcher
	if ordered {
		dispatcher = newDefaultUDPOrderedDispatcher()
		reply = newDefaultUDPReplyDispatcher()
		b.Cleanup(func() {
			dispatcher.close()
			dispatcher.wait()
			reply.close()
			reply.wait()
		})
	}

	// A factory dialer mints a fresh simulation conn per dial so each cache-miss
	// flow gets its own transport. Close on one conn must not tear down a
	// sibling that a concurrent lookup might still observe.
	var writeCalls atomic.Int32
	dialer, underlay := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", func() netproxy.Conn {
		return &udpReuseSimulationConn{
			reads:            make(chan scriptedPacketRead, 1),
			closeCh:          make(chan struct{}),
			sharedWriteCalls: &writeCalls,
		}
	})
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(dialer))
	cp.udpOrderedDispatcher = dispatcher
	cp.udpReplyDispatcher = reply

	payload := makeLikelyQuicInitialPayload(0x33)
	// newQuicInitialRegressionFlow asserts the payload classifies as QUIC
	// Initial and returns the canonical src/dst used to prime anyfrom. Its
	// EnsureSnifferSession side effect is harmless: claimFlow re-derives a
	// per-flow decision and session each iteration, so this baseline session is
	// never on the measured path.
	src, dst, _ := newQuicInitialRegressionFlow(b, payload)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	// Prime anyfrom once for the shared source address family. Source ports
	// vary per iteration but the bind address derivation only depends on the
	// address, so a single prime covers all source ports on the same host.
	primeQuicRegressionAnyfrom(src, dst)

	// Endpoints created during the timed region are collected and torn down
	// once measurement stops. The read loop blocks on an empty reads channel
	// until Close signals EOF, so the reply dispatcher's task WaitGroup stays
	// at zero and teardown only needs to wait for read-loop exit.
	var createdMu sync.Mutex
	created := make([]*UdpEndpoint, 0, 1024)
	collectEndpoint := func(decision UdpFlowDecision) {
		ue, ok := DefaultUdpEndpointPool.Get(decision.SymmetricNatEndpointKey())
		if !ok || ue == nil {
			return
		}
		createdMu.Lock()
		created = append(created, ue)
		createdMu.Unlock()
	}
	b.Cleanup(func() {
		createdMu.Lock()
		pending := created
		created = nil
		createdMu.Unlock()
		for _, ue := range pending {
			closeQuicBenchmarkEndpoint(b, ue)
		}
	})

	// flowPort yields a unique source port per operation so each QUIC Initial
	// targets a distinct flow and forces the cache-miss dial path. Starting
	// above the regression-test base port avoids colliding with the primed
	// anyfrom entry.
	flowPort := uint32(src.Port())
	flowAddr := src.Addr()
	// claimFlow re-derives the decision per iteration via ClassifyUdpFlow +
	// EnsureSnifferSession, exactly as control_plane.go's processPacket does for
	// every packet. Reusing a single decision (as an earlier revision did) made
	// every flow share one PacketSnifferKey/session, skipping the per-packet
	// sniffer-classification cost (NewPacketSnifferKey DCID parse, failed-DCID
	// shard probe, EnsureSnifferSession GetOrCreate) that production pays — which
	// understated the measured ns/op by ~16% (legacy) / ~46% (ordered) and
	// inflated the ordered-vs-legacy advantage from ~9% to ~28%.
	claimFlow := func() (netip.AddrPort, UdpFlowDecision) {
		port := atomic.AddUint32(&flowPort, 1)
		flowSrc := netip.AddrPortFrom(flowAddr, uint16(port))
		decision := ClassifyUdpFlow(flowSrc, dst, payload)
		if decision.IsQuicInitial {
			decision = decision.EnsureSnifferSession()
		}
		return flowSrc, decision
	}

	// Permit semaphore bounds in-flight work so neither dispatcher hits its
	// maxPending ceiling nor the ordered dispatcher's endpoint-create admission
	// gate; overload policy stays out of the comparison. Each accepted task
	// returns its permit on completion.
	permits := make(chan struct{}, udpQuicE2EBenchmarkMaxInFlight)
	for range udpQuicE2EBenchmarkMaxInFlight {
		permits <- struct{}{}
	}
	var completed sync.WaitGroup
	completed.Add(b.N)
	var handleErrs atomic.Int32

	// settle releases the permit owned by this op and records completion. It is
	// the shared tail of both the run and discard paths so a rejected submit
	// stays balanced with an accepted one.
	settle := func() {
		permits <- struct{}{}
		completed.Done()
	}

	b.ReportAllocs()
	b.ResetTimer()
	runProducers(b, producers, func(workerID, op int) {
		<-permits
		flowSrc, decision := claimFlow()
		run := func() {
			if err := cp.handlePkt(nil, payload, flowSrc, dst, routingResult, decision, false); err != nil {
				handleErrs.Add(1)
			}
			collectEndpoint(decision)
			settle()
		}
		discard := settle
		if !cp.submitOrderedUDPIngress(decision.Key, udpTaskFunc(run), nil, nil) {
			discard()
			b.Errorf("submitOrderedUDPIngress rejected QUIC Initial under bounded load")
		}
	})
	completed.Wait()
	b.StopTimer()

	// Sanity: every task settled, at least one dial+write landed (proving the
	// full path executed), and no handlePkt reported an error.
	if errs := handleErrs.Load(); errs > 0 {
		b.Fatalf("QUIC e2e handlePkt reported %d errors", errs)
	}
	if got := underlay.calls.Load(); got == 0 {
		b.Fatal("QUIC e2e path did not reach proxy dial")
	}
	if got := writeCalls.Load(); got == 0 {
		b.Fatal("QUIC e2e path did not reach proxy write")
	}
}

func closeQuicBenchmarkEndpoint(tb testing.TB, ue *UdpEndpoint) {
	if ue == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_ = ue.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		tb.Errorf("UdpEndpoint.Close hung during benchmark teardown")
		return
	}
	// Drain the reply runtime's task WaitGroup so its convoy goroutines stop
	// touching global pools before the benchmark swaps them back. Mirrors the
	// regression test's teardown contract.
	if ue.replyRuntime == nil {
		return
	}
	waitDone := make(chan struct{})
	go func() {
		ue.replyRuntime.tasks.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		tb.Errorf("replyRuntime.tasks.Wait hung during benchmark teardown")
	}
}
