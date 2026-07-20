/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"io"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
)

func makeLikelyQuicInitialPayload(dcidSeed byte) []byte {
	return []byte{
		0xc0,
		0x00, 0x00, 0x00, 0x01,
		0x08,
		dcidSeed, dcidSeed + 1, dcidSeed + 2, dcidSeed + 3,
		dcidSeed + 4, dcidSeed + 5, dcidSeed + 6, dcidSeed + 7,
		0x08,
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x00,
		0x04,
		0x00, 0x00, 0x00, 0x01,
	}
}

func setupQuicInitialRegressionTestState(t *testing.T) func() {
	t.Helper()

	oldUdpPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()

	oldAnyfromPool := DefaultAnyfromPool
	DefaultAnyfromPool = newTestAnyfromPoolWithoutJanitor()

	oldSnifferPool := DefaultPacketSnifferSessionMgr
	DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

	oldFailedCache := getFailedQuicDcidCache()
	SetFailedQuicDcidCache(newFailedQuicDcidCache(failedQuicDcidCacheShardCount))

	return func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldUdpPool

		DefaultAnyfromPool.Reset()
		DefaultAnyfromPool = oldAnyfromPool

		DefaultPacketSnifferSessionMgr.Close()
		DefaultPacketSnifferSessionMgr = oldSnifferPool

		SetFailedQuicDcidCache(oldFailedCache)
	}
}

func newQuicInitialRegressionFlow(t *testing.T, payload []byte) (src, dst netip.AddrPort, decision UdpFlowDecision) {
	t.Helper()

	src = mustParseAddrPort("192.168.89.3:42687")
	dst = mustParseAddrPort("52.199.194.44:443")
	decision = ClassifyUdpFlow(src, dst, payload)
	if !decision.IsQuicInitial {
		t.Fatal("expected test payload to be classified as QUIC Initial")
	}
	return src, dst, decision.EnsureSnifferSession()
}

func primeQuicRegressionAnyfrom(src, dst netip.AddrPort) {
	bindAddr, _ := normalizeSendPktAddrFamily(dst, src)
	af := &Anyfrom{ttl: AnyfromTimeout}
	af.RefreshTtl()

	shard := DefaultAnyfromPool.shardFor(bindAddr)
	shard.mu.Lock()
	shard.pool[anyfromPoolKey{lAddr: bindAddr}] = af
	shard.mu.Unlock()
}

func TestHandlePkt_FailedQuicDcidKeepsExistingDomainlessEndpoint(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	payload := makeLikelyQuicInitialPayload(0x10)
	src, dst, flowDecision := newQuicInitialRegressionFlow(t, payload)
	primeQuicRegressionAnyfrom(src, dst)
	key := flowDecision.SymmetricNatEndpointKey()
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("first handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after first packet = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(key); !ok {
		t.Fatal("expected domain-less UDP endpoint to exist after first packet")
	}

	MarkQuicDcidFailed(NewPacketSnifferKey(src, dst, payload), quicDcidFailureReasonDecryptFailure)

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after failed-DCID reuse = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(key); !ok {
		t.Fatal("expected existing UDP endpoint to survive failed-DCID reuse")
	}
}

func TestHandlePkt_PendingDomainlessEndpointReusesSameQuicInitial(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	payload := makeLikelyQuicInitialPayload(0x18)
	src, dst, flowDecision := newQuicInitialRegressionFlow(t, payload)
	primeQuicRegressionAnyfrom(src, dst)
	key := flowDecision.SymmetricNatEndpointKey()
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("first handlePkt: %v", err)
	}
	ueBefore, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ueBefore == nil {
		t.Fatal("expected domain-less UDP endpoint after first packet")
	}
	if ueBefore.hasReply.Load() {
		t.Fatal("expected endpoint to remain probing before any reply")
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after repeated QUIC Initial = %d, want 1", got)
	}
	if got := conn.writeCalls.Load(); got != 2 {
		t.Fatalf("WriteTo calls after repeated QUIC Initial = %d, want 2", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled udp endpoints after repeated QUIC Initial = %d, want 1", got)
	}

	ueAfter, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ueAfter == nil {
		t.Fatal("expected existing UDP endpoint after repeated QUIC Initial")
	}
	if ueAfter != ueBefore {
		t.Fatal("expected repeated QUIC Initial to reuse the probing endpoint")
	}
	if got := countPooledPacketSniffers(DefaultPacketSnifferSessionMgr); got != 1 {
		t.Fatalf("pooled packet sniffers after repeated QUIC Initial = %d, want 1", got)
	}
}

func TestHandlePkt_ActiveQuicSnifferMismatchResetsDomainlessEndpoint(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	var totalWriteCalls atomic.Int32
	d, underlay := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", func() netproxy.Conn {
		return &udpReuseSimulationConn{
			reads:            make(chan scriptedPacketRead),
			closeCh:          make(chan struct{}),
			sharedWriteCalls: &totalWriteCalls,
		}
	})
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	firstPayload := makeLikelyQuicInitialPayload(0x28)
	secondPayload := makeLikelyQuicInitialPayload(0x38)
	src, dst, firstDecision := newQuicInitialRegressionFlow(t, firstPayload)
	primeQuicRegressionAnyfrom(src, dst)
	key := firstDecision.SymmetricNatEndpointKey()
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, firstPayload, src, dst, routingResult, firstDecision, false); err != nil {
		t.Fatalf("handlePkt(first): %v", err)
	}
	ueBefore, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ueBefore == nil {
		t.Fatal("expected domain-less UDP endpoint after first QUIC Initial")
	}

	secondDecision := ClassifyUdpFlow(src, dst, secondPayload).EnsureSnifferSession()
	if !secondDecision.IsQuicInitial {
		t.Fatal("expected second payload to stay on QUIC Initial path")
	}
	if err := cp.handlePkt(nil, secondPayload, src, dst, routingResult, secondDecision, false); err != nil {
		t.Fatalf("handlePkt(second): %v", err)
	}
	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls after QUIC Initial mismatch = %d, want 2", got)
	}
	if got := totalWriteCalls.Load(); got != 2 {
		t.Fatalf("WriteTo calls after QUIC Initial mismatch = %d, want 2", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled udp endpoints after QUIC Initial mismatch = %d, want 1", got)
	}

	ueAfter, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ueAfter == nil {
		t.Fatal("expected rebuilt UDP endpoint after QUIC Initial mismatch")
	}
	if ueAfter == ueBefore {
		t.Fatal("expected flow-family mismatch to rebuild the probing endpoint")
	}
	if got := countPooledPacketSniffers(DefaultPacketSnifferSessionMgr); got != 1 {
		t.Fatalf("pooled packet sniffers after QUIC Initial mismatch = %d, want 1", got)
	}
	if stale := DefaultPacketSnifferSessionMgr.Get(NewPacketSnifferKey(src, dst, firstPayload)); stale != nil {
		t.Fatal("expected stale flow-family sniffer session to be removed")
	}
	if fresh := DefaultPacketSnifferSessionMgr.Get(NewPacketSnifferKey(src, dst, secondPayload)); fresh == nil {
		t.Fatal("expected current QUIC Initial sniffer session to remain active")
	}
}

func TestHandlePkt_EstablishedDomainlessEndpointSurvivesQuicInitialHeuristic(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	payload := makeLikelyQuicInitialPayload(0x20)
	src, dst, flowDecision := newQuicInitialRegressionFlow(t, payload)
	primeQuicRegressionAnyfrom(src, dst)
	key := flowDecision.SymmetricNatEndpointKey()
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("first handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after first packet = %d, want 1", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected pooled endpoint after first packet")
	}
	ue.markReplied(0)
	if !ue.hasReply.Load() {
		t.Fatal("expected endpoint to enter established state after upstream reply")
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after established reuse = %d, want 1", got)
	}
	if got := conn.writeCalls.Load(); got != 2 {
		t.Fatalf("WriteTo calls after reuse = %d, want 2", got)
	}
}

func TestHandlePkt_NonSniffPortBypassesInitialShapedPayload(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	conn := &udpReuseSimulationConn{
		reads:      make(chan scriptedPacketRead, 4),
		readExitCh: make(chan error, 1),
		closeCh:    make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	fullConeKey := UdpEndpointKey{Src: src}
	symmetricKey := UdpEndpointKey{Src: src, Dst: dst}
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	primeQuicRegressionAnyfrom(src, dst)

	gamePayload := []byte{0x10, 0x20, 0x30, 0x40}
	gameDecision := ClassifyUdpFlow(src, dst, gamePayload)
	if gameDecision.IsQuicInitial {
		t.Fatal("expected game payload to avoid QUIC Initial classification")
	}
	if err := cp.handlePkt(nil, gamePayload, src, dst, routingResult, gameDecision, false); err != nil {
		t.Fatalf("handlePkt(game): %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after initial game packet = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(fullConeKey); !ok {
		t.Fatal("expected pooled full-cone endpoint after initial game packet")
	}

	ue, ok := DefaultUdpEndpointPool.Get(fullConeKey)
	if !ok || ue == nil {
		t.Fatal("expected full-cone endpoint before simulating established state")
	}
	ue.markReplied(0)
	if !ue.hasReply.Load() {
		t.Fatal("expected full-cone endpoint to become established after reply promotion")
	}

	initialLikePayload := makeLikelyQuicInitialPayload(0x42)
	initialLikeDecision := ClassifyUdpFlow(src, dst, initialLikePayload)
	if initialLikeDecision.IsQuicInitial {
		t.Fatal("expected non-sniff port to bypass QUIC Initial classification")
	}
	if initialLikeDecision.HasSnifferSession {
		t.Fatal("expected non-sniff port to avoid creating a sniffer session")
	}
	if err := cp.handlePkt(nil, initialLikePayload, src, dst, routingResult, initialLikeDecision, false); err != nil {
		t.Fatalf("handlePkt(Initial-shaped payload on non-sniff port): %v", err)
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after Initial-shaped payload on non-sniff port = %d, want 1", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled udp endpoints after Initial-shaped payload on non-sniff port = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(fullConeKey); !ok {
		t.Fatal("expected existing full-cone endpoint to be reused on non-sniff port")
	}
	if _, ok := DefaultUdpEndpointPool.Get(symmetricKey); ok {
		t.Fatal("expected non-sniff port to avoid creating a symmetric endpoint")
	}
	if got := countPooledPacketSniffers(DefaultPacketSnifferSessionMgr); got != 0 {
		t.Fatalf("pooled packet sniffers after non-sniff-port Initial-shaped payload = %d, want 0", got)
	}
}

func TestHandlePkt_NonSniffPortInitialShapedPayloadKeepsFullConeReuse(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	conn := &udpReuseSimulationConn{
		reads:      make(chan scriptedPacketRead, 4),
		readExitCh: make(chan error, 1),
		closeCh:    make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src := mustParseAddrPort("192.168.89.3:42688")
	dst := mustParseAddrPort("52.199.194.44:23003")
	fullConeKey := UdpEndpointKey{Src: src}
	symmetricKey := UdpEndpointKey{Src: src, Dst: dst}
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	primeQuicRegressionAnyfrom(src, dst)

	initialLikePayload := makeLikelyQuicInitialPayload(0x52)
	initialLikeDecision := ClassifyUdpFlow(src, dst, initialLikePayload)
	if initialLikeDecision.IsQuicInitial {
		t.Fatal("expected non-sniff port to bypass QUIC Initial classification")
	}
	if err := cp.handlePkt(nil, initialLikePayload, src, dst, routingResult, initialLikeDecision, false); err != nil {
		t.Fatalf("handlePkt(Initial-shaped payload on non-sniff port): %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after Initial-shaped payload on non-sniff port = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(fullConeKey); !ok {
		t.Fatal("expected Initial-shaped payload on non-sniff port to create a full-cone endpoint")
	}
	if _, ok := DefaultUdpEndpointPool.Get(symmetricKey); ok {
		t.Fatal("expected non-sniff port to avoid creating a symmetric endpoint")
	}
	if got := countPooledPacketSniffers(DefaultPacketSnifferSessionMgr); got != 0 {
		t.Fatalf("pooled packet sniffers after Initial-shaped payload on non-sniff port = %d, want 0", got)
	}

	ordinaryPayload := []byte{0x10, 0x20, 0x30, 0x40}
	ordinaryDecision := ClassifyUdpFlow(src, dst, ordinaryPayload)
	if ordinaryDecision.IsQuicInitial {
		t.Fatal("expected ordinary sibling packet to avoid QUIC Initial classification")
	}
	if ordinaryDecision.HasSnifferSession {
		t.Fatal("expected non-sniff port sibling packet to avoid sniffer state")
	}
	if err := cp.handlePkt(nil, ordinaryPayload, src, dst, routingResult, ordinaryDecision, false); err != nil {
		t.Fatalf("handlePkt(ordinary sibling): %v", err)
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after ordinary sibling reuse = %d, want 1", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled udp endpoints after ordinary sibling reuse = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(fullConeKey); !ok {
		t.Fatal("expected existing full-cone endpoint to be reused")
	}
	if _, ok := DefaultUdpEndpointPool.Get(symmetricKey); ok {
		t.Fatal("expected ordinary sibling packet to avoid creating a symmetric endpoint")
	}
}

// TestQuicInitial_FlowsThroughBothNewDispatchers end-to-end regression-tests
// the full production QUIC path after the lock-free dispatcher rewrite:
//
//  1. QUIC Initial submitted via submitOrderedUDPIngress (the real ingress
//     path used when SemanticRefactorFeatureUDPOrderedDispatcher is on).
//  2. The ordered dispatcher convoy runs the task, which calls handlePkt.
//  3. handlePkt dials the proxy, creates a UdpEndpoint whose replyRuntime
//     is backed by the new udpReplyDispatcher.
//  4. A reply is pushed through the proxy conn's read channel.
//  5. The reply flows back through the udpReplyDispatcher convoy → handler.
//  6. Endpoint close completes without hanging (regression-tests the
//     releaseAndCleanup discard-leak fix that was breaking QUIC under
//     repeated endpoint churn).
//
// This closes the coverage gap left by the existing QUIC corpus tests (which
// call handlePkt directly, bypassing the dispatcher) and the dispatcher unit
// tests (which don't exercise handlePkt at all).
func TestQuicInitial_FlowsThroughBothNewDispatchers(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead, 2),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)

	// Build a ControlPlane that matches production defaults: both UDP
	// dispatchers enabled, just like defaultSemanticRefactorFeatures() does.
	ordered := newDefaultUDPOrderedDispatcher()
	reply := newDefaultUDPReplyDispatcher()
	t.Cleanup(func() {
		ordered.close()
		ordered.wait()
		reply.close()
		reply.wait()
	})
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	cp.udpOrderedDispatcher = ordered
	cp.udpReplyDispatcher = reply

	payload := makeLikelyQuicInitialPayload(0x33)
	src, dst, flowDecision := newQuicInitialRegressionFlow(t, payload)
	primeQuicRegressionAnyfrom(src, dst)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	// Submit the QUIC Initial through the real ordered-ingress path. This is
	// the exact code path control_plane.go Serve() takes for QUIC traffic.
	task := func() {
		if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
			t.Errorf("handlePkt through ordered dispatcher: %v", err)
		}
	}
	if !cp.submitOrderedUDPIngress(flowDecision.Key, task, nil) {
		t.Fatal("submitOrderedUDPIngress rejected QUIC Initial task")
	}

	// Wait for the ordered-dispatcher convoy to run the task. The task dials
	// the proxy and then synchronously writes the QUIC Initial to it, so both
	// counters must reach 1. If the dispatcher dropped the task or deadlocked,
	// this times out.
	deadline := time.Now().Add(3 * time.Second)
	for (underlay.calls.Load() == 0 || conn.writeCalls.Load() == 0) && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("proxy DialContext calls = %d, want 1 (ordered dispatcher did not deliver task to handlePkt)", got)
	}
	if got := conn.writeCalls.Load(); got != 1 {
		t.Fatalf("proxy WriteTo calls = %d, want 1 (QUIC Initial not forwarded to proxy)", got)
	}

	// Grab the endpoint that handlePkt created and verify its replyRuntime is
	// backed by the new udpReplyDispatcher (not the legacy per-endpoint sender).
	key := flowDecision.SymmetricNatEndpointKey()
	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected QUIC endpoint to exist after handlePkt through dispatcher")
	}
	if ue.replyRuntime == nil || ue.replyRuntime.dispatcher != reply {
		t.Fatal("expected QUIC endpoint replyRuntime to use the new udpReplyDispatcher")
	}

	// Inject a proxy reply. The endpoint read loop should receive it and
	// dispatch it through udpReplyDispatcher → handler.
	replyPayload := []byte("quic-reply-from-proxy")
	replyFrom := mustParseAddrPort("52.199.194.44:443")
	conn.reads <- scriptedPacketRead{data: replyPayload, from: replyFrom}

	// Wait for the reply dispatcher convoy to run the handler. hasReply is set
	// by the read loop BEFORE submitReply, so we also need to confirm the
	// dispatcher actually processed the task by waiting for the tasks WG to
	// drain. If releaseAndCleanup leaked a slot/WG, this Wait would hang.
	deadline = time.Now().Add(3 * time.Second)
	for !ue.hasReply.Load() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if !ue.hasReply.Load() {
		t.Fatal("endpoint hasReply = false after proxy reply (read loop did not process reply)")
	}

	// Signal end-of-stream so the read loop exits and the endpoint's close
	// path runs. This exercises releaseAndCleanup (discard-leak fix).
	conn.reads <- scriptedPacketRead{err: io.EOF}

	// If releaseAndCleanup leaked the tasks WaitGroup, Close would hang here
	// because the read loop's defer calls closeInputAndWait which blocks on
	// runtime.tasks.Wait(). This is the core QUIC-breakage regression: after
	// enough leaked endpoints, the pool exhausts and new QUIC flows fail.
	closeDone := make(chan struct{})
	go func() {
		_ = ue.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("UdpEndpoint.Close hung — udpReplyDispatcher.releaseAndCleanup is leaking task bookkeeping (discard-leak regression)")
	}

	// Wait for all reply-dispatcher tasks to finish so their goroutines stop
	// touching global pools (DefaultAnyfromPool etc.) before the test
	// cleanup swaps those globals back. Without this, the race detector
	// flags a read in the convoy goroutine racing with the cleanup write.
	deadline = time.Now().Add(3 * time.Second)
	for ue.replyRuntime != nil && !ue.dead.Load() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	// Drain any remaining in-flight reply task by waiting on the runtime's
	// task WaitGroup. This is safe because Close already ran and the read
	// loop's closeInputAndWait has drained accepted replies.
	if ue.replyRuntime != nil {
		waitDone := make(chan struct{})
		go func() {
			ue.replyRuntime.tasks.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(3 * time.Second):
			t.Fatal("replyRuntime.tasks.Wait hung — dispatcher leaked a task WaitGroup ticket")
		}
	}
}
