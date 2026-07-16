/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func TestControlPlaneDrainTrackerAcquireRelease(t *testing.T) {
	tracker := newControlPlaneDrainTracker()
	if tracker.Count() != 0 {
		t.Fatalf("initial Count() = %d, want 0", tracker.Count())
	}

	releaseA := tracker.Acquire()
	releaseB := tracker.Acquire()
	if tracker.Count() != 2 {
		t.Fatalf("Count() after acquire = %d, want 2", tracker.Count())
	}

	releaseA()
	if tracker.Count() != 1 {
		t.Fatalf("Count() after first release = %d, want 1", tracker.Count())
	}

	select {
	case <-tracker.IdleCh():
		t.Fatal("idle channel closed while tracker still has active sessions")
	default:
	}

	releaseB()
	if tracker.Count() != 0 {
		t.Fatalf("Count() after second release = %d, want 0", tracker.Count())
	}

	select {
	case <-tracker.IdleCh():
	default:
		t.Fatal("idle channel should be closed after all sessions release")
	}
}

func TestUdpEndpointAdoptGenerationTransfersDrainOwnership(t *testing.T) {
	oldTracker := newControlPlaneDrainTracker()
	newTracker := newControlPlaneDrainTracker()
	ue := &UdpEndpoint{
		drainTracker: oldTracker,
		drainRelease: oldTracker.Acquire(),
	}

	if oldTracker.Count() != 1 {
		t.Fatalf("oldTracker Count() = %d, want 1", oldTracker.Count())
	}

	ue.adoptGeneration(nil, newTracker)

	if oldTracker.Count() != 0 {
		t.Fatalf("oldTracker Count() after adoption = %d, want 0", oldTracker.Count())
	}
	if newTracker.Count() != 1 {
		t.Fatalf("newTracker Count() after adoption = %d, want 1", newTracker.Count())
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if newTracker.Count() != 0 {
		t.Fatalf("newTracker Count() after close = %d, want 0", newTracker.Count())
	}
}

func TestControlPlaneAbortConnectionsRejectsNewConnections(t *testing.T) {
	cp := &ControlPlane{}

	connA, peerA := net.Pipe()
	defer func() { _ = peerA.Close() }()
	if !cp.registerIncomingConnection(connA) {
		t.Fatal("registerIncomingConnection() = false, want true before abort")
	}

	if err := cp.AbortConnections(); err != nil {
		t.Fatalf("AbortConnections() error = %v", err)
	}
	if _, err := peerA.Write([]byte("x")); err == nil {
		t.Fatal("expected tracked connection to be closed by AbortConnections")
	}

	connB, peerB := net.Pipe()
	defer func() { _ = peerB.Close() }()
	if cp.registerIncomingConnection(connB) {
		t.Fatal("registerIncomingConnection() = true, want false after abort")
	}
	if _, err := peerB.Write([]byte("x")); err == nil {
		t.Fatal("expected newly registered connection to be rejected after abort")
	}
}

func TestControlPlaneAbortConnectionsClosesOnlyOwnedUdpEndpoints(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	pool := NewUdpEndpointPool()
	DefaultUdpEndpointPool = pool
	t.Cleanup(func() {
		pool.Close()
		DefaultUdpEndpointPool = oldPool
	})

	owner := &controlPlaneCore{}
	otherOwner := &controlPlaneCore{}
	plane := &ControlPlane{core: owner}

	newEndpoint := func(key UdpEndpointKey, endpointOwner udpConnStateOwner) (*UdpEndpoint, *scriptedPacketConn) {
		conn := &scriptedPacketConn{
			reads:   make(chan scriptedPacketRead),
			closeCh: make(chan struct{}),
		}
		endpoint := &UdpEndpoint{
			conn:              conn,
			NatTimeout:        DefaultNatTimeout,
			handler:           func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
			poolRef:           pool,
			poolKey:           key,
			udpConnStateOwner: endpointOwner,
		}
		endpoint.expiresAtNano.Store(time.Now().Add(time.Hour).UnixNano())
		shard := pool.shardFor(key)
		shard.mu.Lock()
		shard.pool[key] = endpoint
		shard.mu.Unlock()
		return endpoint, conn
	}

	ownedKey := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:41000")}
	foreignKey := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.11:41001")}
	owned, ownedConn := newEndpoint(ownedKey, owner)
	foreign, foreignConn := newEndpoint(foreignKey, otherOwner)

	if err := plane.AbortConnections(); err != nil {
		t.Fatalf("AbortConnections() error = %v", err)
	}
	if !owned.IsDead() {
		t.Fatal("expected old-generation UDP endpoint to be retired")
	}
	if _, ok := pool.Get(ownedKey); ok {
		t.Fatal("expected old-generation UDP endpoint to be removed from the pool")
	}
	waitForCloseSignal(t, ownedConn.closeCh, "AbortConnections closes old-generation UDP endpoint")

	if foreign.IsDead() {
		t.Fatal("unexpected retirement of endpoint owned by another generation")
	}
	if got, ok := pool.Get(foreignKey); !ok || got != foreign {
		t.Fatalf("foreign endpoint after AbortConnections() = (%v, %v), want retained endpoint", got, ok)
	}
	select {
	case <-foreignConn.closeCh:
		t.Fatal("unexpected close of endpoint owned by another generation")
	default:
	}
}

func TestControlPlaneAbortConnectionsWaitsForInflightUdpEndpointCreation(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	pool := NewUdpEndpointPool()
	DefaultUdpEndpointPool = pool
	t.Cleanup(func() {
		pool.Close()
		DefaultUdpEndpointPool = oldPool
	})

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	d, underlay := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", func() netproxy.Conn {
		close(dialStarted)
		<-releaseDial
		return conn
	})
	owner := &controlPlaneCore{}
	plane := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	plane.core = owner
	plane.ctx = context.Background()

	src := netip.MustParseAddrPort("192.0.2.20:42000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	payload := []byte{0x01, 0x02, 0x03}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.EndpointKeyForDialWithScope("", udpEndpointRouteScope{}, false)
	routingResult := &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin)}

	handleDone := make(chan error, 1)
	go func() {
		handleDone <- plane.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false)
	}()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for UDP endpoint creation to begin")
	}

	abortDone := make(chan error, 1)
	go func() {
		abortDone <- plane.AbortConnections()
	}()
	waitForCondition(t, time.Second, "UDP endpoint admission to close", func() bool {
		return plane.udpEndpointAdmission.closed.Load()
	})
	select {
	case err := <-abortDone:
		t.Fatalf("AbortConnections returned before in-flight creation completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseDial)
	select {
	case err := <-handleDone:
		if err != nil {
			t.Fatalf("handlePkt() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for in-flight UDP endpoint creation")
	}
	select {
	case err := <-abortDone:
		if err != nil {
			t.Fatalf("AbortConnections() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for AbortConnections")
	}

	if _, ok := pool.Get(key); ok {
		t.Fatal("expected endpoint created during abort to be removed from the pool")
	}
	waitForCloseSignal(t, conn.closeCh, "AbortConnections closes in-flight created UDP endpoint")
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("dial calls after abort = %d, want 1", got)
	}

	if err := plane.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt() after abort error = %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("dial calls after abort admission rejection = %d, want 1", got)
	}
}

func TestControlPlaneReleaseRetainedStateClosesDnsHandoffController(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	janitorStop := make(chan struct{})
	janitorDone := make(chan struct{})
	evictorDone := make(chan struct{})
	close(janitorDone)
	close(evictorDone)

	controller := &DnsController{
		dnsControllerStore: &dnsControllerStore{
			janitorStop: janitorStop,
			janitorDone: janitorDone,
			evictorDone: evictorDone,
		},
	}
	cp := &ControlPlane{
		ctx: ctx,
	}
	cp.EnableDNSHandoff(controller, time.Hour)
	cp.releaseRetainedState()

	select {
	case <-janitorStop:
	case <-time.After(time.Second):
		t.Fatal("expected releaseRetainedState to close handoff controller")
	}
	if got := cp.dnsHandoffController.Load(); got != nil {
		t.Fatalf("dnsHandoffController = %v, want nil", got)
	}
}

func TestControlPlaneReleaseRetainedStateKeepsSharedDnsHandoffControllerAlive(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	janitorStop := make(chan struct{})
	janitorDone := make(chan struct{})
	evictorDone := make(chan struct{})
	close(janitorDone)
	close(evictorDone)

	oldController := &DnsController{
		dnsControllerStore: &dnsControllerStore{
			janitorStop: janitorStop,
			janitorDone: janitorDone,
			evictorDone: evictorDone,
		},
	}
	oldCP := &ControlPlane{
		log: logger,
		ctx: context.Background(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: oldController,
		},
	}
	newCP := &ControlPlane{
		log: logger,
		ctx: context.Background(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: &DnsController{},
			dnsRouting:    &dns.Dns{},
		},
	}

	if !newCP.ReuseDNSControllerFrom(oldCP) {
		t.Fatal("ReuseDNSControllerFrom() = false, want true")
	}

	oldCP.releaseRetainedState()

	select {
	case <-janitorStop:
		t.Fatal("expected releaseRetainedState to keep shared handoff controller alive")
	default:
	}
	if oldCP.ActiveDnsController() != nil {
		t.Fatal("expected old control plane to clear handoff pointer on release")
	}

	if err := newCP.dnsController.Close(); err != nil {
		t.Fatalf("shared dns controller Close() error = %v", err)
	}
	select {
	case <-janitorStop:
	case <-time.After(time.Second):
		t.Fatal("expected shared dns controller to close when owned controller closes")
	}
}

func TestCommitPreparedDatapathStartsConnStateJanitor(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cp := &ControlPlane{
		log:                    logger,
		ctx:                    ctx,
		preparedDatapathCommit: true,
		controlPlaneDatapathJanitor: controlPlaneDatapathJanitor{
			connStateJanitorStop: make(chan struct{}),
			connStateJanitorDone: make(chan struct{}),
		},
	}

	if cp.connStateJanitorStarted.Load() {
		t.Fatal("expected conn-state janitor to start disabled")
	}

	if err := cp.CommitPreparedDatapath(); err != nil {
		t.Fatalf("CommitPreparedDatapath() error = %v", err)
	}
	if !cp.connStateJanitorStarted.Load() {
		t.Fatal("expected CommitPreparedDatapath to start conn-state janitor")
	}
	if cp.preparedDatapathCommit {
		t.Fatal("expected preparedDatapathCommit to be cleared after commit")
	}

	cp.stopConnStateJanitor()
}

func TestStartPreparedDNSListenerOnlyRunsWhenDeferred(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	cp := &ControlPlane{
		log: logger,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsListener: &DNSListener{
				log: logger,
			},
		},
	}

	if err := cp.StartPreparedDNSListener(); err != nil {
		t.Fatalf("StartPreparedDNSListener() without deferred flag error = %v", err)
	}
	if cp.dnsListenerStopRegistered {
		t.Fatal("expected StartPreparedDNSListener to no-op when deferred flag is false")
	}

	cp.delayDNSListenerStart = true
	if err := cp.StartPreparedDNSListener(); err != nil {
		t.Fatalf("StartPreparedDNSListener() with deferred flag error = %v", err)
	}
	if cp.delayDNSListenerStart {
		t.Fatal("expected deferred DNS listener flag to be cleared")
	}
	if !cp.dnsListenerStopRegistered {
		t.Fatal("expected DNS listener stop hook to be registered after deferred start")
	}
}

func TestStartPreparedDNSListenerRunsCutoverHook(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	var hookCalls atomic.Int32
	cp := &ControlPlane{
		log: logger,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsListener: &DNSListener{
				log: logger,
			},
			delayDNSListenerStart: true,
			preparedDNSStartHook: func() error {
				hookCalls.Add(1)
				return nil
			},
		},
	}

	if err := cp.StartPreparedDNSListener(); err != nil {
		t.Fatalf("StartPreparedDNSListener() error = %v", err)
	}
	if hookCalls.Load() != 1 {
		t.Fatalf("preparedDNSStartHook calls = %d, want 1", hookCalls.Load())
	}
	if cp.preparedDNSStartHook != nil {
		t.Fatal("expected preparedDNSStartHook to be cleared after execution")
	}
}

func TestStartPreparedDNSListenerWaitsForDNSAvailabilityBeforeReuseHook(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	reuseCalled := make(chan struct{})
	cp := &ControlPlane{
		log: logger,
		ctx: context.Background(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsUpstreamAvailable:  make(chan struct{}),
			delayDNSListenerStart: true,
			preparedDNSReuseHook: func() error {
				close(reuseCalled)
				return nil
			},
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- cp.StartPreparedDNSListener()
	}()

	select {
	case <-reuseCalled:
		t.Fatal("expected DNS reuse hook to wait for upstream availability")
	case <-time.After(20 * time.Millisecond):
	}

	close(cp.dnsUpstreamAvailable)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StartPreparedDNSListener() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected StartPreparedDNSListener to finish after upstream availability")
	}

	select {
	case <-reuseCalled:
	default:
		t.Fatal("expected DNS reuse hook to run after upstream availability")
	}
}

func TestStartPreparedDNSListenerAbortsCutoverWhenUpstreamUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var reuseCalls atomic.Int32
	var startCalls atomic.Int32
	cp := &ControlPlane{
		ctx: ctx,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsUpstreamAvailable:  make(chan struct{}),
			delayDNSListenerStart: true,
			preparedDNSReuseHook: func() error {
				reuseCalls.Add(1)
				return nil
			},
			preparedDNSStartHook: func() error {
				startCalls.Add(1)
				return nil
			},
		},
	}

	err := cp.StartPreparedDNSListener()
	if !stderrors.Is(err, context.Canceled) {
		t.Fatalf("StartPreparedDNSListener() error = %v, want context canceled", err)
	}
	if reuseCalls.Load() != 0 || startCalls.Load() != 0 {
		t.Fatalf("prepared DNS hooks ran after warmup failure: reuse=%d start=%d", reuseCalls.Load(), startCalls.Load())
	}
	if !cp.delayDNSListenerStart {
		t.Fatal("prepared DNS listener started after warmup failure")
	}
	if cp.dnsListenerStopRegistered {
		t.Fatal("prepared DNS listener registered cleanup after warmup failure")
	}
}

func TestStartPreparedDNSListenerAbortsCutoverOnUpstreamAvailabilityTimeout(t *testing.T) {
	var reuseCalls atomic.Int32
	var startCalls atomic.Int32
	cp := &ControlPlane{
		ctx: context.Background(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsUpstreamAvailable:  make(chan struct{}),
			delayDNSListenerStart: true,
			preparedDNSReuseHook: func() error {
				reuseCalls.Add(1)
				return nil
			},
			preparedDNSStartHook: func() error {
				startCalls.Add(1)
				return nil
			},
		},
	}

	err := cp.startPreparedDNSListenerWithWarmupTimeout(context.Background(), nil, &cp.deferFuncs, nil, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "dns upstream availability timed out") {
		t.Fatalf("startPreparedDNSListenerWithWarmupTimeout() error = %v, want availability timeout", err)
	}
	if reuseCalls.Load() != 0 || startCalls.Load() != 0 {
		t.Fatalf("prepared DNS hooks ran after warmup timeout: reuse=%d start=%d", reuseCalls.Load(), startCalls.Load())
	}
	if !cp.delayDNSListenerStart || cp.dnsListenerStopRegistered {
		t.Fatalf("prepared DNS listener state after warmup timeout = (delayed=%v cleanup=%v), want unchanged", cp.delayDNSListenerStart, cp.dnsListenerStopRegistered)
	}
}

func TestStartPreparedDNSListenerAllowsAvailableListenerReuse(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCP := &ControlPlane{log: logger}
	listener := &DNSListener{log: logger, endpoint: Endpoint{UDP: true, Addr: "0.0.0.0:53"}}
	listener.SwapController(oldCP)
	oldCP.dnsListener = listener

	var startCalls atomic.Int32
	newCP := &ControlPlane{
		log: logger,
		ctx: context.Background(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsListener:           &DNSListener{log: logger, endpoint: Endpoint{UDP: true, Addr: "0.0.0.0:53"}},
			dnsUpstreamAvailable:  make(chan struct{}),
			delayDNSListenerStart: true,
		},
	}
	close(newCP.dnsUpstreamAvailable)
	newCP.preparedDNSReuseHook = func() error {
		if !newCP.ReuseDNSListenerFrom(oldCP) {
			return stderrors.New("reuse DNS listener")
		}
		return nil
	}
	newCP.preparedDNSStartHook = func() error {
		startCalls.Add(1)
		return nil
	}

	if err := newCP.StartPreparedDNSListener(); err != nil {
		t.Fatalf("StartPreparedDNSListener() error = %v", err)
	}
	if oldCP.dnsListener != nil || newCP.dnsListener != listener {
		t.Fatal("available prepared DNS listener reuse did not transfer ownership")
	}
	if newCP.delayDNSListenerStart {
		t.Fatal("available prepared DNS listener reuse left delayed start enabled")
	}
	if !newCP.dnsListenerStopRegistered {
		t.Fatal("available prepared DNS listener reuse did not register cleanup")
	}
	if startCalls.Load() != 0 {
		t.Fatalf("prepared DNS start hook calls = %d, want 0 after listener reuse", startCalls.Load())
	}
}

func TestReuseDNSListenerFromTransfersOwnership(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCP := &ControlPlane{log: logger}
	newCP := &ControlPlane{
		log: logger,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsListener:           &DNSListener{log: logger, endpoint: Endpoint{UDP: true, Addr: "0.0.0.0:53"}},
			delayDNSListenerStart: true,
		},
	}
	listener := &DNSListener{log: logger, endpoint: Endpoint{UDP: true, Addr: "0.0.0.0:53"}}
	listener.SwapController(oldCP)
	oldCP.dnsListener = listener

	if !newCP.ReuseDNSListenerFrom(oldCP) {
		t.Fatal("ReuseDNSListenerFrom() = false, want true")
	}
	if oldCP.dnsListener != nil {
		t.Fatal("expected old control plane to detach DNS listener")
	}
	if newCP.dnsListener != listener {
		t.Fatal("expected new control plane to own transferred DNS listener")
	}
	if listener.Controller() != newCP {
		t.Fatal("expected transferred DNS listener to point at new control plane")
	}
	if newCP.delayDNSListenerStart {
		t.Fatal("expected DNS listener reuse to clear delayed start flag")
	}
}

func TestReuseDNSListenerFromRejectsProtocolMismatch(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCP := &ControlPlane{
		log: logger,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsListener: &DNSListener{log: logger, endpoint: Endpoint{UDP: true, Addr: "0.0.0.0:53"}},
		},
	}
	newCP := &ControlPlane{
		log: logger,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsListener:           &DNSListener{log: logger, endpoint: Endpoint{TCP: true, UDP: true, Addr: "0.0.0.0:53"}},
			delayDNSListenerStart: true,
		},
	}

	if newCP.ReuseDNSListenerFrom(oldCP) {
		t.Fatal("ReuseDNSListenerFrom() = true, want false for protocol mismatch")
	}
	if oldCP.dnsListener == nil {
		t.Fatal("expected previous DNS listener to remain owned by old control plane")
	}
}

func TestReuseDNSControllerFromUpdatesRuntime(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldController := &DnsController{}
	oldCP := &ControlPlane{
		log: logger,
		ctx: context.Background(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: oldController,
		},
	}
	newCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newRouting := &dns.Dns{}
	newCP := &ControlPlane{
		log: logger,
		ctx: newCtx,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: &DnsController{},
			dnsRouting:    newRouting,
			dnsFixedDomainTtl: map[string]int{
				"example.com": 60,
			},
		},
	}

	if !newCP.ReuseDNSControllerFrom(oldCP) {
		t.Fatal("ReuseDNSControllerFrom() = false, want true")
	}
	if oldCP.dnsController != nil {
		t.Fatal("expected previous control plane to detach DNS controller")
	}
	if newCP.dnsController == oldController {
		t.Fatal("expected new control plane to bind a fresh DNS facade instead of reusing the same controller object")
	}
	if oldCP.ActiveDnsController() != newCP.dnsController {
		t.Fatal("expected previous control plane to hand off active DNS controller without a nil gap")
	}
	if !oldCP.SharesActiveDnsControllerWith(newCP) {
		t.Fatal("expected old and new control planes to share the active DNS controller after reuse")
	}
	if newCP.dnsController.dnsControllerStore != oldController.dnsControllerStore {
		t.Fatal("expected reused DNS controller facade to share the original DNS store")
	}

	rt := newCP.dnsController.runtime()
	if rt == nil {
		t.Fatal("expected reused DNS controller runtime to be configured")
		return
	}
	if rt.routing != newRouting {
		t.Fatal("expected reused DNS controller runtime to use new routing")
	}
	if rt.lifecycleCtx != newCtx {
		t.Fatal("expected reused DNS controller runtime to use new lifecycle context")
	}
	if rt.bestDialerChooser == nil {
		t.Fatal("expected reused DNS controller runtime to install bestDialerChooser")
	}
	if rt.fixedDomainTtl["example.com"] != 60 {
		t.Fatal("expected reused DNS controller runtime to use new fixedDomainTtl")
	}
	oldRT := oldController.runtime()
	if oldRT == nil || oldRT.lifecycleCtx != newCtx {
		t.Fatal("expected original DNS controller facade runtime to be refreshed before handoff")
	}
}

func TestDnsRequestContextUsesNewLifecycleDuringDNSHandoff(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	defer oldCancel()
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()

	oldController := &DnsController{}
	oldCP := &ControlPlane{
		ctx: oldCtx,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: oldController,
		},
	}
	newCP := &ControlPlane{
		ctx: newCtx,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: &DnsController{},
			dnsRouting:    &dns.Dns{},
		},
	}

	if !newCP.ReuseDNSControllerFrom(oldCP) {
		t.Fatal("ReuseDNSControllerFrom() = false, want true")
	}

	oldCancel()
	got := oldCP.dnsRequestContext(oldCtx, oldCP.ActiveDnsController())
	if got != newCtx {
		t.Fatal("expected old control plane DNS handoff requests to use new lifecycle context")
	}
	select {
	case <-got.Done():
		t.Fatal("expected handoff DNS request context to remain active after old control plane cancellation")
	default:
	}

	type requestContextKey struct{}
	requestCtx := context.WithValue(context.Background(), requestContextKey{}, "request")
	if got := newCP.dnsRequestContext(requestCtx, newCP.ActiveDnsController()); got != requestCtx {
		t.Fatal("expected new control plane DNS requests to preserve caller context")
	}
}

func TestInheritDialerHealthFromUsesReloadSafeSnapshot(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	newTestDialer := func(name string) *dialer.Dialer {
		return dialer.NewDialer(
			direct.SymmetricDirect,
			&dialer.GlobalOption{
				Log:            logger,
				CheckInterval:  30 * time.Second,
				CheckTolerance: time.Second,
			},
			dialer.InstanceOption{},
			&dialer.Property{
				Property: D.Property{Name: name},
			},
		)
	}

	oldDialer := newTestDialer("node-a")
	defer func() { _ = oldDialer.Close() }()
	newDialer := newTestDialer("node-a")
	defer func() { _ = newDialer.Close() }()

	oldGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{oldDialer},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = oldGroup.Close() }()
	newGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{newDialer},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = newGroup.Close() }()

	tcp4 := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	oldDialer.ReportUnavailableForced(tcp4, nil)
	oldDialer.NotifyHealthCheckResult(tcp4, false, false)
	if oldDialer.MustGetAlive(tcp4) {
		t.Fatal("expected source dialer to be unavailable before inheritance")
	}

	oldCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{oldGroup}}}
	newCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{newGroup}}}

	if got := newCP.InheritDialerHealthFrom(oldCP); !got {
		t.Fatal("expected InheritDialerHealthFrom to return true when dialers overlap")
	}

	if !newDialer.MustGetAlive(tcp4) {
		t.Fatal("expected reload selection floor to keep the only group candidate alive")
	}
	if got := newDialer.GetBackoffLevel(consts.L4ProtoStr_TCP); got != 0 {
		t.Fatalf("inherited backoff level = %d, want 0", got)
	}
}

func TestInheritDialerHealthFromDoesNotReviveDeadDialerWhenGroupHasCandidate(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	newTestDialer := func(name string) *dialer.Dialer {
		return dialer.NewDialer(
			direct.SymmetricDirect,
			&dialer.GlobalOption{
				Log:            logger,
				CheckInterval:  30 * time.Second,
				CheckTolerance: time.Second,
			},
			dialer.InstanceOption{},
			&dialer.Property{
				Property: D.Property{Name: name},
			},
		)
	}

	oldDialerA := newTestDialer("node-a")
	defer func() { _ = oldDialerA.Close() }()
	oldDialerB := newTestDialer("node-b")
	defer func() { _ = oldDialerB.Close() }()
	newDialerA := newTestDialer("node-a")
	defer func() { _ = newDialerA.Close() }()
	newDialerB := newTestDialer("node-b")
	defer func() { _ = newDialerB.Close() }()

	oldGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{oldDialerA, oldDialerB},
		[]*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = oldGroup.Close() }()
	newGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{newDialerA, newDialerB},
		[]*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = newGroup.Close() }()

	tcp4 := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	oldDialerA.ReportUnavailableForced(tcp4, nil)
	oldDialerA.NotifyHealthCheckResult(tcp4, false, false)
	if oldDialerA.MustGetAlive(tcp4) {
		t.Fatal("expected source dialer A to be unavailable before inheritance")
	}
	if !oldDialerB.MustGetAlive(tcp4) {
		t.Fatal("expected source dialer B to remain available before inheritance")
	}

	oldCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{oldGroup}}}
	newCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{newGroup}}}

	if got := newCP.InheritDialerHealthFrom(oldCP); !got {
		t.Fatal("expected InheritDialerHealthFrom to return true when dialers overlap")
	}

	if newDialerA.MustGetAlive(tcp4) {
		t.Fatal("expected dead dialer A to remain unavailable while group has another candidate")
	}
	if !newDialerB.MustGetAlive(tcp4) {
		t.Fatal("expected dialer B to remain available after inheritance")
	}
}

func TestInheritDialerHealthFromSkipsSnapshotWhenHealthCheckConfigChanges(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	newTestDialer := func(name string, tcpCheckURL string) *dialer.Dialer {
		return dialer.NewDialer(
			direct.SymmetricDirect,
			&dialer.GlobalOption{
				Log: logger,
				TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{
					Raw:             []string{tcpCheckURL, "1.1.1.1"},
					ResolverNetwork: "udp",
					Method:          "HEAD",
				},
				CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{
					Raw:             []string{"dns.google:53", "8.8.8.8"},
					ResolverNetwork: "udp",
				},
				CheckInterval:  30 * time.Second,
				CheckTolerance: time.Second,
			},
			dialer.InstanceOption{},
			&dialer.Property{
				Property: D.Property{Name: name},
			},
		)
	}

	oldDialerA := newTestDialer("node-a", "http://old-check.example/generate_204")
	defer func() { _ = oldDialerA.Close() }()
	oldDialerB := newTestDialer("node-b", "http://old-check.example/generate_204")
	defer func() { _ = oldDialerB.Close() }()
	newDialerA := newTestDialer("node-a", "http://new-check.example/generate_204")
	defer func() { _ = newDialerA.Close() }()
	newDialerB := newTestDialer("node-b", "http://new-check.example/generate_204")
	defer func() { _ = newDialerB.Close() }()

	oldGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{oldDialerA, oldDialerB},
		[]*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = oldGroup.Close() }()
	newGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{newDialerA, newDialerB},
		[]*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = newGroup.Close() }()

	tcp4 := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	oldDialerA.ReportUnavailableForced(tcp4, nil)
	oldDialerA.NotifyHealthCheckResult(tcp4, false, false)
	if oldDialerA.MustGetAlive(tcp4) {
		t.Fatal("expected source dialer A to be unavailable before inheritance")
	}

	oldCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{oldGroup}}}
	newCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{newGroup}}}

	if got := newCP.InheritDialerHealthFrom(oldCP); !got {
		t.Fatal("expected InheritDialerHealthFrom to return true when dialers overlap")
	}

	if !newDialerA.MustGetAlive(tcp4) {
		t.Fatal("expected changed health-check config to skip inheriting the old unavailable snapshot")
	}
}

func TestInheritDialerHealthFromReturnsFalseWhenNoOverlap(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	newTestDialer := func(name string) *dialer.Dialer {
		return dialer.NewDialer(
			direct.SymmetricDirect,
			&dialer.GlobalOption{
				Log:            logger,
				CheckInterval:  30 * time.Second,
				CheckTolerance: time.Second,
			},
			dialer.InstanceOption{},
			&dialer.Property{
				Property: D.Property{Name: name},
			},
		)
	}

	oldDialer := newTestDialer("node-a")
	defer func() { _ = oldDialer.Close() }()
	newDialer := newTestDialer("node-b")
	defer func() { _ = newDialer.Close() }()

	oldGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-x",
		[]*dialer.Dialer{oldDialer},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = oldGroup.Close() }()
	newGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-y",
		[]*dialer.Dialer{newDialer},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = newGroup.Close() }()

	oldCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{oldGroup}}}
	newCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{newGroup}}}

	if got := newCP.InheritDialerHealthFrom(oldCP); got {
		t.Fatal("expected InheritDialerHealthFrom to return false when no dialers overlap")
	}
}

func TestInheritDialerHealthFromSnapshotIsolatedFromOldGenerationFlap(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	newTestDialer := func(name string) *dialer.Dialer {
		return dialer.NewDialer(
			direct.SymmetricDirect,
			&dialer.GlobalOption{
				Log:            logger,
				CheckInterval:  30 * time.Second,
				CheckTolerance: time.Second,
			},
			dialer.InstanceOption{},
			&dialer.Property{Property: D.Property{Name: name}},
		)
	}
	newGroup := func(name string, members ...*dialer.Dialer) *outbound.DialerGroup {
		annotations := make([]*dialer.Annotation, len(members))
		for i := range annotations {
			annotations[i] = &dialer.Annotation{}
		}
		return outbound.NewDialerGroup(
			&dialer.GlobalOption{
				Log:            logger,
				CheckInterval:  30 * time.Second,
				CheckTolerance: time.Second,
			},
			name,
			members,
			annotations,
			outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
			func(bool, *dialer.NetworkType, bool) {},
		)
	}

	oldA := newTestDialer("node-a")
	oldB := newTestDialer("node-b")
	firstA := newTestDialer("node-a")
	firstB := newTestDialer("node-b")
	secondA := newTestDialer("node-a")
	secondB := newTestDialer("node-b")
	for _, d := range []*dialer.Dialer{oldA, oldB, firstA, firstB, secondA, secondB} {
		t.Cleanup(func() { _ = d.Close() })
	}

	oldGroup := newGroup("group-a", oldA, oldB)
	firstGroup := newGroup("group-a", firstA, firstB)
	secondGroup := newGroup("group-a", secondA, secondB)
	for _, group := range []*outbound.DialerGroup{oldGroup, firstGroup, secondGroup} {
		t.Cleanup(func() { _ = group.Close() })
	}

	udp4 := &dialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: dialer.UdpHealthDomainData,
	}
	oldA.ReportUnavailableForced(udp4, nil)
	oldA.NotifyHealthCheckResult(udp4, false, false)
	if oldA.MustGetAlive(udp4) {
		t.Fatal("expected old node-a to be unavailable before preparing the first candidate")
	}

	oldCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{oldGroup}}}
	firstCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{firstGroup}}}
	if !firstCP.InheritDialerHealthFrom(oldCP) {
		t.Fatal("expected first candidate to inherit overlapping dialer health")
	}
	if firstA.MustGetAlive(udp4) {
		t.Fatal("expected first candidate to retain the prepared unavailable snapshot while node-b is healthy")
	}

	// The old generation may continue to receive health checks while a candidate
	// is prepared or a reload rolls back. Its later result must not mutate the
	// candidate's copied health state.
	oldA.ReportAvailableTraffic(udp4)
	if !oldA.MustGetAlive(udp4) {
		t.Fatal("expected old node-a to recover during the simulated health flap")
	}
	if firstA.MustGetAlive(udp4) {
		t.Fatal("old-generation health flap changed the already prepared candidate")
	}

	secondCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{outbounds: []*outbound.DialerGroup{secondGroup}}}
	if !secondCP.InheritDialerHealthFrom(oldCP) {
		t.Fatal("expected later candidate to inherit overlapping dialer health")
	}
	if !secondA.MustGetAlive(udp4) {
		t.Fatal("expected later candidate to observe the recovered source snapshot")
	}
}

func TestWaitDNSUpstreamsReadyReturnsWhenChannelCloses(t *testing.T) {
	cp := &ControlPlane{
		ctx:   context.Background(),
		ready: make(chan struct{}),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsUpstreamAvailable: make(chan struct{}),
		},
	}
	done := make(chan struct{})
	go func() {
		_ = cp.dnsUpstreamReadyCallback(nil)
		close(done)
	}()

	select {
	case <-cp.dnsUpstreamAvailable:
	case <-time.After(time.Second):
		t.Fatal("expected dnsUpstreamAvailable to close before ready")
	}

	select {
	case <-done:
		t.Fatal("expected callback to remain blocked on ready")
	default:
	}

	cp.markReady()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected callback to finish after ready")
	}
}
