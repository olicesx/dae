/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type tcpFlowRegistryBlockingDialer struct {
	conn    netproxy.Conn
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

type tcpFlowRegistryAlreadyClosedConn struct {
	*mockConn
}

func (c *tcpFlowRegistryAlreadyClosedConn) Close() error {
	_ = c.mockConn.Close()
	return net.ErrClosed
}

func (d *tcpFlowRegistryBlockingDialer) DialContext(ctx context.Context, _, _ string) (netproxy.Conn, error) {
	d.once.Do(func() { close(d.started) })
	select {
	case <-d.release:
		return d.conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newTCPFlowRegistryBlockingDialer(conn netproxy.Conn, release <-chan struct{}) (*componentdialer.Dialer, *tcpFlowRegistryBlockingDialer) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	underlay := &tcpFlowRegistryBlockingDialer{
		conn:    conn,
		started: make(chan struct{}),
		release: release,
	}
	return componentdialer.NewDialer(
		underlay,
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{},
	), underlay
}

func newTCPFlowRegistryTestPlane(t *testing.T, d *componentdialer.Dialer) *ControlPlane {
	t.Helper()
	cp := newTestDialControlPlane(newTestFixedOutboundGroup(d))
	cp.log = logrus.New()
	cp.log.SetOutput(io.Discard)
	return cp
}

func tcpFlowRegistryTestKey() TcpFlowKey {
	return NewTcpFlowKey(
		netip.MustParseAddrPort("192.0.2.10:42687"),
		netip.MustParseAddrPort("198.51.100.20:443"),
	)
}

func TestTCPFlowRegistryRegistersAndCleansUp(t *testing.T) {
	cp := &ControlPlane{}
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingress.Close() }()
	defer func() { _ = ingressPeer.Close() }()
	egress := newMockConn(false, nil)

	if !cp.registerTCPFlow(ingress, egress) {
		t.Fatal("registerTCPFlow() = false")
	}
	if got, ok := cp.tcpFlowEgress(ingress); !ok || got != egress {
		t.Fatalf("ingress lookup = (%p, %t), want (%p, true)", got, ok, egress)
	}

	cp.unregisterTCPFlow(ingress)
	if _, ok := cp.tcpFlowEgress(ingress); ok {
		t.Fatal("ingress binding remained after cleanup")
	}
}

func TestTCPFlowRegistryCleanupDoesNotDeleteAnotherIngress(t *testing.T) {
	cp := &ControlPlane{}
	firstIngress, firstPeer := net.Pipe()
	secondIngress, secondPeer := net.Pipe()
	defer func() { _ = firstIngress.Close() }()
	defer func() { _ = firstPeer.Close() }()
	defer func() { _ = secondIngress.Close() }()
	defer func() { _ = secondPeer.Close() }()

	firstEgress := newMockConn(false, nil)
	secondEgress := newMockConn(false, nil)
	if !cp.registerTCPFlow(firstIngress, firstEgress) || !cp.registerTCPFlow(secondIngress, secondEgress) {
		t.Fatal("registerTCPFlow() = false")
	}

	cp.unregisterTCPFlow(firstIngress)
	if _, ok := cp.tcpFlowEgress(firstIngress); ok {
		t.Fatal("first ingress binding remained after cleanup")
	}
	if got, ok := cp.tcpFlowEgress(secondIngress); !ok || got != secondEgress {
		t.Fatalf("second ingress lookup = (%p, %t), want (%p, true)", got, ok, secondEgress)
	}
}

func TestControlPlaneAbortConnectionsRemovesTCPFlow(t *testing.T) {
	cp := &ControlPlane{}
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	if !cp.registerIncomingConnection(ingress) {
		t.Fatal("registerIncomingConnection() = false")
	}
	egress := newMockConn(false, nil)
	if !cp.registerTCPFlow(ingress, egress) {
		t.Fatal("registerTCPFlow() = false")
	}

	if err := cp.AbortConnections(); err != nil {
		t.Fatalf("AbortConnections() error = %v", err)
	}
	if _, ok := cp.tcpFlowEgress(ingress); ok {
		t.Fatal("ingress binding remained after abort")
	}
	if !egress.closed.Load() {
		t.Fatal("abort did not close the bound egress connection")
	}
}

func TestControlPlaneAbortConnectionsIgnoresClosedTCPFlowEgress(t *testing.T) {
	cp := &ControlPlane{}
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	if !cp.registerIncomingConnection(ingress) {
		t.Fatal("registerIncomingConnection() = false")
	}
	egress := &tcpFlowRegistryAlreadyClosedConn{mockConn: newMockConn(false, nil)}
	if !cp.registerTCPFlow(ingress, egress) {
		t.Fatal("registerTCPFlow() = false")
	}

	if err := cp.AbortConnections(); err != nil {
		t.Fatalf("AbortConnections() error = %v, want nil for an already closed egress", err)
	}
}

func TestTCPFlowRegistryFollowsIncomingConnectionLeaseOwnership(t *testing.T) {
	previous := newRoutingEpochExecutionTestPlane(0)
	successor := newRoutingEpochExecutionTestPlane(1)
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	lease, ok := previous.acquireIncomingConnectionLease(ingress)
	if !ok {
		t.Fatal("acquireIncomingConnectionLease() = false")
	}
	defer lease.release()
	if !lease.transfer(successor) {
		t.Fatal("transfer() = false")
	}

	egress := newMockConn(false, nil)
	if !successor.registerTCPFlow(ingress, egress) {
		t.Fatal("successor registerTCPFlow() = false")
	}

	if err := previous.AbortConnections(); err != nil {
		t.Fatalf("previous AbortConnections() error = %v", err)
	}
	if _, ok := successor.tcpFlowEgress(ingress); !ok {
		t.Fatal("previous abort removed the successor flow")
	}
	if _, ok := successor.inConnections.Load(ingress); !ok {
		t.Fatal("previous abort removed the successor incoming connection")
	}
	if egress.closed.Load() {
		t.Fatal("previous abort closed the successor egress connection")
	}

	if err := successor.AbortConnections(); err != nil {
		t.Fatalf("successor AbortConnections() error = %v", err)
	}
	if _, ok := successor.tcpFlowEgress(ingress); ok {
		t.Fatal("successor abort retained its flow")
	}
	if !egress.closed.Load() {
		t.Fatal("successor abort did not close its egress connection")
	}
}

func TestHandleTCPFlowRegistryRegistersAfterDialAndCleansUp(t *testing.T) {
	releaseDial := make(chan struct{})
	egress := newMockConn(true, nil)
	d, underlay := newTCPFlowRegistryBlockingDialer(egress, releaseDial)
	cp := newTCPFlowRegistryTestPlane(t, d)
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	defer func() { _ = ingress.Close() }()

	key := tcpFlowRegistryTestKey()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- cp.handleConnWithRoutingResult(ctx, ingress, key.Src, key.Dst, &bpfRoutingResult{
			Outbound: uint8(consts.OutboundUserDefinedMin),
			Mark:     42,
			Must:     1,
		})
	}()

	select {
	case <-underlay.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP dial")
	}
	close(releaseDial)
	waitForCondition(t, time.Second, "TCP flow registry entry", func() bool {
		_, ok := cp.tcpFlowEgress(ingress)
		return ok
	})
	if got, _ := cp.tcpFlowEgress(ingress); got != egress {
		t.Fatalf("registered egress = %p, want %p", got, egress)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP relay cleanup")
	}
	if _, ok := cp.tcpFlowEgress(ingress); ok {
		t.Fatal("ingress binding remained after relay exit")
	}
}

func TestProcessOwnedTCPFlowSurvivesGenerationCancellation(t *testing.T) {
	releaseDial := make(chan struct{})
	close(releaseDial)
	egress, egressPeer := net.Pipe()
	d, _ := newTCPFlowRegistryBlockingDialer(egress, releaseDial)
	cp := newTCPFlowRegistryTestPlane(t, d)
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	if err := cp.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager() error = %v", err)
	}
	cleanupCalls := atomic.Int32{}
	cp.egressRuntime = newEgressRuntime(nil, []func() error{func() error {
		cleanupCalls.Add(1)
		return nil
	}})
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	defer func() { _ = egressPeer.Close() }()

	generationCtx, cancelGeneration := context.WithCancel(context.Background())
	done := make(chan error, 1)
	key := tcpFlowRegistryTestKey()
	go func() {
		done <- cp.handleConnWithRoutingResult(generationCtx, ingress, key.Src, key.Dst, &bpfRoutingResult{
			Outbound: uint8(consts.OutboundUserDefinedMin),
		})
	}()
	waitForCondition(t, time.Second, "process-owned TCP flow", func() bool {
		return manager.ActiveTCPConnections() == 1
	})
	cancelGeneration()
	if err := cp.egressRuntime.releaseOwner(); err != nil {
		t.Fatalf("releaseOwner() error = %v", err)
	}
	if cleanupCalls.Load() != 0 {
		t.Fatal("egress runtime closed while flow remained active")
	}

	clientPayload := []byte("client-after-reload")
	if _, err := ingressPeer.Write(clientPayload); err != nil {
		t.Fatalf("client write after generation cancellation: %v", err)
	}
	gotClient := make([]byte, len(clientPayload))
	if _, err := io.ReadFull(egressPeer, gotClient); err != nil {
		t.Fatalf("egress read after generation cancellation: %v", err)
	}
	if string(gotClient) != string(clientPayload) {
		t.Fatalf("egress payload = %q, want %q", gotClient, clientPayload)
	}

	serverPayload := []byte("server-after-reload")
	if _, err := egressPeer.Write(serverPayload); err != nil {
		t.Fatalf("server write after generation cancellation: %v", err)
	}
	gotServer := make([]byte, len(serverPayload))
	if _, err := io.ReadFull(ingressPeer, gotServer); err != nil {
		t.Fatalf("client read after generation cancellation: %v", err)
	}
	if string(gotServer) != string(serverPayload) {
		t.Fatalf("client payload = %q, want %q", gotServer, serverPayload)
	}

	_ = ingressPeer.Close()
	_ = egressPeer.Close()
	select {
	case err := <-done:
		if err != nil && !commonerrors.IsClosedConnection(err) {
			t.Fatalf("relay error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for process-owned relay cleanup")
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("egress cleanup calls = %d, want 1", cleanupCalls.Load())
	}
}

func TestHandleTCPFlowRegistryLeavesFailedDialUnregistered(t *testing.T) {
	d, _ := newTestEndpointErrorDialer("hysteria2", "proxy.example:443", io.ErrUnexpectedEOF)
	cp := newTCPFlowRegistryTestPlane(t, d)
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingress.Close() }()
	defer func() { _ = ingressPeer.Close() }()
	key := tcpFlowRegistryTestKey()

	_ = cp.handleConnWithRoutingResult(context.Background(), ingress, key.Src, key.Dst, &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	})
	if _, ok := cp.tcpFlowEgress(ingress); ok {
		t.Fatal("failed TCP dial registered a flow")
	}
}

func TestHandleTCPFlowRegistryRejectsPostAbortSuccessfulDial(t *testing.T) {
	releaseDial := make(chan struct{})
	egress := newMockConn(true, nil)
	d, underlay := newTCPFlowRegistryBlockingDialer(egress, releaseDial)
	cp := newTCPFlowRegistryTestPlane(t, d)
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	key := tcpFlowRegistryTestKey()
	if !cp.registerIncomingConnection(ingress) {
		t.Fatal("registerIncomingConnection() = false")
	}

	done := make(chan error, 1)
	go func() {
		done <- cp.handleConnWithRoutingResult(context.Background(), ingress, key.Src, key.Dst, &bpfRoutingResult{
			Outbound: uint8(consts.OutboundUserDefinedMin),
		})
	}()
	select {
	case <-underlay.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP dial")
	}
	if err := cp.AbortConnections(); err != nil {
		t.Fatalf("AbortConnections() error = %v", err)
	}
	close(releaseDial)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for post-abort TCP handler")
	}
	if _, ok := cp.tcpFlowEgress(ingress); ok {
		t.Fatal("post-abort successful dial registered a stale flow")
	}
	if !egress.closed.Load() {
		t.Fatal("post-abort successful dial did not close its egress connection")
	}
}
