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
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
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

func tcpFlowRegistryTestBinding() TcpFlowBinding {
	return TcpFlowBinding{
		Route: TcpRouteBinding{
			PolicyEpoch: 7,
			Outbound:    consts.OutboundUserDefinedMin,
			Mark:        42,
			Must:        true,
		},
		Egress: TcpEgressBinding{
			Target:  "198.51.100.20:443",
			Network: "tcp+0x2a",
		},
	}
}

func TestTCPFlowRegistryRegistersAndCleansUp(t *testing.T) {
	cp := &ControlPlane{}
	key := tcpFlowRegistryTestKey()
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingress.Close() }()
	defer func() { _ = ingressPeer.Close() }()
	egress := newMockConn(false, nil)

	entry, ok := cp.registerTCPFlow(key.Src, key.Dst, ingress, egress, tcpFlowRegistryTestBinding())
	if !ok || entry == nil {
		t.Fatal("registerTCPFlow() = nil")
	}
	if got, ok := cp.tcpFlows.lookup(key); !ok || got != entry {
		t.Fatalf("tuple lookup = (%p, %t), want (%p, true)", got, ok, entry)
	}
	if got, ok := cp.tcpFlows.lookupIngress(ingress); !ok || got != entry {
		t.Fatalf("ingress lookup = (%p, %t), want (%p, true)", got, ok, entry)
	}
	if entry.Binding != tcpFlowRegistryTestBinding() {
		t.Fatalf("flow binding = %+v", entry.Binding)
	}

	cp.unregisterTCPFlow(entry)
	if _, ok := cp.tcpFlows.lookup(key); ok {
		t.Fatal("tuple binding remained after cleanup")
	}
	if _, ok := cp.tcpFlows.lookupIngress(ingress); ok {
		t.Fatal("ingress binding remained after cleanup")
	}
}

func TestTCPFlowRegistryCleanupDoesNotDeleteReusedTuple(t *testing.T) {
	cp := &ControlPlane{}
	key := tcpFlowRegistryTestKey()
	firstIngress, firstPeer := net.Pipe()
	secondIngress, secondPeer := net.Pipe()
	defer func() { _ = firstIngress.Close() }()
	defer func() { _ = firstPeer.Close() }()
	defer func() { _ = secondIngress.Close() }()
	defer func() { _ = secondPeer.Close() }()

	first, firstOK := cp.registerTCPFlow(key.Src, key.Dst, firstIngress, newMockConn(false, nil), tcpFlowRegistryTestBinding())
	second, secondOK := cp.registerTCPFlow(key.Src, key.Dst, secondIngress, newMockConn(false, nil), tcpFlowRegistryTestBinding())
	if !firstOK || !secondOK || first == nil || second == nil {
		t.Fatal("registerTCPFlow() returned nil")
	}

	cp.unregisterTCPFlow(first)
	if got, ok := cp.tcpFlows.lookup(key); !ok || got != second {
		t.Fatalf("tuple lookup after stale cleanup = (%p, %t), want (%p, true)", got, ok, second)
	}
	if _, ok := cp.tcpFlows.lookupIngress(firstIngress); ok {
		t.Fatal("first ingress binding remained after cleanup")
	}
	if got, ok := cp.tcpFlows.lookupIngress(secondIngress); !ok || got != second {
		t.Fatalf("second ingress lookup = (%p, %t), want (%p, true)", got, ok, second)
	}
}

func TestControlPlaneAbortConnectionsRemovesTCPFlow(t *testing.T) {
	cp := &ControlPlane{}
	key := tcpFlowRegistryTestKey()
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	if !cp.registerIncomingConnection(ingress) {
		t.Fatal("registerIncomingConnection() = false")
	}
	egress := newMockConn(false, nil)
	entry, ok := cp.registerTCPFlow(key.Src, key.Dst, ingress, egress, tcpFlowRegistryTestBinding())
	if !ok || entry == nil {
		t.Fatal("registerTCPFlow() = nil")
	}

	if err := cp.AbortConnections(); err != nil {
		t.Fatalf("AbortConnections() error = %v", err)
	}
	if _, ok := cp.tcpFlows.lookup(key); ok {
		t.Fatal("tuple binding remained after abort")
	}
	if _, ok := cp.tcpFlows.lookupIngress(ingress); ok {
		t.Fatal("ingress binding remained after abort")
	}
	if !egress.closed.Load() {
		t.Fatal("abort did not close the bound egress connection")
	}
}

func TestControlPlaneAbortConnectionsIgnoresClosedTCPFlowEgress(t *testing.T) {
	cp := &ControlPlane{}
	key := tcpFlowRegistryTestKey()
	ingress, ingressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	if !cp.registerIncomingConnection(ingress) {
		t.Fatal("registerIncomingConnection() = false")
	}
	egress := &tcpFlowRegistryAlreadyClosedConn{mockConn: newMockConn(false, nil)}
	if entry, ok := cp.registerTCPFlow(key.Src, key.Dst, ingress, egress, tcpFlowRegistryTestBinding()); !ok || entry == nil {
		t.Fatal("registerTCPFlow() = nil")
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

	key := tcpFlowRegistryTestKey()
	egress := newMockConn(false, nil)
	entry, registered := successor.registerTCPFlow(key.Src, key.Dst, ingress, egress, tcpFlowRegistryTestBinding())
	if !registered || entry == nil {
		t.Fatal("successor registerTCPFlow() = nil")
	}

	if err := previous.AbortConnections(); err != nil {
		t.Fatalf("previous AbortConnections() error = %v", err)
	}
	if _, ok := successor.tcpFlows.lookup(key); !ok {
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
	if _, ok := successor.tcpFlows.lookup(key); ok {
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
		_, ok := cp.tcpFlows.lookup(key)
		return ok
	})
	entry, _ := cp.tcpFlows.lookup(key)
	if entry.Binding.Route.Outbound != consts.OutboundUserDefinedMin || entry.Binding.Route.Mark != 42 || !entry.Binding.Route.Must || entry.Binding.Egress.Dialer != d {
		t.Fatalf("registered binding = %+v", entry.Binding)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP relay cleanup")
	}
	if _, ok := cp.tcpFlows.lookup(key); ok {
		t.Fatal("tuple binding remained after relay exit")
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
	if _, ok := cp.tcpFlows.lookup(key); ok {
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
	if _, ok := cp.tcpFlows.lookup(key); ok {
		t.Fatal("post-abort successful dial registered a stale flow")
	}
	if !egress.closed.Load() {
		t.Fatal("post-abort successful dial did not close its egress connection")
	}
}
