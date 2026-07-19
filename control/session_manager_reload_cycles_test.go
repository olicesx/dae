/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

const processFlowReloadCycles = 65

type reloadCycleDialerUnderlay struct {
	closeCalls atomic.Int32
}

func (d *reloadCycleDialerUnderlay) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, io.ErrClosedPipe
}

func (d *reloadCycleDialerUnderlay) Close() error {
	d.closeCalls.Add(1)
	return nil
}

type reloadCycleGeneration struct {
	epoch routing.PolicyEpoch
	core  *controlPlaneCore
	plane *ControlPlane

	ctx    context.Context
	cancel context.CancelFunc

	runtime         *egressRuntime
	dialer          *componentdialer.Dialer
	group           *outbound.DialerGroup
	underlay        *reloadCycleDialerUnderlay
	resourceCleanup atomic.Int32
	retirementCalls atomic.Int32
}

func newReloadCycleGeneration(t *testing.T, epoch routing.PolicyEpoch, core *controlPlaneCore) *reloadCycleGeneration {
	t.Helper()

	log := logrus.New()
	log.SetOutput(io.Discard)
	option := &componentdialer.GlobalOption{
		Log:            log,
		CheckInterval:  time.Hour,
		CheckTolerance: time.Hour,
	}
	underlay := &reloadCycleDialerUnderlay{}
	d := componentdialer.NewDialer(
		underlay,
		option,
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{},
	)
	group := outbound.NewDialerGroup(
		option,
		fmt.Sprintf("reload-%d", epoch),
		[]*componentdialer.Dialer{d},
		[]*componentdialer.Annotation{{}},
		outbound.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		},
		func(bool, *componentdialer.NetworkType, bool) {},
	)
	generationCtx, cancel := context.WithCancel(context.Background())
	generation := &reloadCycleGeneration{
		epoch:    epoch,
		core:     core,
		ctx:      generationCtx,
		cancel:   cancel,
		dialer:   d,
		group:    group,
		underlay: underlay,
	}
	generation.runtime = newEgressRuntime(nil, []func() error{func() error {
		generation.resourceCleanup.Add(1)
		return nil
	}})
	generation.runtime.configureResources(
		[]*outbound.DialerGroup{group},
		[]*componentdialer.Dialer{d},
		nil,
	)
	generation.plane = &ControlPlane{
		core:          core,
		ctx:           generationCtx,
		drainTracker:  newControlPlaneDrainTracker(),
		egressRuntime: generation.runtime,
	}
	return generation
}

func (g *reloadCycleGeneration) retire(t *testing.T) {
	t.Helper()
	if got := g.retirementCalls.Add(1); got != 1 {
		t.Fatalf("generation %d retirement calls = %d, want 1", g.epoch, got)
	}
	g.plane.StopRoutingEpochExecution()
	if release, ok := g.plane.acquireRoutingEpochExecutionLease(); ok {
		release()
		t.Fatalf("generation %d accepted execution after retirement", g.epoch)
	}
	g.cancel()
	select {
	case <-g.ctx.Done():
	default:
		t.Fatalf("generation %d context remains active after retirement", g.epoch)
	}
	if err := g.runtime.releaseOwner(); err != nil {
		t.Fatalf("generation %d releaseOwner() error = %v", g.epoch, err)
	}
	g.runtime.mu.Lock()
	ownerReleased := g.runtime.ownerReleased
	g.runtime.mu.Unlock()
	if !ownerReleased {
		t.Fatalf("generation %d retained its egress owner", g.epoch)
	}
}

func (g *reloadCycleGeneration) tcpBinding(target string) TcpFlowBinding {
	networkType := componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP}
	return newTcpFlowBinding(g.epoch, &proxyDialResult{
		OutboundIndex:           consts.OutboundUserDefinedMin,
		Outbound:                g.group,
		Dialer:                  g.dialer,
		DialTarget:              target,
		Network:                 "tcp4",
		Mark:                    uint32(g.epoch) + 1000,
		Must:                    true,
		SelectionNetworkTypeObj: &networkType,
	})
}

func (g *reloadCycleGeneration) udpBinding(target string) UdpFlowBinding {
	networkType := componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP}
	return newUdpFlowBinding(
		g.epoch,
		consts.OutboundUserDefinedMin,
		uint32(g.epoch)+2000,
		true,
		&DialOption{
			Target:      target,
			Dialer:      g.dialer,
			Outbound:    g.group,
			Network:     "udp4",
			NetworkType: &networkType,
		},
	)
}

type reloadCycleTCPFlow struct {
	flow   *FlowRuntime
	client net.Conn
	server net.Conn
	done   chan error
}

func newReloadCycleTCPFlow(
	t *testing.T,
	manager *SessionManager,
	generation *reloadCycleGeneration,
	src netip.AddrPort,
	dst netip.AddrPort,
) *reloadCycleTCPFlow {
	t.Helper()
	ingress, client := net.Pipe()
	egress, server := net.Pipe()
	binding := generation.tcpBinding(dst.String())
	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, 6),
		bpfTuplesKeyFromAddrPorts(dst, src, 6),
	}
	flow, err := manager.adoptTCP(ingress, egress, binding, generation.runtime, keys)
	if err != nil {
		_ = ingress.Close()
		_ = client.Close()
		_ = egress.Close()
		_ = server.Close()
		t.Fatalf("generation %d adoptTCP() error = %v", generation.epoch, err)
	}
	done := make(chan error, 1)
	go func() {
		err := relayEstablishedTCPFlow(flow, ingress, egress, nil, src, dst)
		flow.finish()
		_ = ingress.Close()
		_ = egress.Close()
		done <- err
	}()
	return &reloadCycleTCPFlow{
		flow:   flow,
		client: client,
		server: server,
		done:   done,
	}
}

func (f *reloadCycleTCPFlow) exchange(t *testing.T, payload []byte) {
	t.Helper()
	assertReloadCycleTCPDirection(t, f.client, f.server, payload)
	reply := append([]byte("reply:"), payload...)
	assertReloadCycleTCPDirection(t, f.server, f.client, reply)
}

func assertReloadCycleTCPDirection(t *testing.T, writer, reader net.Conn, payload []byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	if err := writer.SetDeadline(deadline); err != nil {
		t.Fatalf("set TCP writer deadline: %v", err)
	}
	if err := reader.SetDeadline(deadline); err != nil {
		t.Fatalf("set TCP reader deadline: %v", err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := writer.Write(payload)
		writeDone <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read relayed TCP payload: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write relayed TCP payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relayed TCP payload = %x, want %x", got, payload)
	}
	_ = writer.SetDeadline(time.Time{})
	_ = reader.SetDeadline(time.Time{})
}

func (f *reloadCycleTCPFlow) closeAndWait(t *testing.T) {
	t.Helper()
	_ = f.client.Close()
	_ = f.server.Close()
	select {
	case err := <-f.done:
		if err != nil {
			t.Fatalf("TCP relay exit error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for TCP relay exit")
	}
}

type reloadCyclePacketRead struct {
	data []byte
	from netip.AddrPort
}

type reloadCyclePacketWrite struct {
	data   []byte
	target string
}

type reloadCyclePacketConn struct {
	reads  chan reloadCyclePacketRead
	writes chan reloadCyclePacketWrite
	closed chan struct{}

	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func newReloadCyclePacketConn() *reloadCyclePacketConn {
	return &reloadCyclePacketConn{
		reads:  make(chan reloadCyclePacketRead, 1),
		writes: make(chan reloadCyclePacketWrite, 1),
		closed: make(chan struct{}),
	}
}

func (c *reloadCyclePacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *reloadCyclePacketConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *reloadCyclePacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	select {
	case <-c.closed:
		return 0, netip.AddrPort{}, io.EOF
	case read := <-c.reads:
		copy(p, read.data)
		return len(read.data), read.from, nil
	}
}

func (c *reloadCyclePacketConn) WriteTo(p []byte, target string) (int, error) {
	write := reloadCyclePacketWrite{data: append([]byte(nil), p...), target: target}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case c.writes <- write:
		return len(p), nil
	}
}

func (c *reloadCyclePacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeCalls.Add(1)
		close(c.closed)
	})
	return nil
}

func (c *reloadCyclePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *reloadCyclePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *reloadCyclePacketConn) SetWriteDeadline(time.Time) error { return nil }

type reloadCycleUDPReply struct {
	data []byte
	from netip.AddrPort
}

type reloadCycleUDPFlow struct {
	runtime  *UDPFlowRuntime
	endpoint *UdpEndpoint
	conn     *reloadCyclePacketConn
	replies  chan reloadCycleUDPReply
	target   netip.AddrPort
}

func newReloadCycleUDPFlow(
	t *testing.T,
	manager *SessionManager,
	generation *reloadCycleGeneration,
	src netip.AddrPort,
	dst netip.AddrPort,
) *reloadCycleUDPFlow {
	t.Helper()
	conn := newReloadCyclePacketConn()
	replies := make(chan reloadCycleUDPReply, 1)
	binding := generation.udpBinding(dst.String())
	endpoint := &UdpEndpoint{
		conn:                conn,
		NatTimeout:          QuicNatTimeout,
		Dialer:              binding.Egress.Dialer,
		Outbound:            binding.Egress.Outbound,
		DialTarget:          binding.Egress.Target,
		poolKey:             UdpEndpointKey{Src: src, Dst: dst},
		endpointNetworkType: binding.Egress.NetworkType,
		handler: func(_ *UdpEndpoint, data []byte, from netip.AddrPort) error {
			replies <- reloadCycleUDPReply{data: append([]byte(nil), data...), from: from}
			return nil
		},
	}
	flow, err := manager.adoptUDP(endpoint, binding, generation.runtime)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("generation %d adoptUDP() error = %v", generation.epoch, err)
	}
	go endpoint.start()
	return &reloadCycleUDPFlow{
		runtime:  flow,
		endpoint: endpoint,
		conn:     conn,
		replies:  replies,
		target:   dst,
	}
}

func (f *reloadCycleUDPFlow) exchange(t *testing.T, payload []byte, reply []byte) {
	t.Helper()
	if n, err := f.endpoint.WriteTo(payload, f.target.String()); err != nil || n != len(payload) {
		t.Fatalf("UDP endpoint WriteTo() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	select {
	case write := <-f.conn.writes:
		if write.target != f.target.String() || !bytes.Equal(write.data, payload) {
			t.Fatalf("UDP upstream write = (%q, %x), want (%q, %x)", write.target, write.data, f.target, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP upstream write")
	}
	f.conn.reads <- reloadCyclePacketRead{data: append([]byte(nil), reply...), from: f.target}
	select {
	case got := <-f.replies:
		if got.from != f.target || !bytes.Equal(got.data, reply) {
			t.Fatalf("UDP downstream reply = (%v, %x), want (%v, %x)", got.from, got.data, f.target, reply)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP downstream reply")
	}
}

func (f *reloadCycleUDPFlow) close(t *testing.T) {
	t.Helper()
	if err := f.endpoint.Close(); err != nil {
		t.Fatalf("UDP endpoint Close() error = %v", err)
	}
	select {
	case <-f.runtime.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP flow context cancellation")
	}
}

func TestSessionManagerMixedFlowsSurviveSixtyFiveRoutingEpochReloads(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	initialCore, activeMap := newRoutingEpochTestCore(t)
	sharedBPF := initialCore.PeekBpf()

	const initialEpoch routing.PolicyEpoch = 1
	if slot, err := initialCore.PrepareRoutingEpoch(initialEpoch, false); err != nil || slot != 0 {
		t.Fatalf("initial PrepareRoutingEpoch() = (%d, %v), want (0, nil)", slot, err)
	}
	if err := initialCore.StageRoutingEpoch(); err != nil {
		t.Fatalf("initial StageRoutingEpoch() error = %v", err)
	}
	if err := initialCore.PublishRoutingEpoch(); err != nil {
		t.Fatalf("initial PublishRoutingEpoch() error = %v", err)
	}
	assertActiveRoutingEpochSlot(t, activeMap, 0)

	initial := newReloadCycleGeneration(t, initialEpoch, initialCore)
	generations := []*reloadCycleGeneration{initial}
	defer func() {
		for _, generation := range generations {
			generation.cancel()
			_ = generation.runtime.releaseOwner()
		}
	}()

	initialTCPSrc := netip.MustParseAddrPort("192.0.2.10:31000")
	initialDst := netip.MustParseAddrPort("198.51.100.10:443")
	longTCP := newReloadCycleTCPFlow(t, manager, initial, initialTCPSrc, initialDst)
	longUDP := newReloadCycleUDPFlow(t, manager, initial, netip.MustParseAddrPort("192.0.2.20:32000"), initialDst)
	initialTCPBinding := longTCP.flow.Binding()
	initialUDPBinding := longUDP.runtime.binding
	initialTCPContext := longTCP.flow.Context()
	initialUDPContext := longUDP.runtime.ctx
	quicPayload := makeLikelyQuicInitialPayload(0x20)
	if decision := ClassifyUdpFlow(longUDP.endpoint.poolKey.Src, initialDst, quicPayload); !decision.IsQuicInitial {
		t.Fatal("test payload was not classified as a QUIC Initial")
	}
	longTCP.exchange(t, []byte("tcp-before-reload"))
	longUDP.exchange(t, quicPayload, []byte("quic-before-reload"))

	previous := initial
	for cycle := 1; cycle <= processFlowReloadCycles; cycle++ {
		epoch := routing.PolicyEpoch(cycle + 1)
		candidateCore := &controlPlaneCore{}
		candidateCore.bpf.Store(sharedBPF)
		candidate := newReloadCycleGeneration(t, epoch, candidateCore)
		generations = append(generations, candidate)

		previousSlot := previous.core.RoutingEpochSlot()
		slot, err := candidateCore.PrepareRoutingEpoch(epoch, true)
		if err != nil {
			t.Fatalf("cycle %d PrepareRoutingEpoch() error = %v", cycle, err)
		}
		if slot == previousSlot {
			t.Fatalf("cycle %d prepared active slot %d", cycle, slot)
		}
		if err := candidateCore.StageRoutingEpoch(); err != nil {
			t.Fatalf("cycle %d StageRoutingEpoch() error = %v", cycle, err)
		}
		if err := candidateCore.PublishRoutingEpoch(); err != nil {
			t.Fatalf("cycle %d PublishRoutingEpoch() error = %v", cycle, err)
		}
		assertActiveRoutingEpochSlot(t, activeMap, slot)
		if got, ok, err := candidateCore.RoutingEpochForSlot(slot); err != nil || !ok || got != epoch {
			t.Fatalf("cycle %d published epoch = (%d, %v, %v), want (%d, true, nil)", cycle, got, ok, err, epoch)
		}

		previous.retire(t)
		if previous == initial {
			if got := previous.runtime.activeReferences(); got != 2 {
				t.Fatalf("initial runtime references after owner retirement = %d, want 2 live-flow leases", got)
			}
			if previous.resourceCleanup.Load() != 0 || previous.underlay.closeCalls.Load() != 0 {
				t.Fatal("initial egress resources closed while long flows were active")
			}
		} else if previous.resourceCleanup.Load() != 1 || previous.underlay.closeCalls.Load() != 1 {
			t.Fatalf("generation %d cleanup = (runtime=%d, dialer=%d), want (1, 1)",
				previous.epoch, previous.resourceCleanup.Load(), previous.underlay.closeCalls.Load())
		}

		candidate.plane.RunReloadRetirementCleanup(0)
		if candidateCore.routingEpochPreviousSlot.Load() != routingEpochSlotUnset {
			t.Fatalf("cycle %d retained previous routing slot %d", cycle, candidateCore.routingEpochPreviousSlot.Load())
		}
		if got, ok, err := candidateCore.RoutingEpochForSlot(previousSlot); err != nil || ok || got != 0 {
			t.Fatalf("cycle %d retired slot metadata = (%d, %v, %v), want (0, false, nil)", cycle, got, ok, err)
		}

		if longTCP.flow.Context() != initialTCPContext || longUDP.runtime.ctx != initialUDPContext {
			t.Fatalf("cycle %d replaced a process-owned flow context", cycle)
		}
		select {
		case <-initialTCPContext.Done():
			t.Fatalf("cycle %d canceled the initial TCP flow", cycle)
		default:
		}
		select {
		case <-initialUDPContext.Done():
			t.Fatalf("cycle %d canceled the initial UDP flow", cycle)
		default:
		}
		if got := longTCP.flow.Binding(); got != initialTCPBinding {
			t.Fatalf("cycle %d changed initial TCP binding: got %+v, want %+v", cycle, got, initialTCPBinding)
		}
		if got := longUDP.runtime.binding; got != initialUDPBinding || longUDP.endpoint.FlowBinding() != initialUDPBinding {
			t.Fatalf("cycle %d changed initial UDP binding: runtime=%+v endpoint=%+v want=%+v",
				cycle, got, longUDP.endpoint.FlowBinding(), initialUDPBinding)
		}
		longTCP.exchange(t, []byte(fmt.Sprintf("tcp-long-%02d", cycle)))
		longUDP.exchange(t, quicPayload, []byte(fmt.Sprintf("quic-long-%02d", cycle)))

		newSrc := netip.MustParseAddrPort(fmt.Sprintf("192.0.2.30:%d", 33000+cycle))
		newDst := netip.MustParseAddrPort(fmt.Sprintf("198.51.100.%d:443", 20+cycle))
		newTCP := newReloadCycleTCPFlow(t, manager, candidate, newSrc, newDst)
		newUDP := newReloadCycleUDPFlow(t, manager, candidate,
			netip.MustParseAddrPort(fmt.Sprintf("192.0.2.40:%d", 34000+cycle)), newDst)
		if got := newTCP.flow.Binding(); got.Route.PolicyEpoch != epoch || got.Route.Mark != uint32(epoch)+1000 ||
			got.Egress.Dialer != candidate.dialer || got.Egress.Target != newDst.String() {
			t.Fatalf("cycle %d new TCP binding = %+v, want current generation", cycle, got)
		}
		if got := newUDP.runtime.binding; got.Route.PolicyEpoch != epoch || got.Route.Mark != uint32(epoch)+2000 ||
			got.Egress.Dialer != candidate.dialer || got.Egress.Target != newDst.String() {
			t.Fatalf("cycle %d new UDP binding = %+v, want current generation", cycle, got)
		}
		if newTCP.flow.Binding().Egress.Dialer == initialTCPBinding.Egress.Dialer ||
			newUDP.runtime.binding.Egress.Dialer == initialUDPBinding.Egress.Dialer {
			t.Fatalf("cycle %d new flow reused the initial dialer", cycle)
		}
		if manager.ActiveByGeneration(epoch) != 2 || manager.ActiveConnections() != 4 {
			t.Fatalf("cycle %d active flows = (epoch=%d, total=%d), want (2, 4)",
				cycle, manager.ActiveByGeneration(epoch), manager.ActiveConnections())
		}
		newTCP.exchange(t, []byte(fmt.Sprintf("tcp-new-%02d", cycle)))
		newUDP.exchange(t, quicPayload, []byte(fmt.Sprintf("quic-new-%02d", cycle)))
		newTCP.closeAndWait(t)
		newUDP.close(t)
		if manager.ActiveByGeneration(epoch) != 0 || manager.ActiveConnections() != 2 {
			t.Fatalf("cycle %d post-close flows = (epoch=%d, total=%d), want (0, 2)",
				cycle, manager.ActiveByGeneration(epoch), manager.ActiveConnections())
		}
		select {
		case <-manager.GenerationIdle(epoch):
		default:
			t.Fatalf("cycle %d generation remains flow-owned", cycle)
		}
		if manager.ActiveByGeneration(initialEpoch) != 2 {
			t.Fatalf("cycle %d initial flow count = %d, want 2", cycle, manager.ActiveByGeneration(initialEpoch))
		}
		previous = candidate
	}

	previous.retire(t)
	if previous.resourceCleanup.Load() != 1 || previous.underlay.closeCalls.Load() != 1 {
		t.Fatalf("final generation cleanup = (runtime=%d, dialer=%d), want (1, 1)",
			previous.resourceCleanup.Load(), previous.underlay.closeCalls.Load())
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("SessionManager.Close() error = %v", err)
	}
	_ = longTCP.client.Close()
	_ = longTCP.server.Close()
	select {
	case err := <-longTCP.done:
		if err != nil && !stderrors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("long TCP relay exit error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for long TCP relay shutdown")
	}
	if initial.resourceCleanup.Load() != 1 || initial.underlay.closeCalls.Load() != 1 {
		t.Fatalf("initial final cleanup = (runtime=%d, dialer=%d), want (1, 1)",
			initial.resourceCleanup.Load(), initial.underlay.closeCalls.Load())
	}
	if manager.ActiveConnections() != 0 {
		t.Fatalf("active flows after manager close = %d, want 0", manager.ActiveConnections())
	}
}

type reloadCycleCountingConn struct {
	net.Conn
	closeCalls atomic.Int32
}

func (c *reloadCycleCountingConn) Close() error {
	c.closeCalls.Add(1)
	return c.Conn.Close()
}

func TestSessionManagerCloseMixedFlowsIsConcurrentExactlyOnce(t *testing.T) {
	manager := NewSessionManager(context.Background())
	generation := newReloadCycleGeneration(t, 77, nil)

	ingressRaw, ingressPeer := net.Pipe()
	egressRaw, egressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	defer func() { _ = egressPeer.Close() }()
	ingress := &reloadCycleCountingConn{Conn: ingressRaw}
	egress := &reloadCycleCountingConn{Conn: egressRaw}
	tcpFlow, err := manager.adoptTCP(
		ingress,
		egress,
		generation.tcpBinding("198.51.100.77:443"),
		generation.runtime,
		nil,
	)
	if err != nil {
		t.Fatalf("adoptTCP() error = %v", err)
	}

	packetConn := newReloadCyclePacketConn()
	udpBinding := generation.udpBinding("198.51.100.78:443")
	endpoint := &UdpEndpoint{
		conn:                packetConn,
		NatTimeout:          QuicNatTimeout,
		Dialer:              udpBinding.Egress.Dialer,
		Outbound:            udpBinding.Egress.Outbound,
		DialTarget:          udpBinding.Egress.Target,
		poolKey:             UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.77:37777"), Dst: netip.MustParseAddrPort("198.51.100.78:443")},
		endpointNetworkType: udpBinding.Egress.NetworkType,
	}
	udpFlow, err := manager.adoptUDP(endpoint, udpBinding, generation.runtime)
	if err != nil {
		t.Fatalf("adoptUDP() error = %v", err)
	}
	generation.retire(t)
	if generation.runtime.activeReferences() != 2 {
		t.Fatalf("runtime references before mixed close = %d, want 2", generation.runtime.activeReferences())
	}

	const callers = 96
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				errs <- manager.Close()
			case 1:
				errs <- tcpFlow.abort()
			case 2:
				errs <- udpFlow.abort()
			default:
				errs <- endpoint.Close()
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("mixed close error = %v", err)
		}
	}

	if err := manager.Close(); err != nil {
		t.Fatalf("repeated manager Close() error = %v", err)
	}
	if err := tcpFlow.abort(); err != nil {
		t.Fatalf("repeated TCP abort error = %v", err)
	}
	if err := udpFlow.abort(); err != nil {
		t.Fatalf("repeated UDP abort error = %v", err)
	}
	if err := endpoint.Close(); err != nil {
		t.Fatalf("repeated endpoint Close() error = %v", err)
	}

	if got := ingress.closeCalls.Load(); got != 1 {
		t.Fatalf("TCP ingress close calls = %d, want 1", got)
	}
	if got := egress.closeCalls.Load(); got != 1 {
		t.Fatalf("TCP egress close calls = %d, want 1", got)
	}
	if got := packetConn.closeCalls.Load(); got != 1 {
		t.Fatalf("UDP packet connection close calls = %d, want 1", got)
	}
	if got := generation.resourceCleanup.Load(); got != 1 {
		t.Fatalf("egress runtime cleanup calls = %d, want 1", got)
	}
	if got := generation.underlay.closeCalls.Load(); got != 1 {
		t.Fatalf("selected dialer close calls = %d, want 1", got)
	}
	if manager.ActiveConnections() != 0 || manager.ActiveByGeneration(generation.epoch) != 0 {
		t.Fatalf("flows after mixed close = (total=%d, generation=%d), want (0, 0)",
			manager.ActiveConnections(), manager.ActiveByGeneration(generation.epoch))
	}
	select {
	case <-tcpFlow.Context().Done():
	default:
		t.Fatal("TCP flow context remains active after mixed close")
	}
	select {
	case <-udpFlow.ctx.Done():
	default:
		t.Fatal("UDP flow context remains active after mixed close")
	}
	select {
	case <-manager.GenerationIdle(generation.epoch):
	default:
		t.Fatal("generation idle signal remains open after mixed close")
	}
}
