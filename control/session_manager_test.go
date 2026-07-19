/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/component/routing"
	"golang.org/x/sys/unix"
)

func TestSessionManagerFlowRuntimeSurvivesGenerationContextCancellation(t *testing.T) {
	processCtx, processCancel := context.WithCancel(context.Background())
	defer processCancel()
	manager := NewSessionManager(processCtx)
	defer func() { _ = manager.Close() }()

	generationCtx, cancelGeneration := context.WithCancel(context.Background())
	_ = generationCtx
	ingress, ingressPeer := net.Pipe()
	egress, egressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	defer func() { _ = egressPeer.Close() }()

	epoch := routing.PolicyEpoch(7)
	flow, err := manager.adoptTCP(ingress, egress, TcpFlowBinding{Route: TcpRouteBinding{PolicyEpoch: epoch}}, nil, nil)
	if err != nil {
		t.Fatalf("adoptTCP() error = %v", err)
	}
	cancelGeneration()
	select {
	case <-flow.Context().Done():
		t.Fatal("process-owned flow was canceled with generation context")
	default:
	}
	flow.finish()
	if manager.ActiveTCPConnections() != 0 || manager.ActiveByGeneration(epoch) != 0 {
		t.Fatal("flow remained registered after finish")
	}
}

func indexedUDPFlowForTest(src netip.AddrPort, epoch routing.PolicyEpoch) *UDPFlowRuntime {
	endpoint := &UdpEndpoint{poolKey: UdpEndpointKey{Src: src}}
	return &UDPFlowRuntime{
		endpoint: endpoint,
		binding: UdpFlowBinding{Route: UdpRouteBinding{
			PolicyEpoch: epoch,
		}},
	}
}

func TestSessionManagerUDPSourceIndexUsesImmutableSnapshots(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.0.2.40:53000")
	first := indexedUDPFlowForTest(src, 1)
	second := indexedUDPFlowForTest(src, 2)

	manager.mu.Lock()
	manager.appendUDPFlowSourceLocked(src, first)
	manager.mu.Unlock()
	value, ok := manager.udpBySource.Load(src)
	if !ok {
		t.Fatal("first source snapshot was not published")
	}
	firstSnapshot := value.(*udpFlowSourceSnapshot)

	manager.mu.Lock()
	manager.appendUDPFlowSourceLocked(src, second)
	manager.mu.Unlock()
	value, ok = manager.udpBySource.Load(src)
	if !ok {
		t.Fatal("second source snapshot was not published")
	}
	secondSnapshot := value.(*udpFlowSourceSnapshot)
	if len(firstSnapshot.flows) != 1 || firstSnapshot.flows[0] != first {
		t.Fatalf("published snapshot mutated after append: %+v", firstSnapshot.flows)
	}
	if len(secondSnapshot.flows) != 2 || secondSnapshot.flows[0] != first || secondSnapshot.flows[1] != second {
		t.Fatalf("second snapshot = %+v, want first and second flows", secondSnapshot.flows)
	}

	manager.mu.Lock()
	manager.removeUDPFlowSourceLocked(src, first)
	manager.mu.Unlock()
	value, ok = manager.udpBySource.Load(src)
	if !ok {
		t.Fatal("source snapshot disappeared while one flow remained")
	}
	remaining := value.(*udpFlowSourceSnapshot)
	if len(remaining.flows) != 1 || remaining.flows[0] != second {
		t.Fatalf("remaining snapshot = %+v, want second flow", remaining.flows)
	}
	if len(secondSnapshot.flows) != 2 {
		t.Fatal("published snapshot mutated after removal")
	}
}

func TestSessionManagerRetainedUDPEndpointLookupDoesNotTakeManagerLock(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.0.2.41:53001")
	dst := netip.MustParseAddrPort("198.51.100.41:443")
	flow := indexedUDPFlowForTest(src, 1)
	manager.mu.Lock()
	manager.appendUDPFlowSourceLocked(src, flow)
	manager.mu.Unlock()

	manager.mu.Lock()
	result := make(chan *UdpEndpoint, 1)
	go func() {
		endpoint, _ := manager.retainedUDPEndpoint(src, dst, nil, 2)
		result <- endpoint
	}()
	var endpoint *UdpEndpoint
	completedWithoutLock := false
	select {
	case endpoint = <-result:
		completedWithoutLock = true
	case <-time.After(250 * time.Millisecond):
	}
	manager.mu.Unlock()
	if !completedWithoutLock {
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatal("retained UDP lookup blocked on SessionManager.mu")
	}
	if endpoint != flow.endpoint {
		t.Fatalf("retained UDP endpoint = %p, want %p", endpoint, flow.endpoint)
	}
}

func TestSessionManagerRetainedUDPEndpointWarmLookupAllocations(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.0.2.42:53002")
	dst := netip.MustParseAddrPort("198.51.100.42:443")
	flow := indexedUDPFlowForTest(src, 1)
	manager.mu.Lock()
	manager.appendUDPFlowSourceLocked(src, flow)
	manager.mu.Unlock()

	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = manager.retainedUDPEndpoint(src, dst, nil, 2)
	})
	if allocs != 0 {
		t.Fatalf("warm retained UDP lookup allocations = %v, want 0", allocs)
	}
}

func TestSessionManagerUDPSourceIndexConcurrentCOWLookup(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.0.2.44:53004")
	dst := netip.MustParseAddrPort("198.51.100.44:443")
	base := indexedUDPFlowForTest(src, 1)
	manager.mu.Lock()
	manager.appendUDPFlowSourceLocked(src, base)
	manager.mu.Unlock()

	const iterations = 1000
	start := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for range iterations {
				endpoint, ok := manager.retainedUDPEndpoint(src, dst, nil, 2)
				if !ok || endpoint == nil {
					t.Errorf("retained UDP lookup missed the stable old flow")
					return
				}
			}
		}()
	}
	close(start)
	for range iterations {
		transient := indexedUDPFlowForTest(src, 2)
		manager.mu.Lock()
		manager.appendUDPFlowSourceLocked(src, transient)
		manager.removeUDPFlowSourceLocked(src, transient)
		manager.mu.Unlock()
	}
	readers.Wait()
}

func TestSessionManagerRetainedUDPFlowSurvivesDatapathAndSlotReuse(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	connMap := newJanitorTestMap(t, "conn_state_map")
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connMap}})

	src := netip.MustParseAddrPort("192.0.2.45:53005")
	dst := netip.MustParseAddrPort("198.51.100.45:443")
	result := &bpfRoutingResult{
		Outbound:           3,
		Mark:               17,
		RoutingEpochSlot:   bpfRoutingEpochSlot0Encoded,
		DatapathGeneration: 1,
	}
	flow := indexedUDPFlowForTest(src, 1)
	flow.endpoint.poolKey = UdpEndpointKey{
		Src:        src,
		Dst:        dst,
		RouteScope: newUdpEndpointRouteScope(result),
	}
	manager.mu.Lock()
	manager.appendUDPFlowSourceLocked(src, flow)
	manager.mu.Unlock()

	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_UDP),
		bpfTuplesKeyFromAddrPorts(dst, src, unix.IPPROTO_UDP),
	}
	for _, key := range keys {
		state := bpfConnState{LastSeenNs: 1, RoutingEpochSlot: result.RoutingEpochSlot, DatapathGeneration: 1}
		if err := connMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update conn-state: %v", err)
		}
	}
	manager.RetainUdpConnStateTuples(keys)
	defer func() { _ = manager.ReleaseUdpConnStateTuples(keys) }()

	for cycle := 1; cycle <= processFlowReloadCycles; cycle++ {
		result.RoutingEpochSlot = bpfRoutingEpochSlot0Encoded
		if cycle%2 != 0 {
			result.RoutingEpochSlot = bpfRoutingEpochSlot1Encoded
		}
		result.DatapathGeneration = uint16(cycle + 1)
		endpoint, ok := manager.retainedUDPEndpoint(src, dst, result, routing.PolicyEpoch(cycle+1))
		if !ok || endpoint != flow.endpoint {
			t.Fatalf("cycle %d retained endpoint = (%p, %v), want %p", cycle, endpoint, ok, flow.endpoint)
		}
		if retired, err := manager.retireUnpinnedUDPConnState(src, dst); retired || err != nil {
			t.Fatalf("cycle %d retire pinned conn-state = (%v, %v), want (false, nil)", cycle, retired, err)
		}
	}
}

func TestSessionManagerRetiresUnpinnedStaleUDPConnState(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	connMap := newJanitorTestMap(t, "conn_state_map")
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connMap}})

	src := netip.MustParseAddrPort("192.0.2.46:53006")
	dst := netip.MustParseAddrPort("198.51.100.46:443")
	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_UDP),
		bpfTuplesKeyFromAddrPorts(dst, src, unix.IPPROTO_UDP),
	}
	for _, key := range keys {
		state := bpfConnState{LastSeenNs: 1, RoutingEpochSlot: bpfRoutingEpochSlot0Encoded, DatapathGeneration: 1}
		if err := connMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update conn-state: %v", err)
		}
	}

	retired, err := manager.retireUnpinnedUDPConnState(src, dst)
	if err != nil || !retired {
		t.Fatalf("retireUnpinnedUDPConnState() = (%v, %v), want (true, nil)", retired, err)
	}
	for _, key := range keys {
		var state bpfConnState
		if err := connMap.Lookup(&key, &state); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("conn-state after retirement error = %v, want %v", err, ebpf.ErrKeyNotExist)
		}
	}
}

var (
	benchmarkRetainedUDPEndpoint *UdpEndpoint
	benchmarkRetainedUDPFound    bool
)

func BenchmarkSessionManagerRetainedUDPEndpointBySource(b *testing.B) {
	for _, tc := range []struct {
		name         string
		currentFlows int
		oldFlows     int
	}{
		{name: "current=0/old=0"},
		{name: "current=0/old=1", oldFlows: 1},
		{name: "current=0/old=64", oldFlows: 64},
		{name: "current=1/old=0", currentFlows: 1},
		{name: "current=1/old=1", currentFlows: 1, oldFlows: 1},
		{name: "current=1/old=64", currentFlows: 1, oldFlows: 64},
		{name: "current=64/old=0", currentFlows: 64},
		{name: "current=64/old=1", currentFlows: 64, oldFlows: 1},
		{name: "current=64/old=64", currentFlows: 64, oldFlows: 64},
	} {
		b.Run(tc.name, func(b *testing.B) {
			manager := NewSessionManager(context.Background())
			src := netip.MustParseAddrPort("192.0.2.43:53003")
			dst := netip.MustParseAddrPort("198.51.100.43:443")
			const currentEpoch routing.PolicyEpoch = 2
			flows := make([]*UDPFlowRuntime, 0, tc.currentFlows+tc.oldFlows)
			for range tc.currentFlows {
				flows = append(flows, indexedUDPFlowForTest(src, currentEpoch))
			}
			for range tc.oldFlows {
				flows = append(flows, indexedUDPFlowForTest(src, 1))
			}
			if len(flows) > 0 {
				manager.udpBySource.Store(src, &udpFlowSourceSnapshot{flows: flows})
			}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				benchmarkRetainedUDPEndpoint, benchmarkRetainedUDPFound = manager.retainedUDPEndpoint(src, dst, nil, currentEpoch)
			}
		})
	}
}

func TestControlPlaneSessionManagerWarmLookupAllocations(t *testing.T) {
	manager := NewSessionManager(context.Background())
	plane := &ControlPlane{sessionManager: manager}
	got, owned := plane.controlPlaneSessionManager()
	if got != manager || owned {
		t.Fatalf("controlPlaneSessionManager() = (%p, %v), want (%p, false)", got, owned, manager)
	}
	allocs := testing.AllocsPerRun(1000, func() {
		got, _ = plane.controlPlaneSessionManager()
	})
	if allocs != 0 {
		t.Fatalf("warm control-plane manager lookup allocations = %v, want 0", allocs)
	}
}

var benchmarkSessionManager *SessionManager

func BenchmarkControlPlaneSessionManagerLookup(b *testing.B) {
	manager := NewSessionManager(context.Background())
	plane := &ControlPlane{sessionManager: manager}
	_, _ = plane.controlPlaneSessionManager()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkSessionManager, _ = plane.controlPlaneSessionManager()
	}
}

func TestSessionManagerOwnsLocallyTerminatedTCPFlowWithoutEgress(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	ingress, peer := net.Pipe()
	defer func() { _ = peer.Close() }()

	flow, err := manager.adoptTCP(ingress, nil, TcpFlowBinding{}, nil, nil)
	if err != nil {
		t.Fatalf("adoptTCP() error = %v", err)
	}
	if flow.Egress() != nil {
		t.Fatal("locally terminated flow unexpectedly retained an egress")
	}
	if manager.ActiveTCPConnections() != 1 {
		t.Fatalf("active TCP flows = %d, want 1", manager.ActiveTCPConnections())
	}

	flow.finish()
	if manager.ActiveTCPConnections() != 0 {
		t.Fatalf("active TCP flows after finish = %d, want 0", manager.ActiveTCPConnections())
	}
}

func TestSessionManagerPinsFlowAndReleasesEgressRuntime(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	cleanupCalls := 0
	runtime := newEgressRuntime(nil, []func() error{func() error {
		cleanupCalls++
		return nil
	}})
	ingress, ingressPeer := net.Pipe()
	egress, egressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	defer func() { _ = egressPeer.Close() }()

	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, 6),
		bpfTuplesKeyFromAddrPorts(dst, src, 6),
	}
	epoch := routing.PolicyEpoch(11)
	flow, err := manager.adoptTCP(ingress, egress, TcpFlowBinding{Route: TcpRouteBinding{PolicyEpoch: epoch}}, runtime, keys)
	if err != nil {
		t.Fatalf("adoptTCP() error = %v", err)
	}
	if err := runtime.releaseOwner(); err != nil {
		t.Fatalf("releaseOwner() error = %v", err)
	}
	if cleanupCalls != 0 {
		t.Fatal("egress cleanup ran while flow was active")
	}
	for _, key := range keys {
		if !manager.isTCPConnStatePinned(key) {
			t.Fatalf("conn-state key %v is not pinned", key)
		}
	}
	flow.finish()
	if cleanupCalls != 1 {
		t.Fatalf("egress cleanup calls = %d, want 1", cleanupCalls)
	}
	for _, key := range keys {
		if manager.isTCPConnStatePinned(key) {
			t.Fatalf("conn-state key %v remained pinned", key)
		}
	}
}

func TestSessionManagerDeletesTCPConnStateWhenFlowEnds(t *testing.T) {
	connStateMap := newJanitorTestMap(t, "conn_state_map")
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connStateMap}})
	ingress, ingressPeer := net.Pipe()
	egress, egressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	defer func() { _ = egressPeer.Close() }()
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, 6),
		bpfTuplesKeyFromAddrPorts(dst, src, 6),
	}
	for _, key := range keys {
		state := bpfConnState{LastSeenNs: 1}
		if err := connStateMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update conn state: %v", err)
		}
	}
	flow, err := manager.adoptTCP(ingress, egress, TcpFlowBinding{}, nil, keys)
	if err != nil {
		t.Fatalf("adoptTCP() error = %v", err)
	}

	flow.finish()
	for _, key := range keys {
		var state bpfConnState
		if err := connStateMap.Lookup(&key, &state); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("conn state lookup after flow finish error = %v, want %v", err, ebpf.ErrKeyNotExist)
		}
	}
}

func TestSessionManagerAbortGenerationDoesNotAffectSuccessor(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	oldFlow := newSessionManagerTestFlow(t, manager, routing.PolicyEpoch(1))
	newFlow := newSessionManagerTestFlow(t, manager, routing.PolicyEpoch(2))

	if err := manager.AbortGeneration(1); err != nil {
		t.Fatalf("AbortGeneration() error = %v", err)
	}
	if manager.ActiveByGeneration(1) != 0 || manager.ActiveByGeneration(2) != 1 {
		t.Fatalf("generation counts = (%d, %d), want (0, 1)", manager.ActiveByGeneration(1), manager.ActiveByGeneration(2))
	}
	select {
	case <-oldFlow.Context().Done():
	default:
		t.Fatal("old flow context remains active")
	}
	select {
	case <-newFlow.Context().Done():
		t.Fatal("successor flow was canceled")
	default:
	}
}

func TestSessionManagerCloseRejectsNewFlows(t *testing.T) {
	manager := NewSessionManager(context.Background())
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	ingress, ingressPeer := net.Pipe()
	egress, egressPeer := net.Pipe()
	defer func() { _ = ingress.Close() }()
	defer func() { _ = ingressPeer.Close() }()
	defer func() { _ = egress.Close() }()
	defer func() { _ = egressPeer.Close() }()
	_, err := manager.adoptTCP(ingress, egress, TcpFlowBinding{}, nil, nil)
	if !stderrors.Is(err, ErrSessionManagerClosed) {
		t.Fatalf("adoptTCP() error = %v, want %v", err, ErrSessionManagerClosed)
	}
}

func TestControlPlanePendingAbortPreservesManagedTCPFlow(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	cp := &ControlPlane{}
	if err := cp.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager() error = %v", err)
	}
	flow := newSessionManagerTestFlow(t, manager, 0)

	if err := cp.AbortPendingConnections(); err != nil {
		t.Fatalf("AbortPendingConnections() error = %v", err)
	}
	select {
	case <-flow.Context().Done():
		t.Fatal("pending abort canceled an established process-owned flow")
	default:
	}
	if manager.ActiveTCPConnections() != 1 {
		t.Fatalf("active flows = %d, want 1", manager.ActiveTCPConnections())
	}

	if err := cp.AbortConnections(); err != nil {
		t.Fatalf("AbortConnections() error = %v", err)
	}
	select {
	case <-flow.Context().Done():
	default:
		t.Fatal("full abort did not cancel the established flow")
	}
}

func TestRetiredControlPlaneClosePreservesManagedTCPFlowAndEgressLease(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	cleanupCalls := 0
	runtime := newEgressRuntime(nil, []func() error{func() error {
		cleanupCalls++
		return nil
	}})
	cp := &ControlPlane{
		drainTracker:  newControlPlaneDrainTracker(),
		egressRuntime: runtime,
	}
	if err := cp.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager() error = %v", err)
	}
	ingress, ingressPeer := net.Pipe()
	egress, egressPeer := net.Pipe()
	defer func() { _ = ingressPeer.Close() }()
	defer func() { _ = egressPeer.Close() }()
	flow, err := manager.adoptTCP(ingress, egress, TcpFlowBinding{}, runtime, nil)
	if err != nil {
		t.Fatalf("adoptTCP() error = %v", err)
	}

	if err := cp.AbortPendingConnections(); err != nil {
		t.Fatalf("AbortPendingConnections() error = %v", err)
	}
	cp.StopRoutingEpochExecution()
	if err := cp.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-flow.Context().Done():
		t.Fatal("retired control plane canceled the process-owned flow")
	default:
	}
	if manager.ActiveTCPConnections() != 1 {
		t.Fatalf("active TCP flows = %d, want 1", manager.ActiveTCPConnections())
	}
	if cleanupCalls != 0 {
		t.Fatalf("egress cleanup calls while flow is active = %d, want 0", cleanupCalls)
	}

	flow.finish()
	if cleanupCalls != 1 {
		t.Fatalf("egress cleanup calls after flow finish = %d, want 1", cleanupCalls)
	}
}

func TestSessionManagerRetainedUDPFlowSurvivesPendingAbortAndUsesOriginalEgress(t *testing.T) {
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	oldPlane := &ControlPlane{}
	if err := oldPlane.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(old) error = %v", err)
	}
	successor := &ControlPlane{}
	if err := successor.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(successor) error = %v", err)
	}

	conn := &scriptedPacketConn{
		reads:        make(chan scriptedPacketRead),
		writeStarted: make(chan struct{}),
		closeCh:      make(chan struct{}),
	}
	d := newTestEndpointDialer(conn)
	t.Cleanup(func() { _ = d.Close() })
	src := netip.MustParseAddrPort("192.0.2.40:40000")
	dst := netip.MustParseAddrPort("198.51.100.50:443")
	binding := UdpFlowBinding{
		Route: UdpRouteBinding{PolicyEpoch: 9},
		Egress: UdpEgressBinding{
			Dialer:  d,
			Target:  dst.String(),
			Network: "udp+4",
		},
	}
	endpoint := &UdpEndpoint{
		conn:                conn,
		NatTimeout:          QuicNatTimeout,
		Dialer:              d,
		DialTarget:          dst.String(),
		poolKey:             UdpEndpointKey{Src: src, Dst: dst},
		udpConnStateOwner:   manager,
		endpointNetworkType: binding.Egress.NetworkType,
	}
	endpoint.hasSent.Store(true)
	endpoint.setFlowBinding(binding)

	cleanupCalls := 0
	runtime := newEgressRuntime(nil, []func() error{func() error {
		cleanupCalls++
		return nil
	}})
	if _, err := manager.adoptUDP(endpoint, binding, runtime); err != nil {
		t.Fatalf("adoptUDP() error = %v", err)
	}
	endpoint.TrackUdpConnStateTuplePair(src, dst)
	if err := runtime.releaseOwner(); err != nil {
		t.Fatalf("releaseOwner() error = %v", err)
	}
	if err := oldPlane.AbortPendingConnections(); err != nil {
		t.Fatalf("AbortPendingConnections() error = %v", err)
	}
	if endpoint.IsDead() || manager.ActiveUDPConnections() != 1 || cleanupCalls != 0 {
		t.Fatalf("pending abort changed retained UDP flow: dead=%v active=%d cleanup=%d", endpoint.IsDead(), manager.ActiveUDPConnections(), cleanupCalls)
	}

	handled, err := successor.handleRetainedUDPEndpoint([]byte("still-alive"), src, dst, &bpfRoutingResult{}, ClassifyUdpFlow(src, dst, nil))
	if err != nil || !handled {
		t.Fatalf("handleRetainedUDPEndpoint() = (%v, %v), want handled", handled, err)
	}
	select {
	case <-conn.writeStarted:
	default:
		t.Fatal("retained UDP packet did not use the original egress")
	}

	if err := manager.AbortGeneration(binding.Route.PolicyEpoch); err != nil {
		t.Fatalf("AbortGeneration() error = %v", err)
	}
	if manager.ActiveUDPConnections() != 0 || cleanupCalls != 1 {
		t.Fatalf("full abort cleanup = (active=%d, cleanup=%d), want (0, 1)", manager.ActiveUDPConnections(), cleanupCalls)
	}
	select {
	case <-conn.closeCh:
	default:
		t.Fatal("full abort did not close original UDP egress")
	}
}

func newSessionManagerTestFlow(t *testing.T, manager *SessionManager, epoch routing.PolicyEpoch) *FlowRuntime {
	t.Helper()
	ingress, ingressPeer := net.Pipe()
	egress, egressPeer := net.Pipe()
	t.Cleanup(func() { _ = ingressPeer.Close() })
	t.Cleanup(func() { _ = egressPeer.Close() })
	flow, err := manager.adoptTCP(ingress, egress, TcpFlowBinding{Route: TcpRouteBinding{PolicyEpoch: epoch}}, nil, nil)
	if err != nil {
		t.Fatalf("adoptTCP() error = %v", err)
	}
	return flow
}
