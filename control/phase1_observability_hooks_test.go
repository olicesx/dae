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
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func TestPhase1RoutingLookupHooksObserveFinalPath(t *testing.T) {
	recorder := installPhase1ObservabilityForTest(t, 1)
	src := netip.MustParseAddrPort("192.0.2.10:12345")
	dst := netip.MustParseAddrPort("198.51.100.20:443")

	var unavailable *controlPlaneCore
	if _, err := unavailable.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("unavailable RetrieveRoutingResult() error = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if got := recorder.routingLookupCount(phase1RoutingLookupUnavailable, phase1RoutingLookupMiss); got != 1 {
		t.Fatalf("unavailable lookup miss count = %d, want 1", got)
	}

	core := &controlPlaneCore{}
	core.bpf.Store(&bpfObjects{})
	if _, err := core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("handoff-miss RetrieveRoutingResult() error = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if got := recorder.routingLookupCount(phase1RoutingLookupHandoff, phase1RoutingLookupMiss); got != 1 {
		t.Fatalf("handoff lookup miss count = %d, want 1", got)
	}
	if got := recorder.routingLookupCount(phase1RoutingLookupEmbedded, phase1RoutingLookupMiss); got != 0 {
		t.Fatalf("embedded provisional miss count = %d, want 0", got)
	}
}

func TestPhase1ChooseProxyDialerHooksObserveUserspaceRematch(t *testing.T) {
	recorder := installPhase1ObservabilityForTest(t, 1)
	cp := newTestDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	cp.routingMatcher = newTestControlPlaneWithDscpRule(t, "0").routingMatcher
	cp.log = logrus.New()

	if _, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Dscp:     0,
		Src:      netip.MustParseAddrPort("192.0.2.10:12345"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "tcp",
	}); err != nil {
		t.Fatalf("chooseProxyDialer() error = %v", err)
	}
	if got := recorder.userspaceRematchCount(phase1TransportTCP, phase1UserspaceRematchSuccess); got != 1 {
		t.Fatalf("userspace rematch success count = %d, want 1", got)
	}
	if got := recorder.dialCount(phase1DialOperationSelectPrimary, phase1TransportTCP, phase1DialOutcomeSuccess); got != 1 {
		t.Fatalf("primary selection success count = %d, want 1", got)
	}
}

func TestPhase1RouteDialHooksObserveRetry(t *testing.T) {
	recorder := installPhase1ObservabilityForTest(t, 1)
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })

	dialer, _ := newSequenceProxyEndpointDialer(
		"shadowsocks_2022",
		"proxy.example:443",
		scriptedDialResult{err: daerrors.ErrNetworkUnreachable},
		scriptedDialResult{conn: clientConn},
	)
	cp := newTestDialControlPlane(newTestFixedOutboundGroup(dialer))
	conn, _, err := cp.routeDial(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("[2001:db8::10]:42687"),
		Dest:     netip.MustParseAddrPort("[2606:4700:4700::1111]:443"),
		Network:  "tcp",
	})
	if err != nil {
		t.Fatalf("routeDial() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	for _, tt := range []struct {
		operation phase1DialOperation
		outcome   phase1DialOutcome
		want      uint64
	}{
		{phase1DialOperationSelectPrimary, phase1DialOutcomeSuccess, 2},
		{phase1DialOperationConnectInitial, phase1DialOutcomeFailure, 1},
		{phase1DialOperationConnectRetry, phase1DialOutcomeSuccess, 1},
	} {
		if got := recorder.dialCount(tt.operation, phase1TransportTCP, tt.outcome); got != tt.want {
			t.Fatalf("dial count operation=%d outcome=%d = %d, want %d", tt.operation, tt.outcome, got, tt.want)
		}
	}
}

func TestPhase1UDPKeyProbeHooksObservePrimaryReuse(t *testing.T) {
	recorder := installPhase1ObservabilityForTest(t, 1)
	oldPool := DefaultUdpEndpointPool
	pool := NewUdpEndpointPool()
	DefaultUdpEndpointPool = pool
	t.Cleanup(func() {
		pool.Reset()
		DefaultUdpEndpointPool = oldPool
	})

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	dialer, _ := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	plane := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(dialer))
	src := netip.MustParseAddrPort("192.0.2.10:41000")
	dst := netip.MustParseAddrPort("198.51.100.20:3478")
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	flow := ClassifyUdpFlow(src, dst, payload)
	if flow.IsQuicInitial || flow.AllowsSniffing {
		t.Fatal("test payload unexpectedly enabled UDP sniffing")
	}
	routingResult := &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin)}

	if err := plane.handlePkt(nil, payload, src, dst, routingResult, flow, false); err != nil {
		t.Fatalf("first handlePkt() error = %v", err)
	}
	if err := plane.handlePkt(nil, payload, src, dst, routingResult, flow, false); err != nil {
		t.Fatalf("second handlePkt() error = %v", err)
	}

	if got := recorder.udpKeyProbeCount(phase1UDPKeyProbePrimary, phase1UDPKeyProbeMiss); got != 1 {
		t.Fatalf("primary probe miss count = %d, want 1", got)
	}
	if got := recorder.udpKeyProbeCount(phase1UDPKeyProbePrimary, phase1UDPKeyProbeHit); got != 1 {
		t.Fatalf("primary probe hit count = %d, want 1", got)
	}

	endpoint, ok := pool.Get(flow.FullConeNatEndpointKey())
	if !ok || endpoint == nil {
		t.Fatal("expected reusable UDP endpoint")
	}
	if err := endpoint.Close(); err != nil {
		t.Fatalf("close endpoint: %v", err)
	}
}

func TestPhase1BPFPublishHooksObserveEpochOperations(t *testing.T) {
	recorder := installPhase1ObservabilityForTest(t, 1)
	core := &controlPlaneCore{}

	if _, err := core.PrepareRoutingEpoch(0, true); err == nil {
		t.Fatal("PrepareRoutingEpoch(0) error = nil, want error")
	}
	if got := recorder.bpfPublishCount(phase1BPFPublishPrepare, phase1BPFPublishFailure); got != 1 {
		t.Fatalf("prepare failure count = %d, want 1", got)
	}

	activeMap := newJanitorTestMap(t, "active_routing_epoch_map")
	epochMap := newJanitorTestMap(t, "routing_epoch_map")
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			ActiveRoutingEpochMap: activeMap,
			RoutingEpochMap:       epochMap,
		},
	})

	if _, err := core.PrepareRoutingEpoch(23, true); err != nil {
		t.Fatalf("PrepareRoutingEpoch() error = %v", err)
	}
	if err := core.StageRoutingEpoch(); err != nil {
		t.Fatalf("StageRoutingEpoch() error = %v", err)
	}
	if err := core.PublishRoutingEpoch(); err != nil {
		t.Fatalf("PublishRoutingEpoch() error = %v", err)
	}
	if err := core.RollbackRoutingEpoch(); err != nil {
		t.Fatalf("RollbackRoutingEpoch() error = %v", err)
	}

	for _, phase := range []phase1BPFPublishPhase{
		phase1BPFPublishPrepare,
		phase1BPFPublishStage,
		phase1BPFPublishPublish,
		phase1BPFPublishRollback,
	} {
		if got := recorder.bpfPublishCount(phase, phase1BPFPublishSuccess); got != 1 {
			t.Fatalf("phase %d success count = %d, want 1", phase, got)
		}
		var latencySamples uint64
		for bucket := phase1LatencyBucket(0); bucket < phase1LatencyBucketCount; bucket++ {
			latencySamples += recorder.bpfPublishLatencyCount(phase, phase1BPFPublishSuccess, bucket)
		}
		if latencySamples != 1 {
			t.Fatalf("phase %d latency samples = %d, want 1", phase, latencySamples)
		}
	}
}
