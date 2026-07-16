/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
)

func TestUdpFlowBindingKeepsRouteAndEgressSeparate(t *testing.T) {
	program, err := routing.NewNormalizedProgram(nil, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	snapshot, err := routing.NewPolicySnapshot(9, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	networkType := dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_4,
	}
	option := &DialOption{
		Target:        "198.51.100.10:443",
		Network:       "udp+4",
		NetworkType:   &networkType,
		SniffedDomain: "example.com",
		IsDialIp:      true,
	}
	binding := newUdpFlowBinding(snapshot, 7, 42, true, option)

	if binding.Route.PolicyEpoch != snapshot.Epoch() || binding.Route.Outbound != 7 || binding.Route.Mark != 42 || !binding.Route.Must {
		t.Fatalf("route binding = %+v", binding.Route)
	}
	if binding.Egress.Target != option.Target || binding.Egress.Network != option.Network || binding.Egress.NetworkType != networkType || binding.Egress.SniffedDomain != option.SniffedDomain || binding.Egress.IsDialIp != option.IsDialIp {
		t.Fatalf("egress binding = %+v", binding.Egress)
	}

	endpoint := &UdpEndpoint{binding: binding}
	if got := endpoint.FlowBinding(); got != binding {
		t.Fatalf("FlowBinding() = %+v, want %+v", got, binding)
	}
}

func TestUdpEndpointPoolPreservesOriginalFlowBindingOnReuse(t *testing.T) {
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)
	firstTracker := newControlPlaneDrainTracker()
	secondTracker := newControlPlaneDrainTracker()

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d := newTestEndpointDialer(conn)
	t.Cleanup(func() { _ = d.Close() })

	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000")}
	firstBinding := UdpFlowBinding{
		Route: UdpRouteBinding{
			PolicyEpoch: 1,
			Outbound:    consts.OutboundUserDefinedMin,
			Mark:        11,
		},
		Egress: UdpEgressBinding{
			Dialer:  d,
			Target:  "198.51.100.1:443",
			Network: "udp+4",
		},
	}
	firstOptions := &UdpEndpointOptions{
		Handler:      func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
		DrainTracker: firstTracker,
		GetDialOption: func(context.Context) (*DialOption, error) {
			return &DialOption{
				Dialer:  d,
				Network: "udp+4",
				Target:  "198.51.100.1:443",
				Binding: firstBinding,
			}, nil
		},
	}

	first, isNew, err := pool.GetOrCreate(key, firstOptions)
	if err != nil || !isNew {
		t.Fatalf("first GetOrCreate() = (%v, %v, %v), want new endpoint", first, isNew, err)
	}

	secondBinding := firstBinding
	secondBinding.Route.PolicyEpoch = 2
	secondBinding.Route.Mark = 22
	secondBinding.Egress.Target = "203.0.113.2:443"
	secondDialCalled := false
	secondOptions := &UdpEndpointOptions{
		Handler:      func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
		DrainTracker: secondTracker,
		GetDialOption: func(context.Context) (*DialOption, error) {
			secondDialCalled = true
			return &DialOption{Binding: secondBinding}, nil
		},
	}

	second, isNew, err := pool.GetOrCreate(key, secondOptions)
	if err != nil || isNew {
		t.Fatalf("second GetOrCreate() = (%v, %v, %v), want existing endpoint", second, isNew, err)
	}
	if second != first {
		t.Fatal("reused endpoint differs from original endpoint")
	}
	if secondDialCalled {
		t.Fatal("GetDialOption ran while reusing an existing endpoint")
	}
	if got := second.FlowBinding(); got != firstBinding {
		t.Fatalf("reused binding = %+v, want original %+v", got, firstBinding)
	}
	if got := firstTracker.Count(); got != 1 {
		t.Fatalf("original generation active endpoint count = %d, want 1", got)
	}
	if got := secondTracker.Count(); got != 0 {
		t.Fatalf("successor generation active endpoint count = %d, want 0", got)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close reused endpoint: %v", err)
	}
	if got := firstTracker.Count(); got != 0 {
		t.Fatalf("closed endpoint left original generation count = %d, want 0", got)
	}
}
