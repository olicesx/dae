/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
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
	}
	binding := newUdpFlowBinding(snapshot, 7, 42, true, option)

	if binding.Route.PolicyEpoch != snapshot.Epoch() || binding.Route.Outbound != 7 || binding.Route.Mark != 42 || !binding.Route.Must {
		t.Fatalf("route binding = %+v", binding.Route)
	}
	if binding.Egress.Target != option.Target || binding.Egress.Network != option.Network || binding.Egress.NetworkType != networkType || binding.Egress.SniffedDomain != option.SniffedDomain {
		t.Fatalf("egress binding = %+v", binding.Egress)
	}

	endpoint := &UdpEndpoint{binding: binding}
	if got := endpoint.FlowBinding(); got != binding {
		t.Fatalf("FlowBinding() = %+v, want %+v", got, binding)
	}
}
