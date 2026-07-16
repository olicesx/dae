/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
)

func TestRouteDial_RetriesAlternateFamilyAfterLocalNetworkFailure(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	d, underlay := newSequenceProxyEndpointDialer(
		"shadowsocks_2022",
		"proxy.example:443",
		scriptedDialResult{err: daerrors.ErrNetworkUnreachable},
		scriptedDialResult{conn: clientConn},
	)
	cp := newTestDialControlPlane(newTestFixedOutboundGroup(d))

	conn, res, err := cp.routeDial(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("[2001:db8::10]:42687"),
		Dest:     netip.MustParseAddrPort("[2606:4700:4700::1111]:443"),
		Network:  "tcp",
	})
	if err != nil {
		t.Fatalf("routeDial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls = %d, want 2", got)
	}
	if got := res.SelectionNetworkTypeObj.IpVersion; got != consts.IpVersionStr_4 {
		t.Fatalf("selection ip version = %v, want %v", got, consts.IpVersionStr_4)
	}
	if res.Binding.Route.Outbound != res.OutboundIndex || res.Binding.Route.Mark != res.Mark || res.Binding.Route.Must != res.Must {
		t.Fatalf("route binding = %+v, want final result %+v", res.Binding.Route, res)
	}
	if res.Binding.Egress.Dialer != res.Dialer || res.Binding.Egress.Outbound != res.Outbound || res.Binding.Egress.Target != res.DialTarget || res.Binding.Egress.Network != res.Network || res.Binding.Egress.NetworkType != *res.SelectionNetworkTypeObj {
		t.Fatalf("egress binding = %+v, want final result %+v", res.Binding.Egress, res)
	}
	if got := res.Binding.Egress.NetworkType.IpVersion; got != consts.IpVersionStr_4 {
		t.Fatalf("bound selection ip version = %v, want %v", got, consts.IpVersionStr_4)
	}
}
