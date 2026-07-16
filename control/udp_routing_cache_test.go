/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUdpEndpointRoutingCache_HitAndExpire(t *testing.T) {
	oldTTL := UdpRoutingResultCacheTtl
	UdpRoutingResultCacheTtl = 20 * time.Millisecond
	defer func() { UdpRoutingResultCacheTtl = oldTTL }()

	ue := &UdpEndpoint{}
	dst := netip.MustParseAddrPort("1.1.1.1:443")
	otherDst := netip.MustParseAddrPort("8.8.8.8:53")
	l4proto := uint8(17)

	if got, ok := ue.GetCachedRoutingResult(dst, l4proto); ok || got != nil {
		t.Fatalf("expected empty cache")
	}

	rr := &bpfRoutingResult{
		Mark:     123,
		Outbound: 2,
		Dscp:     10,
	}
	ue.UpdateCachedRoutingResult(dst, l4proto, rr)

	got, ok := ue.GetCachedRoutingResult(dst, l4proto)
	require.True(t, ok)
	require.NotNil(t, got)
	require.Equal(t, rr.Mark, got.Mark)
	require.Equal(t, rr.Outbound, got.Outbound)
	require.Equal(t, rr.Dscp, got.Dscp)

	got, ok = ue.GetCachedRoutingResult(otherDst, l4proto)
	require.False(t, ok)
	require.Nil(t, got)

	time.Sleep(2 * UdpRoutingResultCacheTtl)
	got, ok = ue.GetCachedRoutingResult(dst, l4proto)
	require.False(t, ok)
	require.Nil(t, got)
}

func TestUdpEndpointRouteBindingPersistsBeyondCacheTTL(t *testing.T) {
	oldTTL := UdpRoutingResultCacheTtl
	UdpRoutingResultCacheTtl = 10 * time.Millisecond
	defer func() { UdpRoutingResultCacheTtl = oldTTL }()

	ue := &UdpEndpoint{}
	dst := netip.MustParseAddrPort("203.0.113.42:443")
	otherDst := netip.MustParseAddrPort("203.0.113.43:443")
	const l4proto = uint8(17)
	routingResult := &bpfRoutingResult{Mark: 77, Outbound: 3, Dscp: 12}
	ue.UpdateCachedRoutingResult(dst, l4proto, routingResult)

	time.Sleep(2 * UdpRoutingResultCacheTtl)
	if cached, ok := ue.GetCachedRoutingResult(dst, l4proto); ok || cached != nil {
		t.Fatal("short-lived routing cache remained valid after its TTL")
	}
	bound, ok := ue.GetBoundRoutingResult(dst, l4proto)
	require.True(t, ok)
	require.NotNil(t, bound)
	require.Equal(t, routingResult.Mark, bound.Mark)
	require.Equal(t, routingResult.Outbound, bound.Outbound)
	if other, ok := ue.GetBoundRoutingResult(otherDst, l4proto); ok || other != nil {
		t.Fatal("route binding matched a different original destination")
	}
}
