/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRoutingTraceDNSProjectionDeduplicatesAndBoundsFanout(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("2001:db8::1")
	lookups := []control.TraceDNSResult{
		{Question: dnsmessage.Question{Name: "trace.example.", Qtype: dnsmessage.TypeA}, Status: "NOERROR", Addresses: []netip.Addr{a, a}},
		{Question: dnsmessage.Question{Name: "trace.example.", Qtype: dnsmessage.TypeAAAA}, Status: "NOERROR", Addresses: []netip.Addr{a, b}},
	}
	destinations, dns, err := projectRoutingTraceDNS(lookups, nativeapi.MaxRoutingTraceRuleSteps/2)
	require.NoError(t, err)
	require.Equal(t, []*netip.Addr{&a, &b}, destinations)
	require.Equal(t, []string{a.String()}, dns[0].Addresses)
	require.Equal(t, []string{a.String(), b.String()}, dns[1].Addresses)
	require.Equal(t, "bypass", dns[0].Cache)
	require.NotEqual(t, dns[0].LookupID, dns[1].LookupID)
	require.Nil(t, dns[0].AttemptID)

	_, _, err = projectRoutingTraceDNS(lookups, nativeapi.MaxRoutingTraceRuleSteps/2+1)
	var apiErr *nativeapi.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusRequestEntityTooLarge, apiErr.Status)

	addresses := make([]netip.Addr, nativeapi.RoutingTraceMaxAddresses+1)
	for i := range addresses {
		addresses[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
	}
	lookups[0].Addresses = addresses
	_, _, err = projectRoutingTraceDNS(lookups[:1], 1)
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusRequestEntityTooLarge, apiErr.Status)
}
