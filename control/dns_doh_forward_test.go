/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

func TestDoH_ForwardDNS_RetriesOnClosedConnection(t *testing.T) {
	orig := sendHttpDNSFunc
	t.Cleanup(func() { sendHttpDNSFunc = orig })

	attempts := 0
	sendHttpDNSFunc = func(_ *http.Client, _ string, _ *dns.Upstream, _ []byte) (*dnsmessage.Msg, error) {
		attempts++
		if attempts == 1 {
			return nil, net.ErrClosed
		}
		return &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{Id: 42}}, nil
	}

	d := &DoH{
		Upstream: dns.Upstream{
			Scheme:   dns.UpstreamScheme_HTTPS,
			Hostname: "223.5.5.5",
			Port:     443,
			Path:     "/dns-query",
		},
		dialArgument: dialArgument{bestTarget: netip.MustParseAddrPort("223.5.5.5:443")},
	}
	d.clientFactory = func() *http.Client { return &http.Client{} }

	msg, err := d.ForwardDNS(context.Background(), []byte("query"))
	if err != nil {
		t.Fatalf("ForwardDNS: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (one retry after net.ErrClosed)", attempts)
	}
	if msg.Id != 42 {
		t.Fatalf("msg.Id = %d, want 42", msg.Id)
	}
}

func TestDoH_ForwardDNS_ClosedForwarderReturnsErrClosed(t *testing.T) {
	orig := sendHttpDNSFunc
	t.Cleanup(func() { sendHttpDNSFunc = orig })

	sendHttpDNSFunc = func(_ *http.Client, _ string, _ *dns.Upstream, _ []byte) (*dnsmessage.Msg, error) {
		return &dnsmessage.Msg{}, nil
	}

	d := &DoH{Upstream: dns.Upstream{Scheme: dns.UpstreamScheme_HTTPS}}
	d.clientFactory = func() *http.Client { return &http.Client{} }
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := d.ForwardDNS(context.Background(), []byte("query")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ForwardDNS err = %v, want net.ErrClosed", err)
	}
}
