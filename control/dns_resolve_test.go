/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func setSnapshotBestDialerChooser(ctrl *DnsController, chooser func(context.Context, DnsRequestSnapshot, *componentdns.Upstream) (*dialArgument, error)) {
	runtime := ctrl.runtime()
	if runtime == nil {
		return
	}
	updated := *runtime
	updated.bestDialerSnapshotChooser = chooser
	updated.bestDialerChooser = nil
	ctrl.runtimeState.Store(&updated)
}

func TestDnsResultCachedResponseSharesImmutableWire(t *testing.T) {
	message := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Response:           true,
			RecursionAvailable: true,
		},
		Question: []dnsmessage.Question{{
			Name:   "cached.example.",
			Qtype:  dnsmessage.TypeA,
			Qclass: dnsmessage.ClassINET,
		}},
	}
	wire, err := message.Pack()
	require.NoError(t, err)

	result, err := dnsResultFromCachedResponse(wire, 7, "cache-key")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, wire, result.packedResponse)
	require.Equal(t, &wire[0], &result.packedResponse[0])

	requestCopy := result.copyForRequest(8)
	require.Equal(t, &result.packedResponse[0], &requestCopy.packedResponse[0])
	require.Equal(t, wire, result.packedResponse)
}

func TestDnsControllerResolveOwnsQueryAndRoutingSnapshot(t *testing.T) {
	originalFactory := dnsForwarderFactory
	t.Cleanup(func() { dnsForwarderFactory = originalFactory })

	controller := newScopedDnsController(t)
	var seenPID atomic.Uint32
	setSnapshotBestDialerChooser(controller, func(_ context.Context, snapshot DnsRequestSnapshot, _ *componentdns.Upstream) (*dialArgument, error) {
		routingResult := snapshot.routingResultForRoute()
		if routingResult != nil {
			seenPID.Store(routingResult.Pid)
		}
		return &dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestTarget: snapshot.RealDst,
		}, nil
	})
	dnsForwarderFactory = func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return dnsAResponseMsg("snapshot.example.", "198.51.100.7"), nil
		}}, nil
	}

	query := new(dnsmessage.Msg)
	query.SetQuestion("snapshot.example.", dnsmessage.TypeA)
	query.Id = 4312
	before, err := query.Pack()
	require.NoError(t, err)
	routingResult := &bpfRoutingResult{Pid: 73}
	snapshot := dnsRequestSnapshotFromUDPRequest(&udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.71:42000"),
		realDst:       netip.MustParseAddrPort("203.0.113.53:53"),
		routingResult: routingResult,
	})
	routingResult.Pid = 99

	result, err := controller.Resolve(context.Background(), query, snapshot)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Response)
	require.Equal(t, uint16(4312), result.Response.Id)
	require.Equal(t, uint32(73), seenPID.Load())
	after, err := query.Pack()
	require.NoError(t, err)
	require.Equal(t, before, after, "Resolve must not mutate the caller-owned query")
}

func TestDnsControllerResolveSingleflightKeepsRequestIDs(t *testing.T) {
	originalFactory := dnsForwarderFactory
	t.Cleanup(func() { dnsForwarderFactory = originalFactory })

	controller := newScopedDnsController(t)
	setSnapshotBestDialerChooser(controller, func(_ context.Context, snapshot DnsRequestSnapshot, _ *componentdns.Upstream) (*dialArgument, error) {
		return &dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestTarget: snapshot.RealDst,
		}, nil
	})
	started := make(chan struct{})
	release := make(chan struct{})
	var forwards atomic.Int32
	dnsForwarderFactory = func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			if forwards.Add(1) == 1 {
				close(started)
				<-release
			}
			return dnsAResponseMsg("singleflight.example.", "198.51.100.8"), nil
		}}, nil
	}

	newQuery := func(id uint16) *dnsmessage.Msg {
		query := new(dnsmessage.Msg)
		query.SetQuestion("singleflight.example.", dnsmessage.TypeA)
		query.Id = id
		return query
	}
	snapshot := DnsRequestSnapshot{
		RealSrc: netip.MustParseAddrPort("192.0.2.72:42000"),
		RealDst: netip.MustParseAddrPort("203.0.113.54:53"),
	}
	type resolveResult struct {
		result *DnsResult
		err    error
	}
	firstDone := make(chan resolveResult, 1)
	secondDone := make(chan resolveResult, 1)
	go func() {
		result, err := controller.Resolve(context.Background(), newQuery(5101), snapshot)
		firstDone <- resolveResult{result: result, err: err}
	}()
	<-started
	go func() {
		result, err := controller.Resolve(context.Background(), newQuery(5102), snapshot)
		secondDone <- resolveResult{result: result, err: err}
	}()
	time.Sleep(25 * time.Millisecond)
	close(release)

	first := <-firstDone
	second := <-secondDone
	require.NoError(t, first.err)
	require.NoError(t, second.err)
	require.NotNil(t, first.result)
	require.NotNil(t, second.result)
	require.Equal(t, uint16(5101), first.result.Response.Id)
	require.Equal(t, uint16(5102), second.result.Response.Id)
	require.EqualValues(t, 1, forwards.Load())
}

func TestDnsControllerResolveReturnsRefusedResultWhenConcurrencyIsFull(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{ConcurrencyLimit: 1})
	require.NoError(t, err)
	t.Cleanup(func() { _ = controller.Close() })
	controller.concurrencyLimiter <- struct{}{}

	query := new(dnsmessage.Msg)
	query.SetQuestion("limited.example.", dnsmessage.TypeA)
	result, err := controller.Resolve(context.Background(), query, DnsRequestSnapshot{})
	require.ErrorIs(t, err, ErrDNSQueryConcurrencyLimitExceeded)
	require.NotNil(t, result)
	require.NotNil(t, result.Response)
	require.Equal(t, dnsmessage.RcodeRefused, result.Response.Rcode)
	require.False(t, query.Response, "Resolve must not mutate the caller-owned query")
}
