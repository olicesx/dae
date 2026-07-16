/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestShouldRejectNewUdpDialSelection(t *testing.T) {
	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
	tcp6 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}

	if shouldRejectNewUdpDialSelection(&proxyDialResult{
		Dialer:                  d,
		SelectionNetworkTypeObj: udp6,
	}) {
		t.Fatal("expected healthy UDP dialer selection to be admitted")
	}

	d.ReportUnavailableForced(udp6, nil)

	if !shouldRejectNewUdpDialSelection(&proxyDialResult{
		Dialer:                  d,
		SelectionNetworkTypeObj: udp6,
	}) {
		t.Fatal("expected unhealthy UDP dialer selection to be rejected")
	}

	if shouldRejectNewUdpDialSelection(&proxyDialResult{
		Dialer:                  d,
		SelectionNetworkTypeObj: tcp6,
	}) {
		t.Fatal("expected TCP selection to ignore UDP dial guard")
	}
}

func TestShouldRejectNewUdpDialSelection_UsesAdmissionNetworkType(t *testing.T) {
	d := newTestEndpointDialer()
	dataUDP6 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
	dnsUDP6 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		IsDns:           true,
		UdpHealthDomain: componentdialer.UdpHealthDomainDns,
	}

	d.ReportUnavailableForced(dataUDP6, nil)

	if shouldRejectNewUdpDialSelection(&proxyDialResult{
		Dialer:                  d,
		SelectionNetworkTypeObj: dataUDP6,
		AdmissionNetworkTypeObj: dnsUDP6,
	}) {
		t.Fatal("expected DNS-UDP admission fallback to bypass the data-UDP guard")
	}
}

func TestShouldRejectNewUdpDialSelection_FixedOutboundIgnoresHealth(t *testing.T) {
	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
	outbound := newTestFixedOutboundGroup(d)

	d.ReportUnavailableForced(udp6, nil)

	if shouldRejectNewUdpDialSelection(&proxyDialResult{
		Outbound:                outbound,
		Dialer:                  d,
		SelectionNetworkTypeObj: udp6,
	}) {
		t.Fatal("expected fixed outbound UDP selection to ignore health rejection")
	}
}

func TestShouldRejectNewUdpDialSelection_SingleDialerFallbackStillRejects(t *testing.T) {
	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	outbound := ob.NewDialerGroup(
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		"single-random",
		[]*componentdialer.Dialer{d},
		[]*componentdialer.Annotation{{}},
		ob.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		},
		func(bool, *componentdialer.NetworkType, bool) {},
	)

	d.ReportUnavailableForced(udp6, nil)

	if !shouldRejectNewUdpDialSelection(&proxyDialResult{
		Outbound:                outbound,
		Dialer:                  d,
		SelectionNetworkTypeObj: udp6,
	}) {
		t.Fatal("expected non-fixed single-dialer fallback to be rejected")
	}
}

func TestCheckUdpEndpointHealth_UsesEndpointSelectionNetworkType(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
	d.ReportUnavailableForced(udp6, nil)

	key := UdpEndpointKey{
		Src: netip.MustParseAddrPort("192.0.2.10:12345"),
		Dst: netip.MustParseAddrPort("198.51.100.20:443"),
	}
	ue := &UdpEndpoint{
		Dialer:              d,
		lAddr:               key.Src,
		log:                 logger,
		poolRef:             DefaultUdpEndpointPool,
		poolKey:             key,
		endpointNetworkType: *udp6,
	}

	shard := DefaultUdpEndpointPool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()

	c := &ControlPlane{log: logger}
	if c.checkUdpEndpointHealth(ue, key, false) {
		t.Fatal("expected endpoint health check to reject unavailable endpoint network type")
	}
	if _, ok := DefaultUdpEndpointPool.Get(key); ok {
		t.Fatal("expected rejected endpoint to be removed from pool")
	}
}

func TestCheckUdpEndpointHealth_EstablishedEndpointIgnoresTransientDialerHealth(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
	d.ReportUnavailableForced(udp6, nil)

	key := UdpEndpointKey{
		Src: netip.MustParseAddrPort("192.0.2.10:12345"),
		Dst: netip.MustParseAddrPort("198.51.100.20:443"),
	}
	ue := &UdpEndpoint{
		Dialer:              d,
		lAddr:               key.Src,
		log:                 logger,
		poolRef:             DefaultUdpEndpointPool,
		poolKey:             key,
		endpointNetworkType: *udp6,
	}
	ue.hasReply.Store(true)

	shard := DefaultUdpEndpointPool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()

	c := &ControlPlane{log: logger}
	if !c.checkUdpEndpointHealth(ue, key, false) {
		t.Fatal("expected established endpoint to survive transient dialer health failure")
	}
	if got, ok := DefaultUdpEndpointPool.Get(key); !ok || got != ue {
		t.Fatal("expected established endpoint to remain pooled")
	}
}

func TestCheckUdpEndpointHealth_ForwardedEndpointIgnoresTransientDialerHealth(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
	d.ReportUnavailableForced(udp6, nil)

	key := UdpEndpointKey{
		Src: netip.MustParseAddrPort("192.0.2.10:12346"),
		Dst: netip.MustParseAddrPort("198.51.100.21:443"),
	}
	ue := &UdpEndpoint{
		Dialer:              d,
		lAddr:               key.Src,
		log:                 logger,
		poolRef:             DefaultUdpEndpointPool,
		poolKey:             key,
		endpointNetworkType: *udp6,
	}
	ue.hasSent.Store(true)

	shard := DefaultUdpEndpointPool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()

	c := &ControlPlane{log: logger}
	if !c.checkUdpEndpointHealth(ue, key, false) {
		t.Fatal("expected forwarded endpoint to survive transient dialer health failure")
	}
	if got, ok := DefaultUdpEndpointPool.Get(key); !ok || got != ue {
		t.Fatal("expected forwarded endpoint to remain pooled")
	}
}

func TestCheckUdpEndpointHealth_PreservesSuccessfulInitialWrite(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	writeStarted := make(chan struct{})
	writeRelease := make(chan struct{})
	defer func() {
		select {
		case <-writeRelease:
		default:
			close(writeRelease)
		}
	}()

	d := newTestEndpointDialer()
	networkType := componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("[2001:db8::1]:12347")}
	conn := &scriptedPacketConn{
		reads:        make(chan scriptedPacketRead),
		closeCh:      make(chan struct{}),
		writeStarted: writeStarted,
		writeRelease: writeRelease,
	}
	ue := &UdpEndpoint{
		conn:                conn,
		Dialer:              d,
		lAddr:               key.Src,
		log:                 logger,
		poolRef:             NewUdpEndpointPool(),
		poolKey:             key,
		endpointNetworkType: networkType,
	}
	defer func() { _ = ue.Close() }()

	writeDone := make(chan error, 1)
	go func() {
		_, err := ue.WriteTo([]byte("payload"), "[2001:db8::30]:443")
		writeDone <- err
	}()
	select {
	case <-writeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the first UDP write to begin")
	}

	d.ReportUnavailableForced(&networkType, nil)
	controlPlane := &ControlPlane{log: logger}
	if !controlPlane.checkUdpEndpointHealth(ue, key, false) {
		t.Fatal("expected health check to preserve an endpoint with a successful write in flight")
	}
	if got := conn.closeCalls.Load(); got != 0 {
		t.Fatalf("close calls during first write = %d, want 0", got)
	}

	close(writeRelease)
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("first write failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the first UDP write to complete")
	}

	if !ue.hasSent.Load() || ue.IsDead() {
		t.Fatal("expected successful initial write to leave the endpoint live")
	}
}
