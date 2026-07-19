/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func seedAnyfromPoolEntry(pool *AnyfromPool, key anyfromPoolKey, af *Anyfrom) {
	shard := pool.shardForKey(key)
	shard.mu.Lock()
	shard.pool[key] = af
	shard.mu.Unlock()
}

func liveTestAnyfrom(mark uint32) *Anyfrom {
	af := &Anyfrom{
		ttl:    AnyfromTimeout,
		soMark: mark,
	}
	af.RefreshTtl()
	return af
}

func TestAnyfromPoolSocketIdentityIncludesMark(t *testing.T) {
	pool := newTestAnyfromPoolWithoutJanitor()
	lAddr := netip.MustParseAddrPort("127.0.0.1:5353")
	const (
		markA = uint32(0x101)
		markB = uint32(0x202)
	)
	afA := liveTestAnyfrom(markA)
	afB := liveTestAnyfrom(markB)
	seedAnyfromPoolEntry(pool, anyfromPoolKey{lAddr: lAddr, soMark: markA}, afA)
	seedAnyfromPoolEntry(pool, anyfromPoolKey{lAddr: lAddr, soMark: markB}, afB)

	for _, tc := range []struct {
		name string
		mark uint32
		want *Anyfrom
	}{
		{name: "first mark", mark: markA, want: afA},
		{name: "second mark", mark: markB, want: afB},
		{name: "first mark reused", mark: markA, want: afA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, isNew, err := pool.getOrCreateWithMark(lAddr, tc.mark, AnyfromTimeout)
			if err != nil {
				t.Fatalf("getOrCreateWithMark() error = %v", err)
			}
			if isNew {
				t.Fatal("getOrCreateWithMark() reported a cached entry as new")
			}
			if got != tc.want {
				t.Fatalf("getOrCreateWithMark(mark=%#x) = %p, want %p", tc.mark, got, tc.want)
			}
		})
	}
}

func TestAnyfromPoolNegativeCacheIsScopedByMark(t *testing.T) {
	pool := newTestAnyfromPoolWithoutJanitor()
	lAddr := netip.MustParseAddrPort("127.0.0.1:5353")
	const (
		failedMark = uint32(0x303)
		liveMark   = uint32(0x404)
	)
	failed := &Anyfrom{ttl: 2 * time.Second, soMark: failedMark}
	failed.failed.Store(true)
	failed.RefreshTtl()
	live := liveTestAnyfrom(liveMark)
	seedAnyfromPoolEntry(pool, anyfromPoolKey{lAddr: lAddr, soMark: failedMark}, failed)
	seedAnyfromPoolEntry(pool, anyfromPoolKey{lAddr: lAddr, soMark: liveMark}, live)

	if conn, isNew, err := pool.getOrCreateWithMark(lAddr, failedMark, AnyfromTimeout); conn != nil || isNew || !stderrors.Is(err, ErrAnyfromBindFailed) {
		t.Fatalf("failed mark lookup = (%p, %v, %v), want (nil, false, %v)", conn, isNew, err, ErrAnyfromBindFailed)
	}
	conn, isNew, err := pool.getOrCreateWithMark(lAddr, liveMark, AnyfromTimeout)
	if err != nil || isNew || conn != live {
		t.Fatalf("live mark lookup = (%p, %v, %v), want (%p, false, nil)", conn, isNew, err, live)
	}
}

func TestAnyfromPoolConcurrentDefaultMarkSwitchKeepsSocketIdentity(t *testing.T) {
	oldMark := soMarkFromDae.Load()
	defer SetAnyfromSoMark(oldMark)

	pool := newTestAnyfromPoolWithoutJanitor()
	lAddr := netip.MustParseAddrPort("127.0.0.1:5353")
	const (
		markA = uint32(0x505)
		markB = uint32(0x606)
	)
	afA := liveTestAnyfrom(markA)
	afB := liveTestAnyfrom(markB)
	seedAnyfromPoolEntry(pool, anyfromPoolKey{lAddr: lAddr, soMark: markA}, afA)
	seedAnyfromPoolEntry(pool, anyfromPoolKey{lAddr: lAddr, soMark: markB}, afB)
	SetAnyfromSoMark(markA)
	for _, tc := range []struct {
		mark uint32
		want *Anyfrom
	}{
		{mark: markA, want: afA},
		{mark: markB, want: afB},
		{mark: markA, want: afA},
	} {
		SetAnyfromSoMark(tc.mark)
		conn, isNew, err := pool.GetOrCreate(lAddr, AnyfromTimeout)
		if err != nil || isNew || conn != tc.want {
			t.Fatalf("default mark %#x lookup = (%p, %v, %v), want (%p, false, nil)", tc.mark, conn, isNew, err, tc.want)
		}
	}

	const (
		readers    = 16
		iterations = 2_000
	)
	start := make(chan struct{})
	errCh := make(chan error, readers)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				SetAnyfromSoMark(markB)
			} else {
				SetAnyfromSoMark(markA)
			}
		}
	}()
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range iterations {
				conn, isNew, err := pool.GetOrCreate(lAddr, AnyfromTimeout)
				if err != nil {
					errCh <- err
					return
				}
				if conn == nil {
					errCh <- fmt.Errorf("default lookup returned a nil connection")
					return
				}
				if isNew || (conn != afA && conn != afB) || (conn.soMark != markA && conn.soMark != markB) {
					errCh <- fmt.Errorf("default lookup returned conn=%p mark=%#x isNew=%v", conn, conn.soMark, isNew)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestAnyfromPoolResetWaitsForInFlightCreation(t *testing.T) {
	pool := newTestAnyfromPoolWithoutJanitor()
	lAddr := netip.MustParseAddrPort("127.0.0.1:5353")
	shard := pool.shardForKey(anyfromPoolKey{lAddr: lAddr})
	shard.createMu.Lock()

	done := make(chan struct{})
	started := make(chan struct{})
	go func() {
		close(started)
		pool.Reset()
		close(done)
	}()
	<-started
	select {
	case <-done:
		shard.createMu.Unlock()
		t.Fatal("Reset returned while socket creation was still in flight")
	case <-time.After(20 * time.Millisecond):
	}

	shard.createMu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Reset did not resume after socket creation completed")
	}
}

func TestUdpEndpointReplyKeepsImmutableBindingMark(t *testing.T) {
	oldPool := DefaultAnyfromPool
	oldMark := soMarkFromDae.Load()
	DefaultAnyfromPool = newTestAnyfromPoolWithoutJanitor()
	defer func() {
		DefaultAnyfromPool.Reset()
		DefaultAnyfromPool = oldPool
		SetAnyfromSoMark(oldMark)
	}()

	const (
		endpointMark = uint32(0x707)
		defaultMark  = uint32(0x808)
	)
	SetAnyfromSoMark(defaultMark)

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(client) error = %v", err)
	}
	defer clientConn.Close()
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr).AddrPort()

	replyConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP(reply) error = %v", err)
	}
	replyAddr := replyConn.LocalAddr().(*net.UDPAddr).AddrPort()
	bound := &Anyfrom{UDPConn: replyConn, ttl: AnyfromTimeout, soMark: endpointMark}
	bound.RefreshTtl()
	seedAnyfromPoolEntry(DefaultAnyfromPool, anyfromPoolKey{lAddr: replyAddr, soMark: endpointMark}, bound)

	stale := liveTestAnyfrom(defaultMark)
	ue := &UdpEndpoint{
		lAddr:   clientAddr,
		poolKey: UdpEndpointKey{Src: clientAddr, Dst: replyAddr},
	}
	ue.setFlowBinding(UdpFlowBinding{Route: UdpRouteBinding{Mark: endpointMark}})
	ue.swapResponseConn(stale)
	defer ue.releaseCachedResponseConns()

	payload := []byte("immutable-mark-reply")
	if err := forwardUdpEndpointReplyToClient(nil, ue, payload, replyAddr, clientAddr, nil, nil); err != nil {
		t.Fatalf("forwardUdpEndpointReplyToClient() error = %v", err)
	}
	if got := ue.loadResponseConn(); got != bound {
		t.Fatalf("response cache = %p, want endpoint-bound socket %p (mark %#x)", got, bound, endpointMark)
	}
	if got := stale.pins.Load(); got != 0 {
		t.Fatalf("stale default-mark socket pins = %d, want 0", got)
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 128)
	n, from, err := clientConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("ReadFromUDPAddrPort() error = %v", err)
	}
	if from != replyAddr || string(buf[:n]) != string(payload) {
		t.Fatalf("reply = (%q from %v), want (%q from %v)", buf[:n], from, payload, replyAddr)
	}
}

func TestUdpEndpointPrewarmUsesImmutableBindingMark(t *testing.T) {
	oldPool := DefaultAnyfromPool
	oldMark := soMarkFromDae.Load()
	DefaultAnyfromPool = newTestAnyfromPoolWithoutJanitor()
	defer func() {
		DefaultAnyfromPool.Reset()
		DefaultAnyfromPool = oldPool
		SetAnyfromSoMark(oldMark)
	}()

	const (
		endpointMark = uint32(0x909)
		defaultMark  = uint32(0xa0a)
	)
	SetAnyfromSoMark(defaultMark)
	clientAddr := netip.MustParseAddrPort("127.0.0.1:40000")
	replyAddr := netip.MustParseAddrPort("127.0.0.1:5353")
	bound := liveTestAnyfrom(endpointMark)
	defaultConn := liveTestAnyfrom(defaultMark)
	seedAnyfromPoolEntry(DefaultAnyfromPool, anyfromPoolKey{lAddr: replyAddr, soMark: endpointMark}, bound)
	seedAnyfromPoolEntry(DefaultAnyfromPool, anyfromPoolKey{lAddr: replyAddr, soMark: defaultMark}, defaultConn)

	ue := &UdpEndpoint{lAddr: clientAddr, poolKey: UdpEndpointKey{Src: clientAddr}}
	ue.setFlowBinding(UdpFlowBinding{Route: UdpRouteBinding{Mark: endpointMark}})
	ue.prewarmResponseConn(replyAddr.String())
	defer ue.releaseCachedResponseConns()

	if got := ue.CachedResponseConn(replyAddr); got != bound {
		t.Fatalf("prewarmed response conn = %p, want %p (mark %#x)", got, bound, endpointMark)
	}
}

func TestUdpEndpointResponseSlotStaleClearKeepsNewerSocket(t *testing.T) {
	oldConn := liveTestAnyfrom(0x111)
	newConn := liveTestAnyfrom(0x222)
	ue := &UdpEndpoint{
		poolKey: UdpEndpointKey{Dst: netip.MustParseAddrPort("127.0.0.1:5353")},
	}
	slot := ue.responseConnSlot()
	slot.Swap(oldConn)
	stale := slot.Load()
	slot.Swap(newConn)

	if slot.CompareAndSwap(stale, nil) {
		t.Fatal("stale clear unexpectedly replaced a newer response socket")
	}
	if got := slot.Load(); got != newConn {
		t.Fatalf("response slot after stale clear = %p, want newer socket %p", got, newConn)
	}
	if got := oldConn.pins.Load(); got != 0 {
		t.Fatalf("old socket pins = %d, want 0", got)
	}
	if got := newConn.pins.Load(); got != 1 {
		t.Fatalf("new socket pins = %d, want 1", got)
	}
	ue.releaseCachedResponseConns()
}

func TestUDPRequestReplyMarkIsImmutableWhenDefaultChanges(t *testing.T) {
	oldMark := soMarkFromDae.Load()
	defer SetAnyfromSoMark(oldMark)

	const (
		requestMark = uint32(0x333)
		defaultMark = uint32(0x444)
	)
	req := &udpRequest{routingResult: &bpfRoutingResult{Mark: requestMark}}
	SetAnyfromSoMark(defaultMark)
	if got := req.replySoMark(); got != requestMark {
		t.Fatalf("request reply mark = %#x, want immutable mark %#x", got, requestMark)
	}
	if got := (*udpRequest)(nil).replySoMark(); got != defaultMark {
		t.Fatalf("request without binding mark = %#x, want current default %#x", got, defaultMark)
	}
}

func TestAnyfromNegativeCacheStillAllowsDNSRawFallback(t *testing.T) {
	from := netip.MustParseAddrPort("192.0.2.53:53")
	to := netip.MustParseAddrPort("192.0.2.10:40000")
	if !shouldTryRawUDPFallback(ErrAnyfromBindFailed, from, to) {
		t.Fatal("DNS response with an Anyfrom negative-cache hit should allow raw fallback")
	}
	if shouldTryRawUDPFallback(ErrAnyfromBindFailed, netip.MustParseAddrPort("192.0.2.53:5353"), to) {
		t.Fatal("non-DNS response should not allow raw fallback")
	}
}
