//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

// offloadTransformingConn mirrors the fork's protocol conns at the current
// pin: they expose the raw socket through UnderlyingConn so observational
// probes (pending-byte checks) can peel to it, and advertise ReadBufferer
// because they transform the byte stream. Kernel redirect must refuse such a
// chain even though a peeling unwrap reaches the inner *net.TCPConn; before
// the gate switched to the data-movement unwrap this test failed by falling
// through to session registration on the unwrapped socket.
type offloadTransformingConn struct {
	netproxy.Conn
	inner *net.TCPConn
}

func (c *offloadTransformingConn) ReadBuffered() int { return 0 }

func (c *offloadTransformingConn) UnderlyingConn() net.Conn { return c.inner }

func tcpOffloadLoopbackConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	client, okClient := conn.(*net.TCPConn)
	server, okServer := accepted.(*net.TCPConn)
	if !okClient || !okServer {
		t.Fatalf("loopback pair is not *net.TCPConn")
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// TestTCPRelayOffloadSessionRefusesTransformingConns pins the data-movement
// gate: a ReadBufferer/UnderlyingConn chain over a real TCP socket is refused
// on both sides, while the plain TCP peer must be the reason-free leg. Red on
// a peeling gate (the session proceeds to registration and fails on the nil
// maps instead of reporting unavailable).
func TestTCPRelayOffloadSessionRefusesTransformingConns(t *testing.T) {
	client, server := tcpOffloadLoopbackConnPair(t)
	wrapped := &offloadTransformingConn{Conn: client, inner: client}

	nop := func(int64) {}
	_, err := newTCPRelayOffloadSession(nil, nil, nil, nil, wrapped, server, nop, nop)
	if !errors.Is(err, errTCPRelayOffloadUnavailable) {
		t.Fatalf("wrapped left: err = %v, want errTCPRelayOffloadUnavailable", err)
	}
	if err != nil && !strings.Contains(err.Error(), "left connection") {
		t.Fatalf("wrapped left: err = %v, want it to name the left connection", err)
	}

	_, err = newTCPRelayOffloadSession(nil, nil, nil, nil, server, wrapped, nop, nop)
	if !errors.Is(err, errTCPRelayOffloadUnavailable) {
		t.Fatalf("wrapped right: err = %v, want errTCPRelayOffloadUnavailable", err)
	}
	if err != nil && !strings.Contains(err.Error(), "right connection") {
		t.Fatalf("wrapped right: err = %v, want it to name the right connection", err)
	}
}
