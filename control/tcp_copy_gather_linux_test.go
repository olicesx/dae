//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// gatherAliasingSourceConn is a relay source whose taken segments alias an
// internal buffer, exactly like a bufio- or sniffer-backed source. Its Read
// simulates a buffer refill: the internal buffer is overwritten before the
// caller sees the read result, so any code path that keeps the aliased
// segments live across Read observes corrupted bytes.
type gatherAliasingSourceConn struct {
	netproxy.Conn
	underlying *net.TCPConn
	internal   []byte
	payload    []byte
}

func (c *gatherAliasingSourceConn) TakeRelaySegments() [][]byte {
	return [][]byte{c.internal}
}

func (c *gatherAliasingSourceConn) UnderlyingConn() net.Conn { return c.underlying }

func (c *gatherAliasingSourceConn) Read(p []byte) (int, error) {
	for i := range c.internal {
		c.internal[i] = 'X'
	}
	n := copy(p, c.payload)
	return n, io.EOF
}

type gatherCapturingDst struct {
	netproxy.Conn
	mu  sync.Mutex
	got []byte
}

func (d *gatherCapturingDst) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.got = append(d.got, p...)
	return len(p), nil
}

func (d *gatherCapturingDst) written() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return string(d.got)
}

// TestRelayGatherWriteDoesNotReadSrcBetweenTakeAndWrite pins the aliasing
// contract of relayTakeSourceSegments: the taken segments are only valid until
// the next read of src, so the probe read must not run between take and write
// with the aliased slices still queued. Before the copy-first fix the probe
// read landed between them and the written prefix came back as the refilled
// ("XXXXXX") bytes.
func TestRelayGatherWriteDoesNotReadSrcBetweenTakeAndWrite(t *testing.T) {
	client, server := tcpOffloadLoopbackConnPair(t)
	// Seed the server's kernel receive queue so the pending-bytes probe fires.
	// Loopback delivery is immediate but not synchronized with this goroutine,
	// so wait until the probe would actually see the bytes.
	if _, err := client.Write([]byte("PING")); err != nil {
		t.Fatalf("seed pending bytes: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		pending, err := tcpConnHasPendingReadData(server)
		if err != nil {
			t.Fatalf("probe pending bytes: %v", err)
		}
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("seeded bytes never reached the server receive queue")
		}
		time.Sleep(time.Millisecond)
	}

	src := &gatherAliasingSourceConn{
		underlying: server,
		internal:   []byte("PREFIX"),
		payload:    []byte("BODY"),
	}
	dst := &gatherCapturingDst{}

	written, err, ok := tryRelayGatherWrite(context.Background(), dst, src, nil, nil)
	if !ok {
		t.Fatal("tryRelayGatherWrite declined the gather path")
	}
	if err != nil {
		t.Fatalf("tryRelayGatherWrite: %v", err)
	}
	if want := int64(len("PREFIX") + len("BODY")); written != want {
		t.Fatalf("written = %d, want %d", written, want)
	}
	if got := dst.written(); got != "PREFIXBODY" {
		t.Fatalf("written payload = %q, want PREFIXBODY (the taken prefix must survive the probe read)", got)
	}
}

// TestRelayWritevAllAdvancesSegments pins relayWritevAll's iovec advancement
// across partial writes, its EINTR retry, and the short-write guard, through
// the relayWritevFunc seam.
func TestRelayWritevAllAdvancesSegments(t *testing.T) {
	_, server := tcpOffloadLoopbackConnPair(t)
	rawConn, err := server.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	segments := [][]byte{[]byte("hello "), []byte("world")}
	var callShapes []string
	orig := relayWritevFunc
	relayWritevFunc = func(_ int, iovecs [][]byte) (int, error) {
		var shape strings.Builder
		for _, iov := range iovecs {
			shape.WriteString(string(iov))
			shape.WriteByte('|')
		}
		callShapes = append(callShapes, shape.String())
		switch len(callShapes) {
		case 1:
			// Partial write inside the first iovec.
			return 3, nil
		case 2:
			// A signal must not lose the advanced position.
			return 0, syscall.EINTR
		default:
			return 8, nil
		}
	}
	t.Cleanup(func() { relayWritevFunc = orig })

	written, err := relayWritevAll(rawConn, segments)
	if err != nil {
		t.Fatalf("relayWritevAll: %v", err)
	}
	if written != 11 {
		t.Fatalf("written = %d, want 11", written)
	}
	wantShapes := []string{
		"hello |world|",
		"lo |world|",
		"lo |world|",
	}
	if len(callShapes) != len(wantShapes) {
		t.Fatalf("writev calls = %v, want %v", callShapes, wantShapes)
	}
	for i, want := range wantShapes {
		if callShapes[i] != want {
			t.Fatalf("writev call %d iovecs = %q, want %q", i, callShapes[i], want)
		}
	}
}

// TestRelayWritevAllReportsShortWrite pins the n==0-with-nil-error guard.
func TestRelayWritevAllReportsShortWrite(t *testing.T) {
	_, server := tcpOffloadLoopbackConnPair(t)
	rawConn, err := server.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	orig := relayWritevFunc
	relayWritevFunc = func(_ int, _ [][]byte) (int, error) { return 0, nil }
	t.Cleanup(func() { relayWritevFunc = orig })

	_, err = relayWritevAll(rawConn, [][]byte{[]byte("hello")})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("err = %v, want io.ErrShortWrite", err)
	}
}
