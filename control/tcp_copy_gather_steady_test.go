//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeRelaySrc is a scriptable netproxy.Conn source: queued reads are
// returned in order; when the queue is empty a Read waits for the test to
// queue more data or EOF. It does not unwrap to a TCP socket, so the
// gather engine's pending-data probe reports false and every record
// flushes individually. deadlineCalls counts Set*Deadline invocations so
// tests can assert the engine never arms deadlines on the source (a
// mid-record deadline error permanently poisons crypto/tls streams).
type fakeRelaySrc struct {
	mu            sync.Mutex
	reads         [][]byte
	eofNext       bool
	deadlineCalls int
}

func (s *fakeRelaySrc) queue(b ...[]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, b...)
}

func (s *fakeRelaySrc) markEOF() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eofNext = true
}

func (s *fakeRelaySrc) Read(b []byte) (int, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		if len(s.reads) > 0 {
			n := copy(b, s.reads[0])
			s.reads = s.reads[1:]
			s.mu.Unlock()
			return n, nil
		}
		if s.eofNext {
			s.mu.Unlock()
			return 0, io.EOF
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			return 0, errors.New("fake src: starved")
		}
		time.Sleep(200 * time.Microsecond)
	}
}

func (s *fakeRelaySrc) Write(b []byte) (int, error) { return len(b), nil }
func (s *fakeRelaySrc) Close() error                { return nil }
func (s *fakeRelaySrc) SetDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadlineCalls++
	return nil
}
func (s *fakeRelaySrc) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadlineCalls++
	return nil
}
func (s *fakeRelaySrc) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadlineCalls++
	return nil
}

// fakeRelayDst captures writes (one call per gather flush on the coalesced
// fallback path) and can inject a write error.
type fakeRelayDst struct {
	mu     sync.Mutex
	writes []int
	data   bytes.Buffer
	werr   error
}

func (d *fakeRelayDst) Read(b []byte) (int, error) { return 0, io.EOF }
func (d *fakeRelayDst) Write(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.werr != nil {
		return 0, d.werr
	}
	d.writes = append(d.writes, len(b))
	return d.data.Write(b)
}
func (d *fakeRelayDst) Close() error                     { return nil }
func (d *fakeRelayDst) SetDeadline(time.Time) error      { return nil }
func (d *fakeRelayDst) SetReadDeadline(time.Time) error  { return nil }
func (d *fakeRelayDst) SetWriteDeadline(time.Time) error { return nil }

func withSteadyGather(t *testing.T, enabled bool) {
	t.Helper()
	prev := relayWriteGatherEnabled
	relayWriteGatherEnabled = enabled
	t.Cleanup(func() { relayWriteGatherEnabled = prev })
}

func rec(n int, tag byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = tag
	}
	return b
}

func TestRelaySteadyGatherDisabledFallsBack(t *testing.T) {
	withSteadyGather(t, false)
	_, _, ok := relaySteadyGatherCopy(context.Background(), &fakeRelayDst{}, &fakeRelaySrc{}, nil, nil)
	if ok {
		t.Fatal("expected ok=false when disabled")
	}
}

func TestRelaySteadyGatherDefaultEnabled(t *testing.T) {
	t.Setenv("DAE_TCP_RELAY_WRITE_GATHER", "")
	if !envOverrideBool("DAE_TCP_RELAY_WRITE_GATHER", true) {
		t.Fatal("expected default true when env unset")
	}
	t.Setenv("DAE_TCP_RELAY_WRITE_GATHER", "0")
	if envOverrideBool("DAE_TCP_RELAY_WRITE_GATHER", true) {
		t.Fatal("expected explicit 0 to disable")
	}
}

func TestRelaySteadyGatherInteractiveOneWritePerRecord(t *testing.T) {
	withSteadyGather(t, true)
	// Interactive shape: records arrive one at a time on a source that
	// does not unwrap to a TCP socket (no pending-data signal), so every
	// record flushes individually.
	src := &fakeRelaySrc{}
	dst := &fakeRelayDst{}
	go func() {
		for i := 0; i < 3; i++ {
			time.Sleep(2 * time.Millisecond)
			src.queue(rec(1024, byte('a'+i)))
		}
		time.Sleep(2 * time.Millisecond)
		src.markEOF()
	}()
	written, err, ok := relaySteadyGatherCopy(context.Background(), dst, src, nil, nil)
	if !ok || err != nil {
		t.Fatalf("copy: ok=%v err=%v", ok, err)
	}
	if written != 3*1024 {
		t.Fatalf("written=%d want %d", written, 3*1024)
	}
	if len(dst.writes) != 3 {
		t.Fatalf("writes=%v want 3 (one per record)", dst.writes)
	}
}

func TestRelaySteadyGatherTCPBulkBatchesFlushes(t *testing.T) {
	withSteadyGather(t, true)
	// Bulk shape over a real loopback TCP source: the kernel socket holds
	// unread bytes, so the pending-data probe keeps the gather loop reading
	// and the whole backlog flushes as one batch. Three 32 KiB reads (copy
	// buffer size) must coalesce into a single flush.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	type accepted struct {
		conn net.Conn
		err  error
	}
	acc := make(chan accepted, 1)
	go func() {
		c, aerr := ln.Accept()
		acc <- accepted{c, aerr}
	}()
	src, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	peer := <-acc
	if peer.err != nil {
		t.Fatal(peer.err)
	}
	defer func() { _ = peer.conn.Close() }()

	const total = 96 << 10
	go func() {
		chunk := rec(16<<10, 'b')
		for sent := 0; sent < total; sent += len(chunk) {
			if _, werr := peer.conn.Write(chunk); werr != nil {
				return
			}
		}
		// Close the write side so the gather loop observes EOF after the
		// backlog drains.
		if tc, ok := peer.conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	// Wait until the whole payload is queued in the kernel socket instead of
	// assuming a fixed settle time. Under scheduler load the writer can still be
	// mid-write after a sleep, and a partially queued backlog legitimately
	// flushes more than once — which would blame the gather engine for the
	// test's own timing.
	raw, err := src.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	queueDeadline := time.Now().Add(5 * time.Second)
	for {
		pending := 0
		if err := raw.Control(func(fd uintptr) {
			pending, _ = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
		}); err != nil {
			t.Fatal(err)
		}
		if pending >= total {
			break
		}
		if time.Now().After(queueDeadline) {
			t.Fatalf("the peer queued only %d of %d bytes in 5s; the single-flush assertion needs the full backlog", pending, total)
		}
		time.Sleep(time.Millisecond)
	}

	dst := &fakeRelayDst{}
	var flushes int
	written, cerr, ok := relaySteadyGatherCopy(context.Background(), dst, src,
		func(int64) { flushes++ }, nil)
	if !ok || cerr != nil {
		t.Fatalf("copy: ok=%v err=%v", ok, cerr)
	}
	if want := int64(total); written != want {
		t.Fatalf("written=%d want %d", written, want)
	}
	if dst.data.Len() != total {
		t.Fatalf("delivered=%d want %d", dst.data.Len(), total)
	}
	if flushes != 1 {
		t.Fatalf("flushes=%d want 1 (single batched flush)", flushes)
	}
}

// TestRelaySteadyGatherNeverArmsSourceDeadlines is the regression canary
// for the wrapped-stream poisoning class: the gather engine must observe
// socket state (pending bytes) and must never arm read deadlines on the
// source, because an expired-deadline Read landing mid-record permanently
// breaks crypto/tls streams.
func TestRelaySteadyGatherNeverArmsSourceDeadlines(t *testing.T) {
	withSteadyGather(t, true)
	src := &fakeRelaySrc{}
	src.queue(rec(2048, 'x'), rec(4096, 'y'))
	src.markEOF()
	dst := &fakeRelayDst{}
	if _, err, ok := relaySteadyGatherCopy(context.Background(), dst, src, nil, nil); !ok || err != nil {
		t.Fatalf("copy: ok=%v err=%v", ok, err)
	}
	if src.deadlineCalls != 0 {
		t.Fatalf("source deadline calls=%d, want 0", src.deadlineCalls)
	}
}

func TestRelaySteadyGatherFlushesPendingOnEOF(t *testing.T) {
	withSteadyGather(t, true)
	// Two records queued, then EOF, on a non-unwrapping source: both are
	// delivered (one write each) before the copy returns nil.
	src := &fakeRelaySrc{}
	src.queue(rec(2048, 'x'), rec(4096, 'y'))
	src.markEOF()
	dst := &fakeRelayDst{}
	written, err, ok := relaySteadyGatherCopy(context.Background(), dst, src, nil, nil)
	if !ok || err != nil {
		t.Fatalf("copy: ok=%v err=%v", ok, err)
	}
	if written != 2048+4096 {
		t.Fatalf("written=%d want %d", written, 2048+4096)
	}
	if len(dst.writes) != 2 {
		t.Fatalf("writes=%v want 2", dst.writes)
	}
}

func TestRelaySteadyGatherWriteErrorPropagates(t *testing.T) {
	withSteadyGather(t, true)
	src := &fakeRelaySrc{}
	src.queue(rec(512, 'z'))
	src.markEOF()
	dst := &fakeRelayDst{werr: errors.New("boom")}
	_, err, ok := relaySteadyGatherCopy(context.Background(), dst, src, nil, nil)
	if !ok || err == nil || err.Error() != "boom" {
		t.Fatalf("expected write error, got ok=%v err=%v", ok, err)
	}
}

func TestRelaySteadyGatherRecordCallbacks(t *testing.T) {
	withSteadyGather(t, true)
	src := &fakeRelaySrc{}
	src.queue(rec(100, 'p'), rec(200, 'q'))
	src.markEOF()
	dst := &fakeRelayDst{}
	var recorded, active int64
	_, err, ok := relaySteadyGatherCopy(context.Background(), dst, src,
		func(n int64) { recorded += n },
		func(n int64) { active += n })
	if !ok || err != nil {
		t.Fatalf("copy: ok=%v err=%v", ok, err)
	}
	if recorded != 300 || active != 300 {
		t.Fatalf("recorded=%d active=%d want 300/300", recorded, active)
	}
}

// bufferedFakeSrc wraps fakeRelaySrc with a userspace-buffered signal: the
// fork capability reports bytes already queued, mimicking the bufio layer of
// a wrapped transport. The gather engine must batch through this signal
// without any TCP unwrap.
type bufferedFakeSrc struct {
	fakeRelaySrc
	hint int
}

func (s *bufferedFakeSrc) ReadBuffered() int { return s.hint }

func TestRelaySteadyGatherBatchesThroughBufferedSignal(t *testing.T) {
	withSteadyGather(t, true)
	src := &bufferedFakeSrc{hint: 16384}
	src.queue(rec(16384, 'u'), rec(16384, 'v'), rec(16384, 'w'), rec(16384, 'x'))
	src.markEOF()
	dst := &fakeRelayDst{}
	var flushes int
	written, err, ok := relaySteadyGatherCopy(context.Background(), dst, src,
		func(int64) { flushes++ }, nil)
	if !ok || err != nil {
		t.Fatalf("copy: ok=%v err=%v", ok, err)
	}
	if want := int64(4 * 16384); written != want {
		t.Fatalf("written=%d want %d", written, want)
	}
	if flushes != 1 {
		t.Fatalf("flushes=%d want 1 (userspace signal drives one batch)", flushes)
	}
}
