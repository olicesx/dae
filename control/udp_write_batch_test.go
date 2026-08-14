/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// batchRecorder implements PacketConn + PacketBatchWriter and records every
// batch (with deep-copied payloads so reuse of the aggregator buffer is safe).
type batchRecorder struct {
	mu      sync.Mutex
	batches [][]netproxy.BatchItem
	err     error
}

func (r *batchRecorder) WriteBatch(items []netproxy.BatchItem) (int, error) {
	clone := make([]netproxy.BatchItem, len(items))
	for i, it := range items {
		d := make([]byte, len(it.Data))
		copy(d, it.Data)
		clone[i] = netproxy.BatchItem{Data: d, Addr: it.Addr}
	}
	r.mu.Lock()
	r.batches = append(r.batches, clone)
	err := r.err
	r.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(items), nil
}

func (r *batchRecorder) batchCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

func (r *batchRecorder) batch(i int) []netproxy.BatchItem {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.batches[i]
}

func (r *batchRecorder) Read([]byte) (int, error)    { return 0, io.EOF }
func (r *batchRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (r *batchRecorder) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (r *batchRecorder) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (r *batchRecorder) Close() error                               { return nil }
func (r *batchRecorder) SetDeadline(time.Time) error                { return nil }
func (r *batchRecorder) SetReadDeadline(time.Time) error            { return nil }
func (r *batchRecorder) SetWriteDeadline(time.Time) error           { return nil }

func newBatchTestEndpoint(rec *batchRecorder) *UdpEndpoint {
	return &UdpEndpoint{conn: rec}
}

// TestAggregatorFlushOnFull: the 33rd Append flushes the first 32; the 33rd
// item is flushed by the window timer.
func TestAggregatorFlushOnFull(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	for i := 0; i < 33; i++ {
		if err := agg.Append([]byte{byte(i)}, "10.0.0.1:53"); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}
	// The full-batch flush happens synchronously inside the 33rd Append.
	if n := rec.batchCount(); n < 1 {
		t.Fatalf("expected a flush on full batch, got %d batches", n)
	}
	first := rec.batch(0)
	if len(first) != 32 {
		t.Fatalf("expected 32 items in first batch, got %d", len(first))
	}
	for i, it := range first {
		if len(it.Data) != 1 || it.Data[0] != byte(i) {
			t.Fatalf("item %d: unexpected payload %v", i, it.Data)
		}
		if it.Addr != "10.0.0.1:53" {
			t.Fatalf("item %d: unexpected addr %q", i, it.Addr)
		}
	}
	// The trailing item is flushed by the window timer.
	deadline := time.Now().Add(2 * time.Second)
	for rec.batchCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec.batchCount() != 2 {
		t.Fatalf("expected timer flush for trailing item, got %d batches", rec.batchCount())
	}
	second := rec.batch(1)
	if len(second) != 1 || second[0].Data[0] != 32 {
		t.Fatalf("unexpected trailing batch: %d items, first=%v", len(second), second[0].Data)
	}
}

// TestAggregatorFlushOnTimer: a single datagram is flushed after the window.
func TestAggregatorFlushOnTimer(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	if err := agg.Append([]byte("solo"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if rec.batchCount() != 0 {
		t.Fatal("single Append must not flush synchronously")
	}
	deadline := time.Now().Add(2 * time.Second)
	for rec.batchCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec.batchCount() != 1 {
		t.Fatal("expected timer flush")
	}
	b := rec.batch(0)
	if len(b) != 1 || string(b[0].Data) != "solo" {
		t.Fatalf("unexpected batch content: %v", b)
	}
}

// TestAggregatorBufferReuse: the backing buffer survives flushes and payloads
// are copied correctly across two full batches.
func TestAggregatorBufferReuse(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	for round := 0; round < 2; round++ {
		for i := 0; i < 33; i++ {
			if err := agg.Append(payload, "10.0.0.1:53"); err != nil {
				t.Fatalf("round %d Append #%d: %v", round, i, err)
			}
		}
	}
	if rec.batchCount() < 2 {
		t.Fatalf("expected 2 full flushes, got %d", rec.batchCount())
	}
	for round := 0; round < 2; round++ {
		b := rec.batch(round)
		if len(b) != 32 {
			t.Fatalf("round %d: expected 32 items, got %d", round, len(b))
		}
		for i, it := range b {
			if len(it.Data) != len(payload) || it.Data[0] != payload[0] || it.Data[len(payload)-1] != payload[len(payload)-1] {
				t.Fatalf("round %d item %d: payload corrupted", round, i)
			}
		}
	}
}

// TestAggregatorOversized: a datagram larger than the backing buffer falls
// back with errUDPWriteBatchOversized and does not corrupt the batch state.
func TestAggregatorOversized(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	big := make([]byte, udpWriteBatchMaxItems*udpWriteBatchItemSize+1)
	if err := agg.Append(big, "10.0.0.1:53"); !errors.Is(err, errUDPWriteBatchOversized) {
		t.Fatalf("expected errUDPWriteBatchOversized, got %v", err)
	}
	// Aggregator still usable afterwards.
	if err := agg.Append([]byte("ok"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append after oversized: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for rec.batchCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec.batchCount() != 1 || len(rec.batch(0)) != 1 {
		t.Fatal("expected single-item batch after oversized fallback")
	}
}

// TestAggregatorClosed: appends after Close fail with net.ErrClosed; pending
// items are flushed on Close.
func TestAggregatorClosed(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	if err := agg.Append([]byte("last"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	agg.Close()
	if rec.batchCount() != 1 {
		t.Fatalf("Close must flush pending items, got %d batches", rec.batchCount())
	}
	if err := agg.Append([]byte("x"), "10.0.0.1:53"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close, got %v", err)
	}
}

// TestAggregatorErrorClassified: a failed WriteBatch is routed through
// handleWriteError (soft-error counter increments, endpoint not retired).
func TestAggregatorErrorClassified(t *testing.T) {
	rec := &batchRecorder{err: errors.New("boom")}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	for i := 0; i < 33; i++ {
		if err := agg.Append([]byte{byte(i)}, "10.0.0.1:53"); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}
	if rec.batchCount() < 1 {
		t.Fatal("expected flush attempt on full batch")
	}
	if n := ue.writeSoftErrorCount.Load(); n != 1 {
		t.Fatalf("expected soft-error counter 1 after failed flush, got %d", n)
	}
	if ue.dead.Load() {
		t.Fatal("tolerated flush error must not retire the endpoint")
	}
}
