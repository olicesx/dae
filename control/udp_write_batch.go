/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
)

const (
	// udpWriteBatchMaxItems is the number of datagrams accumulated before a
	// batched flush. 32 amortizes the per-datagram UDP write syscall (the
	// dominant hot-path cost under saturated multi-flow UDP: pprof showed
	// ~31% CPU in the write syscall alone) while bounding flush latency.
	udpWriteBatchMaxItems = 32
	// udpWriteBatchWindow is the maximum time a datagram waits in the batch
	// buffer before being flushed. 1ms adds a bounded tail-latency cost that
	// is negligible for game UDP (tens of ms tolerance) but lets low-rate
	// flows still benefit from batching.
	udpWriteBatchWindow = time.Millisecond
	// udpWriteBatchItemSize sizes the batch backing buffer (32 x MTU).
	udpWriteBatchItemSize = consts.EthernetMtu
)

// errUDPWriteBatchOversized is returned by Append when a single datagram is
// larger than the whole batch backing buffer; the caller falls back to a
// direct synchronous write for that datagram.
var errUDPWriteBatchOversized = stderrors.New("udp write batch: datagram too large")

// udpWriteBatchAggregator accumulates datagrams for one UdpEndpoint and
// flushes them through the transport's batched writer (sendmmsg on direct
// UDP, per the netproxy.PacketBatchWriter extension). Flush triggers: batch
// full (udpWriteBatchMaxItems) or udpWriteBatchWindow timer, whichever comes
// first. Write errors are routed through the endpoint's existing retirement
// policy asynchronously, so the synchronous Append path stays allocation-
// light and lock-free for the common case.
//
// Per-flow ordering is preserved: the per-flow convoy task pool funnels each
// flow's WriteTo calls through a single producer, Append preserves order, and
// flush drains in order.
type udpWriteBatchAggregator struct {
	ue *UdpEndpoint

	mu    sync.Mutex
	items []netproxy.BatchItem
	buf   []byte
	used  int
	timer *time.Timer

	flushing atomic.Bool
	closed   atomic.Bool
}

func newUDPWriteBatchAggregator(ue *UdpEndpoint) *udpWriteBatchAggregator {
	return &udpWriteBatchAggregator{ue: ue}
}

// Append copies data into the batch backing buffer and returns immediately.
// The batch is flushed when it reaches udpWriteBatchMaxItems or after
// udpWriteBatchWindow. Returns errUDPWriteBatchOversized for datagrams that
// do not fit the backing buffer (caller falls back to a direct write); other
// errors mean the aggregator is closed.
func (a *udpWriteBatchAggregator) Append(data []byte, addr string) error {
	if a.closed.Load() {
		return net.ErrClosed
	}
	for {
		a.mu.Lock()
		if len(a.items) >= udpWriteBatchMaxItems || (a.used+len(data) > len(a.buf) && len(a.buf) > 0) {
			a.mu.Unlock()
			a.flush()
			continue
		}
		if a.buf == nil {
			a.buf = make([]byte, udpWriteBatchMaxItems*udpWriteBatchItemSize)
		}
		if a.used+len(data) > len(a.buf) {
			a.mu.Unlock()
			return errUDPWriteBatchOversized
		}
		copy(a.buf[a.used:], data)
		a.items = append(a.items, netproxy.BatchItem{
			Data: a.buf[a.used : a.used+len(data)],
			Addr: addr,
		})
		a.used += len(data)
		if len(a.items) == 1 {
			a.timer = time.AfterFunc(udpWriteBatchWindow, a.flush)
		}
		a.mu.Unlock()
		return nil
	}
}

// flush drains the current batch through the batched writer. It is safe to
// call from the timer callback, from Append when the batch is full, and from
// Close. The aggregator mutex is held across the actual transport write:
// BatchItem.Data must remain valid until WriteBatch returns (netproxy
// contract), and the shared backing buffer may not be reused by a concurrent
// Append while a batch is in flight. Write-error classification is
// deliberately deferred until after the unlock — handleWriteError can retire
// the endpoint, whose Close re-enters this aggregator via writeBatch.Close,
// and Go's mutex is not reentrant.
//
// Holding mu across the syscall is a deliberate final design, not an
// oversight. The contention domain is one endpoint only: dae's per-flow FIFO
// ingress (UdpTaskPool) funnels each endpoint's writes through its own convoy
// sender, so there is a single producer goroutine in the steady state, and
// the underlying socket serializes datagrams in-kernel anyway. Slot-swap or
// copy-out variants would relocate that same serialization into an atomic
// handshake (or pay an extra memcpy per packet) while adding tail latency for
// cross-batch reordering — strictly worse here. Revisit only if a future
// consumer feeds one aggregator from many goroutines.
func (a *udpWriteBatchAggregator) flush() {
	if !a.flushing.CompareAndSwap(false, true) {
		return
	}
	defer a.flushing.Store(false)

	a.mu.Lock()
	// Reuse the items backing array instead of dropping it for GC: the next
	// Append runs under this same mutex only after the transport write below
	// completes, so nothing can observe half-reset entries. This avoids
	// reallocating a 32-item slice on every flush window per batched endpoint.
	var items []netproxy.BatchItem
	if len(a.items) > 0 {
		items = a.items
		a.items = a.items[:0]
	}
	a.used = 0
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	if len(items) == 0 {
		a.mu.Unlock()
		return
	}
	a.ue.armWriteDeadline(time.Now())
	bw, ok := a.ue.conn.(netproxy.PacketBatchWriter)
	if !ok {
		// The aggregator is only installed on batched transports; this is a
		// defensive fallback that preserves ordering via synchronous writes.
		// It also runs under the mutex for the same buffer-lifetime reason.
		var fallbackErr error
		sentAny := false
		for _, it := range items {
			if _, err := a.ue.conn.WriteTo(it.Data, it.Addr); err != nil {
				fallbackErr = err
				break
			}
			sentAny = true
		}
		a.mu.Unlock()
		if fallbackErr != nil {
			_ = a.ue.handleWriteError(fallbackErr)
			if sentAny {
				// Some datagrams already left the socket; keep the
				// send timestamp honest even though the rest failed.
				a.ue.hasSent.Store(true)
				a.ue.lastSendNano.Store(time.Now().UnixNano())
			}
			return
		}
		a.ue.hasSent.Store(true)
		a.ue.lastSendNano.Store(time.Now().UnixNano())
		return
	}
	n, err := bw.WriteBatch(items)
	a.mu.Unlock()

	if err != nil {
		_ = a.ue.handleWriteError(err)
		if n > 0 {
			a.ue.hasSent.Store(true)
			a.ue.lastSendNano.Store(time.Now().UnixNano())
		}
		return
	}
	if n < len(items) {
		_ = a.ue.handleWriteError(fmt.Errorf("%w: batched write sent %d/%d datagrams", io.ErrShortWrite, n, len(items)))
		if n > 0 {
			a.ue.hasSent.Store(true)
			a.ue.lastSendNano.Store(time.Now().UnixNano())
		}
		return
	}
	a.ue.hasSent.Store(true)
	a.ue.lastSendNano.Store(time.Now().UnixNano())
}

// Close flushes any pending batch and disables further appends.
func (a *udpWriteBatchAggregator) Close() {
	if a.closed.CompareAndSwap(false, true) {
		a.flush()
	}
}
