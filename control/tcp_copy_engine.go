/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"

	"github.com/daeuniverse/outbound/netproxy"
)

const relayCopyBufferSize = 32 << 10

// maxRelayCopyBuffers bounds how many 32KiB relay buffers are retained.
// 256 x 32KiB = 8MiB worst case.
const maxRelayCopyBuffers = 256

// relayCopyBufferPool recycles relay copy buffers. sync.Pool is cleared on
// every GC cycle, so under connection churn (speedtest opens hundreds of
// short-lived connections) every relay re-allocates its 32KiB buffer,
// feeding the GC loop. A bounded channel pool survives GC.
type relayCopyBufferPoolT struct {
	ch chan *[]byte
}

func newRelayCopyBufferPool() *relayCopyBufferPoolT {
	ch := make(chan *[]byte, maxRelayCopyBuffers)
	for i := 0; i < maxRelayCopyBuffers/4; i++ {
		b := make([]byte, relayCopyBufferSize)
		ch <- &b
	}
	return &relayCopyBufferPoolT{ch: ch}
}

func (p *relayCopyBufferPoolT) Get() *[]byte {
	select {
	case b := <-p.ch:
		return b
	default:
		b := make([]byte, relayCopyBufferSize)
		return &b
	}
}

func (p *relayCopyBufferPoolT) Put(b *[]byte) {
	select {
	case p.ch <- b:
	default:
		// pool full: drop the buffer, GC reclaims it
	}
}

var relayCopyBufferPool = newRelayCopyBufferPool()

func noopTrafficRecord(int64) {}

func normalizeTrafficRecord(record func(int64)) func(int64) {
	if record == nil {
		return noopTrafficRecord
	}
	return record
}

// relayCopyEngine defines the pluggable data plane used by relayCore.
// Implementations can optimize copy strategy without changing relay semantics.
type relayCopyEngine interface {
	Copy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, record func(int64), onActive func(int64)) (int64, error)
}

type defaultRelayCopyEngine struct{}

func (defaultRelayCopyEngine) Copy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, record func(int64), onActive func(int64)) (int64, error) {
	// First, handle any prefix via gather-write path.
	// This ensures FTP/server-first flows use stable copy loops for continuation.
	if n, err, ok := tryRelayGatherWrite(ctx, dst, src, record, onActive); ok {
		return n, err
	}
	// Fast path for unwrapped TCP pairs: use splice(2) on Linux.
	// Only enabled when both ends resolve to concrete *net.TCPConn without wrappers.
	// This preserves performance for pure TCP-to-TCP relay while keeping FTP safe.
	if shouldUseRelayFastPath(dst, src) {
		return relayFastCopy(ctx, dst, src, record, onActive)
	}
	// Slow path: will call Read() on wrapped connections
	bufPtr := relayCopyBufferPool.Get()
	buf := *bufPtr
	defer relayCopyBufferPool.Put(bufPtr)
	return relayCopyLoop(ctx, dst, src, buf, record, onActive)
}

func relayCopyLoop(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, buf []byte, record func(int64), onActive func(int64)) (written int64, err error) {
	record = normalizeTrafficRecord(record)
	onActive = normalizeTrafficRecord(onActive)
	for {
		// Check context cancellation. relayCore.run ensures ctx is never nil.
		if cerr := ctx.Err(); cerr != nil {
			return written, cerr
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			onActive(int64(nr))
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if nw > 0 {
				record(int64(nw))
				onActive(int64(nw))
			}
			if ew != nil {
				return written, ew
			}
			if nw < nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

// relayCopyDirect copies from src to dst using the provided buf.
// buf must be non-empty and is typically obtained from relayCopyBufferPool.
func relayCopyDirect(dst io.Writer, src io.Reader, buf []byte, record func(int64), onActive func(int64)) (written int64, err error) {
	record = normalizeTrafficRecord(record)
	onActive = normalizeTrafficRecord(onActive)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			onActive(int64(nr))
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if nw > 0 {
				record(int64(nw))
				onActive(int64(nw))
			}
			if ew != nil {
				return written, ew
			}
			if nw < nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}
