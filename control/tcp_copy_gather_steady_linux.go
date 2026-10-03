//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"os"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

// Steady-state write gathering for wrapped (non-splice) relay legs.
//
// Wrapped transports (trojan/VMess over TLS) deliver one decrypted TLS
// record per Read (crypto/tls returns a single record), so the plain copy
// loop issues one Write per ~16 KiB record: measured ~80 write syscalls
// per MB on a trojan leg. This engine accumulates consecutive records and
// flushes them with a single writev (relayGatherWriteTo) when either the
// batch bounds are hit or the source socket holds no more unread bytes.
// Only data that has already arrived is batched, so an interactive flow
// whose records arrive one at a time still flushes per record and no
// latency is added by construction.
//
// Availability is probed by observing kernel socket state (TIOCINQ pending
// bytes on the unwrapped TCP socket). The probe MUST NOT touch deadlines
// or issue speculative reads on wrapped streams: crypto/tls permanently
// poisons a connection whose record read fails with a non-temporary error,
// and an expired-deadline read landing mid-record does exactly that. A
// pending-data check observes the socket without influencing the stream.
// Sources that do not unwrap to a TCP socket (e.g. QUIC-backed streams
// such as hy2/tuic) report no pending data and batching degrades to one
// record per flush with no correctness impact.
//
// A gather read may block if the pending bytes are fewer than a complete
// record; the batch (bounded by relayGatherMaxSegments) is held until the
// record completes, which only delays the flush of already-decrypted
// records by the record completion time.
//
// Enabled by default; set DAE_TCP_RELAY_WRITE_GATHER=0 to disable.

const (
	// relayGatherMaxSegments bounds the number of reads coalesced into one
	// writev; 8 x 16 KiB TLS records = 128 KiB per flush.
	relayGatherMaxSegments = 8
	// relayGatherMaxBytes bounds a batch by payload size even when records
	// are smaller than the TLS maximum.
	relayGatherMaxBytes = 128 << 10
)

// relayWriteGatherEnabled reports whether steady-state write gathering is
// enabled. Invalid values fall back to the default (enabled).
var relayWriteGatherEnabled = envOverrideBool("DAE_TCP_RELAY_WRITE_GATHER", true)

// envOverrideBool applies an optional process-level boolean override for
// experimental toggles that are not exposed through the config grammar.
func envOverrideBool(name string, def bool) bool {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	switch raw {
	case "1", "true", "TRUE", "True":
		return true
	case "0", "false", "FALSE", "False":
		return false
	default:
		logrus.StandardLogger().Warnf("invalid %s=%q, using default %v", name, raw, def)
		return def
	}
}

// relayGatherSourceHasMoreBuffered reports whether the source already holds
// immediately-readable bytes in a userspace buffer or in the kernel socket.
// Both checks are purely observational: no deadlines are armed and no stream
// state is modified, so a probe can never poison a TLS record read.
//
// The userspace check dominates for wrapped transports: bulk traffic piles up
// in the transport chain's own buffers (the fork's bufio layer above TLS for
// trojan/vmess/vless, the QUIC receive queue for hy2/tuic/juicity), while
// the kernel socket is often already drained. The kernel check covers chains
// that buffer nothing in userspace.
func relayGatherSourceHasMoreBuffered(src netproxy.Conn) bool {
	if netproxy.ReadBuffered(src) > 0 {
		return true
	}
	srcTCP, ok := relayGatherWriteTCPConn(src)
	if !ok {
		return false
	}
	pending, err := tcpConnHasPendingReadData(srcTCP)
	return err == nil && pending
}

// relaySteadyGatherCopy relays src to dst, batching consecutive reads into
// single vectored writes. ok is false when the feature is disabled; callers
// then fall back to relayCopyLoop.
func relaySteadyGatherCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, record func(int64), onActive func(int64)) (written int64, err error, ok bool) {
	if !relayWriteGatherEnabled {
		return 0, nil, false
	}
	record = normalizeTrafficRecord(record)
	onActive = normalizeTrafficRecord(onActive)

	// gatherSeg pairs the full-length pooled buffer (pool entries must keep
	// their original capacity/length) with the truncated view handed to the
	// write path.
	type gatherSeg struct {
		bufPtr *[]byte
		view   []byte
	}
	segs := make([]gatherSeg, 0, relayGatherMaxSegments)
	views := make([][]byte, 0, relayGatherMaxSegments)
	total := 0
	// Pool discipline: every checked-out buffer is tracked in segs and
	// returned exactly once on every return path (flush resets segs after
	// returning its buffers; the defer covers early returns).
	releaseSegs := func() {
		for i := range segs {
			relayCopyBufferPool.Put(segs[i].bufPtr)
		}
		segs = segs[:0]
	}
	defer releaseSegs()

	flush := func() error {
		if len(segs) == 0 {
			return nil
		}
		views = views[:0]
		for i := range segs {
			views = append(views, segs[i].view)
		}
		nw, werr := relayGatherWriteTo(dst, views)
		releaseSegs()
		total = 0
		written += int64(nw)
		if nw > 0 {
			record(int64(nw))
		}
		return werr
	}

	for {
		// Check context cancellation. relayCore.run ensures ctx is never nil.
		if cerr := ctx.Err(); cerr != nil {
			return written, cerr, true
		}

		bufPtr := relayCopyBufferPool.Get().(*[]byte)
		nr, er := src.Read(*bufPtr)
		if nr > 0 {
			segs = append(segs, gatherSeg{bufPtr: bufPtr, view: (*bufPtr)[:nr]})
			total += nr
			// Refresh activity per read, not per flush: a slow producer can
			// hold a batch open longer than the relay idle bound, and the
			// read itself is the traffic signal.
			onActive(int64(nr))
			// Gather further already-arrived reads while under the batch
			// bounds. The probe observes socket state only; when it reports
			// no pending bytes (or the source does not unwrap to a TCP
			// socket) the batch ends and flushes without waiting.
			for total < relayGatherMaxBytes && len(segs) < relayGatherMaxSegments {
				if !relayGatherSourceHasMoreBuffered(src) {
					break
				}
				pBufPtr := relayCopyBufferPool.Get().(*[]byte)
				pn, _ := src.Read(*pBufPtr)
				if pn > 0 {
					segs = append(segs, gatherSeg{bufPtr: pBufPtr, view: (*pBufPtr)[:pn]})
					total += pn
					onActive(int64(pn))
					continue
				}
				relayCopyBufferPool.Put(pBufPtr)
				break
			}
			if ferr := flush(); ferr != nil {
				return written, ferr, true
			}
		} else {
			relayCopyBufferPool.Put(bufPtr)
		}
		if er != nil {
			if er == io.EOF {
				return written, nil, true
			}
			return written, er, true
		}
	}
}
