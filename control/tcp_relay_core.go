/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

const (
	relayHalfCloseTimeout = 10 * time.Second
	// relayIdleTimeout bounds how long a relay may sit with zero traffic in
	// both directions before it is force-closed. A half-open peer (vanished
	// without FIN/RST) otherwise parks the directional read forever and the
	// relay leaks. Any traffic in either direction refreshes lastActive, so
	// long-lived but active connections (SSH, gaming) are never touched.
	relayIdleTimeout = 5 * time.Minute
	// relayIdleCheckInterval is the watchdog cadence for idle reclamation.
	relayIdleCheckInterval = 30 * time.Second
)

type relayCore struct {
	left  netproxy.Conn
	right netproxy.Conn

	copyEngine       relayCopyEngine
	halfCloseTimeout time.Duration
	idleTimeout      time.Duration
	idleCheckPeriod  time.Duration
	leftRecord       func(int64)
	rightRecord      func(int64)

	// lastActiveNano is the last time either direction read or wrote data.
	// Guarded by atomic; updated by the copy engines via onActive.
	lastActiveNano atomic.Int64
}

type relayDirection struct {
	name   string
	src    netproxy.Conn
	dst    netproxy.Conn
	record func(int64)
}

type relayResult struct {
	dir string
	err error
}

func newRelayCore(lConn, rConn netproxy.Conn, engine relayCopyEngine, leftRecord func(int64), rightRecord func(int64)) *relayCore {
	return &relayCore{
		left:             lConn,
		right:            rConn,
		copyEngine:       engine,
		halfCloseTimeout: relayHalfCloseTimeout,
		idleTimeout:      relayIdleTimeout,
		idleCheckPeriod:  relayIdleCheckInterval,
		leftRecord:       leftRecord,
		rightRecord:      rightRecord,
	}
}

func (c *relayCore) run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	defer close(watchDone)
	defer cancel()

	results := make(chan relayResult, 2)
	var forceCloseOnce sync.Once

	// nudgeReads repeatedly pokes SetReadDeadline on both conns. quic-go
	// (hy2/tuic) may not synchronously unblock a Read after a single
	// SetReadDeadline + Close: the blocked goroutine can remain parked in
	// an internal channel receive. Repeatedly advancing the deadline gives
	// the runtime additional wake-up opportunities without harming already-
	// closed conns (SetReadDeadline on a closed conn returns an error we
	// ignore). TCP conns unblock on the very first nudge, so the loop is
	// a no-op for them thereafter.
	nudgeReads := func() {
		past := time.Unix(1, 0)
		_ = c.left.SetReadDeadline(past)
		_ = c.right.SetReadDeadline(past)
	}

	forceClose := func() {
		forceCloseOnce.Do(func() {
			nudgeReads()
			_ = c.left.Close()
			_ = c.right.Close()
		})
	}

	go func() {
		select {
		case <-ctx.Done():
			forceClose()
		case <-watchDone:
		}
	}()

	// Idle watchdog: half-open peers (vanished without FIN/RST) never return
	// from their directional read, so without a bound the relay goroutine pair
	// leaks. Any traffic in either direction refreshes lastActiveNano; only a
	// fully idle relay is reclaimed.
	//
	// The watchdog deliberately ignores ctx cancellation: when a control-plane
	// reload retires a generation, ctx is canceled and the ctx-watcher above
	// calls forceClose. But for QUIC streams (hy2/tuic), SetReadDeadline and
	// even Close/CancelRead may not synchronously unblock a pending Read in
	// quic-go. If the watchdog also exited on ctx.Done, no one would remain to
	// reap the relay once the QUIC Read eventually returns. By staying alive
	// on its own idle timer, the watchdog guarantees that even a stuck relay
	// is force-closed again once it goes idle, and that run() does not return
	// until both directions have actually finished.
	c.lastActiveNano.Store(time.Now().UnixNano())
	idleTimeout := c.idleTimeout
	if idleTimeout <= 0 {
		idleTimeout = relayIdleTimeout
	}
	checkPeriod := c.idleCheckPeriod
	if checkPeriod <= 0 {
		checkPeriod = relayIdleCheckInterval
	}
	go func() {
		ctxCanceled := false
		ticker := time.NewTicker(checkPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-ctx.Done():
				// ctx was canceled (e.g. reload retired the generation).
				// forceClose was already called by the ctx-watcher, but for
				// QUIC streams the blocked Read may not have woken up yet.
				// Switch to nudge mode: keep poking SetReadDeadline until the
				// relay finishes (watchDone), giving quic-go repeated chances
				// to unblock the parked goroutine.
				ctxCanceled = true
			case <-ticker.C:
				if ctxCanceled {
					// Keep nudging after cancellation — quic-go may need
					// multiple deadline pokes to unblock a parked Read.
					nudgeReads()
					continue
				}
				if time.Since(time.Unix(0, c.lastActiveNano.Load())) > idleTimeout {
					// Idle beyond the bound: reclaim the relay. forceClose
					// unblocks both directional reads via deadline + Close.
					cancel()
					forceClose()
					return
				}
			}
		}
	}()

	runDirection := func(dir relayDirection) {
		onActive := func(_ int64) {
			c.lastActiveNano.Store(time.Now().UnixNano())
		}
		_, err := c.copyEngine.Copy(ctx, dir.dst, dir.src, dir.record, onActive)

		if wc, ok := dir.dst.(WriteCloser); ok {
			_ = wc.CloseWrite()
		}

		if err != nil {
			// Any directional copy error is treated as terminal for this relay:
			// cancel shared context and force-close both sides to promptly
			// unblock pending reads/writes in the peer direction.
			cancel()
			forceClose()
		} else {
			// Graceful half-close: bound the peer's pending read on dir.dst
			// (which is the source of the opposite direction).
			_ = dir.dst.SetReadDeadline(time.Now().Add(c.halfCloseTimeout))
		}

		results <- relayResult{
			dir: dir.name,
			err: err,
		}
	}

	go runDirection(relayDirection{
		name:   "l2r",
		src:    c.left,
		dst:    c.right,
		record: c.rightRecord,
	})
	go runDirection(relayDirection{
		name:   "r2l",
		src:    c.right,
		dst:    c.left,
		record: c.leftRecord,
	})

	first := <-results
	second := <-results
	return mergeRelayErrors(first.err, second.err)
}

// mergeRelayErrors combines errors from both relay directions.
// Uses errors.Join to preserve both errors for inspection with errors.Is/As.
func mergeRelayErrors(err1, err2 error) error {
	return stderrors.Join(err1, err2)
}
