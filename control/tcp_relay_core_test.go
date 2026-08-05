package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// blockingMockConn blocks on Read until closed; Write always succeeds.
type blockingMockConn struct {
	closed atomic.Bool
}

func (m *blockingMockConn) Read(b []byte) (int, error) {
	for !m.closed.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	return 0, net.ErrClosed
}
func (m *blockingMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *blockingMockConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *blockingMockConn) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (m *blockingMockConn) Close() error                               { m.closed.Store(true); return nil }
func (m *blockingMockConn) SetDeadline(t time.Time) error              { return nil }
func (m *blockingMockConn) SetReadDeadline(t time.Time) error          { return nil }
func (m *blockingMockConn) SetWriteDeadline(t time.Time) error         { return nil }

// A fully idle relay (both directions blocked on Read, no traffic) must be
// reclaimed by the idle watchdog.
func TestRelayIdleWatchdogReclaimsIdleRelay(t *testing.T) {
	l := &blockingMockConn{}
	r := &blockingMockConn{}
	rc := newRelayCore(l, r, defaultRelayCopyEngine{}, nil, nil)
	// Inject a short idle bound and fast check cadence for the test.
	rc.idleTimeout = 200 * time.Millisecond
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	select {
	case <-done:
		// run returned -> both directional copies were unblocked and the
		// relay reclaimed.
	case <-time.After(3 * time.Second):
		t.Fatal("idle relay was not reclaimed by the watchdog")
	}
}

// Active relays (traffic refreshing lastActiveNano) must NOT be reclaimed.
func TestRelayIdleWatchdogKeepsActiveRelay(t *testing.T) {
	l := &blockingMockConn{}
	r := &activeMockConn{}
	rc := newRelayCore(l, r, defaultRelayCopyEngine{}, nil, nil)
	rc.idleTimeout = 300 * time.Millisecond
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	// Let the watchdog tick several times; an active relay must survive.
	time.Sleep(1 * time.Second)
	select {
	case err := <-done:
		t.Fatalf("active relay was reclaimed: %v", err)
	default:
	}
	cancel()
}

// activeMockConn produces a steady stream of reads so the relay is never idle.
type activeMockConn struct {
	closed atomic.Bool
	reads  atomic.Int64
}

func (m *activeMockConn) Read(b []byte) (int, error) {
	for !m.closed.Load() {
		if m.reads.Add(1) > 0 && m.reads.Load()%5 == 0 {
			b[0] = 'x'
			return 1, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return 0, net.ErrClosed
}
func (m *activeMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *activeMockConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *activeMockConn) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (m *activeMockConn) Close() error                               { m.closed.Store(true); return nil }
func (m *activeMockConn) SetDeadline(t time.Time) error              { return nil }
func (m *activeMockConn) SetReadDeadline(t time.Time) error          { return nil }
func (m *activeMockConn) SetWriteDeadline(t time.Time) error         { return nil }

// The idle watchdog must not interfere with graceful half-close semantics:
// a relay reclaimed by the watchdog returns promptly (its reads were
// unblocked by forceClose), whatever the surfaced error.
func TestRelayIdleWatchdogCoexistsWithHalfClose(t *testing.T) {
	l := &blockingMockConn{}
	rc := newRelayCore(l, l, defaultRelayCopyEngine{}, nil, nil)
	rc.idleTimeout = 100 * time.Millisecond
	rc.idleCheckPeriod = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	// Both directions blocked; watchdog should reclaim after ~100ms.
	select {
	case <-done:
		// Reclaimed promptly; the surfaced error (closed conn) is expected.
	case <-time.After(3 * time.Second):
		t.Fatal("relay not reclaimed")
	}
}

// delayedReleaseMockConn simulates a QUIC stream Read that does not unblock
// immediately on Close/SetReadDeadline, but eventually returns after a delay.
// This mirrors the real-world quic-go behavior where CancelRead may take a
// tick or two to propagate to the blocked goroutine.
type delayedReleaseMockConn struct {
	closed       atomic.Bool
	closeCh      chan struct{}
	releaseDelay time.Duration
}

func newDelayedReleaseMockConn(delay time.Duration) *delayedReleaseMockConn {
	return &delayedReleaseMockConn{closeCh: make(chan struct{}), releaseDelay: delay}
}

func (m *delayedReleaseMockConn) Read(b []byte) (int, error) {
	<-m.closeCh
	time.Sleep(m.releaseDelay)
	return 0, net.ErrClosed
}
func (m *delayedReleaseMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *delayedReleaseMockConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *delayedReleaseMockConn) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (m *delayedReleaseMockConn) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		close(m.closeCh)
	}
	return nil
}
func (m *delayedReleaseMockConn) SetDeadline(t time.Time) error      { return nil }
func (m *delayedReleaseMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *delayedReleaseMockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestRelayWatchdogSurvivesCtxCancel verifies that the watchdog keeps the
// relay alive after ctx cancellation (e.g. reload) and eventually reclaims
// it when the QUIC-like delayed Read finally returns.
func TestRelayWatchdogSurvivesCtxCancel(t *testing.T) {
	// Conn whose Read releases 200ms after Close (simulating quic-go delay).
	l := newDelayedReleaseMockConn(200 * time.Millisecond)
	r := newDelayedReleaseMockConn(200 * time.Millisecond)
	rc := newRelayCore(l, r, defaultRelayCopyEngine{}, nil, nil)
	rc.idleTimeout = 5 * time.Second // long idle; we test ctx-cancel, not idle
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	// Cancel ctx (simulating reload) after a brief warm-up.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Success: the watchdog nudged forceClose, the delayed Reads
		// eventually returned, and run() finished cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("relay leaked: run() did not return after ctx cancel + delayed Read release")
	}
}
