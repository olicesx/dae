package control

import (
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/daeuniverse/dae/component/outbound"
)

func TestParseDaeEventBlockedAlive(t *testing.T) {
	b := make([]byte, 72)
	binary.LittleEndian.PutUint64(b[0:8], 12345)
	binary.LittleEndian.PutUint32(b[8:12], daeEventBlockedAlive)
	binary.LittleEndian.PutUint32(b[12:16], 42)
	copy(b[16:32], "someproc")
	b[32] = 3 // outbound
	b[33] = unix.IPPROTO_UDP
	binary.LittleEndian.PutUint16(b[68:70], 12345)
	binary.LittleEndian.PutUint16(b[70:72], 53)

	ev := parseDaeEvent(b)
	if ev.Type != daeEventBlockedAlive {
		t.Fatalf("expected type %d, got %d", daeEventBlockedAlive, ev.Type)
	}
	if ev.Outbound != 3 {
		t.Fatalf("expected outbound 3, got %d", ev.Outbound)
	}
	if ev.L4proto != unix.IPPROTO_UDP {
		t.Fatalf("expected l4proto %d, got %d", unix.IPPROTO_UDP, ev.L4proto)
	}
	if ev.Pid != 42 {
		t.Fatalf("expected pid 42, got %d", ev.Pid)
	}
	if ev.Sport != 12345 || ev.Dport != 53 {
		t.Fatalf("unexpected ports: %d/%d", ev.Sport, ev.Dport)
	}
	if string(ev.Pname[:8]) != "someproc" {
		t.Fatalf("unexpected pname: %q", ev.Pname[:8])
	}
}

func TestParseDaeEventShort(t *testing.T) {
	// Buffer shorter than the 72-byte struct must parse to a zero event
	// (type 0 = daeEventBlocked, which the switch ignores).
	ev := parseDaeEvent([]byte{1, 2, 3})
	if ev.Type != 0 || ev.Timestamp != 0 {
		t.Fatalf("short buffer should parse to zero event, got %+v", ev)
	}
}

func TestParseDaeEventExactBoundary(t *testing.T) {
	// Exactly 72 bytes with all fields at max values must not panic.
	b := make([]byte, 72)
	for i := range b {
		b[i] = 0xff
	}
	binary.LittleEndian.PutUint32(b[8:12], daeEventBlockedAlive)
	ev := parseDaeEvent(b)
	if ev.Type != daeEventBlockedAlive {
		t.Fatalf("expected type %d, got %d", daeEventBlockedAlive, ev.Type)
	}
	if ev.Outbound != 0xff {
		t.Fatalf("expected outbound 255, got %d", ev.Outbound)
	}
	// 73+ bytes: extra trailing bytes must be ignored safely.
	b2 := make([]byte, 74)
	copy(b2, b)
	ev2 := parseDaeEvent(b2)
	if ev2.Type != daeEventBlockedAlive {
		t.Fatalf("expected type %d for oversized buffer, got %d", daeEventBlockedAlive, ev2.Type)
	}
}

func TestHandleBlockedAliveEventOutOfRange(t *testing.T) {
	// nil plane and out-of-range outbound must not panic.
	var c *ControlPlane
	c.handleBlockedAliveEvent(&daeEvent{Type: daeEventBlockedAlive, Outbound: 255})
}

func TestHandleBlockedAliveEventUnknownProto(t *testing.T) {
	// Unknown l4proto must be ignored (no probe of the wrong family).
	c := &ControlPlane{core: &controlPlaneCore{}}
	c.outbounds = []*outbound.DialerGroup{}
	c.handleBlockedAliveEvent(&daeEvent{Type: daeEventBlockedAlive, Outbound: 0, L4proto: 99})
}

func TestHandleBlockedAliveEventEmpty(t *testing.T) {
	// Empty outbounds slice: length check must return before access.
	c := &ControlPlane{core: &controlPlaneCore{}}
	c.outbounds = []*outbound.DialerGroup{}
	c.handleBlockedAliveEvent(&daeEvent{Type: daeEventBlockedAlive, Outbound: 0, L4proto: unix.IPPROTO_UDP})
	// nil core must be safe.
	(&ControlPlane{}).handleBlockedAliveEvent(&daeEvent{Type: daeEventBlockedAlive, L4proto: unix.IPPROTO_UDP})
}

// tryDoRateLimitedAction is the primitive gating event-driven resuscitation
// (via DialerGroup.Resuscitate). Verify first-call-immediate + interval-gated
// semantics: this is what prevents probe storms while still allowing the
// first blocked packet to trigger an instant probe.
func TestRateLimitedActionSemantics(t *testing.T) {
	var last atomic.Int64
	interval := 30 * time.Second

	now := time.Now().UnixNano()
	// First call passes immediately (last is zero).
	if !casRateLimited(&last, now, interval) {
		t.Fatal("first call should pass")
	}
	// Second call within interval rejected.
	if casRateLimited(&last, now+100, interval) {
		t.Fatal("second call within interval should be rejected")
	}
	// Call after interval passes again.
	if !casRateLimited(&last, now+int64(31*time.Second), interval) {
		t.Fatal("call after interval should pass again")
	}
}

func TestRateLimitedActionConcurrent(t *testing.T) {
	// Concurrent callers must not all win: exactly one should pass.
	var last atomic.Int64
	interval := 30 * time.Second
	now := time.Now().UnixNano()
	winners := make(chan bool, 64)
	for i := 0; i < 64; i++ {
		go func() {
			winners <- casRateLimited(&last, now, interval)
		}()
	}
	passed := 0
	for i := 0; i < 64; i++ {
		if <-winners {
			passed++
		}
	}
	if passed != 1 {
		t.Fatalf("expected exactly 1 winner under concurrency, got %d", passed)
	}
}

// casRateLimited mirrors DialerGroup.tryDoRateLimitedAction's CAS pattern.
func casRateLimited(last *atomic.Int64, nowNano int64, interval time.Duration) bool {
	l := last.Load()
	if nowNano-l < int64(interval) {
		return false
	}
	return last.CompareAndSwap(l, nowNano)
}
