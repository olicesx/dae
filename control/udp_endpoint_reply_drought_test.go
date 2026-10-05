/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	daeerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
)

// establishedWithDrought builds an established test endpoint whose upstream has
// been silent for the given drought while the client sent `writes` datagrams
// since that last reply.
func establishedWithDrought(t *testing.T, drought time.Duration, writes int64) (*UdpEndpoint, *mockPacketConn) {
	t.Helper()
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	ue.hasReply.Store(true)
	ue.lastReplyNano.Store(time.Now().Add(-drought).UnixNano())
	ue.writesSinceReply.Store(writes)
	return ue, mock
}

// A session whose upstream stopped replying while the client kept sending at a
// game-like rate is presumed reaped: the next write retires it with the
// normal-close classification so the caller redials a fresh session (and a
// fresh forwarding source port).
func TestUdpEndpointWriteToRebuildsOnReplyDrought(t *testing.T) {
	var transportWrites int
	mock := &mockPacketConn{writeToFn: func(p []byte, addr string) (int, error) {
		transportWrites++
		return len(p), nil
	}}
	ue := newTestEndpoint(mock)
	ue.hasReply.Store(true)
	ue.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())
	ue.writesSinceReply.Store(300) // a 10 Hz game heartbeat across the drought

	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, daeerrors.ErrClosedConnection) {
		t.Fatalf("expected ErrClosedConnection on a reply drought, got: %v", err)
	}
	if isUdpEndpointWriteTolerated(err) {
		t.Fatal("a reply-drought rebuild must not be classified as a tolerated write error")
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must be retired after a reply drought")
	}
	if transportWrites != 0 {
		t.Fatalf("the rebuilding write must not reach the transport, got %d writes", transportWrites)
	}
}

// WireGuard-style one-way keepalive: the client transmits, the peer never
// replies while idle, and the packet rate is far below the drought threshold.
// Rebuilding here would move the tunnel's source port for no reason.
func TestUdpEndpointWriteToKeepsSlowKeepaliveThroughDrought(t *testing.T) {
	ue, _ := establishedWithDrought(t, 2*time.Minute, 5) // ~0.04 packets/s

	n, err := ue.WriteTo([]byte("keepalive"), "1.2.3.4:51820")
	if err != nil {
		t.Fatalf("expected the keepalive to succeed through a reply drought, got: %v", err)
	}
	if n != len("keepalive") {
		t.Fatalf("expected %d bytes written, got %d", len("keepalive"), n)
	}
	if ue.dead.Load() {
		t.Fatal("sparse one-way traffic must keep the session and its source port")
	}
}

// A reply gap shorter than the drought window is not evidence of anything: the
// session must stay exactly as it is.
func TestUdpEndpointWriteToKeepsShortReplyGap(t *testing.T) {
	ue, _ := establishedWithDrought(t, udpEndpointReplyDroughtWindow-time.Second, 300)

	if _, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53"); err != nil {
		t.Fatalf("expected success across a short reply gap, got: %v", err)
	}
	if ue.dead.Load() {
		t.Fatal("a reply gap inside the window must not retire the endpoint")
	}
}

// The rate gate uses two measurements and the larger one decides: the lifetime
// average over the drought (a steady flow) and the datagrams counted in the
// most recent probe window (a burst). These cases pin each measurement and its
// boundary.
func TestUdpEndpointDroughtRateBoundary(t *testing.T) {
	write := func(t *testing.T, ue *UdpEndpoint) error {
		t.Helper()
		_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
		return err
	}
	t.Run("lifetime_average_below_threshold_keeps_session", func(t *testing.T) {
		// One packet per second across the window: sparse, keep the session.
		ue, _ := establishedWithDrought(t, udpEndpointReplyDroughtWindow, int64(udpEndpointReplyDroughtMinRate-1)*30)
		if err := write(t, ue); err != nil {
			t.Fatalf("expected success below the rate threshold, got: %v", err)
		}
		if ue.dead.Load() {
			t.Fatal("a rate below the threshold must not rebuild")
		}
	})
	t.Run("lifetime_average_above_threshold_rebuilds", func(t *testing.T) {
		// A 10 Hz sender across the window.
		ue, _ := establishedWithDrought(t, udpEndpointReplyDroughtWindow, int64(udpEndpointReplyDroughtMinRate)*150)
		if err := write(t, ue); !stderrors.Is(err, daeerrors.ErrClosedConnection) {
			t.Fatalf("expected ErrClosedConnection above the rate threshold, got: %v", err)
		}
		if !ue.dead.Load() {
			t.Fatal("a sustained rate above the threshold must rebuild")
		}
	})
	t.Run("recent_burst_rebuilds_despite_low_lifetime_average", func(t *testing.T) {
		// A game that syncs state every tens of seconds: 20 datagrams in the
		// current probe window across a 5 minute drought, i.e. an average far
		// below the threshold. The burst is the evidence that the client is
		// transmitting now.
		ue, _ := establishedWithDrought(t, 10*udpEndpointReplyDroughtWindow, 20)
		ue.recentWriteBucket.Store(time.Now().UnixNano() / int64(udpEndpointReplyDroughtProbeWindow))
		ue.recentWriteBucketWrites.Store(int64(udpEndpointReplyDroughtMinRate) * int64(udpEndpointReplyDroughtProbeWindow/time.Second))
		if err := write(t, ue); !stderrors.Is(err, daeerrors.ErrClosedConnection) {
			t.Fatalf("expected ErrClosedConnection on a recent burst, got: %v", err)
		}
		if !ue.dead.Load() {
			t.Fatal("a burst into a session that stopped replying must rebuild")
		}
	})
	t.Run("recent_activity_below_window_threshold_keeps_session", func(t *testing.T) {
		// One datagram short of the window threshold, with an average far
		// below it: still not enough evidence.
		ue, _ := establishedWithDrought(t, 10*udpEndpointReplyDroughtWindow, 20)
		ue.recentWriteBucket.Store(time.Now().UnixNano() / int64(udpEndpointReplyDroughtProbeWindow))
		ue.recentWriteBucketWrites.Store(int64(udpEndpointReplyDroughtMinRate)*int64(udpEndpointReplyDroughtProbeWindow/time.Second) - 1)
		if err := write(t, ue); err != nil {
			t.Fatalf("expected success below the window threshold, got: %v", err)
		}
		if ue.dead.Load() {
			t.Fatal("activity below the window threshold must not rebuild")
		}
	})
}

// A probing endpoint has no reply evidence at all, so there is no drought to
// reason about however much the client transmits.
func TestUdpEndpointDroughtNeverFiresWithoutReplyEvidence(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	ue.writesSinceReply.Store(100000)

	if _, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53"); err != nil {
		t.Fatalf("expected success while probing, got: %v", err)
	}
	if ue.dead.Load() {
		t.Fatal("probing endpoints must never be rebuilt by the drought check")
	}
}

// A reply is proof of life: it clears the accumulated drought evidence so the
// next write starts a fresh window.
func TestUdpEndpointReplyClearsDroughtEvidence(t *testing.T) {
	ue, _ := establishedWithDrought(t, udpEndpointReplyDroughtWindow+time.Second, 300)
	ue.setNatTimeout(time.Minute)

	ue.markReplied(time.Now().UnixNano(), netip.AddrPort{})
	if got := ue.writesSinceReply.Load(); got != 0 {
		t.Fatalf("writesSinceReply = %d after a reply, want 0", got)
	}
	if _, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53"); err != nil {
		t.Fatalf("expected success right after a reply, got: %v", err)
	}
	if ue.dead.Load() {
		t.Fatal("a fresh reply must protect the session from the drought rebuild")
	}
}

// A recent burst from before a reply must not survive into the next drought.
// Without the bucket-freshness check, markReplied clears writesSinceReply but
// leaves recentWriteBucketWrites populated; the first write after a long quiet
// pause can then be mistaken for a current burst and rebuild a healthy session.
func TestUdpEndpointReplyDoesNotReuseOldRecentBucket(t *testing.T) {
	ue, _ := establishedWithDrought(t, udpEndpointReplyDroughtWindow+time.Second, 0)
	ue.setNatTimeout(time.Minute)
	now := time.Now()
	replyAt := now.Add(-udpEndpointReplyDroughtWindow - time.Second)
	ue.recentWriteBucket.Store(replyAt.UnixNano() / int64(udpEndpointReplyDroughtProbeWindow))
	ue.recentWriteBucketWrites.Store(int64(udpEndpointReplyDroughtMinRate) * int64(udpEndpointReplyDroughtProbeWindow/time.Second))
	ue.markReplied(replyAt.UnixNano(), netip.AddrPort{})

	if got := ue.writesSinceReply.Load(); got != 0 {
		t.Fatalf("writesSinceReply = %d after a reply, want 0", got)
	}
	if err := ue.maybeRebuildOnReplyDrought(now); err != nil {
		t.Fatalf("an old recent bucket must not trigger a rebuild: %v", err)
	}
	if ue.dead.Load() {
		t.Fatal("an old recent bucket incorrectly retired the endpoint")
	}
}

// Transactional flows (DNS) own their per-request timeout and pooled-conn
// discard policy, so the reply-drought rebuild stays off for them even when the
// evidence is present.
func TestUdpEndpointDroughtRebuildHonorsTransactionalProfile(t *testing.T) {
	ue, _ := establishedWithDrought(t, 10*udpEndpointReplyDroughtWindow, 100000)
	ue.lifecycleProfile = newDnsLifecycleProfile(nil)

	if _, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53"); err != nil {
		t.Fatalf("expected success on a transactional flow, got: %v", err)
	}
	if ue.dead.Load() {
		t.Fatal("transactional profiles must not use the reply-drought rebuild")
	}
}

// Closed loop: a reply-drought write retires the pooled endpoint, the retry
// dials a fresh transport session (a new forwarding identity) and the datagram
// is delivered on it. This is the recovery path a reaped game server or
// conntrack entry needs, exercised end to end through the real pool and retry
// logic.
func TestHandlePkt_ReplyDroughtRedialsFreshEndpoint(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn1 := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	conn2 := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	var factoryCalls atomic.Int32
	d, _ := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", func() netproxy.Conn {
		if factoryCalls.Add(1) == 1 {
			return conn1
		}
		return conn2
	})
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	if err := cp.handlePktWithPrefetch(payload, src, dst, routingResult, flowDecision, nil, UdpEndpointKey{}, false); err != nil {
		t.Fatalf("first handlePkt: %v", err)
	}
	first, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || first == nil {
		t.Fatal("expected a pooled endpoint after the first packet")
	}
	if got := conn1.writeCalls.Load(); got != 1 {
		t.Fatalf("first session WriteTo calls = %d, want 1", got)
	}

	// The peer has been silent for a full drought while the client kept up a
	// game-like rate: this is the state a reaped remote leaves behind.
	first.hasReply.Store(true)
	first.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())
	first.writesSinceReply.Store(300)

	if err := cp.handlePktWithPrefetch(payload, src, dst, routingResult, flowDecision, nil, UdpEndpointKey{}, false); err != nil {
		t.Fatalf("handlePkt after the reply drought: %v", err)
	}

	if got := factoryCalls.Load(); got != 2 {
		t.Fatalf("transport dials = %d, want 2 (a fresh session must be dialed)", got)
	}
	second, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || second == nil {
		t.Fatal("expected a replacement pooled endpoint after the drought rebuild")
	}
	if second == first {
		t.Fatal("the drought rebuild must replace the endpoint")
	}
	if !first.dead.Load() {
		t.Fatal("the reaped session's endpoint must be retired")
	}
	if got := conn2.writeCalls.Load(); got != 1 {
		t.Fatalf("replacement session WriteTo calls = %d, want 1 (the datagram must be delivered on the fresh session)", got)
	}
	if got := second.writesSinceReply.Load(); got != 1 {
		t.Fatalf("replacement writesSinceReply = %d, want 1", got)
	}
	if second.hasReply.Load() {
		t.Fatal("the replacement session must start probing again (hasReply = false)")
	}
	// The replacement must inherit the recovery budget from the session it
	// replaced, or a peer that answers once and goes quiet would be rebuilt
	// every window.
	if got := second.droughtRebuildGeneration; got != 1 {
		t.Fatalf("replacement droughtRebuildGeneration = %d, want 1 (the rebuild must be carried across remove-and-redial)", got)
	}
}

// A flow whose healthy reply cadence is slower than the drought window must
// not be rebuilt on every quiet gap: once the session has bridged a 60s
// interval between two replies, the drought threshold rises to
// window+observed gap, so a 35s silence that would otherwise start a
// deterministic rebuild loop (one rebuild per few reply periods, forever)
// keeps the session. Only a silence longer than anything the flow survived
// while healthy still rebuilds.
func TestUdpEndpointDroughtLearnsObservedReplyCadence(t *testing.T) {
	ue, _ := establishedWithDrought(t, 35*time.Second, 300)
	ue.maxReplyGapNano.Store(60 * time.Second.Nanoseconds())

	if _, err := ue.WriteTo([]byte("telemetry"), "1.2.3.4:9"); err != nil {
		t.Fatalf("a silence inside the learned cadence must not rebuild: %v", err)
	}
	if ue.dead.Load() {
		t.Fatal("a silence shorter than the flow's own observed reply gap is not drought")
	}

	ue2, _ := establishedWithDrought(t, udpEndpointReplyDroughtWindow+61*time.Second, 300)
	ue2.maxReplyGapNano.Store(60 * time.Second.Nanoseconds())
	if _, err := ue2.WriteTo([]byte("telemetry"), "1.2.3.4:9"); !stderrors.Is(err, daeerrors.ErrClosedConnection) {
		t.Fatalf("expected ErrClosedConnection once the silence exceeds window+observed gap, got %v", err)
	}
}

// markReplied must record the inter-reply interval it observes, monotonically.
func TestMarkRepliedRecordsReplyGap(t *testing.T) {
	ue, _ := establishedWithDrought(t, time.Second, 0)
	now := time.Now().UnixNano()
	ue.lastReplyNano.Store(now - 42*time.Second.Nanoseconds())
	ue.markReplied(now, netip.AddrPort{})
	if got := ue.maxReplyGapNano.Load(); got < 42*time.Second.Nanoseconds() {
		t.Fatalf("maxReplyGapNano = %d, want >= 42s", got)
	}

	// A shorter later gap must not lower the learned cadence.
	ue.lastReplyNano.Store(now - 5*time.Second.Nanoseconds())
	ue.markReplied(now, netip.AddrPort{})
	if got := ue.maxReplyGapNano.Load(); got < 42*time.Second.Nanoseconds() {
		t.Fatalf("maxReplyGapNano = %d, must not decrease", got)
	}
}

// TestObserveSendRateTransitionPreservesCounts pins the observable
// invariants of observeSendRate's bucket transition under concurrent entry:
// the retired bucket's count must not survive into the new bucket, the total
// must not exceed what was actually counted, and the run must stay race-free
// under -race. The erasure interleaving of the pre-CAS Store(0) sequence (a
// writer preempted between the stale-bucket check and its reset wiping a
// completed transition's counts) is structurally excluded by the CAS-gated
// protocol rather than caught statistically here: no reset can execute after
// the new bucket is published, because resets only run before a successful
// CAS. This test would fail catastrophic regressions (stale survivors,
// over-attribution, data races), not single-count losses.
func TestObserveSendRateTransitionPreservesCounts(t *testing.T) {
	ue := &UdpEndpoint{}
	old := time.Now().Add(-2 * udpEndpointReplyDroughtProbeWindow)
	ue.recentWriteBucket.Store(old.UnixNano() / int64(udpEndpointReplyDroughtProbeWindow))
	ue.recentWriteBucketWrites.Store(12345)

	// Repeated transitions with a wide concurrent entry: all goroutines hit
	// the stale bucket at once, which is exactly the interleaving the old
	// Store(0)-then-publish sequence erased counts in. Rounds use distinct
	// buckets so every round exercises the transition path.
	const rounds, goroutines, perG = 20, 64, 10
	var total int64
	for r := 0; r < rounds; r++ {
		now := time.Now().Add(time.Duration(r+2) * udpEndpointReplyDroughtProbeWindow)
		ue.recentWriteBucket.Store(now.Add(-udpEndpointReplyDroughtProbeWindow).UnixNano() / int64(udpEndpointReplyDroughtProbeWindow))
		ue.recentWriteBucketWrites.Store(0)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for g := 0; g < goroutines; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for i := 0; i < perG; i++ {
					ue.observeSendRate(now, 1)
				}
			}()
		}
		close(start)
		wg.Wait()
		total += ue.recentWriteBucketWrites.Load()
	}
	want := int64(rounds * goroutines * perG)
	// The stale count must not survive, and only the handful of writes
	// racing each publication may be dropped: the fixed protocol loses a
	// bounded trickle, the pre-fix code lost whole groups to erasing
	// Store(0)s.
	if total < want*19/20 || total > want {
		t.Fatalf("send-rate count after %d concurrent transitions = %d, want ~%d", rounds, total, want)
	}
}
