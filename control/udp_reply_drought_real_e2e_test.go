/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// Real-transport end-to-end coverage for the reply-drought session rebuild.
//
// Unlike the unit and pool-level tests, these drive the real UDP path end to
// end: a real ControlPlane handlePkt call -> the real UdpEndpointPool -> the
// real outbound socks5 dialer from the pinned fork -> an RFC 1928 SOCKS5 server
// (socks5_e2e_server_test.go) -> a real UDP target that can REAP the forwarding
// mapping it learned. Reaping is what a game server, a conntrack entry or a NAT
// binding does: datagrams from the reaped source port are dropped from then on,
// so the established proxy session becomes a silent blackhole and only a fresh
// session with a fresh egress port can recover the flow.

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/socks" // registers the socks5 link scheme
	"github.com/sirupsen/logrus"
)

// ---- a UDP echo target that can forget the mappings it learned ----

type targetObservation struct {
	payload string
	from    netip.AddrPort
}

type reapEchoTarget struct {
	conn *net.UDPConn

	mu     sync.Mutex
	echo   bool
	reaped map[string]bool
	recv   []targetObservation
}

func startReapEchoTarget(t *testing.T) *reapEchoTarget {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	tg := &reapEchoTarget{conn: conn, echo: true, reaped: make(map[string]bool)}
	go tg.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return tg
}

func (tg *reapEchoTarget) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := tg.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		tg.mu.Lock()
		if tg.reaped[from.String()] {
			tg.mu.Unlock()
			continue
		}
		tg.recv = append(tg.recv, targetObservation{payload: string(buf[:n]), from: from.AddrPort()})
		echo := tg.echo
		tg.mu.Unlock()
		if echo {
			_, _ = tg.conn.WriteToUDP(buf[:n], from)
		}
	}
}

func (tg *reapEchoTarget) addrPort(t *testing.T) netip.AddrPort {
	t.Helper()
	addr, err := netip.ParseAddrPort(tg.conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("target address: %v", err)
	}
	return addr
}

// setEcho controls whether datagrams are answered; they are always recorded.
func (tg *reapEchoTarget) setEcho(v bool) {
	tg.mu.Lock()
	tg.echo = v
	tg.mu.Unlock()
}

// reap forgets every source mapping seen so far and returns their ports.
func (tg *reapEchoTarget) reap() []string {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	ports := make([]string, 0, len(tg.recv))
	for _, o := range tg.recv {
		key := o.from.String()
		if tg.reaped[key] {
			continue
		}
		ports = append(ports, strconv.Itoa(int(o.from.Port())))
		tg.reaped[key] = true
	}
	return ports
}

func (tg *reapEchoTarget) count(payload string) int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	n := 0
	for _, o := range tg.recv {
		if o.payload == payload {
			n++
		}
	}
	return n
}

func (tg *reapEchoTarget) waitFor(t *testing.T, payload string, d time.Duration) targetObservation {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		tg.mu.Lock()
		for _, o := range tg.recv {
			if o.payload == payload {
				tg.mu.Unlock()
				return o
			}
		}
		tg.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("the target never received %q within %s", payload, d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---- the real dialer, built the way production builds a socks5 outbound ----

func newRealSocks5EndpointDialer(t *testing.T, proxyAddr string) *componentdialer.Dialer {
	t.Helper()
	base, _ := D.NewDirectDialer(&D.ExtraOption{}, true)
	underlay, _, err := D.NewNetproxyDialerFromLink(base, &D.ExtraOption{}, "socks5://"+proxyAddr)
	if err != nil {
		t.Fatalf("socks5 link dialer: %v", err)
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return componentdialer.NewDialerContext(context.Background(), underlay,
		&componentdialer.GlobalOption{Log: logger, CheckInterval: time.Second},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{Property: D.Property{
			Name:     "socks5",
			Address:  proxyAddr,
			Protocol: "socks5",
		}},
	)
}

// ---- the end-to-end harness ----

// The two flow destinations are loopback addresses inside 127.0.0.0/8 that
// nothing binds: dae hands a reply to the local application by binding a
// socket to the address the client originally sent to, and the in-test target
// cannot also hold that address in this same network namespace. They are still
// local addresses, so the spoofed reply survives the loopback receive path.
// The in-test SOCKS5 server forwards them to the real loopback targets, so the
// whole client -> dae -> proxy -> target -> dae -> client loop stays real.
var (
	flowDstA = netip.MustParseAddrPort("127.0.0.2:53123")
	flowDstB = netip.MustParseAddrPort("127.0.0.3:53124")
)

type udpWireReply struct {
	payload string
	from    netip.AddrPort
}

type realUdpE2E struct {
	t  *testing.T
	cp *ControlPlane
	// client is a real UDP socket standing in for the local application: dae
	// must hand the upstream replies back to it, spoofing the address the
	// application sent to.
	client  *net.UDPConn
	replies chan udpWireReply
	src     netip.AddrPort
	dst     netip.AddrPort
	flow    UdpFlowDecision
	key     UdpEndpointKey
}

func newRealUdpE2E(t *testing.T, d *componentdialer.Dialer, dst netip.AddrPort) *realUdpE2E {
	t.Helper()
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	t.Cleanup(func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	})
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	replies := make(chan udpWireReply, 64)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := client.ReadFromUDP(buf)
			if err != nil {
				close(replies)
				return
			}
			select {
			case replies <- udpWireReply{payload: string(buf[:n]), from: from.AddrPort()}:
			default:
			}
		}
	}()
	src := client.LocalAddr().(*net.UDPAddr).AddrPort()
	probe := []byte("probe-0")
	flow := ClassifyUdpFlow(src, dst, probe)
	cp := newRealUdpE2EControlPlane(t, d)
	installTestDaeNetns(t)
	return &realUdpE2E{
		t:       t,
		cp:      cp,
		client:  client,
		replies: replies,
		src:     src,
		dst:     dst,
		flow:    flow,
		key:     flow.FullConeNatEndpointKey(),
	}
}

// newRealUdpE2EControlPlane builds the same minimal control plane as the
// reuse-simulation tests, but honours DAE_E2E_DEBUG for diagnosis.
func newRealUdpE2EControlPlane(t *testing.T, d *componentdialer.Dialer) *ControlPlane {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	if os.Getenv("DAE_E2E_DEBUG") != "" {
		logger.SetOutput(os.Stderr)
		logger.SetLevel(logrus.TraceLevel)
		logrus.SetOutput(os.Stderr)
		logrus.SetLevel(logrus.TraceLevel)
	}
	outbounds := make([]*ob.DialerGroup, int(consts.OutboundUserDefinedMin)+1)
	outbounds[consts.OutboundUserDefinedMin] = newTestFixedOutboundGroup(d)
	return &ControlPlane{
		log: logger,
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: outbounds,
		},
		soMarkFromDae: 0,
	}
}

// installTestDaeNetns points the package-level dae netns at the current one so
// the reply path can create its client-facing socket in this environment.
func installTestDaeNetns(t *testing.T) {
	t.Helper()
	ns := newDaeNetnsWithCurrentHandles(t)
	// The spoofed-reply path creates its client-facing socket through a real
	// setns into the dae netns. Unprivileged runners (CI executes tests as a
	// non-root user) get EPERM from setns even for the current namespace, and
	// every e2e below would then fail with a five-second reply timeout instead
	// of exercising the rebuild logic. Probe the exact prerequisite once and
	// skip rather than fail when it is unavailable.
	if err := ns.With(func() error { return nil }); err != nil {
		t.Skipf("the real spoofed-reply datapath needs setns (CAP_SYS_ADMIN), which this environment denies: %v", err)
	}
	old := daeNetns
	daeNetns = ns
	t.Cleanup(func() { daeNetns = old })
}

// waitForClientReply asserts the upstream reply was handed back to the local
// application socket, which is the last hop of the real datapath.
func (e *realUdpE2E) waitForClientReply(payload string, wantFrom netip.AddrPort, d time.Duration) {
	e.t.Helper()
	deadline := time.After(d)
	for {
		select {
		case got, ok := <-e.replies:
			if !ok {
				e.t.Fatal("the client socket was closed")
			}
			if got.payload != payload {
				continue
			}
			if got.from != wantFrom {
				e.t.Fatalf("the client received %q from %s, want the address it sent to (%s)", payload, got.from, wantFrom)
			}
			return
		case <-deadline:
			e.t.Fatalf("the client never received the reply %q from %s within %s", payload, wantFrom, d)
		}
	}
}

func (e *realUdpE2E) sendTo(dst netip.AddrPort, flow UdpFlowDecision, payload string) error {
	routing := &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin)}
	return e.cp.handlePktWithPrefetch([]byte(payload), e.src, dst, routing, flow, nil, UdpEndpointKey{}, false)
}

func (e *realUdpE2E) send(payload string) error {
	return e.sendTo(e.dst, e.flow, payload)
}

func (e *realUdpE2E) mustSend(payload string) {
	e.t.Helper()
	if err := e.send(payload); err != nil {
		e.t.Fatalf("handlePkt(%q): %v", payload, err)
	}
}

func (e *realUdpE2E) mustSendTo(dst netip.AddrPort, flow UdpFlowDecision, payload string) {
	e.t.Helper()
	if err := e.sendTo(dst, flow, payload); err != nil {
		e.t.Fatalf("handlePkt to %s (%q): %v", dst, payload, err)
	}
}

func (e *realUdpE2E) endpoint() *UdpEndpoint {
	ue, _ := DefaultUdpEndpointPool.Get(e.key)
	return ue
}

// waitForReply polls until a real upstream reply has marked the endpoint.
func (e *realUdpE2E) waitForReply(d time.Duration) *UdpEndpoint {
	e.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ue := e.endpoint(); ue != nil && ue.hasReply.Load() {
			return ue
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatal("the real upstream reply never marked the endpoint")
	return nil
}

// establish runs one real round trip through the proxy and returns the marked
// endpoint plus the egress port the far end observed.
func (e *realUdpE2E) establish(target *reapEchoTarget) (*UdpEndpoint, string) {
	e.t.Helper()
	e.mustSend("probe-0")
	obs := target.waitFor(e.t, "probe-0", 5*time.Second)
	e.waitForClientReply("probe-0", e.dst, 5*time.Second)
	return e.waitForReply(5 * time.Second), strconv.Itoa(int(obs.from.Port()))
}

func TestE2ERealSocks5ReplyDroughtRebuildsAndRecovers(t *testing.T) {
	target := startReapEchoTarget(t)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{},
		map[netip.AddrPort]netip.AddrPort{flowDstA: target.addrPort(t)})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)

	ue1, port1 := e.establish(target)

	// The far end reaps the forwarding mapping: from now on its datagrams are
	// dropped, so the established session is a silent blackhole.
	if reaped := target.reap(); !slices.Contains(reaped, port1) {
		t.Fatalf("reaped ports = %v, want %s", reaped, port1)
	}

	// The client keeps transmitting into the blackhole. Every datagram is a
	// real write through the real socks5 association and is counted by the
	// endpoint; only the wall clock is compressed, because the 30s window itself
	// is covered uncompressed by TestE2ERealSocks5UncompressedDroughtWindow.
	const sent = 70 // >= udpEndpointReplyDroughtMinRate * window
	for i := 0; i < sent; i++ {
		e.mustSend("dead-" + strconv.Itoa(i))
	}
	if got := ue1.writesSinceReply.Load(); got < sent {
		t.Fatalf("writesSinceReply = %d, want >= %d real datagrams counted", got, sent)
	}
	if got := target.count("dead-0"); got != 0 {
		t.Fatalf("the reaped far end accepted %d datagrams, want 0", got)
	}
	if e.endpoint() != ue1 {
		t.Fatal("the endpoint was replaced before the drought window elapsed")
	}

	// Compress the clock: the last real reply is now older than the window.
	ue1.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())

	// Silencing the far end makes "the replacement session starts probing"
	// observable rather than racy: no reply can mark the new endpoint yet.
	target.setEcho(false)

	// The next write must retire the reaped session and be retried on a fresh
	// one, all inside this single call.
	e.mustSend("rebuild")

	ue2 := e.endpoint()
	if ue2 == nil {
		t.Fatal("expected a replacement endpoint after the drought rebuild")
	}
	if ue2 == ue1 {
		t.Fatal("the drought rebuild must replace the endpoint")
	}
	if !ue1.dead.Load() {
		t.Fatal("the reaped endpoint must be retired")
	}
	if ue2.hasReply.Load() {
		t.Fatal("the replacement session must start probing (the anti-churn gate)")
	}
	obs := target.waitFor(t, "rebuild", 5*time.Second)
	if port2 := strconv.Itoa(int(obs.from.Port())); port2 == port1 {
		t.Fatalf("the fresh session reused the reaped egress port %s", port1)
	}
	if got := ue2.writesSinceReply.Load(); got == 0 {
		t.Fatal("the replacement session must have counted the delivered datagram")
	}
	// No reply has arrived yet, so the fresh session cannot fire the gate
	// again, however much the client transmits into it.
	for i := 0; i < 10; i++ {
		e.mustSend("rebuild-probe-" + strconv.Itoa(i))
	}
	if e.endpoint() != ue2 || ue2.dead.Load() {
		t.Fatal("a probing replacement session must not rebuild again (anti-churn)")
	}

	// Recovering the far end must restore the full loop on the fresh session:
	// the client sees the upstream reply again, and the reply marks the new
	// endpoint instead of triggering another rebuild.
	target.setEcho(true)
	e.mustSend("rebuild-recover")
	target.waitFor(t, "rebuild-recover", 5*time.Second)
	e.waitForClientReply("rebuild-recover", flowDstA, 5*time.Second)
	if marked := e.waitForReply(5 * time.Second); marked != ue2 {
		t.Fatal("the recovery reply must mark the replacement session")
	}
}

func TestE2ERealSocks5ProbingEndpointNeverRebuilds(t *testing.T) {
	target := startReapEchoTarget(t)
	// A far end that records but never answers: the endpoint stays probing.
	target.setEcho(false)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{},
		map[netip.AddrPort]netip.AddrPort{flowDstA: target.addrPort(t)})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)

	const sent = 80
	for i := 0; i < sent; i++ {
		e.mustSend("probe-" + strconv.Itoa(i))
	}
	ue1 := e.endpoint()
	if ue1 == nil {
		t.Fatal("expected a pooled endpoint")
	}
	target.waitFor(t, "probe-0", 5*time.Second)
	if ue1.hasReply.Load() {
		t.Fatal("a silent far end must leave the endpoint probing")
	}
	if ue1.dead.Load() || e.endpoint() != ue1 {
		t.Fatal("a probing endpoint must never be rebuilt, however much the client transmits")
	}

	// Once the far end answers, the real reply must mark the endpoint and keep
	// it on the same session.
	target.setEcho(true)
	e.mustSend("probe-alive")
	target.waitFor(t, "probe-alive", 5*time.Second)
	e.waitForClientReply("probe-alive", flowDstA, 5*time.Second)
	if ue2 := e.waitForReply(5 * time.Second); ue2 != ue1 {
		t.Fatal("a real reply must mark the established endpoint, not replace it")
	}
}

func TestE2ERealSocks5LivePeerMasksReapedPeer(t *testing.T) {
	targetA := startReapEchoTarget(t)
	targetB := startReapEchoTarget(t)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{}, map[netip.AddrPort]netip.AddrPort{
		flowDstA: targetA.addrPort(t),
		flowDstB: targetB.addrPort(t),
	})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)

	// Both peers share one full-cone endpoint (keyed on the source alone).
	flowB := ClassifyUdpFlow(e.src, flowDstB, []byte("peer-b"))
	if flowB.FullConeNatEndpointKey() != e.key {
		t.Fatal("this test needs both peers to share one full-cone endpoint")
	}
	sendToB := func(payload string) {
		t.Helper()
		e.mustSendTo(flowDstB, flowB, payload)
	}

	ue1, portA := e.establish(targetA)
	sendToB("peer-b-0")
	targetB.waitFor(t, "peer-b-0", 5*time.Second)
	e.waitForClientReply("peer-b-0", flowDstB, 5*time.Second)

	// Peer A is reaped; peer B stays alive and keeps answering.
	if reaped := targetA.reap(); !slices.Contains(reaped, portA) {
		t.Fatalf("reaped ports = %v, want %s", reaped, portA)
	}
	for i := 0; i < 20; i++ {
		e.mustSend("a-dead-" + strconv.Itoa(i))
		sendToB("peer-b-" + strconv.Itoa(i+1))
		targetB.waitFor(t, "peer-b-"+strconv.Itoa(i+1), 5*time.Second)
	}

	if got := targetA.count("a-dead-0"); got != 0 {
		t.Fatalf("the reaped peer accepted %d datagrams, want 0", got)
	}
	if e.endpoint() != ue1 || ue1.dead.Load() {
		t.Fatal("a live peer's replies must keep the shared full-cone endpoint alive")
	}
	// The live peer's replies are what keep the endpoint fresh: the drought
	// never accumulates even though one peer is dead. This is the documented
	// granularity consequence of a source-keyed (full-cone) endpoint.
	if age := time.Since(time.Unix(0, ue1.lastReplyNano.Load())); age > 3*time.Second {
		t.Fatalf("last reply is %s old; the live peer's replies should have refreshed it", age)
	}
	// Nothing has moved yet either: the reaped peer is promoted only after its
	// own per-peer drought window, which this test never reaches. The endpoint
	// itself can only ever see the live peer's fresh replies.
	if n := DefaultUdpEndpointPool.Len(); n != 1 {
		t.Fatalf("pool holds %d endpoints, want the one shared session", n)
	}
}

func TestE2ERealSocks5SilenceIsNotARebuildSignal(t *testing.T) {
	target := startReapEchoTarget(t)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{},
		map[netip.AddrPort]netip.AddrPort{flowDstA: target.addrPort(t)})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)

	ue1, port1 := e.establish(target)
	if reaped := target.reap(); !slices.Contains(reaped, port1) {
		t.Fatalf("reaped ports = %v, want %s", reaped, port1)
	}

	// A long pause with (almost) no client traffic: the far end may well have
	// reaped the mapping, but silence carries no information, so dae must not
	// rebuild. Only the wall clock is compressed.
	ue1.lastReplyNano.Store(time.Now().Add(-10 * udpEndpointReplyDroughtWindow).UnixNano())
	before := ue1.writesSinceReply.Load()
	e.mustSend("after-pause")

	if e.endpoint() != ue1 || ue1.dead.Load() {
		t.Fatal("a long pause must not rebuild the session")
	}
	if got := ue1.writesSinceReply.Load(); got != before+1 {
		t.Fatalf("writesSinceReply = %d, want %d (one sparse datagram)", got, before+1)
	}
}

// TestE2ERealSocks5RealSilenceDoesNotRebuild encodes why the silence
// heuristic was removed: a healthy session is legitimately silent between
// rounds, and rebuilding it re-keys every QUIC/game flow (RFC 9000 9.2/9.3).
// The pause here is real wall-clock time, longer than the 5s window the old
// heuristic used, so this test fails if silence-triggered rebuilding returns.
// TestE2ERealSocks5BurstyFlowStillRecovers covers a traffic shape the
// lifetime-average rate gate cannot see: a flow whose average is below the
// threshold while its instantaneous activity is not. A game that syncs state
// every tens of seconds, or any flow that resumes after a long pause, pushes
// dense bursts into a session that stopped answering; measuring only the
// average over the whole drought would leave it dead forever.
func TestE2ERealSocks5BurstyFlowStillRecovers(t *testing.T) {
	target := startReapEchoTarget(t)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{},
		map[netip.AddrPort]netip.AddrPort{flowDstA: target.addrPort(t)})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)

	ue1, port1 := e.establish(target)
	if reaped := target.reap(); !slices.Contains(reaped, port1) {
		t.Fatalf("reaped ports = %v, want %s", reaped, port1)
	}

	// A burst: real datagrams, really written through the real association.
	const burst = 20
	for i := 0; i < burst; i++ {
		e.mustSend("burst-" + strconv.Itoa(i))
	}
	if got := target.count("burst-0"); got != 0 {
		t.Fatalf("the reaped far end accepted %d datagrams, want 0", got)
	}

	// Compress the clock so the drought is old while the burst is recent: this
	// is exactly "a low-average flow that is actively transmitting now".
	ue1.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())
	writes := ue1.writesSinceReply.Load()
	drought := time.Duration(time.Now().UnixNano() - ue1.lastReplyNano.Load())
	if avg := float64(writes) / drought.Seconds(); avg >= float64(udpEndpointReplyDroughtMinRate) {
		t.Fatalf("test premise broken: lifetime average %0.2f pkt/s is not below the %d pkt/s threshold", avg, udpEndpointReplyDroughtMinRate)
	}

	e.mustSend("burst-recover")

	ue2 := e.endpoint()
	if ue2 == ue1 {
		t.Fatal("a burst into a session that stopped answering must still recover the flow")
	}
	if !ue1.dead.Load() {
		t.Fatal("the reaped endpoint must be retired")
	}
	obs := target.waitFor(t, "burst-recover", 5*time.Second)
	e.waitForClientReply("burst-recover", flowDstA, 5*time.Second)
	if port2 := strconv.Itoa(int(obs.from.Port())); port2 == port1 {
		t.Fatalf("the fresh session reused the reaped egress port %s", port1)
	}
}

// agePeerDrought moves one peer's reply clock back by age, which is exactly the
// evidence the promotion gate would read after that much real time. Tests use
// it to cover the wiring without spending a real drought window; the real-clock
// companion test below proves the window itself.
func agePeerDrought(t *testing.T, ue *UdpEndpoint, peer netip.AddrPort, age time.Duration) {
	t.Helper()
	ue.peerMu.Lock()
	defer ue.peerMu.Unlock()
	state, ok := ue.peers[peer.String()]
	if !ok {
		t.Fatalf("peer %s has no per-peer liveness state", peer)
	}
	state.lastReplyNano -= int64(age)
}

// TestE2ERealSocks5PeerPromotionWiring drives the promotion through the real
// packet path on a real transport, with the per-peer clock compressed instead
// of waiting for the drought window. This is the fast guard for the wiring in
// handlePktOwned: if the promotion stops being consulted there, the reaped peer
// never gets its own session and this test fails in milliseconds.
func TestE2ERealSocks5PeerPromotionWiring(t *testing.T) {
	targetA := startReapEchoTarget(t)
	targetB := startReapEchoTarget(t)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{}, map[netip.AddrPort]netip.AddrPort{
		flowDstA: targetA.addrPort(t),
		flowDstB: targetB.addrPort(t),
	})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)

	flowB := ClassifyUdpFlow(e.src, flowDstB, []byte("peer-b"))
	if flowB.FullConeNatEndpointKey() != e.key {
		t.Fatal("this test needs both peers to share one full-cone endpoint")
	}

	// Both peers answer once on the shared session, which is what makes their
	// liveness observable per peer.
	ue1, portA := e.establish(targetA)
	e.mustSendTo(flowDstB, flowB, "peer-b-0")
	targetB.waitFor(t, "peer-b-0", 5*time.Second)
	e.waitForClientReply("peer-b-0", flowDstB, 5*time.Second)
	if n := DefaultUdpEndpointPool.Len(); n != 1 {
		t.Fatalf("pool holds %d endpoints, want the one shared session", n)
	}

	// The far end reaps peer B's mapping while the client keeps transmitting to
	// it. Those datagrams are dropped, so the burst is not evidence of anything
	// the shared session can see.
	if reaped := targetB.reap(); !slices.Contains(reaped, portA) {
		t.Fatalf("reaped ports = %v, want %s", reaped, portA)
	}
	for i := range 2 * udpEndpointReplyDroughtMinRate * int(udpEndpointReplyDroughtProbeWindow.Seconds()) {
		e.mustSendTo(flowDstB, flowB, "b-dead-"+strconv.Itoa(i))
	}
	if got := targetB.count("b-dead-0"); got != 0 {
		t.Fatalf("the reaped peer accepted %d datagrams, want 0", got)
	}

	// One full drought later the peer is promoted, and the next datagram for it
	// leaves through the dedicated session's own forwarding source port.
	agePeerDrought(t, ue1, flowDstB, udpEndpointReplyDroughtWindow+time.Second)
	e.mustSendTo(flowDstB, flowB, "b-recovered")
	obsB := targetB.waitFor(t, "b-recovered", 5*time.Second)
	e.waitForClientReply("b-recovered", flowDstB, 5*time.Second)
	if portB := strconv.Itoa(int(obsB.from.Port())); portB == portA {
		t.Fatalf("the reaped peer recovered on the reaped forwarding port %s", portA)
	}
	if _, ok := DefaultUdpEndpointPool.Get(flowB.SymmetricNatEndpointKey()); !ok {
		t.Fatal("the promoted peer must have its own symmetric session")
	}

	// The shared session is untouched and still serves the live peer on its own
	// forwarding port.
	if e.endpoint() != ue1 || ue1.dead.Load() {
		t.Fatal("the shared session must stay alive and unchanged for the healthy peer")
	}
	e.mustSend("a-after")
	obsA := targetA.waitFor(t, "a-after", 5*time.Second)
	e.waitForClientReply("a-after", flowDstA, 5*time.Second)
	if port := strconv.Itoa(int(obsA.from.Port())); port != portA {
		t.Fatalf("the healthy peer moved from port %s to %s: the shared session was disturbed", portA, port)
	}
}

// TestE2ERealSocks5ReapedPeerPromotesWithoutDisturbingLivePeer covers the
// granularity gap of a source-keyed (full-cone) session: one session serves
// several peers, and their fates are independent. The healthy peer's replies
// keep the endpoint-level reply clock fresh, so the shared session is never in
// a drought and a reaped peer would stay dead forever. Recovery must therefore
// move only the reaped peer to its own session, and the healthy peer must keep
// its session and its forwarding source port untouched.
//
// This runs on the real clock: the per-peer drought window is the configured
// 30s, not a compressed timestamp.
func TestE2ERealSocks5ReapedPeerPromotesWithoutDisturbingLivePeer(t *testing.T) {
	if testing.Short() {
		t.Skip("real 30s reply drought for the reaped peer")
	}
	targetA := startReapEchoTarget(t)
	targetB := startReapEchoTarget(t)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{}, map[netip.AddrPort]netip.AddrPort{
		flowDstA: targetA.addrPort(t),
		flowDstB: targetB.addrPort(t),
	})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)

	flowB := ClassifyUdpFlow(e.src, flowDstB, []byte("peer-b"))
	if flowB.FullConeNatEndpointKey() != e.key {
		t.Fatal("this test needs both peers to share one full-cone endpoint")
	}

	// Both peers are established on that one shared session: their replies are
	// what makes per-peer liveness observable at all.
	ue1, portA := e.establish(targetA)
	e.mustSendTo(flowDstB, flowB, "peer-b-0")
	obsB0 := targetB.waitFor(t, "peer-b-0", 5*time.Second)
	e.waitForClientReply("peer-b-0", flowDstB, 5*time.Second)
	if portB0 := strconv.Itoa(int(obsB0.from.Port())); portB0 != portA {
		t.Fatalf("peer B sent from port %s, want the shared session port %s", portB0, portA)
	}
	if n := DefaultUdpEndpointPool.Len(); n != 1 {
		t.Fatalf("pool holds %d endpoints, want the one shared session", n)
	}

	// Peer B's forwarding mapping is reaped; peer A keeps answering.
	if reaped := targetB.reap(); !slices.Contains(reaped, portA) {
		t.Fatalf("reaped ports = %v, want %s", reaped, portA)
	}

	// Keep both peers busy for a full drought window. A's replies keep the
	// shared session healthy, which is exactly the masking this test is about.
	deadline := time.Now().Add(udpEndpointReplyDroughtWindow + 8*time.Second)
	lastA := ""
	for i := 0; time.Now().Before(deadline); i++ {
		e.mustSendTo(flowDstB, flowB, "b-dead-"+strconv.Itoa(i))
		lastA = "a-live-" + strconv.Itoa(i)
		e.mustSend(lastA)
		obs := targetA.waitFor(t, lastA, 5*time.Second)
		if port := strconv.Itoa(int(obs.from.Port())); port != portA {
			t.Fatalf("the healthy peer moved from port %s to %s: the shared session was disturbed", portA, port)
		}
		e.waitForClientReply(lastA, flowDstA, 5*time.Second)
		time.Sleep(100 * time.Millisecond)
	}
	if e.endpoint() != ue1 || ue1.dead.Load() {
		t.Fatal("the shared session must stay alive and unchanged for the healthy peer")
	}
	if got := targetB.count("b-dead-0"); got != 0 {
		t.Fatalf("the reaped peer accepted %d datagrams on the shared session, want 0", got)
	}

	// The reaped peer must have been moved to its own session, which means a new
	// forwarding source port that its reaped mapping does not filter out.
	e.mustSendTo(flowDstB, flowB, "b-recovered")
	obsB1 := targetB.waitFor(t, "b-recovered", 5*time.Second)
	e.waitForClientReply("b-recovered", flowDstB, 5*time.Second)
	if portB1 := strconv.Itoa(int(obsB1.from.Port())); portB1 == portA {
		t.Fatalf("the reaped peer recovered on the same forwarding port %s, which its reaped mapping drops", portA)
	}

	// And the healthy peer's traffic still uses the original session.
	e.mustSend("a-after")
	obsA := targetA.waitFor(t, "a-after", 5*time.Second)
	e.waitForClientReply("a-after", flowDstA, 5*time.Second)
	if port := strconv.Itoa(int(obsA.from.Port())); port != portA {
		t.Fatalf("the healthy peer moved to port %s, want the untouched %s", port, portA)
	}
	if e.endpoint() != ue1 {
		t.Fatal("the healthy peer must still be served by its original shared session")
	}
}

func TestE2ERealSocks5RealSilenceDoesNotRebuild(t *testing.T) {
	target := startReapEchoTarget(t)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{},
		map[netip.AddrPort]netip.AddrPort{flowDstA: target.addrPort(t)})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)

	ue1, port1 := e.establish(target)
	if reaped := target.reap(); !slices.Contains(reaped, port1) {
		t.Fatalf("reaped ports = %v, want %s", reaped, port1)
	}

	// A healthy pause: no write, no reply, for longer than the old window.
	time.Sleep(6 * time.Second)

	e.mustSend("after-silence")
	if e.endpoint() != ue1 || ue1.dead.Load() {
		t.Fatal("silence must not rebuild the session: a pause is indistinguishable from a healthy one")
	}
	// The real reply zeroed the counter, so exactly this sparse datagram is
	// counted: it was written on the same session instead of a fresh one.
	if got := ue1.writesSinceReply.Load(); got != 1 {
		t.Fatalf("writesSinceReply = %d, want exactly the sparse datagram counted since the last reply", got)
	}
	if got := target.count("after-silence"); got != 0 {
		t.Fatalf("the reaped far end accepted %d datagrams, want 0", got)
	}
}

func TestE2ERealSocks5DroughtRateBoundary(t *testing.T) {
	// The gate needs traffic, on either measurement: a flow that sends a couple
	// of datagrams and then goes quiet keeps its session (a real pause belongs to
	// the transport layer), while a flow actively transmitting into a session
	// that stopped replying gets a fresh one. The exact numeric boundary lives in
	// TestUdpEndpointDroughtRateBoundary; here both ends are proven on the real
	// transport, including the burst measurement that a lifetime average misses.
	run := func(t *testing.T, writes int, wantRebuild bool) {
		t.Helper()
		target := startReapEchoTarget(t)
		srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{},
			map[netip.AddrPort]netip.AddrPort{flowDstA: target.addrPort(t)})
		e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)
		ue1, port1 := e.establish(target)
		if reaped := target.reap(); !slices.Contains(reaped, port1) {
			t.Fatalf("reaped ports = %v, want %s", reaped, port1)
		}
		for i := 0; i < writes; i++ {
			e.mustSend("rate-" + strconv.Itoa(i))
		}
		if got := ue1.writesSinceReply.Load(); got < int64(writes) {
			t.Fatalf("writesSinceReply = %d, want >= %d", got, writes)
		}
		ue1.lastReplyNano.Store(time.Now().Add(-udpEndpointReplyDroughtWindow - time.Second).UnixNano())
		e.mustSend("boundary")
		if rebuilt := e.endpoint() != ue1; rebuilt != wantRebuild {
			t.Fatalf("rebuilt = %v, want %v (writes=%d)", rebuilt, wantRebuild, writes)
		}
	}
	t.Run("sparse_flow_keeps_the_session", func(t *testing.T) {
		run(t, 2, false)
	})
	t.Run("active_flow_rebuilds", func(t *testing.T) {
		run(t, 60, true)
	})
}

// TestE2ERealSocks5UncompressedDroughtWindow runs the whole thing on the real
// clock: no timestamp is touched, the client simply keeps transmitting at 20 Hz
// into a reaped far end until the 30s window elapses.
func TestE2ERealSocks5UncompressedDroughtWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("real 30s drought window")
	}
	target := startReapEchoTarget(t)
	srv := startSocks5ServerWithUDPRedirect(t, socks5ServerOptions{},
		map[netip.AddrPort]netip.AddrPort{flowDstA: target.addrPort(t)})
	e := newRealUdpE2E(t, newRealSocks5EndpointDialer(t, srv.addr()), flowDstA)

	ue1, port1 := e.establish(target)
	if reaped := target.reap(); !slices.Contains(reaped, port1) {
		t.Fatalf("reaped ports = %v, want %s", reaped, port1)
	}

	stop := make(chan struct{})
	var writeErrs atomic.Int64
	var writes atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(50 * time.Millisecond) // 20 Hz
		defer ticker.Stop()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := e.send("hb-" + strconv.Itoa(i)); err != nil {
				writeErrs.Add(1)
			}
			writes.Add(1)
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()

	start := time.Now()
	var rebuiltAt time.Duration
	var stopOnce sync.Once
	stopLoop := func() {
		stopOnce.Do(func() { close(stop) })
		wg.Wait()
	}
	for {
		if e.endpoint() != ue1 {
			rebuiltAt = time.Since(start)
			break
		}
		if time.Since(start) > 36*time.Second {
			stopLoop()
			t.Fatalf("no rebuild after %s of a real reply drought (%d writes, %d errors)",
				time.Since(start), writes.Load(), writeErrs.Load())
		}
		time.Sleep(25 * time.Millisecond)
	}
	// Stop the transmitting client before asserting on the replacement session:
	// concurrent handlePkt calls racing the rebuild can legitimately produce a
	// second endpoint, and this test is about the rebuild, not that race.
	stopLoop()
	elapsed := time.Since(start)
	if rebuiltAt < udpEndpointReplyDroughtWindow {
		t.Fatalf("the rebuild fired after %s, before the %s window", rebuiltAt, udpEndpointReplyDroughtWindow)
	}
	if rebuiltAt > udpEndpointReplyDroughtWindow+5*time.Second {
		t.Fatalf("the rebuild took %s, far beyond the %s window", rebuiltAt, udpEndpointReplyDroughtWindow)
	}
	ue2 := e.endpoint()
	if !ue1.dead.Load() {
		t.Fatal("the reaped endpoint must be retired")
	}
	// Recovery is real: the far end accepts the fresh session's egress port,
	// the client sees the reply again, and the reply marks the new session.
	e.mustSend("recovered")
	obs := target.waitFor(t, "recovered", 5*time.Second)
	e.waitForClientReply("recovered", flowDstA, 5*time.Second)
	if port2 := strconv.Itoa(int(obs.from.Port())); port2 == port1 {
		t.Fatalf("the recovery session reused the reaped egress port %s", port1)
	}
	if marked := e.waitForReply(5 * time.Second); marked != ue2 {
		t.Fatal("the recovery reply must mark the replacement session")
	}
	if errs := writeErrs.Load(); errs != 0 {
		t.Fatalf("%d writes failed during the drought loop (writes=%d, elapsed=%s)", errs, writes.Load(), elapsed)
	}
	if ue2 == ue1 {
		t.Fatal("expected a replacement endpoint")
	}
}
