/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

// stubSystemDNS is a SystemDNSProvider that answers with a fixed resolver or
// fails outright, standing in for a generation's direct DNS view.
type stubSystemDNS struct {
	addr netip.AddrPort
	err  error
}

func (s stubSystemDNS) SystemDNS() (netip.AddrPort, error) { return s.addr, s.err }

// scriptedDialer answers DNS queries from the addresses it is told about. A
// resolver in fail is unreachable, one in hang accepts the query but never
// replies until its connection is closed (which pins cancellation behaviour),
// and one in delay stalls before accepting, which pins which leg wins.
type scriptedDialer struct {
	answers map[string]netip.Addr
	fail    map[string]bool
	hang    map[string]bool
	delay   map[string]time.Duration

	mu        sync.Mutex
	opened    []string
	hungClose chan string
}

func newScriptedDialer() *scriptedDialer {
	return &scriptedDialer{
		answers:   make(map[string]netip.Addr),
		fail:      make(map[string]bool),
		hang:      make(map[string]bool),
		delay:     make(map[string]time.Duration),
		hungClose: make(chan string, 16),
	}
}

func (d *scriptedDialer) DialContext(ctx context.Context, _, addr string) (netproxy.Conn, error) {
	if wait := d.delay[addr]; wait > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	d.mu.Lock()
	d.opened = append(d.opened, addr)
	d.mu.Unlock()
	if d.fail[addr] {
		return nil, fmt.Errorf("dial %s: connection refused", addr)
	}
	return &scriptedConn{dialer: d, addr: addr, closed: make(chan struct{})}, nil
}

func (d *scriptedDialer) openedAddrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.opened...)
}

type scriptedConn struct {
	dialer *scriptedDialer
	addr   string
	closed chan struct{}
	once   sync.Once

	mu    sync.Mutex
	reply []byte
}

func (c *scriptedConn) WriteTo(p []byte, _ string) (int, error) {
	if c.dialer.hang[c.addr] {
		return len(p), nil
	}
	var query dnsmessage.Msg
	if err := query.Unpack(p); err != nil {
		return 0, err
	}
	reply := new(dnsmessage.Msg)
	reply.SetReply(&query)
	if ip, ok := c.dialer.answers[c.addr]; ok && len(query.Question) > 0 {
		question := query.Question[0]
		switch {
		case question.Qtype == dnsmessage.TypeA && ip.Is4():
			reply.Answer = append(reply.Answer, &dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: question.Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
				A:   ip.AsSlice(),
			})
		case question.Qtype == dnsmessage.TypeAAAA && ip.Is6():
			reply.Answer = append(reply.Answer, &dnsmessage.AAAA{
				Hdr:  dnsmessage.RR_Header{Name: question.Name, Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 60},
				AAAA: ip.AsSlice(),
			})
		}
	}
	wire, err := reply.Pack()
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.reply = wire
	c.mu.Unlock()
	return len(p), nil
}

func (c *scriptedConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	c.mu.Lock()
	reply := c.reply
	c.reply = nil
	c.mu.Unlock()
	if reply != nil {
		return copy(p, reply), netip.MustParseAddrPort(c.addr), nil
	}
	// A hung resolver stays unanswered until the lookup closes the connection,
	// which is what a canceled leg is expected to do.
	<-c.closed
	return 0, netip.AddrPort{}, io.EOF
}

func (c *scriptedConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		if c.dialer.hang[c.addr] {
			c.dialer.hungClose <- c.addr
		}
	})
	return nil
}

func (c *scriptedConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *scriptedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func testRouter(dialer netproxy.Dialer, systemDNS SystemDNSProvider, bootstrap ...netip.AddrPort) *Router {
	return &Router{
		log:          quietLogger(),
		directDialer: dialer,
		systemDNS:    systemDNS,
		bootstrapDns: bootstrap,
		lookupCalls:  make(map[string]*lookupCall),
	}
}

func singleAddr(t *testing.T, addrs []net.IPAddr) netip.Addr {
	t.Helper()
	if len(addrs) != 1 {
		t.Fatalf("got %d addresses, want exactly 1: %v", len(addrs), addrs)
	}
	got, ok := netip.AddrFromSlice(addrs[0].IP)
	if !ok {
		t.Fatalf("unusable address %v", addrs[0].IP)
	}
	return got
}

func mustAddrs(t *testing.T, addrs []net.IPAddr, want netip.Addr) {
	t.Helper()
	if got := singleAddr(t, addrs); got != want {
		t.Fatalf("got address %v, want %v", got, want)
	}
}

// TestLookupNodeIPAddrResolvesThroughSystemView pins the fix: a node address
// that no node/sub rule routes must resolve without the bootstrap resolvers,
// which are only raced as a fallback leg.
func TestLookupNodeIPAddrResolvesThroughSystemView(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	want := netip.MustParseAddr("203.0.113.7")

	dialer := newScriptedDialer()
	dialer.answers[systemAddr.String()] = want
	dialer.fail[bootstrapAddr.String()] = true

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
	addrs, err := router.lookupNodeIPAddr(context.Background(), "tcp4", "node.test")
	if err != nil {
		t.Fatalf("lookupNodeIPAddr: %v", err)
	}
	mustAddrs(t, addrs, want)
}

// TestLookupNodeIPAddrFallsBackToBootstrap pins the no-regression direction: a
// host whose system DNS view is unusable still reaches the bootstrap resolvers.
func TestLookupNodeIPAddrFallsBackToBootstrap(t *testing.T) {
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	want := netip.MustParseAddr("203.0.113.9")

	dialer := newScriptedDialer()
	dialer.answers[bootstrapAddr.String()] = want

	router := testRouter(dialer, stubSystemDNS{err: errors.New("resolv.conf unusable")}, bootstrapAddr)
	addrs, err := router.lookupNodeIPAddr(context.Background(), "tcp4", "node.test")
	if err != nil {
		t.Fatalf("lookupNodeIPAddr: %v", err)
	}
	mustAddrs(t, addrs, want)
}

// TestLookupNodeIPAddrWithoutSystemViewStaysBootstrapOnly pins that a
// generation without a direct DNS view (the subscription-resolution router) is
// not given a synthetic failing leg: it resolves exactly as it did before, and
// its errors carry only the bootstrap diagnosis.
func TestLookupNodeIPAddrWithoutSystemViewStaysBootstrapOnly(t *testing.T) {
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	want := netip.MustParseAddr("203.0.113.10")

	dialer := newScriptedDialer()
	dialer.answers[bootstrapAddr.String()] = want

	router := testRouter(dialer, nil, bootstrapAddr)
	addrs, err := router.lookupNodeIPAddr(context.Background(), "tcp4", "node.test")
	if err != nil {
		t.Fatalf("lookupNodeIPAddr: %v", err)
	}
	mustAddrs(t, addrs, want)

	// The legacy failure text must stay exactly what it was.
	delete(dialer.answers, bootstrapAddr.String())
	_, err = router.lookupNodeIPAddr(context.Background(), "tcp4", "node.test")
	if err == nil {
		t.Fatal("expected an error when the only leg produces no address")
	}
	if err.Error() != `bootstrap resolver returned no usable address for "node.test"` {
		t.Fatalf("got %q, want the unchanged bootstrap diagnosis", err.Error())
	}
}

// TestLookupNodeIPAddrKeepsBootstrapDiagnosis pins the field-facing error text:
// the bootstrap leg must still report that it returned no usable address, and
// the system leg's own diagnosis must sit in front of it in a stable order.
func TestLookupNodeIPAddrKeepsBootstrapDiagnosis(t *testing.T) {
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")

	dialer := newScriptedDialer() // every leg answers, but no records exist

	router := testRouter(dialer, stubSystemDNS{addr: netip.MustParseAddrPort("192.0.2.53:53")}, bootstrapAddr)
	_, err := router.lookupNodeIPAddr(context.Background(), "tcp4", "node.test")
	if err == nil {
		t.Fatal("expected an error when neither leg produces an address")
	}
	systemText := "system resolver 192.0.2.53:53 returned no usable address"
	bootstrapText := `bootstrap resolver returned no usable address for "node.test"`
	if !strings.Contains(err.Error(), systemText) || !strings.Contains(err.Error(), bootstrapText) {
		t.Fatalf("both diagnoses must survive, got %q", err.Error())
	}
	if strings.Index(err.Error(), systemText) > strings.Index(err.Error(), bootstrapText) {
		t.Fatalf("leg order must be stable (system before bootstrap), got %q", err.Error())
	}
}

// TestLookupNodeIPAddrReportsUnusableSystemView pins that a system DNS view
// that exists but cannot supply a server is a leg failure, not a panic or a
// silent skip.
func TestLookupNodeIPAddrReportsUnusableSystemView(t *testing.T) {
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	dialer := newScriptedDialer()
	dialer.fail[bootstrapAddr.String()] = true

	router := testRouter(dialer, stubSystemDNS{}, bootstrapAddr)
	_, err := router.lookupNodeIPAddr(context.Background(), "tcp4", "node.test")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "system DNS resolver is not configured") {
		t.Fatalf("missing system-view diagnosis in %q", err.Error())
	}
	// The joined error must still unwrap to the system leg's sentinel.
	if !errors.Is(err, errNoSystemDNS) {
		t.Fatalf("got %v, want the system leg's errNoSystemDNS sentinel", err)
	}
}

// TestLookupNodeIPAddrFirstAnswerWins pins the race policy in both orders: the
// leg that answers first decides the address, and the loser's answer is not
// merged into the result.
func TestLookupNodeIPAddrFirstAnswerWins(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	systemIP := netip.MustParseAddr("203.0.113.20")
	bootstrapIP := netip.MustParseAddr("203.0.113.21")

	for _, tc := range []struct {
		name string
		slow string
		want netip.Addr
	}{
		{name: "system answers first", slow: bootstrapAddr.String(), want: systemIP},
		{name: "bootstrap answers first", slow: systemAddr.String(), want: bootstrapIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialer := newScriptedDialer()
			dialer.answers[systemAddr.String()] = systemIP
			dialer.answers[bootstrapAddr.String()] = bootstrapIP
			dialer.delay[tc.slow] = 300 * time.Millisecond

			router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
			addrs, err := router.lookupNodeIPAddr(context.Background(), "tcp4", "node.test")
			if err != nil {
				t.Fatalf("lookupNodeIPAddr: %v", err)
			}
			mustAddrs(t, addrs, tc.want)
		})
	}
}

// TestLookupNodeIPAddrConcurrentCallers drives the race path from several
// goroutines so the detector can observe the new concurrency.
func TestLookupNodeIPAddrConcurrentCallers(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	want := netip.MustParseAddr("203.0.113.22")

	dialer := newScriptedDialer()
	dialer.answers[systemAddr.String()] = want
	dialer.fail[bootstrapAddr.String()] = true

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, err := router.lookupNodeIPAddr(context.Background(), "tcp4", "node.test")
			if err != nil {
				t.Errorf("lookupNodeIPAddr: %v", err)
				return
			}
			if len(addrs) != 1 {
				t.Errorf("got %d addresses, want 1", len(addrs))
			}
		}()
	}
	wg.Wait()
}

// TestLookupNodeIPAddrReturnsIPLiteralWithoutDialing pins the fast path: an
// address literal never reaches a resolver.
func TestLookupNodeIPAddrReturnsIPLiteralWithoutDialing(t *testing.T) {
	dialer := newScriptedDialer()
	router := testRouter(dialer, stubSystemDNS{err: errors.New("resolv.conf unusable")})

	addrs, err := router.lookupNodeIPAddr(context.Background(), "tcp4", "192.0.2.7")
	if err != nil {
		t.Fatalf("lookupNodeIPAddr: %v", err)
	}
	mustAddrs(t, addrs, netip.MustParseAddr("192.0.2.7"))
	if opened := dialer.openedAddrs(); len(opened) != 0 {
		t.Fatalf("literal lookup dialed %v", opened)
	}
}

// TestLookupNodeIPAddrClosesLosingLeg pins the lifecycle contract: the winner
// returns without waiting for the loser, and the loser's lookup is canceled and
// its connection released instead of leaking until a resolver timeout.
func TestLookupNodeIPAddrClosesLosingLeg(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	want := netip.MustParseAddr("203.0.113.11")

	dialer := newScriptedDialer()
	dialer.answers[systemAddr.String()] = want
	dialer.hang[bootstrapAddr.String()] = true

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := router.lookupNodeIPAddr(ctx, "tcp4", "node.test")
	if err != nil {
		t.Fatalf("lookupNodeIPAddr: %v", err)
	}
	mustAddrs(t, addrs, want)

	select {
	case addr := <-dialer.hungClose:
		if addr != bootstrapAddr.String() {
			t.Fatalf("closed %s, want the losing bootstrap leg %s", addr, bootstrapAddr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the losing leg was neither canceled nor closed after the lookup returned")
	}
}

// TestLookupNodeIPAddrPropagatesCallerCancel pins that a canceled caller does
// not wait for either leg and that every leg is released.
func TestLookupNodeIPAddrPropagatesCallerCancel(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")

	dialer := newScriptedDialer()
	dialer.hang[systemAddr.String()] = true
	dialer.hang[bootstrapAddr.String()] = true

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := router.lookupNodeIPAddr(ctx, "tcp4", "node.test")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	closed := make(map[string]bool)
	deadline := time.After(3 * time.Second)
	for len(closed) < 2 {
		select {
		case addr := <-dialer.hungClose:
			closed[addr] = true
		case <-deadline:
			t.Fatalf("only %v were closed after cancellation", closed)
		}
	}
	if !closed[systemAddr.String()] || !closed[bootstrapAddr.String()] {
		t.Fatalf("both legs must be released, closed=%v", closed)
	}
}

// TestRaceIPAddrLookupsCancelMidRace pins the mid-race cancellation contract:
// canceling the parent context while both legs are in flight makes the call
// return promptly with context.Canceled and leaves no leg goroutine running.
func TestRaceIPAddrLookupsCancelMidRace(t *testing.T) {
	type legProbe struct {
		started chan struct{}
		done    chan struct{}
	}
	probes := make([]*legProbe, 0, 2)
	legs := make([]ipLookupLeg, 0, 2)
	for _, name := range []string{"system", "bootstrap"} {
		probe := &legProbe{started: make(chan struct{}), done: make(chan struct{})}
		probes = append(probes, probe)
		legs = append(legs, ipLookupLeg{name: name, lookup: func(ctx context.Context) ([]net.IPAddr, error) {
			close(probe.started)
			defer close(probe.done)
			<-ctx.Done()
			return nil, ctx.Err()
		}})
	}

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() {
		_, _, err := raceIPAddrLookups(ctx, "node.test", legs)
		returned <- err
	}()

	// Wait until both legs are inside the race before canceling.
	for i, probe := range probes {
		select {
		case <-probe.started:
		case <-time.After(3 * time.Second):
			t.Fatalf("leg %d never started", i)
		}
	}
	cancel()

	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the race did not return promptly after the parent canceled")
	}
	for i, probe := range probes {
		select {
		case <-probe.done:
		case <-time.After(3 * time.Second):
			t.Fatalf("leg %d goroutine kept running after the parent canceled", i)
		}
	}
}

// TestLookupNodeIPAddrBoundsBlackholedLegs pins the per-leg deadline: a
// deadline-less caller and two silently-dropping resolvers still end on time,
// the joined failure names which leg timed out in leg order, and both legs'
// connections are released.
func TestLookupNodeIPAddrBoundsBlackholedLegs(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")

	dialer := newScriptedDialer()
	dialer.hang[systemAddr.String()] = true
	dialer.hang[bootstrapAddr.String()] = true

	orig := ipLookupLegTimeout
	ipLookupLegTimeout = 200 * time.Millisecond
	defer func() { ipLookupLegTimeout = orig }()

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
	returned := make(chan error, 1)
	go func() {
		_, err := router.lookupNodeIPAddr(context.Background(), "tcp4", "node.test")
		returned <- err
	}()

	var err error
	select {
	case err = <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the blackholed legs were not bounded by the per-leg timeout")
	}
	if err == nil {
		t.Fatal("expected an error when both legs time out")
	}
	systemText := "system leg timed out after"
	bootstrapText := "bootstrap leg timed out after"
	if !strings.Contains(err.Error(), systemText) || !strings.Contains(err.Error(), bootstrapText) {
		t.Fatalf("both leg timeouts must be named, got %q", err.Error())
	}
	if strings.Index(err.Error(), systemText) > strings.Index(err.Error(), bootstrapText) {
		t.Fatalf("leg order must be stable (system before bootstrap), got %q", err.Error())
	}

	closed := make(map[string]bool)
	deadline := time.After(3 * time.Second)
	for len(closed) < 2 {
		select {
		case addr := <-dialer.hungClose:
			closed[addr] = true
		case <-deadline:
			t.Fatalf("only %v were closed after the legs timed out", closed)
		}
	}
}

// TestLookupNodeIPAddrParentDeadlineStillWins pins that the per-leg bound never
// masks the caller's own deadline: an earlier parent deadline returns
// context.DeadlineExceeded without the per-leg timeout text.
func TestLookupNodeIPAddrParentDeadlineStillWins(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")

	dialer := newScriptedDialer()
	dialer.hang[systemAddr.String()] = true
	dialer.hang[bootstrapAddr.String()] = true

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	returned := make(chan error, 1)
	go func() {
		_, err := router.lookupNodeIPAddr(ctx, "tcp4", "node.test")
		returned <- err
	}()

	select {
	case err := <-returned:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v, want context.DeadlineExceeded", err)
		}
		if strings.Contains(err.Error(), "leg timed out") {
			t.Fatalf("the per-leg bound must not mask the parent deadline, got %q", err.Error())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the race ignored the parent deadline")
	}
}

// TestIpAddrsFromIp46SelectsTheRequestedFamily pins the extracted projection,
// including the dual-stack default branch that the resolver race relies on.
func TestIpAddrsFromIp46SelectsTheRequestedFamily(t *testing.T) {
	ip4 := netip.MustParseAddr("203.0.113.30")
	ip6 := netip.MustParseAddr("2001:db8::30")
	ip46 := &netutils.Ip46{Ip4: ip4, Ip6: ip6}

	for _, tc := range []struct {
		network string
		want    []netip.Addr
	}{
		{"tcp4", []netip.Addr{ip4}},
		{"tcp6", []netip.Addr{ip6}},
		{"tcp", []netip.Addr{ip4, ip6}},
	} {
		t.Run(tc.network, func(t *testing.T) {
			addrs, err := ipAddrsFromIp46(ip46, nil, nil, tc.network, "unused")
			if err != nil {
				t.Fatalf("ipAddrsFromIp46: %v", err)
			}
			if len(addrs) != len(tc.want) {
				t.Fatalf("got %v, want %v", addrs, tc.want)
			}
			for i, want := range tc.want {
				got, ok := netip.AddrFromSlice(addrs[i].IP)
				if !ok || got != want {
					t.Fatalf("address %d: got %v, want %v", i, addrs[i].IP, want)
				}
			}
		})
	}

	// A record-less answer surfaces the A error first, then the AAAA error.
	err4 := errors.New("A failed")
	err6 := errors.New("AAAA failed")
	if _, err := ipAddrsFromIp46(&netutils.Ip46{}, err4, err6, "tcp", "unused"); !errors.Is(err, err4) {
		t.Fatalf("got %v, want the A error", err)
	}
	if _, err := ipAddrsFromIp46(&netutils.Ip46{}, nil, err6, "tcp", "unused"); !errors.Is(err, err6) {
		t.Fatalf("got %v, want the AAAA error", err)
	}
	if _, err := ipAddrsFromIp46(nil, nil, nil, "tcp", "no address here"); err == nil || err.Error() != "no address here" {
		t.Fatalf("got %v, want the caller's no-address text", err)
	}
}

// TestResolvingDialerUsesNodeLookupWithoutControlUpstream pins the wiring: a
// node host with no matching node/sub rule resolves through the node lookup
// instead of bootstrap-only resolution.
func TestResolvingDialerUsesNodeLookupWithoutControlUpstream(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	want := netip.MustParseAddr("203.0.113.13")

	dialer := newScriptedDialer()
	dialer.answers[systemAddr.String()] = want
	dialer.fail[bootstrapAddr.String()] = true

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
	resolver := newResolvingDialer(dialer, router, "", "", "node.test")

	addrs, err := resolver.lookupIPAddr(context.Background(), "tcp4", "node.test")
	if err != nil {
		t.Fatalf("lookupIPAddr: %v", err)
	}
	mustAddrs(t, addrs, want)
}

// TestResolvingDialerKeepsUpstreamErrors pins that a configured upstream which
// fails for a reason other than passthrough is reported, not quietly replaced by
// the node lookup.
func TestResolvingDialerKeepsUpstreamErrors(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	want := netip.MustParseAddr("203.0.113.14")

	dialer := newScriptedDialer()
	dialer.answers[systemAddr.String()] = want

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr})
	resolver := newResolvingDialer(dialer, router, "missing", "missing", "node.test")

	_, err := resolver.lookupIPAddr(context.Background(), "tcp4", "node.test")
	if err == nil {
		t.Fatal("an unresolvable configured upstream must be reported")
	}
	if !strings.Contains(err.Error(), `dns upstream "missing" not found`) {
		t.Fatalf("got %q, want the upstream error", err.Error())
	}
	if opened := dialer.openedAddrs(); len(opened) != 0 {
		t.Fatalf("the node lookup must not run after an upstream error, dialed %v", opened)
	}
}

// controlUpstreamResolver builds a named upstream the control path can select,
// so a test can drive how that upstream's lookup terminates.
func controlUpstreamResolver(raw *url.URL, finish func(*url.URL, *componentdns.Upstream) error) *componentdns.UpstreamResolver {
	return &componentdns.UpstreamResolver{
		Raw:                raw,
		Network:            "udp",
		FinishInitCallback: finish,
	}
}

// TestResolvingDialerControlUpstreamPassthroughFallsBackToNodeLookup pins the
// passthrough branch of the control lookup: when the selected control upstream
// resolves to a passthrough action, the node lookup race answers instead of the
// lookup failing outright.
func TestResolvingDialerControlUpstreamPassthroughFallsBackToNodeLookup(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	want := netip.MustParseAddr("203.0.113.31")

	dialer := newScriptedDialer()
	dialer.answers[systemAddr.String()] = want
	dialer.fail[bootstrapAddr.String()] = true

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
	router.upstreams = map[string]*componentdns.UpstreamResolver{
		"passe": controlUpstreamResolver(&url.URL{Scheme: "udp", Host: "192.0.2.54:53"},
			func(*url.URL, *componentdns.Upstream) error { return errPassthroughToBaseResolver }),
	}
	resolver := newResolvingDialer(dialer, router, "passe", "passe", "node.test")

	addrs, err := resolver.lookupIPAddr(context.Background(), "tcp4", "node.test")
	if err != nil {
		t.Fatalf("lookupIPAddr: %v", err)
	}
	mustAddrs(t, addrs, want)
}

// TestResolvingDialerControlUpstreamEmptyAnswerFallsBackToNodeLookup pins the
// empty-answer branch of the control lookup: a control upstream that answers
// with no records defers to the node lookup race instead of returning nothing.
func TestResolvingDialerControlUpstreamEmptyAnswerFallsBackToNodeLookup(t *testing.T) {
	systemAddr := netip.MustParseAddrPort("192.0.2.53:53")
	bootstrapAddr := netip.MustParseAddrPort("198.51.100.53:53")
	controlAddr := netip.MustParseAddrPort("192.0.2.54:53")
	want := netip.MustParseAddr("203.0.113.32")

	dialer := newScriptedDialer()
	dialer.answers[systemAddr.String()] = want
	dialer.fail[bootstrapAddr.String()] = true
	// The control upstream stays unanswered on purpose: its scripted reply
	// carries zero records, so the control lookup returns no address.

	router := testRouter(dialer, stubSystemDNS{addr: systemAddr}, bootstrapAddr)
	router.upstreams = map[string]*componentdns.UpstreamResolver{
		"empty": controlUpstreamResolver(&url.URL{Scheme: "udp", Host: controlAddr.String()}, nil),
	}
	resolver := newResolvingDialer(dialer, router, "empty", "empty", "node.test")

	addrs, err := resolver.lookupIPAddr(context.Background(), "tcp4", "node.test")
	if err != nil {
		t.Fatalf("lookupIPAddr: %v", err)
	}
	mustAddrs(t, addrs, want)
	if opened := dialer.openedAddrs(); !slices.Contains(opened, controlAddr.String()) {
		t.Fatalf("the control upstream was never queried, dialed %v", opened)
	}
}
