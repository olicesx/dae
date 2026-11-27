/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org
 */

package control

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestTraceDNSUsesPrivateRequestAndResponseRouting(t *testing.T) {
	var udpCalls, tcpCalls, responseRouteCalls atomic.Int32
	listener, err := net.Listen("tcp6", "[::1]:0")
	require.NoError(t, err)
	packetConn, err := net.ListenPacket("udp6", listener.Addr().String())
	require.NoError(t, err)
	serveTraceDNS(t, &dnsmessage.Server{PacketConn: packetConn, Handler: dnsmessage.HandlerFunc(func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		udpCalls.Add(1)
		resp := new(dnsmessage.Msg).SetReply(q)
		resp.Truncated = true
		_ = w.WriteMsg(resp)
	})})
	serveTraceDNS(t, &dnsmessage.Server{Listener: listener, Handler: dnsmessage.HandlerFunc(func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		tcpCalls.Add(1)
		_ = w.WriteMsg(new(dnsmessage.Msg).SetReply(q))
	})})
	final, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	serveTraceDNS(t, &dnsmessage.Server{Listener: final, Handler: dnsmessage.HandlerFunc(func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		responseRouteCalls.Add(1)
		response := new(dnsmessage.Msg).SetReply(q)
		answer, err := dnsmessage.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.42")
		if err != nil {
			t.Error(err)
			return
		}
		response.Answer = []dnsmessage.RR{answer}
		_ = w.WriteMsg(response)
	})})

	cfg := &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString("primary:udp://" + listener.Addr().String()),
			config.KeyableString("final:tcp://" + final.Addr().String()),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules:    []*config_parser.RoutingRule{traceRule([]*config_parser.Function{traceFunction(consts.Function_QType, false, "A")}, "primary")},
				Fallback: "reject",
			},
			Response: config.DnsResponseRouting{
				Rules:    []*config_parser.RoutingRule{traceRule([]*config_parser.Function{traceFunction(consts.Function_Upstream, false, "primary")}, "final")},
				Fallback: "accept",
			},
		},
	}
	// The plane has no runtime DNS controller or proxy dialer. The trace works
	// with both absent, including its UDP-to-TCP and policy retries.
	plane, _ := newTraceDNSTestPlane(t, "direct")
	trace := buildTraceDNSTest(t, plane, cfg)
	t.Cleanup(trace.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := trace.Lookup(ctx, "trace.example", TraceDNSInput{})
	require.NoError(t, err, "upstream calls: UDP=%d TCP=%d response-route=%d", udpCalls.Load(), tcpCalls.Load(), responseRouteCalls.Load())
	require.Len(t, results, 2)
	require.Equal(t, "NOERROR", results[0].Status)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.42")}, results[0].Addresses)
	require.Equal(t, "tcp://"+final.Addr().String(), results[0].Upstream)
	require.Equal(t, "REJECT", results[1].Status)
	require.Empty(t, results[1].Addresses)
	// One UDP attempt truncates and one TCP attempt answers; the A answer is
	// re-asked once by the response policy.
	require.EqualValues(t, 1, udpCalls.Load())
	require.EqualValues(t, 1, tcpCalls.Load())
	require.EqualValues(t, 1, responseRouteCalls.Load())
}

func TestTraceDNSUDPOnlyDoesNotRetryInvalidAnswersOverTCP(t *testing.T) {
	var tcpCalls atomic.Int32
	target := serveTraceDNSOn(t, "127.0.0.1:0", func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		tcpCalls.Add(1)
		_ = w.WriteMsg(new(dnsmessage.Msg).SetReply(q))
	})
	packetConn, err := net.ListenPacket("udp4", target.String())
	require.NoError(t, err)
	serveTraceDNS(t, &dnsmessage.Server{PacketConn: packetConn, Handler: dnsmessage.HandlerFunc(func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		response := new(dnsmessage.Msg).SetReply(q)
		response.Question[0].Name = "wrong.example."
		_ = w.WriteMsg(response)
	})})
	plane, _ := newTraceDNSTestPlane(t, "direct")
	trace := newTraceDNSFor(t, plane, "up:udp://"+target.String())
	t.Cleanup(trace.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	answers, err := trace.Lookup(ctx, "trace.example", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "ERROR", answers[0].Status)
	require.Equal(t, "ERROR", answers[1].Status)
	require.Zero(t, tcpCalls.Load())
}

func TestTraceDNSStaysClosed(t *testing.T) {
	var calls atomic.Int32
	upstream := serveTraceDNSOn(t, "127.0.0.1:0", func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		calls.Add(1)
		_ = w.WriteMsg(new(dnsmessage.Msg).SetReply(q))
	})
	plane, _ := newTraceDNSTestPlane(t, "direct")
	trace := newTraceDNSFor(t, plane, "up:tcp://"+upstream.String())
	results, err := trace.Lookup(context.Background(), "trace.example", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "NOERROR", results[0].Status, results[0].Reason)
	trace.Close()
	_, err = trace.Lookup(context.Background(), "trace.example", TraceDNSInput{})
	var policyErr *TraceDNSPolicyError
	require.ErrorAs(t, err, &policyErr)
	require.ErrorContains(t, err, "closed")
	require.EqualValues(t, 2, calls.Load(), "a closed resolver dials nothing")
	trace.Close()
}

func TestTraceDNSRetirementCancelsBothQuestions(t *testing.T) {
	questions := make(chan uint16, 2)
	release := make(chan struct{})
	upstream := serveTraceDNSOn(t, "127.0.0.1:0", func(_ dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		questions <- q.Question[0].Qtype
		<-release
	})
	defer close(release)
	plane, _ := newTraceDNSTestPlane(t, "direct")
	trace := newTraceDNSFor(t, plane, "up:tcp://"+upstream.String())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	outcome := make(chan error, 1)
	go func() {
		_, err := trace.Lookup(ctx, "trace.example", TraceDNSInput{})
		outcome <- err
	}()
	var seen []uint16
	for range 2 {
		select {
		case question := <-questions:
			seen = append(seen, question)
		case <-ctx.Done():
			t.Fatal("both questions must reach the upstream before it answers either")
		}
	}
	require.ElementsMatch(t, []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA}, seen)
	closed := make(chan struct{})
	go func() {
		trace.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("closing the trace did not cancel in-flight queries")
	}
	require.ErrorContains(t, <-outcome, "closed")
}

func TestTraceDNSTraceEgressVerdictFollowsRulesAndReportsMissingInputs(t *testing.T) {
	matcher, rules := newRoutingTraceMatcher(t,
		traceRule([]*config_parser.Function{traceFunction(consts.Function_ProcessName, false, "dnsmasq")}, "direct"),
		traceRule([]*config_parser.Function{traceFunction(consts.Function_Port, false, "53")}, "proxy"),
	)
	target := netip.MustParseAddrPort("192.0.2.53:53")
	targetAddr := target.Addr()
	pname := "dnsmasq"
	local := netip.MustParseAddr("127.0.0.1")

	// A local client with the named process takes the direct rule; another
	// local client falls through to the port rule.
	verdict, err := matcher.TraceEgress(context.Background(), RoutingTraceInput{
		Network: consts.L4ProtoType_TCP, DstIP: &targetAddr, DstPort: 53, SrcIP: &local, Pname: &pname,
	}, rules)
	require.NoError(t, err)
	require.Equal(t, consts.OutboundDirect, verdict.Outbound)
	require.Empty(t, verdict.MissingInputs)

	other := "curl"
	verdict, err = matcher.TraceEgress(context.Background(), RoutingTraceInput{
		Network: consts.L4ProtoType_TCP, DstIP: &targetAddr, DstPort: 53, SrcIP: &local, Pname: &other,
	}, rules)
	require.NoError(t, err)
	require.Equal(t, consts.OutboundUserDefinedMin, verdict.Outbound)

	// Without the process name the first rule cannot be evaluated, and the
	// verdict reports that instead of guessing.
	verdict, err = matcher.TraceEgress(context.Background(), RoutingTraceInput{
		Network: consts.L4ProtoType_TCP, DstIP: &targetAddr, DstPort: 53, SrcIP: &local,
	}, rules)
	require.NoError(t, err)
	require.Equal(t, []string{"pname"}, verdict.MissingInputs)
}

func TestTraceEgressUsesCompiledFallbackMark(t *testing.T) {
	matcher, rules := newRoutingTraceMatcherWithFallback(t, &config_parser.Function{
		Name: "direct", Params: []*config_parser.Param{{Key: "mark", Val: "2048"}},
	})
	result, err := matcher.TraceEgress(t.Context(), RoutingTraceInput{}, rules)
	require.NoError(t, err)
	require.Equal(t, consts.OutboundDirect, result.Outbound)
	require.EqualValues(t, 2048, result.Mark)
}

func TestTraceDNSRefusesEgressThatDependsOnAMissingInput(t *testing.T) {
	var calls atomic.Int32
	upstream := serveTraceDNSOn(t, "127.0.0.1:0", func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		calls.Add(1)
		_ = w.WriteMsg(new(dnsmessage.Msg).SetReply(q))
	})
	plane, _ := newTraceDNSTestPlane(t, "direct",
		traceRule([]*config_parser.Function{traceFunction(consts.Function_ProcessName, false, "dnsmasq")}, "direct"),
		traceRule([]*config_parser.Function{traceFunction(consts.Function_SourcePort, false, "5353")}, "direct"),
		traceRule([]*config_parser.Function{traceFunction(consts.Function_Ip, false, "127.0.0.1")}, "proxy"),
	)
	trace := newTraceDNSFor(t, plane, "up:tcp://"+upstream.String())
	defer trace.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This host's own traffic has a process name the trace does not know.
	none := ""
	results, err := trace.Lookup(ctx, "trace.example", TraceDNSInput{Src: netip.MustParseAddrPort("127.0.0.1:40000")})
	require.NoError(t, err)
	require.Equal(t, "ERROR", results[0].Status)
	require.Contains(t, results[0].Reason, "pname")
	require.Zero(t, calls.Load(), "a lookup with an unknown path must not dial")

	// A packet forwarded from another host carries no process name, so the
	// absent pname is none: the first rule does not match and the second sends
	// the query to an outbound the trace cannot dial, which is reported.
	results, err = trace.Lookup(ctx, "trace.example", TraceDNSInput{Src: netip.MustParseAddrPort("192.0.2.10:40000")})
	require.NoError(t, err)
	require.Equal(t, "ERROR", results[0].Status, results[0].Reason)
	require.Contains(t, results[0].Reason, "outbound 2")
	require.Zero(t, calls.Load())
	// A source without a port leaves port rules alone: the query is not sent
	// on a guess.
	results, err = trace.Lookup(ctx, "trace.example", TraceDNSInput{Src: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), 0), Pname: &none})
	require.NoError(t, err)
	require.Equal(t, "ERROR", results[0].Status, results[0].Reason)
	require.Contains(t, results[0].Reason, "src_port")
	require.Zero(t, calls.Load())

	// A trace that names no client at all is for a forwarded one: the pname
	// rule is decided. What still cannot be known without a client, here the
	// source port, is reported rather than guessed.
	results, err = trace.Lookup(ctx, "trace.example", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "ERROR", results[0].Status, results[0].Reason)
	require.Contains(t, results[0].Reason, "src_port")
	require.NotContains(t, results[0].Reason, "pname")
	require.Zero(t, calls.Load())

	// Naming the process makes the path known, and the lookup is made.
	pname := "dnsmasq"
	results, err = trace.Lookup(ctx, "trace.example", TraceDNSInput{Src: netip.MustParseAddrPort("127.0.0.1:40000"), Pname: &pname})
	require.NoError(t, err)
	require.Equal(t, "NOERROR", results[0].Status)
	require.EqualValues(t, 2, calls.Load())
}

func TestTraceDNSRefusesOwnListenerAndBlockedUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := serveTraceDNSOn(t, "127.0.0.1:0", func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		calls.Add(1)
		_ = w.WriteMsg(new(dnsmessage.Msg).SetReply(q))
	})

	// The upstream is dae's own listener: a query there would be cached by
	// the runtime.
	plane, _ := newTraceDNSTestPlane(t, "direct")
	trace := newTraceDNSFor(t, plane, "up:tcp://"+upstream.String())
	trace.listener = upstream
	defer trace.Close()
	results, err := trace.Lookup(context.Background(), "trace.example", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "ERROR", results[0].Status)
	require.Contains(t, results[0].Reason, "dae's own listener")
	require.Zero(t, calls.Load())

	// A listener bound to a wildcard address owns its port on this host only:
	// an upstream with the same port on another host is a real upstream.
	var answered atomic.Int32
	directUpstream := serveTraceDNSOn(t, "127.0.0.1:0", func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		answered.Add(1)
		_ = w.WriteMsg(new(dnsmessage.Msg).SetReply(q))
	})
	plane, _ = newTraceDNSTestPlane(t, "direct")
	trace = newTraceDNSFor(t, plane, "up:tcp://"+directUpstream.String())
	listener, err := netip.ParseAddrPort("0.0.0.0:" + strconv.Itoa(int(directUpstream.Port())))
	require.NoError(t, err)
	trace.listener = listener
	defer trace.Close()
	require.True(t, trace.reentersListener(netip.MustParseAddrPort("127.0.0.1:"+strconv.Itoa(int(directUpstream.Port())))), "loopback is this host")
	require.False(t, trace.reentersListener(netip.MustParseAddrPort("192.0.2.53:"+strconv.Itoa(int(directUpstream.Port())))), "another host is not")
	// The daemon's listener is on another port: the upstream is queried.
	trace.listener = netip.MustParseAddrPort("0.0.0.0:53999")
	results, err = trace.Lookup(context.Background(), "trace.example", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "NOERROR", results[0].Status, results[0].Reason)
	require.EqualValues(t, 2, answered.Load())

	// Routing blocks everything the upstream would match.
	plane, _ = newTraceDNSTestPlane(t, "block")
	trace = newTraceDNSFor(t, plane, "up:tcp://"+upstream.String())
	defer trace.Close()
	results, err = trace.Lookup(context.Background(), "trace.example", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "ERROR", results[0].Status)
	require.Contains(t, results[0].Reason, "blocks")
	require.Zero(t, calls.Load())
}

func TestTraceDNSReportsAnOutboundWithoutANode(t *testing.T) {
	plane, option := newTraceDNSTestPlane(t, "proxy")
	// An outbound group without any member: nothing can carry the query.
	plane.outbounds = append(plane.outbounds, outbound.NewDialerGroup(option, "proxy", nil, nil,
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed}, nil))
	trace := newTraceDNSFor(t, plane, "up:tcp://127.0.0.1:53991")
	defer trace.Close()
	results, err := trace.Lookup(context.Background(), "trace.example", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "ERROR", results[0].Status)
	require.Contains(t, results[0].Reason, "proxy")
	require.Contains(t, results[0].Reason, "no node")
}

func TestTraceDNSDialsThroughAPrivateCopyOfTheSelectedNode(t *testing.T) {
	var calls atomic.Int32
	target := serveTraceDNSOn(t, "127.0.0.1:0", func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		calls.Add(1)
		response := new(dnsmessage.Msg).SetReply(q)
		if q.Question[0].Qtype == dnsmessage.TypeA {
			answer, err := dnsmessage.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.99")
			if err != nil {
				t.Error(err)
				return
			}
			response.Answer = []dnsmessage.RR{answer}
		}
		_ = w.WriteMsg(response)
	})
	relay := serveTraceSocks5(t)

	// The outbound group holds a node that leads to the relay; the query must
	// reach the upstream through it without the runtime node being used.
	plane, option := newTraceDNSTestPlane(t, "proxy")
	// The loopback relay needs no routing mark. Setting SO_MARK requires
	// capabilities that the unit and race jobs do not grant.
	option.SoMarkFromDae = 0
	runtime, err := dialer.NewFromLinkContext(context.Background(), option, dialer.InstanceOption{DisableCheck: true},
		"socks5://"+relay.addr.String()+"#runtime-node", "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = runtime.Close() })
	plane.outbounds = append(plane.outbounds, outbound.NewDialerGroup(option, "proxy", []*dialer.Dialer{runtime}, nil,
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, nil))
	trace := newTraceDNSFor(t, plane, "up:tcp://"+target.String())
	defer trace.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := trace.Lookup(ctx, "trace.example", TraceDNSInput{Src: netip.MustParseAddrPort("192.0.2.10:40000")})
	require.NoError(t, err)
	require.Equal(t, "NOERROR", results[0].Status, results[0].Reason)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.99")}, results[0].Addresses)
	require.Equal(t, "tcp", results[0].CarrierTransport)
	require.EqualValues(t, 2, calls.Load(), "A and AAAA both reach the upstream")
	require.Len(t, relay.targets(), 2, "A and AAAA each open one relay connection")
	for _, asked := range relay.targets() {
		require.Equal(t, net.JoinHostPort(target.Addr().String(), strconv.Itoa(int(target.Port()))), asked)
	}
	// The runtime node keeps its identity and is still usable: the lookup went
	// through a copy and closed only that.
	require.Equal(t, "runtime-node", runtime.Property().Name)
	require.Equal(t, "socks5://"+relay.addr.String()+"#runtime-node", runtime.Property().Link)
}

func TestTraceDNSUsesCompiledPolicyAfterAssetReplacement(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", dir)
	payload, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		CountryCode: "cn",
		Domain:      []*geodata.Domain{{Type: geodata.Domain_RootDomain, Value: "example.cn"}},
	}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geosite.dat"), payload, 0o600))

	var cnCalls, otherCalls atomic.Int32
	cn := serveTraceDNSOn(t, "127.0.0.1:0", func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		cnCalls.Add(1)
		_ = w.WriteMsg(new(dnsmessage.Msg).SetReply(q))
	})
	other := serveTraceDNSOn(t, "127.0.0.1:0", func(w dnsmessage.ResponseWriter, q *dnsmessage.Msg) {
		otherCalls.Add(1)
		_ = w.WriteMsg(new(dnsmessage.Msg).SetReply(q))
	})
	plane, _ := newTraceDNSTestPlane(t, "direct")
	trace := buildTraceDNSTest(t, plane, &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString("cn:tcp://" + cn.String()),
			config.KeyableString("other:tcp://" + other.String()),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{traceRule([]*config_parser.Function{{
					Name:   consts.Function_QName,
					Params: []*config_parser.Param{{Key: "geosite", Val: "cn"}},
				}}, "cn")},
				Fallback: "other",
			},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	})
	t.Cleanup(trace.Close)

	// Replace the file before the first trace. The active DNS policy still
	// matches the original domain from generation start.
	replaced, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		CountryCode: "cn",
		Domain:      []*geodata.Domain{{Type: geodata.Domain_RootDomain, Value: "replaced.example"}},
	}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geosite.dat"), replaced, 0o600))
	results, err := trace.Lookup(t.Context(), "www.example.cn", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "NOERROR", results[0].Status, results[0].Reason)
	require.Equal(t, "tcp://"+cn.String(), results[0].Upstream)
	results, err = trace.Lookup(t.Context(), "replaced.example", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "tcp://"+other.String(), results[0].Upstream)
	require.EqualValues(t, 2, cnCalls.Load())
	require.EqualValues(t, 2, otherCalls.Load())
}

func TestTraceDNSReportsAHostnameUpstreamWithoutBootstrap(t *testing.T) {
	plane, _ := newTraceDNSTestPlane(t, "direct")
	trace := newTraceDNSFor(t, plane, "up:tcp://resolver.example:53")
	defer trace.Close()
	// The generation itself would refuse such a configuration; should one
	// reach a trace, the question fails without quoting the upstream.
	results, err := trace.Lookup(context.Background(), "trace.example", TraceDNSInput{})
	require.NoError(t, err)
	require.Equal(t, "ERROR", results[0].Status)
	require.Contains(t, results[0].Reason, "no address to send to")
	require.NotContains(t, results[0].Reason, "resolver.example")
	require.Empty(t, results[0].Addresses)
}

// serveTraceDNS starts server and stops it with the test.
func serveTraceDNS(t *testing.T, server *dnsmessage.Server) {
	t.Helper()
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("start upstream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("DNS upstream did not start")
	}
	t.Cleanup(func() {
		require.NoError(t, server.Shutdown())
		require.NoError(t, <-done)
	})
}

// newTraceDNSTestPlane builds the parts of a plane a trace lookup reads: a
// routing matcher that also serves as the trace matcher, the built-in direct
// outbound and the settings private dialers are built from. It has no runtime
// DNS controller and no proxy outbound; a test adds one under the "proxy"
// name when it needs a group.
func newTraceDNSTestPlane(t *testing.T, fallback string, rules ...*config_parser.RoutingRule) (*ControlPlane, *dialer.GlobalOption) {
	t.Helper()
	matcher, snapshots := newRoutingTraceMatcherWithFallback(t, config.FunctionOrString(fallback), rules...)
	option := dialer.NewGlobalOption(&config.Global{}, quietTraceLogger())
	t.Cleanup(func() { dialer.CleanupTransportCacheNamespace(option.TransportCacheNamespace) })
	base, property := dialer.NewDirectDialer(option, true)
	direct := dialer.NewDialerContext(context.Background(), base, option, dialer.InstanceOption{DisableCheck: true}, property)
	t.Cleanup(func() { _ = direct.Close() })
	plane := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			routingMatcher:      matcher,
			routingTraceMatcher: matcher,
			routingRules:        snapshots,
			routingFallback:     fallback,
			outbounds:           []*outbound.DialerGroup{consts.OutboundDirect: nil},
		},
		traceDnsOption: option,
	}
	plane.outbounds[consts.OutboundDirect] = outbound.NewDialerGroup(option, consts.OutboundDirect.String(),
		[]*dialer.Dialer{direct}, nil,
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, nil)
	_block, blockProperty := dialer.NewBlockDialer(option, func() {})
	block := dialer.NewDialerContext(context.Background(), _block, option, dialer.InstanceOption{DisableCheck: true}, blockProperty)
	t.Cleanup(func() { _ = block.Close() })
	plane.outbounds = append(plane.outbounds, outbound.NewDialerGroup(option, consts.OutboundBlock.String(), []*dialer.Dialer{block}, nil,
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, nil))
	return plane, option
}

func buildTraceDNSTest(t *testing.T, plane *ControlPlane, cfg *config.Dns) *TraceDNS {
	t.Helper()
	routing, err := dns.New(cfg, &dns.NewOption{Logger: quietTraceLogger(), LocationFinder: assets.NewLocationFinder(nil)})
	require.NoError(t, err)
	plane.dnsRouting = routing
	trace, err := plane.NewTraceDNS(cfg)
	require.NoError(t, err)
	return trace
}

// newTraceDNSFor serves every question from one named upstream.
func newTraceDNSFor(t *testing.T, plane *ControlPlane, upstream string) *TraceDNS {
	t.Helper()
	trace := buildTraceDNSTest(t, plane, &config.Dns{
		Upstream: []config.KeyableString{config.KeyableString(upstream)},
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: strings.SplitN(upstream, ":", 2)[0]},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	})
	return trace
}

// serveTraceDNSOn starts a TCP DNS server bound to address and answering
// every question with reply.
func serveTraceDNSOn(t *testing.T, address string, reply func(dnsmessage.ResponseWriter, *dnsmessage.Msg)) netip.AddrPort {
	t.Helper()
	listener, err := net.Listen("tcp4", address)
	require.NoError(t, err)
	serveTraceDNS(t, &dnsmessage.Server{Listener: listener, Handler: dnsmessage.HandlerFunc(reply)})
	addrPort, err := netip.ParseAddrPort(listener.Addr().String())
	require.NoError(t, err)
	return addrPort
}

// traceSocks5Relay is a SOCKS5 server without authentication that relays
// every CONNECT to its destination. It stands in for a proxy node: a query
// that reaches an upstream through it was dialled through a node leading here.
type traceSocks5Relay struct {
	addr  netip.AddrPort
	mu    sync.Mutex
	asked []string
}

// targets returns the destinations the relay was asked for, in order.
func (relay *traceSocks5Relay) targets() []string {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return append([]string(nil), relay.asked...)
}

func serveTraceSocks5(t *testing.T) *traceSocks5Relay {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	relay := &traceSocks5Relay{}
	relay.addr, err = netip.ParseAddrPort(listener.Addr().String())
	require.NoError(t, err)
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go relay.serve(client)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return relay
}

// serve handles one SOCKS5 client: greeting, CONNECT, then a bidirectional
// copy. It records the destination before connecting, as a relay that
// answers first would.
func (relay *traceSocks5Relay) serve(client net.Conn) {
	defer func() { _ = client.Close() }()
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting[0] != 5 {
		return
	}
	if _, err := io.ReadFull(client, make([]byte, greeting[1])); err != nil {
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(client, request[:]); err != nil || request[1] != 1 {
		return
	}
	var host []byte
	switch request[3] {
	case 1:
		host = make([]byte, 4)
	case 4:
		host = make([]byte, 16)
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(client, length[:]); err != nil {
			return
		}
		host = make([]byte, length[0])
	default:
		return
	}
	if _, err := io.ReadFull(client, host); err != nil {
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(client, port[:]); err != nil {
		return
	}
	target := net.JoinHostPort(net.IP(host).String(), strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))
	relay.mu.Lock()
	relay.asked = append(relay.asked, target)
	relay.mu.Unlock()
	if _, err := client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()
	go func() { _, _ = io.Copy(upstream, client) }()
	_, _ = io.Copy(client, upstream)
}
