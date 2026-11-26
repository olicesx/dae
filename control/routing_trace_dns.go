/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// TraceDNS resolves names the way the running generation would for one
// client, from private state only. The DNS policy is a private instance of the
// generation's compiled rules with its own mutable state. Each upstream query is
// routed by the client's source address and packet metadata, as the runtime
// routes it, and travels through a dialer built for the lookup. No runtime DNS
// cache, forwarder, dialer, health or selection state is written, so a lookup
// cannot change what the datapath does.
type TraceDNS struct {
	plane    *ControlPlane
	log      *logrus.Logger
	listener netip.AddrPort // dae's own DNS listener, when one is bound

	lifetime  context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	lookups   sync.WaitGroup
	mu        sync.Mutex
	compiled  *dns.Dns
	routing   *dns.Dns
	direct    *dialer.Dialer
}

// TraceDNSPolicyError reports an unavailable generation DNS snapshot.
// Reason is safe to show to API clients.
type TraceDNSPolicyError struct {
	Reason string
}

func (e *TraceDNSPolicyError) Error() string { return e.Reason }

// TraceDNSInput is the client a lookup is made for. The runtime routes a DNS
// upstream query by the requesting client's source address and packet
// metadata, so a lookup without them cannot say which path a query takes.
type TraceDNSInput struct {
	// Src is the client's address and port. An invalid Src means the trace
	// has no source; port 0 means the source port is unknown.
	Src   netip.AddrPort
	Pname *string
	Dscp  *uint8
}

// TraceDNSResult holds the terminal result for one A or AAAA question.
type TraceDNSResult struct {
	Question          dnsmessage.Question
	Upstream          string
	UpstreamTransport string
	CarrierTransport  string
	Status            string
	// Reason explains a failed Status in words a client may show. It names
	// inputs, outbounds and upstreams, never a node or its credentials.
	Reason    string
	Addresses []netip.Addr
}

// NewTraceDNS prepares live lookups against the control plane's compiled DNS
// and traffic policies. cfg supplies the address of the daemon's DNS listener.
func (c *ControlPlane) NewTraceDNS(cfg *config.Dns) (*TraceDNS, error) {
	if c == nil || c.routingTraceMatcher == nil || cfg == nil || c.traceDnsOption == nil || c.dnsRouting == nil {
		return nil, fmt.Errorf("routing trace DNS policy is unavailable")
	}
	listener, err := traceDNSListener(cfg)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &TraceDNS{plane: c, log: quietTraceLogger(), listener: listener, lifetime: lifetime, cancel: cancel, compiled: c.dnsRouting}, nil
}

// Close releases the private dialers. A lookup that starts after it fails
// instead of rebuilding them for a generation that is being retired.
func (trace *TraceDNS) Close() {
	trace.closeOnce.Do(func() {
		trace.mu.Lock()
		trace.cancel()
		trace.mu.Unlock()

		trace.lookups.Wait()
		if trace.direct != nil {
			_ = trace.direct.Close()
		}
		trace.direct = nil
		trace.routing = nil
		trace.compiled = nil
	})
}

// Lookup follows the request and response matchers with the standard retry
// depth. The caller's deadline bounds both questions and every transport hop.
func (trace *TraceDNS) Lookup(ctx context.Context, domain string, input TraceDNSInput) ([]TraceDNSResult, error) {
	routing, err := trace.beginLookup(ctx)
	if err != nil {
		return nil, err
	}
	defer trace.lookups.Done()
	lookupCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(trace.lifetime, cancel)
	defer cancel()
	defer stop()
	// The datapath knows a process name only for traffic this host generates;
	// a packet forwarded from another host carries none. A lookup for such a
	// source, or for no source at all (a client the trace does not name is
	// taken to be a forwarded one), therefore has no pname, and pname rules
	// are decided instead of left open. A source on this host keeps its
	// pname unknown: the trace must name it to get a determinate path.
	none := ""
	if input.Pname == nil && (!input.Src.IsValid() || !isLocalAddress(input.Src.Addr())) {
		input.Pname = &none
	}
	name := dnsmessage.Fqdn(domain)
	results := make([]TraceDNSResult, 2)
	var aaaa sync.WaitGroup
	aaaa.Go(func() {
		results[1] = trace.lookup(lookupCtx, routing, new(dnsmessage.Msg).SetQuestion(name, dnsmessage.TypeAAAA), input)
	})
	results[0] = trace.lookup(lookupCtx, routing, new(dnsmessage.Msg).SetQuestion(name, dnsmessage.TypeA), input)
	aaaa.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if trace.lifetime.Err() != nil {
		return nil, traceDNSClosedError()
	}
	return results, nil
}

func traceDNSClosedError() error {
	return &TraceDNSPolicyError{Reason: "the live resolver of this generation is closed; retry after the reload"}
}

// beginLookup admits one lookup and initializes its private resources on
// first use. Close holds the same lock when it stops admission.
func (trace *TraceDNS) beginLookup(ctx context.Context) (*dns.Dns, error) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if trace.lifetime.Err() != nil {
		return nil, traceDNSClosedError()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if trace.routing == nil {
		trace.routing = trace.compiled.WithIndependentState(trace.log)
		trace.compiled = nil
		option := trace.plane.traceDnsOption
		base, property := dialer.NewDirectDialer(option, true)
		trace.direct = dialer.NewDialerContext(trace.lifetime, base, option, dialer.InstanceOption{DisableCheck: true}, property)
	}
	trace.lookups.Add(1)
	return trace.routing, nil
}

func (trace *TraceDNS) lookup(ctx context.Context, routing *dns.Dns, query *dnsmessage.Msg, input TraceDNSInput) TraceDNSResult {
	q := query.Question[0]
	result := TraceDNSResult{Question: q, Addresses: []netip.Addr{}}
	index, upstream, err := routing.RequestSelect(ctx, q.Name, q.Qtype)
	if err != nil {
		result.Status, result.Reason = dnsErrorStatus(err), "the DNS request policy could not select an upstream"
		if strings.Contains(err.Error(), "bootstrap_resolver") {
			result.Reason = "a DNS upstream is named by a host that has no address to send to"
		}
		return result
	}
	if index == consts.DnsRequestOutboundIndex_Reject {
		result.Status, result.Reason = "REJECT", "the request policy rejects the question"
		return result
	}
	if upstream == nil {
		result.Status, result.Reason = "ASIS_UNAVAILABLE", "the request policy answers as-is, which needs the client's own DNS server"
		return result
	}
	for range MaxDnsLookupDepth {
		result.CarrierTransport = ""
		result.UpstreamTransport = ""
		result.Upstream = upstream.String()
		if _, protos := upstream.SupportedNetworks(); len(protos) > 0 {
			result.UpstreamTransport = traceUpstreamTransport(upstream.Scheme, protos[0])
		}
		response, err := trace.exchange(ctx, query, upstream, input, &result)
		if err != nil || response.Truncated {
			result.Status, result.Reason = "ERROR", "the upstream answered with a truncated response"
			if err != nil {
				result.Status, result.Reason = dnsErrorStatus(err), traceExchangeReason(ctx, err)
			}
			return result
		}
		decision, next, err := routing.ResponseSelect(ctx, response, upstream)
		if err != nil {
			result.Status, result.Reason = dnsErrorStatus(err), "the response policy could not be evaluated"
			return result
		}
		switch decision {
		case consts.DnsResponseOutboundIndex_Reject:
			result.Status, result.Reason = "REJECT", "the response policy rejects the answer"
			return result
		case consts.DnsResponseOutboundIndex_Accept:
			result.Status = dnsRcodeName(response.Rcode)
			if response.Rcode == dnsmessage.RcodeSuccess {
				for _, rr := range response.Answer {
					switch record := rr.(type) {
					case *dnsmessage.A:
						if ip, ok := netip.AddrFromSlice(record.A); ok && q.Qtype == dnsmessage.TypeA {
							result.Addresses = append(result.Addresses, ip.Unmap())
						}
					case *dnsmessage.AAAA:
						if ip, ok := netip.AddrFromSlice(record.AAAA); ok && q.Qtype == dnsmessage.TypeAAAA {
							result.Addresses = append(result.Addresses, ip.Unmap())
						}
					}
				}
			}
			return result
		default:
			upstream = next
		}
	}
	result.Status, result.Reason = "ERROR", "the response policy asked more upstreams than the lookup depth allows"
	return result
}

// traceExchangeReason words a failed exchange for a client. A terminal
// error already carries its reason; anything else is the upstream not
// answering, or the caller's deadline ending the lookup.
func traceExchangeReason(ctx context.Context, err error) string {
	var terminal *traceDNSTerminal
	if stderrors.As(err, &terminal) {
		return terminal.reason
	}
	if stderrors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return "the lookup did not finish in time"
	}
	return "the upstream did not answer"
}

// traceDNSTerminal marks an error that ends the exchange.
type traceDNSTerminal struct {
	reason string
}

func (e *traceDNSTerminal) Error() string { return e.reason }

// exchange tries each supported path once. A UDP-only upstream permits
// TCP fallback after a truncated or undeliverable response.
func (trace *TraceDNS) exchange(ctx context.Context, query *dnsmessage.Msg, upstream *dns.Upstream, input TraceDNSInput, result *TraceDNSResult) (*dnsmessage.Msg, error) {
	versions, protocols := upstream.SupportedNetworks()
	var lastErr error
	for _, version := range versions {
		address := upstream.Ip4
		if version == consts.IpVersionStr_6 {
			address = upstream.Ip6
		}
		if !address.IsValid() {
			continue
		}
		target := netip.AddrPortFrom(address, upstream.Port)
		for _, protocol := range protocols {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			msg, err := trace.send(ctx, query, upstream, target, version, protocol, input, result)
			var terminal *traceDNSTerminal
			if err == nil || stderrors.As(err, &terminal) {
				return msg, err
			}
			lastErr = err
		}
		if upstream.Scheme == dns.UpstreamScheme_UDP &&
			(stderrors.Is(lastErr, ErrDNSTruncated) || classifyDnsForwardError(lastErr) == commonerrors.ClassDatagramDropped) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			overTCP := *upstream
			overTCP.Scheme = dns.UpstreamScheme_TCP
			msg, err := trace.send(ctx, query, &overTCP, target, version, consts.L4ProtoStr_TCP, input, result)
			var terminal *traceDNSTerminal
			if err == nil || stderrors.As(err, &terminal) {
				return msg, err
			}
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = &traceDNSTerminal{reason: "the upstream has no usable address family"}
	}
	return nil, lastErr
}

// send forwards query over one path: the egress verdict for the client, a
// private dialer for that verdict, and the runtime's own forwarder.
func (trace *TraceDNS) send(ctx context.Context, query *dnsmessage.Msg, upstream *dns.Upstream, target netip.AddrPort, ver consts.IpVersionStr, proto consts.L4ProtoStr, input TraceDNSInput, result *TraceDNSResult) (*dnsmessage.Msg, error) {
	egress, err := trace.egress(ctx, input, target, upstream.Hostname, proto)
	if err != nil {
		return nil, &traceDNSTerminal{reason: err.Error()}
	}
	d, cleanup, err := trace.dialerFor(ctx, egress, ver, proto)
	if err != nil {
		return nil, &traceDNSTerminal{reason: err.Error()}
	}
	defer cleanup()
	mark := egress.Mark
	if mark == 0 {
		mark = trace.plane.soMarkFromDae
	}
	argument := dialArgument{
		l4proto: proto, ipversion: ver, bestDialer: d, bestTarget: target,
		mark: mark, mptcp: trace.plane.mptcp,
	}
	forwarder, err := newDnsForwarder(upstream, argument, trace.log)
	if err != nil {
		return nil, &traceDNSTerminal{reason: "upstream transport " + string(proto) + " is not supported for " + string(upstream.Scheme)}
	}
	defer func() { _ = forwarder.Close() }()
	data, err := query.Pack()
	if err != nil {
		return nil, &traceDNSTerminal{reason: "the question could not be encoded"}
	}
	response, err := forwarder.ForwardDNS(ctx, data)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("empty DNS reply")
	}
	if questionlessTerminalReply(response) {
		response.Question = query.Question
	}
	if !response.Response || !questionEchoMatches(query.Question[0], response) {
		return nil, fmt.Errorf("the answer from the upstream does not echo the question")
	}
	result.CarrierTransport = string(proto)
	result.UpstreamTransport = traceUpstreamTransport(upstream.Scheme, proto)
	return response, nil
}

// traceUpstreamTransport names the transport the way the API does: the
// scheme's transport, and for a udp+tcp upstream the one that carried the
// exchange.
func traceUpstreamTransport(scheme dns.UpstreamScheme, proto consts.L4ProtoStr) string {
	switch scheme {
	case dns.UpstreamScheme_TCP, dns.UpstreamScheme_UDP:
		return string(scheme)
	case dns.UpstreamScheme_TCP_UDP:
		return string(proto)
	case dns.UpstreamScheme_TLS:
		return "dot"
	case dns.UpstreamScheme_HTTPS:
		return "doh"
	case dns.UpstreamScheme_QUIC:
		return "doq"
	case dns.UpstreamScheme_H3:
		return "doh3"
	}
	return string(scheme)
}

// traceDNSEgress is the routing verdict for one upstream path.
type traceDNSEgress struct {
	Outbound consts.OutboundIndex
	Mark     uint32
	Name     string
}

// egress routes an upstream query the way the runtime does, by the client's
// source address and packet metadata. A verdict that depends on an input the
// trace does not have is refused: guessing it would name a path the client's
// queries do not take.
func (trace *TraceDNS) egress(ctx context.Context, input TraceDNSInput, target netip.AddrPort, host string, proto consts.L4ProtoStr) (traceDNSEgress, error) {
	plane := trace.plane
	traceInput := RoutingTraceInput{
		Network: proto.ToL4ProtoType(), Domain: &host,
		DstIP: new(target.Addr()), DstPort: target.Port(), Dscp: input.Dscp,
	}
	if input.Src.IsValid() {
		src := input.Src.Addr()
		traceInput.SrcIP = &src
		if port := input.Src.Port(); port != 0 {
			traceInput.SrcPort = &port
		}
	}
	traceInput.Pname = input.Pname
	verdict, err := plane.routingTraceMatcher.TraceEgress(ctx, traceInput, plane.routingRules)
	if err != nil {
		return traceDNSEgress{}, err
	}
	if len(verdict.MissingInputs) > 0 {
		return traceDNSEgress{}, fmt.Errorf("the path to the DNS upstream depends on %s, which the trace does not have", joinTraceInputs(verdict.MissingInputs))
	}
	egress := traceDNSEgress{Outbound: verdict.Outbound, Mark: verdict.Mark, Name: plane.traceOutboundName(verdict.Outbound)}
	if verdict.Outbound == consts.OutboundBlock {
		return traceDNSEgress{}, fmt.Errorf("routing blocks the DNS upstream")
	}
	if verdict.Outbound != consts.OutboundDirect && (int(verdict.Outbound) >= len(plane.outbounds) || plane.outbounds[verdict.Outbound] == nil) {
		return traceDNSEgress{}, fmt.Errorf("routing sends the DNS upstream through %s, which a trace cannot dial", egress.Name)
	}
	if verdict.Outbound == consts.OutboundDirect && trace.reentersListener(target) {
		return traceDNSEgress{}, fmt.Errorf("the DNS upstream is dae's own listener")
	}
	return egress, nil
}

// reentersListener reports whether an upstream is dae's own DNS listener: a
// query sent there would be answered by the runtime, and cached by it. A
// listener bound to a wildcard address owns the port on every address of
// this host, and on nothing else.
func (trace *TraceDNS) reentersListener(target netip.AddrPort) bool {
	if !trace.listener.IsValid() || trace.listener.Port() != target.Port() {
		return false
	}
	if trace.listener.Addr().IsUnspecified() {
		return isLocalAddress(target.Addr())
	}
	return trace.listener.Addr().Unmap().WithZone("") == target.Addr().Unmap()
}

// dialerFor returns a private dialer for a verdict. The direct path uses the
// TraceDNS's own direct dialer; an outbound group selects its node the way
// the runtime would, read-only, and the node is rebuilt from its link so the
// lookup shares none of its state. cleanup releases what the lookup took.
func (trace *TraceDNS) dialerFor(ctx context.Context, egress traceDNSEgress, ver consts.IpVersionStr, proto consts.L4ProtoStr) (*dialer.Dialer, func(), error) {
	if egress.Outbound == consts.OutboundDirect {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		return trace.direct, func() {}, nil
	}
	group := trace.plane.outbounds[egress.Outbound]
	networkType := dialer.NetworkType{
		IsDns: true, UdpHealthDomain: dialer.UdpHealthDomainDns,
		L4Proto: proto, IpVersion: ver,
	}
	selected, _, err := group.Select(&networkType, true)
	if err != nil || selected == nil || selected.Property() == nil {
		return nil, nil, fmt.Errorf("outbound %s has no node to carry the DNS upstream", egress.Name)
	}
	property := selected.Property()
	if property.Link == "" {
		return nil, nil, fmt.Errorf("the node outbound %s selected cannot be rebuilt for a trace", egress.Name)
	}
	private, err := dialer.NewFromLinkWithProxyCacheContext(ctx, trace.plane.traceDnsOption,
		dialer.InstanceOption{DisableCheck: true}, property.Link, property.SubscriptionTag, dialer.NewProxyIpCache())
	if err != nil {
		return nil, nil, fmt.Errorf("the node outbound %s selected cannot be rebuilt for a trace", egress.Name)
	}
	return private, func() { _ = private.Close() }, nil
}

// traceDNSListener returns the address dae's DNS listener is bound to.
func traceDNSListener(cfg *config.Dns) (netip.AddrPort, error) {
	if cfg.Bind == "" {
		return netip.AddrPort{}, nil
	}
	endpoint, err := ParseEndpoint(cfg.Bind)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("DNS listener endpoint cannot be verified: %w", err)
	}
	listener, err := parseDNSListenerAddrPort(endpoint.Addr, false)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("DNS listener address cannot be verified: %w", err)
	}
	return listener, nil
}

func joinTraceInputs(inputs []string) string {
	switch len(inputs) {
	case 0:
		return ""
	case 1:
		return inputs[0]
	}
	return strings.Join(inputs[:len(inputs)-1], ", ") + " and " + inputs[len(inputs)-1]
}

// isLocalAddress reports whether the host itself owns address.
func isLocalAddress(address netip.Addr) bool {
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return true // unknown: keep the strict reading
	}
	for _, iface := range interfaces {
		if ipNet, ok := iface.(*net.IPNet); ok {
			if prefix, ok := netip.AddrFromSlice(ipNet.IP); ok {
				if prefix.Unmap() == address.Unmap() {
					return true
				}
			}
		}
	}
	return false
}

func quietTraceLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}

// traceOutboundName names an outbound for a trace reason: the configured
// name when the generation has it, its index otherwise.
func (c *ControlPlane) traceOutboundName(index consts.OutboundIndex) string {
	if int(index) < len(c.outbounds) && c.outbounds[index] != nil {
		return c.outbounds[index].Name
	}
	return fmt.Sprintf("outbound %d", index)
}
