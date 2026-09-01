/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/dnstransport"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	tc "github.com/daeuniverse/outbound/protocol/tuic/common"
	dnsmessage "github.com/miekg/dns"
	"github.com/olicesx/quic-go"
)

var errInternalDNSTruncated = fmt.Errorf("internal dns response truncated")
var errPassthroughToBaseResolver = errors.New("dns request routing selected passthrough resolver")

var udpDNSBufPool = sync.Pool{
	// Keep the full UDP DNS payload budget so oversized replies still unpack
	// correctly instead of failing before TCP fallback decisions are made.
	// Buffers are stored as *[]byte so Put hands the pool a pointer instead
	// of boxing the slice header on every Put (SA6002).
	New: func() any {
		buf := make([]byte, 65535)
		return &buf
	},
}

const lookupSharedTimeout = 10 * time.Second

type httpDNSQueryFunc func(context.Context, *http.Client, string, *componentdns.Upstream, []byte) (*dnsmessage.Msg, error)
type httpTransportFactoryFunc func(*Router, *componentdns.Upstream, netip.AddrPort, bool) http.RoundTripper

func (r *Router) selectUpstream(ctx context.Context, upstreamName, host string, qtype uint16) (*componentdns.Upstream, error) {
	if upstreamName != "" {
		upstreamResolver, ok := r.upstreams[upstreamName]
		if !ok {
			return nil, fmt.Errorf("dns upstream %q not found", upstreamName)
		}
		return upstreamResolver.GetUpstream(ctx)
	}
	if r.requestMatcher == nil {
		return nil, fmt.Errorf("dns request routing is not configured for %q", host)
	}
	upstreamIndex, err := r.requestMatcher.Match(dnsmessage.CanonicalName(host), qtype)
	if err != nil {
		return nil, err
	}
	switch upstreamIndex {
	case consts.DnsRequestOutboundIndex_AsIs, consts.DnsRequestOutboundIndex_Reject:
		return nil, errPassthroughToBaseResolver
	}
	if int(upstreamIndex) < 0 || int(upstreamIndex) >= len(r.upstreamByIndex) {
		return nil, fmt.Errorf("dns request routing selected unsupported action %q for %q", upstreamIndex.String(), host)
	}
	return r.upstreamByIndex[upstreamIndex].GetUpstream(ctx)
}

func (r *Router) LookupIPAddr(ctx context.Context, upstreamName string, network string, host string) ([]net.IPAddr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		ip := net.IP(addr.AsSlice())
		return []net.IPAddr{{IP: ip}}, nil
	}

	var qtypes []uint16
	switch requestedIPVersion(network) {
	case "4":
		qtypes = []uint16{dnsmessage.TypeA}
	case "6":
		qtypes = []uint16{dnsmessage.TypeAAAA}
	default:
		qtypes = []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	}

	addrs := make([]net.IPAddr, 0, 2)
	var firstErr error
	sawPassthrough := false
	for _, qtype := range qtypes {
		upstream, lookupErr := r.selectUpstream(ctx, upstreamName, host, qtype)
		if lookupErr != nil {
			if errors.Is(lookupErr, errPassthroughToBaseResolver) {
				sawPassthrough = true
				continue
			}
			if firstErr == nil {
				firstErr = lookupErr
			}
			continue
		}
		ips, lookupErr := r.lookupTypeDedup(ctx, upstream, host, qtype)
		if lookupErr != nil {
			if firstErr == nil {
				firstErr = lookupErr
			}
			continue
		}
		addrs = append(addrs, ips...)
	}
	if len(addrs) == 0 {
		if sawPassthrough {
			return nil, errPassthroughToBaseResolver
		}
		if firstErr != nil {
			return nil, firstErr
		}
	}
	return addrs, nil
}

func lookupTypeDedupKey(upstream *componentdns.Upstream, host string, qtype uint16) string {
	return fmt.Sprintf("%s\x00%s\x00%d", upstream.String(), host, qtype)
}

func (r *Router) lookupTypeDedup(ctx context.Context, upstream *componentdns.Upstream, host string, qtype uint16) ([]net.IPAddr, error) {
	key := lookupTypeDedupKey(upstream, host, qtype)
	call := r.getOrCreateLookupCall(key, upstream, host, qtype)
	defer r.releaseLookupCall(key, call)

	select {
	case <-call.done:
		return call.res, call.err
	default:
	}

	select {
	case <-call.done:
		return call.res, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *Router) getOrCreateLookupCall(key string, upstream *componentdns.Upstream, host string, qtype uint16) *lookupCall {
	r.lookupMu.Lock()
	if call, ok := r.lookupCalls[key]; ok {
		call.waiters++
		r.lookupMu.Unlock()
		return call
	}

	lookupCtx, cancel := context.WithTimeout(context.Background(), lookupSharedTimeout)
	call := &lookupCall{
		waiters: 1,
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	r.lookupCalls[key] = call
	r.lookupMu.Unlock()

	go func() {
		call.res, call.err = r.lookupType(lookupCtx, upstream, host, qtype)
		close(call.done)
		cancel()

		r.lookupMu.Lock()
		if current := r.lookupCalls[key]; current == call {
			delete(r.lookupCalls, key)
		}
		r.lookupMu.Unlock()
	}()

	return call
}

func (r *Router) releaseLookupCall(key string, call *lookupCall) {
	r.lookupMu.Lock()
	defer r.lookupMu.Unlock()

	if call.waiters == 0 {
		return
	}
	call.waiters--
	if call.waiters != 0 {
		return
	}

	select {
	case <-call.done:
		return
	default:
		if current := r.lookupCalls[key]; current == call {
			delete(r.lookupCalls, key)
		}
		call.cancel()
	}
}

type deadlineCloser interface {
	Close() error
	SetDeadline(time.Time) error
}

// interruptConnOnCancel installs a cancellation hook that forcefully
// interrupts blocking I/O on conn. Callers should defer the returned stop
// function immediately after a successful dial so the hook is unregistered on
// the normal completion path.
func interruptConnOnCancel(ctx context.Context, conn deadlineCloser) func() {
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
	})
	return func() {
		_ = stop()
	}
}

// interruptQUICConnOnCancel installs a cancellation hook that forcefully
// interrupts blocking QUIC operations. Callers should defer the returned stop
// function immediately after a successful dial so the hook is unregistered on
// the normal completion path.
func interruptQUICConnOnCancel(ctx context.Context, conn quic.EarlyConnection) func() {
	stop := context.AfterFunc(ctx, func() {
		_ = conn.CloseWithError(0, "")
	})
	return func() {
		_ = stop()
	}
}

func (r *Router) lookupType(ctx context.Context, upstream *componentdns.Upstream, host string, qtype uint16) ([]net.IPAddr, error) {
	msg := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:               uint16(fastrand.Intn(1 << 16)),
			Response:         false,
			Opcode:           0,
			Truncated:        false,
			RecursionDesired: true,
			Authoritative:    false,
		},
	}
	msg.SetQuestion(dnsmessage.CanonicalName(host), qtype)
	// Pack into the pooled buffer instead of allocating per query.
	// r.exchange consumes data synchronously across every scheme
	// (queryUDP writes inline; queryTCP/TLS/QUIC/HTTPS copy data before use),
	// so recycling buf after exchange returns is safe.
	poolBuf := udpDNSBufPool.Get().(*[]byte)
	defer udpDNSBufPool.Put(poolBuf)
	data, err := msg.PackBuffer((*poolBuf)[:cap(*poolBuf)])
	if err != nil {
		return nil, err
	}

	resp, err := r.exchange(ctx, upstream, data)
	if err != nil {
		return nil, err
	}
	addrs := make([]net.IPAddr, 0, 2)
	for _, ans := range resp.Answer {
		switch qtype {
		case dnsmessage.TypeA:
			a, ok := ans.(*dnsmessage.A)
			if !ok {
				continue
			}
			addrs = append(addrs, net.IPAddr{IP: a.A[:]})
		case dnsmessage.TypeAAAA:
			aaaa, ok := ans.(*dnsmessage.AAAA)
			if !ok {
				continue
			}
			addrs = append(addrs, net.IPAddr{IP: aaaa.AAAA[:]})
		}
	}
	return addrs, nil
}

func (r *Router) exchange(ctx context.Context, upstream *componentdns.Upstream, data []byte) (*dnsmessage.Msg, error) {
	targets := upstreamTargets(upstream)
	if len(targets) == 0 {
		return nil, fmt.Errorf("dns upstream %q has no usable address", upstream.String())
	}

	var firstErr error
	for _, target := range targets {
		msg, err := r.exchangeTarget(ctx, upstream, target, data)
		if err == nil {
			return msg, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("failed to query upstream %q", upstream.String())
	}
	return nil, firstErr
}

func (r *Router) exchangeTarget(ctx context.Context, upstream *componentdns.Upstream, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	switch upstream.Scheme {
	case componentdns.UpstreamScheme_UDP:
		return r.queryUDP(ctx, target, data)
	case componentdns.UpstreamScheme_TCP:
		return r.queryTCP(ctx, target, data)
	case componentdns.UpstreamScheme_TCP_UDP:
		msg, err := r.queryUDP(ctx, target, data)
		if err == nil {
			return msg, nil
		}
		if err != errInternalDNSTruncated {
			msg, tcpErr := r.queryTCP(ctx, target, data)
			if tcpErr == nil {
				return msg, nil
			}
			return nil, fmt.Errorf("udp query failed: %w; tcp fallback failed: %v", err, tcpErr)
		}
		return r.queryTCP(ctx, target, data)
	case componentdns.UpstreamScheme_TLS:
		return r.queryTLS(ctx, upstream, target, data)
	case componentdns.UpstreamScheme_HTTPS:
		return r.queryHTTPS(ctx, upstream, target, data, false)
	case componentdns.UpstreamScheme_H3:
		return r.queryHTTPS(ctx, upstream, target, data, true)
	case componentdns.UpstreamScheme_QUIC:
		return r.queryQUIC(ctx, upstream, target, data)
	default:
		return nil, fmt.Errorf("unsupported upstream scheme: %v", upstream.Scheme)
	}
}

func (r *Router) queryUDP(ctx context.Context, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	conn, err := r.directDialer.DialContext(ctx, common.MagicNetwork("udp", r.soMark, r.mptcp), target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	defer interruptConnOnCancel(ctx, conn)()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	originalID := binary.BigEndian.Uint16(data[:2])
	if _, err = netutils.WriteUDPConn(conn, target.String(), data); err != nil {
		return nil, err
	}
	bufPtr := udpDNSBufPool.Get().(*[]byte)
	defer udpDNSBufPool.Put(bufPtr)
	buf := *bufPtr
	for range 8 {
		n, readErr := netutils.ReadUDPConn(conn, buf)
		if readErr != nil {
			return nil, readErr
		}
		if n < 2 || binary.BigEndian.Uint16(buf[:2]) != originalID {
			continue
		}
		var msg dnsmessage.Msg
		if err = msg.Unpack(buf[:n]); err != nil {
			return nil, err
		}
		if msg.Truncated {
			return nil, errInternalDNSTruncated
		}
		return &msg, nil
	}
	return nil, fmt.Errorf("too many stale UDP DNS responses")
}

func (r *Router) queryTCP(ctx context.Context, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	conn, err := r.directDialer.DialContext(ctx, common.MagicNetwork("tcp", r.soMark, r.mptcp), target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	defer interruptConnOnCancel(ctx, conn)()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return dnstransport.SendStreamDNS(conn, data)
}

func (r *Router) queryTLS(ctx context.Context, upstream *componentdns.Upstream, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	conn, err := r.directDialer.DialContext(ctx, common.MagicNetwork("tcp", r.soMark, r.mptcp), target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	tlsConn := tls.Client(&netproxy.FakeNetConn{Conn: conn}, &tls.Config{
		ServerName:         upstream.Hostname,
		InsecureSkipVerify: false,
	})
	defer interruptConnOnCancel(ctx, tlsConn)()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err = tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return dnstransport.SendStreamDNS(tlsConn, data)
}

func (r *Router) sendHTTPQuery(ctx context.Context, client *http.Client, target string, upstream *componentdns.Upstream, data []byte) (*dnsmessage.Msg, error) {
	if r.httpSendFunc != nil {
		return r.httpSendFunc(ctx, client, target, upstream, data)
	}
	return dnstransport.SendHTTPDNS(ctx, client, target, upstream, data)
}

func (r *Router) queryHTTPS(ctx context.Context, upstream *componentdns.Upstream, target netip.AddrPort, data []byte, http3Mode bool) (*dnsmessage.Msg, error) {
	generation := r.getOrCreateHTTPClient(upstream, target, http3Mode)
	if generation == nil {
		return nil, net.ErrClosed
	}
	defer func() { r.releaseHTTPClient(generation) }()

	msg, err := r.sendHTTPQuery(ctx, generation.Client, target.String(), upstream, data)
	if err == nil || ctx.Err() != nil || !dnstransport.ShouldReplaceHTTPClient(err) {
		return msg, err
	}

	next := r.replaceHTTPClient(generation, upstream, target, http3Mode)
	previous := generation
	generation = next
	r.releaseHTTPClient(previous)
	if generation == nil {
		return nil, net.ErrClosed
	}
	return r.sendHTTPQuery(ctx, generation.Client, target.String(), upstream, data)
}

func (r *Router) newHTTPTransport(upstream *componentdns.Upstream, target netip.AddrPort, http3Mode bool) http.RoundTripper {
	if http3Mode {
		return dnstransport.NewHTTP3Transport(upstream.Hostname, func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			return dnstransport.DialEarlyOwned(ctx, func(ctx context.Context) (netproxy.Conn, error) {
				return r.directDialer.DialContext(ctx, common.MagicNetwork("udp", r.soMark, r.mptcp), target.String())
			}, target, tlsCfg, cfg)
		})
	}

	return dnstransport.NewHTTPTransport(upstream.Hostname, func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := r.directDialer.DialContext(ctx, common.MagicNetwork("tcp", r.soMark, r.mptcp), target.String())
		if err != nil {
			return nil, err
		}
		return &netproxy.FakeNetConn{Conn: conn}, nil
	})
}

func (r *Router) queryQUIC(ctx context.Context, upstream *componentdns.Upstream, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	conn, err := r.directDialer.DialContext(ctx, common.MagicNetwork("udp", r.soMark, r.mptcp), target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	udpAddr := net.UDPAddrFromAddrPort(target)
	fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         upstream.Hostname,
	}
	qc, err := quic.DialEarly(ctx, fakePkt, udpAddr, tlsCfg, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = qc.CloseWithError(0, "") }()
	defer interruptQUICConnOnCancel(ctx, qc)()

	stream, err := qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = stream.Close() }()

	wire := append([]byte(nil), data...)
	binary.BigEndian.PutUint16(wire[:2], 0)
	return dnstransport.SendStreamDNS(stream, wire)
}

func upstreamTargets(upstream *componentdns.Upstream) []netip.AddrPort {
	targets := make([]netip.AddrPort, 0, 2)
	if upstream.Ip4.IsValid() {
		targets = append(targets, netip.AddrPortFrom(upstream.Ip4, upstream.Port))
	}
	if upstream.Ip6.IsValid() {
		targets = append(targets, netip.AddrPortFrom(upstream.Ip6, upstream.Port))
	}
	return targets
}

func requestedIPVersion(network string) string {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err == nil && magicNetwork.IPVersion != "" {
		return magicNetwork.IPVersion
	}
	switch network {
	case "tcp4", "udp4":
		return "4"
	case "tcp6", "udp6":
		return "6"
	default:
		return ""
	}
}
