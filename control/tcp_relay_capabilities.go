/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
)

type relaySegmentSource interface {
	TakeRelaySegments() [][]byte
}

type relayContinuationSource interface {
	// CopyRelayRemainder receives the owning relay's ctx so long-running
	// fast paths inside implementers observe cancellation instead of
	// outliving the flow.
	CopyRelayRemainder(ctx context.Context, dst io.Writer, buf []byte, record func(int64), onActive func(int64)) (int64, error)
}

type relayPrefixSource interface {
	TakeRelayPrefix() []byte
}

// The relay capability interfaces are satisfied structurally, so a signature
// drift in an implementer is not a compile error on its own — it just makes
// the type assertion fail and silently changes which relay path runs. These
// assertions pin the intended set of implementers.
//
// sniffing.ConnSniffer is intentionally absent from relayContinuationSource:
// its remainder must be read through Sniffer.Read, so it stays on
// relayCopyLoop. See ConnSniffer.CopyRelayRemainder.
var (
	_ relaySegmentSource      = (*sniffing.ConnSniffer)(nil)
	_ relayPrefixSource       = (*sniffing.ConnSniffer)(nil)
	_ relaySegmentSource      = (*bufioConn)(nil)
	_ relayContinuationSource = (*bufioConn)(nil)
	_ relayPrefixSource       = (*bufioConn)(nil)
	_ relaySegmentSource      = (*prefixedConn)(nil)
	_ relayContinuationSource = (*prefixedConn)(nil)
	_ relayPrefixSource       = (*prefixedConn)(nil)
)

// unwrapRelayTransparentTCPConn resolves conn to a TCP socket only when
// every wrapper in between passes bytes through unmodified. Conns that
// transform the byte stream (protocol framing, TLS encryption, QUIC
// streams, read buffering) advertise themselves through the fork's
// capability interfaces; once any transforming layer is seen the chain is
// not splice- or writev-safe and the walk reports failure. Callers that
// only observe socket state (pending-byte probes, socket options) use
// unwrapRelayTCPConn instead: peeling through a transforming conn is safe
// for observation and unsafe for data movement.
func unwrapRelayTransparentTCPConn(conn any) (*net.TCPConn, bool) {
	for range relayConnChainMaxDepth {
		if conn == nil {
			return nil, false
		}
		switch c := conn.(type) {
		case *net.TCPConn:
			return c, true
		case *prefixedConn:
			conn = c.Conn
		case *sniffing.ConnSniffer:
			if tcpConn, ok := c.UnwrapTCPConn(); ok {
				return tcpConn, true
			}
			conn = c.Conn
		case netproxy.ReadBufferer, netproxy.IntrinsicConnProvider:
			return nil, false
		case netproxy.UnderlyingConnProvider:
			conn = c.UnderlyingConn()
		default:
			return nil, false
		}
	}
	return nil, false
}

const relayConnChainMaxDepth = 8

// unwrapRelayTCPConn resolves transparent wrappers down to a concrete TCP
// socket. Generic wrapper traversal is delegated to outbound/netproxy's
// UnwrapTCPConn so dae stays aligned with wrapper capabilities added there,
// while prefixedConn remains a dae-local relay wrapper that must be peeled
// explicitly.
//
// Iterative implementation reduces function call overhead and improves CPU
// branch prediction compared to the previous recursive approach.
func unwrapRelayTCPConn(conn any) (*net.TCPConn, bool) {
	for range relayConnChainMaxDepth {
		if conn == nil {
			return nil, false
		}

		switch c := conn.(type) {
		case *net.TCPConn:
			return c, true
		case *prefixedConn:
			conn = c.Conn
		case *sniffing.ConnSniffer:
			// ConnSniffer now supports UnwrapTCPConn for splice after sniffing.
			if tcpConn, ok := c.UnwrapTCPConn(); ok {
				return tcpConn, true
			}
			conn = c.Conn
		case netproxy.UnderlyingConnProvider:
			if tcpConn, ok := netproxy.UnwrapTCPConn(c); ok {
				return tcpConn, true
			}
			conn = c.UnderlyingConn()
		default:
			return netproxy.UnwrapTCPConn(conn)
		}
	}
	return nil, false
}
