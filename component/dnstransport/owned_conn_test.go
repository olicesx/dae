/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dnstransport

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/congestion"
)

type ownedPacketCloser struct {
	closed atomic.Int32
}

func (c *ownedPacketCloser) Close() error {
	c.closed.Add(1)
	return nil
}

type stubEarlyConn struct {
	closed atomic.Int32
}

func (c *stubEarlyConn) AcceptStream(context.Context) (quic.Stream, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) AcceptUniStream(context.Context) (quic.ReceiveStream, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) OpenStream() (quic.Stream, error) { return nil, net.ErrClosed }
func (c *stubEarlyConn) OpenStreamSync(context.Context) (quic.Stream, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) OpenUniStream() (quic.SendStream, error) { return nil, net.ErrClosed }
func (c *stubEarlyConn) OpenUniStreamSync(context.Context) (quic.SendStream, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (c *stubEarlyConn) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (c *stubEarlyConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closed.Add(1)
	return nil
}
func (c *stubEarlyConn) Context() context.Context { return context.Background() }
func (c *stubEarlyConn) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}
func (c *stubEarlyConn) SendDatagram([]byte) error { return nil }
func (c *stubEarlyConn) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) ReleaseDatagram([]byte)                            {}
func (c *stubEarlyConn) SetCongestionControl(congestion.CongestionControl) {}
func (c *stubEarlyConn) HandshakeComplete() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
func (c *stubEarlyConn) NextConnection(context.Context) (quic.Connection, error) {
	return nil, net.ErrClosed
}

func TestOwnedEarlyConnCloseClosesPacketConnOnce(t *testing.T) {
	t.Parallel()

	packet := &ownedPacketCloser{}
	qc := &stubEarlyConn{}
	owned := OwnEarlyConnection(qc, packet)
	if err := owned.CloseWithError(0, ""); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}
	if err := owned.CloseWithError(0, "again"); err != nil {
		t.Fatalf("second CloseWithError: %v", err)
	}
	if got := packet.closed.Load(); got != 1 {
		t.Fatalf("packet Close count = %d, want 1", got)
	}
	if got := qc.closed.Load(); got != 1 {
		t.Fatalf("quic CloseWithError count = %d, want 1", got)
	}
}

var (
	_ io.Closer            = (*ownedPacketCloser)(nil)
	_ quic.EarlyConnection = (*stubEarlyConn)(nil)
)
