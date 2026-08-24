/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/olicesx/quic-go"
)

// ownedEarlyConn pairs a package-level quic.DialEarly result with the
// caller-owned PacketConn that quic-go will not close.
type ownedEarlyConn struct {
	quic.EarlyConnection
	packetConn io.Closer
	closeOnce  sync.Once
	closeErr   error
}

func ownEarlyConnection(qc quic.EarlyConnection, packetConn io.Closer) quic.EarlyConnection {
	if qc == nil || packetConn == nil {
		return qc
	}
	return &ownedEarlyConn{EarlyConnection: qc, packetConn: packetConn}
}

func (c *ownedEarlyConn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	c.closeOnce.Do(func() {
		c.closeErr = c.EarlyConnection.CloseWithError(code, reason)
		if err := c.packetConn.Close(); err != nil && c.closeErr == nil && !isBenignConnCloseError(err) {
			c.closeErr = err
		}
	})
	return c.closeErr
}

func isBenignConnCloseError(err error) bool {
	return err == nil || stderrors.Is(err, net.ErrClosed) || stderrors.Is(err, io.EOF)
}

func shouldReplaceHTTPClient(err error) bool {
	var urlErr *url.Error
	if stderrors.As(err, &urlErr) && urlErr.Err != nil {
		err = urlErr.Err
	}
	if stderrors.Is(err, net.ErrClosed) || stderrors.Is(err, io.EOF) || stderrors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	return stderrors.As(err, &netErr)
}

func closeHTTPClient(client *http.Client) {
	if client == nil {
		return
	}
	client.CloseIdleConnections()
	if closer, ok := client.Transport.(io.Closer); ok {
		_ = closer.Close()
	}
}
