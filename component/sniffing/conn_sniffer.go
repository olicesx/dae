/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type ConnSniffer struct {
	// log defaults to the standard logger; callers owning a configured
	// control-plane logger should inject it via NewConnSniffer.
	log *logrus.Logger
	net.Conn
	*Sniffer
}

func NewConnSniffer(conn net.Conn, timeout time.Duration, log ...*logrus.Logger) *ConnSniffer {
	s := &ConnSniffer{
		Conn:    conn,
		Sniffer: NewStreamSniffer(conn, timeout),
	}
	if len(log) > 0 && log[0] != nil {
		s.log = log[0]
	} else {
		s.log = logrus.StandardLogger()
	}
	return s
}

// UnderlyingConn returns the wrapped net.Conn before sniffing.
// Use this instead of accessing the embedded field directly so that
// call-sites remain correct if ConnSniffer's internals are refactored.
func (s *ConnSniffer) UnderlyingConn() net.Conn { return s.Conn }

func (s *ConnSniffer) Read(p []byte) (n int, err error) {
	return s.Sniffer.Read(p)
}

func (s *ConnSniffer) TakeRelaySegments() [][]byte {
	prefix := s.TakeRelayPrefix()
	if len(prefix) == 0 {
		return nil
	}
	return [][]byte{prefix}
}

// TakeRelayPrefix returns buffered sniff bytes and marks them consumed so the
// relay path can flush them directly to the destination socket.
//
// The returned slice is only safe for immediate synchronous use by the relay
// goroutine before the next read or write on this ConnSniffer.
func (s *ConnSniffer) TakeRelayPrefix() []byte {
	if s.Sniffer == nil {
		return nil
	}
	// Relay runs strictly after sniffing completed synchronously in
	// handleConn, so dataReady is normally already closed here and the
	// receive below returns immediately. If it is NOT closed (abnormal
	// sniff state), waiting would block the relay direction forever and
	// leak the whole relayCore (observed: 522 leaked relayCores after a
	// reconnect storm, ~2k goroutines). Skip the wait, log the abnormal
	// state once for root-cause diagnostics, and let relay proceed with
	// whatever is already buffered.
	select {
	case <-s.dataReady:
	default:
		s.log.Warn("TakeRelayPrefix: dataReady not closed (abnormal sniff state); skipping wait to avoid relay deadlock")
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.buf == nil || s.buf.Len() == 0 {
		return nil
	}
	return s.buf.Next(s.buf.Len())
}

func (s *ConnSniffer) Close() (err error) {
	var errs []string
	if err = s.Sniffer.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if err = s.Conn.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// UnwrapTCPConn returns the underlying *net.TCPConn if available.
// This allows the relay code to use splice(2) after sniffing is complete.
func (s *ConnSniffer) UnwrapTCPConn() (*net.TCPConn, bool) {
	if s == nil || s.Conn == nil {
		return nil, false
	}
	// Directly check if the underlying connection is a TCP conn
	if tcpConn, ok := s.Conn.(*net.TCPConn); ok {
		return tcpConn, true
	}
	// Check for nested wrappers
	type underlyingConnProvider interface {
		UnwrapTCPConn() (*net.TCPConn, bool)
	}
	if ucp, ok := s.Conn.(underlyingConnProvider); ok {
		return ucp.UnwrapTCPConn()
	}
	return nil, false
}
