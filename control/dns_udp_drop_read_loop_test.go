/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/outbound/protocol"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// These tests pin the read-error decision order of the DoUDP response wait
// loop. Half the datagram-drop family (the ErrDomainResolution leg) unwraps to
// a *net.DNSError timeout, so the drop classification must run before the
// timeout branches: a timeout-cause drop is still a per-datagram event, and
// the stale cap that bounds the wait must keep the drop cause so the failure
// policy and the UDP-over-TCP upgrade key off it.

// newDropTimeoutError builds an error that is simultaneously drop-classified
// (it wraps protocol.ErrDomainResolution, exactly how the fork's
// DomainIpMapping reports a failed peer-domain resolution) and a net.Error
// timeout (a *net.DNSError with IsTimeout, which Go's resolver returns when
// the lookup context expires).
func newDropTimeoutError() error {
	inner := &net.DNSError{Err: "i/o timeout", Name: "peer.example", IsTimeout: true, IsTemporary: true}
	return fmt.Errorf("%w: peer.example: %w", protocol.ErrDomainResolution, inner)
}

// TestDoUDPDropWithTimeoutCauseKeepsWaitingForReply: one drop whose cause is a
// resolver timeout must not terminate the wait; the reply that follows on the
// same conn is delivered.
func TestDoUDPDropWithTimeoutCauseKeepsWaitingForReply(t *testing.T) {
	dialed := netip.MustParseAddrPort("198.51.100.53:53")
	reply := dnsAResponseMsg("drop-timeout.test.", "203.0.113.10")
	reply.Id = 0x7102
	wire, err := reply.Pack()
	if err != nil {
		t.Fatalf("pack reply: %v", err)
	}

	dropErr := newDropTimeoutError()
	if commonerrors.ClassifyForwardError(dropErr) != commonerrors.ClassDatagramDropped {
		t.Fatalf("fixture sanity: drop error class = %v, want ClassDatagramDropped",
			commonerrors.ClassifyForwardError(dropErr))
	}
	if netErr, ok := errors.AsType[net.Error](dropErr); !ok || !netErr.Timeout() {
		t.Fatalf("fixture sanity: drop error must also unwrap to a net.Error timeout")
	}

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 2),
		closeCh: make(chan struct{}),
	}
	conn.reads <- scriptedPacketRead{err: dropErr}
	conn.reads <- scriptedPacketRead{data: wire, from: dialed}
	t.Cleanup(func() { _ = conn.Close() })

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	dial := &DoUDP{
		dialArgument: dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestDialer: newTestEndpointDialer(conn),
			bestTarget: dialed,
		},
		log: logger,
	}
	t.Cleanup(func() { _ = dial.Close() })

	query := new(dnsmessage.Msg)
	query.SetQuestion("drop-timeout.test.", dnsmessage.TypeA)
	query.Id = 0x7102
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	msg, err := dial.ForwardDNS(t.Context(), queryWire)
	if err != nil {
		t.Fatalf("ForwardDNS: %v (a timeout-cause drop must keep waiting for the reply)", err)
	}
	if msg == nil || msg.Id != 0x7102 {
		t.Fatalf("ForwardDNS returned %#v, want the reply with id 0x7102", msg)
	}
}

// TestDoUDPStaleDropCapErrorKeepsDropCause: when the stale cap ends the wait,
// the returned error still carries the drop cause, so the forwarder policy
// keeps treating it as a per-datagram event and the udp:// TCP upgrade (whose
// trigger is exactly this classification) still applies. The drop here wraps
// io.ErrShortBuffer (no net.Error in the chain) so the wait loop reaches the
// cap through the drop branch on both the old and the new decision order.
func TestDoUDPStaleDropCapErrorKeepsDropCause(t *testing.T) {
	dialed := netip.MustParseAddrPort("198.51.100.53:53")
	dropErr := fmt.Errorf("read udp: %w", io.ErrShortBuffer)
	if commonerrors.ClassifyForwardError(dropErr) != commonerrors.ClassDatagramDropped {
		t.Fatalf("fixture sanity: short-buffer error class = %v, want ClassDatagramDropped",
			commonerrors.ClassifyForwardError(dropErr))
	}

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 16),
		closeCh: make(chan struct{}),
	}
	// maxStaleResponses is 8: the ninth drop ends the wait.
	for range 9 {
		conn.reads <- scriptedPacketRead{err: dropErr}
	}
	t.Cleanup(func() { _ = conn.Close() })

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	dial := &DoUDP{
		dialArgument: dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestDialer: newTestEndpointDialer(conn),
			bestTarget: dialed,
		},
		log: logger,
	}
	t.Cleanup(func() { _ = dial.Close() })

	query := new(dnsmessage.Msg)
	query.SetQuestion("drop-cap.test.", dnsmessage.TypeA)
	query.Id = 0x7103
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	_, err = dial.ForwardDNS(t.Context(), queryWire)
	if err == nil {
		t.Fatal("ForwardDNS unexpectedly succeeded with nine consecutive drops")
	}
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("cap error = %v, want it to keep the drop cause (errors.Is io.ErrShortBuffer)", err)
	}
	if class := classifyDnsForwardError(err); class != commonerrors.ClassDatagramDropped {
		t.Fatalf("cap error class = %v, want ClassDatagramDropped (per-datagram policy and the TCP upgrade key off this class)", class)
	}
}
