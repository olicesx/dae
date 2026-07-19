/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"context"
	"encoding/binary"
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestTCPDNSSessionUsesSuccessorControllerAfterGenerationRetirement(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	oldController := newPhase0TCPIngressDnsController(t)
	newController := newPhase0TCPIngressDnsController(t)
	const (
		queryName = "persistent-dns.reload.test."
		oldIP     = "198.51.100.10"
		newIP     = "198.51.100.20"
	)

	previousFactory := dnsForwarderFactory
	var oldQueries atomic.Int32
	dnsForwarderFactory = func(_ *componentdns.Upstream, _ dialArgument, log *logrus.Logger) (DnsForwarder, error) {
		address := oldIP
		isOld := true
		if log == newController.log {
			address = newIP
			isOld = false
		}
		return &stubDnsForwarder{forward: func(_ context.Context, wire []byte) (*dnsmessage.Msg, error) {
			if isOld && oldQueries.Add(1) == 1 {
				return nil, stderrors.New("injected transient DNS failure")
			}
			var query dnsmessage.Msg
			if err := query.Unpack(wire); err != nil {
				return nil, err
			}
			return dnsAResponseMsg(query.Question[0].Name, address), nil
		}}, nil
	}
	t.Cleanup(func() { dnsForwarderFactory = previousFactory })

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	oldCtx, cancelOld := context.WithCancel(context.Background())
	defer cancelOld()
	oldPlane := &ControlPlane{
		log:          logger,
		ctx:          oldCtx,
		drainTracker: newControlPlaneDrainTracker(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: oldController,
		},
	}
	newPlane := &ControlPlane{
		log: logger,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: newController,
		},
	}
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	if err := oldPlane.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(old) error = %v", err)
	}
	if err := newPlane.AttachSessionManager(manager); err != nil {
		t.Fatalf("AttachSessionManager(new) error = %v", err)
	}
	oldPlane.publishActiveControlPlane()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	ownership, ok := oldPlane.acquireIncomingConnectionLease(serverConn)
	if !ok {
		t.Fatal("acquireIncomingConnectionLease() = false")
	}
	resultCh := make(chan tcpDnsIngressResult, 1)
	go func() {
		handled, err := oldPlane.handleTCPDnsFastPathOwned(
			oldCtx,
			serverConn,
			bufio.NewReader(serverConn),
			netip.MustParseAddrPort("192.0.2.10:42424"),
			netip.MustParseAddrPort("198.51.100.53:53"),
			&bpfRoutingResult{},
			ownership,
		)
		resultCh <- tcpDnsIngressResult{handled: handled, err: err}
	}()

	failed := exchangeTCPDNSQuery(t, clientConn, queryName, 1)
	if failed.Rcode != dnsmessage.RcodeServerFailure {
		t.Fatalf("first response rcode = %d, want SERVFAIL", failed.Rcode)
	}
	first := exchangeTCPDNSQuery(t, clientConn, queryName, 2)
	if got := dnsAnswerIPv4(t, first); got != oldIP {
		t.Fatalf("first response address = %s, want %s", got, oldIP)
	}
	if manager.ActiveTCPConnections() != 1 {
		t.Fatalf("active process TCP flows = %d, want 1", manager.ActiveTCPConnections())
	}
	if oldPlane.ActiveSessionCount() != 0 {
		t.Fatalf("old generation active sessions = %d, want 0", oldPlane.ActiveSessionCount())
	}

	cancelOld()
	newPlane.publishActiveControlPlane()
	if err := oldController.Close(); err != nil {
		t.Fatalf("old DNS controller Close() error = %v", err)
	}
	second := exchangeTCPDNSQuery(t, clientConn, queryName, 3)
	if got := dnsAnswerIPv4(t, second); got != newIP {
		t.Fatalf("second response address = %s, want %s", got, newIP)
	}

	if err := manager.Close(); err != nil {
		t.Fatalf("SessionManager.Close() error = %v", err)
	}
	select {
	case result := <-resultCh:
		if result.err != nil || !result.handled {
			t.Fatalf("handleTCPDnsFastPathOwned() = (%v, %v), want handled", result.handled, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("persistent TCP DNS handler did not stop after client close")
	}
	if manager.ActiveTCPConnections() != 0 {
		t.Fatalf("active process TCP flows after close = %d, want 0", manager.ActiveTCPConnections())
	}
}

func TestTCPDNSResponseFirstFrameIsHandledWithoutFallback(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	query := new(dnsmessage.Msg)
	query.SetQuestion("response-frame.test.", dnsmessage.TypeA)
	response := new(dnsmessage.Msg)
	response.SetReply(query)
	wire, err := response.Pack()
	if err != nil {
		t.Fatalf("response Pack() error = %v", err)
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
	copy(frame[2:], wire)

	resultCh := make(chan tcpDnsIngressResult, 1)
	go func() {
		handled, handleErr := (&ControlPlane{}).handleTCPDnsFastPath(
			context.Background(),
			serverConn,
			bufio.NewReader(serverConn),
			netip.MustParseAddrPort("192.0.2.10:42424"),
			netip.MustParseAddrPort("198.51.100.53:53"),
			&bpfRoutingResult{},
		)
		resultCh <- tcpDnsIngressResult{handled: handled, err: handleErr}
	}()
	if _, err := clientConn.Write(frame); err != nil {
		t.Fatalf("response frame Write() error = %v", err)
	}
	select {
	case result := <-resultCh:
		if result.err != nil || !result.handled {
			t.Fatalf("handleTCPDnsFastPath() = (%v, %v), want handled", result.handled, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP DNS response frame handler did not return")
	}
}

func exchangeTCPDNSQuery(t *testing.T, conn net.Conn, name string, id uint16) *dnsmessage.Msg {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	query := new(dnsmessage.Msg)
	query.SetQuestion(name, dnsmessage.TypeA)
	query.Id = id
	wire, err := query.Pack()
	if err != nil {
		t.Fatalf("query Pack() error = %v", err)
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
	copy(frame[2:], wire)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("query Write() error = %v", err)
	}

	lengthPrefix := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthPrefix); err != nil {
		t.Fatalf("response length ReadFull() error = %v", err)
	}
	responseWire := make([]byte, binary.BigEndian.Uint16(lengthPrefix))
	if _, err := io.ReadFull(conn, responseWire); err != nil {
		t.Fatalf("response payload ReadFull() error = %v", err)
	}
	response := new(dnsmessage.Msg)
	if err := response.Unpack(responseWire); err != nil {
		t.Fatalf("response Unpack() error = %v", err)
	}
	return response
}
