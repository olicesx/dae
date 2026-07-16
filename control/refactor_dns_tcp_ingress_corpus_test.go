/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const phase0TCPIngressResponseWireHex = "" +
	"4a2b810000010001000000000b7463702d696e67726573730670686173653004746573740000010001" +
	"c00c00010001000000000004c633644d"

// TestPhase0TCPDNSIngressCorpus_LegacyBaseline fixes the complete ingress
// DNS-over-TCP observable: a fixed query frame reaches the real TCP fast path,
// the controller resolves through the configured forwarder, and the response is
// returned with the required two-byte length prefix and stable DNS wire bytes.
func TestPhase0TCPDNSIngressCorpus_LegacyBaseline(t *testing.T) {
	const (
		queryName = "tcp-ingress.phase0.test."
		queryID   = 0x4a2b
		answerIP  = "198.51.100.77"
	)

	ctrl := newPhase0TCPIngressDnsController(t)
	installPhase0TCPIngressDnsForwarder(t, func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return phase0TCPIngressAResponse(queryName, answerIP), nil
		}}, nil
	})

	log := logrus.New()
	log.SetOutput(io.Discard)
	plane := &ControlPlane{
		log: log,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: ctrl,
		},
	}

	query := new(dnsmessage.Msg)
	query.SetQuestion(queryName, dnsmessage.TypeA)
	query.Id = queryID
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatalf("query Pack() error = %v", err)
	}
	queryFrame := make([]byte, 2+len(queryWire))
	binary.BigEndian.PutUint16(queryFrame[:2], uint16(len(queryWire)))
	copy(queryFrame[2:], queryWire)

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })
	t.Cleanup(func() { _ = clientConn.Close() })
	if err := clientConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("clientConn.SetDeadline() error = %v", err)
	}

	resultCh := make(chan tcpDnsIngressResult, 1)
	go func() {
		handled, err := plane.handleTCPDnsFastPath(
			context.Background(),
			serverConn,
			bufio.NewReader(serverConn),
			netip.MustParseAddrPort("192.0.2.10:42424"),
			netip.MustParseAddrPort("198.51.100.53:53"),
			&bpfRoutingResult{},
		)
		resultCh <- tcpDnsIngressResult{handled: handled, err: err}
	}()

	if _, err := clientConn.Write(queryFrame); err != nil {
		t.Fatalf("client query frame Write() error = %v", err)
	}

	responseFrame, responseWire := readPhase0TCPDnsFrame(t, clientConn)
	if got, want := binary.BigEndian.Uint16(responseFrame[:2]), uint16(len(responseWire)); got != want {
		t.Fatalf("response length prefix = %d, want payload length %d", got, want)
	}

	wantWire, err := hex.DecodeString(phase0TCPIngressResponseWireHex)
	if err != nil {
		t.Fatalf("decode expected TCP DNS wire: %v", err)
	}
	if !bytes.Equal(responseWire, wantWire) {
		t.Fatalf("TCP DNS response wire = %x, want %x", responseWire, wantWire)
	}

	var response dnsmessage.Msg
	if err := response.Unpack(responseWire); err != nil {
		t.Fatalf("response Unpack() error = %v", err)
	}
	if !response.Response || response.Id != queryID || response.Rcode != dnsmessage.RcodeSuccess {
		t.Fatalf("response header = %+v, want response id=%d rcode=%d", response.MsgHdr, queryID, dnsmessage.RcodeSuccess)
	}
	if len(response.Question) != 1 || response.Question[0].Name != queryName || response.Question[0].Qtype != dnsmessage.TypeA {
		t.Fatalf("response question = %+v, want %s A", response.Question, queryName)
	}
	if got := dnsAnswerIPv4(t, &response); got != answerIP {
		t.Fatalf("response A answer = %s, want %s", got, answerIP)
	}

	if err := clientConn.Close(); err != nil {
		t.Fatalf("clientConn.Close() error = %v", err)
	}
	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("handleTCPDnsFastPath() error = %v", result.err)
		}
		if !result.handled {
			t.Fatal("handleTCPDnsFastPath() handled = false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handleTCPDnsFastPath() did not finish after client close")
	}
}

type tcpDnsIngressResult struct {
	handled bool
	err     error
}

func newPhase0TCPIngressDnsController(t *testing.T) *DnsController {
	t.Helper()

	ctrl := newCorpusDnsController(t, &config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("asis")},
			Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
		},
	})
	setScopedBestDialerChooser(ctrl, func(_ context.Context, req *udpRequest, _ *componentdns.Upstream) (*dialArgument, error) {
		return &dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestTarget: req.realDst,
		}, nil
	})
	return ctrl
}

func installPhase0TCPIngressDnsForwarder(t *testing.T, factory func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error)) {
	t.Helper()

	previous := dnsForwarderFactory
	dnsForwarderFactory = factory
	t.Cleanup(func() {
		dnsForwarderFactory = previous
	})
}

func readPhase0TCPDnsFrame(t *testing.T, conn net.Conn) ([]byte, []byte) {
	t.Helper()

	lengthPrefix := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthPrefix); err != nil {
		t.Fatalf("response length ReadFull() error = %v", err)
	}
	payloadLength := binary.BigEndian.Uint16(lengthPrefix)
	if payloadLength == 0 {
		t.Fatal("response length prefix is zero")
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("response payload ReadFull() error = %v", err)
	}
	return append(lengthPrefix, payload...), payload
}

func phase0TCPIngressAResponse(name, address string) *dnsmessage.Msg {
	msg := dnsAResponseMsg(name, address)
	msg.Answer[0].Header().Ttl = 0
	return msg
}
