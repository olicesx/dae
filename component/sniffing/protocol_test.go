/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"testing"
	"time"
)

// TestSniffTcpReportsMatchedProtocol pins the protocol-return contract that
// the SNI learning hook depends on: TLS payloads report SniffProtocolTLS and
// HTTP payloads SniffProtocolHTTP, while a non-sniffable prefix reports none.
func TestSniffTcpReportsMatchedProtocol(t *testing.T) {
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: proto.example.com\r\nUser-Agent: test\r\n\r\n")

	tlsSniffer := NewStreamSniffer(newDeadlineConn(tlsStreamGoogle), 300*time.Millisecond)
	if _, proto, err := tlsSniffer.SniffTcp(); err != nil {
		t.Fatalf("TLS sniff: %v", err)
	} else if proto != SniffProtocolTLS {
		t.Fatalf("TLS payload protocol = %v, want SniffProtocolTLS", proto)
	}

	httpSniffer := NewStreamSniffer(newDeadlineConn(httpPayload), 300*time.Millisecond)
	if _, proto, err := httpSniffer.SniffTcp(); err != nil {
		t.Fatalf("HTTP sniff: %v", err)
	} else if proto != SniffProtocolHTTP {
		t.Fatalf("HTTP payload protocol = %v, want SniffProtocolHTTP", proto)
	}

	plainSniffer := NewStreamSniffer(bytes.NewReader([]byte("\x16not-tls")), 300*time.Millisecond)
	if _, proto, err := plainSniffer.SniffTcp(); err == nil {
		t.Fatal("non-sniffable payload must not report success")
	} else if proto != SniffProtocolNone {
		t.Fatalf("non-sniffable protocol = %v, want SniffProtocolNone", proto)
	}
}
