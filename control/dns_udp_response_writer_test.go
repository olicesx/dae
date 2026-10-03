/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// countingResponseWriter records the messages it is asked to send. The
// embedded interface satisfies the wide dnsmessage.ResponseWriter; only
// WriteMsg and Close are ever called on it here.
type countingResponseWriter struct {
	dnsmessage.ResponseWriter
	tcSeen int
}

func (w *countingResponseWriter) WriteMsg(m *dnsmessage.Msg) error {
	if m.Truncated {
		w.tcSeen++
	}
	return nil
}

func (w *countingResponseWriter) Close() error { return nil }

func newOversizedResponse(t *testing.T, limit int) *dnsmessage.Msg {
	t.Helper()
	msg := new(dnsmessage.Msg)
	msg.SetReply(new(dnsmessage.Msg).SetQuestion("big.example.", dnsmessage.TypeA))
	for i := range 64 {
		msg.Answer = append(msg.Answer, &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: dnsmessage.Fqdn("big.example."), Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
			A:   net.IPv4(203, 0, 113, byte(i+1)),
		})
	}
	if msg.Len() <= limit {
		t.Fatalf("fixture: response must exceed the limit (%d <= %d)", msg.Len(), limit)
	}
	return msg
}

// TestDnsUDPResponseWriterCountsTruncation pins the last uncounted client
// truncation path: an oversized answer delivered through the responseWriter
// (dae's UDP DNS listener) must feed the truncation summary exactly like the
// direct-send paths do, and only when the datagram actually leaves with TC=1.
func TestDnsUDPResponseWriterCountsTruncation(t *testing.T) {
	inner := &countingResponseWriter{}
	count := 0
	w := &dnsUDPResponseWriter{
		ResponseWriter: inner,
		limit:          512,
		noteTruncated:  func() { count++ },
	}

	oversized := newOversizedResponse(t, 512)
	require.NoError(t, w.WriteMsg(oversized))
	require.NotZero(t, inner.tcSeen, "an oversized message must leave with TC=1")
	require.Equal(t, 1, count, "the writer must record the truncation")
	require.False(t, oversized.Truncated, "the caller's message must stay intact for TCP retries")

	// A message within the limit is delivered verbatim and counts nothing.
	small := new(dnsmessage.Msg)
	small.SetReply(new(dnsmessage.Msg).SetQuestion("small.example.", dnsmessage.TypeA))
	require.NoError(t, w.WriteMsg(small))
	require.Equal(t, 1, count, "an in-limit message must not count as truncated")
	require.Zero(t, small.Truncated)
}
