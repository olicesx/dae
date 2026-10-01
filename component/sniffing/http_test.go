/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"testing"
	"time"
)

// TestSniffHttpNeedsMoreOnSplitRequestLine pins the retry contract for a
// request line that has not reached its LF yet: the method is already
// validated as HTTP at that point, so the sniffer must ask for more data
// instead of ending the sniff and leaving the connection without a Host.
func TestSniffHttpNeedsMoreOnSplitRequestLine(t *testing.T) {
	sniffer := NewPacketSniffer([]byte("GET /path HT"), 50*time.Millisecond)
	_, err := sniffer.SniffHttp()
	if !errors.Is(err, ErrNeedMore) {
		t.Fatalf("err = %v, want ErrNeedMore for a request line without its LF", err)
	}

	// Control: the completed request still resolves the Host.
	full := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
	sniffer = NewPacketSniffer(full, 50*time.Millisecond)
	d, err := sniffer.SniffHttp()
	if err != nil {
		t.Fatalf("completed request: %v", err)
	}
	if d != "example.com" {
		t.Fatalf("domain = %q, want example.com", d)
	}
}
