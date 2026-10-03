/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
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

// TestSniffHttpNeedsMoreOnSplitHostValue pins the same retry contract one line
// down: when the read boundary falls inside the Host value, the truncated line
// must not be accepted as complete — that would route by a silently truncated
// domain (here "exam") instead of waiting for the rest of the header block.
func TestSniffHttpNeedsMoreOnSplitHostValue(t *testing.T) {
	sniffer := NewPacketSniffer([]byte("GET /path HTTP/1.1\r\nHost: exam"), 50*time.Millisecond)
	_, err := sniffer.SniffHttp()
	if !errors.Is(err, ErrNeedMore) {
		t.Fatalf("err = %v, want ErrNeedMore for a Host value split across reads", err)
	}
}

// TestSniffHttpNeedsMoreUntilHeaderBlockEnds: complete lines without the
// end-of-headers blank line are not a final verdict either — the Host may
// arrive in a later header line.
func TestSniffHttpNeedsMoreUntilHeaderBlockEnds(t *testing.T) {
	sniffer := NewPacketSniffer([]byte("GET /path HTTP/1.1\r\nAccept: text/plain\r\n"), 50*time.Millisecond)
	_, err := sniffer.SniffHttp()
	if !errors.Is(err, ErrNeedMore) {
		t.Fatalf("err = %v, want ErrNeedMore while the header block is incomplete", err)
	}

	// Once the blank line arrives, the absence of a Host is final.
	sniffer = NewPacketSniffer([]byte("GET /path HTTP/1.0\r\nAccept: text/plain\r\n\r\n"), 50*time.Millisecond)
	_, err = sniffer.SniffHttp()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound once the complete header block carries no Host", err)
	}
}

// TestSniffHttpGivesUpAtBufferCap: LF-free header bytes are bounded in space;
// beyond the cap the sniff ends instead of buffering without limit. The
// deadline bounds the wait in time; this bounds it structurally.
func TestSniffHttpGivesUpAtBufferCap(t *testing.T) {
	head := append([]byte("GET /path HTTP/1.1\r\nX-Pad: "), bytes.Repeat([]byte{'a'}, sniffHTTPMaxBufferedSize)...)
	sniffer := NewPacketSniffer(head, 50*time.Millisecond)
	_, err := sniffer.SniffHttp()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound past the buffered-size cap", err)
	}
}
