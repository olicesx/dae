/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"unicode"
)

var (
	httpHeaderHost = []byte("host")
	httpHeaderSep  = []byte{':'}
)

// httpMethods lists valid HTTP request methods as []byte so the method check
// in SniffHttp is allocation-free (string(method) would heap-allocate per call
// on a hot path).
var httpMethods = [][]byte{
	[]byte("GET"), []byte("POST"), []byte("PUT"), []byte("PATCH"),
	[]byte("DELETE"), []byte("COPY"), []byte("HEAD"), []byte("OPTIONS"),
	[]byte("LINK"), []byte("UNLINK"), []byte("PURGE"), []byte("LOCK"),
	[]byte("UNLOCK"), []byte("PROPFIND"), []byte("CONNECT"), []byte("TRACE"),
}

// isValidHttpMethod reports whether method is a recognized HTTP method,
// comparing bytes directly to avoid a string conversion.
func isValidHttpMethod(method []byte) bool {
	for _, m := range httpMethods {
		if bytes.Equal(method, m) {
			return true
		}
	}
	return false
}

// sniffHTTPMaxBufferedSize bounds how many LF-free header bytes the sniffer
// accumulates before giving up. The absolute sniffing deadline already bounds
// the wait in time; this bounds it in space, mirroring how the TLS record
// format structurally bounds the TLS path.
const sniffHTTPMaxBufferedSize = 64 << 10

func sniffHTTPHostHeader(data []byte) (string, error) {
	if len(data) > sniffHTTPMaxBufferedSize {
		return "", ErrNotFound
	}
	// The first line is the request line ("METHOD SP target SP version"); it is
	// never a Host header, so jump past it to avoid a wasted scan per request.
	start := 0
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		start = i + 1
	} else {
		// The method check has already validated this is HTTP, so a buffer
		// without an LF is a request line split across reads, not a final
		// verdict: ask for more data instead of giving up on the Host.
		return "", ErrNeedMore
	}
	headersComplete := false
	for start < len(data) {
		// Split on LF. HTTP lines end with CRLF, and a single-byte search for
		// '\n' is markedly cheaper than a two-byte search for "\r\n"; the
		// preceding CR (if present) is stripped from the header content.
		nl := bytes.IndexByte(data[start:], '\n')
		var line []byte
		if nl >= 0 {
			lineEnd := start + nl
			if lineEnd > start && data[lineEnd-1] == '\r' {
				line = data[start : lineEnd-1]
			} else {
				line = data[start:lineEnd]
			}
			start = lineEnd + 1
		} else {
			// The read boundary fell inside a header line (a split Host value
			// would otherwise be accepted truncated) and further headers,
			// Host included, may still arrive: incomplete headers are never a
			// final verdict.
			return "", ErrNeedMore
		}

		// Empty line marks end-of-headers.
		if len(line) == 0 {
			headersComplete = true
			break
		}
		key, value, found := bytes.Cut(line, httpHeaderSep)
		if !found {
			// Bad key value.
			continue
		}
		if bytes.EqualFold(bytes.TrimSpace(key), httpHeaderHost) {
			host := string(bytes.TrimSpace(value))
			if host == "" {
				return "", ErrNotFound
			}
			return host, nil
		}
	}
	if !headersComplete {
		// Every received line was complete but the end-of-headers blank line
		// has not arrived: the client may still send a Host (or more headers)
		// in the next read. A legal request always terminates its header block,
		// so only malformed traffic waits for the sniffing deadline here.
		return "", ErrNeedMore
	}
	return "", ErrNotFound
}

func (s *Sniffer) SniffHttp() (d string, err error) {
	// First byte should be printable.
	if s.buf.Len() == 0 || !unicode.IsPrint(rune(s.buf.Bytes()[0])) {
		return "", ErrNotApplicable
	}

	// Search method.
	search := s.buf.Bytes()
	if len(search) > 12 {
		search = search[:12]
	}
	method, _, found := bytes.Cut(search, []byte(" "))
	if !found {
		return "", ErrNotApplicable
	}
	if !isValidHttpMethod(method) {
		return "", ErrNotApplicable
	}

	// Now we assume it is an HTTP packet. We should not return NotApplicableError after here.

	return sniffHTTPHostHeader(s.buf.Bytes())
}
