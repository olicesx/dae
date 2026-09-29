/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package errors

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

// TestClassifyForwardError locks the single classification table. Every
// consumer (DNS forwarder, UDP endpoint watcher, dialer availability) maps
// these classes to actions; a change here changes all of them at once, which
// is exactly the property that killed the per-consumer predicate copies.
func TestClassifyForwardError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ErrorClass
	}{
		{"nil", nil, ClassSuccess},
		{"bare cancel", context.Canceled, ClassCallerAbort},
		{"wrapped cancel", fmt.Errorf("read udp: %w", context.Canceled), ClassCallerAbort},
		{"closed conn", net.ErrClosed, ClassCallerAbort},
		{"wrapped closed", fmt.Errorf("dial tcp: %w", net.ErrClosed), ClassCallerAbort},

		{"bare short buffer", io.ErrShortBuffer, ClassDatagramDropped},
		{"wrapped short buffer", fmt.Errorf("read udp: %w", io.ErrShortBuffer), ClassDatagramDropped},
		{"domain resolution", protocol.ErrDomainResolution, ClassDatagramDropped},
		{"wrapped domain resolution", fmt.Errorf("recv: %w: host.example: no address", protocol.ErrDomainResolution), ClassDatagramDropped},

		{"replay attack", stderrors.New("replay attack detected"), ClassSoftAuth},
		{"timestamp expired", stderrors.New("timestamp expired"), ClassSoftAuth},
		{"auth failed", stderrors.New("cipher: message authentication failed"), ClassSoftAuth},

		{"EOF", io.EOF, ClassHardFailure},
		{"unexpected EOF", io.ErrUnexpectedEOF, ClassHardFailure},
		{"deadline", context.DeadlineExceeded, ClassHardFailure},
		{"unknown", stderrors.New("connection reset by peer"), ClassHardFailure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyForwardError(tc.err); got != tc.want {
				t.Fatalf("ClassifyForwardError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestErrorClassOrderLock asserts the rule order that makes classification
// deterministic: caller abort outranks everything (a cancellation wrapping a
// datagram drop is still caller-driven), and the drop family outranks the
// soft-auth string matchers.
func TestErrorClassOrderLock(t *testing.T) {
	if ClassCallerAbort >= ClassDatagramDropped || ClassDatagramDropped >= ClassSoftAuth {
		t.Fatalf("unexpected class ordering: abort=%d dropped=%d softauth=%d",
			ClassCallerAbort, ClassDatagramDropped, ClassSoftAuth)
	}
}
