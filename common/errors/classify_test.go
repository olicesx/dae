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

// TestErrorClassOrderLock pins the rule order through classification itself:
// an error matching two rules must resolve to the earlier one. The const
// order carries no behavior, so asserting iota values would be tautological.
func TestErrorClassOrderLock(t *testing.T) {
	// A cancellation wrapping a datagram drop is still caller-driven.
	canceledDrop := fmt.Errorf("read canceled: %w", context.Canceled)
	canceledDrop = fmt.Errorf("%w: %w", canceledDrop, io.ErrShortBuffer)
	if !IsCanceledOrClosed(canceledDrop) {
		t.Fatal("fixture sanity: canceledDrop must match the abort rule")
	}
	if got := ClassifyForwardError(canceledDrop); got != ClassCallerAbort {
		t.Fatalf("a cancellation wrapping a drop classified %v, want ClassCallerAbort (abort outranks drop)", got)
	}

	// A drop whose message also matches the soft-auth family stays a drop.
	dropWithAuthText := fmt.Errorf("read: cipher: message authentication failed: %w", io.ErrShortBuffer)
	if !IsAuthError(dropWithAuthText) {
		t.Fatal("fixture sanity: dropWithAuthText must match the soft-auth rule")
	}
	if got := ClassifyForwardError(dropWithAuthText); got != ClassDatagramDropped {
		t.Fatalf("a drop carrying auth text classified %v, want ClassDatagramDropped (drop outranks soft-auth)", got)
	}
}
