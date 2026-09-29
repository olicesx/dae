/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package errors

import (
	"errors"
	"io"

	"github.com/daeuniverse/outbound/protocol"
)

// ErrorClass is the single classification of an error raised by a transport
// or forward path. Consumers map a class to their own actions (retire,
// health report, log level, retry threshold) instead of each re-deriving
// that decision from raw predicates; the rule table below is the only place
// that knows how an error value maps to a class.
//
// Before this table existed, the "what did this error tell us" decision was
// re-implemented at every consumer (DNS forwarder, UDP endpoint watcher,
// dialer availability) with slightly different predicate subsets, and policy
// fixes landed in one copy but not the others.
type ErrorClass int

const (
	// ClassSuccess is the zero value: err == nil. No consumer action.
	ClassSuccess ErrorClass = iota
	// ClassCallerAbort covers request cancellation and lifecycle teardown.
	// It carries no information about the upstream or the dialer: do not
	// count it, retire on it, or report health on it.
	ClassCallerAbort
	// ClassDatagramDropped means the transport consumed and discarded
	// exactly one datagram (oversized for the caller's buffer, or a source
	// address that could not be resolved in time) while leaving the session
	// usable: the next read returns the next datagram. Treat it as a
	// per-datagram event; never retire a connection, endpoint, or dialer on
	// it.
	ClassDatagramDropped
	// ClassSoftAuth covers the replay-attack / authentication failure
	// family. Consumers apply their own thresholds before escalating.
	ClassSoftAuth
	// ClassTransportCongested means local admission control or backpressure
	// rejected the operation without touching the network. It is never
	// produced by ClassifyForwardError; callers that own such errors (for
	// example the DNS forwarder's UDP conn pool) assign it before consulting
	// their policy.
	ClassTransportCongested
	// ClassHardFailure is the conservative default: an unknown error is
	// treated as fatal to the session.
	ClassHardFailure
)

// String names the class for logs and tests.
func (c ErrorClass) String() string {
	switch c {
	case ClassSuccess:
		return "success"
	case ClassCallerAbort:
		return "caller-abort"
	case ClassDatagramDropped:
		return "datagram-dropped"
	case ClassSoftAuth:
		return "soft-auth"
	case ClassTransportCongested:
		return "transport-congested"
	default:
		return "hard-failure"
	}
}

type classRule struct {
	match func(error) bool
	class ErrorClass
}

// forwardErrorRules is the single source of truth for transport/forward
// error classification. Order is significant: the first matching rule wins.
//
// io.ErrShortBuffer also matches the outbound fork's typed
// netproxy.ErrDatagramDropped (its Cause unwraps to the sentinel), so this
// one rule classifies producers from pins both before and after the fork
// introduced the typed contract. When the fork pin advances past it, an
// explicit errors.As match can be added, but the sentinel match must stay
// for wrapped legacy producers.
var forwardErrorRules = []classRule{
	{IsCanceledOrClosed, ClassCallerAbort},
	{func(err error) bool {
		return errors.Is(err, io.ErrShortBuffer) ||
			errors.Is(err, protocol.ErrDomainResolution)
	}, ClassDatagramDropped},
	{func(err error) bool { return IsReplayAttackError(err) || IsAuthError(err) }, ClassSoftAuth},
}

// ClassifyForwardError maps err to its ErrorClass. err == nil yields
// ClassSuccess; anything unmatched yields ClassHardFailure.
func ClassifyForwardError(err error) ErrorClass {
	if err == nil {
		return ClassSuccess
	}
	for _, rule := range forwardErrorRules {
		if rule.match(err) {
			return rule.class
		}
	}
	return ClassHardFailure
}
