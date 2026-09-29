/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// TestDnsForwardFailurePolicyFor locks the decision table: a classification
// fix here changes every failure consumer at once, so the table itself is the
// contract. The short-buffer row is the incident fix: a dropped datagram must
// not count, retire, or report dialer unavailability.
func TestDnsForwardFailurePolicyFor(t *testing.T) {
	cases := []struct {
		class commonerrors.ErrorClass
		want  dnsForwardFailurePolicy
	}{
		{
			commonerrors.ClassSuccess,
			dnsForwardFailurePolicy{silent: true},
		},
		{
			commonerrors.ClassCallerAbort,
			dnsForwardFailurePolicy{silent: true},
		},
		{
			commonerrors.ClassTransportCongested,
			dnsForwardFailurePolicy{silent: true},
		},
		{
			commonerrors.ClassDatagramDropped,
			dnsForwardFailurePolicy{logDropped: true},
		},
		{
			commonerrors.ClassSoftAuth,
			dnsForwardFailurePolicy{countFailure: true, reportUnavailable: true},
		},
		{
			commonerrors.ClassHardFailure,
			dnsForwardFailurePolicy{countFailure: true, reportUnavailable: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.class.String(), func(t *testing.T) {
			require.Equal(t, tc.want, dnsForwardFailurePolicyFor(tc.class))
		})
	}
}

func TestClassifyDnsForwardError(t *testing.T) {
	require.Equal(t, commonerrors.ClassTransportCongested,
		classifyDnsForwardError(fmt.Errorf("dial: %w", ErrDNSUDPConnPoolExhausted)))
	require.Equal(t, commonerrors.ClassDatagramDropped,
		classifyDnsForwardError(fmt.Errorf("read udp: %w", io.ErrShortBuffer)))
	require.Equal(t, commonerrors.ClassCallerAbort,
		classifyDnsForwardError(context.Canceled))
	require.Equal(t, commonerrors.ClassHardFailure,
		classifyDnsForwardError(io.ErrUnexpectedEOF))
}

// TestHandleDnsForwardFailureDropKeepsForwarderAndDialer wires the decision
// table end to end on a minimal controller: an oversized-datagram error must
// leave the cached forwarder alive, keep the consecutive-error counter at
// zero, and log at Debug, while a hard failure on the same key retires the
// entry and logs at Warn.
func TestHandleDnsForwardFailureDropKeepsForwarderAndDialer(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	controller := &DnsController{
		dnsControllerStore: newDnsControllerStore(),
		log:                logger,
	}

	newEntry := func(t *testing.T) (dnsForwarderKey, *cachedDnsForwarder) {
		t.Helper()
		key := dnsForwarderKey{upstream: "tcp+udp://1.0.0.1:53"}
		entry := newCachedDnsForwarder(&stubDnsForwarder{}, time.Now())
		controller.dnsForwarderCache.Store(key, entry)
		return key, entry
	}
	udpArg := &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4}

	t.Run("dropped datagram", func(t *testing.T) {
		key, entry := newEntry(t)
		controller.handleDnsForwardFailure(nil, udpArg, key, entry,
			fmt.Errorf("read udp: %w", io.ErrShortBuffer))
		require.EqualValues(t, 0, entry.consecutiveErrors.Load(), "drop must not count as failure")
		require.False(t, entry.retired.Load(), "drop must not retire the forwarder")
		_, stillCached := controller.dnsForwarderCache.Load(key)
		require.True(t, stillCached, "drop must keep the cached forwarder")
		require.Len(t, hook.Entries, 1)
		require.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
		require.Contains(t, hook.LastEntry().Message, "dropped a datagram")
		hook.Reset()
	})

	t.Run("caller abort is silent", func(t *testing.T) {
		key, entry := newEntry(t)
		controller.handleDnsForwardFailure(nil, udpArg, key, entry, context.Canceled)
		require.EqualValues(t, 0, entry.consecutiveErrors.Load())
		require.False(t, entry.retired.Load())
		require.Empty(t, hook.Entries, "cancellation must not log")
	})

	t.Run("local backpressure is silent", func(t *testing.T) {
		key, entry := newEntry(t)
		controller.handleDnsForwardFailure(nil, udpArg, key, entry,
			fmt.Errorf("pool: %w", ErrDNSUDPConnPoolExhausted))
		require.EqualValues(t, 0, entry.consecutiveErrors.Load())
		require.Empty(t, hook.Entries)
	})

	t.Run("hard failure counts, retires, warns", func(t *testing.T) {
		key, entry := newEntry(t)
		controller.handleDnsForwardFailure(nil, udpArg, key, entry, io.ErrUnexpectedEOF)
		require.EqualValues(t, 1, entry.consecutiveErrors.Load())
		require.True(t, entry.retired.Load(), "UDP hard failure must retire the forwarder")
		_, stillCached := controller.dnsForwarderCache.Load(key)
		require.False(t, stillCached)
		require.Len(t, hook.Entries, 1)
		require.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
		require.Contains(t, hook.LastEntry().Message, "DNS forward to upstream failed")
	})
}
