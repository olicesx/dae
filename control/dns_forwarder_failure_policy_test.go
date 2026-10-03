/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
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
			dnsForwardFailurePolicy{logDropped: true, countDropped: true},
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
	// The dialer half of the contract needs an observable dialer: a forced
	// unavailability report lands on the dialer's own logger ("Connectivity
	// Check Failed"), so the fixture dialer is built on the same hooked
	// logger and both rows assert the drop never reaches it while the hard
	// failure does.
	newDialArg := func(t *testing.T) *dialArgument {
		t.Helper()
		d := componentdialer.NewDialerContext(t.Context(),
			&scriptedDialer{},
			&componentdialer.GlobalOption{
				Log:           logger,
				CheckInterval: time.Second,
			},
			componentdialer.InstanceOption{DisableCheck: true},
			&componentdialer.Property{},
		)
		return &dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestDialer: d,
		}
	}
	countMessage := func(substr string) int {
		n := 0
		for _, e := range hook.AllEntries() {
			if strings.Contains(e.Message, substr) {
				n++
			}
		}
		return n
	}

	t.Run("dropped datagram", func(t *testing.T) {
		key, entry := newEntry(t)
		udpArg := newDialArg(t)
		before := controller.dnsDroppedDatagrams.Load()
		controller.handleDnsForwardFailure(nil, udpArg, key, entry,
			fmt.Errorf("read udp: %w", io.ErrShortBuffer))
		require.EqualValues(t, 0, entry.consecutiveErrors.Load(), "drop must not count as failure")
		require.False(t, entry.retired.Load(), "drop must not retire the forwarder")
		require.EqualValues(t, before+1, controller.dnsDroppedDatagrams.Load(),
			"drop must feed the counter the janitor publishes")
		_, stillCached := controller.dnsForwarderCache.Load(key)
		require.True(t, stillCached, "drop must keep the cached forwarder")
		require.Equal(t, 1, countMessage("dropped a datagram"))
		require.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
		require.Zero(t, countMessage("Connectivity Check Failed"),
			"a drop must never report the dialer unavailable")
		hook.Reset()
	})

	t.Run("caller abort is silent", func(t *testing.T) {
		key, entry := newEntry(t)
		controller.handleDnsForwardFailure(nil, newDialArg(t), key, entry, context.Canceled)
		require.EqualValues(t, 0, entry.consecutiveErrors.Load())
		require.False(t, entry.retired.Load())
		require.Zero(t, countMessage("DNS forward to upstream failed"), "cancellation must not log")
		require.Zero(t, countMessage("Connectivity Check Failed"))
		hook.Reset()
	})

	t.Run("local backpressure is silent", func(t *testing.T) {
		key, entry := newEntry(t)
		controller.handleDnsForwardFailure(nil, newDialArg(t), key, entry,
			fmt.Errorf("pool: %w", ErrDNSUDPConnPoolExhausted))
		require.EqualValues(t, 0, entry.consecutiveErrors.Load())
		require.Zero(t, countMessage("DNS forward to upstream failed"))
		require.Zero(t, countMessage("Connectivity Check Failed"))
		hook.Reset()
	})

	t.Run("hard failure counts, retires, warns, reports the dialer", func(t *testing.T) {
		key, entry := newEntry(t)
		hardArg := newDialArg(t)
		controller.handleDnsForwardFailure(nil, hardArg, key, entry, io.ErrUnexpectedEOF)
		require.EqualValues(t, 1, entry.consecutiveErrors.Load())
		require.True(t, entry.retired.Load(), "UDP hard failure must retire the forwarder")
		_, stillCached := controller.dnsForwarderCache.Load(key)
		require.False(t, stillCached)
		require.Equal(t, 1, countMessage("DNS forward to upstream failed"))
		for _, e := range hook.AllEntries() {
			if strings.Contains(e.Message, "DNS forward to upstream failed") {
				require.Equal(t, logrus.WarnLevel, e.Level)
			}
		}
		// The dialer half of the contract: the hard failure's report lands on
		// the dialer as a forced-unavailable connectivity-check failure — the
		// exact event the drop row above proves never fires for a drop.
		require.Equal(t, 1, countMessage("Connectivity Check Failed"))
	})
}
