/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"strings"
	"testing"
)

// These tests pin the operational outlet of the dropped-datagram counters. A
// drop is deliberately quiet per event (Debug), so the counters are the only
// record a running daemon keeps of a transport that cannot carry the answer
// size - and counters nobody reads are not visibility. The janitor summary is
// the answering mechanism, so it must report the interval deltas, warn when
// drops became client-visible failures, and stay silent while nothing happens.

func TestDnsDroppedDatagramSummaryIsSilentUntilSomethingHappens(t *testing.T) {
	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	var buf bytes.Buffer
	ctrl.log = truncationSummaryLogger(&buf)

	ctrl.reportDnsDroppedDatagramSummary()
	if buf.Len() != 0 {
		t.Fatalf("an idle interval must not log, got %q", buf.String())
	}
}

func TestDnsDroppedDatagramSummaryReportsIntervalRateAndWarnsOnFailure(t *testing.T) {
	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	var buf bytes.Buffer
	ctrl.log = truncationSummaryLogger(&buf)

	// One interval with two drops that the TCP retry answered and one that it
	// could not: the summary must report the interval deltas and the lifetime
	// totals, at warn level because a client-visible failure occurred.
	ctrl.dnsDroppedDatagrams.Add(3)
	ctrl.dnsDroppedRetries.Add(2)
	ctrl.dnsDroppedRetryFailures.Add(1)
	ctrl.reportDnsDroppedDatagramSummary()

	first := buf.String()
	for _, want := range []string{
		"level=warning",
		"drops=3",
		"drop_retries=2",
		"drop_retry_failures=1",
		"drops_total=3",
		"drop_retries_total=2",
		"drop_retry_failures_total=1",
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("summary %q does not contain %q", first, want)
		}
	}
	buf.Reset()

	// The same interval reported again is empty: the deltas are consumed by the
	// report instead of being repeated on every tick.
	ctrl.reportDnsDroppedDatagramSummary()
	if buf.Len() != 0 {
		t.Fatalf("a repeated report must not repeat the previous interval, got %q", buf.String())
	}

	// Drops whose retry succeeded are informational: the clients got answers,
	// so this is a transport detail rather than a failure. The truncation
	// counters stay untouched by drop traffic, because the two families answer
	// different operator questions (RFC 7766 §5 upgrades vs unusable datagrams).
	ctrl.dnsDroppedDatagrams.Add(1)
	ctrl.dnsDroppedRetries.Add(1)
	ctrl.reportDnsDroppedDatagramSummary()
	second := buf.String()
	if !strings.Contains(second, "level=info") {
		t.Fatalf("a recovered interval must not warn, got %q", second)
	}
	for _, want := range []string{"drops=1", "drop_retries=1", "drop_retry_failures=0", "drops_total=4"} {
		if !strings.Contains(second, want) {
			t.Fatalf("summary %q does not contain %q", second, want)
		}
	}
	if got := ctrl.dnsUdpTruncatedUpgrades.Load(); got != 0 {
		t.Fatalf("drop traffic changed the truncation upgrade counter to %d, want 0", got)
	}
	if got := ctrl.dnsUdpTruncatedUpgradeFailures.Load(); got != 0 {
		t.Fatalf("drop traffic changed the truncation failure counter to %d, want 0", got)
	}
}

// TestDnsDroppedDatagramSummaryReportsDropsWithoutRetries pins the
// `tcp+udp://`-less case: a drop on an upstream that cannot retry (or a retry
// that was never attempted because the scheme forbids it) still has to reach
// the operator, because nothing else about that query is logged above Debug.
func TestDnsDroppedDatagramSummaryReportsDropsWithoutRetries(t *testing.T) {
	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	var buf bytes.Buffer
	ctrl.log = truncationSummaryLogger(&buf)

	ctrl.dnsDroppedDatagrams.Add(2)
	ctrl.reportDnsDroppedDatagramSummary()

	got := buf.String()
	if !strings.Contains(got, "level=info") {
		t.Fatalf("drops alone must be informational, got %q", got)
	}
	for _, want := range []string{"drops=2", "drop_retries=0", "drop_retry_failures=0"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q does not contain %q", got, want)
		}
	}
}
