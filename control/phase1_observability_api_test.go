/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func resetPhase1ObservabilityForAPITest(t *testing.T) {
	t.Helper()
	previous := activePhase1Observability.Swap(nil)
	t.Cleanup(func() {
		activePhase1Observability.CompareAndSwap(nil, previous)
	})
}

func TestPhase1ObservabilityEnableSnapshotAndDisable(t *testing.T) {
	resetPhase1ObservabilityForAPITest(t)

	handle, err := EnablePhase1Observability(1)
	if err != nil {
		t.Fatalf("EnablePhase1Observability() error = %v", err)
	}

	observePhase1RoutingLookup(phase1RoutingLookupEmbedded, phase1RoutingLookupHit)
	observePhase1UserspaceRematch(phase1TransportUDP, phase1UserspaceRematchFailure)
	observePhase1UDPKeyProbe(phase1UDPKeyProbeSibling, phase1UDPKeyProbeTargetMismatch)
	observePhase1DNSCache(phase1DNSCacheStale, 15*time.Millisecond)
	observePhase1BPFPublish(phase1BPFPublishStage, phase1BPFPublishFailure, 500*time.Millisecond)
	observePhase1ReloadDrain(phase1ReloadDrainTimedOut, 2*time.Second)
	observePhase1Dial(phase1DialOperationConnectRetry, phase1TransportTCP, phase1DialOutcomeSuccess)

	snapshot, enabled := SnapshotPhase1Observability()
	if !enabled {
		t.Fatal("SnapshotPhase1Observability() enabled = false, want true")
	}
	if snapshot.SampleEvery != 1 {
		t.Fatalf("snapshot sample interval = %d, want 1", snapshot.SampleEvery)
	}
	if got := snapshot.RoutingLookup[Phase1RoutingLookupEmbedded][Phase1RoutingLookupHit]; got != 1 {
		t.Fatalf("routing lookup snapshot count = %d, want 1", got)
	}
	if got := snapshot.UserspaceRematch[Phase1TransportUDP][Phase1UserspaceRematchFailure]; got != 1 {
		t.Fatalf("userspace rematch snapshot count = %d, want 1", got)
	}
	if got := snapshot.UDPKeyProbe[Phase1UDPKeyProbeSibling][Phase1UDPKeyProbeTargetMismatch]; got != 1 {
		t.Fatalf("UDP key probe snapshot count = %d, want 1", got)
	}
	if got := snapshot.DNSCache[Phase1DNSCacheStale]; got != 1 {
		t.Fatalf("DNS cache snapshot count = %d, want 1", got)
	}
	if got := snapshot.DNSCacheLatency[Phase1DNSCacheStale][Phase1LatencyUnderHundredMilliseconds]; got != 1 {
		t.Fatalf("DNS cache latency snapshot count = %d, want 1", got)
	}
	if got := snapshot.BPFPublish[Phase1BPFPublishStage][Phase1BPFPublishFailure]; got != 1 {
		t.Fatalf("BPF publish snapshot count = %d, want 1", got)
	}
	if got := snapshot.BPFPublishLatency[Phase1BPFPublishStage][Phase1BPFPublishFailure][Phase1LatencyUnderSecond]; got != 1 {
		t.Fatalf("BPF publish latency snapshot count = %d, want 1", got)
	}
	if got := snapshot.ReloadDrain[Phase1ReloadDrainTimedOut]; got != 1 {
		t.Fatalf("reload drain snapshot count = %d, want 1", got)
	}
	if got := snapshot.ReloadDrainLatency[Phase1ReloadDrainTimedOut][Phase1LatencyAtLeastSecond]; got != 1 {
		t.Fatalf("reload drain latency snapshot count = %d, want 1", got)
	}
	if got := snapshot.Dial[Phase1DialOperationConnectRetry][Phase1TransportTCP][Phase1DialOutcomeSuccess]; got != 1 {
		t.Fatalf("dial snapshot count = %d, want 1", got)
	}

	snapshot.RoutingLookup[Phase1RoutingLookupEmbedded][Phase1RoutingLookupHit] = 99
	current, enabled := SnapshotPhase1Observability()
	if !enabled || current.RoutingLookup[Phase1RoutingLookupEmbedded][Phase1RoutingLookupHit] != 1 {
		t.Fatal("snapshot mutation changed the active recorder")
	}

	if !DisablePhase1Observability(handle) {
		t.Fatal("DisablePhase1Observability() = false, want true")
	}
	if _, enabled := SnapshotPhase1Observability(); enabled {
		t.Fatal("SnapshotPhase1Observability() enabled = true after disable")
	}
	if handle.Disable() {
		t.Fatal("second handle.Disable() = true, want false")
	}
}

func TestPhase1ObservabilityEnableValidatesOwnership(t *testing.T) {
	resetPhase1ObservabilityForAPITest(t)

	if _, err := EnablePhase1Observability(0); !stderrors.Is(err, ErrPhase1ObservabilityInvalidSampleEvery) {
		t.Fatalf("EnablePhase1Observability(0) error = %v, want %v", err, ErrPhase1ObservabilityInvalidSampleEvery)
	}

	handle, err := EnablePhase1Observability(3)
	if err != nil {
		t.Fatalf("EnablePhase1Observability(3) error = %v", err)
	}
	if _, err := EnablePhase1Observability(1); !stderrors.Is(err, ErrPhase1ObservabilityAlreadyEnabled) {
		t.Fatalf("second EnablePhase1Observability() error = %v, want %v", err, ErrPhase1ObservabilityAlreadyEnabled)
	}

	replacement := newPhase1Observability(1)
	activePhase1Observability.Store(replacement)
	if handle.Disable() {
		t.Fatal("handle.Disable() disabled a replacement recorder")
	}
	if recorder := activePhase1Observability.Load(); recorder != replacement {
		t.Fatalf("active recorder = %p, want replacement %p", recorder, replacement)
	}
	activePhase1Observability.CompareAndSwap(replacement, nil)
}

func TestPhase1ObservabilityDoesNotChangeRoutingLookupResult(t *testing.T) {
	resetPhase1ObservabilityForAPITest(t)

	src := netip.MustParseAddrPort("192.0.2.10:12345")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	var core *controlPlaneCore

	disabledResult, disabledErr := core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if !stderrors.Is(disabledErr, ebpf.ErrKeyNotExist) {
		t.Fatalf("disabled RetrieveRoutingResult() error = %v, want %v", disabledErr, ebpf.ErrKeyNotExist)
	}

	handle, err := EnablePhase1Observability(1)
	if err != nil {
		t.Fatalf("EnablePhase1Observability() error = %v", err)
	}
	defer handle.Disable()

	enabledResult, enabledErr := core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if !stderrors.Is(enabledErr, ebpf.ErrKeyNotExist) {
		t.Fatalf("enabled RetrieveRoutingResult() error = %v, want %v", enabledErr, ebpf.ErrKeyNotExist)
	}
	if disabledResult != enabledResult {
		t.Fatalf("routing result changed: disabled=%v enabled=%v", disabledResult, enabledResult)
	}
	if disabledErr.Error() != enabledErr.Error() {
		t.Fatalf("routing error changed: disabled=%q enabled=%q", disabledErr, enabledErr)
	}

	snapshot, enabled := SnapshotPhase1Observability()
	if !enabled || snapshot.RoutingLookup[Phase1RoutingLookupUnavailable][Phase1RoutingLookupMiss] != 1 {
		t.Fatal("enabled lookup did not record the expected observation")
	}
}
