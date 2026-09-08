/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// Event rate-limit constants: the single source of truth for the blocked-event
// rate domain. They are injected into the eBPF .rodata variable EVENT_RATE
// (struct dae_event_rate in kern/tproxy.c) before LoadAndAssign, and the
// alive_block_rate_map capacity is derived from the same blocked key in
// tuneEventRateMap, so the key-domain/capacity pairing has exactly one owner.
//
// This file deliberately carries no build tag: both the real-eBPF build
// (bpf_utils.go) and the dae_stub_ebpf test build (parity tests) must see the
// same contract values.
const (
	// blockedEventRateKey is the reserved alive_block_rate_map key for
	// DAE_EVENT_BLOCKED. Outbound ids live in the 0..255 u8 domain, so 256
	// can never collide with a real outbound id.
	blockedEventRateKey = uint32(256)
	// blockedEventRateWindowNs is the per-key minimum spacing between
	// blocked-event emissions (1s).
	blockedEventRateWindowNs = uint64(1_000_000_000)
)

// expectedInjectedVariables lists every .rodata variable this package promises
// to inject at load time. The completeness guard in
// loadBpfObjectsWithConstantsAndCustomizer fails the load when the constants
// map drifts from this list.
var expectedInjectedVariables = []string{
	"PARAM",
	"EVENT_RATE",
}

// eventRateValue returns the value injected into the eBPF .rodata variable
// EVENT_RATE (struct dae_event_rate in kern/tproxy.c). The field order
// mirrors the C struct: window_ns (u64) first, blocked_key (u32) second, no
// implicit padding between them; the trailing [4]byte makes the Go mirror
// match the C sizeof exactly. Keep in sync with kern/tproxy.c (guarded by
// TestBpfVariablesParityWithKernelSource).
func eventRateValue() any {
	return struct {
		WindowNs   uint64
		BlockedKey uint32
		_          [4]byte
	}{
		WindowNs:   blockedEventRateWindowNs,
		BlockedKey: blockedEventRateKey,
	}
}
