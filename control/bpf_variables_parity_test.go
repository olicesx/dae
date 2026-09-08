//go:build dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"reflect"
	"regexp"
	"strconv"
	"testing"
)

// The event rate-limit constants are owned by Go (blockedEventRateKey,
// blockedEventRateWindowNs in bpf_utils.go) and injected into the .rodata
// variable EVENT_RATE at load time. These tests pin the kernel-side half of
// that contract at the source level, so a C-side rename, field reorder, or
// fallback-constant drift turns the Go Unit Test gate red instead of
// silently falling back to clang initializers at load time.

var (
	// matches "const volatile struct dae_event_rate EVENT_RATE = { ... };"
	// and captures the struct tag name and the variable name.
	rodataVariablePattern = regexp.MustCompile(`(?m)const\s+volatile\s+struct\s+(\w+)\s+(\w+)\s*=`)

	// captures the declared field names of struct dae_event_rate in order.
	eventRateStructPattern = regexp.MustCompile(
		`struct\s+dae_event_rate\s*\{([^}]*)\}`)

	// captures " #define BLOCKED_EVENT_RATE_KEY_FALLBACK <n>".
	rateKeyFallbackPattern = regexp.MustCompile(`(?m)#define\s+BLOCKED_EVENT_RATE_KEY_FALLBACK\s+(\d+)`)
)

func TestBpfVariablesParityWithKernelSource(t *testing.T) {
	found := map[string]string{} // variable name -> struct tag name
	for _, m := range rodataVariablePattern.FindAllStringSubmatch(tproxySource, -1) {
		found[m[2]] = m[1]
	}

	for _, name := range expectedInjectedVariables {
		tag, ok := found[name]
		if !ok {
			t.Errorf("kernel source declares no `const volatile struct ... %s`; "+
				"bpf_utils.go injects it but the C-side declaration is gone "+
				"(renamed or removed?)", name)
			continue
		}
		if tag != "dae_param" && tag != "dae_event_rate" {
			t.Errorf("variable %s has unexpected struct type %q", name, tag)
		}
	}

	// The reverse direction: every const-volatile struct variable in the
	// kernel source must be covered by the Go injection list, otherwise it
	// would silently keep its clang fallback value in production.
	for name := range found {
		listed := false
		for _, want := range expectedInjectedVariables {
			if name == want {
				listed = true
				break
			}
		}
		if !listed {
			t.Errorf("kernel source declares const-volatile variable %q but "+
				"expectedInjectedVariables does not list it; it would keep its "+
				"clang fallback initializer instead of being injected by Go", name)
		}
	}
}

func TestEventRateStructLayoutContract(t *testing.T) {
	m := eventRateStructPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("struct dae_event_rate not found in kern/tproxy.c")
	}
	fieldPattern := regexp.MustCompile(`(__u\d+|\w+_t)\s+(\w+)\s*;`)
	var fields []string
	for _, fm := range fieldPattern.FindAllStringSubmatch(m[1], -1) {
		fields = append(fields, fm[2])
	}

	// window_ns (u64) must precede blocked_key (u32) so the C struct has no
	// implicit padding between fields; eventRateValue() mirrors this order
	// with an explicit trailing [4]byte to match the C sizeof.
	want := []string{"window_ns", "blocked_key"}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("struct dae_event_rate field order %v, want %v (no implicit padding allowed: the Go mirror is binary-injected)", fields, want)
	}
}

func TestEventRateFallbackConstantsMatchGoOwner(t *testing.T) {
	m := rateKeyFallbackPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("#define BLOCKED_EVENT_RATE_KEY_FALLBACK not found in kern/tproxy.c")
	}
	fallback, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		t.Fatalf("parse fallback key %q: %v", m[1], err)
	}
	if uint32(fallback) != blockedEventRateKey {
		t.Fatalf("C fallback BLOCKED_EVENT_RATE_KEY_FALLBACK=%d diverges from the Go-owned blockedEventRateKey=%d; the map capacity derives from the Go value while the C code uses the fallback",
			fallback, blockedEventRateKey)
	}
}
