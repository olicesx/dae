/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The conn_state_map capacity is written down in three places that no runtime
// check ties together: the clang-side default MAX_CONN_STATE_NUM (which sizes
// the compiled map declaration), the config default bpf_conn_state_map_size
// (which userspace applies at load), and the sample example.dae. dae sizes both
// the live map and the janitor's pressure threshold from the configured value,
// so a drift here silently changes how many concurrent flows fit and when
// cleanup turns aggressive. This test pins the three literals against each
// other; control/bpf_variables_parity_test.go pins the two Go loader mirrors
// (bpf_utils.go, bpf_stub.go) against the same C macro.
var (
	// captures `mapstructure:"bpf_conn_state_map_size" default:"<n>"`.
	bpfConnStateMapSizeDefaultPattern = regexp.MustCompile(
		`mapstructure:"bpf_conn_state_map_size"\s+default:"(\d+)"`)

	// captures a `bpf_conn_state_map_size: <n>` line in example.dae.
	bpfConnStateMapSizeSamplePattern = regexp.MustCompile(
		`(?m)^\s*bpf_conn_state_map_size:\s*(\d+)`)

	// captures " #define MAX_CONN_STATE_NUM <n>".
	bpfConnStateNumPattern = regexp.MustCompile(
		`(?m)#define\s+MAX_CONN_STATE_NUM\s+(\d+)`)
)

func TestBpfConnStateMapSizeParity(t *testing.T) {
	read := func(rel string) string {
		t.Helper()
		abs, err := filepath.Abs(rel)
		if err != nil {
			t.Fatalf("resolve %s: %v", rel, err)
		}
		raw, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(raw)
	}

	parse := func(where, source string, pattern *regexp.Regexp) uint64 {
		t.Helper()
		matches := pattern.FindAllStringSubmatch(source, -1)
		if len(matches) != 1 {
			t.Fatalf("expected exactly one %s in %s, found %d", pattern.String(), where, len(matches))
		}
		value, err := strconv.ParseUint(matches[0][1], 10, 32)
		if err != nil {
			t.Fatalf("parse %s in %s: %v", matches[0][1], where, err)
		}
		return value
	}

	cValue := parse("control/kern/tproxy.c", read("../control/kern/tproxy.c"), bpfConnStateNumPattern)
	defaultValue := parse("config.go", read("config.go"), bpfConnStateMapSizeDefaultPattern)
	sampleValue := parse("example.dae", read("../example.dae"), bpfConnStateMapSizeSamplePattern)

	if defaultValue != cValue {
		t.Errorf("config default bpf_conn_state_map_size=%d diverges from C MAX_CONN_STATE_NUM=%d; the C macro sizes the compiled map declaration while userspace overrides it from this config value",
			defaultValue, cValue)
	}
	if sampleValue != defaultValue {
		t.Errorf("example.dae bpf_conn_state_map_size=%d diverges from the config default %d; the sample must document the value a fresh deployment gets",
			sampleValue, defaultValue)
	}
}
