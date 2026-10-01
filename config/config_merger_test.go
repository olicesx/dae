/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMergeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestMergerAcceptsDiamondInclude pins that a shared file included by two
// siblings is legal: the visited-set used to double as the merged-section
// accumulator, so the second branch to reach the shared file was misreported
// as a circular include. Its items must also be merged exactly once.
func TestMergerAcceptsDiamondInclude(t *testing.T) {
	dir := t.TempDir()
	writeMergeFile(t, dir, "common.dae", "routing {\n  domain(example.com) -> direct\n}\n")
	writeMergeFile(t, dir, "a.dae", "include {\n  common.dae\n}\nrouting {\n  domain(a.example) -> proxy\n}\n")
	writeMergeFile(t, dir, "b.dae", "include {\n  common.dae\n}\nrouting {\n  domain(b.example) -> proxy\n}\n")
	main := writeMergeFile(t, dir, "main.dae", "include {\n  a.dae\n  b.dae\n}\n")

	sections, entries, err := NewMerger(main).Merge()
	if err != nil {
		t.Fatalf("diamond include must merge, got: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("entries = %v, want all four files", entries)
	}
	var joined strings.Builder
	for _, sec := range sections {
		if sec.Name != "routing" {
			continue
		}
		for _, item := range sec.Items {
			joined.WriteString(item.String(false, false))
			joined.WriteByte('\n')
		}
	}
	got := joined.String()
	for _, want := range []string{"example.com", "a.example", "b.example"} {
		if !strings.Contains(got, want) {
			t.Fatalf("merged routing misses %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "example.com) -> direct") != 1 {
		t.Fatalf("shared include must be merged exactly once, got:\n%s", got)
	}
}

// TestMergerRejectsRealCircularInclude keeps the genuine cycle rejected and
// names the actual chain in the error.
func TestMergerRejectsRealCircularInclude(t *testing.T) {
	dir := t.TempDir()
	writeMergeFile(t, dir, "a.dae", "include {\n  b.dae\n}\n")
	writeMergeFile(t, dir, "b.dae", "include {\n  a.dae\n}\n")
	main := writeMergeFile(t, dir, "main.dae", "include {\n  a.dae\n}\n")

	_, _, err := NewMerger(main).Merge()
	if !errors.Is(err, ErrCircularInclude) {
		t.Fatalf("err = %v, want ErrCircularInclude", err)
	}
	// The chain must name the real path in order: main -> a -> b -> a.
	msg := err.Error()
	for _, frag := range []string{"main.dae -> ", "a.dae -> ", "b.dae -> ", "a.dae"} {
		idx := strings.Index(msg, frag)
		if idx < 0 {
			t.Fatalf("cycle error should name the chain, missing %q: %v", frag, msg)
		}
		msg = msg[idx:]
	}
}
