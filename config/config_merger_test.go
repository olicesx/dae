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

// TestMergerRejectsSelfIncludeCycle pins the shortest real cycle: a file
// including itself. The error must name the actual 2-element cycle
// (main -> main) instead of stopping at a bare ErrCircularInclude.
func TestMergerRejectsSelfIncludeCycle(t *testing.T) {
	dir := t.TempDir()
	main := writeMergeFile(t, dir, "main.dae", "include {\n  main.dae\n}\n")

	_, _, err := NewMerger(main).Merge()
	if !errors.Is(err, ErrCircularInclude) {
		t.Fatalf("err = %v, want ErrCircularInclude", err)
	}
	// The chain must name both hops of the cycle in order: main -> main.
	msg := err.Error()
	for _, frag := range []string{main + " -> ", main} {
		idx := strings.Index(msg, frag)
		if idx < 0 {
			t.Fatalf("cycle error should name the 2-element chain, missing %q: %v", frag, msg)
		}
		msg = msg[idx:]
	}
}

// TestMergerRejectsCycleBehindDiamondInclude pins that a cycle hidden behind a
// diamond is still rejected: the entry fans out to a and b, both include the
// shared file s, and s loops back to a. Only the visiting set (not the merged
// marker) detects it, and the DFS error aborts Merge before any section is
// produced, so nothing from the shared file is merged anywhere.
func TestMergerRejectsCycleBehindDiamondInclude(t *testing.T) {
	dir := t.TempDir()
	a := writeMergeFile(t, dir, "a.dae", "include {\n  s.dae\n}\nrouting {\n  domain(a.example) -> proxy\n}\n")
	writeMergeFile(t, dir, "b.dae", "include {\n  s.dae\n}\nrouting {\n  domain(b.example) -> proxy\n}\n")
	s := writeMergeFile(t, dir, "s.dae", "include {\n  a.dae\n}\nrouting {\n  domain(shared.example) -> direct\n}\n")
	main := writeMergeFile(t, dir, "main.dae", "include {\n  a.dae\n  b.dae\n}\n")

	sections, entries, err := NewMerger(main).Merge()
	if !errors.Is(err, ErrCircularInclude) {
		t.Fatalf("err = %v, want ErrCircularInclude", err)
	}
	// The chain must name the real path in order: main -> a -> s -> a. The
	// first branch (a) is explored before b, and s loops back into it.
	msg := err.Error()
	for _, frag := range []string{main + " -> ", a + " -> ", s + " -> ", a} {
		idx := strings.Index(msg, frag)
		if idx < 0 {
			t.Fatalf("cycle error should name the chain, missing %q: %v", frag, msg)
		}
		msg = msg[idx:]
	}
	// The error precedes any merge output: nothing, in particular nothing from
	// the shared file, may be merged anywhere.
	if sections != nil || entries != nil {
		t.Fatalf("cycle must abort before producing merge output, got sections=%v entries=%v", sections, entries)
	}
}
