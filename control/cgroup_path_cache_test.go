//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"sync"
	"testing"
)

// swapScanCgroupPath installs a fake scan and resets the probe cache; the
// original state is restored on cleanup. Tests swapping the seam must stay
// sequential (no t.Parallel): the seam and the cache are package state.
func swapScanCgroupPath(t *testing.T, fake func() (string, error)) {
	t.Helper()
	detectCgroupPathMu.Lock()
	origFn := scanCgroupPathFn
	origValue, origFound := detectCgroupPathValue, detectCgroupPathFound
	scanCgroupPathFn = fake
	detectCgroupPathValue, detectCgroupPathFound = "", false
	detectCgroupPathMu.Unlock()
	t.Cleanup(func() {
		detectCgroupPathMu.Lock()
		scanCgroupPathFn = origFn
		detectCgroupPathValue, detectCgroupPathFound = origValue, origFound
		detectCgroupPathMu.Unlock()
	})
}

// TestDetectCgroupPathCachesSuccessOnly pins the recovery semantics of the
// probe cache: a success is scanned once and reused for the process lifetime,
// while a failure is never cached — the next call scans again, so a transient
// /proc/mounts failure recovers at the next reload instead of disabling pname
// routing until restart.
func TestDetectCgroupPathCachesSuccessOnly(t *testing.T) {
	var calls int
	swapScanCgroupPath(t, func() (string, error) {
		calls++
		return "/sys/fs/cgroup/unified", nil
	})

	for range 2 {
		path, err := detectCgroupPath()
		if err != nil || path != "/sys/fs/cgroup/unified" {
			t.Fatalf("detectCgroupPath = %q, %v; want the scanned path", path, err)
		}
	}
	if calls != 1 {
		t.Fatalf("success must be scanned once, scans = %d", calls)
	}
}

func TestDetectCgroupPathRetriesAfterFailure(t *testing.T) {
	var calls int
	probeErr := errors.New("transient scan failure")
	swapScanCgroupPath(t, func() (string, error) {
		calls++
		if calls == 1 {
			return "", probeErr
		}
		return "/sys/fs/cgroup", nil
	})

	if _, err := detectCgroupPath(); !errors.Is(err, probeErr) {
		t.Fatalf("first call err = %v, want the scan failure", err)
	}
	path, err := detectCgroupPath()
	if err != nil || path != "/sys/fs/cgroup" {
		t.Fatalf("second call = %q, %v; want the recovered scan result", path, err)
	}
	if calls != 2 {
		t.Fatalf("a failed scan must not be cached, scans = %d", calls)
	}
	// The recovered success is cached from here on.
	if _, err = detectCgroupPath(); err != nil {
		t.Fatalf("third call err = %v, want nil", err)
	}
	if calls != 2 {
		t.Fatalf("recovered success must be cached, scans = %d", calls)
	}
}

// TestDetectCgroupPathConcurrentCallersShareOneScan keeps the previous
// contract that concurrent callers observe one consistent result.
func TestDetectCgroupPathConcurrentCallersShareOneScan(t *testing.T) {
	var calls int
	var callsMu sync.Mutex
	swapScanCgroupPath(t, func() (string, error) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		return "/sys/fs/cgroup/unified", nil
	})

	const concurrency = 16
	paths := make([]string, concurrency)
	errs := make([]error, concurrency)
	var wg sync.WaitGroup
	for i := range concurrency {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			paths[idx], errs[idx] = detectCgroupPath()
		}(i)
	}
	wg.Wait()

	for i := range concurrency {
		if errs[i] != nil {
			t.Fatalf("err[%d] = %v, want nil", i, errs[i])
		}
		if paths[i] != paths[0] {
			t.Fatalf("path[%d] = %q, want %q", i, paths[i], paths[0])
		}
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	if calls != 1 {
		t.Fatalf("concurrent callers must share one scan, scans = %d", calls)
	}
}
