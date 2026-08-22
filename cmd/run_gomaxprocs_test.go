/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"runtime"
	"testing"
)

func TestConfigureGOMAXPROCSDefaultsToOne(t *testing.T) {
	previous := runtime.GOMAXPROCS(runtime.NumCPU())
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	orig, had := os.LookupEnv("GOMAXPROCS")
	os.Unsetenv("GOMAXPROCS")
	t.Cleanup(func() {
		if had {
			os.Setenv("GOMAXPROCS", orig)
		}
	})

	configureGOMAXPROCS(nil)
	if got := runtime.GOMAXPROCS(0); got != 1 {
		t.Fatalf("configureGOMAXPROCS() left GOMAXPROCS at %d, want 1", got)
	}
}

func TestConfigureGOMAXPROCSRespectsExplicitEnvironment(t *testing.T) {
	const sentinel = 2
	previous := runtime.GOMAXPROCS(sentinel)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	t.Setenv("GOMAXPROCS", "2")

	configureGOMAXPROCS(nil)
	if got := runtime.GOMAXPROCS(0); got != sentinel {
		t.Fatalf("configureGOMAXPROCS() changed explicit GOMAXPROCS to %d, want %d", got, sentinel)
	}
}
