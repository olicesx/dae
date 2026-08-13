/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import (
	"testing"

	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

// Locks the CVE-2025-37959 gate matrix: mainline fix is 6.14.7 (not 6.8),
// with official stable backports 6.1.139 / 6.6.91 / 6.12.29.
func TestIsRedirectPeerSafeKernel(t *testing.T) {
	safe := []internal.Version{
		{6, 14, 7},               // mainline fix
		{6, 15, 0},               // later mainline
		{7, 0, 0},                // future major
		{6, 1, 139}, {6, 1, 140}, // stable backport and later
		{6, 6, 91}, {6, 6, 200}, // stable backport and later
		{6, 12, 29}, {6, 12, 100}, // stable backport and later
	}
	unsafe := []internal.Version{
		{6, 8, 0},    // the old, incorrect threshold
		{6, 14, 6},   // just below the mainline fix
		{6, 1, 138},  // just below the backport
		{6, 6, 90},   // just below the backport
		{6, 12, 28},  // just below the backport
		{5, 15, 200}, // EOL series without backport
	}
	for _, v := range safe {
		if !IsRedirectPeerSafeKernel(v) {
			t.Errorf("expected kernel %v to be considered safe", v)
		}
	}
	for _, v := range unsafe {
		if IsRedirectPeerSafeKernel(v) {
			t.Errorf("expected kernel %v to be considered unsafe", v)
		}
	}
}
