/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import "testing"

// TestEngineNameReportsTheFork pins the engine name a panel shows and keys
// its adapter choice on. Only "honk" selects a non-generic adapter, so the
// fork must answer under its own name: as "dae" it would pose as upstream,
// and as "honk" it would be driven through an API it does not implement.
func TestEngineNameReportsTheFork(t *testing.T) {
	if EngineName != "kdae" {
		t.Fatalf("EngineName = %q, want the fork's own name", EngineName)
	}
}
