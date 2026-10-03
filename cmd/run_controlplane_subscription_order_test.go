/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"slices"
	"testing"

	"github.com/daeuniverse/dae/config"
)

// TestMergeSubscriptionResultsKeepsConfigOrderAcrossReloads pins the stable
// within-tag order: subscription fetches complete in parallel, but two
// subscription entries sharing one tag must fold their nodes in subscription
// config order on every reload, because the within-tag node order decides what
// fixed(0) selects. Fetch results are indexed by config position, so the
// completion order — varied on every simulated reload below by writing the
// slots in a different order — must not leak into the merged list.
func TestMergeSubscriptionResultsKeepsConfigOrderAcrossReloads(t *testing.T) {
	subA := subscriptionResult{
		tag:   "shared",
		sub:   config.KeyableString("https://example.com/a"),
		nodes: []string{"node-a1", "node-a2"},
	}
	subB := subscriptionResult{
		tag:   "shared",
		sub:   config.KeyableString("https://example.com/b"),
		nodes: []string{"node-b1"},
	}
	want := []string{"node-a1", "node-a2", "node-b1"}

	for reload := range 8 {
		results := make([]subscriptionResult, 2)
		if reload%2 == 0 {
			// Subscription A's fetch lands in its slot first.
			results[0] = subA
			results[1] = subB
		} else {
			// Subscription B's goroutine finishes first; it still writes its
			// own config-position slot, so the merge order must not change.
			results[1] = subB
			results[0] = subA
		}
		tagToNodeList := map[string][]string{"": {"inline-node"}}
		if failed := mergeSubscriptionResults(discardLogger(), tagToNodeList, results); failed {
			t.Fatalf("reload %d: merge reported a failure although no result failed", reload)
		}
		if got := tagToNodeList["shared"]; !slices.Equal(got, want) {
			t.Fatalf("reload %d: within-tag node order = %v, want %v (subscription config order)", reload, got, want)
		}
	}
}
