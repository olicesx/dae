/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"slices"
	"testing"
)

// TestSortedSubscriptionTagsIsDeterministic pins the ordering contract the
// fixed(N) policy depends on: example.dae documents fixed(0) as "Select the
// first node from the group", which is only meaningful when the subscription
// tags (and therefore the dialer list) iterate in a stable order instead of
// Go's randomized map order.
func TestSortedSubscriptionTagsIsDeterministic(t *testing.T) {
	tagToNodeList := map[string][]string{
		"sub-b": {"node3"},
		"":      {"node0"},
		"sub-a": {"node1", "node2"},
	}
	want := []string{"", "sub-a", "sub-b"}
	for i := 0; i < 16; i++ {
		if got := sortedSubscriptionTags(tagToNodeList); !slices.Equal(got, want) {
			t.Fatalf("iteration %d: sortedSubscriptionTags = %v, want %v", i, got, want)
		}
	}
}
