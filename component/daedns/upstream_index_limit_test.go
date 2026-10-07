/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
)

// TestInitUpstreamsRejectsMoreUpstreamsThanTheIndexRangeHolds pins the cap that
// dns.New also enforces: UpstreamName2Id truncates each raw index to uint8, so
// the 252nd upstream would collide with the reserved request/response index
// values (or wrap around), and the ids the matchers build would no longer index
// upstreamByIndex.
func TestInitUpstreamsRejectsMoreUpstreamsThanTheIndexRangeHolds(t *testing.T) {
	max := int(consts.DnsRequestOutboundIndex_UserDefinedMax)
	if responseMax := int(consts.DnsResponseOutboundIndex_UserDefinedMax); responseMax < max {
		max = responseMax
	}

	accepted := make([]config.KeyableString, 0, max)
	for i := 0; i < max; i++ {
		// KeyableString entries are "tag:link" (see Marshaller.marshalStringList,
		// which re-quotes the link after splitting on the first colon).
		accepted = append(accepted, config.KeyableString(fmt.Sprintf("tag%d:udp://192.0.2.%d:53", i, i%254+1)))
	}
	router := &Router{upstreams: map[string]*componentdns.UpstreamResolver{}}
	if err := router.initUpstreams(accepted); err != nil {
		t.Fatalf("initUpstreams rejected %d upstreams, want them accepted: %v", max, err)
	}
	if got := len(router.upstreamByIndex); got != max {
		t.Fatalf("upstreamByIndex holds %d entries, want %d", got, max)
	}

	tooMany := slices.Concat(accepted, []config.KeyableString{
		config.KeyableString(fmt.Sprintf("tag%d:udp://192.0.2.200:53", max)),
	})
	overflowing := &Router{upstreams: map[string]*componentdns.UpstreamResolver{}}
	err := overflowing.initUpstreams(tooMany)
	if err == nil {
		t.Fatalf("initUpstreams accepted %d upstreams; the id of the last one would collide with the reserved index range", len(tooMany))
	}
	if !strings.Contains(err.Error(), "too many upstreams") {
		t.Fatalf("initUpstreams rejected the overflow with %q, want the same error dns.New returns", err)
	}
	if len(overflowing.upstreamByIndex) != 0 {
		t.Fatalf("rejecting the overflow still registered %d upstreams", len(overflowing.upstreamByIndex))
	}
}
