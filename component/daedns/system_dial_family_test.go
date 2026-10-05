/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

// TestLookupSystemIPAddrDoesNotInheritRequestedFamily pins the same contract
// as TestLookupBootstrapIPAddrDoesNotInheritRequestedFamily on the system-DNS
// leg of the node-address race: the system resolver is a fixed address (read
// from /etc/resolv.conf, or the configured fallback), so the family used to
// dial it follows from that address. Inheriting the family requested by the
// caller made a v6-origin flow dial a v4 resolver literal over "udp6", which
// Go rejects with "no suitable address found" and which took down the whole
// system leg instead of merely returning no v6 answer. The requested family
// only filters the answers.
func TestLookupSystemIPAddrDoesNotInheritRequestedFamily(t *testing.T) {
	cases := []struct {
		label   string
		network string
	}{
		{"udp6", "udp6"},
		{"tcp6", "tcp6"},
		{"magic-udp-ipv6", common.MagicNetworkWithIPVersion("udp", 0, false, "6")},
		{"udp4", "udp4"},
		{"udp", "udp"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			d := &recordingDialer{}
			r := &Router{
				directDialer: d,
				systemDNS: stubSystemDNS{
					addr: netip.MustParseAddrPort("192.0.2.1:53"),
				},
				log: quietLogger(),
			}

			_, _ = r.lookupSystemIPAddr(context.Background(), tc.network, "node.example.test")

			attempts := d.recorded()
			if len(attempts) == 0 {
				t.Fatal("system resolution dialed nothing")
			}
			for _, attempt := range attempts {
				mn, err := netproxy.ParseMagicNetwork(attempt)
				if err != nil {
					t.Fatalf("dial attempt %q: %v", attempt, err)
				}
				if mn.IPVersion != "" {
					t.Errorf("dial %q carried IPVersion %q, want family-agnostic dialing",
						attempt, mn.IPVersion)
				}
			}
		})
	}
}
