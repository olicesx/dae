/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

// A host the caller resolved itself needs no cache knowledge: the dial-mode
// policy alone decides, nothing is probed, and a reserved outbound or an IP
// host keeps the numeric destination.
func TestDialTargetForResolvedDomainFollowsDialMode(t *testing.T) {
	dst := netip.MustParseAddrPort("185.199.108.133:443")
	proxy := consts.OutboundUserDefinedMin + 1
	const domain = "raw.githubusercontent.com"
	for _, tt := range []struct {
		mode consts.DialMode
		want string
	}{
		{consts.DialMode_Domain, domain + ":443"},
		{consts.DialMode_DomainPlus, domain + ":443"},
		{consts.DialMode_DomainCao, domain + ":443"},
		{consts.DialMode_Ip, dst.String()},
	} {
		c := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{dialMode: tt.mode}}
		if got := c.DialTargetForResolvedDomain(proxy, dst, domain); got != tt.want {
			t.Fatalf("dial mode %v: dial target = %q, want %q", tt.mode, got, tt.want)
		}
		for _, outbound := range []consts.OutboundIndex{consts.OutboundDirect, consts.OutboundBlock} {
			if got := c.DialTargetForResolvedDomain(outbound, dst, domain); got != dst.String() {
				t.Fatalf("dial mode %v: %v dial target = %q, want the numeric destination", tt.mode, outbound, got)
			}
		}
	}
	c := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{dialMode: consts.DialMode_Domain}}
	for _, host := range []string{"", "185.199.108.133", "[2606:50c0::154]"} {
		if got := c.DialTargetForResolvedDomain(proxy, dst, host); got != dst.String() {
			t.Fatalf("host %q: dial target = %q, want the numeric destination", host, got)
		}
	}
}
