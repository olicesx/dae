/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// During a staged reload the previous plane keeps serving traffic while its
// DNS knowledge has already moved to the handoff controller. ChooseDialTarget
// must consult that controller, not only the plane's own (frozen) one, or
// dial_mode domain stays stuck on IP targets until the next generation takes
// over.

func newDialTargetHandoffPlane(t *testing.T, handoff *DnsController) *ControlPlane {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	plane := &ControlPlane{
		log: log,
		controlPlaneGenerationState: controlPlaneGenerationState{
			dialMode: consts.DialMode_Domain,
		},
	}
	if handoff != nil {
		plane.SetDNSHandoffController(handoff)
	}
	return plane
}

func TestChooseDialTargetUsesHandoffDnsKnowledge(t *testing.T) {
	const domain = "example.com"
	dst := netip.MustParseAddrPort("203.0.113.7:443")

	controller := &DnsController{dnsControllerStore: newDnsControllerStore()}
	controller.rememberDnsKnowledge(
		controller.cacheKey(domain, dnsmessage.TypeA),
		time.Now().Add(time.Minute),
		false,
	)
	// The plane carries no controller of its own: the knowledge reachable for
	// dial-target selection lives exclusively in the handoff slot.
	plane := newDialTargetHandoffPlane(t, controller)

	dialTarget, shouldReroute, dialIp := plane.ChooseDialTarget(consts.OutboundIndex(100), dst, domain)
	if dialTarget != "example.com:443" {
		t.Fatalf("dialTarget = %q, want example.com:443", dialTarget)
	}
	if !shouldReroute {
		t.Fatal("handoff DNS knowledge should enable the domain reroute")
	}
	if dialIp {
		t.Fatal("expected a domain dial target, got IP dial mode")
	}
}

func TestChooseDialTargetWithoutHandoffKnowledgeKeepsIPTarget(t *testing.T) {
	const domain = "unknown.example.org"
	dst := netip.MustParseAddrPort("203.0.113.9:443")

	plane := newDialTargetHandoffPlane(t, nil)
	// Pin the negative cache so the asynchronous real-domain probe is not
	// spawned: its lifecycle is not wired up in this bare plane.
	plane.realDomainNegSet.Store(domain, time.Now().Add(time.Minute).UnixNano())

	dialTarget, shouldReroute, dialIp := plane.ChooseDialTarget(consts.OutboundIndex(100), dst, domain)
	if dialTarget != "203.0.113.9:443" {
		t.Fatalf("dialTarget = %q, want the IP target", dialTarget)
	}
	if shouldReroute || !dialIp {
		t.Fatal("without DNS knowledge the dial target must stay IP")
	}
}
