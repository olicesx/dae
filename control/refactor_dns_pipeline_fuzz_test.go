/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var dnsCorpusFuzzForwarderMu sync.Mutex

// FuzzPhase5DnsResolvePipelineEquivalence mutates the fixed Phase 0 DNS
// corpus at the request boundary and compares the legacy handler with the
// resolver/delivery split. The comparison covers the complete response wire
// apart from elapsed TTLs, returned errors, cache ownership keys, and the
// upstream delivery route. It intentionally leaves the legacy handler
// authoritative; any difference is a regression signal rather than a cutover.
func FuzzPhase5DnsResolvePipelineEquivalence(f *testing.F) {
	fixtures := DnsCorpusFixtures()
	for fixtureIndex, fixture := range fixtures {
		for caseIndex, tc := range fixture.Cases {
			query := tc.Query()
			if query == nil || len(query.Question) == 0 {
				continue
			}
			f.Add(
				byte(fixtureIndex),
				byte(caseIndex),
				append([]byte(nil), query.Question[0].Name...),
				query.Question[0].Qtype,
				query.Id,
			)
		}
	}

	f.Fuzz(func(t *testing.T, fixtureIndex, caseIndex byte, nameBytes []byte, qtype, id uint16) {
		fixture := fixtures[int(fixtureIndex)%len(fixtures)]
		tc := fixture.Cases[int(caseIndex)%len(fixture.Cases)]
		query := tc.Query()
		if query == nil || len(query.Question) == 0 {
			t.Fatal("DNS corpus case has no question")
		}
		query.Id = id
		query.Question[0].Name = fuzzDnsCorpusQName(nameBytes)
		query.Question[0].Qtype = fuzzDnsCorpusQtype(qtype)
		query.Question[0].Qclass = dnsmessage.ClassINET

		legacy := observeDnsCorpusFuzzHandler(t, fixture, tc, query, false)
		pipeline := observeDnsCorpusFuzzHandler(t, fixture, tc, query, true)
		if legacy != pipeline {
			t.Fatalf("legacy/pipeline DNS observation mismatch\nlegacy:  %+v\npipeline: %+v", legacy, pipeline)
		}
	})
}

type dnsCorpusFuzzObservation struct {
	Error     string
	Response  string
	CacheKeys string
	Routes    string
}

func observeDnsCorpusFuzzHandler(
	t *testing.T,
	fixture DnsCorpusFixture,
	tc DnsCorpusCase,
	query *dnsmessage.Msg,
	useResolvePipeline bool,
) dnsCorpusFuzzObservation {
	t.Helper()

	// dnsForwarderFactory is a package-level test seam. Fuzz workers can
	// execute this target repeatedly, so keep each temporary factory installed
	// only while its fresh controller is handling the request.
	dnsCorpusFuzzForwarderMu.Lock()
	defer dnsCorpusFuzzForwarderMu.Unlock()

	originalFactory := dnsForwarderFactory
	defer func() { dnsForwarderFactory = originalFactory }()

	ctrl := newCorpusDnsControllerWithResolvePipeline(t, fixture.BuildConfig(), useResolvePipeline)
	chooser := fixture.BestDialerChooser
	if chooser == nil {
		chooser = defaultCorpusChooser
	}
	setScopedBestDialerChooser(ctrl, chooser)

	var routesMu sync.Mutex
	var routes []dnsCorpusRouteObservation
	routeObserved := make(chan struct{}, 1)
	if fixture.ForwarderFactory != nil {
		dnsForwarderFactory = func(upstream *componentdns.Upstream, dialArg dialArgument, log *logrus.Logger) (DnsForwarder, error) {
			route := dnsCorpusRouteObservation{
				L4Proto:   string(dialArg.l4proto),
				IPVersion: string(dialArg.ipversion),
				Target:    dialArg.bestTarget.String(),
			}
			if upstream != nil {
				route.Upstream = upstream.String()
			}
			routesMu.Lock()
			routes = append(routes, route)
			routesMu.Unlock()
			select {
			case routeObserved <- struct{}{}:
			default:
			}
			return fixture.ForwarderFactory(upstream, dialArg, log)
		}
	}

	if tc.PreState != nil {
		tc.PreState(t, ctrl)
	}
	request := defaultUdpRequest()
	if tc.Request != nil {
		request = tc.Request()
	}
	writer := &dnsCorpusCaptureWriter{}
	observation := dnsCorpusFuzzObservation{}
	if err := ctrl.HandleWithResponseWriter_(context.Background(), query.Copy(), request, writer); err != nil {
		observation.Error = err.Error()
	} else if wire := writer.Wire(); len(wire) != 0 {
		canonical, canonicalErr := canonicalDnsWire(wire)
		if canonicalErr != nil {
			t.Fatalf("canonicalize DNS response: %v", canonicalErr)
		}
		observation.Response = hex.EncodeToString(canonical)
	}
	if dnsCorpusFuzzMayTriggerStaleRefresh(fixture, query) {
		select {
		case <-routeObserved:
		case <-time.After(time.Second):
			t.Fatal("stale DNS refresh did not reach the delivery route boundary")
		}
	}

	observation.CacheKeys = joinDnsCorpusCacheKeys(ctrl)
	routesMu.Lock()
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Upstream != routes[j].Upstream {
			return routes[i].Upstream < routes[j].Upstream
		}
		if routes[i].L4Proto != routes[j].L4Proto {
			return routes[i].L4Proto < routes[j].L4Proto
		}
		if routes[i].IPVersion != routes[j].IPVersion {
			return routes[i].IPVersion < routes[j].IPVersion
		}
		return routes[i].Target < routes[j].Target
	})
	for _, route := range routes {
		observation.Routes += route.Upstream + "\x00" + route.L4Proto + "\x00" + route.IPVersion + "\x00" + route.Target + "\x00"
	}
	routesMu.Unlock()
	return observation
}

func dnsCorpusFuzzMayTriggerStaleRefresh(fixture DnsCorpusFixture, query *dnsmessage.Msg) bool {
	if fixture.Name != "udp_cache_stale_optimistic" || query == nil || len(query.Question) == 0 {
		return false
	}
	question := query.Question[0]
	return strings.EqualFold(question.Name, "stale.test.") && question.Qtype == dnsmessage.TypeA
}

func joinDnsCorpusCacheKeys(ctrl *DnsController) string {
	keys := dnsCorpusObservedCacheKeys(ctrl)
	result := ""
	for _, key := range keys {
		result += key + "\x00"
	}
	return result
}

func fuzzDnsCorpusQName(input []byte) string {
	if isDnsCorpusQName(input) {
		return string(input)
	}
	if len(input) == 0 {
		return "fuzz.invalid."
	}
	if len(input) > 120 {
		input = input[:120]
	}

	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	name := ""
	for i, value := range input {
		if i > 0 && i%30 == 0 {
			name += "."
		}
		name += string(alphabet[int(value)%len(alphabet)])
	}
	return name + "."
}

func isDnsCorpusQName(name []byte) bool {
	if len(name) < 2 || len(name) > 253 || name[len(name)-1] != '.' {
		return false
	}

	labelLength := 0
	for _, value := range name[:len(name)-1] {
		switch {
		case value >= 'a' && value <= 'z', value >= 'A' && value <= 'Z', value >= '0' && value <= '9', value == '-':
			labelLength++
			if labelLength > 63 {
				return false
			}
		case value == '.':
			if labelLength == 0 {
				return false
			}
			labelLength = 0
		default:
			return false
		}
	}
	return labelLength != 0
}

func fuzzDnsCorpusQtype(value uint16) uint16 {
	switch value % 4 {
	case 0:
		return dnsmessage.TypeA
	case 1:
		return dnsmessage.TypeAAAA
	case 2:
		return dnsmessage.TypeTXT
	default:
		return dnsmessage.TypeCNAME
	}
}
