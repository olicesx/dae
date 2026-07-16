/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"testing"

	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestPhase5DnsResolvePipelineMatchesLegacyCorpus exercises the fixed Phase 0
// DNS corpus through both handler implementations. It compares the complete
// response wire (apart from elapsed TTLs), error outcome, cache scope, and
// selected upstream/dial route. A new fixture is constructed for each mode so
// its counters and preloaded cache do not cross the compatibility boundary.
func TestPhase5DnsResolvePipelineMatchesLegacyCorpus(t *testing.T) {
	fixtures := DnsCorpusFixtures()
	for fixtureIndex, fixture := range fixtures {
		fixtureIndex, fixture := fixtureIndex, fixture
		t.Run(fixture.Name, func(t *testing.T) {
			legacyFixture := DnsCorpusFixtures()[fixtureIndex]
			pipelineFixture := DnsCorpusFixtures()[fixtureIndex]
			require.Equal(t, fixture.Name, legacyFixture.Name)
			require.Equal(t, fixture.Name, pipelineFixture.Name)

			legacy := replayDnsCorpusHandlerMode(t, legacyFixture, false)
			pipeline := replayDnsCorpusHandlerMode(t, pipelineFixture, true)
			require.Equal(t, legacy, pipeline)
		})
	}
}

func TestPhase5DnsResolvePipelineLongReplay(t *testing.T) {
	const rounds = 256
	fixtures := DnsCorpusFixtures()
	for round := 0; round < rounds; round++ {
		for fixtureIndex, fixture := range fixtures {
			fixtureIndex, fixture := fixtureIndex, fixture
			t.Run(fmt.Sprintf("round_%02d/%s", round, fixture.Name), func(t *testing.T) {
				legacyFixture := DnsCorpusFixtures()[fixtureIndex]
				pipelineFixture := DnsCorpusFixtures()[fixtureIndex]
				legacy := replayDnsCorpusHandlerMode(t, legacyFixture, false)
				pipeline := replayDnsCorpusHandlerMode(t, pipelineFixture, true)
				require.Equal(t, legacy, pipeline, "legacy/pipeline DNS observation mismatch")
			})
		}
	}
}

func TestPhase5DnsResolvePipelineDeterministicMutationMatrix(t *testing.T) {
	const mutationsPerCase = 128
	fixtures := DnsCorpusFixtures()

	for fixtureIndex, fixture := range fixtures {
		for caseIndex, tc := range fixture.Cases {
			fixtureIndex, caseIndex, tc := fixtureIndex, caseIndex, tc
			t.Run(fmt.Sprintf("fixture_%02d/case_%02d", fixtureIndex, caseIndex), func(t *testing.T) {
				for mutation := 0; mutation < mutationsPerCase; mutation++ {
					query := tc.Query()
					if query == nil || len(query.Question) == 0 {
						t.Fatalf("DNS corpus case has no question")
					}
					query.Id = uint16(0x4000 + mutation)
					query.Question[0].Name = fuzzDnsCorpusQName([]byte(fmt.Sprintf(
						"%s-%d-%d", fixture.Name, caseIndex, mutation,
					)))
					query.Question[0].Qtype = fuzzDnsCorpusQtype(uint16(mutation))

					legacy := observeDnsCorpusFuzzHandler(t, fixtures[fixtureIndex], tc, query, false)
					pipeline := observeDnsCorpusFuzzHandler(t, fixtures[fixtureIndex], tc, query, true)
					if legacy != pipeline {
						t.Fatalf("mutation %d legacy/pipeline mismatch\\nlegacy:  %+v\\npipeline: %+v", mutation, legacy, pipeline)
					}
				}
			})
		}
	}
}

type dnsCorpusHandlerObservation struct {
	Cases  []dnsCorpusHandlerCaseObservation
	Routes []dnsCorpusRouteObservation
}

type dnsCorpusHandlerCaseObservation struct {
	Name      string
	Error     string
	Response  string
	CacheKeys []string
}

type dnsCorpusRouteObservation struct {
	Upstream  string
	L4Proto   string
	IPVersion string
	Target    string
}

func replayDnsCorpusHandlerMode(t *testing.T, fixture DnsCorpusFixture, useResolvePipeline bool) dnsCorpusHandlerObservation {
	t.Helper()
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
			return fixture.ForwarderFactory(upstream, dialArg, log)
		}
	}

	observation := dnsCorpusHandlerObservation{
		Cases: make([]dnsCorpusHandlerCaseObservation, 0, len(fixture.Cases)),
	}
	for _, tc := range fixture.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			if tc.PreState != nil {
				tc.PreState(t, ctrl)
			}
			request := defaultUdpRequest()
			if tc.Request != nil {
				request = tc.Request()
			}
			query := tc.Query()
			require.NotNil(t, query, "%s: nil Query in case %s", fixture.Name, tc.Name)

			writer := &dnsCorpusCaptureWriter{}
			err := ctrl.HandleWithResponseWriter_(context.Background(), query, request, writer)
			caseObservation := dnsCorpusHandlerCaseObservation{
				Name:      tc.Name,
				CacheKeys: dnsCorpusObservedCacheKeys(ctrl),
			}
			if err != nil {
				caseObservation.Error = err.Error()
				observation.Cases = append(observation.Cases, caseObservation)
				return
			}
			message := writer.Message()
			require.NotNil(t, message, "%s: no response captured", tc.Name)
			assertDnsShape(t, tc.Expected, message)
			assertDnsWire(t, tc.Expected.WireHex, writer.Wire())
			if tc.PostAssert != nil {
				tc.PostAssert(t, ctrl, message)
			}

			caseObservation.CacheKeys = dnsCorpusObservedCacheKeys(ctrl)
			if wire := writer.Wire(); len(wire) != 0 {
				canonical, canonicalErr := canonicalDnsWire(wire)
				require.NoError(t, canonicalErr, "%s: canonicalize response", tc.Name)
				caseObservation.Response = hex.EncodeToString(canonical)
			}
			observation.Cases = append(observation.Cases, caseObservation)
		})
	}

	routesMu.Lock()
	observation.Routes = append(observation.Routes, routes...)
	routesMu.Unlock()
	sort.Slice(observation.Routes, func(i, j int) bool {
		left := observation.Routes[i]
		right := observation.Routes[j]
		if left.Upstream != right.Upstream {
			return left.Upstream < right.Upstream
		}
		if left.L4Proto != right.L4Proto {
			return left.L4Proto < right.L4Proto
		}
		if left.IPVersion != right.IPVersion {
			return left.IPVersion < right.IPVersion
		}
		return left.Target < right.Target
	})
	return observation
}

func dnsCorpusObservedCacheKeys(ctrl *DnsController) []string {
	if ctrl == nil {
		return nil
	}
	var keys []string
	ctrl.dnsCache.Range(func(key, _ any) bool {
		if cacheKey, ok := key.(string); ok {
			keys = append(keys, cacheKey)
		}
		return true
	})
	sort.Strings(keys)
	return keys
}
