/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func BenchmarkPhase0LegacyRoutingMatch(b *testing.B) {
	fixture := domainSuffixFixture()
	matcher := benchmarkRoutingMatcher(b, fixture)
	input := fixture.Cases[0].Input

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _, _, _ = matchCorpusInput(matcher, input)
	}
}

func BenchmarkPhase0LegacyRoutingCorpusMatrix(b *testing.B) {
	type benchmarkCase struct {
		matcher *RoutingMatcher
		input   CorpusInput
	}

	fixtures := RoutingCorpusFixtures()
	cases := make([]benchmarkCase, 0)
	for _, fixture := range fixtures {
		matcher := benchmarkRoutingMatcher(b, fixture)
		for _, corpusCase := range fixture.Cases {
			cases = append(cases, benchmarkCase{matcher: matcher, input: corpusCase.Input})
		}
	}
	if len(cases) == 0 {
		b.Fatal("routing corpus has no benchmark cases")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for index := range b.N {
		corpusCase := cases[index%len(cases)]
		_, _, _, _ = matchCorpusInput(corpusCase.matcher, corpusCase.input)
	}
}

func BenchmarkPhase3DecisionShadowEvaluate(b *testing.B) {
	fixture := domainSuffixFixture()
	shadow := benchmarkDecisionShadow(b, fixture)
	input := phase4DecisionShadowInput{
		source:      staticSrcV4(),
		destination: staticDstV4(),
		domain:      "api.example.com",
		domainKnown: true,
		l4Proto:     consts.L4ProtoType_TCP,
		evidence:    routing.EvidenceTLSSNI,
	}

	for _, variant := range []struct {
		name  string
		proto consts.L4ProtoType
		evid  routing.EvidenceSource
	}{
		{name: "tcp_tls", proto: consts.L4ProtoType_TCP, evid: routing.EvidenceTLSSNI},
		{name: "udp_quic", proto: consts.L4ProtoType_UDP, evid: routing.EvidenceQUICSNI},
	} {
		variant := variant
		b.Run(variant.name, func(b *testing.B) {
			input.l4Proto = variant.proto
			input.evidence = variant.evid
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_, _ = shadow.evaluate(input, routing.Continuation{})
			}
		})
	}
}

func BenchmarkPhase5DnsCacheHit(b *testing.B) {
	fixture := udpCacheHitFixture()
	for _, variant := range []struct {
		name     string
		pipeline bool
	}{
		{name: "legacy"},
		{name: "resolve_pipeline", pipeline: true},
	} {
		variant := variant
		b.Run(variant.name, func(b *testing.B) {
			ctrl := newCorpusDnsControllerWithResolvePipeline(b, fixture.BuildConfig(), variant.pipeline)
			request := defaultUdpRequest()
			baseKey := ctrl.cacheKey("cache-hit.test.", dnsmessage.TypeA)
			cacheKey := ctrl.responseCacheKey(
				baseKey, request,
				consts.DnsRequestOutboundIndex_AsIs, nil,
			)
			installCorpusCache(b, ctrl, cacheKey, "cache-hit.test.", dnsmessage.TypeA, dnsAResponseMsg("cache-hit.test.", "203.0.113.42").Answer, 300)
			query := corpusDnsQuery(0x1200, "cache-hit.test.", dnsmessage.TypeA)

			b.ReportAllocs()
			b.ResetTimer()
			for index := range b.N {
				query.Id = uint16(0x1200 + index)
				writer := &dnsCorpusCaptureWriter{}
				if err := ctrl.HandleWithResponseWriter_(context.Background(), query, request, writer); err != nil {
					b.Fatalf("DNS cache hit = %v", err)
				}
			}
		})
	}
}

func TestPhase3DecisionShadowAllocationBudget(t *testing.T) {
	shadow := benchmarkDecisionShadow(t, domainSuffixFixture())
	input := phase4DecisionShadowInput{
		source:      staticSrcV4(),
		destination: staticDstV4(),
		domain:      "api.example.com",
		domainKnown: true,
		l4Proto:     consts.L4ProtoType_TCP,
		evidence:    routing.EvidenceTLSSNI,
	}

	const maxAllocsPerEvaluation = 24
	allocs := testing.AllocsPerRun(1000, func() {
		decision, failure := shadow.evaluate(input, routing.Continuation{})
		if failure != Phase4DecisionShadowFailureNone || decision.State != routing.DecisionResolved {
			t.Fatalf("shadow evaluation = (%+v,%v), want resolved decision", decision, failure)
		}
	})
	if allocs > maxAllocsPerEvaluation {
		t.Fatalf("shadow evaluation allocations = %.1f, want <= %d", allocs, maxAllocsPerEvaluation)
	}
}

func TestPhase3DecisionShadowCPUBudget(t *testing.T) {
	fixture := domainSuffixFixture()
	matcher := benchmarkRoutingMatcher(t, fixture)
	legacyInput := fixture.Cases[0].Input

	const maxShadowCPUFactor = 4
	for _, variant := range []struct {
		name  string
		proto consts.L4ProtoType
		evid  routing.EvidenceSource
	}{
		{name: "tcp_tls", proto: consts.L4ProtoType_TCP, evid: routing.EvidenceTLSSNI},
		{name: "udp_quic", proto: consts.L4ProtoType_UDP, evid: routing.EvidenceQUICSNI},
	} {
		variant := variant
		t.Run(variant.name, func(t *testing.T) {
			shadow := benchmarkDecisionShadow(t, fixture)
			shadowInput := phase4DecisionShadowInput{
				source:      staticSrcV4(),
				destination: staticDstV4(),
				domain:      "api.example.com",
				domainKnown: true,
				l4Proto:     variant.proto,
				evidence:    variant.evid,
			}
			if decision, failure := shadow.evaluate(shadowInput, routing.Continuation{}); failure != Phase4DecisionShadowFailureNone || decision.State != routing.DecisionResolved {
				t.Fatalf("shadow evaluation = (%+v,%v), want resolved decision", decision, failure)
			}

			legacy := testing.Benchmark(func(b *testing.B) {
				for range b.N {
					_, _, _, _ = matchCorpusInput(matcher, legacyInput)
				}
			})
			shadowResult := testing.Benchmark(func(b *testing.B) {
				for range b.N {
					_, _ = shadow.evaluate(shadowInput, routing.Continuation{})
				}
			})
			legacyNs := legacy.NsPerOp()
			shadowNs := shadowResult.NsPerOp()
			if legacyNs <= 0 || shadowNs <= 0 {
				t.Fatalf("invalid benchmark results: legacy=%d ns/op shadow=%d ns/op", legacyNs, shadowNs)
			}
			if shadowNs > legacyNs*maxShadowCPUFactor {
				t.Fatalf("shadow CPU = %d ns/op, legacy = %d ns/op, want <= %dx legacy", shadowNs, legacyNs, maxShadowCPUFactor)
			}
		})
	}
}

func benchmarkRoutingMatcher(b testing.TB, fixture CorpusFixture) *RoutingMatcher {
	b.Helper()
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		fixture.Rules,
		fixture.OutboundIDs,
		nil,
		fixture.Fallback,
	)
	if err != nil {
		b.Fatalf("NewRoutingMatcherBuilder() error = %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		b.Fatalf("BuildUserspace() error = %v", err)
	}
	return matcher
}

func benchmarkDecisionShadow(b testing.TB, fixture CorpusFixture) *phase4DecisionShadow {
	b.Helper()
	program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
	if err != nil {
		b.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	snapshot, err := routing.NewPolicySnapshot(101, program)
	if err != nil {
		b.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	compiled, err := snapshot.Compile(logrus.New(), fixture.OutboundIDs)
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}
	shadow, err := newPhase4DecisionShadow(snapshot, compiled, 1)
	if err != nil {
		b.Fatalf("newPhase4DecisionShadow() error = %v", err)
	}
	return shadow
}
