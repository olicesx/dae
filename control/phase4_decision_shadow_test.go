/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestPhase4DecisionShadowMatchesLegacyRoutingCorpus(t *testing.T) {
	for _, fixture := range RoutingCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			program, err := routing.NewNormalizedProgram(fixture.Rules, fixture.Fallback)
			if err != nil {
				t.Fatalf("NewNormalizedProgram() error = %v", err)
			}
			snapshot, err := routing.NewPolicySnapshot(61, program)
			if err != nil {
				t.Fatalf("NewPolicySnapshot() error = %v", err)
			}
			compiled, err := snapshot.Compile(logrus.New(), fixture.OutboundIDs)
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}
			shadow, err := newPhase4DecisionShadow(snapshot, compiled, 1)
			if err != nil {
				t.Fatalf("newPhase4DecisionShadow() error = %v", err)
			}
			matcher := fixture.BuildMatcher(t)

			for _, tc := range fixture.Cases {
				legacyOutbound, legacyMark, legacyMust, err := matchCorpusInput(matcher, tc.Input)
				if err != nil {
					t.Fatalf("%s: legacy Match() error = %v", tc.Name, err)
				}
				shadow.Observe(phase4DecisionShadowInput{
					source:      tc.Input.Src,
					destination: tc.Input.Dst,
					l4Proto:     tc.Input.L4Proto,
					domain:      tc.Input.Domain,
					domainKnown: true,
					evidence:    evidenceForCorpusInput(tc.Input),
					processName: tc.Input.ProcessName,
					dscp:        tc.Input.Dscp,
					mac:         tc.Input.Mac,
				}, LegacyRouteOutcome{Outbound: legacyOutbound, Mark: legacyMark, Must: legacyMust})
			}

			got := shadow.Snapshot()
			if got.Sampled != uint64(len(fixture.Cases)) || got.Matched != uint64(len(fixture.Cases)) {
				t.Fatalf("shadow counters = %+v, want every corpus case matched", got)
			}
			if got.Diverged != 0 || got.Errors != 0 || !got.CutoverEligible || len(got.Evidence) != 0 {
				t.Fatalf("shadow snapshot = %+v, want zero-difference eligible result", got)
			}
		})
	}
}

func TestPhase4DecisionShadowDivergenceDoesNotChangeRoute(t *testing.T) {
	plane, snapshot := newPhase4DecisionShadowRoutePlane(t, 1)
	outbound, mark, must, err := plane.routeWithDomainFacts(
		staticSrcV4(),
		staticDstV4(),
		"",
		consts.L4ProtoType_TCP,
		&bpfRoutingResult{Pid: 731, RoutingEpochSlot: bpfRoutingEpochSlot1Encoded},
		false,
		routing.EvidenceNone,
	)
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if outbound != consts.OutboundDirect || mark != 0 || must {
		t.Fatalf("Route() tuple = (%v,%d,%v), want authoritative later direct rule", outbound, mark, must)
	}

	got, enabled := plane.Phase4DecisionShadowSnapshot()
	if !enabled {
		t.Fatal("Phase4DecisionShadowSnapshot() enabled = false")
	}
	if got.Sampled != 1 || got.Matched != 0 || got.Diverged != 1 || got.Errors != 0 || got.CutoverEligible {
		t.Fatalf("shadow snapshot = %+v, want recorded divergence and cutover block", got)
	}
	if len(got.Evidence) != 1 {
		t.Fatalf("evidence len = %d, want 1", len(got.Evidence))
	}
	evidence := got.Evidence[0]
	if evidence.Epoch != snapshot.Epoch() || evidence.PolicyHash != snapshot.Hash() || evidence.DomainKnown || evidence.PID != 731 || evidence.RoutingSlot != 1 || !evidence.RoutingSlotKnown || evidence.Legacy.Outbound != consts.OutboundDirect {
		t.Fatalf("divergence evidence = %+v, want copied unknown-domain legacy route", evidence)
	}
	if evidence.Failure != Phase4DecisionShadowFailureNone || evidence.Shadow.State != routing.DecisionDeferred {
		t.Fatalf("divergence evidence shadow = %+v, want deferred semantic difference", evidence)
	}
}

func TestPhase4DecisionShadowMatchesKnownDomainRoute(t *testing.T) {
	plane, _ := newPhase4DecisionShadowRoutePlane(t, 1)
	outbound, mark, must, err := plane.Route(
		staticSrcV4(),
		staticDstV4(),
		"api.example.test",
		consts.L4ProtoType_TCP,
		&bpfRoutingResult{},
	)
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if outbound != consts.OutboundUserDefinedMin || mark != 0 || must {
		t.Fatalf("Route() tuple = (%v,%d,%v), want proxy", outbound, mark, must)
	}
	got, enabled := plane.Phase4DecisionShadowSnapshot()
	if !enabled || got.Sampled != 1 || got.Matched != 1 || got.Diverged != 0 || got.Errors != 0 || !got.CutoverEligible || len(got.Evidence) != 0 {
		t.Fatalf("shadow snapshot = %+v enabled=%v, want eligible match", got, enabled)
	}
}

func TestPhase4DecisionShadowMatchesKnownAbsentDomainRoute(t *testing.T) {
	plane, _ := newPhase4DecisionShadowRoutePlane(t, 1)
	outbound, mark, must, err := plane.Route(
		staticSrcV4(),
		staticDstV4(),
		"",
		consts.L4ProtoType_TCP,
		&bpfRoutingResult{},
	)
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if outbound != consts.OutboundDirect || mark != 0 || must {
		t.Fatalf("Route() tuple = (%v,%d,%v), want direct", outbound, mark, must)
	}
	got, enabled := plane.Phase4DecisionShadowSnapshot()
	if !enabled || got.Sampled != 1 || got.Matched != 1 || got.Diverged != 0 || got.Errors != 0 || !got.CutoverEligible || len(got.Evidence) != 0 {
		t.Fatalf("shadow snapshot = %+v enabled=%v, want eligible known-absent match", got, enabled)
	}
}

func TestPhase4DecisionShadowUsesLiveMatcherResolver(t *testing.T) {
	plane, _ := newPhase4DecisionShadowRoutePlane(t, 1)
	shadow := plane.decisionShadow
	if got := shadow.liveMatcher.Load(); got != plane.routingMatcher {
		t.Fatalf("live matcher = %p, want control-plane matcher %p", got, plane.routingMatcher)
	}

	if _, _, _, err := plane.Route(
		staticSrcV4(),
		staticDstV4(),
		"api.example.test",
		consts.L4ProtoType_TCP,
		&bpfRoutingResult{},
	); err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if got := phase4DecisionShadowPredicateMatcherCount(shadow); got != 0 {
		t.Fatalf("isolated predicate matcher count = %d, want live-resolver path only", got)
	}
}

func TestPhase4DecisionShadowLiveResolverPreservesUnknownDomainContinuation(t *testing.T) {
	plane, snapshot := newPhase4DecisionShadowRoutePlane(t, 1)
	shadow := plane.decisionShadow
	input := phase4DecisionShadowInput{
		source:      staticSrcV4(),
		destination: staticDstV4(),
		l4Proto:     consts.L4ProtoType_TCP,
	}

	deferred, failure := shadow.evaluate(input, routing.Continuation{})
	if failure != Phase4DecisionShadowFailureNone || deferred.State != routing.DecisionDeferred {
		t.Fatalf("unknown-domain evaluation = (%+v,%v), want deferred without failure", deferred, failure)
	}
	if err := snapshot.ValidateContinuation(deferred.Continuation); err != nil {
		t.Fatalf("ValidateContinuation() error = %v", err)
	}
	if got := phase4DecisionShadowPredicateMatcherCount(shadow); got != 0 {
		t.Fatalf("isolated predicate matcher count after deferred result = %d, want 0", got)
	}

	input.domain = "api.example.test"
	input.domainKnown = true
	input.evidence = routing.EvidenceTLSSNI
	resolved, failure := shadow.evaluate(input, deferred.Continuation)
	if failure != Phase4DecisionShadowFailureNone || resolved.State != routing.DecisionResolved || resolved.Outbound != consts.OutboundUserDefinedMin {
		t.Fatalf("known-domain resume = (%+v,%v), want resolved proxy without failure", resolved, failure)
	}
	if got := phase4DecisionShadowPredicateMatcherCount(shadow); got != 0 {
		t.Fatalf("isolated predicate matcher count after resume = %d, want 0", got)
	}
}

func TestPhase4DecisionShadowResumesPendingDomainFacts(t *testing.T) {
	plane, _ := newPhase4DecisionShadowRoutePlane(t, 1)
	pending := phase4DecisionShadowInput{
		source:      staticSrcV4(),
		destination: staticDstV4(),
		l4Proto:     consts.L4ProtoType_TCP,
	}
	plane.decisionShadow.ObservePending(pending)
	before, enabled := plane.Phase4DecisionShadowSnapshot()
	if !enabled || before.Sampled != 0 || before.Deferred != 1 || before.Diverged != 0 || before.Errors != 0 || before.CutoverEligible {
		t.Fatalf("pending shadow snapshot = %+v enabled=%v, want one deferred continuation without a terminal comparison", before, enabled)
	}

	pending.domain = "api.example.test"
	pending.domainKnown = true
	pending.evidence = routing.EvidenceTLSSNI
	plane.decisionShadow.Observe(pending, LegacyRouteOutcome{Outbound: consts.OutboundUserDefinedMin})
	after, enabled := plane.Phase4DecisionShadowSnapshot()
	if !enabled || after.Sampled != 1 || after.Matched != 1 || after.Deferred != 1 || after.Diverged != 0 || after.Errors != 0 || !after.CutoverEligible || len(after.Evidence) != 0 {
		t.Fatalf("resumed shadow snapshot = %+v enabled=%v, want matching terminal resume", after, enabled)
	}
}

func TestPhase4DecisionShadowExpiresPendingDomainFacts(t *testing.T) {
	plane, _ := newPhase4DecisionShadowRoutePlane(t, 3)
	pending := phase4DecisionShadowInput{
		source:      staticSrcV4(),
		destination: staticDstV4(),
		l4Proto:     consts.L4ProtoType_TCP,
	}
	for range 3 {
		plane.decisionShadow.ObservePending(pending)
	}

	key := phase4DecisionShadowContinuationKeyFor(pending)
	plane.decisionShadow.continuationMu.Lock()
	found := false
	for index := range plane.decisionShadow.continuations {
		continuation := &plane.decisionShadow.continuations[index]
		if continuation.used && continuation.key == key {
			continuation.expiresAt = time.Now().Add(-time.Nanosecond)
			found = true
		}
	}
	plane.decisionShadow.continuationMu.Unlock()
	if !found {
		t.Fatal("expected pending continuation before expiration")
	}

	pending.domain = "api.example.test"
	pending.domainKnown = true
	pending.evidence = routing.EvidenceTLSSNI
	plane.decisionShadow.Observe(pending, LegacyRouteOutcome{Outbound: consts.OutboundUserDefinedMin})

	got, enabled := plane.Phase4DecisionShadowSnapshot()
	if !enabled || got.Sampled != 0 || got.Matched != 0 || got.Deferred != 1 || got.Diverged != 0 || got.Errors != 0 {
		t.Fatalf("expired continuation snapshot = %+v enabled=%v, want terminal observation to use normal sampling", got, enabled)
	}
}

func TestPhase4DecisionShadowSamplesDeterministically(t *testing.T) {
	plane, _ := newPhase4DecisionShadowRoutePlane(t, 2)
	if before, enabled := plane.Phase4DecisionShadowSnapshot(); !enabled || before.CutoverEligible || before.Sampled != 0 {
		t.Fatalf("initial shadow snapshot = %+v enabled=%v, want unsampled and ineligible", before, enabled)
	}
	for call := 0; call < 2; call++ {
		if _, _, _, err := plane.routeWithDomainFacts(
			staticSrcV4(),
			staticDstV4(),
			"",
			consts.L4ProtoType_TCP,
			&bpfRoutingResult{},
			false,
			routing.EvidenceNone,
		); err != nil {
			t.Fatalf("Route() call %d error = %v", call, err)
		}
	}
	got, enabled := plane.Phase4DecisionShadowSnapshot()
	if !enabled || got.Sampled != 1 || got.Diverged != 1 {
		t.Fatalf("shadow snapshot = %+v enabled=%v, want only second call sampled", got, enabled)
	}
}

func TestPhase4DecisionShadowBlockPersistsAcrossGenerations(t *testing.T) {
	state := &phase4DecisionShadowProcessState{}
	first, _ := newPhase4DecisionShadowRoutePlane(t, 1)
	first.decisionShadow.processState = state
	if _, _, _, err := first.routeWithDomainFacts(
		staticSrcV4(),
		staticDstV4(),
		"",
		consts.L4ProtoType_TCP,
		&bpfRoutingResult{},
		false,
		routing.EvidenceNone,
	); err != nil {
		t.Fatalf("first Route() error = %v", err)
	}

	second, _ := newPhase4DecisionShadowRoutePlane(t, 1)
	second.decisionShadow.processState = state
	if _, _, _, err := second.Route(staticSrcV4(), staticDstV4(), "api.example.test", consts.L4ProtoType_TCP, &bpfRoutingResult{}); err != nil {
		t.Fatalf("second Route() error = %v", err)
	}
	got, enabled := second.Phase4DecisionShadowSnapshot()
	if !enabled || got.Matched != 1 || got.CutoverEligible || len(got.Evidence) != 1 {
		t.Fatalf("second generation snapshot = %+v enabled=%v, want persisted block and evidence", got, enabled)
	}
}

func TestPhase4DecisionShadowFeatureGateOwnership(t *testing.T) {
	handle, err := EnablePhase4DecisionShadow(7)
	if err != nil {
		t.Fatalf("EnablePhase4DecisionShadow() error = %v", err)
	}
	defer handle.Disable()
	if setting := phase4DecisionShadowSettingValue.Load(); setting == nil || setting.sampleEvery != 7 {
		t.Fatalf("feature setting = %+v, want sampleEvery 7", setting)
	}
	if _, err := EnablePhase4DecisionShadow(3); !stderrors.Is(err, ErrPhase4DecisionShadowAlreadyEnabled) {
		t.Fatalf("second EnablePhase4DecisionShadow() error = %v, want ownership error", err)
	}
	handle.Disable()
	replacement, err := EnablePhase4DecisionShadow(7)
	if err != nil {
		t.Fatalf("replacement EnablePhase4DecisionShadow() error = %v", err)
	}
	defer replacement.Disable()
	handle.Disable()
	if setting := phase4DecisionShadowSettingValue.Load(); setting != replacement.setting {
		t.Fatalf("late Disable() changed replacement setting: got %+v, want %+v", setting, replacement.setting)
	}
	replacement.Disable()
	if setting := phase4DecisionShadowSettingValue.Load(); setting != nil {
		t.Fatalf("feature setting after replacement Disable() = %+v, want nil", setting)
	}
}

func TestPhase4DecisionShadowCrossProtocolCorpus(t *testing.T) {
	tests := []struct {
		name        string
		dst         netip.AddrPort
		l4Proto     consts.L4ProtoType
		domain      string
		evidence    routing.EvidenceSource
		expected    consts.OutboundIndex
		domainKnown bool
	}{
		{
			name:        "tcp_tls_sni",
			dst:         staticDstV4(),
			l4Proto:     consts.L4ProtoType_TCP,
			domain:      "api.example.test",
			evidence:    routing.EvidenceTLSSNI,
			expected:    consts.OutboundUserDefinedMin,
			domainKnown: true,
		},
		{
			name:        "udp_quic_sni",
			dst:         staticDstV4(),
			l4Proto:     consts.L4ProtoType_UDP,
			domain:      "api.example.test",
			evidence:    routing.EvidenceQUICSNI,
			expected:    consts.OutboundUserDefinedMin,
			domainKnown: true,
		},
		{
			name:        "tcp_dns_association",
			dst:         netip.AddrPortFrom(staticDstV4().Addr(), 53),
			l4Proto:     consts.L4ProtoType_TCP,
			domain:      "api.example.test",
			evidence:    routing.EvidenceDNSAssociation,
			expected:    consts.OutboundUserDefinedMin,
			domainKnown: true,
		},
		{
			name:        "udp_dns_association",
			dst:         netip.AddrPortFrom(staticDstV4().Addr(), 53),
			l4Proto:     consts.L4ProtoType_UDP,
			domain:      "api.example.test",
			evidence:    routing.EvidenceDNSAssociation,
			expected:    consts.OutboundUserDefinedMin,
			domainKnown: true,
		},
		{
			name:        "udp_known_absent",
			dst:         staticDstV4(),
			l4Proto:     consts.L4ProtoType_UDP,
			evidence:    routing.EvidenceNone,
			expected:    consts.OutboundDirect,
			domainKnown: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			plane, _ := newPhase4DecisionShadowRoutePlane(t, 1)
			outbound, mark, must, err := plane.routeWithDomainFacts(
				staticSrcV4(),
				tc.dst,
				tc.domain,
				tc.l4Proto,
				&bpfRoutingResult{},
				tc.domainKnown,
				tc.evidence,
			)
			if err != nil {
				t.Fatalf("legacy route error = %v", err)
			}
			if outbound != tc.expected || mark != 0 || must {
				t.Fatalf("legacy route = (%v,%d,%v), want outbound %v", outbound, mark, must, tc.expected)
			}

			shadow, enabled := plane.Phase4DecisionShadowSnapshot()
			if !enabled || shadow.Sampled != 1 || shadow.Matched != 1 || shadow.Diverged != 0 || shadow.Errors != 0 || !shadow.CutoverEligible || len(shadow.Evidence) != 0 {
				t.Fatalf("shadow snapshot = %+v enabled=%v, want one eligible match", shadow, enabled)
			}
			decision, failure := plane.decisionShadow.evaluate(
				plane.newPhase4DecisionShadowInput(
					staticSrcV4(),
					tc.dst,
					tc.domain,
					tc.l4Proto,
					&bpfRoutingResult{},
					tc.domainKnown,
					tc.evidence,
				),
				routing.Continuation{},
			)
			if failure != Phase4DecisionShadowFailureNone || decision.Evidence != tc.evidence {
				t.Fatalf("shadow evaluation = (%+v,%v), want evidence source %v", decision, failure, tc.evidence)
			}
		})
	}
}

func newPhase4DecisionShadowRoutePlane(t *testing.T, sampleEvery uint64) (*ControlPlane, *routing.PolicySnapshot) {
	t.Helper()
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Domain,
				Params: []*config_parser.Param{{Key: string(consts.RoutingDomainKey_Suffix), Val: "example.test"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Port,
				Params: []*config_parser.Param{{Val: "443"}},
			}},
			Outbound: config_parser.Function{Name: "direct"},
		},
	}
	outboundIDs := map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"proxy":  uint8(consts.OutboundUserDefinedMin),
	}
	program, err := routing.NewNormalizedProgram(rules, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	snapshot, err := routing.NewPolicySnapshot(62, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	compiled, err := snapshot.Compile(logrus.New(), outboundIDs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	builder, err := NewRoutingMatcherBuilderFromCompiledPolicy(logrus.New(), compiled, nil)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilderFromCompiledPolicy() error = %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace() error = %v", err)
	}
	shadow, err := newPhase4DecisionShadow(snapshot, compiled, sampleEvery)
	if err != nil {
		t.Fatalf("newPhase4DecisionShadow() error = %v", err)
	}
	shadow.setLiveMatcher(matcher)
	return &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			policySnapshot: snapshot,
			routingMatcher: matcher,
			decisionShadow: shadow,
		},
	}, snapshot
}

func phase4DecisionShadowPredicateMatcherCount(shadow *phase4DecisionShadow) int {
	shadow.predicateMu.RLock()
	defer shadow.predicateMu.RUnlock()
	return len(shadow.predicateMatchers)
}
