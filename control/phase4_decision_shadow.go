/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"crypto/sha256"
	stderrors "errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

const (
	phase4DecisionShadowTrueOutbound      = "__dae_phase4_shadow_true__"
	phase4DecisionShadowFalseOutbound     = "__dae_phase4_shadow_false__"
	phase4DecisionShadowEvidenceLimit     = 16
	phase4DecisionShadowContinuationLimit = 16
	phase4DecisionShadowMaxDomainBytes    = 253
	phase4DecisionShadowContinuationTTL   = time.Second
)

var (
	// ErrPhase4DecisionShadowInvalidSampleEvery rejects a disabled or invalid
	// sampling period at the explicit feature gate.
	ErrPhase4DecisionShadowInvalidSampleEvery = stderrors.New("phase 4 decision shadow sampleEvery must be positive")
	// ErrPhase4DecisionShadowAlreadyEnabled prevents two owners from changing
	// the process-wide generation build setting at the same time.
	ErrPhase4DecisionShadowAlreadyEnabled = stderrors.New("phase 4 decision shadow is already enabled")
)

// Phase4DecisionShadowFailure classifies a sampled shadow evaluation that
// could not produce a comparable Decision.
type Phase4DecisionShadowFailure uint8

const (
	Phase4DecisionShadowFailureNone Phase4DecisionShadowFailure = iota
	Phase4DecisionShadowFailurePredicate
	Phase4DecisionShadowFailureOutbound
	Phase4DecisionShadowFailureLegacy
	Phase4DecisionShadowFailureDecision
	Phase4DecisionShadowFailureContinuation
)

// Phase4DecisionDivergenceEvidence is a copied, bounded record retained only
// when sampled shadow evaluation differs from the authoritative legacy route
// or cannot complete. It is never emitted as a hot-path log label.
type Phase4DecisionDivergenceEvidence struct {
	Epoch       routing.PolicyEpoch
	PolicyHash  [sha256.Size]byte
	Source      netip.AddrPort
	Destination netip.AddrPort
	L4Proto     consts.L4ProtoType
	Domain      string
	DomainKnown bool
	Evidence    routing.EvidenceSource
	ProcessName [consts.TaskCommLen]uint8
	PID         uint32
	DSCP        uint8
	MAC         [6]uint8
	RoutingSlot uint32
	// RoutingSlotKnown reports whether RoutingSlot came from the attributed BPF
	// result rather than a control-plane fallback.
	RoutingSlotKnown bool
	Legacy           LegacyRouteOutcome
	Shadow           routing.Decision
	Failure          Phase4DecisionShadowFailure
}

// Phase4DecisionShadowSnapshot exposes fixed-cardinality shadow health and a
// bounded divergence ring. A mismatch permanently blocks this generation from
// being considered eligible for a future Decision-path cutover while its
// process-wide feature-gate owner remains active.
type Phase4DecisionShadowSnapshot struct {
	Sampled         uint64
	Matched         uint64
	Deferred        uint64
	Diverged        uint64
	Errors          uint64
	CutoverEligible bool
	Evidence        []Phase4DecisionDivergenceEvidence
}

// phase4DecisionShadowProcessState outlives any one control-plane generation
// while its feature-gate owner is active. It preserves mismatch evidence and
// blocks a later cutover after reload.
type phase4DecisionShadowProcessState struct {
	cutoverBlocked atomic.Bool
	evidenceMu     sync.Mutex
	evidence       [phase4DecisionShadowEvidenceLimit]Phase4DecisionDivergenceEvidence
	evidenceNext   int
	evidenceCount  int
}

type phase4DecisionShadowSetting struct {
	sampleEvery uint64
	state       *phase4DecisionShadowProcessState
}

var phase4DecisionShadowSettingValue atomic.Pointer[phase4DecisionShadowSetting]

// Phase4DecisionShadowHandle owns the process-wide sampled shadow setting.
// Its unique setting pointer prevents a late Disable call from clearing a
// newer owner that happens to use the same sampling period.
type Phase4DecisionShadowHandle struct {
	setting  *phase4DecisionShadowSetting
	disabled atomic.Bool
}

// EnablePhase4DecisionShadow enables sampled Decision shadow evaluation for
// subsequently built control-plane generations.
func EnablePhase4DecisionShadow(sampleEvery uint64) (*Phase4DecisionShadowHandle, error) {
	if sampleEvery == 0 {
		return nil, ErrPhase4DecisionShadowInvalidSampleEvery
	}
	setting := &phase4DecisionShadowSetting{
		sampleEvery: sampleEvery,
		state:       &phase4DecisionShadowProcessState{},
	}
	if !phase4DecisionShadowSettingValue.CompareAndSwap(nil, setting) {
		return nil, ErrPhase4DecisionShadowAlreadyEnabled
	}
	return &Phase4DecisionShadowHandle{setting: setting}, nil
}

// Disable releases this handle's sampled shadow setting without changing a
// newer owner that may have replaced it.
func (h *Phase4DecisionShadowHandle) Disable() {
	if h == nil || h.setting == nil || h.disabled.Swap(true) {
		return
	}
	phase4DecisionShadowSettingValue.CompareAndSwap(h.setting, nil)
}

type phase4DecisionShadowInput struct {
	source           netip.AddrPort
	destination      netip.AddrPort
	l4Proto          consts.L4ProtoType
	domain           string
	domainKnown      bool
	evidence         routing.EvidenceSource
	processName      [consts.TaskCommLen]uint8
	pid              uint32
	dscp             uint8
	mac              [6]uint8
	routingSlot      uint32
	routingSlotKnown bool
}

type phase4DecisionShadowPredicateKey struct {
	ruleIndex     int
	functionIndex int
	groupIndex    int
}

type phase4DecisionShadowContinuationKey struct {
	source           netip.AddrPort
	destination      netip.AddrPort
	l4Proto          consts.L4ProtoType
	pid              uint32
	routingSlot      uint32
	routingSlotKnown bool
}

type phase4DecisionShadowPendingContinuation struct {
	key          phase4DecisionShadowContinuationKey
	continuation routing.Continuation
	expiresAt    time.Time
	used         bool
}

type phase4DecisionShadowPredicateMatcher struct {
	matcher       *RoutingMatcher
	trueOutbound  consts.OutboundIndex
	falseOutbound consts.OutboundIndex
}

type phase4DecisionShadow struct {
	snapshot        *routing.PolicySnapshot
	policyHash      [sha256.Size]byte
	outboundName2ID map[string]uint8
	sampleEvery     uint64
	sequence        atomic.Uint64
	sampled         atomic.Uint64
	matched         atomic.Uint64
	deferred        atomic.Uint64
	diverged        atomic.Uint64
	errors          atomic.Uint64
	processState    *phase4DecisionShadowProcessState

	// liveMatcher is bound while constructing a control-plane generation. It
	// lets sampled shadow evaluation use the exact lowered predicate layout
	// that remains authoritative in RoutingMatcher.Match.
	liveMatcher       atomic.Pointer[RoutingMatcher]
	predicateMu       sync.RWMutex
	predicateMatchers map[phase4DecisionShadowPredicateKey]*phase4DecisionShadowPredicateMatcher
	continuationMu    sync.Mutex
	continuations     [phase4DecisionShadowContinuationLimit]phase4DecisionShadowPendingContinuation
	continuationNext  int
}

func newPhase4DecisionShadow(snapshot *routing.PolicySnapshot, compiled *routing.CompiledPolicy, sampleEvery uint64) (*phase4DecisionShadow, error) {
	return newPhase4DecisionShadowWithProcessState(snapshot, compiled, sampleEvery, &phase4DecisionShadowProcessState{})
}

func newPhase4DecisionShadowWithProcessState(snapshot *routing.PolicySnapshot, compiled *routing.CompiledPolicy, sampleEvery uint64, processState *phase4DecisionShadowProcessState) (*phase4DecisionShadow, error) {
	if sampleEvery == 0 {
		return nil, nil
	}
	if snapshot == nil {
		return nil, fmt.Errorf("nil policy snapshot")
	}
	if compiled == nil {
		return nil, fmt.Errorf("nil compiled policy")
	}
	if compiled.Epoch() != snapshot.Epoch() || compiled.SourceHash() != snapshot.Hash() {
		return nil, fmt.Errorf("compiled policy does not belong to policy snapshot")
	}
	if processState == nil {
		return nil, fmt.Errorf("nil phase 4 decision shadow process state")
	}
	bindings := make(map[string]uint8)
	for _, binding := range compiled.OutboundIDs() {
		bindings[binding.Name] = uint8(binding.ID)
	}
	return &phase4DecisionShadow{
		snapshot:          snapshot,
		policyHash:        snapshot.Hash(),
		outboundName2ID:   bindings,
		sampleEvery:       sampleEvery,
		processState:      processState,
		predicateMatchers: make(map[phase4DecisionShadowPredicateKey]*phase4DecisionShadowPredicateMatcher),
	}, nil
}

// setLiveMatcher binds the immutable userspace matcher for this generation.
// A nil matcher deliberately preserves the isolated predicate-matcher fallback
// used by tests and compatibility callers that construct shadows directly.
func (s *phase4DecisionShadow) setLiveMatcher(matcher *RoutingMatcher) {
	if s == nil {
		return
	}
	s.liveMatcher.Store(matcher)
}

func (s *phase4DecisionShadow) Observe(input phase4DecisionShadowInput, legacy LegacyRouteOutcome) {
	if s == nil || s.sampleEvery == 0 {
		return
	}
	continuation, resumes := s.takeContinuation(input)
	if !resumes && !s.shouldSample() {
		return
	}
	s.sampled.Add(1)
	shadow, failure := s.evaluate(input, continuation)
	if failure != Phase4DecisionShadowFailureNone {
		s.errors.Add(1)
		s.processState.cutoverBlocked.Store(true)
		s.recordEvidence(input, legacy, shadow, failure)
		return
	}
	matches, legacyFailure := s.matchesLegacy(shadow, legacy, input)
	if legacyFailure != Phase4DecisionShadowFailureNone {
		s.errors.Add(1)
		s.processState.cutoverBlocked.Store(true)
		s.recordEvidence(input, legacy, shadow, legacyFailure)
		return
	}
	if matches {
		s.matched.Add(1)
		return
	}
	s.diverged.Add(1)
	s.processState.cutoverBlocked.Store(true)
	s.recordEvidence(input, legacy, shadow, Phase4DecisionShadowFailureNone)
}

// ObservePending validates a sampled incomplete fact set without comparing it
// to the legacy terminal result. A deferred result keeps only its immutable
// continuation in a bounded, short-lived per-generation ring until a complete
// fact set for the same flow arrives.
func (s *phase4DecisionShadow) ObservePending(input phase4DecisionShadowInput) {
	if s == nil || input.domainKnown || !s.shouldSample() {
		return
	}
	shadow, failure := s.evaluate(input, routing.Continuation{})
	if failure != Phase4DecisionShadowFailureNone {
		s.errors.Add(1)
		s.processState.cutoverBlocked.Store(true)
		s.recordEvidence(input, LegacyRouteOutcome{}, shadow, failure)
		return
	}
	if shadow.State != routing.DecisionDeferred {
		return
	}
	s.deferred.Add(1)
	s.storeContinuation(input, shadow.Continuation)
}

func (s *phase4DecisionShadow) Snapshot() Phase4DecisionShadowSnapshot {
	if s == nil {
		return Phase4DecisionShadowSnapshot{}
	}
	return Phase4DecisionShadowSnapshot{
		Sampled:         s.sampled.Load(),
		Matched:         s.matched.Load(),
		Deferred:        s.deferred.Load(),
		Diverged:        s.diverged.Load(),
		Errors:          s.errors.Load(),
		CutoverEligible: s.sampled.Load() > 0 && !s.processState.cutoverBlocked.Load(),
		Evidence:        s.processState.snapshotEvidence(),
	}
}

func (s *phase4DecisionShadow) shouldSample() bool {
	return s != nil && s.sampleEvery > 0 && s.sequence.Add(1)%s.sampleEvery == 0
}

// Phase4DecisionShadowSnapshot returns the current sampled shadow state for
// this control-plane generation. The boolean is false when the feature gate
// was disabled while the generation was built.
func (c *ControlPlane) Phase4DecisionShadowSnapshot() (Phase4DecisionShadowSnapshot, bool) {
	if c == nil || c.decisionShadow == nil {
		return Phase4DecisionShadowSnapshot{}, false
	}
	return c.decisionShadow.Snapshot(), true
}

func (s *phase4DecisionShadow) evaluate(input phase4DecisionShadowInput, continuation routing.Continuation) (routing.Decision, Phase4DecisionShadowFailure) {
	facts := routing.PolicyFacts{
		DomainKnown: input.domainKnown,
		Domain:      input.domain,
		Evidence:    input.evidence,
	}
	liveResolver, resolverErr := s.liveGroupResolver(input, facts)
	if resolverErr != nil {
		return routing.Decision{}, Phase4DecisionShadowFailurePredicate
	}
	var predicateErr error
	resolve := func(group routing.PredicateGroup, observed routing.PolicyFacts) routing.Truth {
		if predicateErr != nil {
			return routing.TruthFalse
		}
		if liveResolver != nil {
			return liveResolver.Resolve(group)
		}
		matcher, matcherErr := s.predicateMatcher(group)
		if matcherErr != nil {
			predicateErr = matcherErr
			return routing.TruthFalse
		}
		matchInput := input
		if observed.DomainKnown {
			matchInput.domain = observed.Domain
		}
		truth, truthErr := matcher.truth(matchInput)
		if truthErr != nil {
			predicateErr = truthErr
			return routing.TruthFalse
		}
		return truth
	}
	var (
		evaluation routing.PolicyEvaluation
		err        error
	)
	if continuation != (routing.Continuation{}) {
		evaluation, err = s.snapshot.ResumeFacts(continuation, facts, resolve)
		if err != nil {
			return routing.Decision{}, Phase4DecisionShadowFailureContinuation
		}
	} else {
		evaluation, err = s.snapshot.EvaluateFacts(facts, resolve)
	}
	if liveResolver != nil && predicateErr == nil {
		predicateErr = liveResolver.Err()
	}
	if err != nil || predicateErr != nil {
		return routing.Decision{}, Phase4DecisionShadowFailurePredicate
	}
	if evaluation.State == routing.DecisionDeferred {
		decision, decisionErr := routing.NewDeferredDecision(evaluation.Continuation, input.evidence)
		if decisionErr != nil {
			return routing.Decision{}, Phase4DecisionShadowFailureDecision
		}
		return decision, Phase4DecisionShadowFailureNone
	}

	outboundFunction, err := s.snapshot.OutboundFor(evaluation)
	if err != nil {
		return routing.Decision{}, Phase4DecisionShadowFailureOutbound
	}
	outbound, err := routing.ParseOutbound(outboundFunction)
	if err != nil {
		return routing.Decision{}, Phase4DecisionShadowFailureOutbound
	}
	outboundID, ok := s.outboundName2ID[outbound.Name]
	if !ok {
		return routing.Decision{}, Phase4DecisionShadowFailureOutbound
	}
	legacy := LegacyRouteOutcome{Outbound: consts.OutboundIndex(outboundID), Mark: outbound.Mark, Must: outbound.Must}
	execution, err := executionForLegacyRouteOutcome(legacy, LegacyRouteExecutionFacts{DstPort: input.destination.Port(), L4Proto: input.l4Proto})
	if err != nil {
		return routing.Decision{}, Phase4DecisionShadowFailureDecision
	}
	binding, err := routing.BindingProfileFor(legacy.Outbound)
	if err != nil {
		return routing.Decision{}, Phase4DecisionShadowFailureDecision
	}
	decision, err := routing.NewResolvedDecision(
		evaluation,
		s.snapshot.RuleCount(),
		execution,
		binding,
		legacy.Outbound,
		legacy.Mark,
		legacy.Must,
		input.evidence,
	)
	if err != nil {
		return routing.Decision{}, Phase4DecisionShadowFailureDecision
	}
	return decision, Phase4DecisionShadowFailureNone
}

func (s *phase4DecisionShadow) liveGroupResolver(input phase4DecisionShadowInput, facts routing.PolicyFacts) (*routingMatcherGroupResolver, error) {
	matcher := s.liveMatcher.Load()
	if matcher == nil {
		return nil, nil
	}

	domain := ""
	if facts.DomainKnown {
		domain = facts.Domain
	}
	ipVersion := consts.IpVersion_6
	if input.destination.Addr().Is4() || input.destination.Addr().Is4In6() {
		ipVersion = consts.IpVersion_4
	}
	var mac [16]uint8
	copy(mac[10:], input.mac[:])
	matcherFacts, err := matcher.newFacts(
		input.source.Addr().As16(),
		input.destination.Addr().As16(),
		input.source.Port(),
		input.destination.Port(),
		ipVersion,
		input.l4Proto,
		domain,
		input.processName,
		input.dscp,
		mac,
	)
	if err != nil {
		return nil, err
	}
	return newRoutingMatcherGroupResolver(matcher, matcherFacts), nil
}

func phase4DecisionShadowContinuationKeyFor(input phase4DecisionShadowInput) phase4DecisionShadowContinuationKey {
	return phase4DecisionShadowContinuationKey{
		source:           input.source,
		destination:      input.destination,
		l4Proto:          input.l4Proto,
		pid:              input.pid,
		routingSlot:      input.routingSlot,
		routingSlotKnown: input.routingSlotKnown,
	}
}

func (s *phase4DecisionShadow) storeContinuation(input phase4DecisionShadowInput, continuation routing.Continuation) {
	if s == nil || continuation == (routing.Continuation{}) {
		return
	}
	key := phase4DecisionShadowContinuationKeyFor(input)
	s.continuationMu.Lock()
	defer s.continuationMu.Unlock()
	for index := range s.continuations {
		if s.continuations[index].used && s.continuations[index].key == key {
			s.continuations[index].continuation = continuation
			s.continuations[index].expiresAt = time.Now().Add(phase4DecisionShadowContinuationTTL)
			return
		}
	}
	s.continuations[s.continuationNext] = phase4DecisionShadowPendingContinuation{
		key:          key,
		continuation: continuation,
		expiresAt:    time.Now().Add(phase4DecisionShadowContinuationTTL),
		used:         true,
	}
	s.continuationNext = (s.continuationNext + 1) % len(s.continuations)
}

func (s *phase4DecisionShadow) takeContinuation(input phase4DecisionShadowInput) (routing.Continuation, bool) {
	if s == nil || !input.domainKnown {
		return routing.Continuation{}, false
	}
	key := phase4DecisionShadowContinuationKeyFor(input)
	s.continuationMu.Lock()
	defer s.continuationMu.Unlock()
	for index := range s.continuations {
		pending := &s.continuations[index]
		if !pending.used || pending.key != key {
			continue
		}
		if !time.Now().Before(pending.expiresAt) {
			*pending = phase4DecisionShadowPendingContinuation{}
			return routing.Continuation{}, false
		}
		continuation := pending.continuation
		*pending = phase4DecisionShadowPendingContinuation{}
		return continuation, true
	}
	return routing.Continuation{}, false
}

func (s *phase4DecisionShadow) matchesLegacy(shadow routing.Decision, legacy LegacyRouteOutcome, input phase4DecisionShadowInput) (bool, Phase4DecisionShadowFailure) {
	if shadow.State != routing.DecisionResolved {
		return false, Phase4DecisionShadowFailureNone
	}
	execution, err := executionForLegacyRouteOutcome(legacy, LegacyRouteExecutionFacts{DstPort: input.destination.Port(), L4Proto: input.l4Proto})
	if err != nil {
		return false, Phase4DecisionShadowFailureLegacy
	}
	binding, err := routing.BindingProfileFor(legacy.Outbound)
	if err != nil {
		return false, Phase4DecisionShadowFailureLegacy
	}
	return shadow.Outbound == legacy.Outbound &&
		shadow.Mark == legacy.Mark &&
		shadow.Must == legacy.Must &&
		shadow.Execution == execution &&
		shadow.Binding == binding, Phase4DecisionShadowFailureNone
}

func (s *phase4DecisionShadow) predicateMatcher(group routing.PredicateGroup) (*phase4DecisionShadowPredicateMatcher, error) {
	key := phase4DecisionShadowPredicateKey{
		ruleIndex:     group.RuleIndex,
		functionIndex: group.FunctionIndex,
		groupIndex:    group.GroupIndex,
	}
	s.predicateMu.RLock()
	if matcher, ok := s.predicateMatchers[key]; ok {
		s.predicateMu.RUnlock()
		return matcher, nil
	}
	s.predicateMu.RUnlock()

	s.predicateMu.Lock()
	defer s.predicateMu.Unlock()
	if matcher, ok := s.predicateMatchers[key]; ok {
		return matcher, nil
	}
	matcher, err := newPhase4DecisionShadowPredicateMatcher(group)
	if err != nil {
		return nil, err
	}
	s.predicateMatchers[key] = matcher
	return matcher, nil
}

func newPhase4DecisionShadowPredicateMatcher(group routing.PredicateGroup) (*phase4DecisionShadowPredicateMatcher, error) {
	trueOutbound := consts.OutboundUserDefinedMax
	falseOutbound := consts.OutboundUserDefinedMax - 1
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		[]*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{phase4DecisionShadowPositivePredicate(group)},
			Outbound:     config_parser.Function{Name: phase4DecisionShadowTrueOutbound},
		}},
		map[string]uint8{
			phase4DecisionShadowTrueOutbound:  uint8(trueOutbound),
			phase4DecisionShadowFalseOutbound: uint8(falseOutbound),
		},
		nil,
		config.FunctionOrString(phase4DecisionShadowFalseOutbound),
	)
	if err != nil {
		return nil, err
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, err
	}
	return &phase4DecisionShadowPredicateMatcher{
		matcher:       matcher,
		trueOutbound:  trueOutbound,
		falseOutbound: falseOutbound,
	}, nil
}

func phase4DecisionShadowPositivePredicate(group routing.PredicateGroup) *config_parser.Function {
	function := &config_parser.Function{
		Name:   group.Name,
		Params: make([]*config_parser.Param, 0, len(group.Values)+1),
	}
	for _, value := range group.Values {
		function.Params = append(function.Params, &config_parser.Param{Key: group.Key, Val: value})
	}
	if group.Not && group.Name == consts.Function_Mac {
		// The legacy negative-MAC lowerer includes the zero MAC before negation.
		function.Params = append(function.Params, &config_parser.Param{Key: group.Key, Val: "00:00:00:00:00:00"})
	}
	return function
}

func (m *phase4DecisionShadowPredicateMatcher) truth(input phase4DecisionShadowInput) (routing.Truth, error) {
	source := input.source.Addr().As16()
	destination := input.destination.Addr().As16()
	var mac [16]uint8
	copy(mac[10:], input.mac[:])
	ipVersion := consts.IpVersion_6
	if input.destination.Addr().Is4() || input.destination.Addr().Is4In6() {
		ipVersion = consts.IpVersion_4
	}
	outbound, _, _, err := m.matcher.Match(
		source,
		destination,
		input.source.Port(),
		input.destination.Port(),
		ipVersion,
		input.l4Proto,
		input.domain,
		input.processName,
		input.dscp,
		mac,
	)
	if err != nil {
		return routing.TruthUnknown, err
	}
	switch outbound {
	case m.trueOutbound:
		return routing.TruthTrue, nil
	case m.falseOutbound:
		return routing.TruthFalse, nil
	default:
		return routing.TruthUnknown, fmt.Errorf("predicate matcher returned unexpected outbound %v", outbound)
	}
}

func (s *phase4DecisionShadow) recordEvidence(input phase4DecisionShadowInput, legacy LegacyRouteOutcome, shadow routing.Decision, failure Phase4DecisionShadowFailure) {
	evidence := Phase4DecisionDivergenceEvidence{
		Epoch:            s.snapshot.Epoch(),
		PolicyHash:       s.policyHash,
		Source:           input.source,
		Destination:      input.destination,
		L4Proto:          input.l4Proto,
		Domain:           phase4DecisionShadowDomainCopy(input.domain),
		DomainKnown:      input.domainKnown,
		Evidence:         input.evidence,
		ProcessName:      input.processName,
		PID:              input.pid,
		DSCP:             input.dscp,
		MAC:              input.mac,
		RoutingSlot:      input.routingSlot,
		RoutingSlotKnown: input.routingSlotKnown,
		Legacy:           legacy,
		Shadow:           shadow,
		Failure:          failure,
	}
	s.processState.recordEvidence(evidence)
}

func (s *phase4DecisionShadowProcessState) recordEvidence(evidence Phase4DecisionDivergenceEvidence) {
	s.evidenceMu.Lock()
	s.evidence[s.evidenceNext] = evidence
	s.evidenceNext = (s.evidenceNext + 1) % len(s.evidence)
	if s.evidenceCount < len(s.evidence) {
		s.evidenceCount++
	}
	s.evidenceMu.Unlock()
}

func (s *phase4DecisionShadowProcessState) snapshotEvidence() []Phase4DecisionDivergenceEvidence {
	if s == nil {
		return nil
	}
	s.evidenceMu.Lock()
	defer s.evidenceMu.Unlock()
	if s.evidenceCount == 0 {
		return nil
	}
	evidence := make([]Phase4DecisionDivergenceEvidence, 0, s.evidenceCount)
	start := (s.evidenceNext - s.evidenceCount + len(s.evidence)) % len(s.evidence)
	for index := 0; index < s.evidenceCount; index++ {
		evidence = append(evidence, s.evidence[(start+index)%len(s.evidence)])
	}
	return evidence
}

func phase4DecisionShadowDomainCopy(domain string) string {
	if len(domain) > phase4DecisionShadowMaxDomainBytes {
		domain = domain[:phase4DecisionShadowMaxDomainBytes]
	}
	return strings.Clone(domain)
}
