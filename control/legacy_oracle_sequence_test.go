/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
)

type legacyOracleSequenceEventKind uint8

const (
	legacyOracleSequenceFlowEstablished legacyOracleSequenceEventKind = iota
	legacyOracleSequenceHealthChanged
	legacyOracleSequenceExistingFlowReused
	legacyOracleSequenceNewFlowEstablished
)

type legacyOracleSequenceKind uint8

const (
	legacyOracleSequenceUnknown legacyOracleSequenceKind = iota
	legacyOracleSequenceUDPHealthTransition
)

type legacyOracleSequenceFactKind uint8

const (
	legacyOracleSequenceFactUnknown legacyOracleSequenceFactKind = iota
	legacyOracleSequenceFactEstablishFlow
	legacyOracleSequenceFactHealthChanged
	legacyOracleSequenceFactReuseFlow
)

// legacyOracleSequenceFact is one ordered input to an oracle replay. Its
// candidate and flow labels are stable fixture identities, not runtime object
// addresses, so the expected action trace remains a fixed golden.
type legacyOracleSequenceFact struct {
	Kind             legacyOracleSequenceFactKind
	Flow             string
	Candidate        string
	CandidateHealthy bool
}

type legacyOracleSequence struct {
	Name  string
	Kind  legacyOracleSequenceKind
	Facts []legacyOracleSequenceFact
	Want  []legacyOracleSequenceEvent
}

// legacyOracleSequenceEvent records the ordered observable legacy behavior
// around a health transition without retaining any mutable control-plane state.
type legacyOracleSequenceEvent struct {
	Kind             legacyOracleSequenceEventKind
	Flow             string
	Candidate        string
	CandidateHealthy bool
	DialTarget       string
}

func legacyOracleOrderedSequences() []legacyOracleSequence {
	return []legacyOracleSequence{{
		Name: "udp_health_transition_pins_existing_flow_and_reselects_new_flow",
		Kind: legacyOracleSequenceUDPHealthTransition,
		Facts: []legacyOracleSequenceFact{
			{
				Kind:             legacyOracleSequenceFactEstablishFlow,
				Flow:             "flow-a",
				Candidate:        "dialer-a",
				CandidateHealthy: true,
			},
			{
				Kind:             legacyOracleSequenceFactHealthChanged,
				Candidate:        "dialer-a",
				CandidateHealthy: false,
			},
			{
				Kind:             legacyOracleSequenceFactReuseFlow,
				Flow:             "flow-a",
				Candidate:        "dialer-a",
				CandidateHealthy: true,
			},
			{
				Kind:             legacyOracleSequenceFactHealthChanged,
				Candidate:        "dialer-a",
				CandidateHealthy: false,
			},
			{
				Kind:             legacyOracleSequenceFactEstablishFlow,
				Flow:             "flow-b",
				Candidate:        "dialer-b",
				CandidateHealthy: true,
			},
		},
		Want: []legacyOracleSequenceEvent{
			{
				Kind:             legacyOracleSequenceFlowEstablished,
				Flow:             "flow-a",
				Candidate:        "dialer-a",
				CandidateHealthy: true,
				DialTarget:       "198.51.100.20:3478",
			},
			{
				Kind:             legacyOracleSequenceHealthChanged,
				Candidate:        "dialer-a",
				CandidateHealthy: false,
			},
			{
				Kind:             legacyOracleSequenceExistingFlowReused,
				Flow:             "flow-a",
				Candidate:        "dialer-a",
				CandidateHealthy: true,
				DialTarget:       "198.51.100.20:3478",
			},
			{
				Kind:             legacyOracleSequenceHealthChanged,
				Candidate:        "dialer-a",
				CandidateHealthy: false,
			},
			{
				Kind:             legacyOracleSequenceNewFlowEstablished,
				Flow:             "flow-b",
				Candidate:        "dialer-b",
				CandidateHealthy: true,
				DialTarget:       "198.51.100.20:3478",
			},
		},
	}}
}

func validateLegacyOracleSequence(sequence legacyOracleSequence) error {
	if sequence.Name == "" || sequence.Kind == legacyOracleSequenceUnknown {
		return fmt.Errorf("sequence identity is not recorded")
	}
	if len(sequence.Facts) == 0 || len(sequence.Want) == 0 {
		return fmt.Errorf("sequence facts or expected actions are empty")
	}
	for i, fact := range sequence.Facts {
		if fact.Kind == legacyOracleSequenceFactUnknown {
			return fmt.Errorf("fact %d has no kind", i)
		}
		if fact.Candidate == "" {
			return fmt.Errorf("fact %d has no candidate", i)
		}
		if (fact.Kind == legacyOracleSequenceFactEstablishFlow || fact.Kind == legacyOracleSequenceFactReuseFlow) && fact.Flow == "" {
			return fmt.Errorf("fact %d has no flow", i)
		}
	}
	return nil
}

func (o LegacyOracle) replayOrderedSequence(t *testing.T, sequence legacyOracleSequence) ([]legacyOracleSequenceEvent, error) {
	t.Helper()
	switch sequence.Kind {
	case legacyOracleSequenceUDPHealthTransition:
		return replayLegacyOracleUDPHealthTransition(t, sequence.Facts)
	default:
		return nil, fmt.Errorf("unsupported legacy sequence kind %d", sequence.Kind)
	}
}

type legacyOracleUDPSequenceFlow struct {
	source   netip.AddrPort
	decision UdpFlowDecision
	key      UdpEndpointKey
	endpoint *UdpEndpoint
}

func replayLegacyOracleUDPHealthTransition(t *testing.T, facts []legacyOracleSequenceFact) ([]legacyOracleSequenceEvent, error) {
	t.Helper()

	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	t.Cleanup(func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	})

	firstConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	firstDialer, firstUnderlay := newCountingProxyEndpointDialer("hysteria2", "first.example:443", firstConn)
	secondConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	secondDialer, secondUnderlay := newCountingProxyEndpointDialer("hysteria2", "second.example:443", secondConn)

	outbound := newTestFixedOutboundGroup(firstDialer, secondDialer)
	cp := newUdpReuseSimulationControlPlane(outbound)
	routingResult := &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin)}
	dst := mustParseAddrPort("198.51.100.20:3478")
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	candidates := map[string]*componentdialer.Dialer{
		"dialer-a": firstDialer,
		"dialer-b": secondDialer,
	}
	flows := map[string]*legacyOracleUDPSequenceFlow{
		"flow-a": {source: mustParseAddrPort("192.0.2.10:41000")},
		"flow-b": {source: mustParseAddrPort("192.0.2.11:41001")},
	}
	for _, flow := range flows {
		flow.decision = ClassifyUdpFlow(flow.source, dst, payload)
		flow.key = flow.decision.FullConeNatEndpointKey()
	}

	trace := make([]legacyOracleSequenceEvent, 0, len(facts))
	for _, fact := range facts {
		candidate, ok := candidates[fact.Candidate]
		if !ok {
			return nil, fmt.Errorf("unknown candidate %q", fact.Candidate)
		}
		switch fact.Kind {
		case legacyOracleSequenceFactEstablishFlow:
			flow, ok := flows[fact.Flow]
			if !ok {
				return nil, fmt.Errorf("unknown flow %q", fact.Flow)
			}
			if flow.endpoint != nil {
				return nil, fmt.Errorf("flow %q was already established", fact.Flow)
			}
			if err := cp.handlePkt(nil, payload, flow.source, dst, routingResult, flow.decision, false); err != nil {
				return nil, fmt.Errorf("establish %s: %w", fact.Flow, err)
			}
			endpoint, ok := DefaultUdpEndpointPool.Get(flow.key)
			if !ok || endpoint == nil {
				return nil, fmt.Errorf("flow %q did not create an endpoint", fact.Flow)
			}
			if endpoint.Dialer != candidate {
				return nil, fmt.Errorf("flow %q dialer = %p, want candidate %q", fact.Flow, endpoint.Dialer, fact.Candidate)
			}
			if got := candidate.MustGetAlive(udp4NetworkType()); got != fact.CandidateHealthy {
				return nil, fmt.Errorf("candidate %q health after establishing %q = %v, want %v", fact.Candidate, fact.Flow, got, fact.CandidateHealthy)
			}
			flow.endpoint = endpoint
			eventKind := legacyOracleSequenceFlowEstablished
			if fact.Flow != "flow-a" {
				eventKind = legacyOracleSequenceNewFlowEstablished
			}
			trace = append(trace, legacyOracleSequenceEvent{
				Kind:             eventKind,
				Flow:             fact.Flow,
				Candidate:        fact.Candidate,
				CandidateHealthy: candidate.MustGetAlive(udp4NetworkType()),
				DialTarget:       endpoint.DialTarget,
			})
		case legacyOracleSequenceFactHealthChanged:
			// New admissions are health-aware from this point onward; sent flows
			// retain their endpoint binding in the control-plane fast path.
			outbound.SetSelectionPolicy(ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random})
			if fact.CandidateHealthy {
				candidate.NotifyHealthCheckResult(udp4NetworkType(), true, true)
			} else {
				candidate.ReportUnavailableForced(udp4NetworkType(), io.ErrUnexpectedEOF)
			}
			if got := candidate.MustGetAlive(udp4NetworkType()); got != fact.CandidateHealthy {
				return nil, fmt.Errorf("candidate %q health = %v, want %v", fact.Candidate, got, fact.CandidateHealthy)
			}
			if !fact.CandidateHealthy {
				if !secondDialer.MustGetAlive(udp4NetworkType()) {
					return nil, fmt.Errorf("remaining candidate unexpectedly became unhealthy")
				}
				if alive := outbound.MustGetAliveDialerSet(udp4NetworkType()); alive == nil || alive.Len() != 1 {
					return nil, fmt.Errorf("healthy UDP selection candidates = %v, want exactly one", alive)
				}
			}
			trace = append(trace, legacyOracleSequenceEvent{
				Kind:             legacyOracleSequenceHealthChanged,
				Candidate:        fact.Candidate,
				CandidateHealthy: candidate.MustGetAlive(udp4NetworkType()),
			})
		case legacyOracleSequenceFactReuseFlow:
			flow, ok := flows[fact.Flow]
			if !ok || flow.endpoint == nil {
				return nil, fmt.Errorf("flow %q is not established", fact.Flow)
			}
			if flow.endpoint.Dialer != candidate {
				return nil, fmt.Errorf("flow %q is not bound to candidate %q", fact.Flow, fact.Candidate)
			}
			if err := cp.handlePkt(nil, payload, flow.source, dst, routingResult, flow.decision, false); err != nil {
				return nil, fmt.Errorf("reuse %s: %w", fact.Flow, err)
			}
			reused, ok := DefaultUdpEndpointPool.Get(flow.key)
			if !ok || reused != flow.endpoint {
				return nil, fmt.Errorf("health transition replaced established flow %q", fact.Flow)
			}
			if reused.Dialer != candidate {
				return nil, fmt.Errorf("health transition rebound established flow %q", fact.Flow)
			}
			if got := candidate.MustGetAlive(udp4NetworkType()); got != fact.CandidateHealthy {
				return nil, fmt.Errorf("candidate %q health after reusing %q = %v, want %v", fact.Candidate, fact.Flow, got, fact.CandidateHealthy)
			}
			trace = append(trace, legacyOracleSequenceEvent{
				Kind:             legacyOracleSequenceExistingFlowReused,
				Flow:             fact.Flow,
				Candidate:        fact.Candidate,
				CandidateHealthy: candidate.MustGetAlive(udp4NetworkType()),
				DialTarget:       reused.DialTarget,
			})
		default:
			return nil, fmt.Errorf("unsupported sequence fact kind %d", fact.Kind)
		}
	}

	if got := firstUnderlay.calls.Load(); got != 1 {
		return nil, fmt.Errorf("first dialer DialContext calls = %d, want 1", got)
	}
	if got := firstConn.writeCalls.Load(); got != 2 {
		return nil, fmt.Errorf("first flow writes = %d, want 2", got)
	}
	if got := secondUnderlay.calls.Load(); got != 1 {
		return nil, fmt.Errorf("second dialer DialContext calls = %d, want 1", got)
	}
	if got := secondConn.writeCalls.Load(); got != 1 {
		return nil, fmt.Errorf("second flow writes = %d, want 1", got)
	}
	return trace, nil
}
