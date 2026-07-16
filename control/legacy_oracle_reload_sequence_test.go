/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
)

type legacyReloadOracleAction uint8

const (
	legacyReloadOracleActionOldFlowBound legacyReloadOracleAction = iota
	legacyReloadOracleActionPublished
	legacyReloadOracleActionSuccessorReusedOldFlow
	legacyReloadOracleActionOldFlowDrained
)

// legacyReloadOracleSequenceEvent records one observable action in a reload
// sequence. Reload is an input fact, while the remaining fields are derived
// from the real UDP endpoint and drain tracker state.
type legacyReloadOracleSequenceEvent struct {
	Action                  legacyReloadOracleAction
	Reload                  legacyReloadEvent
	Flow                    string
	Route                   UdpRouteBinding
	DialTarget              string
	OldDrainCount           int
	SuccessorDrainCount     int
	OldDialCalls            int32
	SuccessorDialCalls      int32
	InheritedCandidateAlive bool
}

type legacyReloadOracleSequence struct {
	Name  string
	Facts []legacyReloadEvent
	Want  []legacyReloadOracleSequenceEvent
}

func legacyOracleReloadSequences() []legacyReloadOracleSequence {
	const (
		oldEpoch       routing.PolicyEpoch = 71
		successorEpoch routing.PolicyEpoch = 72
	)
	wantRoute := UdpRouteBinding{
		PolicyEpoch: oldEpoch,
		Outbound:    consts.OutboundUserDefinedMin,
		Mark:        71,
		Must:        true,
	}
	publish := legacyReloadEvent{Kind: legacyReloadPublished, Epoch: uint64(successorEpoch)}
	return []legacyReloadOracleSequence{{
		Name: "published_successor_reuses_old_udp_binding",
		Facts: []legacyReloadEvent{
			{Kind: legacyReloadNone, Epoch: uint64(oldEpoch)},
			publish,
		},
		Want: []legacyReloadOracleSequenceEvent{
			{
				Action:              legacyReloadOracleActionOldFlowBound,
				Reload:              legacyReloadEvent{Kind: legacyReloadNone, Epoch: uint64(oldEpoch)},
				Flow:                "flow-a",
				Route:               wantRoute,
				DialTarget:          "198.51.100.20:443",
				OldDrainCount:       1,
				SuccessorDrainCount: 0,
				OldDialCalls:        1,
			},
			{
				Action:                  legacyReloadOracleActionPublished,
				Reload:                  publish,
				OldDrainCount:           1,
				SuccessorDrainCount:     0,
				OldDialCalls:            1,
				SuccessorDialCalls:      0,
				InheritedCandidateAlive: false,
			},
			{
				Action:              legacyReloadOracleActionSuccessorReusedOldFlow,
				Reload:              publish,
				Flow:                "flow-a",
				Route:               wantRoute,
				DialTarget:          "198.51.100.20:443",
				OldDrainCount:       1,
				SuccessorDrainCount: 0,
				OldDialCalls:        1,
				SuccessorDialCalls:  0,
			},
			{
				Action:              legacyReloadOracleActionOldFlowDrained,
				Reload:              publish,
				Flow:                "flow-a",
				Route:               wantRoute,
				DialTarget:          "198.51.100.20:443",
				OldDrainCount:       0,
				SuccessorDrainCount: 0,
				OldDialCalls:        1,
				SuccessorDialCalls:  0,
			},
		},
	}}
}

func validateLegacyReloadOracleSequence(sequence legacyReloadOracleSequence) error {
	if sequence.Name == "" || len(sequence.Facts) != 2 || len(sequence.Want) == 0 {
		return fmt.Errorf("reload sequence is incomplete")
	}
	old, publish := sequence.Facts[0], sequence.Facts[1]
	if old.Kind != legacyReloadNone || old.Epoch == 0 {
		return fmt.Errorf("old generation reload fact is invalid")
	}
	if publish.Kind != legacyReloadPublished || publish.Epoch <= old.Epoch {
		return fmt.Errorf("published successor reload fact is invalid")
	}
	return nil
}

func (o LegacyOracle) replayReloadSequence(t *testing.T, sequence legacyReloadOracleSequence) ([]legacyReloadOracleSequenceEvent, error) {
	t.Helper()
	return replayLegacyReloadOracleSequence(t, sequence.Facts)
}

func replayLegacyReloadOracleSequence(t *testing.T, facts []legacyReloadEvent) ([]legacyReloadOracleSequenceEvent, error) {
	t.Helper()
	if len(facts) != 2 {
		return nil, fmt.Errorf("reload facts = %d, want 2", len(facts))
	}
	oldReload, publish := facts[0], facts[1]
	if oldReload.Kind != legacyReloadNone || publish.Kind != legacyReloadPublished {
		return nil, fmt.Errorf("unsupported reload fact sequence")
	}

	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	t.Cleanup(func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	})

	oldEpoch := routing.PolicyEpoch(oldReload.Epoch)
	successorEpoch := routing.PolicyEpoch(publish.Epoch)
	const flowID = "flow-a"
	wantRoute := UdpRouteBinding{
		PolicyEpoch: oldEpoch,
		Outbound:    consts.OutboundUserDefinedMin,
		Mark:        71,
		Must:        true,
	}
	oldSnapshot := newLegacyReloadOracleSequenceSnapshot(t, oldEpoch)
	successorSnapshot := newLegacyReloadOracleSequenceSnapshot(t, successorEpoch)
	oldTracker := newControlPlaneDrainTracker()
	successorTracker := newControlPlaneDrainTracker()

	oldConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	oldDialer, oldUnderlay := newCountingProxyEndpointDialer("hysteria2", "old.example:443", oldConn)
	oldPlane := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(oldDialer))
	oldPlane.policySnapshot = oldSnapshot
	oldPlane.drainTracker = oldTracker

	successorConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	successorMatchedDialer, successorUnderlay := newCountingProxyEndpointDialer("hysteria2", "successor.example:443", successorConn)
	successorFallbackConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	successorFallbackDialer, successorFallbackUnderlay := newCountingProxyEndpointDialer("shadowsocks_2022", "fallback.example:443", successorFallbackConn)
	successorOutbound := newTestFixedOutboundGroup(successorMatchedDialer, successorFallbackDialer)
	successorOutbound.SetSelectionPolicy(ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random})
	successorPlane := newUdpReuseSimulationControlPlane(successorOutbound)
	successorPlane.policySnapshot = successorSnapshot
	successorPlane.drainTracker = successorTracker

	src := mustParseAddrPort("192.0.2.10:41000")
	dst := mustParseAddrPort("198.51.100.20:443")
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	flow := ClassifyUdpFlow(src, dst, payload)
	key := flow.FullConeNatEndpointKey()
	oldRoute := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
		Mark:     71,
		Must:     1,
	}
	if err := oldPlane.handlePkt(nil, payload, src, dst, oldRoute, flow, false); err != nil {
		t.Fatalf("old generation handlePkt: %v", err)
	}
	endpoint, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || endpoint == nil {
		t.Fatal("old generation did not create an endpoint")
	}
	oldBinding := endpoint.FlowBinding()
	if oldBinding.Route != wantRoute || oldBinding.Egress.Dialer != oldDialer {
		t.Fatalf("old binding = %+v, want old epoch and old dialer", oldBinding)
	}

	trace := []legacyReloadOracleSequenceEvent{{
		Action:              legacyReloadOracleActionOldFlowBound,
		Reload:              oldReload,
		Flow:                flowID,
		Route:               oldBinding.Route,
		DialTarget:          oldBinding.Egress.Target,
		OldDrainCount:       oldTracker.Count(),
		SuccessorDrainCount: successorTracker.Count(),
		OldDialCalls:        oldUnderlay.calls.Load(),
	}}

	// Preserve the old flow after its selected dialer becomes unhealthy, then
	// inherit that state into the matching successor candidate before publish.
	oldDialer.ReportUnavailableForced(udp4NetworkType(), io.ErrUnexpectedEOF)
	if oldDialer.MustGetAlive(udp4NetworkType()) {
		t.Fatal("old dialer remained alive after forced UDP health transition")
	}
	if !successorPlane.InheritDialerHealthFrom(oldPlane) {
		t.Fatal("expected reload health inheritance to find the matching dialer")
	}
	if successorMatchedDialer.MustGetAlive(udp4NetworkType()) {
		t.Fatal("successor matching dialer did not inherit unavailable UDP health")
	}
	if !successorFallbackDialer.MustGetAlive(udp4NetworkType()) {
		t.Fatal("successor fallback dialer unexpectedly became unavailable")
	}
	if alive := successorOutbound.MustGetAliveDialerSet(udp4NetworkType()); alive == nil || alive.Len() != 1 {
		t.Fatalf("successor healthy UDP candidates = %v, want one fallback candidate", alive)
	}

	trace = append(trace, legacyReloadOracleSequenceEvent{
		Action:                  legacyReloadOracleActionPublished,
		Reload:                  publish,
		OldDrainCount:           oldTracker.Count(),
		SuccessorDrainCount:     successorTracker.Count(),
		OldDialCalls:            oldUnderlay.calls.Load(),
		SuccessorDialCalls:      successorUnderlay.calls.Load() + successorFallbackUnderlay.calls.Load(),
		InheritedCandidateAlive: successorMatchedDialer.MustGetAlive(udp4NetworkType()),
	})

	// The successor observes the published route facts, but the shared endpoint
	// must retain the route and egress selected by the old generation.
	successorRoute := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
		Mark:     72,
	}
	if err := successorPlane.handlePkt(nil, payload, src, dst, successorRoute, flow, false); err != nil {
		t.Fatalf("successor generation handlePkt: %v", err)
	}
	reusedEndpoint, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || reusedEndpoint != endpoint {
		t.Fatal("successor generation did not reuse the old endpoint")
	}
	reusedBinding := reusedEndpoint.FlowBinding()
	if reusedBinding != oldBinding {
		t.Fatalf("reused binding = %+v, want old binding %+v", reusedBinding, oldBinding)
	}
	trace = append(trace, legacyReloadOracleSequenceEvent{
		Action:              legacyReloadOracleActionSuccessorReusedOldFlow,
		Reload:              publish,
		Flow:                flowID,
		Route:               reusedBinding.Route,
		DialTarget:          reusedBinding.Egress.Target,
		OldDrainCount:       oldTracker.Count(),
		SuccessorDrainCount: successorTracker.Count(),
		OldDialCalls:        oldUnderlay.calls.Load(),
		SuccessorDialCalls:  successorUnderlay.calls.Load() + successorFallbackUnderlay.calls.Load(),
	})

	if err := endpoint.Close(); err != nil {
		t.Fatalf("close old endpoint: %v", err)
	}
	trace = append(trace, legacyReloadOracleSequenceEvent{
		Action:              legacyReloadOracleActionOldFlowDrained,
		Reload:              publish,
		Flow:                flowID,
		Route:               oldBinding.Route,
		DialTarget:          oldBinding.Egress.Target,
		OldDrainCount:       oldTracker.Count(),
		SuccessorDrainCount: successorTracker.Count(),
		OldDialCalls:        oldUnderlay.calls.Load(),
		SuccessorDialCalls:  successorUnderlay.calls.Load() + successorFallbackUnderlay.calls.Load(),
	})

	return trace, nil
}

func newLegacyReloadOracleSequenceSnapshot(t *testing.T, epoch routing.PolicyEpoch) *routing.PolicySnapshot {
	t.Helper()

	program, err := routing.NewNormalizedProgram(nil, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	snapshot, err := routing.NewPolicySnapshot(epoch, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	return snapshot
}
