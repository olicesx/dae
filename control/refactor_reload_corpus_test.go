/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
)

type reloadLiveUdpFlowCorpusFixture struct {
	name           string
	oldEpoch       routing.PolicyEpoch
	successorEpoch routing.PolicyEpoch
}

func phase0ReloadLiveUdpFlowCorpusFixtures() []reloadLiveUdpFlowCorpusFixture {
	return []reloadLiveUdpFlowCorpusFixture{
		{
			name:           "staged_hot_reload_preserves_established_full_cone_flow",
			oldEpoch:       41,
			successorEpoch: 42,
		},
	}
}

// TestPhase0ReloadLiveUdpFlowCorpus_LegacyBaseline replays the compatible
// staged hot-reload path for an established full-cone UDP flow. The successor
// receives a packet with different newly-selected route facts, but the shared
// endpoint must continue using the original route, dialer, and drain lease.
//
// This legacy corpus exercises the shared-datapath compatibility path. The
// process-level SessionManager tests cover fresh-datapath and no-overlap
// reloads, where established flows retain their immutable bindings while new
// flows use the newly published generation.
func TestPhase0ReloadLiveUdpFlowCorpus_LegacyBaseline(t *testing.T) {
	for _, fixture := range phase0ReloadLiveUdpFlowCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			replayReloadLiveUdpFlowCorpusFixture(t, fixture)
		})
	}
}

func replayReloadLiveUdpFlowCorpusFixture(t *testing.T, fixture reloadLiveUdpFlowCorpusFixture) {
	t.Helper()

	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	t.Cleanup(func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	})

	oldSnapshot := newReloadCorpusPolicySnapshot(t, fixture.oldEpoch)
	successorSnapshot := newReloadCorpusPolicySnapshot(t, fixture.successorEpoch)
	oldTracker := newControlPlaneDrainTracker()
	successorTracker := newControlPlaneDrainTracker()

	oldConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	oldDialer, oldUnderlay := newCountingProxyEndpointDialer("hysteria2", "old-proxy.example:443", oldConn)
	oldPlane := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(oldDialer))
	oldPlane.policySnapshot = oldSnapshot
	oldPlane.drainTracker = oldTracker

	successorConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	successorDialer, successorUnderlay := newCountingProxyEndpointDialer("hysteria2", "successor-proxy.example:443", successorConn)
	successorPlane := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(successorDialer))
	successorPlane.policySnapshot = successorSnapshot
	successorPlane.drainTracker = successorTracker
	if !successorPlane.InheritDialerHealthFrom(oldPlane) {
		t.Fatal("expected staged hot reload to detect overlapping dialers")
	}

	src := mustParseAddrPort("192.0.2.10:41000")
	dst := mustParseAddrPort("198.51.100.20:443")
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	oldRoute := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
		Mark:     41,
		Must:     1,
	}
	if err := oldPlane.handlePkt(nil, payload, src, dst, oldRoute, flowDecision, false); err != nil {
		t.Fatalf("old generation handlePkt() error = %v", err)
	}

	endpoint, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || endpoint == nil {
		t.Fatal("old generation did not create the expected UDP endpoint")
	}
	oldBinding := endpoint.FlowBinding()
	if oldBinding.Route.PolicyEpoch != oldSnapshot.Epoch() ||
		oldBinding.Route.Outbound != consts.OutboundUserDefinedMin ||
		oldBinding.Route.Mark != oldRoute.Mark || !oldBinding.Route.Must {
		t.Fatalf("old flow route binding = %+v", oldBinding.Route)
	}
	if oldBinding.Egress.Dialer != oldDialer || oldBinding.Egress.Target != dst.String() {
		t.Fatalf("old flow egress binding = %+v", oldBinding.Egress)
	}
	if got := oldTracker.Count(); got != 1 {
		t.Fatalf("old generation active endpoint count = %d, want 1", got)
	}
	if got := successorTracker.Count(); got != 0 {
		t.Fatalf("successor generation active endpoint count before reuse = %d, want 0", got)
	}

	// The successor's packet represents a newly published policy epoch. If the
	// flow were admitted anew it would carry this different mark and use the
	// successor dialer, but an established endpoint must not be rebound.
	successorRoute := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
		Mark:     42,
	}
	if err := successorPlane.handlePkt(nil, payload, src, dst, successorRoute, flowDecision, false); err != nil {
		t.Fatalf("successor generation handlePkt() error = %v", err)
	}

	reusedEndpoint, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || reusedEndpoint == nil {
		t.Fatal("successor generation removed the established UDP endpoint")
	}
	if reusedEndpoint != endpoint {
		t.Fatal("successor generation created a replacement endpoint for the established flow")
	}
	reusedBinding := reusedEndpoint.FlowBinding()
	if reusedBinding.Route != oldBinding.Route || reusedBinding.Egress != oldBinding.Egress {
		t.Fatalf("reused flow binding = %+v, want original %+v", reusedBinding, oldBinding)
	}
	if got := oldUnderlay.calls.Load(); got != 1 {
		t.Fatalf("old DialContext calls = %d, want 1", got)
	}
	if got := successorUnderlay.calls.Load(); got != 0 {
		t.Fatalf("successor DialContext calls = %d, want 0 for an established flow", got)
	}
	if got := oldConn.writeCalls.Load(); got != 2 {
		t.Fatalf("old endpoint WriteTo calls = %d, want 2", got)
	}
	if got := successorConn.writeCalls.Load(); got != 0 {
		t.Fatalf("successor endpoint WriteTo calls = %d, want 0", got)
	}
	if got := oldTracker.Count(); got != 1 {
		t.Fatalf("old generation active endpoint count after reuse = %d, want 1", got)
	}
	if got := successorTracker.Count(); got != 0 {
		t.Fatalf("successor generation active endpoint count after reuse = %d, want 0", got)
	}

	if err := endpoint.Close(); err != nil {
		t.Fatalf("close established endpoint: %v", err)
	}
	if got := oldTracker.Count(); got != 0 {
		t.Fatalf("closed endpoint left old generation active count = %d, want 0", got)
	}
	if got := successorTracker.Count(); got != 0 {
		t.Fatalf("closed endpoint changed successor generation active count = %d, want 0", got)
	}
}

func newReloadCorpusPolicySnapshot(t *testing.T, epoch routing.PolicyEpoch) *routing.PolicySnapshot {
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
