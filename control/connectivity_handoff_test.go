/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func newConnectivityHandoffTestPlane(log *logrus.Logger, bpf *bpfObjects) *ControlPlane {
	core := &controlPlaneCore{
		log:                    log,
		closed:                 context.Background(),
		outboundId2Name:        map[uint8]string{0: "proxy"},
		bpfOwned:               false,
		routingEpochStagedSlot: routingEpochSlotUnset,
	}
	core.bpf.Store(bpf)
	return &ControlPlane{core: core}
}

func newConnectivityHandoffTestGroup(t *testing.T, log *logrus.Logger, callback func(bool, *dialer.NetworkType, bool)) *outbound.DialerGroup {
	t.Helper()
	d := dialer.NewDialer(
		direct.SymmetricDirect,
		&dialer.GlobalOption{
			Log:            log,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		dialer.InstanceOption{},
		&dialer.Property{Property: D.Property{Name: "node-a"}},
	)
	t.Cleanup(func() { _ = d.Close() })

	group := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            log,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"proxy",
		[]*dialer.Dialer{d},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		callback,
	)
	t.Cleanup(func() { _ = group.Close() })
	return group
}

func outboundConnectivityValue(t *testing.T, bpf *bpfObjects, outbound uint8, networkType *dialer.NetworkType) uint32 {
	t.Helper()
	var value uint32
	key := outboundConnectivityMapKey(outbound, networkType)
	if err := bpf.OutboundConnectivityMap.Lookup(key, &value); err != nil {
		t.Fatalf("lookup outbound connectivity key %d: %v", key, err)
	}
	return value
}

func TestPreparedConnectivityHandoffSuppressesStaleWritesAndRestoresRollbackOwner(t *testing.T) {
	connectivityMap := newJanitorTestMap(t, "outbound_connectivity_map")
	sharedBpf := &bpfObjects{bpfMaps: bpfMaps{OutboundConnectivityMap: connectivityMap}}
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldPlane := newConnectivityHandoffTestPlane(logger, sharedBpf)
	candidate := newConnectivityHandoffTestPlane(logger, sharedBpf)
	// A shared-BPF prepared generation is paused before its dialer groups are
	// constructed, so their initial all-alive callbacks cannot alter the active
	// generation's map.
	candidate.PauseOutboundConnectivityUpdates()
	candidate.outbounds = []*outbound.DialerGroup{
		newConnectivityHandoffTestGroup(t, logger, candidate.core.outboundAliveChangeCallback(0, false)),
	}

	tcp4 := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	oldWrite := oldPlane.core.outboundAliveChangeCallback(0, false)
	candidateWrite := candidate.core.outboundAliveChangeCallback(0, false)
	if got := outboundConnectivityValue(t, sharedBpf, 0, tcp4); got != 0 {
		t.Fatalf("prepared candidate initial callback changed connectivity to %d, want 0", got)
	}

	oldWrite(true, tcp4, false)
	if got := outboundConnectivityValue(t, sharedBpf, 0, tcp4); got != 1 {
		t.Fatalf("active generation connectivity = %d, want 1", got)
	}

	// The active generation is paused before the candidate commits its shared
	// BPF epoch. Neither side may mutate connectivity until publish or rollback.
	oldPlane.PauseOutboundConnectivityUpdates()
	oldWrite(false, tcp4, false)
	candidateWrite(false, tcp4, false)
	if got := outboundConnectivityValue(t, sharedBpf, 0, tcp4); got != 1 {
		t.Fatalf("prepared cutover connectivity = %d, want active value 1", got)
	}

	// A failed prepared candidate leaves it paused and restores the old writer.
	oldPlane.ResumeOutboundConnectivityUpdates()
	oldWrite(false, tcp4, false)
	candidateWrite(true, tcp4, false)
	if got := outboundConnectivityValue(t, sharedBpf, 0, tcp4); got != 0 {
		t.Fatalf("rollback did not restore old generation connectivity owner: got %d, want 0", got)
	}

	oldWrite(true, tcp4, false)
	oldPlane.PauseOutboundConnectivityUpdates()
	if got := outboundConnectivityValue(t, sharedBpf, 0, tcp4); got != 1 {
		t.Fatalf("second prepared cutover baseline = %d, want 1", got)
	}

	// The candidate publishes its current snapshot only after supervisor
	// publication. The old generation stays unable to overwrite that snapshot.
	candidate.ResumeOutboundConnectivityUpdates()
	if got := outboundConnectivityValue(t, sharedBpf, 0, tcp4); got != 1 {
		t.Fatalf("published candidate health snapshot = %d, want 1", got)
	}
	candidateWrite(false, tcp4, false)
	oldWrite(true, tcp4, false)
	if got := outboundConnectivityValue(t, sharedBpf, 0, tcp4); got != 0 {
		t.Fatalf("old generation overwrote published candidate connectivity: got %d, want 0", got)
	}

	candidateWrite(true, tcp4, false)
	oldPlane.MarkRetired()
	oldWrite(false, tcp4, false)
	if got := outboundConnectivityValue(t, sharedBpf, 0, tcp4); got != 1 {
		t.Fatalf("retiring generation overwrote published connectivity: got %d, want 1", got)
	}
}
