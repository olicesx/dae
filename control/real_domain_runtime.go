/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
	"golang.org/x/sync/singleflight"
)

// controlPlaneRealDomainRuntime groups the real-domain detection state: the
// positive bloom filter, negative caches, dialer selection snapshots, TCP
// sniff negative cache, and the negative-cache janitor lifecycle.
type controlPlaneRealDomainRuntime struct {
	muRealDomainSet   sync.RWMutex
	realDomainSet     *bloom.BloomFilter
	realDomainNegSet  sync.Map // map[string]int64 (expiresAt unix nano)
	dnsDialerSnapshot sync.Map // map[dnsDialerSnapshotKey]*dnsDialerSnapshotEntry
	dnsDialerPenalty  sync.Map // map[dnsDialerPenaltyKey]*dnsDialerPenaltyEntry
	tcpSniffNegMu     sync.RWMutex
	tcpSniffNegSet    map[tcpSniffNegKey]tcpSniffNegEntry
	realDomainProbeS  singleflight.Group
	negJanitorStop    chan struct{}
	negJanitorDone    chan struct{}
	negJanitorOnce    sync.Once
}

func newControlPlaneRealDomainRuntime() controlPlaneRealDomainRuntime {
	return controlPlaneRealDomainRuntime{
		muRealDomainSet: sync.RWMutex{},
		realDomainSet:   bloom.NewWithEstimates(2048, 0.001),
		tcpSniffNegSet:  make(map[tcpSniffNegKey]tcpSniffNegEntry),
		negJanitorStop:  make(chan struct{}),
		negJanitorDone:  make(chan struct{}),
	}
}
