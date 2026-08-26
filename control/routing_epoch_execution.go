/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	errRoutingEpochOwnerUnavailable = stderrors.New("routing epoch execution owner is unavailable")
	routingEpochPeerLinkMu          sync.Mutex
	incomingConnectionOwnershipMu   sync.Mutex
)

// incomingConnectionLease keeps an accepted TCP connection attached to the
// control plane currently responsible for executing its policy. During a
// staged reload it can move to the peer before either generation retires.
type incomingConnectionLease struct {
	conn         net.Conn
	owner        *ControlPlane
	drainRelease func()
	once         sync.Once
}

const routingEpochIngressClosed uint64 = 1 << 63

// routingEpochIngressGate accounts for packets that have already been read
// from a listener but have not reached their asynchronous UDP task yet. Its
// atomic fast path keeps ordinary packet ingress independent of the control
// plane drain mutex while allowing retirement to close admission exactly once.
type routingEpochIngressGate struct {
	state   atomic.Uint64
	waitMu  sync.Mutex
	drained chan struct{}
}

func (g *routingEpochIngressGate) tryAcquire() bool {
	if g == nil {
		return true
	}
	for {
		state := g.state.Load()
		if state&routingEpochIngressClosed != 0 {
			return false
		}
		if g.state.CompareAndSwap(state, state+1) {
			return true
		}
	}
}

func (g *routingEpochIngressGate) release() {
	if g == nil {
		return
	}
	if g.state.Add(^uint64(0)) != routingEpochIngressClosed {
		return
	}
	g.waitMu.Lock()
	if g.drained != nil {
		close(g.drained)
	}
	g.waitMu.Unlock()
}

func (g *routingEpochIngressGate) closeAndWait() {
	if g == nil {
		return
	}
	for {
		state := g.state.Load()
		if state&routingEpochIngressClosed != 0 {
			break
		}
		if g.state.CompareAndSwap(state, state|routingEpochIngressClosed) {
			break
		}
	}
	if g.state.Load() == routingEpochIngressClosed {
		return
	}
	g.waitMu.Lock()
	if g.state.Load() == routingEpochIngressClosed {
		g.waitMu.Unlock()
		return
	}
	if g.drained == nil {
		g.drained = make(chan struct{})
	}
	drained := g.drained
	g.waitMu.Unlock()
	<-drained
}

// LinkRoutingEpochPeer links two generations that share one BPF object during
// a staged reload. The association is intentionally pairwise and temporary:
// routing slots are reused by later reloads, so slot ownership remains local
// to the linked pair even though published execution owners are process-wide.
func (c *ControlPlane) LinkRoutingEpochPeer(peer *ControlPlane) error {
	if c == nil || peer == nil || c == peer {
		return fmt.Errorf("routing epoch peer must be a distinct control plane")
	}
	if c.core == nil || peer.core == nil {
		return fmt.Errorf("routing epoch peer requires initialized control planes")
	}
	cSlot := c.core.RoutingEpochSlot()
	peerSlot := peer.core.RoutingEpochSlot()
	if cSlot == peerSlot {
		return fmt.Errorf("routing epoch peers use the same slot %d", cSlot)
	}
	cBpf, peerBpf := c.core.PeekBpf(), peer.core.PeekBpf()
	if cBpf != nil && peerBpf != nil && cBpf != peerBpf {
		return fmt.Errorf("routing epoch peers do not share BPF objects")
	}
	cGeneration := uint16(c.core.datapathGeneration.Load())
	peerGeneration := uint16(peer.core.datapathGeneration.Load())
	if cBpf != nil && cBpf == peerBpf {
		if registered := bpfDatapathGeneration(cBpf); registered != 0 {
			if cGeneration != 0 && cGeneration != registered {
				return fmt.Errorf("routing epoch owner generation %d does not match shared BPF generation %d", cGeneration, registered)
			}
			if peerGeneration != 0 && peerGeneration != registered {
				return fmt.Errorf("routing epoch peer generation %d does not match shared BPF generation %d", peerGeneration, registered)
			}
			cGeneration = registered
			peerGeneration = registered
		}
	}
	if cGeneration != 0 && peerGeneration != 0 && cGeneration != peerGeneration {
		return fmt.Errorf("routing epoch peers use different datapath generations %d and %d", cGeneration, peerGeneration)
	}
	sharedGeneration := cGeneration
	if sharedGeneration == 0 {
		sharedGeneration = peerGeneration
	}
	if sharedGeneration != 0 {
		c.core.datapathGeneration.Store(uint32(sharedGeneration))
		peer.core.datapathGeneration.Store(uint32(sharedGeneration))
	}

	routingEpochPeerLinkMu.Lock()
	defer routingEpochPeerLinkMu.Unlock()

	c.routingEpochPeerMu.Lock()
	defer c.routingEpochPeerMu.Unlock()
	peer.routingEpochPeerMu.Lock()
	defer peer.routingEpochPeerMu.Unlock()
	if c.routingEpochPeer != nil && c.routingEpochPeer != peer {
		return fmt.Errorf("control plane already has a routing epoch peer")
	}
	if peer.routingEpochPeer != nil && peer.routingEpochPeer != c {
		return fmt.Errorf("routing epoch peer already belongs to another control plane")
	}
	c.routingEpochPeer = peer
	peer.routingEpochPeer = c
	c.routingEpochSlot.Store(cSlot)
	c.routingEpochSlotKnown.Store(true)
	peer.routingEpochSlot.Store(peerSlot)
	peer.routingEpochSlotKnown.Store(true)
	return nil
}

// UnlinkRoutingEpochPeer removes a staged reload association. Passing nil
// clears the current link regardless of its peer, which is useful while a
// generation is closing.
func (c *ControlPlane) UnlinkRoutingEpochPeer(peer *ControlPlane) {
	if c == nil {
		return
	}
	routingEpochPeerLinkMu.Lock()
	defer routingEpochPeerLinkMu.Unlock()

	c.routingEpochPeerMu.Lock()
	current := c.routingEpochPeer
	if current == nil || (peer != nil && current != peer) {
		c.routingEpochPeerMu.Unlock()
		return
	}
	c.routingEpochPeer = nil
	c.routingEpochPeerMu.Unlock()

	current.routingEpochPeerMu.Lock()
	if current.routingEpochPeer == c {
		current.routingEpochPeer = nil
	}
	current.routingEpochPeerMu.Unlock()
}

func (c *ControlPlane) routingEpochSlotMatches(slot uint32) bool {
	if c == nil {
		return false
	}
	if c.routingEpochSlotKnown.Load() {
		return c.routingEpochSlot.Load() == slot
	}
	return c.core != nil && c.core.RoutingEpochSlot() == slot
}

func (c *ControlPlane) routingEpochExecutionMatches(result *bpfRoutingResult) bool {
	if c == nil {
		return false
	}
	if result == nil {
		return true
	}
	resultGeneration := result.DatapathGeneration
	ownerGeneration := uint16(0)
	if c.core != nil {
		ownerGeneration = uint16(c.core.datapathGeneration.Load())
	}
	if resultGeneration != 0 && resultGeneration != ownerGeneration {
		return false
	}
	slot, known := decodeBpfRoutingEpochSlot(result.RoutingEpochSlot)
	return !known || c.routingEpochSlotMatches(slot)
}

func routingEpochOwnerUnavailableError(result *bpfRoutingResult) error {
	if result == nil {
		return errRoutingEpochOwnerUnavailable
	}
	slot, known := decodeBpfRoutingEpochSlot(result.RoutingEpochSlot)
	if !known {
		return fmt.Errorf("%w for unknown slot in datapath generation %d", errRoutingEpochOwnerUnavailable, result.DatapathGeneration)
	}
	return fmt.Errorf("%w for slot %d in datapath generation %d", errRoutingEpochOwnerUnavailable, slot, result.DatapathGeneration)
}

func publishedRoutingEpochExecutionOwner(source *ControlPlane, result *bpfRoutingResult) *ControlPlane {
	activeControlPlanePublication.mu.RLock()
	defer activeControlPlanePublication.mu.RUnlock()

	owner := activeControlPlanePublication.plane.Load()
	if owner != nil && owner != source && owner.acceptsRoutingEpochExecutionLocked() && owner.routingEpochExecutionMatches(result) {
		return owner
	}
	for candidate, publication := range activeControlPlanePublication.owners {
		if publication == 0 {
			continue
		}
		if candidate == nil || candidate == source || candidate == owner {
			continue
		}
		if candidate.acceptsRoutingEpochExecutionLocked() && candidate.routingEpochExecutionMatches(result) {
			return candidate
		}
	}
	return nil
}

func (c *ControlPlane) routingEpochExecutionOwner(result *bpfRoutingResult) (*ControlPlane, error) {
	if c == nil {
		return nil, errRoutingEpochOwnerUnavailable
	}
	if c.routingEpochExecutionMatches(result) {
		return c, nil
	}

	c.routingEpochPeerMu.RLock()
	peer := c.routingEpochPeer
	c.routingEpochPeerMu.RUnlock()
	if peer != nil && peer.routingEpochExecutionMatches(result) {
		return peer, nil
	}
	if published := publishedRoutingEpochExecutionOwner(c, result); published != nil {
		return published, nil
	}
	return nil, routingEpochOwnerUnavailableError(result)
}

// acquireRoutingEpochExecutionOwner resolves an attributed BPF result and,
// when it targets a staged peer, acquires that peer's execution lease before
// releasing the peer-link lock. StopRoutingEpochExecution closes admission
// under the same ownership lock, so a selected peer cannot begin work after
// retirement has committed to closing it.
func (c *ControlPlane) acquireRoutingEpochExecutionOwner(result *bpfRoutingResult) (*ControlPlane, func(), error) {
	if c == nil {
		return nil, nil, errRoutingEpochOwnerUnavailable
	}
	if c.routingEpochExecutionMatches(result) {
		return c, nil, nil
	}

	routingEpochPeerLinkMu.Lock()
	defer routingEpochPeerLinkMu.Unlock()
	c.routingEpochPeerMu.RLock()
	peer := c.routingEpochPeer
	c.routingEpochPeerMu.RUnlock()
	if peer == nil || !peer.routingEpochExecutionMatches(result) {
		peer = publishedRoutingEpochExecutionOwner(c, result)
		if peer == nil {
			return nil, nil, routingEpochOwnerUnavailableError(result)
		}
	}

	incomingConnectionOwnershipMu.Lock()
	if !peer.acceptsRoutingEpochExecutionLocked() || !peer.routingEpochExecutionMatches(result) {
		incomingConnectionOwnershipMu.Unlock()
		return nil, nil, routingEpochOwnerUnavailableError(result)
	}
	release := peer.acquireDrainTicket()
	incomingConnectionOwnershipMu.Unlock()
	return peer, release, nil
}

func (c *ControlPlane) ownsActiveRoutingEpoch() bool {
	if c == nil || c.core == nil || !c.core.routingEpochEnabled() {
		return true
	}
	active, err := c.core.readActiveRoutingEpochSlot()
	return err == nil && active == c.core.RoutingEpochSlot()
}

func (c *ControlPlane) acceptsRoutingEpochExecutionLocked() bool {
	return c != nil && !c.rejectNewConnections.Load() && !c.routingEpochExecutionClosed.Load()
}

func (c *ControlPlane) acquireRoutingEpochExecutionLeaseFor(result *bpfRoutingResult) (func(), bool) {
	incomingConnectionOwnershipMu.Lock()
	defer incomingConnectionOwnershipMu.Unlock()
	if !c.acceptsRoutingEpochExecutionLocked() || !c.routingEpochExecutionMatches(result) {
		return nil, false
	}
	return c.acquireDrainTicket(), true
}

func (c *ControlPlane) acquireIncomingConnectionLease(conn net.Conn) (*incomingConnectionLease, bool) {
	if c == nil || conn == nil {
		return nil, false
	}
	incomingConnectionOwnershipMu.Lock()
	defer incomingConnectionOwnershipMu.Unlock()
	if !c.acceptsRoutingEpochExecutionLocked() {
		_ = conn.Close()
		return nil, false
	}
	lease := &incomingConnectionLease{
		conn:         conn,
		owner:        c,
		drainRelease: c.acquireDrainTicket(),
	}
	c.inConnections.Store(conn, struct{}{})
	return lease, true
}

func (l *incomingConnectionLease) transferRoutingEpoch(owner *ControlPlane, result *bpfRoutingResult) bool {
	if l == nil || owner == nil || owner == l.owner {
		return l != nil && owner == l.owner && owner.routingEpochExecutionMatches(result)
	}
	incomingConnectionOwnershipMu.Lock()
	if l.owner == nil ||
		!l.owner.acceptsRoutingEpochExecutionLocked() ||
		!owner.acceptsRoutingEpochExecutionLocked() ||
		!owner.routingEpochExecutionMatches(result) {
		incomingConnectionOwnershipMu.Unlock()
		return false
	}
	previous := l.owner
	previousRelease := l.drainRelease
	owner.inConnections.Store(l.conn, struct{}{})
	previous.inConnections.Delete(l.conn)
	l.owner = owner
	l.drainRelease = owner.acquireDrainTicket()
	incomingConnectionOwnershipMu.Unlock()

	if previousRelease != nil {
		previousRelease()
	}
	return true
}

func (l *incomingConnectionLease) release() {
	if l == nil {
		return
	}
	incomingConnectionOwnershipMu.Lock()
	drainRelease := l.releaseLocked()
	incomingConnectionOwnershipMu.Unlock()
	if drainRelease != nil {
		drainRelease()
	}
}

// releaseLocked detaches the generation-owned ingress while the caller holds
// incomingConnectionOwnershipMu. The returned drain release must run after the
// ownership mutex is unlocked.
func (l *incomingConnectionLease) releaseLocked() (drainRelease func()) {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		owner := l.owner
		drainRelease = l.drainRelease
		l.owner = nil
		l.drainRelease = nil
		if owner != nil && l.conn != nil {
			owner.inConnections.Delete(l.conn)
		}
	})
	return drainRelease
}

func (c *ControlPlane) closeRoutingEpochExecution() {
	if c == nil {
		return
	}
	incomingConnectionOwnershipMu.Lock()
	c.routingEpochExecutionClosed.Store(true)
	incomingConnectionOwnershipMu.Unlock()
	c.unregisterRoutingEpochExecutionOwner()
}

// StopRoutingEpochExecution prevents further staged-peer dispatch and waits
// for work that acquired an execution lease before the gate closed. It is used
// immediately before a retired generation is canceled and closed.
func (c *ControlPlane) StopRoutingEpochExecution() {
	if c == nil {
		return
	}
	c.closeRoutingEpochExecution()
	c.udpIngressAdmission.closeAndWait()
	if c.drainTracker != nil {
		<-c.drainTracker.IdleCh()
	}
}

func (c *ControlPlane) takeIncomingConnectionsForAbort() ([]net.Conn, []netproxy.Conn, []error) {
	if c == nil {
		return nil, nil, nil
	}
	incomingConnectionOwnershipMu.Lock()
	c.routingEpochExecutionClosed.Store(true)
	c.rejectNewConnections.Store(true)
	var connections []net.Conn
	var flows []netproxy.Conn
	var errs []error
	c.inConnections.Range(func(key, value any) bool {
		conn, ok := key.(net.Conn)
		if ok {
			connections = append(connections, conn)
			if egress, flowOK := value.(netproxy.Conn); flowOK && egress != nil {
				flows = append(flows, egress)
			}
		} else {
			errs = append(errs, fmt.Errorf("unexpected type %T in inConnections", key))
		}
		c.inConnections.Delete(key)
		return true
	})
	incomingConnectionOwnershipMu.Unlock()
	c.unregisterRoutingEpochExecutionOwner()
	return connections, flows, errs
}
