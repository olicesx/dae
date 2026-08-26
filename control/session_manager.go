/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

var (
	// ErrSessionManagerClosed is returned when a flow is registered after the
	// process-level session manager has begun shutdown.
	ErrSessionManagerClosed = stderrors.New("session manager is closed")
	// ErrFlowAlreadyRegistered is returned when an ingress connection already
	// belongs to a live flow runtime.
	ErrFlowAlreadyRegistered = stderrors.New("flow is already registered")
)

type sessionGenerationState struct {
	active int
}

type controlPlaneSessionManagerBinding struct {
	manager *SessionManager
	owned   bool
}

type udpFlowSourceSnapshot struct {
	flows []*UDPFlowRuntime
	// epochCounts tallies held flows per policy epoch. It is rebuilt
	// together with flows (writers already reserialize under mu) so
	// retainedUDPEndpoint can skip its whole O(flows) scan when the
	// current epoch already owns every flow — the steady state between
	// reloads.
	epochCounts map[routing.PolicyEpoch]int
}

// SessionManager owns established flow lifecycles independently of any
// ControlPlane generation. Reload swaps the policy used for new flows while
// existing runtimes retain their original sockets and immutable bindings.
type SessionManager struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu             sync.RWMutex
	closed         bool
	flows          map[net.Conn]*FlowRuntime
	udpFlows       map[*UdpEndpoint]*UDPFlowRuntime
	udpBySource    sync.Map // map[netip.AddrPort]*udpFlowSourceSnapshot
	generations    map[routing.PolicyEpoch]*sessionGenerationState
	pinnedTCP      map[bpfTuplesKey]int
	pinnedRedirect map[bpfRedirectTuple]int

	udpStateMu sync.RWMutex
	udpBPF     atomic.Pointer[bpfObjects]
	pinnedUDP  map[bpfTuplesKey]int

	closeOnce sync.Once
	closeErr  error
}

// FlowRuntime is the process-owned lifecycle capsule for one established TCP
// flow. Its context is independent from the ControlPlane that selected the
// immutable route and egress binding.
type FlowRuntime struct {
	manager *SessionManager

	ingress net.Conn
	egress  netproxy.Conn
	binding TcpFlowBinding

	ctx    context.Context
	cancel context.CancelFunc

	egressLease    *egressRuntimeLease
	pinKeys        [2]bpfTuplesKey
	pinKeyCount    uint8
	redirectKey    bpfRedirectTuple
	hasRedirectKey bool

	// migratedBpf tracks bpfObjects sets (other than the manager's primary
	// udpBPF) into which this flow's conn_state_map entries were re-pinned.
	// releaseFlow uses this to clean up every map that still holds an entry,
	// mirroring Cilium's "graceful period" cleanup: the owning generation's
	// map is gone by the time the flow finishes, so stale entries must not
	// leak into successor maps.
	migratedBpf []*bpfObjects

	finishOnce  sync.Once
	abortOnce   sync.Once
	migrateOnce sync.Once
}

// UDPFlowRuntime keeps an established UDP endpoint and its immutable route
// binding alive independently of the ControlPlane that selected it.
type UDPFlowRuntime struct {
	manager  *SessionManager
	endpoint *UdpEndpoint
	binding  UdpFlowBinding

	ctx    context.Context
	cancel context.CancelFunc

	egressLease *egressRuntimeLease

	finishOnce sync.Once
	abortOnce  sync.Once
}

// NewSessionManager constructs a process-level flow owner. A nil parent uses
// context.Background.
func NewSessionManager(parent context.Context) *SessionManager {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &SessionManager{
		ctx:            ctx,
		cancel:         cancel,
		flows:          make(map[net.Conn]*FlowRuntime),
		udpFlows:       make(map[*UdpEndpoint]*UDPFlowRuntime),
		generations:    make(map[routing.PolicyEpoch]*sessionGenerationState),
		pinnedTCP:      make(map[bpfTuplesKey]int),
		pinnedRedirect: make(map[bpfRedirectTuple]int),
		pinnedUDP:      make(map[bpfTuplesKey]int),
	}
}

// AttachSessionManager installs the process-level session owner used by this
// control plane. It must be called before Serve starts accepting connections.
// Existing constructors remain compatible by creating a private manager lazily
// when no process owner is attached.
func (c *ControlPlane) AttachSessionManager(manager *SessionManager) error {
	if c == nil || manager == nil {
		return fmt.Errorf("attach session manager: manager is required")
	}
	incomingConnectionOwnershipMu.Lock()
	defer incomingConnectionOwnershipMu.Unlock()
	if c.drainTracker != nil && c.drainTracker.Count() != 0 {
		return fmt.Errorf("attach session manager after connection admission")
	}
	if c.udpIngressAdmission.state.Load() != 0 {
		return fmt.Errorf("attach session manager after UDP ingress admission")
	}
	activeIngress := false
	c.inConnections.Range(func(_, _ any) bool {
		activeIngress = true
		return false
	})
	if activeIngress {
		return fmt.Errorf("attach session manager with active ingress")
	}

	c.sessionManagerMu.Lock()
	previous := c.sessionManager
	previousOwned := c.ownsSessionManager
	if previous != nil && previous != manager && previous.ActiveConnections() != 0 {
		c.sessionManagerMu.Unlock()
		return fmt.Errorf("attach session manager with active private flows")
	}
	if err := manager.prepareControlPlane(c); err != nil {
		c.sessionManagerMu.Unlock()
		return err
	}
	c.sessionManager = manager
	c.ownsSessionManager = false
	c.sessionManagerBinding.Store(&controlPlaneSessionManagerBinding{manager: manager})
	c.sessionManagerMu.Unlock()
	if previousOwned && previous != nil && previous != manager {
		return previous.Close()
	}
	return nil
}

func (m *SessionManager) prepareControlPlane(c *ControlPlane) error {
	if m == nil || c == nil {
		return ErrSessionManagerClosed
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrSessionManagerClosed
	}
	m.mu.Unlock()

	if bpf := c.PeekBpf(); bpf != nil {
		m.udpBPF.CompareAndSwap(nil, bpf)
	}
	return nil
}

func (c *ControlPlane) sessionManagerForFlow(parent context.Context) *SessionManager {
	if c == nil {
		return nil
	}
	if binding := c.sessionManagerBinding.Load(); binding != nil {
		return binding.manager
	}
	c.sessionManagerMu.Lock()
	defer c.sessionManagerMu.Unlock()
	if c.sessionManager == nil {
		c.sessionManager = NewSessionManager(parent)
		c.ownsSessionManager = true
	}
	c.sessionManagerBinding.Store(&controlPlaneSessionManagerBinding{
		manager: c.sessionManager,
		owned:   c.ownsSessionManager,
	})
	return c.sessionManager
}

func (c *ControlPlane) controlPlaneSessionManager() (*SessionManager, bool) {
	if c == nil {
		return nil, false
	}
	if binding := c.sessionManagerBinding.Load(); binding != nil {
		return binding.manager, binding.owned
	}
	c.sessionManagerMu.Lock()
	manager := c.sessionManager
	owned := c.ownsSessionManager
	if manager != nil {
		c.sessionManagerBinding.Store(&controlPlaneSessionManagerBinding{
			manager: manager,
			owned:   owned,
		})
	}
	c.sessionManagerMu.Unlock()
	return manager, owned
}

func (c *ControlPlane) adoptTCPFlow(
	parent context.Context,
	ownership *incomingConnectionLease,
	ingress net.Conn,
	egress netproxy.Conn,
	binding TcpFlowBinding,
	src netip.AddrPort,
	dst netip.AddrPort,
) (*FlowRuntime, error) {
	manager := c.sessionManagerForFlow(parent)
	if manager == nil {
		return nil, ErrSessionManagerClosed
	}
	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_TCP)),
		bpfTuplesKeyFromAddrPorts(dst, src, uint8(unix.IPPROTO_TCP)),
	}
	incomingConnectionOwnershipMu.Lock()
	if !c.acceptsRoutingEpochExecutionLocked() || (ownership != nil && ownership.owner != c) {
		incomingConnectionOwnershipMu.Unlock()
		return nil, errRoutingEpochOwnerUnavailable
	}
	var runtime *egressRuntime
	if egress != nil {
		runtime = c.egressRuntime
	}
	flow, err := manager.adoptTCP(ingress, egress, binding, runtime, keys)
	var drainRelease func()
	if err == nil && ownership != nil {
		drainRelease = ownership.releaseLocked()
	}
	incomingConnectionOwnershipMu.Unlock()
	if drainRelease != nil {
		drainRelease()
	}
	return flow, err
}

// Context returns the flow-specific lifetime context.
func (f *FlowRuntime) Context() context.Context {
	if f == nil || f.ctx == nil {
		return context.Background()
	}
	return f.ctx
}

// Ingress returns the accepted transparent connection.
func (f *FlowRuntime) Ingress() net.Conn {
	if f == nil {
		return nil
	}
	return f.ingress
}

// Egress returns the concrete outbound connection selected at establishment.
// It is nil for locally terminated flows such as transparent DNS-over-TCP.
func (f *FlowRuntime) Egress() netproxy.Conn {
	if f == nil {
		return nil
	}
	return f.egress
}

// Binding returns the immutable route and concrete egress decision.
func (f *FlowRuntime) Binding() TcpFlowBinding {
	if f == nil {
		return TcpFlowBinding{}
	}
	return f.binding
}

func (m *SessionManager) adoptTCP(
	ingress net.Conn,
	egress netproxy.Conn,
	binding TcpFlowBinding,
	runtime *egressRuntime,
	pinKeys []bpfTuplesKey,
) (*FlowRuntime, error) {
	if m == nil {
		return nil, ErrSessionManagerClosed
	}
	if ingress == nil {
		return nil, fmt.Errorf("adopt TCP flow: ingress is required")
	}
	lease, retainedOutbound, ok := runtime.acquireEgress(binding.Egress.Dialer, binding.Egress.Outbound)
	if !ok {
		return nil, fmt.Errorf("adopt TCP flow: egress runtime is retiring")
	}
	binding.Egress.Outbound = retainedOutbound
	ctx, cancel := context.WithCancel(m.ctx)
	flow := &FlowRuntime{
		manager:     m,
		ingress:     ingress,
		egress:      egress,
		binding:     binding,
		ctx:         ctx,
		cancel:      cancel,
		egressLease: lease,
	}
	if len(pinKeys) > len(flow.pinKeys) {
		pinKeys = pinKeys[:len(flow.pinKeys)]
	}
	flow.pinKeyCount = uint8(copy(flow.pinKeys[:], pinKeys))

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		cancel()
		_ = lease.release()
		return nil, ErrSessionManagerClosed
	}
	if _, exists := m.flows[ingress]; exists {
		m.mu.Unlock()
		cancel()
		_ = lease.release()
		return nil, ErrFlowAlreadyRegistered
	}
	m.flows[ingress] = flow
	m.retainGenerationLocked(binding.Route.PolicyEpoch)
	for i := range int(flow.pinKeyCount) {
		m.pinnedTCP[flow.pinKeys[i]]++
	}
	if flow.pinKeyCount > 0 {
		flow.redirectKey = redirectTupleForFlow(flow.pinKeys[0])
		flow.hasRedirectKey = true
		m.pinnedRedirect[flow.redirectKey]++
	}
	m.mu.Unlock()
	return flow, nil
}

func (f *FlowRuntime) finish() {
	if f == nil {
		return
	}
	f.finishOnce.Do(func() {
		if f.manager != nil {
			f.manager.releaseFlow(f)
			return
		}
		if f.cancel != nil {
			f.cancel()
		}
		_ = f.egressLease.release()
	})
}

func (m *SessionManager) releaseFlow(flow *FlowRuntime) {
	if m == nil || flow == nil {
		return
	}
	deleteKeys := make([]bpfTuplesKey, 0, flow.pinKeyCount)
	migratedMaps := []*bpfObjects(nil)
	m.mu.Lock()
	if current := m.flows[flow.ingress]; current == flow {
		delete(m.flows, flow.ingress)
		m.releaseGenerationLocked(flow.binding.Route.PolicyEpoch)

		// For each migrated bpfObjects set, undo the per-map refcount
		// boost that repinConnStateMapsForRollback applied. After this
		// loop the pinnedTCP refcounts reflect only the primary map, so
		// the standard refcount <= 1 logic below produces correct
		// deleteKeys for the primary (janitor-scanned) map.
		for _, bpf := range flow.migratedBpf {
			if bpf != nil && bpf.ConnStateMap != nil {
				for i := range int(flow.pinKeyCount) {
					key := flow.pinKeys[i]
					if refs := m.pinnedTCP[key]; refs <= 1 {
						delete(m.pinnedTCP, key)
					} else {
						m.pinnedTCP[key] = refs - 1
					}
				}
			}
		}

		for i := range int(flow.pinKeyCount) {
			key := flow.pinKeys[i]
			if refs := m.pinnedTCP[key]; refs <= 1 {
				delete(m.pinnedTCP, key)
				deleteKeys = append(deleteKeys, key)
			} else {
				m.pinnedTCP[key] = refs - 1
			}
		}
		if flow.hasRedirectKey {
			if refs := m.pinnedRedirect[flow.redirectKey]; refs <= 1 {
				delete(m.pinnedRedirect, flow.redirectKey)
			} else {
				m.pinnedRedirect[flow.redirectKey] = refs - 1
			}
		}
		migratedMaps = flow.migratedBpf
	}
	m.mu.Unlock()
	if len(deleteKeys) > 0 {
		m.udpStateMu.RLock()
		if bpf := m.udpBPF.Load(); bpf != nil && bpf.ConnStateMap != nil {
			_, _ = BpfMapBatchDelete(bpf.ConnStateMap, deleteKeys)
		}
		m.udpStateMu.RUnlock()
	}
	// Also scrub every map this flow was migrated into. The refcounts
	// for these keys were already unwound above, so we only need to
	// physically remove the entries from the migrated maps.
	for _, bpf := range migratedMaps {
		if bpf != nil && bpf.ConnStateMap != nil {
			migrateKeys := make([]bpfTuplesKey, 0, flow.pinKeyCount)
			for i := range int(flow.pinKeyCount) {
				migrateKeys = append(migrateKeys, flow.pinKeys[i])
			}
			_, _ = BpfMapBatchDelete(bpf.ConnStateMap, migrateKeys)
		}
	}
	if flow.cancel != nil {
		flow.cancel()
	}
	_ = flow.egressLease.release()
}

func (m *SessionManager) retainGenerationLocked(epoch routing.PolicyEpoch) {
	state := m.generations[epoch]
	if state == nil {
		state = &sessionGenerationState{}
		m.generations[epoch] = state
	}
	state.active++
}

func (m *SessionManager) releaseGenerationLocked(epoch routing.PolicyEpoch) {
	state := m.generations[epoch]
	if state == nil || state.active == 0 {
		return
	}
	state.active--
	if state.active == 0 {
		delete(m.generations, epoch)
	}
}

func (m *SessionManager) adoptUDP(endpoint *UdpEndpoint, binding UdpFlowBinding, runtime *egressRuntime) (*UDPFlowRuntime, error) {
	if m == nil {
		return nil, ErrSessionManagerClosed
	}
	if endpoint == nil {
		return nil, fmt.Errorf("adopt UDP flow: endpoint is required")
	}
	if binding.Egress.Dialer == nil {
		binding.Egress.Dialer = endpoint.Dialer
	}
	if binding.Egress.Outbound == nil {
		binding.Egress.Outbound = endpoint.Outbound
	}
	lease, retainedOutbound, ok := runtime.acquireEgress(binding.Egress.Dialer, binding.Egress.Outbound)
	if !ok {
		return nil, fmt.Errorf("adopt UDP flow: egress runtime is retiring")
	}
	binding.Egress.Outbound = retainedOutbound
	endpoint.Outbound = retainedOutbound
	endpoint.setFlowBinding(binding)
	ctx, cancel := context.WithCancel(m.ctx)
	flow := &UDPFlowRuntime{
		manager:     m,
		endpoint:    endpoint,
		binding:     binding,
		ctx:         ctx,
		cancel:      cancel,
		egressLease: lease,
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		cancel()
		_ = lease.release()
		return nil, ErrSessionManagerClosed
	}
	if _, exists := m.udpFlows[endpoint]; exists {
		m.mu.Unlock()
		cancel()
		_ = lease.release()
		return nil, ErrFlowAlreadyRegistered
	}
	m.udpFlows[endpoint] = flow
	m.appendUDPFlowSourceLocked(endpoint.poolKey.Src, flow)
	m.retainGenerationLocked(binding.Route.PolicyEpoch)
	endpoint.sessionRuntime = flow
	m.mu.Unlock()
	return flow, nil
}

func (f *UDPFlowRuntime) finish() {
	if f == nil {
		return
	}
	f.finishOnce.Do(func() {
		if f.manager != nil {
			f.manager.releaseUDPFlow(f)
			return
		}
		if f.cancel != nil {
			f.cancel()
		}
		_ = f.egressLease.release()
	})
}

func (m *SessionManager) releaseUDPFlow(flow *UDPFlowRuntime) {
	if m == nil || flow == nil {
		return
	}
	m.mu.Lock()
	if current := m.udpFlows[flow.endpoint]; current == flow {
		delete(m.udpFlows, flow.endpoint)
		m.removeUDPFlowSourceLocked(flow.endpoint.poolKey.Src, flow)
		m.releaseGenerationLocked(flow.binding.Route.PolicyEpoch)
	}
	m.mu.Unlock()
	if flow.cancel != nil {
		flow.cancel()
	}
	_ = flow.egressLease.release()
}

func (f *UDPFlowRuntime) abort() error {
	if f == nil {
		return nil
	}
	var err error
	f.abortOnce.Do(func() {
		if f.cancel != nil {
			f.cancel()
		}
		if f.endpoint != nil {
			f.endpoint.dead.Store(true)
			f.endpoint.selfRemoveFromPool()
			err = f.endpoint.Close()
		}
		f.finish()
	})
	return err
}

func (m *SessionManager) retainedUDPEndpoint(src, dst netip.AddrPort, result *bpfRoutingResult, currentEpoch routing.PolicyEpoch) (*UdpEndpoint, bool) {
	if m == nil {
		return nil, false
	}
	desiredScope := newUdpEndpointRouteScope(result)
	value, ok := m.udpBySource.Load(src)
	if !ok {
		return nil, false
	}
	snapshot, ok := value.(*udpFlowSourceSnapshot)
	if !ok || snapshot == nil {
		return nil, false
	}
	if snapshot.epochCounts[currentEpoch] == len(snapshot.flows) {
		// Every flow for this source already routes under the current
		// epoch: no retained (stale-epoch) endpoint can exist. This keeps
		// the per-packet probe off the O(flows) scan for high-fan-out
		// sources outside reload windows.
		return nil, false
	}
	var selected *UDPFlowRuntime
	selectedScore := -1
	for _, flow := range snapshot.flows {
		if flow == nil || flow.endpoint == nil || flow.binding.Route.PolicyEpoch == currentEpoch {
			continue
		}
		key := flow.endpoint.poolKey
		if key.Dst.IsValid() && key.Dst != dst {
			continue
		}
		if key.RouteScope != (udpEndpointRouteScope{}) && key.RouteScope != desiredScope {
			continue
		}
		score := 0
		if key.Dst.IsValid() {
			score += 2
		}
		if key.RouteScope == desiredScope {
			score++
		}
		if score > selectedScore {
			selected = flow
			selectedScore = score
		}
	}
	if selected == nil || selected.endpoint.IsDead() {
		return nil, false
	}
	return selected.endpoint, true
}

// appendUDPFlowSourceLocked publishes a new immutable per-source index. The
// caller serializes writers with SessionManager.mu.
func (m *SessionManager) appendUDPFlowSourceLocked(src netip.AddrPort, flow *UDPFlowRuntime) {
	if m == nil || flow == nil {
		return
	}
	var current []*UDPFlowRuntime
	if value, ok := m.udpBySource.Load(src); ok {
		if snapshot, snapshotOK := value.(*udpFlowSourceSnapshot); snapshotOK && snapshot != nil {
			current = snapshot.flows
		}
	}
	next := make([]*UDPFlowRuntime, len(current)+1)
	copy(next, current)
	next[len(current)] = flow
	m.udpBySource.Store(src, &udpFlowSourceSnapshot{
		flows:       next,
		epochCounts: udpFlowEpochCounts(next),
	})
}

// removeUDPFlowSourceLocked replaces one immutable per-source index. The
// caller serializes writers with SessionManager.mu.
func (m *SessionManager) removeUDPFlowSourceLocked(src netip.AddrPort, flow *UDPFlowRuntime) {
	if m == nil || flow == nil {
		return
	}
	value, ok := m.udpBySource.Load(src)
	if !ok {
		return
	}
	snapshot, ok := value.(*udpFlowSourceSnapshot)
	if !ok || snapshot == nil {
		return
	}
	index := -1
	for i, candidate := range snapshot.flows {
		if candidate == flow {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	if len(snapshot.flows) == 1 {
		m.udpBySource.Delete(src)
		return
	}
	next := make([]*UDPFlowRuntime, len(snapshot.flows)-1)
	copy(next, snapshot.flows[:index])
	copy(next[index:], snapshot.flows[index+1:])
	m.udpBySource.Store(src, &udpFlowSourceSnapshot{
		flows:       next,
		epochCounts: udpFlowEpochCounts(next),
	})
}

// udpFlowEpochCounts tallies the routing epoch of every held flow. The
// snapshot rebuild paths are already O(flows); folding the tally in keeps the
// per-packet retained-endpoint probe O(1) in the steady state.
func udpFlowEpochCounts(flows []*UDPFlowRuntime) map[routing.PolicyEpoch]int {
	counts := make(map[routing.PolicyEpoch]int, 1)
	for _, flow := range flows {
		if flow != nil {
			counts[flow.binding.Route.PolicyEpoch]++
		}
	}
	return counts
}

// ActiveConnections returns all process-owned TCP and UDP flows.
func (m *SessionManager) ActiveConnections() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	n := len(m.flows) + len(m.udpFlows)
	m.mu.RUnlock()
	return n
}

func (f *FlowRuntime) abort() error {
	if f == nil {
		return nil
	}
	var err error
	f.abortOnce.Do(func() {
		if f.cancel != nil {
			f.cancel()
		}
		var errs []error
		if f.ingress != nil {
			if closeErr := f.ingress.Close(); closeErr != nil && !commonerrors.IsClosedConnection(closeErr) {
				errs = append(errs, closeErr)
			}
		}
		if f.egress != nil {
			if closeErr := f.egress.Close(); closeErr != nil && !commonerrors.IsClosedConnection(closeErr) {
				errs = append(errs, closeErr)
			}
		}
		err = stderrors.Join(errs...)
		f.finish()
	})
	return err
}

// migrate transfers a TCP flow from its current generation to a new one
// without closing the underlying sockets. It re-pins BPF conn_state_map
// entries, swaps the egress lease, and updates the generation tracking so
// that the flow survives a same-port reload. On failure the flow is left
// untouched so the caller can fall back to abort.
//
// The migration is transactional: if re-pinning fails the flow keeps its
// original lease and epoch, and the new bpfObjects does not retain stale
// entries. Once the generation tracking has moved to the new epoch the
// migration has committed and the old lease is released.
func (f *FlowRuntime) migrate(m *SessionManager, newBpf *bpfObjects, newLease *egressRuntimeLease, newOutbound *outbound.DialerGroup, newEpoch routing.PolicyEpoch) error {
	if f == nil {
		return nil
	}
	var err error
	f.migrateOnce.Do(func() {
		oldEpoch := f.binding.Route.PolicyEpoch
		oldLease := f.egressLease

		// Step 1: BPF re-pin. Failures here are non-fatal — the flow can
		// still relay via userspace — so we proceed even if no entries
		// were copied. Successful pins are tracked for cleanup on finish.
		if newBpf != nil {
			f.repinConnStateMapsForRollback(newBpf)
		}

		// Step 2: Bind the new lease before releasing the old one. This
		// keeps the dialer reference count monotonic across the swap.
		f.egressLease = newLease
		if newOutbound != nil {
			f.binding.Egress.Outbound = newOutbound
		}

		// Step 3: Move the flow from the old generation to the new one.
		// This is the commit point: after this the flow belongs to the
		// new generation for tracking purposes, and the old lease can be
		// released without risking an underflow in the old runtime.
		m.mu.Lock()
		m.releaseGenerationLocked(oldEpoch)
		f.binding.Route.PolicyEpoch = newEpoch
		m.retainGenerationLocked(newEpoch)
		m.mu.Unlock()

		// Commit complete: drop the old lease now that the new one is
		// bound and the flow is tracked by the new generation.
		if oldLease != nil {
			_ = oldLease.release()
		}
		err = nil
	})
	return err
}

// repinConnStateMapsForRollback is the rollback-aware variant of
// repinConnStateMaps. It returns the keys that were successfully re-pinned
// so the caller can undo the operation if a later step fails.
func (f *FlowRuntime) repinConnStateMapsForRollback(newBpf *bpfObjects) []bpfTuplesKey {
	if f == nil || newBpf == nil || newBpf.ConnStateMap == nil || f.manager == nil {
		return nil
	}
	oldBpf := f.manager.udpBPF.Load()
	if oldBpf == nil || oldBpf.ConnStateMap == nil {
		return nil
	}

	var rePinned []bpfTuplesKey
	for i := range int(f.pinKeyCount) {
		var value bpfConnState
		if err := oldBpf.ConnStateMap.Lookup(&f.pinKeys[i], &value); err != nil {
			continue
		}
		if err := newBpf.ConnStateMap.Update(&f.pinKeys[i], &value, ebpf.UpdateAny); err != nil {
			break
		}
		rePinned = append(rePinned, f.pinKeys[i])
	}
	if len(rePinned) > 0 {
		f.manager.mu.Lock()
		for _, key := range rePinned {
			f.manager.pinnedTCP[key]++
		}
		f.migratedBpf = append(f.migratedBpf, newBpf)
		f.manager.mu.Unlock()
	}
	return rePinned
}

// ActiveTCPConnections returns the number of process-owned TCP flows.
func (m *SessionManager) ActiveTCPConnections() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	n := len(m.flows)
	m.mu.RUnlock()
	return n
}

// AbortGeneration closes every flow established under one policy epoch.
// The manager remains open for flows created by other or future generations.
func (m *SessionManager) AbortGeneration(epoch routing.PolicyEpoch) error {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	flows := make([]*FlowRuntime, 0)
	udpFlows := make([]*UDPFlowRuntime, 0)
	for _, flow := range m.flows {
		if flow.binding.Route.PolicyEpoch == epoch {
			flows = append(flows, flow)
		}
	}
	for _, flow := range m.udpFlows {
		if flow.binding.Route.PolicyEpoch == epoch {
			udpFlows = append(udpFlows, flow)
		}
	}
	m.mu.RUnlock()
	var errs []error
	for _, flow := range flows {
		if err := flow.abort(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, flow := range udpFlows {
		if err := flow.abort(); err != nil {
			errs = append(errs, err)
		}
	}
	return stderrors.Join(errs...)
}

// MigrateGeneration attempts to transfer TCP flows established under the old
// epoch to the new generation without closing the underlying kernel sockets.
// Each flow keeps its relay goroutines alive and re-pins its conn_state_map
// entries into newBpf so the fresh BPF datapath can bypass userspace for
// subsequent packets. Flows that cannot be migrated (e.g. the new runtime
// does not hold a matching dialer reference) are left untouched and should
// be aborted or drained by the caller.
//
// Returns the count of successfully migrated flows and the count of flows
// that could not be migrated.
func (m *SessionManager) MigrateGeneration(
	oldEpoch, newEpoch routing.PolicyEpoch,
	newBpf *bpfObjects,
	newRuntime *egressRuntime,
) (migrated int, remaining int) {
	if m == nil {
		return 0, 0
	}
	m.mu.RLock()
	var flows []*FlowRuntime
	for _, flow := range m.flows {
		if flow.binding.Route.PolicyEpoch == oldEpoch {
			flows = append(flows, flow)
		}
	}
	m.mu.RUnlock()

	for _, flow := range flows {
		// Try to acquire an equivalent lease from the new runtime so the
		// flow's dialer reference does not keep the old generation alive.
		newLease, retainedGroup := newRuntime.transferLease(flow.egressLease)
		if newLease == nil {
			remaining++
			continue
		}
		if err := flow.migrate(m, newBpf, newLease, retainedGroup, newEpoch); err != nil {
			// Migration failed: put back the lease and leave the flow
			// untouched. The caller may drain/abort it separately.
			if newLease != nil {
				_ = newLease.release()
			}
			remaining++
			continue
		}
		migrated++
	}
	return migrated, remaining
}

// AbortAll closes every established flow without closing the manager.
func (m *SessionManager) AbortAll() error {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	flows := make([]*FlowRuntime, 0, len(m.flows))
	udpFlows := make([]*UDPFlowRuntime, 0, len(m.udpFlows))
	for _, flow := range m.flows {
		flows = append(flows, flow)
	}
	for _, flow := range m.udpFlows {
		udpFlows = append(udpFlows, flow)
	}
	m.mu.RUnlock()
	var errs []error
	for _, flow := range flows {
		if err := flow.abort(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, flow := range udpFlows {
		if err := flow.abort(); err != nil {
			errs = append(errs, err)
		}
	}
	return stderrors.Join(errs...)
}

// Close prevents new adoption and aborts all process-owned flows.
func (m *SessionManager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.mu.Unlock()
		m.cancel()
		m.closeErr = m.AbortAll()
	})
	return m.closeErr
}
