/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

// TcpFlowKey identifies one transparent TCP flow by its converged ingress tuple.
// TCP has no full-cone or symmetric endpoint reuse: one live connection owns one
// tuple and its binding for the lifetime of that connection.
type TcpFlowKey struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

// NewTcpFlowKey constructs a TCP flow key from the transparent ingress tuple.
func NewTcpFlowKey(src, dst netip.AddrPort) TcpFlowKey {
	return TcpFlowKey{Src: src, Dst: dst}
}

// tcpFlowEntry retains the fixed route and egress choice for one live relay.
// The entry is immutable after registration; the registry only manages its
// lifetime and does not participate in relay copy loops.
type tcpFlowEntry struct {
	Key     TcpFlowKey
	Binding TcpFlowBinding
	Ingress net.Conn
	Egress  netproxy.Conn
}

// tcpFlowRegistry indexes a live TCP relay by both its tuple and the accepted
// connection. The latter keeps abort and drain cleanup aligned with the
// existing incoming-connection lifecycle.
type tcpFlowRegistry struct {
	byKey     sync.Map // map[TcpFlowKey]*tcpFlowEntry
	byIngress sync.Map // map[net.Conn]*tcpFlowEntry
}

func (r *tcpFlowRegistry) register(entry *tcpFlowEntry) {
	if r == nil || entry == nil || entry.Ingress == nil {
		return
	}
	r.byKey.Store(entry.Key, entry)
	r.byIngress.Store(entry.Ingress, entry)
}

func (r *tcpFlowRegistry) lookup(key TcpFlowKey) (*tcpFlowEntry, bool) {
	if r == nil {
		return nil, false
	}
	value, ok := r.byKey.Load(key)
	if !ok {
		return nil, false
	}
	entry, ok := value.(*tcpFlowEntry)
	return entry, ok
}

func (r *tcpFlowRegistry) lookupIngress(conn net.Conn) (*tcpFlowEntry, bool) {
	if r == nil || conn == nil {
		return nil, false
	}
	value, ok := r.byIngress.Load(conn)
	if !ok {
		return nil, false
	}
	entry, ok := value.(*tcpFlowEntry)
	return entry, ok
}

func (r *tcpFlowRegistry) remove(entry *tcpFlowEntry) {
	if r == nil || entry == nil {
		return
	}
	r.byKey.CompareAndDelete(entry.Key, entry)
	if entry.Ingress != nil {
		r.byIngress.CompareAndDelete(entry.Ingress, entry)
	}
}

func (r *tcpFlowRegistry) removeIngress(conn net.Conn) *tcpFlowEntry {
	entry, ok := r.lookupIngress(conn)
	if !ok {
		return nil
	}
	r.remove(entry)
	return entry
}

// registerTCPFlow records a successful transparent TCP dial. It shares the
// incoming-connection ownership lock with AbortConnections so a forced abort
// cannot leave a newly registered flow behind after its connection is closed.
func (c *ControlPlane) registerTCPFlow(src, dst netip.AddrPort, ingress net.Conn, egress netproxy.Conn, binding TcpFlowBinding) (*tcpFlowEntry, bool) {
	if c == nil || ingress == nil || egress == nil {
		return nil, false
	}
	incomingConnectionOwnershipMu.Lock()
	defer incomingConnectionOwnershipMu.Unlock()
	if c.rejectNewConnections.Load() {
		return nil, false
	}
	entry := &tcpFlowEntry{
		Key:     NewTcpFlowKey(src, dst),
		Binding: binding,
		Ingress: ingress,
		Egress:  egress,
	}
	c.tcpFlows.register(entry)
	return entry, true
}

func (c *ControlPlane) unregisterTCPFlow(entry *tcpFlowEntry) {
	if c == nil {
		return
	}
	c.tcpFlows.remove(entry)
}
