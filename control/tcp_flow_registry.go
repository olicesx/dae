/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
)

// TcpFlowKey identifies one transparent TCP flow by its converged ingress tuple.
// It remains available to diagnostics without being duplicated for every live
// connection; the ingress connection is the runtime lifecycle identity.
type TcpFlowKey struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

// NewTcpFlowKey constructs a TCP flow key from the transparent ingress tuple.
func NewTcpFlowKey(src, dst netip.AddrPort) TcpFlowKey {
	return TcpFlowKey{Src: src, Dst: dst}
}

// registerTCPFlow upgrades the existing incoming-connection entry with its
// egress. AbortConnections can then close both sides without a second registry
// or per-flow wrapper allocation.
func (c *ControlPlane) registerTCPFlow(ingress net.Conn, egress netproxy.Conn) bool {
	if c == nil || ingress == nil || egress == nil {
		return false
	}
	incomingConnectionOwnershipMu.Lock()
	defer incomingConnectionOwnershipMu.Unlock()
	if !c.acceptsRoutingEpochExecutionLocked() {
		return false
	}
	c.inConnections.Store(ingress, egress)
	return true
}

func (c *ControlPlane) unregisterTCPFlow(ingress net.Conn) {
	if c == nil || ingress == nil {
		return
	}
	incomingConnectionOwnershipMu.Lock()
	c.inConnections.Delete(ingress)
	incomingConnectionOwnershipMu.Unlock()
}

// tcpFlowEgress returns the egress attached to an accepted connection. This is
// intentionally ingress-indexed: tuple diagnostics are already emitted when
// the flow is established and do not require another live-flow map.
func (c *ControlPlane) tcpFlowEgress(ingress net.Conn) (netproxy.Conn, bool) {
	if c == nil || ingress == nil {
		return nil, false
	}
	if manager, _ := c.controlPlaneSessionManager(); manager != nil {
		if flow, ok := manager.flowForIngress(ingress); ok {
			return flow.Egress(), true
		}
	}
	value, ok := c.inConnections.Load(ingress)
	if !ok {
		return nil, false
	}
	egress, ok := value.(netproxy.Conn)
	return egress, ok && egress != nil
}
