/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/outbound/pool"
)

func (c *ControlPlane) submitOrderedUDPIngress(key UdpFlowKey, run UdpTask, data pool.PB, admission *routingEpochIngressGate) bool {
	if c != nil && c.udpOrderedDispatcher != nil {
		return c.udpOrderedDispatcher.submitOwned(key, run, data, admission)
	}
	return DefaultUdpTaskPool.EmitTask(key, run)
}

func (c *ControlPlane) orderedUDPEndpointCreateAdmission(flowDecision UdpFlowDecision) udpEndpointCreateAdmission {
	if c == nil || c.udpOrderedDispatcher == nil ||
		flowDecision.DispatchStrategy() != StrategyOrderedIngress {
		return nil
	}
	return c.udpOrderedDispatcher.acquireEndpointCreateAdmission
}

func (c *ControlPlane) closeUDPOrderedDispatcher() {
	if c == nil || c.udpOrderedDispatcher == nil || c.udpOrderedDispatcherShared {
		return
	}
	c.udpOrderedDispatcher.close()
}

func (c *ControlPlane) waitUDPOrderedDispatcher() {
	if c == nil || c.udpOrderedDispatcher == nil || c.udpOrderedDispatcherShared {
		return
	}
	c.udpOrderedDispatcher.wait()
}

func (c *ControlPlane) closeUDPReplyDispatcher() {
	if c == nil || c.udpReplyDispatcher == nil || c.udpReplyDispatcherShared {
		return
	}
	c.udpReplyDispatcher.close()
}

func (c *ControlPlane) waitUDPReplyDispatcher() {
	if c == nil || c.udpReplyDispatcher == nil || c.udpReplyDispatcherShared {
		return
	}
	c.udpReplyDispatcher.wait()
}
