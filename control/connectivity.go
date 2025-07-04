/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func (c *controlPlaneCore) outboundAliveChangeCallback(outbound uint8, noConnectivityTrySniff bool, noConnectivityOutbound consts.OutboundIndex) func(alive bool, networkType *dialer.NetworkType) {
	return func(alive bool, networkType *dialer.NetworkType) {
		if c.closed.Err() != nil {
			return
		}
		// if c.log.IsLevelEnabled(logrus.TraceLevel) {
		strAlive := "NOT ALIVE"
		if alive {
			strAlive = "ALIVE"
		}
		c.log.WithFields(logrus.Fields{
			"outboundId": outbound,
		}).Warnf("Outbound <%v> %v -> %v, notify the kernel program.", c.outboundId2Name[outbound], networkType.StringWithoutDns(), strAlive)
		// }

		// 0: go control plane
		// 1: direct
		// 2: block
		value := uint32(0)
		if !alive && !noConnectivityTrySniff {
			value = uint32(noConnectivityOutbound) + 1
		}

		if err := c.bpf.OutboundConnectivityMap.Update(bpfOutboundConnectivityQuery{
			Outbound:  outbound,
			L4proto:   networkType.L4Proto.ToL4Proto(),
			Ipversion: networkType.IpVersion.ToIpVersion(),
		}, value, ebpf.UpdateAny); err != nil {
			c.log.WithFields(logrus.Fields{
				"alive":    alive,
				"network":  networkType.StringWithoutDns(),
				"outbound": c.outboundId2Name[outbound],
			}).Warnf("Failed to notify the kernel program: %v", err)
		}
	}
}
