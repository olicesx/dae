/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

// backgroundRefresh performs asynchronous cache refresh for optimistic caching (RFC 8767).
// This is called when a stale cache entry is returned to the client.
// The refresh happens in the background without blocking the client request.
func (c *DnsController) backgroundRefresh(cacheKey string, dnsMessage *dnsmessage.Msg, req *udpRequest, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream) {
	c.backgroundRefreshSnapshot(cacheKey, dnsMessage, dnsRequestSnapshotFromUDPRequest(req), upstreamIndex, upstream)
}
