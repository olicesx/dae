/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"context"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// backgroundRefresh performs asynchronous cache refresh for optimistic caching
// (RFC 8767). It runs after a stale entry has already been returned to the
// client, so a failure here must leave that entry in place: the client is
// currently being served from it, and evicting it would turn a refresh miss
// into a resolution failure for every subsequent query.
func (c *DnsController) backgroundRefresh(cacheKey string, dnsMessage *dnsmessage.Msg, req *udpRequest, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream) {
	defer func() {
		if recovered := recover(); recovered != nil && c.log != nil {
			c.log.Errorf("panic in background DNS refresh: %v", recovered)
		}
	}()
	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject || dnsMessage == nil {
		return
	}
	ctx, cancel := c.newWorkContext(5 * time.Second)
	defer cancel()
	defer func() {
		if cache := c.LookupDnsRespCache(cacheKey, false); cache != nil && cache.IsRefreshing() {
			cache.MarkRefreshed()
		}
	}()

	refresh := dnsMessage.Copy()
	if refresh == nil || len(refresh.Question) == 0 {
		return
	}
	refresh.Response = false
	refresh.Answer = nil
	refresh.Ns = nil
	refresh.Extra = nil

	if err := c.refreshDnsRespCache(ctx, refresh, req, upstream, cacheKey); err != nil &&
		c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"cacheKey": cacheKey,
			"error":    err,
		}).Debugf("background refresh failed")
	}
}

// refreshDnsRespCache resolves request upstream and replaces the cached
// response under cacheKey. It never deletes the existing entry on failure.
func (c *DnsController) refreshDnsRespCache(ctx context.Context, request *dnsmessage.Msg, req *udpRequest, upstream *dns.Upstream, cacheKey string) error {
	data, err := request.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	resolution, err := c.resolveDNSUpstream(ctx, 0, req, data, upstream)
	if err != nil {
		return err
	}
	response := resolution.response.Copy()
	response.Id = request.Id
	response.Compress = true
	if cacheKey == "" {
		return nil
	}
	return c.NormalizeAndCacheDnsResp_(response, cacheKey)
}
