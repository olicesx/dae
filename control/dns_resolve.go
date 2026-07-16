/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DnsRequestSnapshot contains the immutable routing facts needed to resolve a
// DNS request. Transport sockets, packet recorders, and response writers stay
// in the protocol adapters.
type DnsRequestSnapshot struct {
	RealSrc netip.AddrPort
	RealDst netip.AddrPort

	routingResult    bpfRoutingResult
	hasRoutingResult bool
}

func dnsRequestSnapshotFromUDPRequest(req *udpRequest) DnsRequestSnapshot {
	if req == nil {
		return DnsRequestSnapshot{}
	}
	snapshot := DnsRequestSnapshot{
		RealSrc: req.realSrc,
		RealDst: req.realDst,
	}
	if req.routingResult != nil {
		snapshot.routingResult = *req.routingResult
		snapshot.hasRoutingResult = true
	}
	return snapshot
}

func (snapshot DnsRequestSnapshot) legacyUDPRequest() *udpRequest {
	req := &udpRequest{
		realSrc: snapshot.RealSrc,
		realDst: snapshot.RealDst,
	}
	if snapshot.hasRoutingResult {
		routingResult := snapshot.routingResult
		req.routingResult = &routingResult
	}
	return req
}

func (snapshot DnsRequestSnapshot) routingResultForRoute() *bpfRoutingResult {
	if !snapshot.hasRoutingResult {
		return nil
	}
	routingResult := snapshot.routingResult
	return &routingResult
}

func (runtime *dnsControllerRuntimeState) chooseBestDnsDialer(ctx context.Context, snapshot DnsRequestSnapshot, upstream *dns.Upstream) (*dialArgument, error) {
	if runtime == nil {
		return nil, fmt.Errorf("dns controller runtime is not configured")
	}
	if runtime.bestDialerSnapshotChooser != nil {
		return runtime.bestDialerSnapshotChooser(ctx, snapshot, upstream)
	}
	if runtime.bestDialerChooser != nil {
		return runtime.bestDialerChooser(ctx, snapshot.legacyUDPRequest(), upstream)
	}
	return nil, fmt.Errorf("dns controller runtime best dialer chooser is not configured")
}

// DnsResult is an owned DNS resolution result. Response is independent from
// the caller's query and may be handed to a transport adapter for delivery.
type DnsResult struct {
	Response  *dnsmessage.Msg
	CacheKey  string
	FromCache bool
	Rejected  bool

	packedResponse []byte
}

func (result *DnsResult) copyForRequest(id uint16) *DnsResult {
	if result == nil {
		return nil
	}
	copy := &DnsResult{
		CacheKey:  result.CacheKey,
		FromCache: result.FromCache,
		Rejected:  result.Rejected,
	}
	if result.Response != nil {
		copy.Response = result.Response.Copy()
		copy.Response.Id = id
	}
	if result.packedResponse != nil {
		// Cached wire responses are immutable COW snapshots. Delivery copies
		// before patching the request ID, so results can share this payload.
		copy.packedResponse = result.packedResponse
	}
	return copy
}

func dnsErrorResult(query *dnsmessage.Msg, rcode int) *DnsResult {
	if query == nil {
		return nil
	}
	response := query.Copy()
	response.Answer = nil
	response.Ns = nil
	response.Extra = nil
	response.Rcode = rcode
	response.Response = true
	response.RecursionAvailable = true
	response.Truncated = false
	response.Compress = true
	return &DnsResult{Response: response, Rejected: rcode == dnsmessage.RcodeSuccess}
}

func dnsResultFromCachedResponse(resp []byte, id uint16, cacheKey string) (*DnsResult, error) {
	var response dnsmessage.Msg
	if err := response.Unpack(resp); err != nil {
		return nil, fmt.Errorf("unpack cached DNS response: %w", err)
	}
	response.Id = id
	return &DnsResult{
		Response:  &response,
		CacheKey:  cacheKey,
		FromCache: true,
		// The cache publishes wire responses through an immutable COW snapshot.
		// Keep the shared bytes; UDP delivery copies before changing the ID.
		packedResponse: resp,
	}, nil
}

func (c *DnsController) responseCacheScopeForSnapshot(snapshot DnsRequestSnapshot, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream) string {
	switch upstreamIndex {
	case consts.DnsRequestOutboundIndex_AsIs:
		if snapshot.RealDst.IsValid() {
			return "asis@" + snapshot.RealDst.String()
		}
		return "asis"
	case consts.DnsRequestOutboundIndex_Reject:
		return "reject"
	default:
		if upstream != nil {
			return "upstream@" + upstream.String()
		}
		if upstreamIndex != 0 {
			return "upstream-index@" + strconv.Itoa(int(upstreamIndex))
		}
		return ""
	}
}

func (c *DnsController) responseCacheKeyForSnapshot(baseKey string, snapshot DnsRequestSnapshot, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream) string {
	scope := c.responseCacheScopeForSnapshot(snapshot, upstreamIndex, upstream)
	if scope == "" {
		return baseKey
	}
	return baseKey + "|" + scope
}

// Resolve resolves query against the current DNS runtime without reading or
// writing a listener socket. The query is copied before any cache or upstream
// operation so caller-owned DNS messages remain unchanged.
func (c *DnsController) Resolve(ctx context.Context, query *dnsmessage.Msg, snapshot DnsRequestSnapshot) (*DnsResult, error) {
	c.requireStore()
	if query == nil {
		return nil, fmt.Errorf("nil DNS query")
	}
	request := query.Copy()
	if request == nil {
		return nil, fmt.Errorf("copy DNS query")
	}
	if request.Response {
		return nil, fmt.Errorf("DNS request expected but DNS response received")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if cap(c.concurrencyLimiter) > 0 {
		select {
		case c.concurrencyLimiter <- struct{}{}:
			defer func() { <-c.concurrencyLimiter }()
		default:
			return dnsErrorResult(request, dnsmessage.RcodeRefused), ErrDNSQueryConcurrencyLimitExceeded
		}
	}

	return c.resolveDNSRequest(ctx, request, snapshot)
}

func (c *DnsController) resolveDNSRequest(ctx context.Context, request *dnsmessage.Msg, snapshot DnsRequestSnapshot) (*DnsResult, error) {
	var (
		qname        string
		qtype        uint16
		baseCacheKey string
	)
	if len(request.Question) > 0 {
		question := request.Question[0]
		qname = question.Name
		qtype = question.Qtype
		baseCacheKey = c.cacheKey(qname, qtype)
	}

	runtime := c.runtime()
	if runtime == nil || runtime.routing == nil {
		return nil, fmt.Errorf("dns routing is not configured")
	}
	upstreamIndex, upstream, err := runtime.routing.RequestSelect(ctx, qname, qtype)
	if err != nil {
		return nil, err
	}
	responseCacheKey := c.responseCacheKeyForSnapshot(baseCacheKey, snapshot, upstreamIndex, upstream)
	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		if baseCacheKey != "" {
			c.RemoveDnsRespCacheFamily(baseCacheKey)
		}
		return dnsErrorResult(request, dnsmessage.RcodeSuccess), nil
	}

	if baseCacheKey == "" {
		return c.resolveDNSUncached(ctx, request, snapshot, upstream, responseCacheKey)
	}

	if resp, needRefresh := c.LookupDnsRespCache_(request, responseCacheKey, false); resp != nil {
		if needRefresh {
			go c.backgroundRefreshSnapshot(responseCacheKey, request, snapshot, upstreamIndex, upstream)
		}
		return dnsResultFromCachedResponse(resp, request.Id, responseCacheKey)
	}

	shared, err, _ := c.sf.Do(responseCacheKey, func() (any, error) {
		resolutionCtx, cancel := c.newWorkContext(5 * time.Second)
		defer cancel()
		return c.resolveForSingleflightSnapshot(resolutionCtx, request, snapshot, upstreamIndex, upstream, responseCacheKey)
	})
	if err != nil {
		return nil, err
	}
	result, ok := shared.(*DnsResult)
	if !ok || result == nil {
		return nil, fmt.Errorf("unexpected DNS singleflight result: %T", shared)
	}

	if resp, _ := c.LookupDnsRespCache_(request, responseCacheKey, false); resp != nil {
		return dnsResultFromCachedResponse(resp, request.Id, responseCacheKey)
	}
	return result.copyForRequest(request.Id), nil
}

func (c *DnsController) resolveForSingleflightSnapshot(
	ctx context.Context,
	request *dnsmessage.Msg,
	snapshot DnsRequestSnapshot,
	upstreamIndex consts.DnsRequestOutboundIndex,
	upstream *dns.Upstream,
	responseCacheKey string,
) (*DnsResult, error) {
	if resp, needRefresh := c.LookupDnsRespCache_(request, responseCacheKey, false); resp != nil {
		if needRefresh {
			go c.backgroundRefreshSnapshot(responseCacheKey, request, snapshot, upstreamIndex, upstream)
		}
		return dnsResultFromCachedResponse(resp, request.Id, responseCacheKey)
	}
	return c.resolveDNSUncached(ctx, request, snapshot, upstream, responseCacheKey)
}

func (c *DnsController) resolveDNSUncached(ctx context.Context, request *dnsmessage.Msg, snapshot DnsRequestSnapshot, upstream *dns.Upstream, responseCacheKey string) (*DnsResult, error) {
	data, err := request.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS packet: %w", err)
	}
	resolution, err := c.resolveDNSUpstreamSnapshot(ctx, 0, snapshot, data, upstream)
	if err != nil {
		return nil, err
	}
	c.logDNSResolution(snapshot, resolution)

	response := resolution.response.Copy()
	response.Id = request.Id
	response.Compress = true
	if responseCacheKey != "" {
		if err := c.NormalizeAndCacheDnsResp_(response, responseCacheKey); err != nil && c.log != nil {
			c.log.Warnf("failed to cache DNS response: %v", err)
		}
	}
	return &DnsResult{Response: response, CacheKey: responseCacheKey}, nil
}

func (c *DnsController) resolveDNSUpstreamSnapshot(
	ctx context.Context,
	invokingDepth int,
	snapshot DnsRequestSnapshot,
	data []byte,
	upstream *dns.Upstream,
) (*dnsUpstreamResolution, error) {
	data = append([]byte(nil), data...)
	if invokingDepth >= MaxDnsLookupDepth {
		return nil, fmt.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
	}

	upstreamName := "asis"
	if upstream == nil {
		if !snapshot.RealDst.IsValid() {
			return nil, fmt.Errorf("DNS request destination is invalid for as-is upstream")
		}
		var ip46 netutils.Ip46
		if snapshot.RealDst.Addr().Is4() {
			ip46.Ip4 = snapshot.RealDst.Addr()
		} else {
			ip46.Ip6 = snapshot.RealDst.Addr()
		}
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: snapshot.RealDst.Addr().String(),
			Port:     snapshot.RealDst.Port(),
			Ip46:     &ip46,
		}
	} else {
		upstreamName = upstream.String()
	}

	runtime := c.runtime()
	dialArg, err := runtime.chooseBestDnsDialer(ctx, snapshot, upstream)
	if err != nil {
		return nil, err
	}
	response, usedDialArg, err := c.forwardWithFallbackSnapshot(ctx, snapshot, upstream, dialArg, data)
	if err != nil {
		return nil, err
	}

	networkType := &dialer.NetworkType{
		L4Proto:         usedDialArg.l4proto,
		IpVersion:       usedDialArg.ipversion,
		IsDns:           true,
		UdpHealthDomain: dialer.UdpHealthDomainDns,
	}
	if runtime.routing == nil {
		return nil, fmt.Errorf("dns routing is not configured")
	}
	upstreamIndex, nextUpstream, err := runtime.routing.ResponseSelect(ctx, response, upstream)
	if err != nil {
		return nil, err
	}
	switch upstreamIndex {
	case consts.DnsResponseOutboundIndex_Accept:
		if c.log != nil && c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": response.Question,
				"upstream": upstreamName,
			}).Traceln("Accept")
		}
	case consts.DnsResponseOutboundIndex_Reject:
		response.Answer = nil
		if c.log != nil && c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": response.Question,
				"upstream": upstreamName,
			}).Traceln("Reject with empty answer")
		}
	default:
		if c.log != nil && c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      response.Question,
				"last_upstream": upstreamName,
				"next_upstream": nextUpstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		return c.resolveDNSUpstreamSnapshot(ctx, invokingDepth+1, snapshot, data, nextUpstream)
	}

	return &dnsUpstreamResolution{
		response:      c.applyPreferenceWait(response),
		networkType:   networkType,
		upstreamIndex: upstreamIndex,
		dialArgument:  usedDialArg,
	}, nil
}

func (c *DnsController) forwardWithFallbackSnapshot(
	ctx context.Context,
	snapshot DnsRequestSnapshot,
	upstream *dns.Upstream,
	primaryDialArg *dialArgument,
	data []byte,
) (respMsg *dnsmessage.Msg, usedDialArg *dialArgument, err error) {
	primaryCtx, primaryCancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer primaryCancel()
	respMsg, err = c.forwardWithDialArg(primaryCtx, upstream, primaryDialArg, data)
	if err == nil {
		return respMsg, primaryDialArg, nil
	}
	primaryErr := err
	if upstream == nil || upstream.Scheme != dns.UpstreamScheme_TCP_UDP || primaryDialArg.l4proto != consts.L4ProtoStr_UDP {
		return nil, primaryDialArg, primaryErr
	}

	fallbackUpstream := *upstream
	fallbackUpstream.Scheme = dns.UpstreamScheme_TCP
	runtime := c.runtime()
	fallbackDialArg, chooseErr := runtime.chooseBestDnsDialer(ctx, snapshot, &fallbackUpstream)
	if chooseErr != nil {
		return nil, primaryDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback select failed: %v", primaryErr, chooseErr)
	}
	if fallbackDialArg == nil || fallbackDialArg.l4proto != consts.L4ProtoStr_TCP {
		return nil, primaryDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback select returned invalid network", primaryErr)
	}
	if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"upstream": upstream.String(),
			"from":     primaryDialArg.l4proto,
			"to":       fallbackDialArg.l4proto,
		}).Debugln("DNS fallback to TCP after UDP failure")
	}

	fallbackCtx, fallbackCancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer fallbackCancel()
	respMsg, err = c.forwardWithDialArg(fallbackCtx, upstream, fallbackDialArg, data)
	if err != nil {
		return nil, fallbackDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback failed: %v", primaryErr, err)
	}
	return respMsg, fallbackDialArg, nil
}

func (c *DnsController) backgroundRefreshSnapshot(cacheKey string, request *dnsmessage.Msg, snapshot DnsRequestSnapshot, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream) {
	defer func() {
		if recovered := recover(); recovered != nil && c.log != nil {
			c.log.Errorf("panic in background DNS refresh: %v", recovered)
		}
	}()
	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject || request == nil {
		return
	}
	ctx, cancel := c.newWorkContext(5 * time.Second)
	defer cancel()
	defer func() {
		if cache := c.LookupDnsRespCache(cacheKey, false); cache != nil && cache.IsRefreshing() {
			cache.MarkRefreshed()
		}
	}()

	refresh := request.Copy()
	if refresh == nil || len(refresh.Question) == 0 {
		return
	}
	refresh.Response = false
	refresh.Answer = nil
	refresh.Ns = nil
	refresh.Extra = nil
	if _, err := c.resolveDNSUncached(ctx, refresh, snapshot, upstream, cacheKey); err != nil && c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"cacheKey": cacheKey,
			"error":    err,
		}).Debugf("background refresh failed")
	}
}

func (c *DnsController) logDNSResolution(snapshot DnsRequestSnapshot, resolution *dnsUpstreamResolution) {
	if c.log == nil || resolution == nil || resolution.dialArgument == nil || !resolution.upstreamIndex.IsReserved() || !c.log.IsLevelEnabled(logrus.DebugLevel) {
		return
	}
	var qname, qtype string
	if response := resolution.response; response != nil && len(response.Question) > 0 {
		question := response.Question[0]
		qname = strings.ToLower(question.Name)
		qtype = QtypeToString(question.Qtype)
	}
	fields := logrus.Fields{
		"network": resolution.networkType.String(),
		"_qname":  qname,
		"qtype":   qtype,
	}
	if outbound := resolution.dialArgument.bestOutbound; outbound != nil {
		fields["outbound"] = outbound.Name
		fields["policy"] = outbound.GetSelectionPolicy()
	}
	if selectedDialer := resolution.dialArgument.bestDialer; selectedDialer != nil {
		fields["dialer"] = selectedDialer.Property().Name
	}
	if routingResult := snapshot.routingResultForRoute(); routingResult != nil {
		fields["pid"] = routingResult.Pid
		fields["dscp"] = routingResult.Dscp
		fields["pname"] = ProcessName2String(routingResult.Pname[:])
		fields["mac"] = Mac2String(routingResult.Mac[:])
	}
	switch resolution.upstreamIndex {
	case consts.DnsResponseOutboundIndex_Accept:
		c.log.WithFields(fields).Debugf("%v <-> %v", RefineSourceToShow(snapshot.RealSrc, snapshot.RealDst.Addr()), RefineAddrPortToShow(resolution.dialArgument.bestTarget))
	case consts.DnsResponseOutboundIndex_Reject:
		c.log.WithFields(fields).Debugf("%v -> reject", RefineSourceToShow(snapshot.RealSrc, snapshot.RealDst.Addr()))
	}
}

func (c *DnsController) deliverDNSResult(result *DnsResult, requestID uint16, req *udpRequest, responseWriter dnsmessage.ResponseWriter) error {
	if result == nil || result.Response == nil {
		return nil
	}
	if responseWriter == nil && (req == nil || req.lConn == nil) {
		return nil
	}
	if result.packedResponse != nil {
		// Resolve already unpacked cached responses so the result carries an
		// owned message for writer-based transports. Reusing it avoids a second
		// unpack while preserving the packed fast path for transparent UDP.
		if responseWriter != nil {
			result.Response.Id = requestID
			return responseWriter.WriteMsg(result.Response)
		}
		return c.writeCachedResponse(result.packedResponse, requestID, req, responseWriter)
	}
	response := result.Response.Copy()
	response.Id = requestID
	if responseWriter != nil {
		return responseWriter.WriteMsg(response)
	}
	data, err := response.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS response: %w", err)
	}
	if err := sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.downloadRecorder()); err != nil {
		return err
	}
	return nil
}

func (c *DnsController) handleResolvedDNS(ctx context.Context, query *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) error {
	result, resolutionErr := c.Resolve(ctx, query, dnsRequestSnapshotFromUDPRequest(req))
	var requestID uint16
	if query != nil {
		requestID = query.Id
	}
	deliveryErr := c.deliverDNSResult(result, requestID, req, responseWriter)
	return joinDNSResolutionAndDeliveryErrors(resolutionErr, deliveryErr)
}

func joinDNSResolutionAndDeliveryErrors(resolutionErr, deliveryErr error) error {
	if resolutionErr == nil {
		return deliveryErr
	}
	if deliveryErr == nil {
		return resolutionErr
	}
	return errors.Join(resolutionErr, deliveryErr)
}
