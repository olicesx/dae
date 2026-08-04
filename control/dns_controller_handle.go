/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type udpRequest struct {
	realSrc        netip.AddrPort
	realDst        netip.AddrPort
	src            netip.AddrPort
	lConn          *net.UDPConn
	routingResult  *bpfRoutingResult
	uploadRecord   func(int64)
	downloadRecord func(int64)
}

func (r *udpRequest) downloadRecorder() func(int64) {
	if r == nil {
		return RecordDownloadTraffic
	}
	return normalizeTrafficRecord(r.downloadRecord)
}

func (c *DnsController) baseContext() context.Context {
	if rt := c.runtime(); rt != nil && rt.lifecycleCtx != nil {
		return rt.lifecycleCtx
	}
	return context.Background()
}

func (c *DnsController) newWorkContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.baseContext(), timeout)
}

func (c *DnsController) forwardWithFallback(
	ctx context.Context, // Request-scoped context from dialSend/handler
	req *udpRequest,
	upstream *dns.Upstream,
	primaryDialArg *dialArgument,
	data []byte,
) (respMsg *dnsmessage.Msg, usedDialArg *dialArgument, err error) {
	// Per-attempt timeout: each attempt gets the full DefaultDialTimeout budget.
	// WithoutCancel strips the parent (singleflight work context) deadline, which
	// is shorter than DefaultDialTimeout; otherwise a UDP black-hole timeout would
	// exhaust the parent context and the TCP fallback would start already expired.
	attemptCtx := context.WithoutCancel(ctx)
	primaryCtx, primaryCancel := context.WithTimeout(attemptCtx, consts.DefaultDialTimeout)
	defer primaryCancel()

	respMsg, err = c.forwardWithDialArg(primaryCtx, upstream, primaryDialArg, data)
	if err == nil {
		return respMsg, primaryDialArg, nil
	}

	primaryErr := err

	// For tcp+udp upstream, perform immediate same-request fallback:
	// prefer UDP, fallback to TCP on failure.
	if upstream == nil || upstream.Scheme != dns.UpstreamScheme_TCP_UDP || primaryDialArg.l4proto != consts.L4ProtoStr_UDP {
		return nil, primaryDialArg, primaryErr
	}

	fallbackUpstream := *upstream
	fallbackUpstream.Scheme = dns.UpstreamScheme_TCP

	fallbackDialArg, chooseErr := c.runtime().chooseBestDnsDialer(ctx, dnsRequestSnapshotFromUDPRequest(req), &fallbackUpstream)
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

	fallbackCtx, fallbackCancel := context.WithTimeout(attemptCtx, consts.DefaultDialTimeout)
	defer fallbackCancel()

	respMsg, err = c.forwardWithDialArg(fallbackCtx, upstream, fallbackDialArg, data)
	if err != nil {
		return nil, fallbackDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback failed: %v", primaryErr, err)
	}

	return respMsg, fallbackDialArg, nil
}

func (c *DnsController) Handle_(ctx context.Context, dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	return c.HandleWithResponseWriter_(ctx, dnsMessage, req, nil)
}

func (c *DnsController) HandleWithResponseWriter_(ctx context.Context, dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	c.requireStore()
	var upstreamIndex consts.DnsRequestOutboundIndex
	var upstream *dns.Upstream

	if cap(c.concurrencyLimiter) > 0 {
		select {
		case c.concurrencyLimiter <- struct{}{}:
			defer func() { <-c.concurrencyLimiter }()
		default:
			if responseWriter != nil || (req != nil && req.lConn != nil) {
				if sendErr := c.sendRefusedWithResponseWriter_(dnsMessage, req, responseWriter); sendErr != nil {
					return errors.Join(ErrDNSQueryConcurrencyLimitExceeded, sendErr)
				}
			}
			return ErrDNSQueryConcurrencyLimitExceeded
		}
	}

	// Prepare qname, qtype for cache lookup
	var qname string
	var qtype uint16
	var baseCacheKey string
	var responseCacheKey string
	if len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
		baseCacheKey = c.cacheKey(qname, qtype)
	}

	// Route request first, then check cache.
	// This ensures Reject rules are always applied, even if cache exists.
	// Cache lookup overhead (~1µs) is negligible compared to network latency (~ms).
	if baseCacheKey != "" && !dnsMessage.Response {
		// Route request to get upstream
		rt := c.runtime()
		if rt == nil || rt.routing == nil {
			return fmt.Errorf("dns routing is not configured")
		}
		var err error
		upstreamIndex, upstream, err = rt.routing.RequestSelect(ctx, qname, qtype)
		if err != nil {
			return err
		}
		responseCacheKey = c.responseCacheKey(baseCacheKey, req, upstreamIndex, upstream)

		if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
			c.RemoveDnsRespCacheFamily(baseCacheKey)
			return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
		}

		// Check cache after routing (non-reject case)
		if resp, needRefresh := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
			// Cache hit - return immediately without singleflight
			// OPTIMISTIC CACHE: resp may be stale, trigger background refresh if needed
			if needRefresh {
				// Background refresh - don't block the current request
				go c.backgroundRefresh(responseCacheKey, dnsMessage, req, upstreamIndex, upstream)
			}

			if err = c.writeCachedResponse(resp, dnsMessage.Id, req, responseWriter, dnsMessage); err != nil {
				return err
			}
			// Log cache hit with dest addr for CI compatibility.
			// Format includes "-> dest:port" so CI grep can verify routing.
			if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Question) > 0 && req != nil {
				q := dnsMessage.Question[0]
				c.log.WithFields(logrus.Fields{
					"network": "udp(dns)",
					"_qname":  strings.ToLower(q.Name),
					"qtype":   QtypeToString(q.Qtype),
				}).Debugf("%v <-> %v (cache)",
					RefineSourceToShow(req.realSrc, req.realDst.Addr()),
					RefineAddrPortToShow(req.realDst),
				)
			}
			return nil
		}

		// Cache miss - use singleflight to coalesce concurrent requests
		// This prevents thundering herd on upstream DNS servers
		res, err, _ := c.sf.Do(responseCacheKey, func() (any, error) {
			// Shared singleflight resolution should ignore individual client
			// cancellation, but it must still stop promptly when the DNS
			// controller is closing during reload/shutdown.
			resCtx, resCancel := c.newWorkContext(5 * time.Second)
			defer resCancel()

			// This goroutine performs the actual resolution.
			// It returns the DNS response message, or an error.
			return c.resolveForSingleflight(resCtx, dnsMessage, req, upstreamIndex, upstream, responseCacheKey)
		})

		if err != nil {
			return err
		}

		// res is the *dnsmessage.Msg
		respMsg := res.(*dnsmessage.Msg)

		// Optimization: Try to get pre-packed response from cache after singleflight.
		// This avoids another Pack() call which is common in high-concurrency scenarios.
		if responseCacheKey != "" {
			if resp, _ := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
				if err = c.writeCachedResponse(resp, dnsMessage.Id, req, responseWriter, dnsMessage); err != nil {
					return err
				}
				return nil
			}
		}

		// Write response.
		// For packet-send path, avoid deep-copying DNS message and just patch ID in packed bytes.
		if responseWriter != nil {
			respMsgUnique := respMsg.Copy()
			respMsgUnique.Id = dnsMessage.Id
			return responseWriter.WriteMsg(respMsgUnique)
		}

		// If no responseWriter (internal UDP path), pack and send directly.
		// Reuse the DNS response buffer pool; data is consumed synchronously by the send.
		bufPtr := dnsResponseBufPool.Get().(*[]byte)
		defer dnsResponseBufPool.Put(bufPtr)
		data, err := respMsg.PackBuffer((*bufPtr)[:cap(*bufPtr)])
		if err != nil {
			return fmt.Errorf("pack DNS packet: %w", err)
		}
		if len(data) >= 2 {
			binary.BigEndian.PutUint16(data[:2], dnsMessage.Id)
		}
		if req == nil || req.lConn == nil {
			return fmt.Errorf("dns request connection is nil for singleflight response")
		}
		if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
			return err
		}
		return nil
	}

	return c.handleWithResponseWriterInternal(ctx, dnsMessage, req, responseWriter, upstreamIndex, upstream, responseCacheKey, baseCacheKey)
}

func (c *DnsController) resolveForSingleflight(
	ctx context.Context,
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	upstreamIndex consts.DnsRequestOutboundIndex,
	upstream *dns.Upstream,
	responseCacheKey string,
) (*dnsmessage.Msg, error) {
	// Preserve the second cache lookup from the former response-writer path.
	// Another request may have populated the entry after the outer cache miss
	// and before this singleflight leader starts upstream resolution.
	if resp, needRefresh := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
		if needRefresh {
			go c.backgroundRefresh(responseCacheKey, dnsMessage, req, upstreamIndex, upstream)
		}
		respMsg := new(dnsmessage.Msg)
		if err := respMsg.Unpack(resp); err != nil {
			return nil, fmt.Errorf("unpack cached DNS response: %w", err)
		}
		respMsg.Id = dnsMessage.Id
		return respMsg, nil
	}

	data, err := dnsMessage.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS packet: %w", err)
	}
	resolution, err := c.resolveDNSUpstream(ctx, 0, req, data, upstream)
	if err != nil {
		return nil, err
	}

	respMsg := resolution.response
	respMsg.Id = dnsMessage.Id
	respMsg.Compress = true
	if err := c.NormalizeAndCacheDnsResp_(respMsg, responseCacheKey); err != nil {
		if c.log != nil {
			c.log.Warnf("failed to cache DNS response: %v", err)
		}
	}
	return respMsg, nil
}

// handleWithResponseWriterInternal handles DNS requests with response writer.
// When ip_version_prefer is set, it implements RFC 8305 Happy Eyeballs
// Resolution Delay: wait briefly for preferred response type before responding.
//
// Renamed from HandleWithResponseWriter_ to internal to avoid recursion loop with SF.
func (c *DnsController) handleWithResponseWriterInternal(ctx context.Context, dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream, responseCacheKey string, baseCacheKey string) (err error) {
	if c.log.IsLevelEnabled(logrus.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		c.log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.realSrc, req.realDst.Addr()), req.realDst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		return fmt.Errorf("DNS request expected but DNS response received")
	}

	// Get qtype for preference handling (RFC 8305 Happy Eyeballs).
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		qtype = dnsMessage.Question[0].Qtype
	}

	// Fast path: no ip_version_prefer set, bypass all preference logic
	if c.currentQtypePrefer() == 0 {
		return c.handleWithResponseWriter_(ctx, dnsMessage, req, true, responseWriter, upstreamIndex, upstream, responseCacheKey, baseCacheKey)
	}

	// Only A and AAAA responses participate in preference waiting. The wait is
	// applied after upstream resolution so cached/direct non-address responses
	// keep the fast path.
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return c.handleWithResponseWriter_(ctx, dnsMessage, req, true, responseWriter, upstreamIndex, upstream, responseCacheKey, baseCacheKey)
	}

	return c.handleWithResponseWriter_(ctx, dnsMessage, req, true, responseWriter, upstreamIndex, upstream, responseCacheKey, baseCacheKey)
}

func (c *DnsController) handleWithResponseWriter_(
	ctx context.Context,
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
	responseWriter dnsmessage.ResponseWriter,
	upstreamIndex consts.DnsRequestOutboundIndex,
	upstream *dns.Upstream,
	responseCacheKey string,
	baseCacheKey string,
) (err error) {
	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
	}

	// Route request if not already routed.
	if upstream == nil && upstreamIndex == 0 {
		rt := c.runtime()
		if rt == nil || rt.routing == nil {
			return fmt.Errorf("dns routing is not configured")
		}
		upstreamIndex, upstream, err = rt.routing.RequestSelect(ctx, qname, qtype)
		if err != nil {
			return err
		}
	}

	if baseCacheKey == "" {
		baseCacheKey = c.cacheKey(qname, qtype)
	}
	if responseCacheKey == "" {
		responseCacheKey = c.responseCacheKey(baseCacheKey, req, upstreamIndex, upstream)
	}

	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		// Reject with empty answer.
		c.RemoveDnsRespCacheFamily(baseCacheKey)
		if !needResp {
			return nil
		}
		return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
	}

	if resp, needRefresh := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
		// Send cache to client directly.
		// OPTIMISTIC CACHE: Trigger background refresh if stale
		if needRefresh {
			go c.backgroundRefresh(responseCacheKey, dnsMessage, req, upstreamIndex, upstream)
		}

		if needResp {
			if err = c.writeCachedResponse(resp, dnsMessage.Id, req, responseWriter, dnsMessage); err != nil {
				return err
			}
		}
		if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Question) > 0 {
			q := dnsMessage.Question[0]
			if req != nil {
				c.log.Debugf("UDP(DNS) %v <-> Cache: %v %v",
					RefineSourceToShow(req.realSrc, req.realDst.Addr()), strings.ToLower(q.Name), QtypeToString(q.Qtype),
				)
			} else {
				c.log.Debugf("UDP(DNS) Cache: %v %v", strings.ToLower(q.Name), QtypeToString(q.Qtype))
			}
		}
		return nil
	}

	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		upstreamName := upstreamIndex.String()
		if upstream != nil {
			upstreamName = upstream.String()
		}
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
			"upstream": upstreamName,
		}).Traceln("Request to DNS upstream")
	}

	// Re-pack DNS packet.
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	return c.dialSend(ctx, req, data, dnsMessage.Id, upstream, needResp, responseWriter, responseCacheKey)
}

type dnsUpstreamResolution struct {
	response      *dnsmessage.Msg
	networkType   *dialer.NetworkType
	upstreamIndex consts.DnsResponseOutboundIndex
	dialArgument  *dialArgument
}

// resolveDNSUpstream obtains a DNS response without writing it to the client
// or mutating the response cache. It owns response routing and recursive
// upstream fallback so delivery can be shared by UDP, TCP, and singleflight.
func (c *DnsController) resolveDNSUpstream(
	ctx context.Context,
	invokingDepth int,
	req *udpRequest,
	data []byte,
	upstream *dns.Upstream,
) (*dnsUpstreamResolution, error) {
	data = append([]byte(nil), data...) // defensive copy: callers may reuse the slice across recursive retries
	if invokingDepth >= MaxDnsLookupDepth {
		return nil, fmt.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
	}

	upstreamName := "asis"
	if upstream == nil {
		// As-is.

		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		var ip46 netutils.Ip46
		if req.realDst.Addr().Is4() {
			ip46.Ip4 = req.realDst.Addr()
		} else {
			ip46.Ip6 = req.realDst.Addr()
		}
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.realDst.Addr().String(),
			Port:     req.realDst.Port(),
			Ip46:     &ip46,
		}
	} else {
		upstreamName = upstream.String()
	}

	// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
	dialArg, err := c.runtime().chooseBestDnsDialer(ctx, dnsRequestSnapshotFromUDPRequest(req), upstream)
	if err != nil {
		return nil, err
	}

	// Dial and send.
	var respMsg *dnsmessage.Msg
	var usedDialArg *dialArgument
	respMsg, usedDialArg, err = c.forwardWithFallback(ctx, req, upstream, dialArg, data)
	if err != nil {
		return nil, err
	}

	networkType := &dialer.NetworkType{
		L4Proto:         usedDialArg.l4proto,
		IpVersion:       usedDialArg.ipversion,
		IsDns:           true,
		UdpHealthDomain: dialer.UdpHealthDomainDns,
	}

	// Route response.
	rt := c.runtime()
	if rt == nil || rt.routing == nil {
		return nil, fmt.Errorf("dns routing is not configured")
	}
	upstreamIndex, nextUpstream, err := rt.routing.ResponseSelect(ctx, respMsg, upstream)
	if err != nil {
		return nil, err
	}
	switch upstreamIndex {
	case consts.DnsResponseOutboundIndex_Accept:
		// Accept.
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Accept")
		}
	case consts.DnsResponseOutboundIndex_Reject:
		// Reject the request with empty answer.
		respMsg.Answer = nil
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Reject with empty answer")
		}
		// We also cache response reject.
	default:
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      respMsg.Question,
				"last_upstream": upstreamName,
				"next_upstream": nextUpstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		return c.resolveDNSUpstream(ctx, invokingDepth+1, req, data, nextUpstream)
	}

	// Apply preference wait logic for A/AAAA responses.
	// This must happen before logging and sending the response.
	respMsg = c.applyPreferenceWait(respMsg)

	return &dnsUpstreamResolution{
		response:      respMsg,
		networkType:   networkType,
		upstreamIndex: upstreamIndex,
		dialArgument:  usedDialArg,
	}, nil
}
