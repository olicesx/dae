/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

// TODO: Lookup Cache 的 GC
// TODO: reload时保留lookup cache

const (
	MaxDnsLookupDepth = 3
)

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

var (
	UnspecifiedAddressA        = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA     = netip.MustParseAddr("::")
	ErrUnsupportedQuestionType = fmt.Errorf("unsupported question type")
)

type DnsControllerOption struct {
	MatchBitmap        func(fqdn string) []uint32
	NewLookupCache     func(ip netip.Addr, domainBitmap [32]uint32) error
	LookupCacheTimeout func(ip netip.Addr, domainBitmap [32]uint32) error
	BestDialerChooser  func(req *dnsRequest, upstream *dns.Upstream) (*dialArgument, error)
	IpVersionPrefer    int
	FixedDomainTtl     map[string]int
	MinSniffingTtl     time.Duration
	EnableCache        bool
	SniffVerifyMode    consts.SniffVerifyMode
}

type DnsController struct {
	routing     *dns.Dns
	qtypePrefer uint16

	matchBitmap        func(fqdn string) []uint32
	newLookupCache     func(ip netip.Addr, domainBitmap [32]uint32) error
	lookupCacheTimeout func(ip netip.Addr, domainBitmap [32]uint32) error
	bestDialerChooser  func(req *dnsRequest, upstream *dns.Upstream) (*dialArgument, error)

	fixedDomainTtl    map[string]int
	minSniffingTtl    time.Duration
	enableCache       bool
	dnsCache          *commonDnsCache[dnsCacheKey]
	dnsKeyLocker      common.KeyLocker[dnsCacheKey]
	dnsForwarderCache sync.Map // map[dnsForwarderKey]DnsForwarder
	// mu protects deadlineTimers
	mu              sync.Mutex
	deadlineTimers  map[string]map[netip.Addr]*time.Timer
	sniffVerifyMode consts.SniffVerifyMode
	// sfGroup deduplicates concurrent DNS queries for the same domain
	sfGroup singleflight.Group
	// workerPool processes DNS requests using fixed worker pool
	workerPool *DnsWorkerPool
	// responseWg tracks response goroutines for graceful shutdown
	responseWg sync.WaitGroup
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	// Parse ip version preference.
	prefer, err := parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return nil, err
	}

	// Normalize fixedDomainTtl keys to lowercase for consistent matching
	normalizedFixedDomainTtl := make(map[string]int, len(option.FixedDomainTtl))
	for domain, ttl := range option.FixedDomainTtl {
		normalizedFixedDomainTtl[dnsmessage.CanonicalName(domain)] = ttl
	}

	return &DnsController{
		routing:     routing,
		qtypePrefer: prefer,

		matchBitmap:        option.MatchBitmap,
		newLookupCache:     option.NewLookupCache,
		lookupCacheTimeout: option.LookupCacheTimeout,
		bestDialerChooser:  option.BestDialerChooser,

		fixedDomainTtl:    normalizedFixedDomainTtl,
		minSniffingTtl:    option.MinSniffingTtl,
		enableCache:       option.EnableCache,
		sniffVerifyMode:   option.SniffVerifyMode,
		dnsForwarderCache: sync.Map{},
		dnsCache:          newCommonDnsCache[dnsCacheKey](),
		deadlineTimers:    make(map[string]map[netip.Addr]*time.Timer),
		workerPool:        NewDnsWorkerPool(8, 1000), // 8 workers, 1000 queue size
	}, nil
}

func (c *DnsController) UpdateDnsCacheTtl(cacheKey dnsCacheKey, fqdn string, answers []dnsmessage.RR) {
	ttl := 0
	for _, ans := range answers {
		if ttl == 0 {
			ttl = int(ans.Header().Ttl)
			break
		}
	}
	if fixedTtl, ok := c.fixedDomainTtl[fqdn]; ok {
		ttl = fixedTtl
	}
	for _, answer := range answers {
		c.dnsCache.UpdateTtl(cacheKey, answer, ttl)
	}
}

type dnsRequest struct {
	src           netip.AddrPort
	dst           netip.AddrPort
	routingResult *bpfRoutingResult
	isTcp         bool
	controller    *DnsController // Reference to controller for worker pool
}

type dialArgument struct {
	networkType common.NetworkType
	Dialer      *dialer.Dialer
	Outbound    *outbound.DialerGroup
	Target      netip.AddrPort
	// mark        uint32
}

type dnsForwarderKey struct {
	upstream     string
	dialArgument dialArgument
}

type queryInfo struct {
	qname string
	qtype uint16
}

type dnsCacheKey struct {
	queryInfo
	outbound *outbound.DialerGroup
	//target   netip.AddrPort
}

func (c *DnsController) prepareQueryInfo(dnsMessage *dnsmessage.Msg) (queryInfo queryInfo) {
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		queryInfo.qname = dnsmessage.CanonicalName(q.Name)
		queryInfo.qtype = q.Qtype
	}
	return
}

func (c *DnsController) Handle(dnsMessage *dnsmessage.Msg, req *dnsRequest) {
	if log.IsLevelEnabled(log.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.src, req.dst.Addr()), req.dst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		log.Errorln("DNS request expected but DNS response received")
	}

	queryInfo := c.prepareQueryInfo(dnsMessage)
	id := dnsMessage.Id
	// Avoids duplicated id from clients, so make the id unique.
	dnsMessage.Id = uint16(fastrand.Intn(math.MaxUint16))

	// Set controller reference in request for worker pool
	req.controller = c

	// Fast path: Check cache before submitting to worker pool
	// This avoids worker queue latency for cache hits (90%+ of traffic)
	if c.enableCache {
		// Perform routing selection to determine outbound
		requestIndex, err := c.routing.RequestSelect(queryInfo.qname, queryInfo.qtype)
		if err == nil && requestIndex != consts.DnsRequestOutboundIndex_Reject {
			// Get outbound for cache key
			var outbound *outbound.DialerGroup
			if requestIndex == consts.DnsRequestOutboundIndex_AsIs {
				// AsIs mode - use nil as outbound (cache key won't include outbound)
				outbound = nil
			} else {
				var upstream *dns.Upstream
				upstream, err = c.routing.GetUpstream(requestIndex)
				if err == nil {
					// Create a temporary dialArgument to get outbound
					// This is a bit inefficient but necessary for correct cache key
					dialArg, err := c.bestDialerChooser(req, upstream)
					if err == nil {
						outbound = dialArg.Outbound
					}
				}
			}

			// Try to get cached response
			cacheKey := &dnsCacheKey{queryInfo: queryInfo, outbound: outbound}
			if cache := c.dnsCache.Get(*cacheKey); cache != nil && !AllTimeout(cache) {
				// Cache hit - process synchronously for minimal latency
				FillInto(dnsMessage, cache)

				if log.IsLevelEnabled(log.DebugLevel) && len(dnsMessage.Question) > 0 {
					log.WithFields(log.Fields{
						"answer": dnsMessage.Answer,
					}).Debugf("UDP(DNS) <-> Cache (fast path): %v %v", queryInfo.qname, queryInfo.qtype)
				}

				// Update metrics
				labels := prometheus.Labels{
					"outbound": func() string {
						if outbound != nil {
							return outbound.Name
						}
						return "asis"
					}(),
					"qtype": QtypeToString(queryInfo.qtype),
				}
				common.DnsCacheHit.With(labels).Inc()

				// Send response immediately
				dnsMessage.Id = id
				dnsMessage.Compress = true
				buf := pool.GetBuffer(512)
				defer pool.PutBuffer(buf)
				if data, err := dnsMessage.PackBuffer(buf); err != nil {
					log.Errorf("%+v", oops.Wrapf(err, "failed to pack dns message"))
				} else if err = sendPkt(data, req.dst, req.src); err != nil {
					log.Warningf("%+v", oops.Wrapf(err, "failed to send dns message back"))
				}
				return
			}
		}
	}

	// Slow path: Cache miss - submit to worker pool
	// Create a copy of the message for the worker to avoid data races
	task := &DnsTask{
		msg:       dnsMessage.Copy(),
		req:       req,
		queryInfo: queryInfo,
		ctx:       context.Background(),
		done:      make(chan struct{}),
	}

	// Submit to worker pool and process asynchronously
	if !c.workerPool.Submit(task) {
		// Worker pool queue is full, fall back to goroutine
		log.Warnf("DNS worker pool queue full, falling back to goroutine")
		c.responseWg.Add(1)
		go func() {
			defer c.responseWg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("DNS response goroutine panic: %v", r)
				}
			}()
			// Process the copy and copy result back
			c.processDnsRequest(task.msg, req, queryInfo, id)
			*dnsMessage = *task.msg

			// Send response
			dnsMessage.Id = id
			dnsMessage.Compress = true
			buf := pool.GetBuffer(512)
			defer pool.PutBuffer(buf)
			if data, err := dnsMessage.PackBuffer(buf); err != nil {
				log.Errorf("%+v", oops.Wrapf(err, "failed to pack dns message"))
			} else if err = sendPkt(data, req.dst, req.src); err != nil {
				log.Warningf("%+v", oops.Wrapf(err, "failed to send dns message back"))
			}
		}()
	} else {
		// Process in worker pool - wait for worker to finish before sending response
		c.responseWg.Add(1)
		go func() {
			defer c.responseWg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("DNS response goroutine panic: %v", r)
				}
			}()
			// Wait for worker to finish processing
			<-task.done
			// The worker has processed the task (which was a copy of dnsMessage)
			// Now we need to copy the result back to the original dnsMessage
			*dnsMessage = *task.msg

			// Keep the id the same with request.
			dnsMessage.Id = id
			dnsMessage.Compress = true
			buf := pool.GetBuffer(512)
			defer pool.PutBuffer(buf)
			if data, err := dnsMessage.PackBuffer(buf); err != nil {
				log.Errorf("%+v", oops.Wrapf(err, "failed to pack dns message"))
			} else if err = sendPkt(data, req.dst, req.src); err != nil {
				log.Warningf("%+v", oops.Wrapf(err, "failed to send dns message back"))
			}
		}()
	}
}

// processDnsRequest contains the DNS request processing logic
// This is called by the worker pool or fallback goroutine
func (c *DnsController) processDnsRequest(dnsMessage *dnsmessage.Msg, req *dnsRequest, queryInfo queryInfo, id uint16) {
	var err error
	// Check ip version preference and qtype.
	switch queryInfo.qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if c.qtypePrefer == 0 {
			err = c.handleDNSRequest(dnsMessage, req, queryInfo)
		} else {
			// Try to make both A and AAAA lookups.
			dnsMessage2 := dnsMessage.Copy()
			dnsMessage2.Id = uint16(fastrand.Intn(math.MaxUint16))
			switch queryInfo.qtype {
			case dnsmessage.TypeA:
				dnsMessage2.Question[0].Qtype = dnsmessage.TypeAAAA
			case dnsmessage.TypeAAAA:
				dnsMessage2.Question[0].Qtype = dnsmessage.TypeA
			}

			// TODO: ignoreFixedTTL?
			errCh := make(chan error, 1)
			go func() {
				err = c.handleDNSRequest(dnsMessage2, req, queryInfo)
				errCh <- err
			}()
			err = oops.Join(c.handleDNSRequest(dnsMessage, req, queryInfo), <-errCh)
			if err != nil {
				break
			}
			if c.qtypePrefer != queryInfo.qtype && dnsMessage2 != nil && IncludeAnyIpInMsg(dnsMessage2) {
				c.reject(dnsMessage)
			}
		}
	default:
		err = c.handleDNSRequest(dnsMessage, req, queryInfo)
	}
	if err != nil {
		netErr, ok := IsNetError(err)
		err = oops.
			With("Is NetError", ok).
			With("Is Temporary", ok && netErr.Temporary()).
			With("Is Timeout", ok && netErr.Timeout()).
			Wrapf(err, "failed to make dns request")
		if !ok || !netErr.Temporary() {
			log.Warningf("%+v", err)
		}
		dnsMessage.Rcode = dnsmessage.RcodeServerFailure
		dnsMessage.Response = true
	}
}

// TODO: 除了dialSend, 不应该有可预期的 err
// TODO: qname=. qtype=2 的查询是什么, 为什么没有缓存, 因为AsIs?
// TODO: 如果AsIs都不缓存的话，如果一个server可用一个不可用，那就是远端sever的问题?
func (c *DnsController) handleDNSRequest(
	dnsMessage *dnsmessage.Msg,
	req *dnsRequest,
	queryInfo queryInfo,
) error {
	// Route Request
	RequestIndex, err := c.routing.RequestSelect(queryInfo.qname, queryInfo.qtype)
	if err != nil {
		return err
	}

	if RequestIndex == consts.DnsRequestOutboundIndex_Reject {
		c.reject(dnsMessage)
		return nil
	}

	var upstream *dns.Upstream
	if RequestIndex == consts.DnsRequestOutboundIndex_AsIs {
		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.dst.Addr().String(),
			Port:     req.dst.Port(),
			Ip46:     netutils.FromAddr(req.dst.Addr()),
			IsAsIs:   true,
		}
	} else {
		// Get corresponding upstream.
		upstream, err = c.routing.GetUpstream(RequestIndex)
		if err != nil {
			return err
		}
	}

	// Dial and re-route
	var reqMsg *dnsmessage.Msg
	if !c.routing.HasResponseRules() {
		reqMsg = dnsMessage
	} else {
		reqMsg = dnsMessage.Copy()
	}
Dial:
	for invokingDepth := 1; invokingDepth <= MaxDnsLookupDepth; invokingDepth++ {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"question": dnsMessage.Question,
				"upstream": upstream.String(),
			}).Debugln("Request to DNS upstream")
		}

		// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
		dialArgument, err := c.bestDialerChooser(req, upstream)
		if err != nil {
			return err
		}

		// TODO: 这里可能不可以这样做
		err = c.dialSend(dnsMessage, upstream, dialArgument, queryInfo)
		if err != nil {
			netErr, ok := IsNetError(err)
			err = oops.
				In("DialContext").
				With("Is NetError", ok).
				With("Is Temporary", ok && netErr.Temporary()).
				With("Is Timeout", ok && netErr.Timeout()).
				With("qname", queryInfo.qname).
				With("qtype", queryInfo.qtype).
				With("Outbound", dialArgument.Outbound.Name).
				With("Dialer", dialArgument.Dialer.Name).
				Wrapf(err, "DNS dialSend error")
			if !ok || !dnsMessage.Response {
				return err
			} else if !netErr.Timeout() {
				if dialArgument.Dialer.NeedAliveState() {
					labels := prometheus.Labels{
						"outbound": dialArgument.Outbound.Name,
						"subtag":   dialArgument.Dialer.Property.SubscriptionTag,
						"dialer":   dialArgument.Dialer.Name,
						"network":  dialArgument.networkType.String(),
					}
					common.ErrorCount.With(labels).Inc()
					dialArgument.Dialer.ReportUnavailable()
					return err
				}
			}
		}

		// Route response.
		ResponseIndex, nextUpstream, err := c.routing.ResponseSelect(dnsMessage, upstream)
		if err != nil {
			return err
		}
		if ResponseIndex.IsReserved() {
			c.logDnsResponse(req, dialArgument, queryInfo, ResponseIndex == consts.DnsResponseOutboundIndex_Accept)
			switch ResponseIndex {
			case consts.DnsResponseOutboundIndex_Reject:
				// Reject
				// TODO: cache response reject.
				c.reject(dnsMessage)
				fallthrough
			case consts.DnsResponseOutboundIndex_Accept:
				// Accept.
				break Dial
			default:
				return oops.Errorf("unknown upstream: %v", ResponseIndex.String())
			}
		}
		if invokingDepth == MaxDnsLookupDepth {
			return oops.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"question":      dnsMessage.Question,
				"last_upstream": upstream.String(),
				"next_upstream": nextUpstream.String(),
			}).Debugln("Change DNS upstream and resend")
		}
		upstream = nextUpstream
		reqMsg.CopyTo(dnsMessage)
	}
	// TODO: dial_mode: domain 的逻辑失效问题
	// TODO: 我们现在缓存了它, 但并不响应缓存, 这是一个workround, 会导致污染其他非AsIs的查询
	// TODO: AsIs也需要更新domain_routing_map? 不然没有办法sniff, 并且考虑到有些应用会使用不同的DNS, 必须对全部 upstream 更新
	// TODO: RemoveCache
	// TODO: 不再存储Bitmap, 提高更新代码可读性
	// 但在有bump_map的情况下这不是大问题
	// TOOD: 细分日志
	switch {
	case !dnsMessage.Response,
		len(dnsMessage.Answer) == 0,
		len(dnsMessage.Question) == 0,               // Check healthy resp.
		dnsMessage.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
		return nil
	}

	if domainBitmap, allZero, shouldUpdate := c.checkDomainBitmap(queryInfo.qname); shouldUpdate {
		var ttl uint32
		var ips []netip.Addr
		for _, rr := range dnsMessage.Answer {
			if ttl == 0 {
				ttl = rr.Header().Ttl
			}
			ip, ok := GetIp(rr)
			if ok {
				ips = append(ips, ip)
			}
		}
		return c.updateLookupCache(queryInfo.qname, domainBitmap, allZero, ips, time.Duration(ttl)*time.Second)
	}
	return nil
}

func (c *DnsController) logDnsResponse(req *dnsRequest, dialArgument *dialArgument, queryInfo queryInfo, accepted bool) {
	if log.IsLevelEnabled(log.InfoLevel) {
		fields := log.Fields{
			"network":  dialArgument.networkType.String(),
			"outbound": dialArgument.Outbound.Name,
			"policy":   dialArgument.Outbound.GetSelectionPolicy(),
			"dialer":   dialArgument.Dialer.Name,
			"qname":    queryInfo.qname,
			"qtype":    queryInfo.qtype,
			"pid":      req.routingResult.Pid,
			"ifindex":  req.routingResult.Ifindex,
			"dscp":     req.routingResult.Dscp,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		if accepted {
			tcpDnsStr := ""
			if req.isTcp {
				tcpDnsStr = "(TCP)"
			}
			log.WithFields(fields).Infof("[DNS%s] %v <-> %v", tcpDnsStr, RefineSourceToShow(req.src, req.dst.Addr()), RefineAddrPortToShow(dialArgument.Target))
		} else {
			log.WithFields(fields).Infof("[DNS] %v <-> %v Reject with empty answer", RefineSourceToShow(req.src, req.dst.Addr()), RefineAddrPortToShow(dialArgument.Target))
		}
	}
}

func (c *DnsController) checkDomainBitmap(qname string) (domainBitmap [32]uint32, allZero bool, shouldUpdateLookupCache bool) {
	bitmapSlice := c.matchBitmap(qname)
	copy(domainBitmap[:], bitmapSlice)
	allZero = true
	for _, v := range domainBitmap {
		if v != 0 {
			allZero = false
			break
		}
	}
	// When SniffVerifyMode is 'loose' and no record in deadline timers, ControlPlane would try
	// to resolve IPs for sniffing verification, which might cause dns leaks! So only skip the
	// lookup cache update when SniffVerifyMode isn't 'loose'.
	shouldUpdateLookupCache = !allZero || c.sniffVerifyMode == consts.SniffVerifyMode_Loose
	return
}

func (c *DnsController) updateLookupCache(qname string, domainBitmap [32]uint32, allZero bool, ips []netip.Addr, ttl time.Duration) error {
	if len(ips) == 0 {
		return nil
	}
	lookupTTL := max(ttl, c.minSniffingTtl)
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ip := range ips {
		if _, ok := c.deadlineTimers[qname]; !ok {
			c.deadlineTimers[qname] = make(map[netip.Addr]*time.Timer)
		}
		if timer, ok := c.deadlineTimers[qname][ip]; ok {
			timer.Reset(lookupTTL)
			continue
		}
		if !allZero {
			if err := c.newLookupCache(ip, domainBitmap); err != nil {
				return err
			}
			common.CoreIpDomainBitmap.Inc()
		}
		c.deadlineTimers[qname][ip] = time.AfterFunc(lookupTTL, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if !allZero {
				if err := c.lookupCacheTimeout(ip, domainBitmap); err == nil {
					common.CoreIpDomainBitmap.Dec()
				}
			}
			delete(c.deadlineTimers[qname], ip)
			if len(c.deadlineTimers[qname]) == 0 {
				delete(c.deadlineTimers, qname)
			}
			common.DeadlineTimers.Dec()
		})
		common.DeadlineTimers.Inc()
	}
	return nil
}

func (c *DnsController) MaybeUpdateLookupCache(qname string, ips []netip.Addr, ttl time.Duration) error {
	if len(ips) == 0 {
		return nil
	}
	if domainBitmap, allZero, shouldUpdate := c.checkDomainBitmap(qname); shouldUpdate {
		return c.updateLookupCache(qname, domainBitmap, allZero, ips, ttl)
	}
	return nil
}

func (c *DnsController) reject(msg *dnsmessage.Msg) {
	// Reject with empty answer.
	msg.Answer = []dnsmessage.RR{}
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
}

// TODO: 简化 cacheKey?
func (c *DnsController) dialSend(msg *dnsmessage.Msg, upstream *dns.Upstream, dialArgument *dialArgument, queryInfo queryInfo) error {
	/// Dial and send.
	// get forwarder from cache
	key := dnsForwarderKey{upstream: upstream.String(), dialArgument: *dialArgument}
	var cacheKey *dnsCacheKey
	if c.enableCache {
		cacheKey = &dnsCacheKey{queryInfo: queryInfo, outbound: dialArgument.Outbound}
		// No parallel for the same lookup.
		l, _ := c.dnsKeyLocker.Lock(*cacheKey)
		defer c.dnsKeyLocker.Unlock(*cacheKey, l)
	}
	var forwarder DnsForwarder
	value, ok := c.dnsForwarderCache.Load(key)
	if ok {
		// Lookup Cache
		if cacheKey != nil {
			if cache := c.dnsCache.Get(*cacheKey); cache != nil {
				if !AllTimeout(cache) {
					FillInto(msg, cache)
					if log.IsLevelEnabled(log.DebugLevel) && len(msg.Question) > 0 {
						log.WithFields(log.Fields{
							"answer": msg.Answer,
						}).Debugf("UDP(DNS) <-> Cache: %v %v", queryInfo.qname, queryInfo.qtype)
					}
					labels := prometheus.Labels{
						"outbound": dialArgument.Outbound.Name,
						"qtype":    QtypeToString(queryInfo.qtype),
					}
					common.DnsCacheHit.With(labels).Inc()
					return nil
				}
			}
		}
		forwarder = value.(DnsForwarder)
	} else {
		var err error
		forwarder, err = newDnsForwarder(upstream, *dialArgument)
		if err != nil {
			return err
		}
		// Try to store the new forwarder, but use LoadOrStore to handle concurrent creation
		actualValue, _ := c.dnsForwarderCache.LoadOrStore(key, forwarder)
		forwarder = actualValue.(DnsForwarder)
	}

	// Use singleflight to deduplicate concurrent queries for the same domain
	// Key format: "qname:qtype:upstream" to ensure uniqueness
	sfKey := fmt.Sprintf("%s:%d:%s", queryInfo.qname, queryInfo.qtype, upstream.String())
	result, err, shared := c.sfGroup.Do(sfKey, func() (interface{}, error) {
		// ForwardDNS performs the actual DNS query
		forwardErr := forwarder.ForwardDNS(msg)
		if forwardErr != nil {
			return nil, forwardErr
		}
		// Return a copy of the message to avoid data races
		return msg.Copy(), nil
	})

	if err != nil {
		return err
	}

	// If the result was shared (another goroutine performed the query),
	// copy the result back to the original message
	if shared {
		// Use comma-ok pattern for type assertion to prevent panic
		resultMsg, ok := result.(*dnsmessage.Msg)
		if !ok {
			return oops.Errorf("singleflight result type assertion failed: expected *dnsmessage.Msg, got %T", result)
		}
		// Copy the response back to the original message
		msg.Id = resultMsg.Id
		msg.Response = resultMsg.Response
		msg.Rcode = resultMsg.Rcode
		msg.Answer = append([]dnsmessage.RR{}, resultMsg.Answer...)
		msg.Ns = append([]dnsmessage.RR{}, resultMsg.Ns...)
		msg.Extra = append([]dnsmessage.RR{}, resultMsg.Extra...)
	}

	if log.IsLevelEnabled(log.DebugLevel) && shared {
		log.WithFields(log.Fields{
			"qname": queryInfo.qname,
			"qtype": queryInfo.qtype,
		}).Debugf("DNS query result was shared (singleflight deduplication)")
	}

	log.WithFields(log.Fields{
		"qname": queryInfo.qname,
		"qtype": queryInfo.qtype,
		"rcode": msg.Rcode,
		"ans":   FormatDnsRsc(msg.Answer),
	}).Debugf("Got DNS response")

	// TODO: 细分日志
	if !msg.Response {
		return oops.Errorf("DNS message response flag is unset")
	}
	switch {
	case len(msg.Question) == 0, // Check healthy resp.
		msg.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
		log.WithFields(log.Fields{
			"qname": queryInfo.qname,
			"qtype": queryInfo.qtype,
			"rcode": msg.Rcode,
			"ans":   FormatDnsRsc(msg.Answer),
		}).Tracef("Not a valid DNS response")
		return nil
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"qname":    queryInfo.qname,
			"qtype":    queryInfo.qtype,
			"rcode":    msg.Rcode,
			"ans":      FormatDnsRsc(msg.Answer),
			"upstream": upstream,
			"dialer":   dialArgument.Dialer,
			"outbound": dialArgument.Outbound,
		}).Debugf("Update DNS record cache")
	}
	if cacheKey != nil {
		c.UpdateDnsCacheTtl(*cacheKey, queryInfo.qname, msg.Answer)
	}

	return nil
}

func (c *DnsController) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Stop worker pool
	if c.workerPool != nil {
		c.workerPool.Stop()
	}

	// Wait for all response goroutines to finish
	c.responseWg.Wait()

	// Clean up all deadline timers to prevent goroutine leaks
	for _, ipTimers := range c.deadlineTimers {
		for _, timer := range ipTimers {
			if timer != nil {
				timer.Stop()
			}
		}
	}
	c.deadlineTimers = make(map[string]map[netip.Addr]*time.Timer)

	// Close all DNS forwarders
	c.dnsForwarderCache.Range(func(key, value any) bool {
		if forwarder, ok := value.(io.Closer); ok {
			forwarder.Close()
		}
		return true
	})
	return nil
}
