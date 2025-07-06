/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

const (
	MaxDnsLookupDepth  = 3
	minFirefoxCacheTtl = 120
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
	Log                *logrus.Logger
	NewLookupCache     func(fqdn string, answers []dnsmessage.RR, deadline time.Time) (cache *LookupCache, err error)
	LookupCacheTimeout func(cache *LookupCache) (err error)
	BestDialerChooser  func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	IpVersionPrefer    int
	FixedDomainTtl     map[string]int
}

type DnsController struct {
	routing     *dns.Dns
	qtypePrefer uint16

	log                *logrus.Logger
	newLookupCache     func(fqdn string, answers []dnsmessage.RR, deadline time.Time) (cache *LookupCache, err error)
	lookupCacheTimeout func(cache *LookupCache) (err error)
	bestDialerChooser  func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)

	fixedDomainTtl    map[string]int
	lookupKeyLocker   common.KeyLocker[string]
	dnsCache          sync.Map // map[string]*DnsCache
	lookupCache       sync.Map // map[string]*LookupCache
	dnsForwarderCache sync.Map // map[dnsForwarderKey]DnsForwarder
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

	return &DnsController{
		routing:     routing,
		qtypePrefer: prefer,

		log:                option.Log,
		newLookupCache:     option.NewLookupCache,
		lookupCacheTimeout: option.LookupCacheTimeout,
		bestDialerChooser:  option.BestDialerChooser,

		fixedDomainTtl:    option.FixedDomainTtl,
		dnsForwarderCache: sync.Map{},
	}, nil
}

func (c *DnsController) cacheKey(qname string, qtype uint16) string {
	return dnsmessage.CanonicalName(qname) + strconv.Itoa(int(qtype))
}

func (c *DnsController) RemoveDnsRespCache(cacheKey string) {
	c.dnsCache.Delete(cacheKey)
}

func (c *DnsController) HasLookupCache(cacheKey string) (ok bool) {
	_, ok = c.lookupCache.Load(cacheKey)
	// TODO: Check TTL?
	return
}

func (c *DnsController) LookupDnsRespCache(cacheKey string) (cache *DnsCache) {
	value, ok := c.dnsCache.Load(cacheKey)
	if !ok {
		return nil
	}
	cache = value.(*DnsCache)
	// We should make sure the cache did not expire, or
	// return nil and request a new lookup to refresh the cache.
	if cache.Deadline.Before(time.Now()) {
		return nil
	}
	return cache
}

func (c *DnsController) LookupDnsRespCacheMsg(msg *dnsmessage.Msg, cacheKey string) {
	cache := c.LookupDnsRespCache(cacheKey)
	if cache != nil {
		cache.FillInto(msg)
		// TODO: 允许关闭这部分逻辑
		ttl := uint32(time.Until(cache.Deadline).Seconds())
		for i := range msg.Answer {
			msg.Answer[i].Header().Ttl = ttl
		}
	}
}

func (c *DnsController) NormalizeDnsResp(answers []dnsmessage.RR) (ttl uint32) {
	// Get TTL.
	for _, ans := range answers {
		if ttl == 0 {
			ttl = ans.Header().Ttl
			break
		}
	}
	if len(answers) == 0 {
		// It seems no answers (NXDomain).
		ttl = minFirefoxCacheTtl
	}

	// Set TTL = zero. This requests applications must resend every request.
	// However, it may be not defined in the standard.
	for i := range answers {
		answers[i].Header().Ttl = 0
	}
	return
}

func (c *DnsController) updateLookupCacheDeadline(fqdn string, cacheKey string, answers []dnsmessage.RR, deadline time.Time) (err error) {
	value, ok := c.lookupCache.Load(cacheKey)
	if ok {
		cache := value.(*LookupCache)
		cache.Answer = answers
		cache.Deadline = deadline
	} else {
		cache, err := c.newLookupCache(fqdn, answers, deadline)
		if err != nil {
			return err
		}
		// Try to store the new cache, but use LoadOrStore to handle concurrent creation
		c.lookupCache.LoadOrStore(cacheKey, cache)
	}
	return nil
}

func (c *DnsController) UpdateLookupCacheTtl(fqdn string, cacheKey string, answers []dnsmessage.RR, ttl int) (err error) {
	return c.updateLookupCacheDeadline(fqdn, cacheKey, answers, time.Now().Add(time.Duration(ttl)*time.Second))
}

func (c *DnsController) updateDnsCacheDeadline(fqdn string, cacheKey string, answers []dnsmessage.RR, deadline time.Time) (err error) {
	value, ok := c.dnsCache.Load(cacheKey)
	if ok {
		cache := value.(*DnsCache)
		cache.Answer = answers
		cache.Deadline = deadline
	} else {
		cache := &DnsCache{
			Answer:   answers,
			Deadline: deadline,
		}
		if err != nil {
			return err
		}
		// Try to store the new cache, but use LoadOrStore to handle concurrent creation
		c.dnsCache.LoadOrStore(cacheKey, cache)
	}
	return nil
}

func (c *DnsController) UpdateDnsCacheDeadline(fqdn string, cacheKey string, answers []dnsmessage.RR, deadline time.Time) (err error) {
	if fixedTtl, ok := c.fixedDomainTtl[fqdn]; ok {
		return c.updateDnsCacheDeadline(fqdn, cacheKey, answers, time.Now().Add(time.Duration(fixedTtl)*time.Second))
	} else {
		return c.updateDnsCacheDeadline(fqdn, cacheKey, answers, deadline)
	}
}

func (c *DnsController) UpdateDnsCacheTtl(fqdn string, cacheKey string, answers []dnsmessage.RR, ttl int) (err error) {
	if fixedTtl, ok := c.fixedDomainTtl[fqdn]; ok {
		return c.updateDnsCacheDeadline(fqdn, cacheKey, answers, time.Now().Add(time.Duration(fixedTtl)*time.Second))
	} else {
		return c.updateDnsCacheDeadline(fqdn, cacheKey, answers, time.Now().Add(time.Duration(ttl)*time.Second))
	}
}

type udpRequest struct {
	realSrc       netip.AddrPort
	realDst       netip.AddrPort
	src           netip.AddrPort
	lConn         *net.UDPConn
	routingResult *bpfRoutingResult
}

type dialArgument struct {
	networkType  dialer.NetworkType
	bestDialer   *dialer.Dialer
	bestOutbound *outbound.DialerGroup
	bestTarget   netip.AddrPort
	mark         uint32
}

type dnsForwarderKey struct {
	upstream     string
	dialArgument dialArgument
}

func IncludeAnyIp(msg *dnsmessage.Msg) bool {
	for _, ans := range msg.Answer {
		switch ans.(type) {
		case *dnsmessage.A, *dnsmessage.AAAA:
			return true
		}
	}
	return false
}

func (c *DnsController) prepareQueryInfo(dnsMessage *dnsmessage.Msg) (qname string, qtype uint16) {
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		qname = dnsmessage.CanonicalName(q.Name)
		qtype = q.Qtype
	}
	return
}

func (c *DnsController) Handle(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	if c.log.IsLevelEnabled(logrus.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		c.log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.realSrc, req.realDst.Addr()), req.realDst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		return fmt.Errorf("DNS request expected but DNS response received")
	}

	_, qtype := c.prepareQueryInfo(dnsMessage)
	id := dnsMessage.Id

	go func() {
		var err error
		// Check ip version preference and qtype.
		switch qtype {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			if c.qtypePrefer == 0 {
				err = c.handleDNSRequest(dnsMessage, req)
			} else {
				// Try to make both A and AAAA lookups.
				dnsMessage2 := deepcopy.Copy(dnsMessage).(*dnsmessage.Msg)
				dnsMessage2.Id = uint16(fastrand.Intn(math.MaxUint16))
				switch qtype {
				case dnsmessage.TypeA:
					dnsMessage2.Question[0].Qtype = dnsmessage.TypeAAAA
				case dnsmessage.TypeAAAA:
					dnsMessage2.Question[0].Qtype = dnsmessage.TypeA
				}

				// TODO: ignoreFixedTTL?
				errCh := make(chan error, 1)
				go func() {
					err = c.handleDNSRequest(dnsMessage2, req)
					errCh <- err
				}()
				err = oops.Join(c.handleDNSRequest(dnsMessage, req), <-errCh)
				if err != nil {
					break
				}
				if c.qtypePrefer != qtype && dnsMessage2 != nil && IncludeAnyIp(dnsMessage2) {
					c.reject(dnsMessage)
				}
			}
		default:
			err = c.handleDNSRequest(dnsMessage, req)
		}
		if err != nil {
			var netErr net.Error
			err = oops.
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				Wrapf(err, "failed to make dns request")
			// TODO: 不是neterr也需要展示, 需要同步这个行为到其他代码
			if errors.As(err, &netErr) {
				if !netErr.Temporary() {
					c.log.Warningf("%+v", err)
				}
			} else {
				c.log.Warningf("%+v", err)
			}
			return
		}
		// Keep the id the same with request.
		dnsMessage.Id = id
		dnsMessage.Compress = true
		var data []byte
		if data, err = dnsMessage.Pack(); err != nil {
			c.log.Errorf("%+v", oops.Wrapf(err, "failed to pack dns message"))
		}
		if err = sendPkt(c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
			c.log.Warningf("%+v", oops.Wrapf(err, "failed to send dns message back"))
		}
	}()

	return nil
}

// TODO: 除了dialSend, 不应该有可预期的 err
// TODO: qname=. qtype=2 的查询是什么, 为什么没有缓存, 因为AsIs?
// TODO: 如果AsIs都不缓存的话，如果一个server可用一个不可用，那就是远端sever的问题?
func (c *DnsController) handleDNSRequest(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
) error {
	qname, qtype := c.prepareQueryInfo(dnsMessage)
	cacheKey := c.cacheKey(qname, qtype)

	// Route Requset
	RequestIndex, upstream, err := c.routing.RequestSelect(qname, qtype)
	if err != nil {
		return err
	}

	if RequestIndex == consts.DnsRequestOutboundIndex_Reject {
		c.reject(dnsMessage)
		return nil
	}

	if RequestIndex == consts.DnsRequestOutboundIndex_AsIs {
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
		// upstream already retrieved from RequestSelect

		// Lookup Cache
		// Not Lookup Cache if AsIs
		if c.LookupDnsRespCacheMsg(dnsMessage, cacheKey); dnsMessage.Response {
			if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Question) > 0 {
				c.log.Debugf("UDP(DNS) %v <-> Cache: %v %v",
					RefineSourceToShow(req.realSrc, req.realDst.Addr()), qname, qtype,
				)
			}
			return nil
		}
	}

	// Dial and re-route
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
			"upstream": upstream.String(),
		}).Traceln("Request to DNS upstream")
	}

	var dialArgument *dialArgument
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}

	// No parallel for the same lookup.
	// l := c.lookupKeyLocker.Lock(cacheKey)
	// defer c.lookupKeyLocker.Unlock(cacheKey, l)
Dial:
	for invokingDepth := 1; invokingDepth <= MaxDnsLookupDepth; invokingDepth++ {
		// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
		dialArgument, err = c.bestDialerChooser(req, upstream)
		if err != nil {
			return err
		}

		// TODO: 这里可能不可以这样做
		err = c.dialSend(0, req, data, upstream, dialArgument, dnsMessage)
		if err != nil {
			var netErr net.Error
			err = oops.
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				Wrapf(err, "DNS dialSend error")
			if errors.As(err, &netErr) && !netErr.Temporary() {
				dialArgument.bestDialer.ReportUnavailable(&dialArgument.networkType, err)
			}
			return err
		}

		// Route response.
		ResponseIndex, nextUpstream, err := c.routing.ResponseSelect(dnsMessage, upstream)
		if err != nil {
			return err
		}
		if ResponseIndex.IsReserved() {
			if c.log.IsLevelEnabled(logrus.InfoLevel) {
				fields := logrus.Fields{
					"network":  dialArgument.networkType.String(),
					"outbound": dialArgument.bestOutbound.Name,
					"policy":   dialArgument.bestOutbound.GetSelectionPolicy(),
					"dialer":   dialArgument.bestDialer.Property().Name,
					"qname":    qname,
					"qtype":    qtype,
					"pid":      req.routingResult.Pid,
					"ifindex":  req.routingResult.Ifindex,
					"dscp":     req.routingResult.Dscp,
					"pname":    ProcessName2String(req.routingResult.Pname[:]),
					"mac":      Mac2String(req.routingResult.Mac[:]),
				}
				switch ResponseIndex {
				case consts.DnsResponseOutboundIndex_Accept:
					c.log.WithFields(fields).Infof("[DNS] %v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr()), RefineAddrPortToShow(dialArgument.bestTarget))
				case consts.DnsResponseOutboundIndex_Reject:
					c.log.WithFields(fields).Infof("[DNS] %v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr()), RefineAddrPortToShow(dialArgument.bestTarget))
				}
			}
			switch ResponseIndex {
			case consts.DnsResponseOutboundIndex_Accept:
				// Accept.
				break Dial
			case consts.DnsResponseOutboundIndex_Reject:
				// Reject
				// TODO: cache response reject.
				c.reject(dnsMessage)
				break Dial
			default:
				return oops.Errorf("unknown upstream: %v", ResponseIndex.String())
			}
		}
		if invokingDepth == MaxDnsLookupDepth {
			return oops.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
		}
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      dnsMessage.Question,
				"last_upstream": upstream.String(),
				"next_upstream": nextUpstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		upstream = nextUpstream
	}
	// TODO: dial_mode: domain 的逻辑失效问题
	// TODO: 我们现在缓存了它, 但并不响应缓存, 这是一个workround, 会导致污染其他非AsIs的查询
	// TODO: AsIs也需要更新domain_routing_map? 不然没有办法sniff, 并且考虑到有些应用会使用不同的DNS, 必须对全部 upstream 更新
	// TODO: RemoveCache
	// TODO: 不再存储Bitmap, 提高更新代码可读性
	// 但在有bump_map的情况下这不是大问题
	switch {
	case !dnsMessage.Response,
		len(dnsMessage.Question) == 0,               // Check healthy resp.
		dnsMessage.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
		return nil
	}
	ans := deepcopy.Copy(dnsMessage.Answer).([]dnsmessage.RR)
	ttl := c.NormalizeDnsResp(ans)
	if err := c.UpdateLookupCacheTtl(qname, cacheKey, ans, int(ttl)); err != nil {
		return err
	}
	if RequestIndex != consts.DnsRequestOutboundIndex_AsIs {
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"qname": qname,
				"qtype": qtype,
				"rcode": dnsMessage.Rcode,
				"ans":   FormatDnsRsc(ans),
			}).Tracef("Update DNS record cache")
		}

		if err := c.UpdateDnsCacheTtl(qname, cacheKey, ans, int(ttl)); err != nil {
			return err
		}
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

func (c *DnsController) dialSend(invokingDepth int, req *udpRequest, data []byte, upstream *dns.Upstream, dialArgument *dialArgument, dnsMessage *dnsmessage.Msg) error {
	// Dial and send.
	// defer in a recursive call will delay Close(), thus we Close() before
	// the next recursive call. However, a connection cannot be closed twice.
	// We should set a connClosed flag to avoid it.
	ctxDial, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()

	// get forwarder from cache
	key := dnsForwarderKey{upstream: upstream.String(), dialArgument: *dialArgument}
	var forwarder DnsForwarder
	value, ok := c.dnsForwarderCache.Load(key)
	if ok {
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

	defer func() {
		forwarder.Close()
	}()

	respMsg, err := forwarder.ForwardDNS(ctxDial, data)
	if err != nil {
		return err
	}
	*dnsMessage = *respMsg
	return nil
}
