/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// udpIngressTask is the pooled owned form of the per-packet ingress task
// that used to be an escaping closure inside processPacket. Under saturated
// UDP load the closure was ~200-300B allocated per packet (~20% of the
// hot-path allocation profile); this structure captures the same variables
// by value (they are per-packet locals that never change after submission,
// so snapshotting is semantically identical) and is returned to the pool
// when Run completes.
type udpIngressTask struct {
	c            *ControlPlane
	lConn        *net.UDPConn
	pktBuf       pool.PB
	admission    *routingEpochIngressGate
	realDst      netip.AddrPort
	convergeSrc  netip.AddrPort
	flowDecision UdpFlowDecision
}

var udpIngressTaskPool = sync.Pool{
	New: func() any { return &udpIngressTask{} },
}

// Run executes the ingress packet handling. The buffer and admission gate
// are released and the task is returned to the pool in all paths.
func (t *udpIngressTask) Run() {
	c := t.c
	data := t.pktBuf
	realDst := t.realDst
	convergeSrc := t.convergeSrc
	flowDecision := t.flowDecision

	// Release order: buffer, admission, then the task itself (the pool must
	// not see the task before its deferred cleanup completes).
	defer udpIngressTaskPool.Put(t)
	defer data.Put()
	defer t.admission.release()
	var routingResult *bpfRoutingResult
	var freshRoutingResult *bpfRoutingResult

	// DNS ingress fast path: valid DNS packets to port 53 do not need
	// UdpEndpoint state tracking on ingress. Keep userspace handling to
	// reduce hot-path overhead, but best-effort preserve tuple metadata
	// for rules matching (pname/mac/dscp).
	if realDst.Port() == 53 {
		// Only self-directed traffic to the local DNS listener should be
		// short-circuited here. External LAN clients targeting a LAN-bound
		// listener have already entered the ingress/TProxy userspace path
		// and still need fast-path DNS handling.
		if c.dnsListener != nil {
			listenAddr := c.dnsListener.Addr()
			if shouldSkipDNSFastPathForLocalListenerTraffic(listenAddr, convergeSrc, realDst) {
				if c.log.IsLevelEnabled(logrus.TraceLevel) {
					c.log.WithFields(logrus.Fields{
						"src":        convergeSrc.String(),
						"dst":        realDst.String(),
						"listenAddr": listenAddr,
					}).Trace("Skipping DNS fast path for local traffic to our own DNS listener")
				}
				return
			}
		}

		if dnsMessage, _ := ChooseNatTimeout(data, true); dnsMessage != nil {
			dnsRoutingResult := &bpfRoutingResult{
				Outbound: uint8(consts.OutboundControlPlaneRouting),
			}
			if rr, retrieveErr := c.core.RetrieveRoutingResult(convergeSrc, realDst, unix.IPPROTO_UDP); retrieveErr == nil {
				dnsRoutingResult = rr
			} else if !stderrors.Is(retrieveErr, ebpf.ErrKeyNotExist) && c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithFields(logrus.Fields{
					"src": convergeSrc.String(),
					"dst": realDst.String(),
				}).WithError(retrieveErr).Debug("UDP routing tuple lookup failed for DNS ingress fast path; fallback to minimal routing metadata")
			}
			handler, release, ownerErr := c.acquireRoutingEpochExecutionOwner(dnsRoutingResult)
			if ownerErr != nil {
				c.log.WithError(ownerErr).Warn("DNS ingress routing epoch owner is unavailable")
				return
			}
			if release != nil {
				defer release()
			}
			if dnsRoutingResult.Mark == 0 {
				dnsRoutingResult.Mark = handler.soMarkFromDae
			}
			req := &udpRequest{
				realSrc:       convergeSrc,
				realDst:       realDst,
				src:           convergeSrc,
				lConn:         t.lConn,
				routingResult: dnsRoutingResult,
			}

			dnsController := handler.ActiveDnsController()
			if dnsController == nil {
				return
			}
			if e := dnsController.Handle_(handler.dnsRequestContext(handler.ctx, dnsController), dnsMessage, req); e != nil {
				if stderrors.Is(e, ErrDNSQueryConcurrencyLimitExceeded) {
					if handler.log.IsLevelEnabled(logrus.DebugLevel) {
						handler.log.WithFields(logrus.Fields{
							"src": convergeSrc.String(),
							"dst": realDst.String(),
						}).Debug("DNS query concurrency limit exceeded in fast path")
					}
					return
				}
				if stderrors.Is(e, ErrDNSTruncated) {
					if handler.log.IsLevelEnabled(logrus.DebugLevel) {
						handler.log.WithFields(logrus.Fields{
							"src":      convergeSrc.String(),
							"dst":      realDst.String(),
							"question": dnsMessage.Question,
						}).Debug("DNS ingress fast path got truncated UDP response; returning TC=1 to client")
					}
					if sendErr := dnsController.sendDnsTruncatedResponse_(dnsMessage, req, nil); sendErr != nil {
						if handler.log.IsLevelEnabled(logrus.WarnLevel) && handler.allowDnsFastPathServfailLog(time.Now()) {
							handler.log.WithError(stderrors.Join(e, sendErr)).WithFields(logrus.Fields{
								"src": convergeSrc.String(),
								"dst": realDst.String(),
							}).Warn("Failed to send truncated DNS response in DNS fast path")
						}
					}
					return
				}
				if handler.log.IsLevelEnabled(logrus.WarnLevel) && handler.allowDnsFastPathErrorLog(time.Now()) {
					handler.log.WithFields(logrus.Fields{
						"src":      convergeSrc.String(),
						"dst":      realDst.String(),
						"question": dnsMessage.Question,
						"error":    e.Error(),
					}).Warn("DNS ingress fast path failed; sending SERVFAIL response")
				}
				if sendErr := dnsController.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeServerFailure, "ServeFail (dns ingress fast path)", req, nil); sendErr != nil {
					if handler.log.IsLevelEnabled(logrus.WarnLevel) && handler.allowDnsFastPathServfailLog(time.Now()) {
						handler.log.WithError(stderrors.Join(e, sendErr)).WithFields(logrus.Fields{
							"src": convergeSrc.String(),
							"dst": realDst.String(),
						}).Warn("Failed to send SERVFAIL response in DNS fast path")
					}
					return
				}
			} else if handler.log.IsLevelEnabled(logrus.TraceLevel) {
				// Success logging for DNS fast path (trace level only)
				handler.log.WithFields(logrus.Fields{
					"src":      convergeSrc.String(),
					"dst":      realDst.String(),
					"question": dnsMessage.Question,
				}).Trace("DNS ingress fast path handled successfully")
			}
			return
		}
	}

	if !c.udpRouteScopeSensitive && c.ownsActiveRoutingEpoch() {
		if ue, ok := DefaultUdpEndpointPool.Get(flowDecision.CachedRoutingEndpointKey()); ok {
			if bound, bindingHit := ue.GetBoundRoutingResult(realDst, unix.IPPROTO_UDP); bindingHit {
				routingResult = bound
			}
		}
		if routingResult == nil {
			if fallbackKey, ok := flowDecision.CachedRoutingFallbackKey(); ok {
				if ue, ok := DefaultUdpEndpointPool.Get(fallbackKey); ok {
					if bound, bindingHit := ue.GetBoundRoutingResult(realDst, unix.IPPROTO_UDP); bindingHit {
						routingResult = bound
					}
				}
			}
		}
	}

	if routingResult == nil {
		rr, retrieveErr := c.core.RetrieveRoutingResult(convergeSrc, realDst, unix.IPPROTO_UDP)
		if retrieveErr != nil {
			switch {
			case stderrors.Is(retrieveErr, ebpf.ErrKeyNotExist):
				// Keep behavior consistent with TCP path: missing tuple can happen
				// in short race windows; fallback to userspace routing instead of
				// dropping the packet.
				routingResult = &bpfRoutingResult{
					Outbound: uint8(consts.OutboundControlPlaneRouting),
				}
				if c.log.IsLevelEnabled(logrus.DebugLevel) {
					c.log.WithFields(logrus.Fields{
						"src": convergeSrc.String(),
						"dst": realDst.String(),
					}).WithError(retrieveErr).Debug("UDP routing tuple missing; fallback to userspace routing")
				}
			case realDst.Port() == 53:
				// DNS should never be silently dropped due to transient eBPF lookup
				// failures. Fall back to userspace routing to preserve availability.
				routingResult = &bpfRoutingResult{
					Outbound: uint8(consts.OutboundControlPlaneRouting),
				}
				c.log.WithFields(logrus.Fields{
					"src": convergeSrc.String(),
					"dst": realDst.String(),
				}).WithError(retrieveErr).Warn("UDP routing tuple lookup failed for DNS; fallback to userspace routing")
			default:
				c.log.Warnf("No AddrPort presented: %v", retrieveErr)
				return
			}
		} else {
			routingResult = rr
			rrCopy := *routingResult
			freshRoutingResult = &rrCopy
		}
	}

	if e := c.handlePkt(t.lConn, data, convergeSrc, realDst, routingResult, flowDecision, false); e != nil {
		// Rate-limit the expected reload-window routing-epoch
		// ownership loss; other handlePkt errors still log always.
		if stderrors.Is(e, errRoutingEpochOwnerUnavailable) {
			if c.log.IsLevelEnabled(logrus.WarnLevel) && c.allowHandlePktEpochWarn(time.Now()) {
				c.log.Warnln("handlePkt:", e)
			}
		} else {
			c.log.Warnln("handlePkt:", e)
		}
		return
	}

	if !c.udpRouteScopeSensitive && c.ownsActiveRoutingEpoch() && freshRoutingResult != nil {
		updatedCache := false
		if ue, ok := DefaultUdpEndpointPool.Get(flowDecision.CachedRoutingEndpointKey()); ok {
			ue.UpdateCachedRoutingResult(realDst, unix.IPPROTO_UDP, freshRoutingResult)
			updatedCache = true
		}
		if !updatedCache {
			if fallbackKey, ok := flowDecision.CachedRoutingFallbackKey(); ok {
				if ue, ok := DefaultUdpEndpointPool.Get(fallbackKey); ok {
					ue.UpdateCachedRoutingResult(realDst, unix.IPPROTO_UDP, freshRoutingResult)
				}
			}
		}
	}
}
