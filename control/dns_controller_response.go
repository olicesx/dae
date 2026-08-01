/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func (c *DnsController) writeCachedResponse(resp []byte, reqId uint16, req *udpRequest, responseWriter dnsmessage.ResponseWriter) error {
	// Optimization: Patch ID directly in the packed buffer if possible.
	// For UDP, we can use Write() directly. For TCP, we might need WriteMsg or manual length.
	// However, most responseWriters here are either UDP or wrappers that handle message framing.

	if responseWriter != nil {
		var respMsg dnsmessage.Msg
		if err := respMsg.Unpack(resp); err != nil {
			return fmt.Errorf("failed to unpack DNS response: %w", err)
		}
		// Set the correct ID from the original request
		respMsg.Id = reqId
		return responseWriter.WriteMsg(&respMsg)
	}

	// For UDP path, directly send pre-packed response with patched ID
	if req == nil || req.lConn == nil {
		return fmt.Errorf("dns request connection is nil for cached response")
	}

	// OPTIMIZATION: Use buffer pool to avoid memory allocation on every cache hit.
	// DNS Message ID is in the first 2 bytes (big-endian).
	if len(resp) >= 2 && len(resp) <= 1024 {
		bufPtr := dnsResponseBufPool.Get().(*[]byte)
		defer dnsResponseBufPool.Put(bufPtr)

		patchedResp := (*bufPtr)[:len(resp)]
		copy(patchedResp, resp)
		binary.BigEndian.PutUint16(patchedResp[0:2], reqId)

		// Transparent DNS replies must preserve the original DNS server tuple.
		// sendPkt also carries the DNS port-conflict raw fallback for host-local
		// clients where binding the source address may fail transiently.
		if err := sendRuntimeTrackedPkt(c.log, patchedResp, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
			return fmt.Errorf("failed to write cached DNS resp: %w", err)
		}
		return nil
	}

	// Fallback for oversized responses (rare)
	patchedResp := make([]byte, len(resp))
	copy(patchedResp, resp)
	if len(resp) >= 2 {
		binary.BigEndian.PutUint16(patchedResp[0:2], reqId)
	}

	if err := sendRuntimeTrackedPkt(c.log, patchedResp, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
		return fmt.Errorf("failed to write oversized cached DNS resp: %w", err)
	}
	return nil
}

// sendDnsErrorResponse_ is the shared implementation for both sendRejectWithResponseWriter_
// and sendRefusedWithResponseWriter_. It sets the common response fields, logs at trace
// level, and sends the response via responseWriter or UDP.

func (c *DnsController) sendDnsErrorResponse_(
	dnsMessage *dnsmessage.Msg,
	rcode int,
	traceMsg string,
	req *udpRequest,
	responseWriter dnsmessage.ResponseWriter,
) (err error) {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = rcode
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = false
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln(traceMsg)
	}
	if responseWriter != nil {
		return responseWriter.WriteMsg(dnsMessage)
	}
	if req == nil || req.lConn == nil {
		return nil
	}
	// Pack into a pooled DNS response buffer; data is consumed synchronously by the send.
	bufPtr := dnsResponseBufPool.Get().(*[]byte)
	defer dnsResponseBufPool.Put(bufPtr)
	data, err := dnsMessage.PackBuffer((*bufPtr)[:cap(*bufPtr)])
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
		return err
	}
	return nil
}

// sendRefusedWithResponseWriter_ sends REFUSED response when overload protection is triggered.

func (c *DnsController) sendRefusedWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	return c.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeRefused, "Refused due to concurrency limit", req, responseWriter)
}

func (c *DnsController) sendDnsTruncatedResponse_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) error {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = dnsmessage.RcodeSuccess
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = true
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln("Truncated")
	}
	if responseWriter != nil {
		return responseWriter.WriteMsg(dnsMessage)
	}
	if req == nil || req.lConn == nil {
		return nil
	}
	// Pack into a pooled DNS response buffer; data is consumed synchronously by the send.
	bufPtr := dnsResponseBufPool.Get().(*[]byte)
	defer dnsResponseBufPool.Put(bufPtr)
	data, err := dnsMessage.PackBuffer((*bufPtr)[:cap(*bufPtr)])
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
		return err
	}
	return nil
}

// sendRejectWithResponseWriter_ send empty answer.

func (c *DnsController) sendRejectWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	return c.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeSuccess, "Reject", req, responseWriter)
}

// applyPreferenceWait implements RFC 8305 Happy Eyeballs Resolution Delay.
// When ip_version_prefer is set and a non-preferred A/AAAA response is received,
// wait briefly (50ms) for the preferred response to arrive before using this one.
//
// This function handles two scenarios:
// 1. Non-preferred response arrives (e.g., A when prefer=6): Register wait and wait for preferred
// 2. Preferred response arrives (e.g., AAAA when prefer=6): Notify any waiting requests
//
// The function returns the response to use (preferred if arrived during wait, otherwise original).

func (c *DnsController) applyPreferenceWait(respMsg *dnsmessage.Msg) *dnsmessage.Msg {
	c.requireStore()
	// Fast path: preference not enabled
	if c.currentQtypePrefer() == 0 {
		return respMsg
	}

	// Only handle A/AAAA responses
	if len(respMsg.Question) == 0 {
		return respMsg
	}
	q := respMsg.Question[0]
	if q.Qtype != dnsmessage.TypeA && q.Qtype != dnsmessage.TypeAAAA {
		return respMsg
	}

	// Get canonical qname for matching
	qname := dnsmessage.CanonicalName(q.Name)

	// Case 1: This is the preferred response type - notify waiting requests
	qtypePrefer := c.currentQtypePrefer()
	if isPreferredType(q.Qtype, qtypePrefer) {
		// Notify any waiting requests for this domain
		if c.prefWaitRegistry.notifyPreferred(qname, q.Qtype, qtypePrefer) {
			if c.log.IsLevelEnabled(logrus.TraceLevel) {
				c.log.Tracef("Preferred %v response for %v notified waiting request", QtypeToString(q.Qtype), qname)
			}
		}
		return respMsg
	}

	// Case 2: This is a non-preferred response - register wait and wait for preferred
	if wait := c.prefWaitRegistry.registerWait(qname, q.Qtype, qtypePrefer); wait != nil {
		// Non-preferred response arrived before preferred - wait briefly for preferred
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("Non-preferred %v response for %v, waiting %v for preferred %v",
				QtypeToString(q.Qtype), qname, PreferenceResolutionDelay, QtypeToString(qtypePrefer))
		}

		// Wait for preferred response or timeout
		preferred := wait.waitFor()

		// Clean up wait registry
		c.prefWaitRegistry.remove(qname)

		if preferred {
			if c.log.IsLevelEnabled(logrus.TraceLevel) {
				c.log.Tracef("Preferred %v response arrived for %v during wait for %v",
					QtypeToString(qtypePrefer), qname, QtypeToString(q.Qtype))
			}
		} else if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("Preferred %v response not arrived for %v within %v, using %v response",
				QtypeToString(qtypePrefer), qname, PreferenceResolutionDelay, QtypeToString(q.Qtype))
		}

		// Always return the original response. The wait only changes when we
		// release the response, not the DNS question/answer type pairing.
		return respMsg
	}

	return respMsg
}
