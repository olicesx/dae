/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

var (
	// Values from OpenWRT default sysctl config
	DefaultNatTimeoutTCP = 5 * time.Minute
	DefaultNatTimeoutUDP = 90 * time.Second
)

const (
	DnsNatTimeout  = 17 * time.Second // RFC 5452
	AnyfromTimeout = 5 * time.Second  // Do not cache too long.
	MaxRetry       = 2
)

func ChooseNatTimeout(data []byte, sniffDns bool) (dmsg *dnsmessage.Msg, timeout time.Duration) {
	if sniffDns {
		var dnsmsg dnsmessage.Msg
		if err := dnsmsg.Unpack(data); err == nil {
			//log.Printf("DEBUG: lookup %v", dnsmsg.Question[0].Name)
			return &dnsmsg, DnsNatTimeout
		}
	}
	return nil, DefaultNatTimeoutUDP
}

// sendPkt uses bind first, and fallback to send hdr if addr is in use.
func sendPkt(log *logrus.Logger, data []byte, from netip.AddrPort, realTo, to netip.AddrPort, lConn *net.UDPConn) (err error) {
	uConn, _, err := DefaultAnyfromPool.GetOrCreate(from.String(), AnyfromTimeout)
	if err != nil {
		return
	}
	_, err = uConn.WriteToUDPAddrPort(data, realTo)
	return err
}

func (c *ControlPlane) handlePkt(lConn *net.UDPConn, data []byte, src, pktDst, realDst netip.AddrPort, routingResult *bpfRoutingResult, skipSniffing bool) (err error) {
	var realSrc netip.AddrPort
	var domain string
	realSrc = src

	/// Handle DNS
	// To keep consistency with kernel program, we only sniff DNS request sent to 53.
	dnsMessage, natTimeout := ChooseNatTimeout(data, realDst.Port() == 53)
	// We should cache DNS records and set record TTL to 0, in order to monitor the dns req and resp in real time.
	isDns := dnsMessage != nil && routingResult.Must == 0 // Regard as plain traffic
	// TODO: 重复逻辑
	if routingResult.Mark == 0 {
		routingResult.Mark = c.soMarkFromDae
	}
	if isDns {
		return c.dnsController.Handle(dnsMessage, &udpRequest{
			realSrc:       realSrc,
			realDst:       realDst,
			src:           src,
			lConn:         lConn,
			routingResult: routingResult,
		})
	}

	/// Sniff
	if !skipSniffing {
		// Sniff Quic, ...
		key := PacketSnifferKey{
			LAddr: realSrc,
			RAddr: realDst,
		}
		_sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
		_sniffer.Mu.Lock()
		// Re-get sniffer from pool to confirm the transaction is not done.
		sniffer := DefaultPacketSnifferSessionMgr.Get(key)
		if _sniffer == sniffer {
			sniffer.AppendData(data)
			domain, err = sniffer.SniffUdp()
			if err != nil && !sniffing.IsSniffingError(err) {
				sniffer.Mu.Unlock()
				return err
			}
			if sniffer.NeedMore() {
				sniffer.Mu.Unlock()
				return nil
			}
			if err != nil {
				logrus.Tracef("%+v", oops.
					With("from", realSrc).
					With("to", realDst).
					Wrapf(err, "sniffUDP"))
			}
			defer DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
			// Re-handlePkt after self func.
			toRehandle := sniffer.Data()[1 : len(sniffer.Data())-1] // Skip the first empty and the last (self).
			sniffer.Mu.Unlock()
			if len(toRehandle) > 0 {
				defer func() {
					if err == nil {
						for _, d := range toRehandle {
							dCopy := pool.Get(len(d))
							copy(dCopy, d)
							go c.handlePkt(lConn, dCopy, src, pktDst, realDst, routingResult, true)
							// TODO: error?
						}
					}
				}()
			}
		} else {
			_sniffer.Mu.Unlock()
			// sniffer may be nil.
		}
	}

	/// Dial and send.
	// TODO: Rewritten domain should not use full-cone (such as VMess Packet Addr).
	// 		Maybe we should set up a mapping for UDP: Dialer + Target Domain => Remote Resolved IP.
	//		However, games may not use QUIC for communication, thus we cannot use domain to dial, which is fine.

	// Retry loop for UDP endpoint creation and writing
	// for retry := 1; retry <= MaxRetry; retry++ {
	// 	if retry > 0 {
	// 		// Log retry atteWriteTompt
	// 		if c.log.IsLevelEnabled(logrus.DebugLevel) {
	// 			c.log.WithFields(logrus.Fields{
	// 				"src":     RefineSourceToShow(realSrc, realDst.Addr()),
	// 				"network": networkType.String(),
	// 				"retry":   retry,
	// 			}).Debugln("Retrying UDP endpoint creation/write...")
	// 		}
	// 	}

	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(realDst.Addr()),
		IsDns:     false,
	}

	l := DefaultUdpEndpointPool.UdpEndpointKeyLocker.Lock(realSrc)
	defer DefaultUdpEndpointPool.UdpEndpointKeyLocker.Unlock(realSrc, l)

	// Get udp endpoint.
	ue, ok := DefaultUdpEndpointPool.Get(realSrc)
	// If the udp endpoint has been not alive, remove it from pool and retry
	// UDP 不是面向连接的, 在 tcp 中, 一个连接失败, 我们会重置中继它, 等待一个新的连接
	// 在 UDP 中, l -> r继续中继到新的节点, 并在新的节点上进行 r -> l 中继
	if ok && !ue.Dialer.MustGetAlive(networkType) {
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"src":     RefineSourceToShow(realSrc, realDst.Addr()),
				"network": networkType.String(),
				"dialer":  ue.Dialer.Property().Name,
			}).Debugln("Old udp endpoint was not alive and removed.")
		}
		_ = DefaultUdpEndpointPool.Remove(realSrc)
		ok = false
	}
	if !ok {
		// Route
		dialOption, err := c.RouteDialOption(&RouteParam{
			routingResult: routingResult,
			networkType:   networkType,
			Domain:        domain,
			Src:           realSrc,
			Dest:          realDst,
		})
		if err != nil {
			return err
		}
		// Only print routing for new connection to avoid the log exploded (Quic and BT).
		if c.log.IsLevelEnabled(logrus.InfoLevel) {
			c.log.WithFields(logrus.Fields{
				"network":  networkType.StringWithoutDns(),
				"outbound": dialOption.Outbound.Name,
				"policy":   dialOption.Outbound.GetSelectionPolicy(),
				"dialer":   dialOption.Dialer.Property().Name,
				"sniffed":  domain,
				"ip":       RefineAddrPortToShow(realDst),
				"pid":      routingResult.Pid,
				"dscp":     routingResult.Dscp,
				"pname":    ProcessName2String(routingResult.Pname[:]),
				"mac":      Mac2String(routingResult.Mac[:]),
			}).Infof("[%v] %v <-> %v", strings.ToUpper(networkType.String()), RefineSourceToShow(realSrc, realDst.Addr()), dialOption.DialTarget)
		}

		// Dial
		// Do not overwrite target.
		// This fixes a problem that quic connection to google servers.
		// Reproduce:
		// docker run --rm --name curl-http3 ymuski/curl-http3 curl --http3 -o /dev/null -v -L https://i.ytimg.com
		ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
		defer cancel()
		udpConn, err := dialOption.Dialer.DialContext(ctx, common.MagicNetwork("udp", dialOption.Mark), realDst.String())
		if err != nil {
			return err
		}
		ue, err = DefaultUdpEndpointPool.Create(realSrc, &UdpEndpointOptions{
			PacketConn: udpConn.(netproxy.PacketConn),
			Handler: func(data []byte, from netip.AddrPort) (err error) {
				return sendPkt(c.log, data, from, realSrc, src, lConn)
			},
			NatTimeout: natTimeout,
			Dialer:     dialOption.Dialer,
		})
		if err != nil {
			var netErr net.Error
			err = oops.
				In("DialContext").
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				With("Outbound", dialOption.Outbound.Name).
				With("src", realSrc.String()).
				With("dst", realDst.String()).
				With("domain", domain).
				With("routingResult", routingResult).
				Wrapf(err, "failed to DialContext")
			if errors.As(err, &netErr) && !netErr.Temporary() {
				dialOption.Dialer.ReportUnavailable(networkType, err)
				if !dialOption.OutboundIndex.IsReserved() {
					return err
				}
			}
			c.log.Debugf("%+v", err)
			return nil
		}
	}

	// TODO: What is realSrc/Dst?
	// Try to write data
	_, err = ue.WriteTo(data, realDst.String())
	if err != nil {
		_ = DefaultUdpEndpointPool.Remove(realSrc)

		var netErr net.Error
		err = oops.
			In("UDP WriteTo").
			With("Is NetError", errors.As(err, &netErr)).
			With("Is Temporary", netErr != nil && netErr.Temporary()).
			With("Is Timeout", netErr != nil && netErr.Timeout()).
			Wrapf(err, "failed to write UDP packet")

		if errors.As(err, &netErr) && !netErr.Temporary() {
			ue.Dialer.ReportUnavailable(networkType, err)
			// if !dialOption.OutboundIndex.IsReserved() {
			return err
			// }
		}
		c.log.Debugf("%+v", err)

		// if c.log.IsLevelEnabled(logrus.DebugLevel) {
		// 	c.log.WithFields(logrus.Fields{
		// 		"to":      realDst.String(),
		// 		"domain":  domain,
		// 		"pid":     routingResult.Pid,
		// 		"ifindex": routingResult.Ifindex,
		// 		"dscp":    routingResult.Dscp,
		// 		"pname":   ProcessName2String(routingResult.Pname[:]),
		// 		"mac":     Mac2String(routingResult.Mac[:]),
		// 		"from":    realSrc.String(),
		// 		"network": networkType.StringWithoutDns(),
		// 		"err":     err.Error(),
		// 	}).Debugln("Failed to write UDP packet request. Try to remove old UDP endpoint and retry.")
		// }
	}

	// // Print log.
	// // Only print routing for new connection to avoid the log exploded (Quic and BT).
	// if (isNew && c.log.IsLevelEnabled(logrus.InfoLevel)) || c.log.IsLevelEnabled(logrus.DebugLevel) {
	// 	fields := logrus.Fields{
	// 		"network":  networkType.StringWithoutDns(),
	// 		"outbound": ue.Outbound.Name,
	// 		"policy":   ue.Outbound.GetSelectionPolicy(),
	// 		"dialer":   ue.Dialer.Property().Name,
	// 		"sniffed":  domain,
	// 		"ip":       RefineAddrPortToShow(realDst),
	// 		"pid":      routingResult.Pid,
	// 		"ifindex":  routingResult.Ifindex,
	// 		"dscp":     routingResult.Dscp,
	// 		"pname":    ProcessName2String(routingResult.Pname[:]),
	// 		"mac":      Mac2String(routingResult.Mac[:]),
	// 	}
	// 	logger := c.log.WithFields(fields).Infof
	// 	if !isNew && c.log.IsLevelEnabled(logrus.DebugLevel) {
	// 		logger = c.log.WithFields(fields).Debugf
	// 	}
	// 	logger("[%v] %v <-> %v", strings.ToUpper(networkType.String()), RefineSourceToShow(realSrc, realDst.Addr()), dialTarget)
	// }
	return nil
}
