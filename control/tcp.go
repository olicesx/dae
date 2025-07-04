/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func (c *ControlPlane) handleConn(lConn net.Conn) error {
	defer lConn.Close()

	// Sniff target domain.
	sniffer := sniffing.NewConnSniffer(lConn, c.sniffingTimeout)
	// ConnSniffer should be used later, so we cannot close it now.
	defer sniffer.Close()
	domain, err := sniffer.SniffTcp()
	if err != nil && !sniffing.IsSniffingError(err) {
		// We ignore lConn errors or temporary network errors
		var netErr net.Error
		if !errors.As(err, &netErr) {
			return oops.Wrapf(err, "Sniff Failed")
		}
		c.log.Debugf("Sniff Failed: %+v", err)
		return nil
	}

	// Get tuples and outbound.
	src := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dst := lConn.LocalAddr().(*net.TCPAddr).AddrPort()
	routingResult, err := c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if err != nil {
		return oops.Wrapf(err, "failed to retrieve target info %v", dst.String())
	}
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)

	// Route
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionFromAddr(dst.Addr()),
		IsDns:     false,
	}
	dialOption, err := c.RouteDialOption(&RouteParam{
		routingResult: routingResult,
		networkType:   networkType,
		Domain:        domain,
		Src:           src,
		Dest:          dst,
	})
	if err != nil {
		return err
	}

	if c.log.IsLevelEnabled(logrus.InfoLevel) {
		c.log.WithFields(logrus.Fields{
			"network":  networkType.String(),
			"outbound": dialOption.Outbound.Name,
			"policy":   dialOption.Outbound.GetSelectionPolicy(),
			"dialer":   dialOption.Dialer.Property().Name,
			"sniffed":  domain,
			"ip":       RefineAddrPortToShow(dst),
			"pid":      routingResult.Pid,
			"ifindex":  routingResult.Ifindex,
			"dscp":     routingResult.Dscp,
			"pname":    ProcessName2String(routingResult.Pname[:]),
			"mac":      Mac2String(routingResult.Mac[:]),
		}).Infof("[%v] %v <-> %v", strings.ToUpper(networkType.String()), RefineSourceToShow(src, dst.Addr()), dialOption.DialTarget)
	}

	// Dial
	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	rConn, err := dialOption.Dialer.DialContext(ctx, common.MagicNetwork("tcp", dialOption.Mark), dialOption.DialTarget)
	if err != nil {
		var netErr net.Error
		err = oops.
			In("DialContext").
			With("Is NetError", errors.As(err, &netErr)).
			With("Is Temporary", netErr != nil && netErr.Temporary()).
			With("Is Timeout", netErr != nil && netErr.Timeout()).
			With("Outbound", dialOption.Outbound.Name).
			With("src", src.String()).
			With("dst", dst.String()).
			With("domain", domain).
			With("routingResult", routingResult).
			Wrapf(err, "failed to DialContext")
		// TODO: UDP 是不是也有Direct Outbound出问题的情况?
		// TODO: Control Plane Routing?
		// TODO: 哪些错误说明节点不工作或GFW在工作?
		// TCP: Connection Reset / Connection Refused
		if errors.As(err, &netErr) && !netErr.Temporary() {
			dialOption.Dialer.ReportUnavailable(networkType, err)
			if !dialOption.OutboundIndex.IsReserved() {
				return err
			}
		}
		c.log.Debugf("%+v", err)
		return nil
	}

	// Relay
	defer rConn.Close()
	if err := RelayTCP(sniffer, rConn); err != nil {
		var netErr net.Error
		err = oops.
			In("RelayTCP").
			With("Is NetError", errors.As(err, &netErr)).
			With("Is Temporary", netErr != nil && netErr.Temporary()).
			With("Is Timeout", netErr != nil && netErr.Timeout()).
			With("Outbound", dialOption.Outbound.Name).
			With("src", src.String()).
			With("dst", dst.String()).
			With("domain", domain).
			With("routingResult", routingResult).
			Wrapf(err, "failed to RelayTCP")
		if errors.As(err, &netErr) && !netErr.Temporary() && dialOption.Dialer.MustGetAlive(networkType) {
			dialOption.Dialer.ReportUnavailable(networkType, err)
			if !dialOption.OutboundIndex.IsReserved() {
				return err
			}
		}
		c.log.Debugf("%+v", err)
	}
	// case strings.HasSuffix(err.Error(), "write: broken pipe"),
	// 	strings.HasSuffix(err.Error(), "i/o timeout"),
	// 	strings.HasPrefix(err.Error(), "EOF"),
	// 	strings.HasSuffix(err.Error(), "connection reset by peer"),
	// 	strings.HasSuffix(err.Error(), "canceled by local with error code 0"),
	// 	strings.HasSuffix(err.Error(), "canceled by remote with error code 0"):
	return nil
}

type RouteParam struct {
	routingResult *bpfRoutingResult
	networkType   *dialer.NetworkType
	Domain        string
	Src           netip.AddrPort
	Dest          netip.AddrPort
}

type DialOption struct {
	DialTarget    string
	Dialer        *dialer.Dialer
	Outbound      *outbound.DialerGroup
	OutboundIndex consts.OutboundIndex
	Mark          uint32
}

func (c *ControlPlane) RouteDialOption(p *RouteParam) (dialOption *DialOption, err error) {
	// TODO: Why not directly transfer routingResult
	outboundIndex := consts.OutboundIndex(p.routingResult.Outbound)
	mark := p.routingResult.Mark

	dialTarget, shouldReroute, dialIp := c.ChooseDialTarget(outboundIndex, p.Dest, p.Domain)
	if shouldReroute {
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneRouting:
		if outboundIndex, mark, _, err = c.Route(p.Src, p.Dest, p.Domain, p.networkType.L4Proto.ToL4ProtoType(), p.routingResult); err != nil {
			oops.Wrap(err)
			return
		}
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("outbound: %v => <Control Plane Routing>",
				outboundIndex.String(),
			)
		}
		// Reset dialTarget.
		dialTarget, _, dialIp = c.ChooseDialTarget(outboundIndex, p.Dest, p.Domain)
	default:
	}
	if mark == 0 {
		mark = c.soMarkFromDae
	}
	// TODO: Set-up ip to domain mapping and show domain if possible.
	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			err = oops.Errorf("traffic was dropped due to no-load configuration")
			return
		}
		err = oops.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
		return
	}
	outbound := c.outbounds[outboundIndex]
	dialer, _, err := outbound.SelectFallbackIpVersion(p.networkType, dialIp)
	if err != nil {
		dialer, _, err = c.outbounds[c.noConnectivityOutbound].Select(p.networkType)
		if err != nil {
			return nil, oops.Wrap(err)
		}
		if c.log.IsLevelEnabled(logrus.InfoLevel) {
			c.log.WithFields(logrus.Fields{
				"network":          p.networkType.String(),
				"originalOutbound": outbound.Name,
				"policy":           outbound.GetSelectionPolicy(),
				"fallbackDialer":   dialer.Property().Name,
				"sniffed":          p.Domain,
				"ip":               RefineAddrPortToShow(p.Dest),
				"pid":              p.routingResult.Pid,
				"ifindex":          p.routingResult.Ifindex,
				"dscp":             p.routingResult.Dscp,
				"pname":            ProcessName2String(p.routingResult.Pname[:]),
				"mac":              Mac2String(p.routingResult.Mac[:]),
			}).Infof("[%v] %v <-(fallback)-> %v", strings.ToUpper(p.networkType.String()), RefineSourceToShow(p.Src, p.Dest.Addr()), dialTarget)
		}
		// err = oops.Errorf("failed to select dialer from group %v (%v): %w", outbound.Name, p.networkType.String(), err)
	}
	return &DialOption{
		DialTarget:    dialTarget,
		Dialer:        dialer,
		Outbound:      outbound,
		OutboundIndex: outboundIndex,
		Mark:          mark,
	}, nil
}

type WriteCloser interface {
	CloseWrite() error
}

func relayDirection(dst, src netproxy.Conn) error {
	_, err := io.Copy(dst, src)

	// For Quic
	if writeCloser, ok := dst.(WriteCloser); ok {
		_ = writeCloser.CloseWrite()
	}

	if err != nil {
		dst.SetWriteDeadline(time.Now())
	}

	return oops.Wrap(err)
}

// Error1 is the error from lConn to rConn
// Error2 is the error from rConn to lConn
// TODO: 引入 ctx, 在 dialer 不可用时取消 relay
// 进一步的, 给 lConn 发送 rst
func RelayTCP(lConn, rConn netproxy.Conn) error {
	errCh := make(chan error, 1)

	var netErr net.Error

	// Start relay goroutine from rConn to lConn
	go func() {
		err := relayDirection(lConn, rConn)
		errCh <- err
	}()
	// Do relay from lConn to rConn
	err := relayDirection(rConn, lConn)
	err2 := <-errCh

	// We ignore lConn errors or temporary network errors
	// TODO: Why get EOF as an error?
	if err != nil { // l -> r
		switch {
		case
			strings.HasSuffix(err.Error(), "canceled by remote with error code 0"), // rConn closed
			strings.Contains(err.Error(), "read:"):                                 // lConn Read
			err = nil
		default:
			err = oops.
				Hint("lConn -> rConn Relay Error").
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				Wrap(err)
		}

	}
	if err2 != nil { // r -> l
		switch {
		case strings.Contains(err2.Error(), "write:"): // lConn Write
			err2 = nil
		default:
			err2 = oops.
				Hint("rConn -> lConn Relay Error").
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				Wrap(err2)
		}
	}

	return oops.Join(err, err2)
}
