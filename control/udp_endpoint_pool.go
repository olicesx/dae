/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

type UdpHandler func(data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn netproxy.PacketConn
	// mu protects deadlineTimer
	mu            sync.Mutex
	deadlineTimer *time.Timer
	handler       UdpHandler
	NatTimeout    time.Duration

	Dialer *dialer.Dialer
}

// TODO: 错误处理
func (ue *UdpEndpoint) run() {
	buf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(buf)
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			// var netErr net.Error
			// err = oops.
			// 	In("UdpEndpoint Relay").
			// 	Hint("rConn -> lConn Relay Error").
			// 	With("Is NetError", errors.As(err, &netErr)).
			// 	With("Is Temporary", netErr != nil && netErr.Temporary()).
			// 	With("Is Timeout", netErr != nil && netErr.Timeout()).
			// 	With("Dialer", ue.Dialer.Property().Name).
			// 	Wrapf(err, "failed to ReadFrom")
			break
		}
		ue.mu.Lock()
		ue.deadlineTimer.Reset(ue.NatTimeout)
		ue.mu.Unlock()
		if err = ue.handler(buf[:n], from); err != nil {
			break
		}
	}
	ue.mu.Lock()
	ue.deadlineTimer.Stop()
	ue.mu.Unlock()
}

func (ue *UdpEndpoint) WriteTo(b []byte, addr string) (int, error) {
	return ue.conn.WriteTo(b, addr)
}

func (ue *UdpEndpoint) Close() error {
	ue.mu.Lock()
	if ue.deadlineTimer != nil {
		ue.deadlineTimer.Stop()
	}
	ue.mu.Unlock()
	return ue.conn.Close()
}

// UdpEndpointPool is a full-cone udp conn pool
type UdpEndpointPool struct {
	pool                 sync.Map
	UdpEndpointKeyLocker common.KeyLocker[netip.AddrPort]
}
type UdpEndpointOptions struct {
	PacketConn netproxy.PacketConn
	Handler    UdpHandler
	NatTimeout time.Duration

	Dialer *dialer.Dialer
}

var DefaultUdpEndpointPool = UdpEndpointPool{}

func (p *UdpEndpointPool) Remove(lAddr netip.AddrPort) (err error) {
	if ue, ok := p.pool.LoadAndDelete(lAddr); ok {
		ue.(*UdpEndpoint).Close()
	}
	return nil
}

func (p *UdpEndpointPool) Get(lAddr netip.AddrPort) (udpEndpoint *UdpEndpoint, ok bool) {
	_ue, ok := p.pool.Load(lAddr)
	if !ok {
		return nil, ok
	}
	ue := _ue.(*UdpEndpoint)
	// Postpone the deadline.
	ue.mu.Lock()
	ue.deadlineTimer.Reset(ue.NatTimeout)
	ue.mu.Unlock()
	return _ue.(*UdpEndpoint), ok
}

func (p *UdpEndpointPool) Create(lAddr netip.AddrPort, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint, err error) {
	ue := &UdpEndpoint{
		conn:       createOption.PacketConn,
		handler:    createOption.Handler,
		NatTimeout: createOption.NatTimeout,
		Dialer:     createOption.Dialer,
	}
	ue.deadlineTimer = time.AfterFunc(createOption.NatTimeout, func() {
		p.Remove(lAddr)
	})
	p.pool.Store(lAddr, ue)
	// Receive UDP messages.
	go func() {
		ue.run()
		p.Remove(lAddr)
	}()
	return ue, nil
}

// func (p *UdpEndpointPool) GetOrCreate(lAddr netip.AddrPort, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint, reportUnavailable func(err error), isNew bool, err error) {
// 	_ue, ok := p.pool.Load(lAddr)
// begin:
// 	if !ok {
// 		l := p.udpEndpointKeyLocker.Lock(lAddr)
// 		defer p.udpEndpointKeyLocker.Unlock(lAddr, l)

// 		_ue, ok = p.pool.Load(lAddr)
// 		if ok {
// 			goto begin
// 		}
// 		// Create an UdpEndpoint.
// 		if createOption == nil {
// 			createOption = &UdpEndpointOptions{}
// 		}
// 		if createOption.NatTimeout == 0 {
// 			createOption.NatTimeout = DefaultNatTimeoutUDP
// 		}
// 		if createOption.Handler == nil {
// 			return nil, nil, true, oops.Errorf("createOption.Handler cannot be nil")
// 		}

// 		dialOption, err := createOption.GetDialOption()
// 		if err != nil {
// 			return nil, nil, false, err
// 		}

// 		reportUnavailable = func(err error) {
// 			dialOption.Dialer.ReportUnavailable(dialOption.NetworkType, err)
// 		}

// 		ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
// 		defer cancel()
// 		udpConn, err := dialOption.Dialer.DialContext(ctx, dialOption.Network, dialOption.Target)
// 		if err != nil {
// 			return nil, reportUnavailable, true, oops.
// 				WithContext(ctx).
// 				With("Target", dialOption.Target).
// 				With("Dialer", dialOption.Dialer.Property().Name).
// 				With("Outbound", dialOption.Outbound.Name).
// 				With("Network", dialOption.Network).With("Target", dialOption.Target).
// 				Wrapf(err, "Failed to DialContext")
// 		}
// 		if _, ok = udpConn.(netproxy.PacketConn); !ok {
// 			return nil, reportUnavailable, true, oops.Errorf("protocol does not support udp")
// 		}
// 		ue := &UdpEndpoint{
// 			conn:          udpConn.(netproxy.PacketConn),
// 			deadlineTimer: nil,
// 			handler:       createOption.Handler,
// 			NatTimeout:    createOption.NatTimeout,
// 			Dialer:        dialOption.Dialer,
// 			Outbound:      dialOption.Outbound,
// 			SniffedDomain: dialOption.SniffedDomain,
// 			DialTarget:    dialOption.Target,
// 		}
// 		ue.deadlineTimer = time.AfterFunc(createOption.NatTimeout, func() {
// 			if _ue, ok := p.pool.LoadAndDelete(lAddr); ok {
// 				if _ue == ue {
// 					ue.Close()
// 				} else {
// 					// FIXME: ?
// 				}
// 			}
// 		})
// 		_ue = ue
// 		p.pool.Store(lAddr, ue)
// 		// Receive UDP messages.
// 		go ue.start()
// 		isNew = true
// 	} else {
// 		ue := _ue.(*UdpEndpoint)
// 		// Postpone the deadline.
// 		ue.mu.Lock()
// 		ue.deadlineTimer.Reset(ue.NatTimeout)
// 		ue.mu.Unlock()
// 	}
// 	return _ue.(*UdpEndpoint), reportUnavailable, isNew, nil
// }
