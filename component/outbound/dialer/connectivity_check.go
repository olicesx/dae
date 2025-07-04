/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/direct"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

const Timeout = 10 * time.Second

type NetworkType struct {
	L4Proto   consts.L4ProtoStr
	IpVersion consts.IpVersionStr
	IsDns     bool
}

func (t *NetworkType) String() string {
	if t.IsDns {
		return t.StringWithoutDns() + "(DNS)"
	} else {
		return t.StringWithoutDns()
	}
}

func (t *NetworkType) StringWithoutDns() string {
	return string(t.L4Proto) + string(t.IpVersion)
}

type collection struct {
	// AliveDialerSetSet uses reference counting.
	AliveDialerSetSet AliveDialerSetSet
	Latencies10       *LatenciesN
	MovingAverage     time.Duration
	Alive             bool
	// 用于追踪连续错误
	ErrorCount    int
	LastErrorTime time.Time
}

func newCollection() *collection {
	return &collection{
		AliveDialerSetSet: make(AliveDialerSetSet),
		Latencies10:       NewLatenciesN(10),
		Alive:             false,
	}
}

// networkTypeToIndex 将网络类型映射到集合索引
func networkTypeToIndex(typ *NetworkType) int {
	if typ.IsDns {
		switch typ.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return 0
			case consts.IpVersionStr_6:
				return 1
			}
		case consts.L4ProtoStr_UDP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return 2
			case consts.IpVersionStr_6:
				return 3
			}
		}
	} else {
		switch typ.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return 4
			case consts.IpVersionStr_6:
				return 5
			}
		case consts.L4ProtoStr_UDP:
			// UDP share the DNS check result.
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return 2
			case consts.IpVersionStr_6:
				return 3
			}
		}
	}
	panic("invalid network type")
}

func (d *Dialer) mustGetCollection(typ *NetworkType) *collection {
	index := networkTypeToIndex(typ)
	return d.collections[index]
}

func (d *Dialer) MustGetAlive(typ *NetworkType) bool {
	return d.mustGetCollection(typ).Alive
}

func parseIp46FromList(ip []string) *netutils.Ip46 {
	ip46 := new(netutils.Ip46)
	for _, ip := range ip {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if addr.Is4() || addr.Is4In6() {
			ip46.Ip4 = addr
		} else if addr.Is6() {
			ip46.Ip6 = addr
		}
	}
	return ip46
}

type TcpCheckOption struct {
	Url *netutils.URL
	*netutils.Ip46
	Method string
}

func ParseTcpCheckOption(ctx context.Context, rawURL []string, method string, resolverNetwork string) (opt *TcpCheckOption, err error) {
	if method == "" {
		method = http.MethodGet
	}
	systemDns, err := netutils.SystemDns()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = netutils.TryUpdateSystemDnsElapse(time.Second)
		}
	}()

	if len(rawURL) == 0 {
		return nil, fmt.Errorf("ParseTcpCheckOption: bad format: empty")
	}
	u, err := url.Parse(rawURL[0])
	if err != nil {
		return nil, err
	}
	var ip46 *netutils.Ip46
	if len(rawURL) > 1 {
		ip46 = parseIp46FromList(rawURL[1:])
	} else {
		ip46, _, _ = netutils.ResolveIp46(ctx, direct.SymmetricDirect, systemDns, u.Hostname(), resolverNetwork, false)
		if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
			return nil, fmt.Errorf("ResolveIp46: no valid ip for %v", u.Hostname())
		}
	}
	return &TcpCheckOption{
		Url:    &netutils.URL{URL: u},
		Ip46:   ip46,
		Method: method,
	}, nil
}

type CheckDnsOption struct {
	DnsHost string
	DnsPort uint16
	*netutils.Ip46
}

func ParseCheckDnsOption(ctx context.Context, dnsHostPort []string, resolverNetwork string) (opt *CheckDnsOption, err error) {
	systemDns, err := netutils.SystemDns()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = netutils.TryUpdateSystemDnsElapse(time.Second)
		}
	}()

	if len(dnsHostPort) == 0 {
		return nil, fmt.Errorf("ParseCheckDnsOption: bad format: empty")
	}

	host, _port, err := net.SplitHostPort(dnsHostPort[0])
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port: %v", err)
	}
	var ip46 *netutils.Ip46
	if len(dnsHostPort) > 1 {
		ip46 = parseIp46FromList(dnsHostPort[1:])
	} else {
		ip46, _, _ = netutils.ResolveIp46(ctx, direct.SymmetricDirect, systemDns, host, resolverNetwork, false)
		if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
			return nil, fmt.Errorf("ResolveIp46: no valid ip for %v", host)
		}
	}
	return &CheckDnsOption{
		DnsHost: host,
		DnsPort: uint16(port),
		Ip46:    ip46,
	}, nil
}

type TcpCheckOptionRaw struct {
	opt             *TcpCheckOption
	mu              sync.Mutex
	Raw             []string
	ResolverNetwork string
	Method          string
	Somark          uint32
}

func (c *TcpCheckOptionRaw) Option() (opt *TcpCheckOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		ctx, cancel := context.WithTimeout(context.TODO(), Timeout)
		defer cancel()
		tcpCheckOption, err := ParseTcpCheckOption(ctx, c.Raw, c.Method, c.ResolverNetwork)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = tcpCheckOption
	}
	return c.opt, nil
}

type CheckDnsOptionRaw struct {
	opt             *CheckDnsOption
	mu              sync.Mutex
	Raw             []string
	ResolverNetwork string
	Somark          uint32
}

func (c *CheckDnsOptionRaw) Option() (opt *CheckDnsOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		ctx, cancel := context.WithTimeout(context.TODO(), Timeout)
		defer cancel()
		udpCheckOption, err := ParseCheckDnsOption(ctx, c.Raw, c.ResolverNetwork)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = udpCheckOption
	}
	return c.opt, nil
}

type CheckOption struct {
	networkType *NetworkType
	CheckFunc   func(ctx context.Context, typ *NetworkType) (ok bool, err error)
}

// createTcpCheckFunc 创建TCP检查函数
func (d *Dialer) createTcpCheckFunc(ipVersion consts.IpVersionStr, network string) func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
	return func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
		opt, err := d.TcpCheckOptionRaw.Option()
		if err != nil {
			return false, err
		}

		var ip netip.Addr
		switch ipVersion {
		case consts.IpVersionStr_4:
			ip = opt.Ip4
		case consts.IpVersionStr_6:
			ip = opt.Ip6
		}

		if !ip.IsValid() {
			d.Log.WithFields(logrus.Fields{
				"link":    d.TcpCheckOptionRaw.Raw,
				"dialer":  d.property.Name,
				"network": typ.String(),
			}).Debugln("Skip check due to no DNS record.")
			return false, nil
		}

		return d.HttpCheck(ctx, opt.Url, ip, opt.Method, network)
	}
}

// createDnsCheckFunc 创建DNS检查函数
func (d *Dialer) createDnsCheckFunc(ipVersion consts.IpVersionStr, network string) func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
	return func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
		opt, err := d.CheckDnsOptionRaw.Option()
		if err != nil {
			return false, err
		}

		var ip netip.Addr
		switch ipVersion {
		case consts.IpVersionStr_4:
			ip = opt.Ip4
		case consts.IpVersionStr_6:
			ip = opt.Ip6
		}

		if !ip.IsValid() {
			d.Log.WithFields(logrus.Fields{
				"link":    d.CheckDnsOptionRaw.Raw,
				"dialer":  d.property.Name,
				"network": typ.String(),
			}).Debugln("Skip check due to no DNS record.")
			return false, nil
		}

		return d.DnsCheck(ctx, netip.AddrPortFrom(ip, opt.DnsPort), network)
	}
}

// createCheckOptions 创建所有检查选项
func (d *Dialer) createCheckOptions() []*CheckOption {
	tcpNetwork := netproxy.MagicNetwork{
		Network: "tcp",
		Mark:    d.TcpCheckOptionRaw.Somark,
	}.Encode()
	udpNetwork := netproxy.MagicNetwork{
		Network: "udp",
		Mark:    d.CheckDnsOptionRaw.Somark,
	}.Encode()

	return []*CheckOption{
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_4,
				IsDns:     false,
			},
			CheckFunc: d.createTcpCheckFunc(consts.IpVersionStr_4, tcpNetwork),
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
				IsDns:     false,
			},
			CheckFunc: d.createTcpCheckFunc(consts.IpVersionStr_6, tcpNetwork),
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionStr_4,
				IsDns:     true,
			},
			CheckFunc: d.createDnsCheckFunc(consts.IpVersionStr_4, udpNetwork),
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionStr_6,
				IsDns:     true,
			},
			CheckFunc: d.createDnsCheckFunc(consts.IpVersionStr_6, udpNetwork),
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_4,
				IsDns:     true,
			},
			CheckFunc: d.createDnsCheckFunc(consts.IpVersionStr_4, tcpNetwork),
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
				IsDns:     true,
			},
			CheckFunc: d.createDnsCheckFunc(consts.IpVersionStr_6, tcpNetwork),
		},
	}
}

// collections:
// 0: TCP4 DNS
// 1: TCP6 DNS
// 2: UDP4(DNS/N)
// 3: UDP6(DNS/N)
// 4: TCP4
// 5: TCP6

func (d *Dialer) ActivateCheck() {
	d.tickerMu.Lock()
	defer d.tickerMu.Unlock()
	if d.InstanceOption.DisableCheck || d.checkActivated {
		return
	}
	d.checkActivated = true
	go d.aliveBackground()
}

func (d *Dialer) aliveBackground() {
	cycle := d.CheckInterval
	CheckOpts := d.createCheckOptions()

	ctx, cancel := context.WithCancel(d.ctx)
	defer cancel()

	// 启动定时器
	d.startCheckTicker(ctx, cycle)

	// 检查是否有使用的网络类型
	if d.shouldSkipCheck(CheckOpts) {
		d.Log.WithField("dialer", d.Property().Name).
			WithField("p", unsafe.Pointer(d)).
			Traceln("cleaned up due to unused")
		return
	}

	// 执行检查循环
	d.runCheckLoop(CheckOpts)
}

// startCheckTicker 启动检查定时器
func (d *Dialer) startCheckTicker(ctx context.Context, cycle time.Duration) {
	go func() {
		// Sleep to avoid avalanche.
		time.Sleep(time.Duration(fastrand.Int63n(int64(cycle))))
		d.tickerMu.Lock()
		d.ticker = time.NewTicker(cycle)
		d.tickerMu.Unlock()
		for t := range d.ticker.C {
			select {
			case <-ctx.Done():
				return
			default:
				d.checkCh <- t
			}
		}
	}()
}

// TODO: NeedAliveState?
// shouldSkipCheck 判断是否应该跳过检查
func (d *Dialer) shouldSkipCheck(checkOpts []*CheckOption) bool {
	unused := 0
	for _, opt := range checkOpts {
		if len(d.mustGetCollection(opt.networkType).AliveDialerSetSet) == 0 {
			unused++
		}
	}
	return unused == len(checkOpts)
}

// runCheckLoop 运行检查循环
func (d *Dialer) runCheckLoop(checkOpts []*CheckOption) {
	var wg sync.WaitGroup
	for range d.checkCh {
		for _, opt := range checkOpts {
			// No need to test if there is no dialer selection policy using its latency.
			if len(d.mustGetCollection(opt.networkType).AliveDialerSetSet) == 0 {
				continue
			}

			wg.Add(1)
			go func(opt *CheckOption) {
				defer wg.Done()
				_, _ = d.Check(opt)
			}(opt)
		}
		// Wait to block the loop.
		wg.Wait()
	}
}

// NotifyCheck will succeed only when CheckEnabled is true.
func (d *Dialer) NotifyCheck() {
	select {
	case <-d.ctx.Done():
		return
	default:
	}

	select {
	// If fail to push elem to chan, the check is in process.
	case d.checkCh <- time.Now():
	default:
	}
}

func (d *Dialer) MustGetLatencies10(typ *NetworkType) *LatenciesN {
	return d.mustGetCollection(typ).Latencies10
}

// RegisterAliveDialerSet is thread-safe.
func (d *Dialer) RegisterAliveDialerSet(a *AliveDialerSet) {
	if a == nil {
		return
	}
	d.collectionFineMu.Lock()
	d.mustGetCollection(a.networkType).AliveDialerSetSet[a]++
	d.collectionFineMu.Unlock()
}

// UnregisterAliveDialerSet is thread-safe.
func (d *Dialer) UnregisterAliveDialerSet(a *AliveDialerSet) {
	if a == nil {
		return
	}
	d.collectionFineMu.Lock()
	defer d.collectionFineMu.Unlock()
	setSet := d.mustGetCollection(a.networkType).AliveDialerSetSet
	setSet[a]--
	if setSet[a] <= 0 {
		delete(setSet, a)
	}
}

func (d *Dialer) makeUnavailable(
	collection *collection,
) {
	collection.Latencies10.AppendLatency(Timeout)
	collection.MovingAverage = (collection.MovingAverage + Timeout) / 2
	collection.Alive = false
}

func (d *Dialer) informDialerGroupUpdate(collection *collection) {
	// Inform DialerGroups to update state.
	// We use lock because AliveDialerSetSet is a reference of that in collection.
	d.collectionFineMu.Lock()
	for a := range collection.AliveDialerSetSet {
		a.NotifyLatencyChange(d, collection.Alive)
	}
	d.collectionFineMu.Unlock()
}

// Dialer -> Collection(networkType) -> AliveDialerSet -> NotifyLatencyChange -> NotifyKernel
// TODO: 在 Collection 完成测速之前, AliveDialerSet 应该不提供 dialer, TCP/UDP应该忽略错误
// 进一步的, 此时我们应该让kernel不路由流量
func (d *Dialer) ReportUnavailable(typ *NetworkType, err error) {
	collection := d.mustGetCollection(typ)

	if collection == nil {
		return
	}

	fmt.Println("ReportUnavailable", d.property.Name, typ.String())

	if time.Since(collection.LastErrorTime) > 15*time.Second {
		collection.ErrorCount = 0
	}

	collection.ErrorCount++
	collection.LastErrorTime = time.Now()

	d.Log.WithFields(logrus.Fields{
		"network":     typ.String(),
		"node":        d.property.Name,
		"err":         err.Error(),
		"error_count": collection.ErrorCount,
	}).Warnf("Connection Failed (Count: %d/3)", collection.ErrorCount)

	if collection.ErrorCount >= 3 {
		d.makeUnavailable(collection)
		d.informDialerGroupUpdate(collection)
	}
}

// TODO: Maybe we need multiple check to get fault
func (d *Dialer) Check(opts *CheckOption) (ok bool, err error) {
	ctx, cancel := context.WithTimeout(context.TODO(), Timeout)
	defer cancel()
	start := time.Now()
	// Calc latency.
	collection := d.mustGetCollection(opts.networkType)
	if ok, err = opts.CheckFunc(ctx, opts.networkType); ok && err == nil {
		// No error.
		latency := time.Since(start)
		collection.Latencies10.AppendLatency(latency)
		avg, _ := collection.Latencies10.AvgLatency()
		collection.MovingAverage = (collection.MovingAverage + latency) / 2

		if !collection.Alive {
			d.Log.WithFields(logrus.Fields{
				"network": opts.networkType.String(),
				"node":    d.property.Name,
				"last":    latency.Truncate(time.Millisecond).String(),
				"avg_10":  avg.Truncate(time.Millisecond),
				"mov_avg": collection.MovingAverage.Truncate(time.Millisecond),
			}).Infoln("Connectivity Check")
		} else {
			d.Log.WithFields(logrus.Fields{
				"network": opts.networkType.String(),
				"node":    d.property.Name,
				"last":    latency.Truncate(time.Millisecond).String(),
				"avg_10":  avg.Truncate(time.Millisecond),
				"mov_avg": collection.MovingAverage.Truncate(time.Millisecond),
			}).Debugln("Connectivity Check")
		}
		collection.Alive = true

		// Reset error count.
		if time.Since(collection.LastErrorTime) > 30*time.Second {
			collection.ErrorCount = 0
		}
	} else {
		// Append timeout if there is any error or unexpected status code.
		if strings.HasSuffix(err.Error(), "network is unreachable") {
			err = oops.Errorf("network is unreachable")
		} else if strings.HasSuffix(err.Error(), "no suitable address found") ||
			strings.HasSuffix(err.Error(), "non-IPv4 address") {
			err = oops.Errorf("IPv%v is not supported", opts.networkType.IpVersion)
		}
		if collection.Alive {
			d.Log.WithFields(logrus.Fields{
				"network": opts.networkType.String(),
				"node":    d.property.Name,
			}).Warnln(oops.Wrapf(err, "Connectivity Check Failed"))
		} else {
			d.Log.WithFields(logrus.Fields{
				"network": opts.networkType.String(),
				"node":    d.property.Name,
			}).Infoln(oops.Wrapf(err, "Connectivity Check Failed"))
		}
		d.makeUnavailable(collection)
	}
	d.informDialerGroupUpdate(collection)
	return ok, err
}

func (d *Dialer) HttpCheck(ctx context.Context, u *netutils.URL, ip netip.Addr, method string, network string) (ok bool, err error) {
	// HTTP(S) check.
	if method == "" {
		method = http.MethodGet
	}
	cli := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				// Force to dial "ip".
				conn, err := d.Dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), u.Port()))
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr); netErr.Timeout() {
			err = fmt.Errorf("timeout")
		}
		return false, err
	}
	defer resp.Body.Close()
	// Judge the status code.
	if page := path.Base(req.URL.Path); strings.HasPrefix(page, "generate_") {
		if strconv.Itoa(resp.StatusCode) != strings.TrimPrefix(page, "generate_") {
			b, _ := io.ReadAll(resp.Body)
			buf := pool.GetBuffer()
			defer pool.PutBuffer(buf)
			_ = resp.Request.Write(buf)
			d.Log.Debugln(buf.String(), "Resp: ", string(b))
			return false, fmt.Errorf("unexpected status code: %v", resp.StatusCode)
		}
		return true, nil
	} else {
		if resp.StatusCode < 200 || resp.StatusCode >= 500 {
			return false, fmt.Errorf("bad status code: %v", resp.StatusCode)
		}
		return true, nil
	}
}

func (d *Dialer) DnsCheck(ctx context.Context, dns netip.AddrPort, network string) (ok bool, err error) {
	addrs, err := netutils.ResolveNetip(ctx, d, dns, consts.UdpCheckLookupHost, dnsmessage.TypeA, network)
	if err != nil {
		return false, err
	}
	if len(addrs) == 0 {
		return false, fmt.Errorf("bad DNS response: no record")
	}
	return true, nil
}
