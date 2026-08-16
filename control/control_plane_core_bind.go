/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func getIfParamsFromLink(link netlink.Link) (ifParams bpfIfParams, err error) {
	// Get link offload features.
	et, err := ethtool.NewEthtool()
	if err != nil {
		// ethtool may be unavailable in restricted environments (e.g. containers
		// without CAP_NET_ADMIN). Silently degrade to defaults.
		return bpfIfParams{}, nil
	}
	defer et.Close()
	features, err := et.Features(link.Attrs().Name)
	if err != nil {
		// Virtual interfaces (TUN/TAP, WireGuard, etc.) or older kernels
		// may not support ETHTOOL_GFEATURES.  Silently degrade to defaults
		// (all offload flags = false) rather than blocking interface binding.
		return bpfIfParams{}, nil
	}
	if features["tx-checksum-ip-generic"] {
		ifParams.TxL4CksmIp4Offload = true
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["tx-checksum-ipv4"] {
		ifParams.TxL4CksmIp4Offload = true
	}
	if features["tx-checksum-ipv6"] {
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["rx-checksum"] {
		ifParams.RxCksmOffload = true
	}
	switch {
	case regexp.MustCompile(`^docker\d+$`).MatchString(link.Attrs().Name):
		ifParams.UseNonstandardOffloadAlgorithm = true
	default:
	}
	return ifParams, nil
}

func (c *controlPlaneCore) linkHdrLen(ifname string) (uint32, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return 0, err
	}
	var linkHdrLen uint32
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		linkHdrLen = consts.LinkHdrLen_None
	case "ether":
		linkHdrLen = consts.LinkHdrLen_Ethernet
	default:
		c.log.Warnf("Maybe unsupported link type %v, using default link header length", link.Attrs().EncapType)
		linkHdrLen = consts.LinkHdrLen_Ethernet
	}
	return linkHdrLen, nil
}

func buildClsactQdisc(link netlink.Link) *netlink.GenericQdisc {
	return &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
}

func (c *controlPlaneCore) addQdisc(link netlink.Link) error {
	qdisc := buildClsactQdisc(link)
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot add clsact qdisc: %w", err)
	}
	return nil
}

func (c *controlPlaneCore) delQdisc(link netlink.Link) error {
	qdisc := buildClsactQdisc(link)
	if err := netlink.QdiscDel(qdisc); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("cannot delete clsact qdisc: %w", err)
	} else if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		c.log.Debugf("delQdisc: clsact qdisc or link not found for %v (already gone)", link.Attrs().Name)
	}
	return nil
}

// bindLan automatically configures kernel parameters and bind to lan interface `ifname`.
// bindLan supports lazy-bind if interface `ifname` is not found.
// bindLan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindLan(ifname string, autoConfigKernelParameter bool) error {
	attach := func(link netlink.Link) error {
		if link.Attrs().Name == HostVethName {
			return nil
		}
		if !c.beginBpfHookAttach() {
			return nil
		}
		defer c.endBpfHookAttach()
		if autoConfigKernelParameter {
			SetSendRedirects(link.Attrs().Name, "0")
			SetForwarding(link.Attrs().Name, "1")
		}
		return c._bindLan(link.Attrs().Name)
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind LAN program to it.", link.Attrs().Name)
		if err := attach(link); err != nil {
			c.log.Errorf("bindLan: %v", err)
		}
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", link.Attrs().Name)
		if err := c.delQdisc(link); err != nil {
			c.log.Errorf("delQdisc: %v", err)
		}
	}
	if err := c.registerInterfacePattern(ifname, true, newlinkCallback, dellinkCallback); err != nil {
		return err
	}
	return c.attachMatchingInterfaces(ifname, attach)
}

func (c *controlPlaneCore) _bindLan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	bpf := c.bpf.Load()
	if bpf == nil {
		return nil
	}
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	c.log.Infof("Bind to LAN: %v", ifname)

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if err = CheckIpforward(ifname); err != nil {
		return err
	}
	if err = CheckSendRedirects(ifname); err != nil {
		return err
	}
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(link)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}
	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	// Insert filters.
	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be behind of WAN's
			Priority: 2,
		},
		Name:         consts.AppName + "_lan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = bpf.TproxyLanIngressL2.FD()
		filterIngress.Name += "_l2"
	} else {
		filterIngress.Fd = bpf.TproxyLanIngressL3.FD()
		filterIngress.Name += "_l3"
	}
	if err := deleteTCFiltersByHandle(link, filterIngress.Parent, filterIngress.Handle); err != nil {
		return fmt.Errorf("cannot remove existing LAN ingress filter: %w", err)
	}
	if !c.isReload {
		if err := deleteTCFiltersByHandle(link, filterIngress.Parent, filterIngress.Handle^1); err != nil {
			return fmt.Errorf("cannot remove flipped LAN ingress filter: %w", err)
		}
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	detachFunc := func() error {
		if err := deleteTCFiltersByHandle(link, filterIngress.Parent, filterIngress.Handle); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	}
	c.addManagedBpfHookCleanup(detachFunc)

	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be front of WAN's
			Priority: 1,
		},
		Name:         consts.AppName + "_lan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = bpf.TproxyLanEgressL2.FD()
		filterEgress.Name += "_l2"
	} else {
		filterEgress.Fd = bpf.TproxyLanEgressL3.FD()
		filterEgress.Name += "_l3"
	}
	if err := deleteTCFiltersByHandle(link, filterEgress.Parent, filterEgress.Handle); err != nil {
		return fmt.Errorf("cannot remove existing LAN egress filter: %w", err)
	}
	if !c.isReload {
		if err := deleteTCFiltersByHandle(link, filterEgress.Parent, filterEgress.Handle^1); err != nil {
			return fmt.Errorf("cannot remove flipped LAN egress filter: %w", err)
		}
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	egressDetachFunc := func() error {
		if err := deleteTCFiltersByHandle(link, filterEgress.Parent, filterEgress.Handle); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	}
	c.addManagedBpfHookCleanup(egressDetachFunc)

	return nil
}

func (c *controlPlaneCore) setupSkPidMonitor() error {
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	/// Set-up SrcPidMapper.
	/// Attach programs to support pname routing.
	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPathFunc()
	if err != nil {
		return err
	}
	// Bind cg programs
	type cgProg struct {
		Name   string
		Prog   *ebpf.Program
		Attach ebpf.AttachType
	}
	bpf := c.bpf.Load()
	cgProgs := []cgProg{
		{Prog: bpf.TproxyWanCgSockCreate, Attach: ebpf.AttachCGroupInetSockCreate},
		{Prog: bpf.TproxyWanCgSockRelease, Attach: ebpf.AttachCgroupInetSockRelease},
		{Prog: bpf.TproxyWanCgConnect4, Attach: ebpf.AttachCGroupInet4Connect},
		{Prog: bpf.TproxyWanCgConnect6, Attach: ebpf.AttachCGroupInet6Connect},
		{Prog: bpf.TproxyWanCgSendmsg4, Attach: ebpf.AttachCGroupUDP4Sendmsg},
		{Prog: bpf.TproxyWanCgSendmsg6, Attach: ebpf.AttachCGroupUDP6Sendmsg},
	}
	attachedLinks := make([]cgroupAttachment, 0, len(cgProgs))
	detachFuncs := make([]func() error, 0, len(cgProgs))
	for _, prog := range cgProgs {
		attached, err := attachCgroupFunc(ciliumLink.CgroupOptions{
			Path:    cgroupPath,
			Attach:  prog.Attach,
			Program: prog.Prog,
		})
		if err != nil {
			for i := len(attachedLinks) - 1; i >= 0; i-- {
				_ = attachedLinks[i].Close()
			}
			return fmt.Errorf("AttachCgroup: %v: %w", prog.Prog.String(), err)
		}
		attachedLinks = append(attachedLinks, attached)
		attachedLink := attached
		detachFunc := func() error {
			if err := attachedLink.Close(); err != nil {
				return fmt.Errorf("inet6Bind.Close(): %w", err)
			}
			return nil
		}
		detachFuncs = append(detachFuncs, detachFunc)
	}
	for _, detachFunc := range detachFuncs {
		c.addManagedBpfHookCleanup(detachFunc)
	}
	return nil
}

func (c *controlPlaneCore) setupTCPRelayOffload() error {
	// Idempotent: reload/rollback paths re-enter commitInterfaceBindings with
	// the same loaded program objects, and resetBpfHookDetachForReattach does
	// not close the links attached by a previous pass. Re-attaching the fentry
	// link while the first one is alive is rejected by the kernel with EBUSY
	// ("prog already linked", kernel/bpf/trampoline.c
	// __bpf_trampoline_link_prog), which surfaced as a spurious
	// "TCP relay eBPF offload disabled" on rollback.
	if c.tcpSockmapOffloadReady.Load() {
		return nil
	}
	if os.Getenv("DAE_DISABLE_TCP_RELAY_OFFLOAD") == "1" {
		c.log.Debug("TCP relay eBPF offload disabled by DAE_DISABLE_TCP_RELAY_OFFLOAD=1")
		return nil
	}

	// Opt-in only. The sockmap redirect was removed upstream (dae#912) after
	// CVE-2025-38165 ("bpf, sockmap: Fix panic when calling skb_linearize")
	// and because the psock ingress_skb queue is still not charged to socket
	// buffers/memcg (bpf-next 2025-04 series issue #4, unfixed), so a
	// slow-reading peer can grow kernel memory without bound. The user-space
	// session enforces tcpOffloadMaxPeerBacklog as a mitigation, but the
	// feature stays off unless explicitly enabled.
	if os.Getenv("DAE_ALLOW_TCP_SOCKMAP") != "1" {
		c.log.Debug("TCP relay eBPF offload disabled (opt-in via DAE_ALLOW_TCP_SOCKMAP=1)")
		return nil
	}

	bpf := c.bpf.Load()
	if bpf == nil || bpf.FastSock == nil || bpf.TcpOffloadRedirect == nil || bpf.TcpOffloadSent == nil || bpf.TcpOffloadPause == nil || bpf.TcpOffloadSentAccount == nil {
		return fmt.Errorf("fast_sock, tcp_offload_redirect, tcp_offload_pause, tcp_offload_sent or tcp_offload_sent_account unavailable")
	}

	switch {
	case c.kernelVersion == nil:
		return fmt.Errorf("kernel version unavailable")
	case consts.IsTcpSockmapPanicSafeKernel(*c.kernelVersion):
		c.log.Infof("Enabling TCP relay eBPF offload (kernel %v has the CVE-2025-38165 fix)", *c.kernelVersion)
	default:
		c.log.Warnf("Enabling TCP relay eBPF offload via DAE_ALLOW_TCP_SOCKMAP on kernel %v without a known CVE-2025-38165 fix; a message larger than ~100KB redirected between relay sockets can panic this kernel", *c.kernelVersion)
	}

	// The links target maps/programs inside the shared bpfObjects, which are
	// handed over to the next generation on reload while this core's cleanup
	// list is not run until the old generation finalizes. attachTCPOffloadLinks
	// therefore keys the links (and their reference count) by the bpfObjects
	// themselves: a reload reuses the still-attached links instead of
	// re-attaching and hitting EBUSY on fast_sock.
	reused, err := attachTCPOffloadLinks(bpf, func() (tcpOffloadLinks, error) {
		rawLink, err := ciliumLink.AttachRawLink(ciliumLink.RawLinkOptions{
			Target:  bpf.FastSock.FD(),
			Program: bpf.TcpOffloadRedirect,
			Attach:  ebpf.AttachSkSKBStreamVerdict,
		})
		if err != nil {
			return tcpOffloadLinks{}, fmt.Errorf("attach tcp_offload_redirect to fast_sock: %w", err)
		}
		var account io.Closer
		// Backlog-fuse accounting: count bytes entering each relay socket's
		// send path via skb_send_sock_locked, keyed by reversed four-tuple.
		// fentry (BPF trampoline) avoids the kprobe trap cost on the hot path.
		// DAE_FUSE_ACCOUNT=0 skips the attach (diagnostics only: the backlog
		// fuse cannot engage without the accounting).
		if os.Getenv("DAE_FUSE_ACCOUNT") != "0" {
			sentLink, err := ciliumLink.AttachTracing(ciliumLink.TracingOptions{
				Program:    bpf.TcpOffloadSentAccount,
				AttachType: ebpf.AttachTraceFEntry,
			})
			if err != nil && bpf.TcpOffloadSentAccountKprobe != nil {
				// fentry requires a 5-byte NOP entry (an ftrace mcount point).
				// Kernels without CONFIG_DYNAMIC_FTRACE (common in trimmed router
				// builds such as ImmortalWrt) leave tail-call wrapper functions
				// with a `jmp` entry; bpf_arch_text_poke then returns EBUSY
				// (entry != NOP). Fall back to a kprobe, which attaches at any
				// instruction boundary and costs a per-packet trap on the
				// accounting path only.
				c.log.WithError(err).Debug("TCP relay eBPF offload fentry accounting unavailable; falling back to kprobe")
				sentLink, err = ciliumLink.Kprobe(tcpRelayOffloadAccountTarget, bpf.TcpOffloadSentAccountKprobe, nil)
			}
			if err != nil {
				// Without the accounting the backlog fuse cannot engage, so the
				// verdict program is useless; drop it so a retry starts clean.
				_ = rawLink.Close()
				return tcpOffloadLinks{}, fmt.Errorf("attach tcp_offload_sent_account fentry to %v: %w", tcpRelayOffloadAccountTarget, err)
			}
			account = sentLink
		}
		return tcpOffloadLinks{verdict: rawLink, account: account}, nil
	})
	if err != nil {
		return err
	}
	c.addManagedBpfHookCleanup(func() error {
		releaseTCPOffloadLinks(bpf)
		return nil
	})

	c.tcpSockmapOffloadReady.Store(true)
	if reused {
		c.log.Debug("TCP relay eBPF offload links reused from the previous datapath generation")
	} else {
		c.log.Info("TCP relay eBPF offload enabled (sk_skb stream verdict on fast_sock)")
	}
	return nil
}

// tcpRelayOffloadAccountTarget is the kernel function the accounting fentry
// attaches to (SEC("fentry/...") in kern/tproxy.c). Kept as a named constant
// so the error message stays truthful if the hook is ever moved; cilium/ebpf
// v0.20 exposes no Spec() on runtime programs to derive it.
const tcpRelayOffloadAccountTarget = "skb_send_sock_locked"

// bindWan supports lazy-bind if interface `ifname` is not found.
// bindWan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindWan(ifname string) error {
	attach := func(link netlink.Link) error {
		if link.Attrs().Name == HostVethName {
			return nil
		}
		if !c.beginBpfHookAttach() {
			return nil
		}
		defer c.endBpfHookAttach()
		return c._bindWan(link.Attrs().Name)
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind WAN program to it.", link.Attrs().Name)
		if err := attach(link); err != nil {
			c.log.Errorf("bindWan: %v", err)
		}
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created.", link.Attrs().Name)
		if err := c.delQdisc(link); err != nil {
			c.log.Errorf("delQdisc: %v", err)
		}
	}
	if err := c.registerInterfacePattern(ifname, false, newlinkCallback, dellinkCallback); err != nil {
		return err
	}
	return c.attachMatchingInterfaces(ifname, attach)
}

func (c *controlPlaneCore) registerInterfacePattern(
	pattern string,
	lan bool,
	newCallback func(netlink.Link),
	delCallback func(netlink.Link),
) error {
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("invalid interface pattern %q: %w", pattern, err)
	}

	c.interfacePatternMu.Lock()
	defer c.interfacePatternMu.Unlock()
	registered := c.registeredWanPatterns
	if lan {
		registered = c.registeredLanPatterns
	}
	if registered == nil {
		registered = make(map[string]struct{})
		if lan {
			c.registeredLanPatterns = registered
		} else {
			c.registeredWanPatterns = registered
		}
	}
	if _, ok := registered[pattern]; ok {
		return nil
	}
	c.ifmgr.RegisterWithPattern(pattern, nil, newCallback, delCallback)
	registered[pattern] = struct{}{}
	return nil
}

func (c *controlPlaneCore) attachMatchingInterfaces(pattern string, attach func(netlink.Link) error) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list interfaces for pattern %q: %w", pattern, err)
	}
	for _, link := range links {
		matched, matchErr := path.Match(pattern, link.Attrs().Name)
		if matchErr != nil {
			return fmt.Errorf("match interface pattern %q: %w", pattern, matchErr)
		}
		if !matched {
			continue
		}
		if err := attach(link); err != nil {
			return fmt.Errorf("attach interface %s: %w", link.Attrs().Name, err)
		}
	}
	return nil
}

func (c *controlPlaneCore) _bindWan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	bpf := c.bpf.Load()
	if bpf == nil {
		return nil
	}
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	c.log.Infof("Bind to WAN: %v", ifname)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if link.Attrs().Index == consts.LoopbackIfIndex {
		return fmt.Errorf("cannot bind to loopback interface")
	}
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(link)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}

	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	/// Set-up WAN ingress/egress TC programs.
	// Insert TC filters
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  2,
		},
		Name:         consts.AppName + "_wan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = bpf.TproxyWanEgressL2.FD()
		filterEgress.Name += "_l2"
	} else {
		filterEgress.Fd = bpf.TproxyWanEgressL3.FD()
		filterEgress.Name += "_l3"
	}
	if err := deleteTCFiltersByHandle(link, filterEgress.Parent, filterEgress.Handle); err != nil {
		return fmt.Errorf("cannot remove existing WAN egress filter: %w", err)
	}
	if !c.isReload {
		if err := deleteTCFiltersByHandle(link, filterEgress.Parent, filterEgress.Handle^1); err != nil {
			return fmt.Errorf("cannot remove flipped WAN egress filter: %w", err)
		}
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	egressDetachFunc := func() error {
		if err := deleteTCFiltersByHandle(link, filterEgress.Parent, filterEgress.Handle); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	}
	c.addManagedBpfHookCleanup(egressDetachFunc)

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Name:         consts.AppName + "_wan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = bpf.TproxyWanIngressL2.FD()
		filterIngress.Name += "_l2"
	} else {
		filterIngress.Fd = bpf.TproxyWanIngressL3.FD()
		filterIngress.Name += "_l3"
	}
	if err := deleteTCFiltersByHandle(link, filterIngress.Parent, filterIngress.Handle); err != nil {
		return fmt.Errorf("cannot remove existing WAN ingress filter: %w", err)
	}
	if !c.isReload {
		if err := deleteTCFiltersByHandle(link, filterIngress.Parent, filterIngress.Handle^1); err != nil {
			return fmt.Errorf("cannot remove flipped WAN ingress filter: %w", err)
		}
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	ingressDetachFunc := func() error {
		if err := deleteTCFiltersByHandle(link, filterIngress.Parent, filterIngress.Handle); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	}
	c.addManagedBpfHookCleanup(ingressDetachFunc)

	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	bpf := c.bpf.Load()
	daens := GetDaeNetns()

	// tproxy_dae0peer_ingress@eth0 at dae netns
	// Best effort: qdisc may already exist and tx queue tuning is non-critical.
	daens.WithBestEffort("set dae0peer tx queue and add clsact qdisc", func() error {
		err := netlink.LinkSetTxQLen(daens.Dae0Peer(), DaeVethTxQLen)
		if err == nil {
			err = c.addQdisc(daens.Dae0Peer())
		}
		return err
	})
	filterDae0peerIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0Peer().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           bpf.TproxyDae0peerIngress.FD(),
		Name:         consts.AppName + "_dae0peer_ingress",
		DirectAction: true,
	}
	if err = daens.WithRequired("delete old dae0peer ingress filter", func() error {
		return deleteTCFiltersByHandle(
			daens.Dae0Peer(),
			filterDae0peerIngress.Parent,
			filterDae0peerIngress.Handle,
		)
	}); err != nil {
		return fmt.Errorf("cannot remove existing dae0peer ingress filter: %w", err)
	}
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly: delete the filter with the flipped handle.
		if err = daens.WithRequired("delete flipped dae0peer ingress filter", func() error {
			return deleteTCFiltersByHandle(
				daens.Dae0Peer(),
				filterDae0peerIngress.Parent,
				filterDae0peerIngress.Handle^1,
			)
		}); err != nil {
			return fmt.Errorf("cannot remove flipped dae0peer ingress filter: %w", err)
		}
	}
	if err = daens.WithRequired("add dae0peer ingress filter", func() error {
		return netlink.FilterAdd(filterDae0peerIngress)
	}); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	detachFunc := func() error {
		return daens.WithRequired("delete dae0peer ingress filter", func() error {
			if err := deleteTCFiltersByHandle(
				daens.Dae0Peer(),
				filterDae0peerIngress.Parent,
				filterDae0peerIngress.Handle,
			); err != nil {
				return fmt.Errorf("FilterDel(%v:%v): %w", daens.Dae0Peer().Attrs().Name, filterDae0peerIngress.Name, err)
			}
			return nil
		})
	}
	c.addManagedBpfHookCleanup(detachFunc)

	// tproxy_dae0_ingress@dae0 at host netns
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(daens.Dae0())
	filterDae0Ingress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           bpf.TproxyDae0Ingress.FD(),
		Name:         consts.AppName + "_dae0_ingress",
		DirectAction: true,
	}
	if err := deleteTCFiltersByHandle(daens.Dae0(), filterDae0Ingress.Parent, filterDae0Ingress.Handle); err != nil {
		return fmt.Errorf("cannot remove existing dae0 ingress filter: %w", err)
	}
	// Remove and add.
	if !c.isReload {
		if err := deleteTCFiltersByHandle(daens.Dae0(), filterDae0Ingress.Parent, filterDae0Ingress.Handle^1); err != nil {
			return fmt.Errorf("cannot remove flipped dae0 ingress filter: %w", err)
		}
	}
	if err := netlink.FilterAdd(filterDae0Ingress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	dae0DetachFunc := func() error {
		if err := deleteTCFiltersByHandle(daens.Dae0(), filterDae0Ingress.Parent, filterDae0Ingress.Handle); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", daens.Dae0().Attrs().Name, filterDae0Ingress.Name, err)
		}
		return nil
	}
	c.addManagedBpfHookCleanup(dae0DetachFunc)
	return
}
