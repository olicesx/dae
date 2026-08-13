/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

func (c *ControlPlane) closePublishedListenerFiles() error {
	if c == nil {
		return nil
	}

	c.listenerPublishMu.Lock()
	files := c.listenerFiles
	c.listenerFiles = nil
	c.listenerPublishMu.Unlock()

	var errs []error
	for _, f := range files {
		if f == nil {
			continue
		}
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return stderrors.Join(errs...)
}

func (c *ControlPlane) publishListenerSockets(listener *Listener) error {
	if c == nil || c.core == nil || listener == nil {
		return fmt.Errorf("publishListenerSockets: nil control plane or listener")
	}
	bpf := c.core.bpf.Load()
	if bpf == nil || bpf.ListenSocketMap == nil {
		return fmt.Errorf("publishListenerSockets: listen socket map is unavailable")
	}

	var (
		newFiles []*os.File
		err      error
	)
	closeNewFiles := func() {
		for _, f := range newFiles {
			if f != nil {
				_ = f.Close()
			}
		}
	}

	if listener.tcp4Listener != nil {
		tcp4File, e := dupTCPListenerFile(listener.tcp4Listener)
		if e != nil {
			return fmt.Errorf("failed to retrieve copy of the underlying TCP IPv4 listener file")
		}
		newFiles = append(newFiles, tcp4File)
		if err = bpf.ListenSocketMap.Update(consts.ZeroKey, uint64(tcp4File.Fd()), ebpf.UpdateAny); err != nil {
			closeNewFiles()
			return err
		}
	}
	if listener.tcp6Listener != nil {
		tcp6File, e := dupTCPListenerFile(listener.tcp6Listener)
		if e != nil {
			closeNewFiles()
			return fmt.Errorf("failed to retrieve copy of the underlying TCP IPv6 listener file")
		}
		newFiles = append(newFiles, tcp6File)
		if err = bpf.ListenSocketMap.Update(consts.TwoKey, uint64(tcp6File.Fd()), ebpf.UpdateAny); err != nil {
			closeNewFiles()
			return err
		}
	}
	if listener.packetConn != nil {
		udpFile, e := dupUDPPacketConnFile(listener.packetConn)
		if e != nil {
			closeNewFiles()
			return fmt.Errorf("failed to retrieve copy of the underlying UDP connection file")
		}
		newFiles = append(newFiles, udpFile)
		if err = bpf.ListenSocketMap.Update(consts.OneKey, uint64(udpFile.Fd()), ebpf.UpdateAny); err != nil {
			closeNewFiles()
			return err
		}
	}

	c.listenerPublishMu.Lock()
	oldFiles := c.listenerFiles
	c.listenerFiles = newFiles
	c.listenerPublishMu.Unlock()
	for _, f := range oldFiles {
		if f != nil {
			_ = f.Close()
		}
	}
	return nil
}

func (c *ControlPlane) PublishListenerSockets(listener *Listener) error {
	return c.publishListenerSockets(listener)
}

func (c *ControlPlane) commitInterfaceBindings() error {
	if c == nil || c.core == nil {
		return nil
	}

	if len(c.lanInterface) > 0 {
		if c.autoConfigKernelParameter {
			if err := SetIpv4forward("1"); err != nil {
				c.log.WithError(err).Warnln("Failed to enable IPv4 forwarding; proxy functionality may be limited")
			}
			if err := setForwarding("all", consts.IpVersionStr_6, "1"); err != nil {
				c.log.WithError(err).Warnln("Failed to enable IPv6 forwarding; proxy functionality may be limited")
			}
		}
		c.lanInterface = common.Deduplicate(c.lanInterface)
		for _, ifname := range c.lanInterface {
			if err := c.core.bindLan(ifname, c.autoConfigKernelParameter); err != nil {
				return fmt.Errorf("bind LAN interface %s: %w", ifname, err)
			}
		}
	}

	if len(c.wanInterface) > 0 {
		if err := c.core.setupSkPidMonitor(); err != nil {
			c.log.WithError(err).Warnln("cgroup2 is not enabled; pname routing cannot be used")
		}
		if err := c.core.setupTCPRelayOffload(); err != nil {
			c.log.WithError(err).Debugln("TCP relay eBPF offload disabled")
		}
		for _, ifname := range c.wanInterface {
			if len(c.lanInterface) > 0 && c.autoConfigKernelParameter {
				acceptRa := sysctl.Keyf("net.ipv6.conf.%v.accept_ra", ifname)
				val, err := acceptRa.Get()
				if err == nil && val == "1" {
					if err := acceptRa.Set("2", false); err != nil {
						c.log.WithError(err).Warnf("Failed to set accept_ra=2 for %v; IPv6 autoconfig may not work as expected", ifname)
					}
				}
			}
			if err := c.core.bindWan(ifname); err != nil {
				return fmt.Errorf("bind WAN interface %s: %w", ifname, err)
			}
		}
	}

	if err := c.core.bindDaens(); err != nil {
		return fmt.Errorf("bindDaens: %w", err)
	}
	return nil
}

func (c *ControlPlane) replayDnsReloadCache() error {
	if c == nil || c.dnsController == nil || c.pendingDnsReloadCache == nil {
		return nil
	}
	start := time.Now()
	count, err := c.dnsController.RestoreReloadCacheAndProject(
		c.pendingDnsReloadCache,
		c.routingMatcher.domainMatcher.MatchDomainBitmap,
		time.Now(),
	)
	if err != nil {
		return err
	}
	if count > 0 {
		c.log.Infof("Restored %d DNS cache entries from previous control plane in %v", count, time.Since(start))
	}
	c.pendingDnsReloadCache = nil
	return nil
}

// releaseCommittedDNSReloadState drops rollback-only cache state after the
// datapath and hook flip have both committed successfully.
func (c *ControlPlane) releaseCommittedDNSReloadState() {
	if c == nil {
		return
	}
	c.pendingDnsReloadCache = nil
	c.ClearReloadDnsCacheSource()
}

// CommitPreparedDatapath applies deferred kernel/BPF mutations for a prepared
// control plane. It is safe to call once; subsequent calls are no-ops.
func (c *ControlPlane) CommitPreparedDatapath() error {
	if c == nil || !c.preparedDatapathCommit {
		return nil
	}
	prepareIsolatedDatapath := !c.sharedBpfReload
	if !prepareIsolatedDatapath {
		if err := c.commitInterfaceBindings(); err != nil {
			return err
		}
	}
	if c.core == nil {
		c.releaseCommittedDNSReloadState()
		c.startConnStateJanitor()
		c.preparedDatapathCommit = false
		return nil
	}
	if c.routingKernspaceSnapshot != nil {
		c.log.Infoln("Loading routing rules into kernel space (BPF)...")
		var (
			lpmIndices []uint32
			err        error
		)
		if c.semanticRefactorFeatures.RoutingEpoch {
			lpmIndices, err = c.routingKernspaceSnapshot.BuildKernspaceForSlot(
				c.log,
				c.core.bpf.Load(),
				c.core.RoutingEpochSlot(),
			)
		} else {
			lpmIndices, err = c.routingKernspaceSnapshot.BuildKernspace(c.log, c.core.bpf.Load())
		}
		if err != nil {
			return fmt.Errorf("routing kernspace snapshot: %w", err)
		}
		c.core.lpmTrieIndices = lpmIndices
		if c.semanticRefactorFeatures.RoutingEpoch {
			if err := c.core.StageRoutingEpoch(); err != nil {
				return fmt.Errorf("stage routing epoch: %w", err)
			}
		}
	}
	if c.semanticRefactorFeatures.RoutingEpoch {
		refreshedDnsReloadCache, err := c.refreshDnsReloadCacheForCutover()
		if err != nil {
			return fmt.Errorf("refresh DNS reload cache for cutover: %w", err)
		}
		if err := c.replayDnsReloadCache(); err != nil {
			return fmt.Errorf("replay DNS reload cache: %w", err)
		}
		if refreshedDnsReloadCache {
			c.ClearReloadDnsCacheSource()
		}
		// Publishing the prepared slot is the atomic cutover: until this
		// succeeds the kernel keeps routing through the previous slot, so a
		// failure above leaves the old policy serving rather than a
		// half-written new one.
		if err := c.core.PublishRoutingEpoch(); err != nil {
			return fmt.Errorf("publish routing epoch: %w", err)
		}
	} else {
		skipDNSReloadReplay := c.sharedBpfReload && c.dnsRoutingUnchanged
		if !skipDNSReloadReplay {
			if bpf := c.core.bpf.Load(); bpf != nil {
				if err := clearReloadDomainRoutingMap(bpf); err != nil {
					return fmt.Errorf("clearReloadDomainRoutingMap: %w", err)
				}
			}
			if err := c.replayDnsReloadCache(); err != nil {
				return fmt.Errorf("replay DNS reload cache: %w", err)
			}
		}
	}
	if prepareIsolatedDatapath {
		// Isolated candidates can populate every policy map before their first
		// hook becomes reachable. The listener map is published by Serve before
		// entering this method.
		if err := c.commitInterfaceBindings(); err != nil {
			return err
		}
	}
	if !prepareIsolatedDatapath {
		if err := c.core.commitBpfHookFlip(); err != nil {
			if c.semanticRefactorFeatures.RoutingEpoch {
				if rollbackErr := c.core.RollbackRoutingEpoch(); rollbackErr != nil {
					return stderrors.Join(err, rollbackErr)
				}
			}
			return err
		}
	}
	c.releaseCommittedDNSReloadState()
	c.startConnStateJanitor()
	c.preparedDatapathCommit = false
	return nil
}

// CommitPreparedBpfHookFlip publishes the TC handle selected by an isolated
// prepared datapath after its listener, maps, and hooks are all ready.
func (c *ControlPlane) CommitPreparedBpfHookFlip() error {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.commitBpfHookFlip()
}

// RollbackPreparedBpfHookFlip restores the previous TC handle after a fresh
// candidate committed its handle but failed before supervisor publication.
func (c *ControlPlane) RollbackPreparedBpfHookFlip() error {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.rollbackCommittedBpfHookFlip()
}

// RebuildReloadDatapath restores this generation's datapath after a staged
// reload attempt modified shared BPF state but failed before cutover completed.
func (c *ControlPlane) RebuildReloadDatapath() error {
	if c == nil || c.routingKernspaceSnapshot == nil || c.core == nil || c.core.PeekBpf() == nil {
		return nil
	}
	if c.core.routingEpochEnabled() {
		c.log.Warnln("[Reload] Rolling back to the previous routing epoch after staged handoff failure")
		if err := c.core.PublishRoutingEpoch(); err != nil {
			return fmt.Errorf("publish previous routing epoch: %w", err)
		}
		c.core.activateBpfHookFlip()
		return nil
	}
	c.log.Warnln("[Reload] Rebuilding previous generation datapath after staged handoff failure")
	lpmIndices, err := c.routingKernspaceSnapshot.BuildKernspace(c.log, c.core.bpf.Load())
	if err != nil {
		return fmt.Errorf("rebuild routing kernspace: %w", err)
	}
	c.ReplaceLpmIndices(lpmIndices)
	if err := clearReloadDomainRoutingMap(c.core.bpf.Load()); err != nil {
		return fmt.Errorf("rebuild clearReloadDomainRoutingMap: %w", err)
	}
	cache := c.CloneDnsCache()
	c.pendingDnsReloadCache = cache
	if err := c.replayDnsReloadCache(); err != nil {
		return fmt.Errorf("rebuild DNS reload cache: %w", err)
	}
	c.core.activateBpfHookFlip()
	return nil
}

// RestoreDatapathForReloadRollback reattaches this generation's kernel hooks
// and restores routing/DNS maps after a prepared fresh-datapath reload failed
// during cutover.
func (c *ControlPlane) RestoreDatapathForReloadRollback() error {
	if c == nil || c.core == nil || c.core.PeekBpf() == nil {
		return nil
	}
	c.log.Warnln("[Reload] Restoring previous generation datapath after fresh handoff failure")
	c.core.resetBpfHookDetachForReattach()
	if err := c.commitInterfaceBindings(); err != nil {
		return fmt.Errorf("restore interface bindings: %w", err)
	}
	if c.routingKernspaceSnapshot != nil {
		var (
			lpmIndices []uint32
			err        error
		)
		if c.semanticRefactorFeatures.RoutingEpoch {
			lpmIndices, err = c.routingKernspaceSnapshot.BuildKernspaceForSlot(
				c.log,
				c.core.bpf.Load(),
				c.core.RoutingEpochSlot(),
			)
		} else {
			lpmIndices, err = c.routingKernspaceSnapshot.BuildKernspace(c.log, c.core.bpf.Load())
		}
		if err != nil {
			return fmt.Errorf("restore routing kernspace: %w", err)
		}
		c.ReplaceLpmIndices(lpmIndices)
		if c.semanticRefactorFeatures.RoutingEpoch {
			if err := c.core.StageRoutingEpoch(); err != nil {
				return fmt.Errorf("restore routing epoch: %w", err)
			}
		}
	}
	if c.semanticRefactorFeatures.RoutingEpoch {
		if err := c.core.clearDomainRoutingSlot(c.core.RoutingEpochSlot()); err != nil {
			return fmt.Errorf("restore clear domain routing slot: %w", err)
		}
	} else if err := clearReloadDomainRoutingMap(c.core.bpf.Load()); err != nil {
		return fmt.Errorf("restore clearReloadDomainRoutingMap: %w", err)
	}
	c.pendingDnsReloadCache = c.CloneDnsCache()
	if err := c.replayDnsReloadCache(); err != nil {
		return fmt.Errorf("restore DNS reload cache: %w", err)
	}
	if c.semanticRefactorFeatures.RoutingEpoch {
		if err := c.core.PublishRoutingEpoch(); err != nil {
			return fmt.Errorf("restore publish routing epoch: %w", err)
		}
	}
	c.core.activateBpfHookFlip()
	return nil
}
