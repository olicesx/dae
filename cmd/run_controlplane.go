/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/mohae/deepcopy"
	"golang.org/x/sys/unix"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/daedns"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

func listenControlPlaneInDaeNetns(c *control.ControlPlane, port uint16) (*control.Listener, error) {
	var listener *control.Listener
	err := withDaeNetnsRequiredFunc("listen control plane", func() error {
		var listenErr error
		listener, listenErr = listenControlPlaneFunc(c, port)
		return listenErr
	})
	if err != nil {
		if listener != nil {
			if closeErr := listener.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close listener after netns failure: %w", closeErr))
			}
		}
		return nil, fmt.Errorf("listen in dae netns: %w", err)
	}
	if listener == nil {
		return nil, fmt.Errorf("listen in dae netns: listener is nil")
	}
	return listener, nil
}

func newControlPlane(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, dnsRoutingUnchanged bool, isReloadBuild bool) (c *control.ControlPlane, err error) {
	return newControlPlaneWithMode(ctx, log, bpf, dnsCache, conf, externGeoDataDirs, false, dnsRoutingUnchanged, isReloadBuild)
}

func newPreparedControlPlane(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, dnsRoutingUnchanged bool, isReloadBuild bool) (c *control.ControlPlane, err error) {
	return newControlPlaneWithMode(ctx, log, bpf, dnsCache, conf, externGeoDataDirs, true, dnsRoutingUnchanged, isReloadBuild)
}

// buildControlPlaneRuntime is the final construction boundary after config
// normalization, subscription resolution, and reload safety checks.
func buildControlPlaneRuntime(
	ctx context.Context,
	log *logrus.Logger,
	bpf any,
	dnsCache map[string]*control.DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routing *config.Routing,
	global *config.Global,
	dns *config.Dns,
	externGeoDataDirs []string,
	prepareOnly bool,
	dnsRoutingUnchanged bool,
	isReloadBuild bool,
) (*control.ControlPlane, error) {
	if prepareOnly {
		if isReloadBuild {
			return control.NewPreparedReloadControlPlaneWithContext(
				ctx,
				log,
				bpf,
				dnsCache,
				tagToNodeList,
				groups,
				routing,
				global,
				dns,
				externGeoDataDirs,
				dnsRoutingUnchanged,
			)
		}
		return control.NewPreparedControlPlaneWithContext(
			ctx,
			log,
			bpf,
			dnsCache,
			tagToNodeList,
			groups,
			routing,
			global,
			dns,
			externGeoDataDirs,
			dnsRoutingUnchanged,
		)
	}
	if isReloadBuild {
		return control.NewReloadControlPlaneWithContext(
			ctx,
			log,
			bpf,
			dnsCache,
			tagToNodeList,
			groups,
			routing,
			global,
			dns,
			externGeoDataDirs,
			dnsRoutingUnchanged,
		)
	}
	return control.NewControlPlaneWithContext(
		ctx,
		log,
		bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routing,
		global,
		dns,
		externGeoDataDirs,
		dnsRoutingUnchanged,
	)
}

func configureTransparentHugePages(log *logrus.Logger, disable bool) {
	value := uintptr(0)
	action := "enable"
	if disable {
		value = 1
		action = "disable"
	}

	if err := unix.Prctl(unix.PR_SET_THP_DISABLE, value, 0, 0, 0); err != nil {
		if log != nil {
			log.WithError(err).Warnf("Failed to %s transparent huge pages for dae process", action)
		}
		return
	}
	if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
		log.Debugf("Configured transparent huge pages for dae process: disable=%v", disable)
	}
}

// configureGcMemoryLimit auto-detects the cgroup v2 memory ceiling for the
// current process and sets GOMEMLIMIT to 90% of it. This lets the Go runtime
// GC proactively release memory before hitting the container/system limit,
// which is critical for containerized deployments where GOGC's default
// (100% heap growth) can overshoot the cgroup limit and trigger OOM kills.
//
// An explicit GOMEMLIMIT always wins. Only memory.max participates in the
// detected ceiling: memory.high is a reclaim throttle the kernel lets the
// process exceed, so deriving a soft heap limit from it makes the Go GC run
// back-to-back against a threshold that was never meant to be a hard bound.
// The function is a no-op when no finite cgroup ceiling is configured.
func configureGcMemoryLimit(log *logrus.Logger) {
	if value, ok := os.LookupEnv("GOMEMLIMIT"); ok {
		if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
			log.Debugf("GOMEMLIMIT: using explicit environment value %q", value)
		}
		return
	}
	limit := detectCgroupMemLimit()
	if limit <= 0 {
		if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
			log.Debug("GOMEMLIMIT: no finite cgroup memory ceiling detected, skipping")
		}
		return
	}
	// Reserve 10% headroom for non-Go allocations (eBPF maps, goroutine stacks, etc.)
	softLimit := limit * 9 / 10
	debug.SetMemoryLimit(softLimit)
	if log != nil {
		log.Infof("Configured GOMEMLIMIT=%d MiB (cgroup memory ceiling=%d MiB)",
			softLimit/1024/1024, limit/1024/1024)
	}
}

// configureGOMAXPROCS pins the Go scheduler to a single P by default. On the
// few-core relay boxes dae targets, cross-P work stealing and netpoll handoffs
// around the per-packet QUIC receive path cost more CPU than the parallelism
// buys: on a 2-core box, GOMAXPROCS=1 cut proxied-relay CPU roughly in half at
// identical throughput (measured 23.6 -> ~13 CPU-seconds per 45s of ~14MB/s
// relay). The userspace relay stays well under one core, and direct traffic
// bypasses userspace via the eBPF fast path, so a single P is not a
// bottleneck; Go's asynchronous preemption keeps head-of-line delays bounded
// if a bulk burst monopolizes the P.
//
// An explicit GOMAXPROCS environment variable always wins, preserving the
// escape hatch for deployments that can actually saturate a core (e.g. many
// parallel proxy nodes).
func configureGOMAXPROCS(log *logrus.Logger) {
	if value, ok := os.LookupEnv("GOMAXPROCS"); ok {
		if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
			log.Debugf("GOMAXPROCS: using explicit environment value %q", value)
		}
		return
	}
	runtime.GOMAXPROCS(1)
	if log != nil {
		log.Infoln("Configured GOMAXPROCS=1 (set GOMAXPROCS in the service environment to override)")
	}
}

func newControlPlaneWithMode(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, prepareOnly bool, dnsRoutingUnchanged bool, isReloadBuild bool) (c *control.ControlPlane, err error) {
	// Deep copy to prevent modification.
	conf = deepcopy.Copy(conf).(*config.Config)
	if conf.Global.SoMarkFromDae == 0 {
		var autoSelected bool
		conf.Global.SoMarkFromDae, autoSelected = common.ResolveSoMarkFromDae(conf.Global.SoMarkFromDae, conf.Global.SoMarkFromDaeSet)
		if autoSelected {
			log.Warnf("so_mark_from_dae is unset; using internal socket mark %#x to prevent dae UDP self-capture", conf.Global.SoMarkFromDae)
		}
	}

	/// Get tag -> nodeList mapping.
	tagToNodeList := map[string][]string{}
	// On initial startup (not reload), purge stale TC filters left by any previous process.
	if bpf == nil && !isReloadBuild {
		control.PurgeStaleTCFilters(log)
	}
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}

	/// Init Direct Dialers.
	direct.InitDirectDialers(conf.Global.FallbackResolver)
	netutils.FallbackDns = netip.MustParseAddrPort(conf.Global.FallbackResolver)
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	daeDNSRouter, err := daedns.NewWithOption(log, &conf.Global, &conf.Dns, &daedns.NewOption{LocationFinder: locationFinder})
	if err != nil {
		return nil, err
	}

	// Start timing the startup process
	startTime := time.Now()
	stageStart := startTime

	// Resolve subscriptions to nodes.
	resolvingfailed := false
	if !conf.Global.DisableWaitingNetwork {
		epo := 5 * time.Second
		client := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
					conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("tcp", conf.Global.SoMarkFromDae, conf.Global.Mptcp), addr)
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
			Timeout: epo,
		}
		log.Infoln("Waiting for network...")
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			resp, err := client.Get(CheckNetworkLinks[i%len(CheckNetworkLinks)])
			if err != nil {
				log.Debugln("CheckNetwork:", err)
				var neterr net.Error
				if errors.As(err, &neterr) && neterr.Timeout() {
					// Do not sleep.
					continue
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(epo):
				}
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				break
			}
			log.Infof("Bad status: %v (%v)", resp.Status, resp.StatusCode)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(epo):
			}
		}
		log.Infoln("Network online.")
	}
	if len(conf.Subscription) > 0 {
		log.Infoln("Fetching subscriptions...")
	}
	// Parallelize subscription resolution to improve startup performance.
	// Use a semaphore to limit concurrency and avoid overwhelming the network.
	type subscriptionResult struct {
		tag   string
		nodes []string
		err   error
		sub   config.KeyableString
	}
	numSubscriptions := len(conf.Subscription)
	if numSubscriptions > 0 {
		// Limit concurrency to 4 subscriptions at a time to avoid overwhelming network
		maxConcurrency := min(numSubscriptions, 4)
		sem := make(chan struct{}, maxConcurrency)
		results := make(chan subscriptionResult, numSubscriptions)

		for _, sub := range conf.Subscription {
			go func(s config.KeyableString) {
				sem <- struct{}{}        // Acquire semaphore
				defer func() { <-sem }() // Release semaphore

				subDialer := direct.SymmetricDirect
				if daeDNSRouter != nil {
					wrappedDialer, wrapErr := daeDNSRouter.WrapSubscriptionDialer(subDialer, string(s))
					if wrapErr != nil {
						results <- subscriptionResult{
							err: wrapErr,
							sub: s,
						}
						return
					}
					subDialer = wrappedDialer
				}
				client := newHTTPClientForDialer(subDialer, 30*time.Second, conf.Global.SoMarkFromDae, conf.Global.Mptcp)
				tag, nodes, err := subscription.ResolveSubscription(log, &client, filepath.Dir(cfgFile), string(s))
				results <- subscriptionResult{
					tag:   tag,
					nodes: nodes,
					err:   err,
					sub:   s,
				}
			}(sub)
		}

		// Collect results
		for range numSubscriptions {
			result := <-results
			if result.err != nil {
				log.Warnf(`failed to resolve subscription "%v": %v`, result.sub, result.err)
				resolvingfailed = true
			}
			if len(result.nodes) > 0 {
				tagToNodeList[result.tag] = append(tagToNodeList[result.tag], result.nodes...)
			}
		}
		close(results)
		log.Infof("Subscriptions fetched in %v", time.Since(stageStart))
	}

	// Delete all files in persist.d that are not in tagToNodeList
	files, err := os.ReadDir(filepath.Join(filepath.Dir(cfgFile), "persist.d"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, file := range files {
		tag := strings.TrimSuffix(file.Name(), ".sub")
		if _, ok := tagToNodeList[tag]; !ok {
			err := os.Remove(filepath.Join(filepath.Dir(cfgFile), "persist.d", file.Name()))
			if err != nil {
				return nil, err
			}
		}
	}

	if len(tagToNodeList) == 0 {
		if resolvingfailed {
			log.Warnln("No node found because all subscription resolving failed.")
		} else {
			log.Warnln("No node found.")
		}
	}

	// On reload, refuse to switch to a dead (zero-node) generation when every
	// subscription failed to resolve. Without this guard the caller's rollback
	// path is never taken (a zero-node build is not an error by itself), so dae
	// would silently cut all proxied traffic until a full restart. The persisted
	// cache in persist.d normally shields against transient failures, but when
	// it is also missing/empty this guard is the last line of defense.
	//
	// A successful-but-empty fetch (subscription legitimately returned 0 nodes)
	// is left alone — resolvingfailed is only set on a hard fetch error, so an
	// intentional zero-node config is unaffected. Initial startup is also
	// excluded: there is no previous generation to preserve.
	if isReloadBuild && resolvingfailed && len(tagToNodeList) == 0 {
		return nil, fmt.Errorf("refusing reload with 0 nodes: all subscription resolving failed; keeping the current generation")
	}

	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		log.Warnln("No interface to bind.")
	}

	if err = preprocessWanInterfaceAuto(conf); err != nil {
		return nil, err
	}

	// Start timing the control plane creation
	log.Infoln("Building control plane and routing rules...")
	stageStart = time.Now()
	c, err = buildControlPlaneRuntime(
		ctx,
		log,
		bpf,
		dnsCache,
		tagToNodeList,
		conf.Group,
		&conf.Routing,
		&conf.Global,
		&conf.Dns,
		externGeoDataDirs,
		prepareOnly,
		dnsRoutingUnchanged,
		isReloadBuild,
	)
	if err != nil {
		return nil, err
	}
	log.Infof("Control plane built in %v", time.Since(stageStart))
	log.Infof("Total startup time: %v", time.Since(startTime))

	return c, nil
}
