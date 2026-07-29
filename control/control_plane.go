/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/daedns"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/direct"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
	"golang.org/x/sys/unix"
)

type ControlPlane struct {
	log *logrus.Logger

	runtimeStats *runtimeStats

	core       *controlPlaneCore
	deferFuncs []func() error
	listenIp   string

	controlPlaneGenerationState
	inConnections         sync.Map
	rejectNewConnections  atomic.Bool
	sessionManagerMu      sync.Mutex
	sessionManager        *SessionManager
	ownsSessionManager    bool
	sessionManagerBinding atomic.Pointer[controlPlaneSessionManagerBinding]
	egressRuntime         *egressRuntime
	udpEndpointAdmission  udpEndpointAdmissionGate
	udpIngressAdmission   routingEpochIngressGate
	drainTracker          *controlPlaneDrainTracker
	routingEpochPeerMu    sync.RWMutex
	routingEpochPeer      *ControlPlane
	routingEpochSlot      atomic.Uint32
	routingEpochSlotKnown atomic.Bool
	// routingEpochExecutionClosed prevents a retiring generation from
	// accepting work delegated by its staged reload peer.
	routingEpochExecutionClosed atomic.Bool

	controlPlaneDNSRuntime
	dnsHandoffMu         sync.Mutex
	dnsHandoffController atomic.Pointer[DnsController]
	dnsHandoffOwned      bool
	onceNetworkReady     sync.Once

	ctx       context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	readyOnce sync.Once

	muRealDomainSet   sync.RWMutex
	realDomainSet     *bloom.BloomFilter
	realDomainNegSet  sync.Map // map[string]int64 (expiresAt unix nano)
	dnsDialerSnapshot sync.Map // map[dnsDialerSnapshotKey]*dnsDialerSnapshotEntry
	dnsDialerPenalty  sync.Map // map[dnsDialerPenaltyKey]*dnsDialerPenaltyEntry
	tcpSniffNegMu     sync.RWMutex
	tcpSniffNegSet    map[tcpSniffNegKey]tcpSniffNegEntry
	realDomainProbeS  singleflight.Group
	negJanitorStop    chan struct{}
	negJanitorDone    chan struct{}
	negJanitorOnce    sync.Once

	controlPlaneDatapathJanitor

	// Track last alert time to avoid spamming logs
	lastBpfOverflowAlertTime atomic.Int64
	lastUdpPressureAlertTime atomic.Int64
	lastTcpPressureAlertTime atomic.Int64

	wanInterface []string
	lanInterface []string

	sniffingTimeout                time.Duration
	tproxyPortProtect              bool
	soMarkFromDae                  uint32
	mptcp                          bool
	udpRouteScopeSensitive         bool
	udpOrderedDispatcher           *udpOrderedDispatcher
	udpOrderedDispatcherShared     bool
	udpReplyDispatcher             *udpReplyDispatcher
	udpReplyDispatcherShared       bool
	failedQuicDcidCache            *failedQuicDcidCache
	lastConnectionErrorLogTime     atomic.Int64
	lastDnsFastPathErrorLogTime    atomic.Int64
	lastDnsFastPathServfailLogTime atomic.Int64
	listenerPublishMu              sync.Mutex
	listenerFiles                  []*os.File
	preparedDatapathCommit         bool
	autoConfigKernelParameter      bool
	routingKernspaceSnapshot       *routingKernspaceSnapshot
	pendingDnsReloadCache          map[string]*DnsCache
	dnsReloadCacheSourceMu         sync.Mutex
	dnsReloadCacheSource           func() map[string]*DnsCache
	dnsReloadCacheStreamSource     func(func(string, *DnsCache) error) error
	dnsReloadCacheStreamSourceHash [32]byte
	sharedBpfReload                bool
	semanticRefactorFeatures       SemanticRefactorFeatureSet
	// dnsRoutingUnchanged indicates that DNS routing configuration (excluding
	// runtime-tunable parameters like OptimisticCache) did not change from the
	// previous generation. It is retained for staged DNS handoff decisions;
	// routing epoch projection is always isolated by its target slot.
	dnsRoutingUnchanged bool
	closeOnce           sync.Once
	closeErr            error
	serveHooksMu        sync.RWMutex
	serveHooks          *ServeLifecycleHooks
}

// ServeLifecycleHooks provides optional integration hooks for the three
// prepared-generation boundaries in Serve. The production path leaves every
// hook nil and calls the normal ControlPlane implementation directly.
type ServeLifecycleHooks struct {
	// ValidateListener replaces listener validation when non-nil.
	ValidateListener func(*Listener) error
	// CommitPreparedDatapath replaces the prepared BPF commit when non-nil.
	CommitPreparedDatapath func() error
	// PublishListenerSockets replaces listener FD publication when non-nil.
	PublishListenerSockets func(*Listener) error
	// ActivatePreparedRuntime replaces DNS/runtime activation when non-nil.
	ActivatePreparedRuntime func() error
}

// SetServeLifecycleHooks installs optional lifecycle hooks and returns a
// restore function. It is intended for controlled integration tests and
// internal lifecycle adapters; nil hooks preserve the default behavior.
func (c *ControlPlane) SetServeLifecycleHooks(hooks ServeLifecycleHooks) (restore func()) {
	if c == nil {
		return func() {}
	}
	c.serveHooksMu.Lock()
	previous := c.serveHooks
	copy := hooks
	c.serveHooks = &copy
	c.serveHooksMu.Unlock()
	return func() {
		c.serveHooksMu.Lock()
		c.serveHooks = previous
		c.serveHooksMu.Unlock()
	}
}

func (c *ControlPlane) serveLifecycleHooks() ServeLifecycleHooks {
	if c == nil {
		return ServeLifecycleHooks{}
	}
	c.serveHooksMu.RLock()
	defer c.serveHooksMu.RUnlock()
	if c.serveHooks == nil {
		return ServeLifecycleHooks{}
	}
	return *c.serveHooks
}

var policyEpochSequence atomic.Uint64

type controlPlaneBuildOptions struct {
	delayDatapathCommit   bool
	delayDNSListenerStart bool
	dnsRoutingUnchanged   bool
	isReload              bool
}

var (
	// realDomainNegativeCacheTTL controls how long failed real-domain probes are cached.
	// Keep it short to avoid stale negatives while still damping bursty probe storms.
	realDomainNegativeCacheTTL = 10 * time.Second
	// gracefulShutdownWaitTimeout bounds how long shutdown waits for background
	// janitors and workers before continuing teardown.
	gracefulShutdownWaitTimeout = 5 * time.Second
	// controlPlaneDeferredCleanupTimeout bounds non-critical Close tail work
	// such as old-generation dialer, DNS, and hook cleanup during reload.
	controlPlaneDeferredCleanupTimeout = 5 * time.Second
	preparedDNSWarmupTimeout           = 15 * time.Second
	// realDomainProbeTimeout bounds synchronous probe latency on connection setup path.
	// Keep it sub-second to avoid hurting first-paint responsiveness under DNS jitter.
	// Reduced from 800ms to 500ms for faster fallback under poor network conditions.
	realDomainProbeTimeout = 500 * time.Millisecond
	// dnsDialerSnapshotTTL caches dialer selection results to reduce selection overhead.
	// Set to 2s since dialer health status only updates every 30s (default CheckInterval).
	// This provides good cache hit rate without missing dialer state changes.
	dnsDialerSnapshotTTL         = 2 * time.Second
	dnsDialerPenaltyTTL          = 5 * time.Second
	realDomainNegJanitorInterval = 30 * time.Second

	// redirectTrackJanitorPressureInterval is used when maps are under pressure.
	redirectTrackJanitorPressureInterval = 5 * time.Second
	// redirectTrackJanitorSteadyInterval is sufficient for the redirect cache
	// because stale entries have a limited blast radius.
	redirectTrackJanitorSteadyInterval = 30 * time.Second
	// cookiePidMapTimeout bounds stale cookie metadata when sock_release backstop
	// is missed for any reason. Active sockets refresh this timestamp from BPF.
	cookiePidMapTimeout = 5 * time.Minute
	// routingHandoffTimeout bounds the tuple-miss metadata bridge between eBPF
	// and userspace. Keep it short so the handoff map does not become a second
	// long-lived conn-state cache.
	routingHandoffTimeout = 10 * time.Second
	// routingHandoffPressureInterval lets the janitor react quickly when the
	// handoff map is churning under repeated tuple misses.
	routingHandoffPressureInterval = 1 * time.Second
	// routingHandoffSteadyInterval is sufficient because RetrieveRoutingResult
	// also rejects expired handoff entries on read.
	routingHandoffSteadyInterval = 5 * time.Second
	dnsFastPathErrorLogInterval  = 5 * time.Second

	// Test seams: injected in tests to avoid external DNS dependency.
	resolveIp46ForBootstrap       = netutils.ResolveIp46
	resolveIp46ForRealDomainProbe = netutils.ResolveIp46
)

func isIPLikeDomain(domain string) bool {
	if domain == "" {
		return false
	}
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		domain = domain[1 : len(domain)-1]
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return true
	}
	if host, _, err := net.SplitHostPort(domain); err == nil {
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return true
		}
	}
	return false
}

func NewControlPlane(
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
) (plane *ControlPlane, err error) {
	return newControlPlaneWithContextOptions(
		context.Background(),
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		controlPlaneBuildOptions{},
	)
}

func NewControlPlaneWithContext(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	dnsRoutingUnchanged bool,
) (plane *ControlPlane, err error) {
	return newControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		controlPlaneBuildOptions{
			dnsRoutingUnchanged: dnsRoutingUnchanged,
			isReload:            _bpf != nil,
		},
	)
}

// NewReloadControlPlaneWithContext builds a control plane during reload even
// when it receives fresh BPF objects instead of shared objects from the old
// generation. Reload builds must use reload TC handle flipping and must not run
// startup-only stale hook purges.
func NewReloadControlPlaneWithContext(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	dnsRoutingUnchanged bool,
) (plane *ControlPlane, err error) {
	return newControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		controlPlaneBuildOptions{
			dnsRoutingUnchanged: dnsRoutingUnchanged,
			isReload:            true,
		},
	)
}

// NewPreparedControlPlaneWithContext builds a new generation without mutating
// the shared datapath. Call CommitPreparedDatapath before switching traffic.
func NewPreparedControlPlaneWithContext(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	dnsRoutingUnchanged bool,
) (plane *ControlPlane, err error) {
	return newControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		controlPlaneBuildOptions{
			delayDatapathCommit:   true,
			delayDNSListenerStart: true,
			dnsRoutingUnchanged:   dnsRoutingUnchanged,
			isReload:              _bpf != nil,
		},
	)
}

// NewPreparedReloadControlPlaneWithContext builds a reload generation without
// mutating the kernel datapath until CommitPreparedDatapath is called.
func NewPreparedReloadControlPlaneWithContext(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	dnsRoutingUnchanged bool,
) (plane *ControlPlane, err error) {
	return newControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		controlPlaneBuildOptions{
			delayDatapathCommit:   true,
			delayDNSListenerStart: true,
			dnsRoutingUnchanged:   dnsRoutingUnchanged,
			isReload:              true,
		},
	)
}

func newControlPlaneWithContextOptions(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	buildOpts controlPlaneBuildOptions,
) (plane *ControlPlane, err error) {
	var freshDatapathState *FreshDatapathState
	if state, ok := _bpf.(*FreshDatapathState); ok {
		freshDatapathState = state
		_bpf = nil
	}
	// The ctx parameter may carry a preparation timeout from the caller (e.g.
	// context.WithTimeout in cmd/run.go). All long-lived objects owned by the
	// ControlPlane — its lifecycle context, dialer contexts, goroutines — MUST
	// derive from a background context so they are not cancelled when the
	// preparation deadline expires. The caller's ctx is only consulted at
	// cooperative checkpoints between slow build stages so a stalled build can
	// be aborted; it is never used as a parent for any perennial context below.
	checkCtx := func(stage string) error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("control plane build canceled at %s: %w", stage, err)
		}
		return nil
	}
	if err := checkCtx("prepare"); err != nil {
		return nil, err
	}
	refactorFeatures := semanticRefactorFeatureGateSnapshot()

	// Clear failed QUIC DCID cache on reload/startup.
	// Network conditions may have changed, so we should allow retrying sniffing
	// for DCIDs that previously failed.
	ClearFailedQuicDcids()

	if global.SoMarkFromDae == 0 {
		var autoSelected bool
		global.SoMarkFromDae, autoSelected = common.ResolveSoMarkFromDae(global.SoMarkFromDae, global.SoMarkFromDaeSet)
		if autoSelected {
			log.Warnf("so_mark_from_dae is unset; using internal socket mark %#x to prevent dae UDP self-capture", global.SoMarkFromDae)
		}
	}

	// Register the cache clear function with dialer package so health checks
	// can clear the failed DCID cache when network conditions improve.
	dialer.SetQuicDcidCacheClearFunc(ClearFailedQuicDcids)

	bootstrapResolvers, err := config.BootstrapResolvers(global)
	if err != nil {
		return nil, err
	}

	if _, ok := os.LookupEnv("QUIC_GO_DISABLE_GSO"); !ok {
		_ = os.Setenv("QUIC_GO_DISABLE_GSO", "1")
	}

	kernelVersion, e := internal.KernelVersion()
	if e != nil {
		return nil, fmt.Errorf("failed to get kernel version: %w", e)
	}
	/// Check linux kernel requirements.
	// Check version from high to low to reduce the number of user upgrading kernel.
	if kernelVersion.Less(consts.BpfLoopFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not support bpf_loop (needed by routing); expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			consts.BpfLoopFeatureVersion.String())
	}
	if requirement := consts.ChecksumFeatureVersion; kernelVersion.Less(requirement) {
		return nil, fmt.Errorf("your kernel version %v does not support checksum related features; expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if requirement := consts.BpfTimerFeatureVersion; len(global.WanInterface) > 0 && kernelVersion.Less(requirement) {
		return nil, fmt.Errorf("your kernel version %v does not support bind to WAN; expect >=%v; remove wan_interface in config file and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if requirement := consts.SkAssignFeatureVersion; len(global.LanInterface) > 0 && kernelVersion.Less(requirement) {
		return nil, fmt.Errorf("your kernel version %v does not support bind to LAN; expect >=%v; remove lan_interface in config file and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if kernelVersion.Less(consts.BasicFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not satisfy basic requirement; expect >=%v",
			kernelVersion.String(),
			consts.BasicFeatureVersion.String())
	}

	var deferFuncs []func() error

	/// Allow the current process to lock memory for eBPF resources.
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock:%v", err)
	}

	InitDaeNetns(log)
	if err = InitSysctlManager(log); err != nil {
		return nil, err
	}

	daeNetns := GetDaeNetns()
	netnsCreated, setupErr := daeNetns.SetupWithOwnership()
	if setupErr != nil {
		if netnsCreated {
			if cleanupErr := daeNetns.Close(); cleanupErr != nil && log != nil {
				log.WithError(cleanupErr).Warn("failed to clean dae netns after setup failure")
			}
		}
		return nil, fmt.Errorf("failed to setup dae netns: %w", setupErr)
	}
	defer func() {
		if err == nil || !netnsCreated {
			return
		}
		if cleanupErr := daeNetns.Close(); cleanupErr != nil && log != nil {
			log.WithError(cleanupErr).Warn("failed to clean dae netns after control plane build failure")
		}
	}()
	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	ephemeralPinPath := false
	if _bpf == nil && buildOpts.isReload {
		pinPath = filepath.Join(pinPath, fmt.Sprintf("reload-%d-%d", os.Getpid(), time.Now().UnixNano()))
		ephemeralPinPath = true
	}
	if err = os.MkdirAll(pinPath, 0755); err != nil && !os.IsExist(err) {
		if os.IsNotExist(err) {
			log.Warnln("Perhaps you are in a container environment (such as lxc). If so, please use higher virtualization (kvm/qemu).")
		}
		return nil, err
	}
	if ephemeralPinPath {
		defer func() {
			if err == nil {
				return
			}
			if cleanupErr := os.RemoveAll(pinPath); cleanupErr != nil && log != nil {
				log.WithError(cleanupErr).Warnf("Failed to clean reload BPF pin directory %s after build error", pinPath)
			}
		}()
	}

	/// Load pre-compiled programs and maps into the kernel.
	if _bpf == nil {
		// Conn-state maps are preserved across in-process reload via object handoff,
		// so fresh loads should not inherit stale bpffs pins from previous processes.
		if !ephemeralPinPath {
			cleanupEphemeralBpfPinDirs(log, pinPath)
			cleanupPinnedConnStateMapFiles(log, pinPath)
		}
		if err := checkCtx("load eBPF objects"); err != nil {
			return nil, err
		}
		log.Infof("Loading eBPF programs and maps into the kernel...")
		log.Infof("The loading process takes about 120MB free memory, which will be released after loading. Insufficient memory will cause loading failure.")
	}
	// var bpf bpfObjects
	ProgramOptions := ebpf.ProgramOptions{
		KernelTypes: nil,
	}
	if log.Level == logrus.PanicLevel {
		ProgramOptions.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelStats
		// ProgramOptions.LogLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
	}
	collectionOpts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ProgramOptions,
	}
	connStateMapMaxEntries := global.BpfConnStateMapSize
	if freshDatapathState != nil {
		connStateMapMaxEntries, err = freshDatapathState.apply(collectionOpts, connStateMapMaxEntries, log)
		if err != nil {
			return nil, err
		}
	}

	var bpf *bpfObjects
	if _bpf != nil {
		if obj, ok := _bpf.(*bpfObjects); ok {
			bpf = obj
		} else {
			return nil, fmt.Errorf("unexpected bpf type: %T", _bpf)
		}
	} else {
		bpf = new(bpfObjects)
		datapathGeneration := nextDatapathGeneration()
		if err = fullLoadBpfObjects(log, bpf, &loadBpfOptions{
			PinPath:                pinPath,
			CollectionOptions:      collectionOpts,
			ConnStateMapMaxEntries: connStateMapMaxEntries,
			DatapathGeneration:     datapathGeneration,
		}, global.SoMarkFromDae); err != nil {
			if log.Level == logrus.PanicLevel {
				log.Panicln(err)
			}
			return nil, fmt.Errorf("load eBPF objects: %w", err)
		}
		registerBpfDatapathGeneration(bpf, datapathGeneration)
	}
	sharedBpfReload := _bpf != nil
	// Ensure critical maps are always present. DNS fast-path optimizations only
	// skip per-flow map updates, never map object creation.
	if err = validateRequiredBpfMapsLoaded(bpf); err != nil {
		return nil, fmt.Errorf("validate bpf maps: %w", err)
	}
	log.Infof("Loaded eBPF programs and maps")
	// outboundId2Name can be modified later.
	outboundId2Name := make(map[uint8]string)
	core := newControlPlaneCore(
		log,
		bpf,
		outboundId2Name,
		&kernelVersion,
		buildOpts.isReload,
		!sharedBpfReload,
	)
	// A prepared shared-BPF routing-epoch generation must not overwrite the
	// active generation's health map while it is still only a candidate. The
	// runtime supervisor resumes its writes after publish, or leaves it paused
	// while rollback restores the old generation.
	if buildOpts.delayDatapathCommit && sharedBpfReload {
		core.pauseOutboundConnectivityUpdates()
	}
	if ephemeralPinPath {
		core.addDeferFunc(func() error {
			return os.RemoveAll(pinPath)
		})
	}
	defer func() {
		if err != nil {
			if plane != nil {
				_ = plane.Close()
			} else {
				// Fallback cleanup if plane was not yet fully constructed.
				for i := len(deferFuncs) - 1; i >= 0; i-- {
					_ = deferFuncs[i]()
				}
				_ = core.Close()
			}
		}
	}()

	/// DialerGroups (outbounds).
	if global.AllowInsecure {
		log.Warnln("AllowInsecure is enabled, but it is not recommended. Please make sure you have to turn it on.")
	}
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	option := dialer.NewGlobalOption(global, log)
	option.DaeDNS, err = daedns.NewWithOption(log, global, dnsConfig, &daedns.NewOption{LocationFinder: locationFinder})
	if err != nil {
		return nil, err
	}

	// Dial mode.
	dialMode, err := consts.ParseDialMode(global.DialMode)
	if err != nil {
		return nil, err
	}
	sniffingTimeout := global.SniffingTimeout
	if dialMode == consts.DialMode_Ip {
		sniffingTimeout = 0
	}
	disableKernelAliveCallback := dialMode != consts.DialMode_Ip
	_direct, directProperty := dialer.NewDirectDialer(option, true)
	direct := dialer.NewDialerContext(context.Background(), _direct, option, dialer.InstanceOption{DisableCheck: true}, directProperty)
	_block, blockProperty := dialer.NewBlockDialer(option, func() { /*Dialer Outbound*/ })
	block := dialer.NewDialerContext(context.Background(), _block, option, dialer.InstanceOption{DisableCheck: true}, blockProperty)
	outbounds := []*outbound.DialerGroup{
		outbound.NewDialerGroup(option, consts.OutboundDirect.String(),
			[]*dialer.Dialer{direct}, []*dialer.Annotation{{}},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, core.outboundAliveChangeCallback(0, disableKernelAliveCallback)),
		outbound.NewDialerGroup(option, consts.OutboundBlock.String(),
			[]*dialer.Dialer{block}, []*dialer.Annotation{{}},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, core.outboundAliveChangeCallback(1, disableKernelAliveCallback)),
	}

	// Filter out groups.
	if err := checkCtx("resolve subscription links"); err != nil {
		return nil, err
	}
	dialerSet := outbound.NewDialerSetFromLinksContext(context.Background(), option, tagToNodeList)
	deferFuncs = append(deferFuncs, dialerSet.Close)
	deferFuncs = append(deferFuncs, func() error {
		dialer.CleanupTransportCacheNamespace(option.TransportCacheNamespace)
		return nil
	})
	for _, group := range groups {
		// Parse policy.
		policy, err := outbound.NewDialerSelectionPolicyFromGroupParam(&group)
		if err != nil {
			return nil, fmt.Errorf("failed to create group %v: %w", group.Name, err)
		}
		// Filter nodes with user given filters.
		dialers, annos, err := dialerSet.FilterAndAnnotate(group.Filter, group.FilterAnnotation)
		if err != nil {
			return nil, fmt.Errorf(`failed to create group "%v": %w`, group.Name, err)
		}
		// Convert node links to dialers.
		if log.IsLevelEnabled(logrus.DebugLevel) {
			log.Debugf(`Group "%v" node list:`, group.Name)
			for _, d := range dialers {
				log.Debugln("\t" + d.Property().Name)
			}
			if len(dialers) == 0 {
				log.Debugln("\t<Empty>")
			}
		}
		groupOption, err := ParseGroupOverrideOption(group, *global, log)
		finalOption := option
		if err == nil && groupOption != nil {
			groupOption.TransportCacheNamespace = option.TransportCacheNamespace
			newDialers := make([]*dialer.Dialer, 0)
			for _, d := range dialers {
				newDialer := d.CloneWithGlobalOptionContext(context.Background(), groupOption)
				deferFuncs = append(deferFuncs, newDialer.Close)
				newDialers = append(newDialers, newDialer)
			}
			log.Infof(`Group "%v"'s check option has been override.`, group.Name)
			dialers = newDialers
			finalOption = groupOption
		}
		// Create dialer group and append it to outbounds.
		dialerGroup := outbound.NewDialerGroup(finalOption, group.Name, dialers, annos, *policy,
			core.outboundAliveChangeCallback(uint8(len(outbounds)), disableKernelAliveCallback))
		outbounds = append(outbounds, dialerGroup)
	}

	registeredDialerCallbacks := make(map[*dialer.Dialer]struct{})
	for _, group := range outbounds {
		for _, d := range group.Dialers {
			if _, ok := registeredDialerCallbacks[d]; ok {
				continue
			}
			registeredDialerCallbacks[d] = struct{}{}
			d.RegisterAliveTransitionCallback(core.dialerAliveTransitionCallback(d))
		}
	}

	/// Routing.
	// Generate outboundName2Id from outbounds.
	if len(outbounds) > int(consts.OutboundUserDefinedMax) {
		return nil, fmt.Errorf("too many outbounds")
	}
	outboundName2Id := make(map[string]uint8)
	for i, o := range outbounds {
		if _, exist := outboundName2Id[o.Name]; exist {
			return nil, fmt.Errorf("duplicated outbound name: %v", o.Name)
		}
		outboundName2Id[o.Name] = uint8(i)
		outboundId2Name[uint8(i)] = o.Name
	}
	// Apply rules optimizers.
	log.Infoln("Optimizing and loading routing rules (this may take a while for large rule sets)...")
	if err := checkCtx("optimize routing rules"); err != nil {
		return nil, err
	}
	routingProgram, err := routing.NewNormalizedProgram(routingA.Rules, routingA.Fallback,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{Logger: log, LocationFinder: locationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		return nil, fmt.Errorf("ApplyRulesOptimizers error:\n%w", err)
	}
	routingA.Rules = nil // Release.
	policyEpoch := routing.PolicyEpoch(policyEpochSequence.Add(1))
	policyIdentity, err := routing.NewPolicyIdentity(policyEpoch, routingProgram)
	if err != nil {
		return nil, fmt.Errorf("create routing policy identity: %w", err)
	}
	if refactorFeatures.RoutingEpoch {
		if _, err = core.PrepareRoutingEpoch(policyIdentity.Epoch(), sharedBpfReload); err != nil {
			return nil, fmt.Errorf("prepare routing epoch: %w", err)
		}
		if err = core.clearDomainRoutingSlot(core.RoutingEpochSlot()); err != nil {
			return nil, fmt.Errorf("clear inactive domain routing epoch: %w", err)
		}
	}
	if log.IsLevelEnabled(logrus.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range routingProgram.Rules {
			debugBuilder.WriteString(rule.String(true, false, false) + "\n")
		}
		log.Debugf("RoutingA:\n%vfallback: %v\n", debugBuilder.String(), routingProgram.Fallback)
	}
	// Parse rules and build.
	log.Infoln("Building routing matcher...")
	builder, err := NewRoutingMatcherBuilderFromProgram(log, routingProgram, outboundName2Id, core.bpf.Load())
	if err != nil {
		return nil, fmt.Errorf("NewRoutingMatcherBuilder: %w", err)
	}
	kernspaceSnapshot := builder.KernspaceSnapshot()
	if !buildOpts.delayDatapathCommit {
		log.Infoln("Loading routing rules into kernel space (BPF)...")
		var lpmIndices []uint32
		if refactorFeatures.RoutingEpoch {
			if lpmIndices, err = kernspaceSnapshot.BuildKernspaceForSlot(log, core.bpf.Load(), core.RoutingEpochSlot()); err != nil {
				return nil, fmt.Errorf("routing kernspace snapshot: %w", err)
			}
			if err = core.StageRoutingEpoch(); err != nil {
				return nil, fmt.Errorf("stage routing epoch: %w", err)
			}
		} else if lpmIndices, err = kernspaceSnapshot.BuildKernspace(log, core.bpf.Load()); err != nil {
			return nil, fmt.Errorf("routing kernspace snapshot: %w", err)
		}
		core.lpmTrieIndices = lpmIndices
	} else {
		log.Infoln("Prepared routing matcher; kernel-space routing commit deferred until listener cutover")
	}
	log.Infoln("Building userspace routing matcher...")
	routingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.BuildUserspace: %w", err)
	}

	// Get referenced outbounds to limit health checks.
	referencedOutbounds := builder.GetReferencedOutbounds()
	if len(referencedOutbounds) > 0 {
		var names []string
		for name := range referencedOutbounds {
			names = append(names, name)
		}
		log.Infof("Health check will only verify %d outbounds referenced by routing rules: %v",
			len(names), names)
	} else {
		log.Warnln("No outbounds referenced by routing rules; all outbounds will be health-checked")
		// If no outbounds are referenced (e.g., all rules use logical operators),
		// fall back to checking all outbounds to avoid breaking existing behavior.
		for _, o := range outbounds {
			referencedOutbounds[o.Name] = struct{}{}
		}
	}

	// Routing compilation allocates large temporary slices and trie builders.
	// Startup/reload is infrequent.
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Infof("Memory usage after routing build: Alloc=%vMiB, Sys=%vMiB, HeapObjects=%v",
		m.Alloc/1024/1024, m.Sys/1024/1024, m.HeapObjects)

	// Transfer every dialer, group health registration and the shared transport
	// cache namespace into structured runtime ownership. The constructor's
	// defer stack remains responsible until this point.
	egressDialers := dialerSet.AllDialers()
	for _, group := range outbounds {
		if group != nil {
			egressDialers = append(egressDialers, group.Dialers...)
		}
	}
	egressRuntime := newEgressRuntime(log, []func() error{func() error {
		dialer.CleanupTransportCacheNamespace(option.TransportCacheNamespace)
		return nil
	}})
	egressRuntime.configureResources(outbounds, egressDialers, DefaultUdpEndpointPool.forgetDialerEpochs)
	deferFuncs = nil

	// New control plane.
	cctx, cancel := context.WithCancel(context.Background())
	plane = &ControlPlane{
		log:           log,
		runtimeStats:  newRuntimeStats(),
		core:          core,
		deferFuncs:    nil,
		listenIp:      "0.0.0.0",
		egressRuntime: egressRuntime,
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds:           outbounds,
			referencedOutbounds: referencedOutbounds,
			dialMode:            dialMode,
			policyIdentity:      policyIdentity,
			routingMatcher:      routingMatcher,
			bootstrapResolvers:  bootstrapResolvers,
		},
		controlPlaneDNSRuntime:      newControlPlaneDNSRuntime(buildOpts.delayDNSListenerStart),
		controlPlaneDatapathJanitor: newControlPlaneDatapathJanitor(),
		onceNetworkReady:            sync.Once{},
		drainTracker:                newControlPlaneDrainTracker(),
		ctx:                         cctx,
		cancel:                      cancel,
		ready:                       make(chan struct{}),
		autoConfigKernelParameter:   global.AutoConfigKernelParameter,
		routingKernspaceSnapshot:    kernspaceSnapshot,
		preparedDatapathCommit:      buildOpts.delayDatapathCommit,
		sharedBpfReload:             sharedBpfReload,
		pendingDnsReloadCache:       dnsCache,
		dnsRoutingUnchanged:         buildOpts.dnsRoutingUnchanged,
		semanticRefactorFeatures:    refactorFeatures,
		muRealDomainSet:             sync.RWMutex{},
		realDomainSet:               bloom.NewWithEstimates(2048, 0.001),
		tcpSniffNegSet:              make(map[tcpSniffNegKey]tcpSniffNegEntry),
		negJanitorStop:              make(chan struct{}),
		negJanitorDone:              make(chan struct{}),
		lanInterface:                global.LanInterface,
		wanInterface:                global.WanInterface,
		sniffingTimeout:             sniffingTimeout,
		tproxyPortProtect:           global.TproxyPortProtect,
		soMarkFromDae:               global.SoMarkFromDae,
		mptcp:                       global.Mptcp,
		udpRouteScopeSensitive:      builder.UsesPacketMetadataRouting(),
		failedQuicDcidCache:         newFailedQuicDcidCache(failedQuicDcidCacheMaxEntries),
	}
	SetFailedQuicDcidCache(plane.failedQuicDcidCache)
	SetAnyfromSoMark(global.SoMarkFromDae)
	plane.runtimeStats.startRoller(cctx)
	plane.deferFuncs = append(plane.deferFuncs, plane.closePublishedListenerFiles)
	plane.startRealDomainNegJanitor()
	if !buildOpts.delayDatapathCommit {
		plane.startConnStateJanitor()
	}

	var upstreamHostResolver func(ctx context.Context, host string, network string) (*netutils.Ip46, error, error)
	if len(bootstrapResolvers) > 0 {
		upstreamHostResolver = plane.resolveBootstrapIp46
	}

	/// DNS upstream.
	dnsUpstream, err := dns.New(dnsConfig, &dns.NewOption{
		Logger:                  log,
		LocationFinder:          locationFinder,
		UpstreamReadyCallback:   plane.dnsUpstreamReadyCallback,
		UpstreamResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp),
		UpstreamHostResolver:    upstreamHostResolver,
	})
	if err != nil {
		return nil, err
	}
	/// Dns controller.
	fixedDomainTtl, err := ParseFixedDomainTtl(dnsConfig.FixedDomainTtl)
	if err != nil {
		return nil, err
	}
	plane.dnsRouting = dnsUpstream
	plane.dnsFixedDomainTtl = fixedDomainTtl
	plane.dnsOptimisticCache = dnsConfig.OptimisticCache
	plane.dnsOptimisticCacheTtl = dnsConfig.OptimisticCacheTtl
	plane.dnsMaxCacheSize = dnsConfig.MaxCacheSize
	plane.dnsIpVersionPrefer = dnsConfig.IpVersionPrefer
	plane.dnsController, err = NewDnsController(dnsUpstream, plane.dnsControllerOption())
	if err != nil {
		return nil, err
	}
	plane.deferFuncs = append(plane.deferFuncs, plane.closeOwnedDNSController)

	// Create and start DNS listener if configured
	if dnsConfig.Bind != "" {
		plane.dnsListener, err = NewDNSListener(log, dnsConfig.Bind, plane)
		if err != nil {
			return nil, err
		}
		if !buildOpts.delayDNSListenerStart {
			if err = plane.dnsListener.Start(); err != nil {
				log.Errorf("Failed to start DNS listener: %v", err)
			} else {
				log.Infof("DNS listener started on %s", dnsConfig.Bind)
				plane.registerDNSListenerStop()
			}
		}
	}

	// Init immediately to avoid DNS leaking in the very beginning because param control_plane_dns_routing will
	// be set in callback.
	if err = dnsUpstream.CheckUpstreamsFormat(); err != nil {
		return nil, err
	}
	go func() {
		defer close(plane.dnsUpstreamsReady)
		dnsUpstream.InitUpstreams(plane.ctx)
	}()

	if buildOpts.delayDatapathCommit {
		plane.preparedDatapathCommit = true
	} else {
		if err = plane.commitInterfaceBindings(); err != nil {
			return nil, err
		}
		if plane.semanticRefactorFeatures.RoutingEpoch {
			if err = plane.replayDnsReloadCache(); err != nil {
				return nil, fmt.Errorf("replay DNS reload cache: %w", err)
			}
			if err = core.PublishRoutingEpoch(); err != nil {
				return nil, fmt.Errorf("publish routing epoch: %w", err)
			}
		} else {
			skipDNSReloadReplay := plane.sharedBpfReload && plane.dnsRoutingUnchanged
			if !skipDNSReloadReplay {
				if bpf := core.bpf.Load(); bpf != nil {
					if err = clearReloadDomainRoutingMap(bpf); err != nil {
						return nil, fmt.Errorf("clearReloadDomainRoutingMap: %w", err)
					}
				}
				if err = plane.replayDnsReloadCache(); err != nil {
					return nil, fmt.Errorf("replay DNS reload cache: %w", err)
				}
			}
		}
		if err = core.commitBpfHookFlip(); err != nil {
			if plane.semanticRefactorFeatures.RoutingEpoch {
				if rollbackErr := core.RollbackRoutingEpoch(); rollbackErr != nil {
					return nil, stderrors.Join(err, rollbackErr)
				}
			}
			return nil, err
		}
		plane.releaseCommittedDNSReloadState()
		plane.markReady()
	}
	// Standalone callers retain generation-owned dispatchers. AttachSessionManager
	// replaces them with process-owned instances before Serve starts.
	plane.udpOrderedDispatcher = newUDPOrderedDispatcherForFeatures(plane.semanticRefactorFeatures)
	plane.udpReplyDispatcher = newUDPReplyDispatcherForFeatures(plane.semanticRefactorFeatures)
	return plane, nil
}

func ParseFixedDomainTtl(ks []config.KeyableString) (map[string]int, error) {
	m := make(map[string]int)
	for _, k := range ks {
		key, value, _ := strings.Cut(string(k), ":")
		ttl, err := strconv.ParseInt(strings.TrimSpace(value), 0, strconv.IntSize)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ttl: %v", err)
		}
		m[strings.TrimSpace(key)] = int(ttl)
	}
	return m, nil
}

func ParseGroupOverrideOption(group config.Group, global config.Global, log *logrus.Logger) (*dialer.GlobalOption, error) {
	result := global
	changed := false
	if group.TcpCheckUrl != nil {
		result.TcpCheckUrl = group.TcpCheckUrl
		changed = true
	}
	if group.TcpCheckHttpMethod != "" {
		result.TcpCheckHttpMethod = group.TcpCheckHttpMethod
		changed = true
	}
	if group.UdpCheckDns != nil {
		result.UdpCheckDns = group.UdpCheckDns
		changed = true
	}
	if group.CheckInterval != 0 {
		result.CheckInterval = group.CheckInterval
		changed = true
	}
	if group.CheckTolerance != 0 {
		result.CheckTolerance = group.CheckTolerance
		changed = true
	}
	if changed {
		option := dialer.NewGlobalOption(&result, log)
		return option, nil
	}
	return nil, nil
}

// clearReloadDomainRoutingMap clears slot zero for callers that operate on a
// fresh datapath. Shared reloads must use clearReloadDomainRoutingMapSlot so
// they never erase the still-readable active plan.
func clearReloadDomainRoutingMap(bpf *bpfObjects) error {
	return clearReloadDomainRoutingMapSlot(bpf, 0)
}

func clearReloadDomainRoutingMapSlot(bpf *bpfObjects, slot uint32) error {
	if bpf == nil || bpf.DomainRoutingMap == nil {
		return nil
	}
	if !validRoutingEpochSlot(slot) {
		return fmt.Errorf("invalid domain routing epoch slot %d", slot)
	}

	var (
		key   bpfRoutingEpochIp
		value bpfDomainRouting
		keys  []bpfRoutingEpochIp
		iter  = bpf.DomainRoutingMap.Iterate()
	)
	for iter.Next(&key, &value) {
		if key.Slot == slot {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate domain routing slot %d: %w", slot, err)
	}
	if len(keys) == 0 {
		return nil
	}
	if _, err := BpfMapBatchDelete(bpf.DomainRoutingMap, keys); err != nil {
		return fmt.Errorf("clear domain routing slot %d: %w", slot, err)
	}
	return nil
}

// validateRequiredBpfMapsLoaded checks maps that are required by both DNS and
// non-DNS datapaths. DNS fast-path may skip per-flow entry updates, but these
// map objects must always exist.
func validateRequiredBpfMapsLoaded(bpf *bpfObjects) error {
	if bpf == nil {
		return fmt.Errorf("nil bpf objects")
	}
	required := []struct {
		name string
		m    *ebpf.Map
	}{
		{name: "domain_routing_map", m: bpf.DomainRoutingMap},
		{name: "conn_state_map", m: bpf.ConnStateMap},
		{name: "routing_handoff_map", m: bpf.RoutingHandoffMap},
		{name: "routing_map", m: bpf.RoutingMap},
		{name: "routing_meta_map", m: bpf.RoutingMetaMap},
		{name: "active_routing_epoch_map", m: bpf.ActiveRoutingEpochMap},
		{name: "routing_epoch_map", m: bpf.RoutingEpochMap},
	}
	for _, r := range required {
		if r.m == nil {
			return fmt.Errorf("required map %q is nil", r.name)
		}
	}
	return nil
}

func (c *ControlPlane) EjectBpf() *bpfObjects {
	if c.core == nil {
		return nil
	}
	return c.core.EjectBpf()
}

func (c *ControlPlane) InjectBpf(bpf *bpfObjects) {
	c.core.InjectBpf(bpf)
}

func (c *ControlPlane) PeekBpf() *bpfObjects {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.PeekBpf()
}

func (c *ControlPlane) ActiveSessionCount() int {
	if c == nil || c.drainTracker == nil {
		return 0
	}
	return c.drainTracker.Count()
}

func (c *ControlPlane) DrainIdleCh() <-chan struct{} {
	if c == nil || c.drainTracker == nil {
		return closedDrainIdleCh
	}
	return c.drainTracker.IdleCh()
}

func (c *ControlPlane) EjectLpmIndices() []uint32 {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.EjectLpmIndices()
}

func (c *ControlPlane) InheritLpmIndices(indices []uint32) {
	if c == nil || c.core == nil {
		return
	}
	c.core.InheritLpmIndices(indices)
}

func (c *ControlPlane) ReplaceLpmIndices(indices []uint32) {
	if c == nil || c.core == nil {
		return
	}
	c.core.ReplaceLpmIndices(indices)
}

func (c *ControlPlane) currentBpf() *bpfObjects {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.PeekBpf()
}

func (c *ControlPlane) acquireDrainTicket() func() {
	if c == nil || c.drainTracker == nil {
		return func() {}
	}
	return c.drainTracker.Acquire()
}

func (c *ControlPlane) CloneDnsCache() map[string]*DnsCache {
	if c == nil {
		return nil
	}
	return c.cloneDnsCache()
}

// StreamDnsCacheForReload visits the current cache without building a second
// map or retaining another set of cache wrappers. Membership is stable for the
// duration of the visit; cache payloads are immutable after publication.
func (c *ControlPlane) StreamDnsCacheForReload(visit func(string, *DnsCache) error) error {
	if c == nil || visit == nil {
		return nil
	}
	controller := c.ActiveDnsController()
	if controller == nil || controller.dnsControllerStore == nil {
		return nil
	}
	controller.cacheProjectionMu.RLock()
	defer controller.cacheProjectionMu.RUnlock()

	var visitErr error
	controller.dnsCache.Range(func(key, value any) bool {
		cacheKey, keyOK := key.(string)
		cache, cacheOK := value.(*DnsCache)
		if !keyOK || !cacheOK || cache == nil {
			return true
		}
		visitErr = visit(cacheKey, cache)
		return visitErr == nil
	})
	return visitErr
}

// SetReloadDnsCacheSource installs the previous generation's cache snapshot
// source for a prepared shared-BPF reload. It is consumed at datapath commit.
func (c *ControlPlane) SetReloadDnsCacheSource(source func() map[string]*DnsCache) {
	if c == nil {
		return
	}
	c.dnsReloadCacheSourceMu.Lock()
	c.dnsReloadCacheSource = source
	c.dnsReloadCacheStreamSource = nil
	c.dnsReloadCacheStreamSourceHash = [32]byte{}
	c.dnsReloadCacheSourceMu.Unlock()
}

// SetReloadDnsCacheStreamSource installs a zero-copy cache visitor for a
// prepared routing-epoch cutover. sourceHash identifies the cached bitmaps.
func (c *ControlPlane) SetReloadDnsCacheStreamSource(
	source func(func(string, *DnsCache) error) error,
	sourceHash [32]byte,
) {
	if c == nil {
		return
	}
	c.dnsReloadCacheSourceMu.Lock()
	c.dnsReloadCacheSource = nil
	c.dnsReloadCacheStreamSource = source
	c.dnsReloadCacheStreamSourceHash = sourceHash
	c.dnsReloadCacheSourceMu.Unlock()
}

// ClearReloadDnsCacheSource releases the previous generation cache source.
func (c *ControlPlane) ClearReloadDnsCacheSource() {
	if c == nil {
		return
	}
	c.dnsReloadCacheSourceMu.Lock()
	c.dnsReloadCacheSource = nil
	c.dnsReloadCacheStreamSource = nil
	c.dnsReloadCacheStreamSourceHash = [32]byte{}
	c.dnsReloadCacheSourceMu.Unlock()
}

func (c *ControlPlane) cloneDnsReloadCacheForCutover() (map[string]*DnsCache, bool) {
	if c == nil || !c.sharedBpfReload || !c.preparedDatapathCommit {
		return nil, false
	}
	c.dnsReloadCacheSourceMu.Lock()
	defer c.dnsReloadCacheSourceMu.Unlock()
	if c.dnsReloadCacheSource == nil {
		return nil, false
	}
	return c.dnsReloadCacheSource(), true
}

func (c *ControlPlane) dnsReloadCacheStreamForCutover() (
	func(func(string, *DnsCache) error) error,
	[32]byte,
	bool,
) {
	if c == nil || !c.sharedBpfReload || !c.preparedDatapathCommit {
		return nil, [32]byte{}, false
	}
	c.dnsReloadCacheSourceMu.Lock()
	defer c.dnsReloadCacheSourceMu.Unlock()
	if c.dnsReloadCacheStreamSource == nil {
		return nil, [32]byte{}, false
	}
	return c.dnsReloadCacheStreamSource, c.dnsReloadCacheStreamSourceHash, true
}

func (c *ControlPlane) projectDnsReloadCacheStream(
	source func(func(string, *DnsCache) error) error,
	reuseBitmap bool,
) (int, error) {
	if c == nil || source == nil || c.core == nil {
		return 0, nil
	}
	count := 0
	err := source(func(cacheKey string, cache *DnsCache) error {
		if cache == nil {
			return nil
		}
		bitmap := cache.DomainBitmap
		if !reuseBitmap || len(bitmap) != len(bpfDomainRouting{}.Bitmap) {
			if c.routingMatcher == nil || c.routingMatcher.domainMatcher == nil {
				return fmt.Errorf("project DNS reload cache without domain matcher")
			}
			bitmap = c.routingMatcher.domainMatcher.MatchDomainBitmap(cache.GetFqdn())
		}
		ownerKey := cache.RouteOwnerKey
		if ownerKey == "" {
			ownerKey = cacheKey
		}
		projected := DnsCache{
			RouteOwnerKey:        ownerKey,
			RouteProjectionEpoch: uint64(c.PolicyEpoch()),
			DomainBitmap:         bitmap,
			Answer:               cache.Answer,
		}
		if err := c.core.BatchUpdateDomainRouting(&projected); err != nil {
			return fmt.Errorf("project streamed DNS cache %q: %w", cacheKey, err)
		}
		count++
		return nil
	})
	return count, err
}

// refreshDnsReloadCacheForCutover replaces the early preparation snapshot
// with one taken immediately before the target routing epoch is published.
func (c *ControlPlane) refreshDnsReloadCacheForCutover() (bool, error) {
	streamSource, streamSourceHash, streamOK := c.dnsReloadCacheStreamForCutover()
	cache, cacheOK := c.cloneDnsReloadCacheForCutover()
	if !streamOK && !cacheOK {
		return false, nil
	}
	if c.core == nil {
		return false, fmt.Errorf("refresh DNS reload cache without control-plane core")
	}
	if err := c.core.clearDomainRoutingSlot(c.core.RoutingEpochSlot()); err != nil {
		return false, fmt.Errorf("clear target domain routing slot: %w", err)
	}
	if streamOK {
		// Release any preparation-time fallback before walking the authoritative
		// cache. The stream itself retains no map or wrapper copies.
		c.pendingDnsReloadCache = nil
		reuseBitmap := streamSourceHash != ([32]byte{}) && streamSourceHash == c.PolicyIdentity().Hash()
		count, err := c.projectDnsReloadCacheStream(streamSource, reuseBitmap)
		if err != nil {
			return false, err
		}
		if count > 0 && c.log != nil {
			c.log.Infof("Projected %d DNS cache entries from previous control plane", count)
		}
		return true, nil
	}
	c.pendingDnsReloadCache = cache
	return true, nil
}

func (c *ControlPlane) ActiveDnsController() *DnsController {
	if c == nil {
		return nil
	}
	return c.activeController(&c.dnsHandoffController)
}

func (c *ControlPlane) dnsRequestContext(ctx context.Context, controller *DnsController) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || controller == nil || controller == c.dnsController {
		return ctx
	}
	if c.dnsHandoffController.Load() == controller {
		return controller.baseContext()
	}
	return ctx
}

// SharesActiveDnsControllerWith reports whether both control planes currently
// resolve DNS through the same active controller instance.
func (c *ControlPlane) SharesActiveDnsControllerWith(other *ControlPlane) bool {
	if c == nil || other == nil {
		return false
	}
	controller := c.ActiveDnsController()
	return controller != nil && controller == other.ActiveDnsController()
}

func (c *ControlPlane) DetachDnsController() *DnsController {
	if c == nil {
		return nil
	}
	return c.detachController()
}

func (c *ControlPlane) replaceDNSHandoffController(controller *DnsController, owned bool) (*DnsController, bool) {
	if c == nil {
		return nil, false
	}
	c.dnsHandoffMu.Lock()
	defer c.dnsHandoffMu.Unlock()

	previous := c.dnsHandoffController.Load()
	previousOwned := c.dnsHandoffOwned
	c.dnsHandoffOwned = owned && controller != nil
	c.dnsHandoffController.Store(controller)
	return previous, previousOwned
}

func (c *ControlPlane) clearDNSHandoffControllerIfMatch(controller *DnsController) (*DnsController, bool, bool) {
	if c == nil {
		return nil, false, false
	}
	c.dnsHandoffMu.Lock()
	defer c.dnsHandoffMu.Unlock()

	current := c.dnsHandoffController.Load()
	if current != controller {
		return current, false, false
	}
	owned := c.dnsHandoffOwned
	c.dnsHandoffOwned = false
	c.dnsHandoffController.Store(nil)
	return current, owned, true
}

func (c *ControlPlane) takeDNSHandoffController() (*DnsController, bool) {
	if c == nil {
		return nil, false
	}
	c.dnsHandoffMu.Lock()
	defer c.dnsHandoffMu.Unlock()

	controller := c.dnsHandoffController.Load()
	owned := c.dnsHandoffOwned
	c.dnsHandoffOwned = false
	c.dnsHandoffController.Store(nil)
	return controller, owned
}

func (c *ControlPlane) EnableDNSHandoff(controller *DnsController, duration time.Duration) {
	if c == nil || controller == nil {
		return
	}
	if c.log != nil {
		c.log.WithField("duration", duration).Warnln("[Reload] Enabled DNS handoff controller")
	}
	if previous, previousOwned := c.replaceDNSHandoffController(controller, true); previous != nil && previousOwned && previous != controller {
		_ = previous.Close()
	}
	go func(ctrl *DnsController) {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-timer.C:
			if _, owned, cleared := c.clearDNSHandoffControllerIfMatch(ctrl); cleared {
				if c.log != nil {
					c.log.Warnln("[Reload] DNS handoff controller expired")
				}
				if owned {
					_ = ctrl.Close()
				}
			}
		case <-c.ctx.Done():
			if _, owned, cleared := c.clearDNSHandoffControllerIfMatch(ctrl); cleared && owned {
				_ = ctrl.Close()
			}
		}
	}(controller)
}

func (c *ControlPlane) SetDNSHandoffController(controller *DnsController) {
	if c == nil {
		return
	}
	if previous, previousOwned := c.replaceDNSHandoffController(controller, false); previous != nil && previousOwned && previous != controller {
		_ = previous.Close()
	}
}

// InheritDialerHealthFrom copies health snapshots from a previous control plane
// generation into the current one. It returns true when at least one dialer
// matched by group+name between the old and new generation, indicating that
// active connections on those dialers may survive the reload.
func (c *ControlPlane) InheritDialerHealthFrom(previous *ControlPlane) bool {
	if c == nil || previous == nil {
		return false
	}

	var hasOverlap bool

	previousGroups := make(map[string]*outbound.DialerGroup, len(previous.outbounds))
	for _, group := range previous.outbounds {
		if group == nil {
			continue
		}
		previousGroups[group.Name] = group
	}

	for _, group := range c.outbounds {
		if group == nil {
			continue
		}
		oldGroup := previousGroups[group.Name]
		if oldGroup == nil {
			continue
		}
		fallback := group.CaptureReloadSelectionFallback()
		oldDialers := make(map[string]*dialer.Dialer, len(oldGroup.Dialers))
		for _, d := range oldGroup.Dialers {
			if d == nil || d.Property() == nil {
				continue
			}
			oldDialers[d.Property().Name] = d
		}
		for _, d := range group.Dialers {
			if d == nil || d.Property() == nil {
				continue
			}
			if oldDialer := oldDialers[d.Property().Name]; oldDialer != nil {
				hasOverlap = true
				if dialerHealthCheckConfigEqual(d, oldDialer) {
					d.RestoreHealthSnapshot(oldDialer.ReloadHealthSnapshot())
				}
			}
		}
		group.EnsureReloadSelectionFloor(fallback)
	}
	return hasOverlap
}

func dialerHealthCheckConfigEqual(current, previous *dialer.Dialer) bool {
	if current == nil || previous == nil || current.GlobalOption == nil || previous.GlobalOption == nil {
		return false
	}
	return slices.Equal(current.TcpCheckOptionRaw.Raw, previous.TcpCheckOptionRaw.Raw) &&
		current.TcpCheckOptionRaw.Method == previous.TcpCheckOptionRaw.Method &&
		current.TcpCheckOptionRaw.ResolverNetwork == previous.TcpCheckOptionRaw.ResolverNetwork &&
		slices.Equal(current.CheckDnsOptionRaw.Raw, previous.CheckDnsOptionRaw.Raw) &&
		current.CheckDnsOptionRaw.ResolverNetwork == previous.CheckDnsOptionRaw.ResolverNetwork &&
		current.CheckDnsOptionRaw.Somark == previous.CheckDnsOptionRaw.Somark
}

func isIgnorableBatchLookupErr(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, ebpf.ErrKeyNotExist) ||
		stderrors.Is(err, os.ErrClosed) ||
		stderrors.Is(err, unix.EBADF) {
		return true
	}

	// Keep a compact string fallback for wrapped kernel/libbpf errors.
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "bad file descriptor") ||
		strings.Contains(errStr, "file descriptor") ||
		strings.Contains(errStr, "closed") ||
		strings.Contains(errStr, "key does not exist")
}

func (c *ControlPlane) markReady() {
	if c == nil {
		return
	}
	c.readyOnce.Do(func() {
		close(c.ready)
	})
}

func (c *ControlPlane) registerDNSListenerStop() {
	if c == nil {
		return
	}
	c.registerListenerStop(&c.deferFuncs, c.stopOwnedDNSListener)
}

func (c *ControlPlane) stopOwnedDNSListener() error {
	if c == nil {
		return nil
	}
	return c.controlPlaneDNSRuntime.stopOwnedDNSListener()
}

func (c *ControlPlane) closeOwnedDNSController() error {
	if c == nil {
		return nil
	}
	return c.controlPlaneDNSRuntime.closeOwnedDNSController()
}

var domainRoutingMapFullLastLog atomic.Int64

// logDomainRoutingMapFull reports a saturated domain_routing_map at most once a
// minute, so a sustained overflow cannot flood the log from the DNS hot path.
func (c *ControlPlane) logDomainRoutingMapFull(cache *DnsCache) {
	if c == nil || c.log == nil {
		return
	}
	now := time.Now().UnixNano()
	last := domainRoutingMapFullLastLog.Load()
	if now-last < int64(time.Minute) || !domainRoutingMapFullLastLog.CompareAndSwap(last, now) {
		return
	}
	var fqdn string
	if cache != nil {
		fqdn = cache.GetFqdn()
	}
	c.log.WithField("domain", fqdn).Warn(
		"domain_routing_map is full; newly resolved domains fall back to userspace routing until cached entries expire")
}

func (c *ControlPlane) dnsControllerOption() *DnsControllerOption {
	if c == nil {
		return nil
	}
	policyIdentity := c.PolicyIdentity()
	routeProjectionEpoch := uint64(policyIdentity.Epoch())
	return &DnsControllerOption{
		Log:              c.log,
		LifecycleContext: c.ctx,
		ConcurrencyLimit: 0,
		CacheAccessCallback: func(cache *DnsCache) (err error) {
			if err = c.core.BatchUpdateDomainRouting(cache); err != nil {
				if stderrors.Is(err, ErrBpfMapFull) {
					// The answer itself is valid; only the kernel-side domain
					// bitmap could not be projected. Failing the query would
					// take DNS down for every new domain until entries expire,
					// so degrade to routing this domain in userspace and let
					// the projection retry once the map drains.
					c.logDomainRoutingMapFull(cache)
					return nil
				}
				return fmt.Errorf("BatchUpdateDomainRouting: %w", err)
			}
			return nil
		},
		CacheDeleteCallback: func(cacheKey string, cache *DnsCache) (err error) {
			_ = cacheKey
			if err = c.core.BatchRemoveDomainRouting(cache); err != nil {
				return fmt.Errorf("BatchRemoveDomainRouting: %w", err)
			}
			return nil
		},
		RouteProjectionEpoch: routeProjectionEpoch,
		RouteProjectionHash:  policyIdentity.Hash(),
		ProjectCacheRoute: func(cache *DnsCache) []uint32 {
			if cache == nil {
				return nil
			}
			return c.routingMatcher.domainMatcher.MatchDomainBitmap(cache.GetFqdn())
		},
		NewCache: func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error) {
			return &DnsCache{
				RouteProjectionEpoch: routeProjectionEpoch,
				DomainBitmap:         c.routingMatcher.domainMatcher.MatchDomainBitmap(fqdn),
				NS:                   ns,
				Extra:                extra,
				Answer:               answers,
				Deadline:             deadline,
				OriginalDeadline:     originalDeadline,
			}, nil
		},
		BestDialerChooser: c.chooseBestDnsDialerSnapshot,
		TimeoutExceedCallback: func(dialArgument *dialArgument, err error) {
			if commonerrors.IsIgnorableConnectionError(err) {
				return
			}
			c.penalizeDnsDialArg(dialArgument, time.Now())
			if dialArgument == nil || dialArgument.l4proto == consts.L4ProtoStr_UDP {
				return
			}
			dialArgument.bestDialer.ReportUnavailable(&dialer.NetworkType{
				L4Proto:         dialArgument.l4proto,
				IpVersion:       dialArgument.ipversion,
				IsDns:           true,
				UdpHealthDomain: dialer.UdpHealthDomainDns,
			}, err)
		},
		FixedDomainTtl:     c.dnsFixedDomainTtl,
		OptimisticCache:    c.dnsOptimisticCache,
		OptimisticCacheTtl: c.dnsOptimisticCacheTtl,
		MaxCacheSize:       c.dnsMaxCacheSize,
		IpVersionPrefer:    c.dnsIpVersionPrefer,
	}
}

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
	count, err := c.dnsController.RestoreReloadCacheAndProject(
		c.pendingDnsReloadCache,
		c.routingMatcher.domainMatcher.MatchDomainBitmap,
		time.Now(),
	)
	if err != nil {
		return err
	}
	if count > 0 {
		c.log.Infof("Restored %d DNS cache entries from previous control plane", count)
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

func (c *ControlPlane) dnsUpstreamReadyCallback(dnsUpstream *dns.Upstream) (err error) {
	if c != nil {
		c.noteDNSUpstreamAvailable()
	}
	// Waiting for ready.
	select {
	case <-c.ctx.Done():
		return nil
	case <-c.ready:
	}

	///  Notify dialers to check.
	c.onceNetworkReady.Do(func() {
		for _, out := range c.outbounds {
			for _, d := range out.Dialers {
				d.NotifyCheck()
			}
		}
	})
	if dnsUpstream == nil {
		return nil
	}

	/// Updates dns cache to support domain routing for hostname of dns_upstream.
	// Ten years later.
	deadline := time.Now().Add(time.Hour * 24 * 365 * 10)
	fqdn := dnsmessage.CanonicalName(dnsUpstream.Hostname)

	if dnsUpstream.Ip4.IsValid() {
		typ := dnsmessage.TypeA
		answers := []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(fqdn),
				Rrtype: typ,
				Class:  dnsmessage.ClassINET,
				Ttl:    0, // Must be zero.
			},
			A: dnsUpstream.Ip4.AsSlice(),
		}}
		ttl := max(int(time.Until(deadline).Seconds()), 0)
		if err = c.dnsController.UpdateDnsCacheTtl(dnsUpstream.Hostname, typ, answers, nil, nil, ttl); err != nil {
			return err
		}
	}

	if dnsUpstream.Ip6.IsValid() {
		typ := dnsmessage.TypeAAAA
		answers := []dnsmessage.RR{&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(fqdn),
				Rrtype: typ,
				Class:  dnsmessage.ClassINET,
				Ttl:    0, // Must be zero.
			},
			AAAA: dnsUpstream.Ip6.AsSlice(),
		}}
		ttl := max(int(time.Until(deadline).Seconds()), 0)
		if err = c.dnsController.UpdateDnsCacheTtl(dnsUpstream.Hostname, typ, answers, nil, nil, ttl); err != nil {
			return err
		}
	}
	return nil
}

func (c *ControlPlane) ActivateCheck() {
	for _, g := range c.outbounds {
		// Only activate health checks for outbounds referenced by routing rules.
		// This significantly reduces startup time when subscription has many nodes
		// but only a few groups are actually used in routing.
		if _, referenced := c.referencedOutbounds[g.Name]; !referenced {
			c.log.Debugf("Skip health check for unreferenced outbound: %v", g.Name)
			continue
		}
		for _, d := range g.Dialers {
			// We only activate check of nodes that have a group.
			d.ActivateCheck()
		}
	}
}

// OnHealthCheckSuccess is called when a dialer passes health check.
// This clears the failed QUIC DCID cache since network conditions may have improved.
func (c *ControlPlane) OnHealthCheckSuccess() {
	ClearFailedQuicDcids()
}

func (c *ControlPlane) ChooseDialTarget(outbound consts.OutboundIndex, dst netip.AddrPort, domain string) (dialTarget string, shouldReroute bool, dialIp bool) {
	dialMode := consts.DialMode_Ip

	if !outbound.IsReserved() && domain != "" {
		switch c.dialMode {
		case consts.DialMode_Domain:
			// Avoid blocking probe for literal IP / host:port values.
			if isIPLikeDomain(domain) {
				break
			}
			if c.dnsController.HasDnsKnowledge(c.dnsController.cacheKey(domain, common.AddrToDnsType(dst.Addr()))) {
				// Has A/AAAA records. It is a real domain.
				dialMode = consts.DialMode_Domain
				shouldReroute = true
			} else {
				if known, real := c.lookupRealDomainCache(domain); known {
					if real {
						dialMode = consts.DialMode_Domain
						shouldReroute = true
					}
				} else {
					// Unknown domain on first hit: warm it asynchronously to avoid
					// blocking connection setup on webpage first paint path.
					c.triggerRealDomainProbe(domain)
				}
			}
		case consts.DialMode_DomainCao:
			shouldReroute = true
			fallthrough
		case consts.DialMode_DomainPlus:
			dialMode = consts.DialMode_Domain
		}
	}

	switch dialMode {
	case consts.DialMode_Ip:
		dialTarget = dst.String()
		dialIp = true
	case consts.DialMode_Domain:
		if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
			// Sniffed domain may be like `[2606:4700:20::681a:d1f]`. We should remove the brackets.
			domain = domain[1 : len(domain)-1]
		}
		if _, err := netip.ParseAddr(domain); err == nil {
			// domain is IPv4 or IPv6 (has colon)
			dialTarget = net.JoinHostPort(domain, strconv.Itoa(int(dst.Port())))
			dialIp = true

		} else if _, _, err := net.SplitHostPort(domain); err == nil {
			// domain is already domain:port
			dialTarget = domain
		} else {
			dialTarget = net.JoinHostPort(domain, strconv.Itoa(int(dst.Port())))
		}
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"from": dst.String(),
				"to":   dialTarget,
			}).Debugln("Rewrite dial target to domain")
		}
	}
	return dialTarget, shouldReroute, dialIp
}

func (c *ControlPlane) lookupRealDomainCache(domain string) (known bool, real bool) {
	// Read-mostly fast path.
	c.muRealDomainSet.RLock()
	hit := c.realDomainSet.TestString(domain)
	c.muRealDomainSet.RUnlock()
	if hit {
		return true, true
	}

	// Negative-cache fast path.
	now := time.Now()
	if v, ok := c.realDomainNegSet.Load(domain); ok {
		expiresAt, _ := v.(int64)
		if now.UnixNano() < expiresAt {
			return true, false
		}
		c.realDomainNegSet.Delete(domain)
	}
	return false, false
}

func (c *ControlPlane) resolveBootstrapIp46(ctx context.Context, host string, network string) (*netutils.Ip46, error, error) {
	if len(c.bootstrapResolvers) == 0 {
		err := fmt.Errorf("bootstrap resolver is not configured")
		return &netutils.Ip46{}, err, err
	}
	return c.resolveIp46WithBootstrapResolvers(ctx, host, network, false, resolveIp46ForBootstrap)
}

func (c *ControlPlane) triggerRealDomainProbe(domain string) {
	if domain == "" || isIPLikeDomain(domain) {
		return
	}
	if known, _ := c.lookupRealDomainCache(domain); known {
		return
	}
	go func() {
		_, _, _ = c.realDomainProbeS.Do(domain, func() (any, error) {
			return c.probeAndUpdateRealDomain(domain), nil
		})
	}()
}

func (c *ControlPlane) probeAndUpdateRealDomain(domain string) bool {
	if known, real := c.lookupRealDomainCache(domain); known {
		return real
	}

	now := time.Now()
	// Use ControlPlane's context for real domain probe to enable proper cancel propagation
	ctx, cancel := context.WithTimeout(c.ctx, realDomainProbeTimeout)
	defer cancel()

	if len(c.bootstrapResolvers) == 0 {
		// Fail closed when no bootstrap resolver is configured.
		return false
	}

	ip46, err4, err6 := c.resolveIp46WithBootstrapResolvers(
		ctx,
		domain,
		common.MagicNetwork("udp", c.soMarkFromDae, c.mptcp),
		true,
		resolveIp46ForRealDomainProbe,
	)
	if err4 != nil && err6 != nil {
		// Probe failed for both families; avoid sticky false negatives.
		return false
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		c.realDomainNegSet.Store(domain, now.Add(realDomainNegativeCacheTTL).UnixNano())
		return false
	}

	c.muRealDomainSet.Lock()
	c.realDomainSet.AddString(domain)
	c.muRealDomainSet.Unlock()
	c.realDomainNegSet.Delete(domain)
	return true
}

func (c *ControlPlane) resolveIp46WithBootstrapResolvers(
	ctx context.Context,
	host string,
	network string,
	race bool,
	resolve func(context.Context, netproxy.Dialer, netip.AddrPort, string, string, bool) (*netutils.Ip46, error, error),
) (*netutils.Ip46, error, error) {
	if len(c.bootstrapResolvers) == 0 {
		err := fmt.Errorf("bootstrap resolver is not configured")
		return &netutils.Ip46{}, err, err
	}

	var firstErr4 error
	var firstErr6 error
	var lastNoRecord *netutils.Ip46
	var lastNoRecordErr4 error
	var lastNoRecordErr6 error
	for _, resolver := range c.bootstrapResolvers {
		ip46, err4, err6 := resolve(ctx, direct.SymmetricDirect, resolver, host, network, race)
		if ip46 == nil {
			ip46 = &netutils.Ip46{}
		}
		if ip46.Ip4.IsValid() || ip46.Ip6.IsValid() {
			return ip46, err4, err6
		}
		if err4 == nil || err6 == nil {
			lastNoRecord = ip46
			lastNoRecordErr4 = err4
			lastNoRecordErr6 = err6
			continue
		}
		if firstErr4 == nil {
			firstErr4 = err4
		}
		if firstErr6 == nil {
			firstErr6 = err6
		}
	}
	if lastNoRecord != nil {
		return lastNoRecord, lastNoRecordErr4, lastNoRecordErr6
	}
	if firstErr4 == nil {
		firstErr4 = fmt.Errorf("bootstrap resolver failed")
	}
	if firstErr6 == nil {
		firstErr6 = firstErr4
	}
	return &netutils.Ip46{}, firstErr4, firstErr6
}

func (c *ControlPlane) cleanupNegativeCaches(now time.Time) {
	nowNano := now.UnixNano()

	// 1. Cleanup real domain negative cache
	c.realDomainNegSet.Range(func(key, value interface{}) bool {
		expiresAt, ok := value.(int64)
		if !ok || nowNano >= expiresAt {
			c.realDomainNegSet.Delete(key)
		}
		return true
	})

	// 2. Cleanup QUIC DCID negative cache
	c.failedQuicDcidCache.CleanupExpired(now)

	// 3. Cleanup TCP sniff negative cache
	c.cleanupTcpSniffNegative(now)
}

type dnsDialerSnapshotKey struct {
	realSrc      netip.AddrPort
	upstream     string
	upstreamIp4  netip.Addr
	upstreamIp6  netip.Addr
	routingPname [16]uint8
	routingMac   [6]uint8
	routingDscp  uint8
}

type dnsDialerSnapshotEntry struct {
	expiresAtUnixNano int64
	dialArg           dialArgument
}

type dnsDialerPenaltyKey struct {
	dialer    *dialer.Dialer
	target    netip.AddrPort
	l4proto   consts.L4ProtoStr
	ipversion consts.IpVersionStr
}

type dnsDialerPenaltyEntry struct {
	expiresAtUnixNano int64
}

type dnsDialerCandidate struct {
	dialArg *dialArgument
	latency time.Duration
}

func pickBetterDnsDialerCandidate(best, candidate *dnsDialerCandidate) *dnsDialerCandidate {
	if candidate == nil {
		return best
	}
	if best == nil || candidate.latency < best.latency {
		return candidate
	}
	return best
}

func chooseDnsDialerCandidate(preferred, penalized *dnsDialerCandidate) (*dnsDialerCandidate, bool) {
	if preferred != nil {
		return preferred, false
	}
	if penalized != nil {
		return penalized, true
	}
	return nil, false
}

func buildDnsDialerSnapshotKeyForSnapshot(snapshot DnsRequestSnapshot, upstream *dns.Upstream) (dnsDialerSnapshotKey, bool) {
	if upstream == nil {
		return dnsDialerSnapshotKey{}, false
	}

	realSrc := snapshot.RealSrc
	// DNS fast path: exempt source port from cache key to enable cache reuse.
	// DNS queries use random source ports; including the port would completely invalidate the cache.
	// Routing decisions do not depend on the DNS query's source port (port is only for transport layer multiplexing).
	if snapshot.RealDst.Port() == 53 {
		realSrc = netip.AddrPortFrom(snapshot.RealSrc.Addr(), 0)
	}

	key := dnsDialerSnapshotKey{
		realSrc:     realSrc,
		upstream:    upstream.String(),
		upstreamIp4: upstream.Ip4,
		upstreamIp6: upstream.Ip6,
	}

	if routingResult := snapshot.routingResultForRoute(); routingResult != nil {
		key.routingPname = routingResult.Pname
		key.routingMac = routingResult.Mac
		key.routingDscp = routingResult.Dscp
	}

	return key, true
}

func (c *ControlPlane) loadDnsDialerSnapshot(key dnsDialerSnapshotKey, now time.Time) (*dialArgument, bool) {
	if dnsDialerSnapshotTTL <= 0 {
		return nil, false
	}

	v, ok := c.dnsDialerSnapshot.Load(key)
	if !ok {
		return nil, false
	}

	entry, ok := v.(*dnsDialerSnapshotEntry)
	if !ok {
		c.dnsDialerSnapshot.Delete(key)
		return nil, false
	}

	if entry.expiresAtUnixNano <= now.UnixNano() {
		c.dnsDialerSnapshot.CompareAndDelete(key, entry)
		return nil, false
	}

	dialArg := entry.dialArg
	if c.isDnsDialArgPenalized(&dialArg, now) {
		c.dnsDialerSnapshot.CompareAndDelete(key, entry)
		return nil, false
	}
	return &dialArg, true
}

func (c *ControlPlane) storeDnsDialerSnapshot(key dnsDialerSnapshotKey, dialArg *dialArgument, now time.Time) {
	if dnsDialerSnapshotTTL <= 0 || dialArg == nil {
		return
	}
	entry := &dnsDialerSnapshotEntry{
		expiresAtUnixNano: now.Add(dnsDialerSnapshotTTL).UnixNano(),
		dialArg:           *dialArg,
	}
	c.dnsDialerSnapshot.Store(key, entry)
}

func (c *ControlPlane) cleanupDnsDialerSnapshot(now time.Time) {
	nowNano := now.UnixNano()
	c.dnsDialerSnapshot.Range(func(key, value any) bool {
		entry, ok := value.(*dnsDialerSnapshotEntry)
		if !ok {
			c.dnsDialerSnapshot.Delete(key)
			return true
		}
		if entry.expiresAtUnixNano <= nowNano {
			c.dnsDialerSnapshot.CompareAndDelete(key, entry)
		}
		return true
	})
}

func (c *ControlPlane) cleanupDnsDialerPenalty(now time.Time) {
	nowNano := now.UnixNano()
	c.dnsDialerPenalty.Range(func(key, value any) bool {
		entry, ok := value.(*dnsDialerPenaltyEntry)
		if !ok {
			c.dnsDialerPenalty.Delete(key)
			return true
		}
		if entry.expiresAtUnixNano <= nowNano {
			c.dnsDialerPenalty.CompareAndDelete(key, entry)
		}
		return true
	})
}

func buildDnsDialerPenaltyKey(dialArg *dialArgument) (dnsDialerPenaltyKey, bool) {
	if dialArg == nil || dialArg.bestDialer == nil || !dialArg.bestTarget.IsValid() {
		return dnsDialerPenaltyKey{}, false
	}
	return dnsDialerPenaltyKey{
		dialer:    dialArg.bestDialer,
		target:    dialArg.bestTarget,
		l4proto:   dialArg.l4proto,
		ipversion: dialArg.ipversion,
	}, true
}

func (c *ControlPlane) isDnsDialArgPenalized(dialArg *dialArgument, now time.Time) bool {
	key, ok := buildDnsDialerPenaltyKey(dialArg)
	if !ok {
		return false
	}
	value, ok := c.dnsDialerPenalty.Load(key)
	if !ok {
		return false
	}
	entry, ok := value.(*dnsDialerPenaltyEntry)
	if !ok {
		c.dnsDialerPenalty.Delete(key)
		return false
	}
	if entry.expiresAtUnixNano <= now.UnixNano() {
		c.dnsDialerPenalty.CompareAndDelete(key, entry)
		return false
	}
	return true
}

func (c *ControlPlane) penalizeDnsDialArg(dialArg *dialArgument, now time.Time) {
	if dnsDialerPenaltyTTL <= 0 {
		return
	}
	key, ok := buildDnsDialerPenaltyKey(dialArg)
	if !ok {
		return
	}
	c.dnsDialerPenalty.Store(key, &dnsDialerPenaltyEntry{
		expiresAtUnixNano: now.Add(dnsDialerPenaltyTTL).UnixNano(),
	})
}

func (c *ControlPlane) startRealDomainNegJanitor() {
	go func() {
		ticker := time.NewTicker(realDomainNegJanitorInterval)
		defer ticker.Stop()
		defer close(c.negJanitorDone)
		for {
			select {
			case <-c.negJanitorStop:
				return
			case <-c.ctx.Done():
				return
			case now := <-ticker.C:
				c.cleanupNegativeCaches(now)
				c.cleanupDnsDialerSnapshot(now)
				c.cleanupDnsDialerPenalty(now)
			}
		}
	}()
}

func (c *ControlPlane) stopRealDomainNegJanitor() {
	c.negJanitorOnce.Do(func() {
		if c.negJanitorStop != nil {
			close(c.negJanitorStop)
		}
		if c.negJanitorDone != nil {
			timer := time.NewTimer(gracefulShutdownWaitTimeout)
			defer timer.Stop()
			select {
			case <-c.negJanitorDone:
			case <-timer.C:
				c.log.Warn("stopRealDomainNegJanitor: timeout waiting for janitor to exit")
			}
		}
	})
}

func (c *ControlPlane) RunReloadRetirementCleanup(staleBeforeNs uint64) {
	if c == nil {
		return
	}
	if c.core != nil {
		err := retryPreviousRoutingEpochCleanup(c.ctx, c.core.finalizePreviousRoutingEpoch, nil)
		if err != nil && c.log != nil {
			c.log.WithError(err).Warnln("[Reload] Failed to release previous routing epoch projection")
		}
	}
	if staleBeforeNs == 0 {
		return
	}

	c.connStateCleanupMu.Lock()
	redirectDeleted := c.cleanupRedirectTrackMapBeforeLocked(0)
	cookieDeleted := c.cleanupCookiePidMapBeforeLocked(0)
	routingHandoffDeleted := c.cleanupRoutingHandoffMapBeforeLocked(0)
	udpStats, tcpStats := c.cleanupConnStateMapBeforeLocked(true, 0)
	c.connStateCleanupMu.Unlock()

	if c.log == nil {
		return
	}
	if redirectDeleted == 0 && cookieDeleted == 0 && routingHandoffDeleted == 0 &&
		udpStats.deleted == 0 && tcpStats.deleted == 0 {
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.Debugln("[Reload] No stale datapath state remained after generation retirement")
		}
		return
	}
	c.log.WithFields(logrus.Fields{
		"redirect_deleted":        redirectDeleted,
		"cookie_pid_deleted":      cookieDeleted,
		"routing_handoff_deleted": routingHandoffDeleted,
		"udp_conn_deleted":        udpStats.deleted,
		"tcp_conn_deleted":        tcpStats.deleted,
	}).Infoln("[Reload] Cleaned stale datapath state after generation retirement")
}

// redirectTrackTimeout is the TTL for redirect entries.
// Redirect entries track which interface and MAC addresses to use for reply traffic.
// A longer timeout is acceptable because these entries are small and the consequence
// of stale entries is minimal (wrong MAC address causes one packet to be misdirected).
const redirectTrackTimeout = 5 * time.Minute

// cleanupRedirectTrackMap iterates through the redirect track map and removes
// entries that haven't been accessed within redirectTrackTimeout.
// This is necessary because redirect_track uses HASH (not LRU) to avoid
// the problem where long-lived connections prevent cleanup of other entries.
func (c *ControlPlane) cleanupRedirectTrackMap() int {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupRedirectTrackMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupRedirectTrackMapBeforeLocked(staleBeforeNs uint64) int {
	// Check if we're shutting down - if stop signal is sent, skip cleanup
	select {
	case <-c.connStateJanitorStop:
		return 0
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.RedirectTrack == nil {
		return 0
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupRedirectTrackMap: failed to get monotonic time: %v", err)
		return 0
	}
	nowNano := ts.Nano()

	timeoutNano := redirectTrackTimeout.Nanoseconds()

	scratch := c.connStateJanitorScratch()
	keysToDelete := takeJanitorDeleteScratch(scratch.redirectDelete)
	totalEntries := 0
	maxAge := int64(0)
	totalAge := int64(0)

	keysOut := ensureJanitorLookupScratch(scratch.redirectKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.redirectValues)
	defer func() {
		scratch.redirectDelete = keepJanitorDeleteScratch(keysToDelete)
		scratch.redirectKeys = keysOut
		scratch.redirectValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	manager, _ := c.controlPlaneSessionManager()
	for {
		count, err := bpf.RedirectTrack.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				key := keysOut[i]
				value := valuesOut[i]
				totalEntries++
				age := nowNano - int64(value.LastSeenNs)
				totalAge += age
				if age > maxAge {
					maxAge = age
				}
				if manager != nil && manager.isRedirectTrackPinned(key) {
					continue
				}
				if age > timeoutNano ||
					(staleBeforeNs > 0 && (value.LastSeenNs == 0 || value.LastSeenNs < staleBeforeNs)) {
					keysToDelete = append(keysToDelete, key)
				}
			}
		}
		if err != nil {
			if !isIgnorableBatchLookupErr(err) {
				c.log.Errorf("cleanupRedirectTrackMap: BatchLookup error: %v", err)
			}
			break
		}
	}

	if len(keysToDelete) > 0 {
		if _, err := BpfMapBatchDelete(bpf.RedirectTrack, keysToDelete); err != nil {
			c.log.Debugf("cleanupRedirectTrackMap: batch delete error: %v", err)
		}
	}

	// Only log when there are actual changes
	if len(keysToDelete) > 0 {
		c.log.Debugf("cleanupRedirectTrackMap: removed %d entries", len(keysToDelete))
	}

	// Alert if map usage is high
	const redirectTrackCapacity = 65536
	if totalEntries > 0 {
		usagePercent := float64(totalEntries) / float64(redirectTrackCapacity) * 100
		if usagePercent > 90 {
			c.log.Warnf("cleanupRedirectTrackMap: map at %.1f%% capacity (%d entries)",
				usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

// cleanupCookiePidMap removes stale cookie->pid metadata that escaped the
// cgroup sock_release backstop. Active sockets refresh last_seen_ns in BPF.
func (c *ControlPlane) cleanupCookiePidMap() int {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupCookiePidMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupCookiePidMapBeforeLocked(staleBeforeNs uint64) int {
	select {
	case <-c.connStateJanitorStop:
		return 0
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.CookiePidMap == nil {
		return 0
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupCookiePidMap: failed to get monotonic time: %v", err)
		return 0
	}
	nowNano := ts.Nano()
	timeoutNano := cookiePidMapTimeout.Nanoseconds()

	scratch := c.connStateJanitorScratch()
	keysToDelete := takeJanitorDeleteScratch(scratch.cookiePidDelete)
	keysOut := ensureJanitorLookupScratch(scratch.cookiePidKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.cookiePidValues)
	totalEntries := 0
	defer func() {
		scratch.cookiePidDelete = keepJanitorDeleteScratch(keysToDelete)
		scratch.cookiePidKeys = keysOut
		scratch.cookiePidValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	for {
		count, err := bpf.CookiePidMap.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				totalEntries++
				age := nowNano - int64(valuesOut[i].LastSeenNs)
				if age > timeoutNano ||
					(staleBeforeNs > 0 && (valuesOut[i].LastSeenNs == 0 || valuesOut[i].LastSeenNs < staleBeforeNs)) {
					keysToDelete = append(keysToDelete, keysOut[i])
				}
			}
		}
		if err != nil {
			if !isIgnorableBatchLookupErr(err) {
				c.log.Errorf("cleanupCookiePidMap: BatchLookup error: %v", err)
			}
			break
		}
	}

	if len(keysToDelete) > 0 {
		if _, err := BpfMapBatchDelete(bpf.CookiePidMap, keysToDelete); err != nil {
			c.log.Debugf("cleanupCookiePidMap: batch delete error: %v", err)
		}
		c.log.Debugf("cleanupCookiePidMap: removed %d entries", len(keysToDelete))
	}

	maxEntries := bpf.CookiePidMap.MaxEntries()
	if totalEntries > 0 && maxEntries > 0 {
		usagePercent := float64(totalEntries) / float64(maxEntries) * 100
		if usagePercent > 90 {
			c.log.Warnf("cleanupCookiePidMap: map at %.1f%% capacity (%d entries)", usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

// cleanupRoutingHandoffMap removes expired tuple-miss routing metadata entries.
// The handoff map is a short-lived bridge for userspace consumers that miss the
// authoritative conn-state publication window.
func (c *ControlPlane) cleanupRoutingHandoffMap() int {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupRoutingHandoffMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupRoutingHandoffMapBeforeLocked(staleBeforeNs uint64) int {
	select {
	case <-c.connStateJanitorStop:
		return 0
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.RoutingHandoffMap == nil {
		return 0
	}

	nowNano, err := monotonicNowNano()
	if err != nil {
		c.log.Errorf("cleanupRoutingHandoffMap: failed to get monotonic time: %v", err)
		return 0
	}

	scratch := c.connStateJanitorScratch()
	keysToDelete := takeJanitorDeleteScratch(scratch.routingHandoffDelete)
	keysOut := ensureJanitorLookupScratch(scratch.routingHandoffKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.routingHandoffValues)
	totalEntries := 0
	defer func() {
		scratch.routingHandoffDelete = keepJanitorDeleteScratch(keysToDelete)
		scratch.routingHandoffKeys = keysOut
		scratch.routingHandoffValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	for {
		count, batchErr := bpf.RoutingHandoffMap.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				totalEntries++
				if routingHandoffExpired(nowNano, valuesOut[i].LastSeenNs) ||
					(staleBeforeNs > 0 && (valuesOut[i].LastSeenNs == 0 || valuesOut[i].LastSeenNs < staleBeforeNs)) {
					keysToDelete = append(keysToDelete, keysOut[i])
				}
			}
		}
		if batchErr != nil {
			if !isIgnorableBatchLookupErr(batchErr) {
				c.log.Errorf("cleanupRoutingHandoffMap: BatchLookup error: %v", batchErr)
			}
			break
		}
	}

	if len(keysToDelete) > 0 {
		if _, deleteErr := BpfMapBatchDelete(bpf.RoutingHandoffMap, keysToDelete); deleteErr != nil {
			c.log.Debugf("cleanupRoutingHandoffMap: batch delete error: %v", deleteErr)
		}
		c.log.Debugf("cleanupRoutingHandoffMap: removed %d expired entries", len(keysToDelete))
	}

	maxEntries := bpf.RoutingHandoffMap.MaxEntries()
	if totalEntries > 0 && maxEntries > 0 {
		usagePercent := float64(totalEntries) / float64(maxEntries) * 100
		if usagePercent > 90 {
			c.log.Warnf("cleanupRoutingHandoffMap: map at %.1f%% capacity (%d entries)", usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

// checkBpfMapHealth monitors map usage and overflow counters for robustness.
// Alerts when maps are approaching capacity or experiencing high overflow rates.
// Accepts pre-read overflow counters to avoid redundant BPF map lookups.
func (c *ControlPlane) checkBpfMapHealth(udpOverflow, tcpOverflow uint64) {
	bpf := c.currentBpf()
	if bpf == nil {
		return
	}

	// Define alert thresholds
	const (
		warnThreshold = 70               // Alert at 70% capacity
		critThreshold = 85               // Critical alert at 85% capacity
		alertCooldown = 30 * time.Second // Minimum time between alerts
	)

	now := time.Now()

	// Alert on significant overflow counts
	if udpOverflow > 0 || tcpOverflow > 0 {
		// Use atomic Int64 to store the last alert time in Unix nanoseconds.
		// Cooldown prevents alert spam.
		nowNano := now.UnixNano()
		last := c.lastBpfOverflowAlertTime.Load()
		if last == 0 || last+int64(alertCooldown) < nowNano {
			if c.lastBpfOverflowAlertTime.CompareAndSwap(last, nowNano) {
				c.log.Warnf("BPF map overflow detected: UDP conn state=%d, TCP conn state=%d. "+
					"Some packets are falling back to slower paths. Check if map capacity is adequate.",
					udpOverflow, tcpOverflow)
			}
		}
	}

	// Estimate map usage by sampling (full iteration is expensive)
	if bpf.ConnStateMap == nil {
		return
	}

	maxEntries := bpf.ConnStateMap.MaxEntries()
	if maxEntries == 0 {
		return
	}

	// If overflow is happening, map is under pressure.
	if udpOverflow > 100 {
		nowNano := now.UnixNano()
		last := c.lastUdpPressureAlertTime.Load()
		if last == 0 || last+int64(alertCooldown) < nowNano {
			if c.lastUdpPressureAlertTime.CompareAndSwap(last, nowNano) {
				c.log.Errorf("CRITICAL: UDP conn state map is under heavy pressure (overflow=%d). "+
					"Configured capacity=%d. Consider increasing conn_state_map capacity or reducing UDP connection timeout.",
					udpOverflow, maxEntries)
			}
		}
	}
	if tcpOverflow > 100 {
		nowNano := now.UnixNano()
		last := c.lastTcpPressureAlertTime.Load()
		if last == 0 || last+int64(alertCooldown) < nowNano {
			if c.lastTcpPressureAlertTime.CompareAndSwap(last, nowNano) {
				c.log.Errorf("CRITICAL: TCP conn state map is under heavy pressure (overflow=%d). "+
					"Configured capacity=%d. Consider increasing conn_state_map capacity or reducing TCP connection timeout.",
					tcpOverflow, maxEntries)
			}
		}
	}
}

func (c *ControlPlane) readMapOverflowCounters(m *ebpf.Map) (udpOverflow uint64, tcpOverflow uint64) {
	if m == nil {
		return 0, 0
	}
	if v, err := readBpfStatsCounter(m, 0); err == nil {
		udpOverflow = v
	}
	if v, err := readBpfStatsCounter(m, 1); err == nil {
		tcpOverflow = v
	}
	return udpOverflow, tcpOverflow
}

func (c *ControlPlane) allowDnsFastPathErrorLog(now time.Time) bool {
	nowNano := now.UnixNano()
	for {
		last := c.lastDnsFastPathErrorLogTime.Load()
		if nowNano-last < int64(dnsFastPathErrorLogInterval) {
			return false
		}
		if c.lastDnsFastPathErrorLogTime.CompareAndSwap(last, nowNano) {
			return true
		}
	}
}

func (c *ControlPlane) allowDnsFastPathServfailLog(now time.Time) bool {
	nowNano := now.UnixNano()
	for {
		last := c.lastDnsFastPathServfailLogTime.Load()
		if nowNano-last < int64(dnsFastPathErrorLogInterval) {
			return false
		}
		if c.lastDnsFastPathServfailLogTime.CompareAndSwap(last, nowNano) {
			return true
		}
	}
}

// readBpfStatsCounter reads a counter from the BPF stats map by key index.
func readBpfStatsCounter(m *ebpf.Map, key uint32) (uint64, error) {
	var value uint64
	if err := m.Lookup(&key, &value); err != nil {
		return 0, err
	}
	return value, nil
}

type Listener struct {
	tcp4Listener net.Listener
	tcp6Listener net.Listener
	packetConn   net.PacketConn
	port         uint16
}

func currentNetnsCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
}

func socketNetnsCookie(conn any) (uint64, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("socket type %T does not expose SyscallConn", conn)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		cookie    uint64
		cookieErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		cookie, cookieErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	}); err != nil {
		return 0, err
	}
	return cookie, cookieErr
}

// ValidateCurrentNetns verifies that every listener socket belongs to the
// caller's current network namespace. BPF socket assignment rejects sockets
// from another namespace, so publishing one would silently black-hole proxy
// traffic even though the listener itself was otherwise healthy.
func (l *Listener) ValidateCurrentNetns() error {
	if l == nil {
		return fmt.Errorf("validate listener netns: nil listener")
	}
	expected, err := currentNetnsCookie()
	if err != nil {
		return fmt.Errorf("read current network namespace cookie: %w", err)
	}
	sockets := []struct {
		name string
		conn any
	}{
		{name: "tcp4", conn: l.tcp4Listener},
		{name: "tcp6", conn: l.tcp6Listener},
		{name: "udp", conn: l.packetConn},
	}
	validated := 0
	for _, socket := range sockets {
		if socket.conn == nil {
			continue
		}
		cookie, err := socketNetnsCookie(socket.conn)
		if err != nil {
			return fmt.Errorf("read %s listener network namespace cookie: %w", socket.name, err)
		}
		if cookie != expected {
			return fmt.Errorf("%s listener belongs to network namespace cookie %d, want %d", socket.name, cookie, expected)
		}
		validated++
	}
	if validated == 0 {
		return fmt.Errorf("validate listener netns: listener has no sockets")
	}
	return nil
}

const udpDualStackListenIP = "::"

func udpDualStackListenAddr(port uint16) string {
	return net.JoinHostPort(udpDualStackListenIP, strconv.Itoa(int(port)))
}

func enableUDPDualStackSocket(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
			sockOptErr = fmt.Errorf("error setting IPV6_V6ONLY socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func udpDualStackListenControl(c syscall.RawConn) error {
	if err := dialer.TproxyControl(c); err != nil {
		return err
	}
	return enableUDPDualStackSocket(c)
}

func udpIngressSupportsBatch(conn *net.UDPConn) bool {
	if conn == nil {
		return false
	}
	_, ok := conn.LocalAddr().(*net.UDPAddr)
	return ok
}

func wakeTCPListener(listener net.Listener) {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok || tcpListener == nil {
		return
	}
	_ = tcpListener.SetDeadline(time.Now())
}

func wakePacketConn(packetConn net.PacketConn) {
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok || udpConn == nil {
		return
	}
	now := time.Now()
	_ = udpConn.SetReadDeadline(now)
	_ = udpConn.SetWriteDeadline(now)
}

func (l *Listener) Close() error {
	if l == nil {
		return nil
	}

	var err error

	if l.tcp4Listener != nil {
		wakeTCPListener(l.tcp4Listener)
		err = l.tcp4Listener.Close()
	}
	if l.tcp6Listener != nil {
		wakeTCPListener(l.tcp6Listener)
		if err2 := l.tcp6Listener.Close(); err2 != nil {
			if err == nil {
				err = err2
			} else {
				err = fmt.Errorf("%w: %v", err, err2)
			}
		}
	}
	if l.packetConn != nil {
		wakePacketConn(l.packetConn)
		if err2 := l.packetConn.Close(); err2 != nil {
			if err == nil {
				err = err2
			} else {
				err = fmt.Errorf("%w: %v", err, err2)
			}
		}
	}
	return err
}

// Clone duplicates the listener sockets so a new control plane generation can
// take over serving before the old generation closes its copies. This allows
// reload to wake the old Accept/Read goroutines without rebinding the port.
func (l *Listener) Clone() (cloned *Listener, err error) {
	if l == nil {
		return nil, fmt.Errorf("nil listener")
	}

	cloned = &Listener{port: l.port}
	defer func() {
		if err != nil && cloned != nil {
			_ = cloned.Close()
		}
	}()

	if l.tcp4Listener != nil {
		cloned.tcp4Listener, err = cloneTCPListener(l.tcp4Listener)
		if err != nil {
			return nil, fmt.Errorf("clone tcp4 listener: %w", err)
		}
	}
	if l.tcp6Listener != nil {
		cloned.tcp6Listener, err = cloneTCPListener(l.tcp6Listener)
		if err != nil {
			return nil, fmt.Errorf("clone tcp6 listener: %w", err)
		}
	}
	if l.packetConn != nil {
		cloned.packetConn, err = cloneUDPPacketConn(l.packetConn)
		if err != nil {
			return nil, fmt.Errorf("clone udp packet conn: %w", err)
		}
	}

	return cloned, nil
}

func cloneTCPListener(listener net.Listener) (net.Listener, error) {
	file, err := dupTCPListenerFile(listener)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	cloned, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

func cloneUDPPacketConn(packetConn net.PacketConn) (net.PacketConn, error) {
	file, err := dupUDPPacketConnFile(packetConn)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	cloned, err := net.FilePacketConn(file)
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

func dupTCPListenerFile(listener net.Listener) (*os.File, error) {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("unexpected tcp listener type %T", listener)
	}
	rawConn, err := tcpListener.SyscallConn()
	if err != nil {
		return nil, err
	}
	return dupRawConnFile(rawConn, "dae-tcp-listener")
}

func dupUDPPacketConnFile(packetConn net.PacketConn) (*os.File, error) {
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("unexpected udp packet conn type %T", packetConn)
	}
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	return dupRawConnFile(rawConn, "dae-udp-packet-conn")
}

func dupRawConnFile(rawConn syscall.RawConn, name string) (*os.File, error) {
	var dupFD int
	var dupErr error
	if err := rawConn.Control(func(fd uintptr) {
		dupFD, dupErr = unix.Dup(int(fd))
		if dupErr == nil {
			unix.CloseOnExec(dupFD)
		}
	}); err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	return os.NewFile(uintptr(dupFD), name), nil
}

func (c *ControlPlane) activatePreparedRuntime() error {
	if c == nil {
		return nil
	}

	c.publishRuntimeStats()
	if err := c.StartPreparedDNSListener(); err != nil {
		c.unpublishRuntimeStats()
		return err
	}
	return nil
}

// shouldSkipDNSFastPathForLocalListenerTraffic returns true only for packets
// that are both addressed to the control plane's own DNS listener and likely
// sourced from the local host itself. External LAN clients querying a
// LAN-bound DNS listener are intercepted via the ingress/TProxy path and must
// continue into the DNS fast path instead of being dropped here.
func shouldSkipDNSFastPathForLocalListenerTraffic(listenAddr string, src, dst netip.AddrPort) bool {
	if listenAddr == "" || dst.Port() != 53 {
		return false
	}

	if dst.Addr().IsLoopback() || dst.Addr().IsUnspecified() {
		_, portStr, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return false
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return false
		}
		return uint16(port) == dst.Port()
	}

	if listenAddr == dst.String() {
		return src.Addr().IsLoopback() || src.Addr().IsUnspecified() || src.Addr() == dst.Addr()
	}

	return false
}

func (c *ControlPlane) Serve(readyChan chan<- bool, listener *Listener) (err error) {
	sentReady := false
	defer func() {
		if !sentReady {
			select {
			case readyChan <- false:
			default:
			}
		}
	}()
	hooks := c.serveLifecycleHooks()
	validateListener := func(listener *Listener) error {
		if listener == nil {
			return fmt.Errorf("nil listener")
		}
		if tcp4, ok := listener.tcp4Listener.(*net.TCPListener); !ok || tcp4 == nil {
			return fmt.Errorf("listener TCP IPv4 socket is not TCP")
		}
		if tcp6, ok := listener.tcp6Listener.(*net.TCPListener); !ok || tcp6 == nil {
			return fmt.Errorf("listener TCP IPv6 socket is not TCP")
		}
		udpConn, ok := listener.packetConn.(*net.UDPConn)
		if !ok || udpConn == nil {
			return fmt.Errorf("listener packet connection is not UDP")
		}
		return nil
	}
	if hooks.ValidateListener != nil {
		validateListener = hooks.ValidateListener
	}
	if err := validateListener(listener); err != nil {
		return err
	}
	publishListenerSockets := c.publishListenerSockets
	if hooks.PublishListenerSockets != nil {
		publishListenerSockets = hooks.PublishListenerSockets
	}
	publishBeforeCommit := c.preparedDatapathCommit && !c.sharedBpfReload && c.core != nil
	if publishBeforeCommit {
		if err := publishListenerSockets(listener); err != nil {
			return err
		}
	}
	commitPreparedDatapath := c.CommitPreparedDatapath
	if hooks.CommitPreparedDatapath != nil {
		commitPreparedDatapath = hooks.CommitPreparedDatapath
	}
	if err := commitPreparedDatapath(); err != nil {
		return err
	}
	if !publishBeforeCommit {
		if err := publishListenerSockets(listener); err != nil {
			return err
		}
	}
	activatePreparedRuntime := c.activatePreparedRuntime
	if hooks.ActivatePreparedRuntime != nil {
		activatePreparedRuntime = hooks.ActivatePreparedRuntime
	}
	if err := activatePreparedRuntime(); err != nil {
		return err
	}
	udpConn, _ := listener.packetConn.(*net.UDPConn)

	c.markReady()
	sentReady = true
	select {
	case readyChan <- true:
	default:
	}
	serveTCP := func(tcpListener net.Listener) {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			lconn, err := tcpListener.Accept()
			if err != nil {
				var netErr net.Error
				if stderrors.As(err, &netErr) && netErr.Timeout() {
					return
				}
				if !commonerrors.IsClosedConnection(err) && !stderrors.Is(err, context.Canceled) {
					c.log.Errorf("Error when accept: %v", err)
				}
				return
			}
			go func(lconn net.Conn) {
				ownership, ok := c.acquireIncomingConnectionLease(lconn)
				if !ok {
					return
				}
				defer ownership.release()
				// Keep the ControlPlane lifecycle context so shutdown/reload can cancel
				// in-flight connection handling. Dial timeout is applied independently
				// inside RouteDialTcp and is not reduced by sniffing time.
				if err := c.handleConn(c.ctx, lconn, ownership); err != nil {
					c.log.Warnln("handleConn:", err)
				}
			}(lconn)
		}
	}
	go serveTCP(listener.tcp4Listener)
	go serveTCP(listener.tcp6Listener)
	go func() {
		processPacket := func(pktBuf pool.PB, src netip.AddrPort, oob []byte) {
			pktDst := RetrieveOriginalDest(oob)
			realDst := common.ConvergeAddrPort(pktDst)
			// IMPORTANT: keep original capacity for pool bucketing.
			// Do not use full-slice cap clipping ([:n:n]) here, otherwise Put()
			// may return the buffer into a wrong size-class and poison the pool.
			convergeSrc := common.ConvergeAddrPort(src)
			flowDecision := ClassifyUdpFlow(convergeSrc, realDst, pktBuf)
			if flowDecision.IsQuicInitial {
				flowDecision = flowDecision.EnsureSnifferSession()
			}
			// Debug:
			// t := time.Now()
			if !c.udpIngressAdmission.tryAcquire() {
				pktBuf.Put()
				return
			}
			task := func() {
				data := pktBuf

				defer data.Put()
				defer c.udpIngressAdmission.release()
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
							lConn:         udpConn,
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

				if e := c.handlePkt(udpConn, data, convergeSrc, realDst, routingResult, flowDecision, false); e != nil {
					c.log.Warnln("handlePkt:", e)
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

			// Session FIFO now takes precedence for generic UDP forwarding.
			// Ordered ingress keeps same-flow packets in the order they were read
			// from the client socket before they reach handlePkt/ue.WriteTo.
			// Direct goroutine dispatch remains only for narrow low-latency
			// exceptions where queue handoff is less valuable than minimal overhead
			// (DNS, SIP/RTP, STUN).
			discardTask := func() {
				c.udpIngressAdmission.release()
				pktBuf.Put()
			}
			if flowDecision.DispatchStrategy() == StrategyDirectGoroutine {
				// DNS, VoIP, and other low-latency exception traffic bypasses the
				// ordered per-flow queue and runs immediately.
				go task()
			} else if !c.submitOrderedUDPIngress(flowDecision.Key, task, discardTask) {
				discardTask()
			}
			// if d := time.Since(t); d > 100*time.Millisecond {
			// 	logrus.Println(d)
			// }
		}

		if udpIngressSupportsBatch(udpConn) {
			batchReader := newUDPIngressBatchReader(udpConn, 0)
			if batchReader == nil {
				goto singleRead
			}
			defer batchReader.Close()

			for {
				select {
				case <-c.ctx.Done():
					return
				default:
				}

				// IPv4 listener fast path: batch read reduces syscall overhead while
				// preserving one exclusive ingress buffer per packet.
				n, err := batchReader.ReadBatch()
				if err != nil {
					if !commonerrors.IsClosedConnection(err) {
						c.log.Errorf("ReadBatchUDP: %v", err)
					}
					break
				}
				for i := range n {
					pktBuf, src, oob, ok := batchReader.Take(i)
					if !ok {
						continue
					}
					processPacket(pktBuf, src, oob)
				}
			}
			return
		}

	singleRead:
		var oob [udpIngressOobSize]byte
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}

			pktBuf := pool.GetFullCap(consts.EthernetMtu)
			n, oobn, _, src, err := udpConn.ReadMsgUDPAddrPort(pktBuf, oob[:])
			if err != nil {
				pktBuf.Put()
				if !commonerrors.IsClosedConnection(err) {
					c.log.Errorf("ReadMsgUDPAddrPort: %v", err)
				}
				break
			}

			// Dual-stack UDP listener path: prefer correctness and IPv6 coverage
			// over batch-read optimization. OOB is consumed synchronously in
			// processPacket, so reusing the stack buffer is safe here.
			processPacket(pktBuf[:n], src, oob[:oobn])
		}
	}()
	c.ActivateCheck()
	<-c.ctx.Done()
	// Log the reason Serve() is exiting to help distinguish intentional
	// shutdown/reload from unexpected context cancellation (e.g. a leaked
	// timeout inherited from the reload preparation context).
	ctxErr := c.ctx.Err()
	if ctxErr != nil {
		c.log.WithFields(logrus.Fields{
			"error": ctxErr.Error(),
		}).Info("[ControlPlane] Serve() exiting; context cancelled")
	}
	return nil
}

// Listen opens the ingress listeners without starting the serving loops.
func (c *ControlPlane) Listen(port uint16) (listener *Listener, err error) {
	// Listen.
	tcpListenConfig := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	udpListenConfig := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return udpDualStackListenControl(c)
		},
	}
	tcp4ListenAddr := net.JoinHostPort(c.listenIp, strconv.Itoa(int(port)))
	tcp4Listener, err := tcpListenConfig.Listen(context.Background(), "tcp4", tcp4ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listenTCP4: %w", err)
	}
	tcp6Listener, err := tcpListenConfig.Listen(context.Background(), "tcp6", net.JoinHostPort("::", strconv.Itoa(int(port))))
	if err != nil {
		_ = tcp4Listener.Close()
		return nil, fmt.Errorf("listenTCP6: %w", err)
	}
	packetConn, err := udpListenConfig.ListenPacket(context.Background(), "udp6", udpDualStackListenAddr(port))
	if err != nil {
		if c.log != nil {
			c.log.WithError(err).Warn("Failed to open dual-stack UDP listener; fallback to IPv4-only UDP listener")
		}
		packetConn, err = tcpListenConfig.ListenPacket(context.Background(), "udp", tcp4ListenAddr)
		if err != nil {
			_ = tcp4Listener.Close()
			_ = tcp6Listener.Close()
			return nil, fmt.Errorf("listenUDP: %w", err)
		}
	}
	listener = &Listener{
		tcp4Listener: tcp4Listener,
		tcp6Listener: tcp6Listener,
		packetConn:   packetConn,
		port:         port,
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()

	return listener, nil
}

func (c *ControlPlane) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	listener, err = c.Listen(port)
	if err != nil {
		return nil, err
	}

	if err = c.Serve(readyChan, listener); err != nil {
		return nil, fmt.Errorf("failed to serve: %w", err)
	}

	return listener, nil
}

func (c *ControlPlane) chooseBestDnsDialerSnapshot(
	ctx context.Context, snapshot DnsRequestSnapshot, dnsUpstream *dns.Upstream,
) (*dialArgument, error) {
	now := time.Now()
	snapshotKey, snapshotEnabled := buildDnsDialerSnapshotKeyForSnapshot(snapshot, dnsUpstream)
	if snapshotEnabled {
		if cachedDialArg, hit := c.loadDnsDialerSnapshot(snapshotKey, now); hit {
			return cachedDialArg, nil
		}
	}

	/// Choose the best l4proto+ipversion dialer, and change taregt DNS to the best ipversion DNS upstream for DNS request.
	// Get available ipversions and l4protos for DNS upstream.
	ipversions, l4protos := dnsUpstream.SupportedNetworks()
	var (
		bestCandidate          *dnsDialerCandidate
		bestPenalizedCandidate *dnsDialerCandidate
	)
	// Get the min latency path.
	networkType := dialer.NetworkType{
		IsDns:           true,
		UdpHealthDomain: dialer.UdpHealthDomainDns,
	}
	for _, ver := range ipversions {
		for _, proto := range l4protos {
			networkType.L4Proto = proto
			networkType.IpVersion = ver
			var dAddr netip.Addr
			switch ver {
			case consts.IpVersionStr_4:
				dAddr = dnsUpstream.Ip4
			case consts.IpVersionStr_6:
				dAddr = dnsUpstream.Ip6
			default:
				return nil, fmt.Errorf("unexpected ipversion: %v", ver)
			}
			outboundIndex, mark, _, err := c.Route(
				snapshot.RealSrc,
				netip.AddrPortFrom(dAddr, dnsUpstream.Port),
				dnsUpstream.Hostname,
				proto.ToL4ProtoType(),
				snapshot.routingResultForRoute(),
			)
			if err != nil {
				return nil, err
			}
			if mark == 0 {
				mark = c.soMarkFromDae
			}
			if int(outboundIndex) >= len(c.outbounds) {
				return nil, fmt.Errorf("bad outbound index: %v", outboundIndex)
			}
			dialerGroup := c.outbounds[outboundIndex]
			// DNS always dial IP.
			d, latency, err := dialerGroup.Select(&networkType, true)
			if err != nil {
				continue
			}
			candidate := &dnsDialerCandidate{
				dialArg: &dialArgument{
					l4proto:      proto,
					ipversion:    ver,
					bestDialer:   d,
					bestOutbound: dialerGroup,
					bestTarget:   netip.AddrPortFrom(dAddr, dnsUpstream.Port),
					mark:         mark,
					mptcp:        c.mptcp,
				},
				latency: latency,
			}
			if c.isDnsDialArgPenalized(candidate.dialArg, now) {
				bestPenalizedCandidate = pickBetterDnsDialerCandidate(bestPenalizedCandidate, candidate)
				continue
			}
			bestCandidate = pickBetterDnsDialerCandidate(bestCandidate, candidate)
			if bestCandidate.latency == 0 {
				break
			}
		}
	}
	selectedCandidate, selectedPenalized := chooseDnsDialerCandidate(bestCandidate, bestPenalizedCandidate)
	if selectedCandidate == nil || selectedCandidate.dialArg == nil {
		return nil, fmt.Errorf("no proper dialer for DNS upstream: %v", dnsUpstream.String())
	}
	selected := *selectedCandidate.dialArg
	switch selected.ipversion {
	case consts.IpVersionStr_4:
		selected.bestTarget = netip.AddrPortFrom(dnsUpstream.Ip4, dnsUpstream.Port)
	case consts.IpVersionStr_6:
		selected.bestTarget = netip.AddrPortFrom(dnsUpstream.Ip6, dnsUpstream.Port)
	}
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		fields := logrus.Fields{
			"ipversions": ipversions,
			"l4protos":   l4protos,
			"upstream":   dnsUpstream.String(),
			"choose":     string(selected.l4proto) + "+" + string(selected.ipversion),
			"use":        selected.bestTarget.String(),
		}
		if selected.bestOutbound != nil {
			fields["outbound"] = selected.bestOutbound.Name
		}
		if selected.bestDialer != nil {
			fields["dialer"] = selected.bestDialer.Property().Name
		}
		if selectedPenalized {
			fields["penalized_fallback"] = true
		}
		c.log.WithFields(fields).Traceln("Choose DNS path")
	}
	if snapshotEnabled && !selectedPenalized {
		c.storeDnsDialerSnapshot(snapshotKey, &selected, now)
	}
	return &selected, nil
}

func (c *ControlPlane) AbortConnections() (err error) {
	return c.abortConnections(true)
}

// AbortPendingConnections stops generation-owned admission and UDP work while
// preserving TCP flows already promoted into the process SessionManager.
func (c *ControlPlane) AbortPendingConnections() error {
	return c.abortConnections(false)
}

func (c *ControlPlane) abortConnections(abortManagedTCP bool) (err error) {
	if c == nil {
		return nil
	}
	connections, flows, errs := c.takeIncomingConnectionsForAbort()
	if abortManagedTCP {
		manager, _ := c.controlPlaneSessionManager()
		if manager != nil {
			// Attempt to migrate surviving TCP flows to the peer
			// generation before falling back to abort. This keeps
			// established connections alive across a same-port reload
			// when the new generation shares a dialer with the old one.
			c.routingEpochPeerMu.RLock()
			peer := c.routingEpochPeer
			c.routingEpochPeerMu.RUnlock()
			if peer != nil {
				newBpf := peer.PeekBpf()
				newEpoch := peer.PolicyEpoch()
				migrated, remaining := manager.MigrateGeneration(
					c.PolicyEpoch(), newEpoch, newBpf, peer.egressRuntime,
				)
				if migrated > 0 && c.log != nil {
					c.log.Infof("[Reload] Migrated %d TCP flows to new generation; %d remaining",
						migrated, remaining)
				}
				// Only abort the flows that could not be migrated.
				if remaining > 0 {
					if abortErr := manager.AbortGeneration(c.PolicyEpoch()); abortErr != nil {
						errs = append(errs, abortErr)
					}
				}
			} else {
				// No peer generation (e.g. fresh start or shutdown):
				// abort all flows immediately.
				if abortErr := manager.AbortGeneration(c.PolicyEpoch()); abortErr != nil {
					errs = append(errs, abortErr)
				}
			}
		}
	}
	c.closeUDPOrderedDispatcher()
	c.udpIngressAdmission.closeAndWait()
	c.waitUDPOrderedDispatcher()
	// Wait for endpoint creation already admitted by this generation before
	// scanning the shared pool. New creation attempts are rejected once closed.
	c.udpEndpointAdmission.closeAndWait()

	for _, conn := range connections {
		if cerr := conn.Close(); cerr != nil {
			errs = append(errs, cerr)
		}
	}
	for _, egress := range flows {
		if egress == nil {
			continue
		}
		if cerr := egress.Close(); cerr != nil && !commonerrors.IsClosedConnection(cerr) {
			errs = append(errs, cerr)
		}
	}
	if c.core != nil {
		if udpErr := DefaultUdpEndpointPool.AbortEndpointsOwnedBy(c.core); udpErr != nil {
			errs = append(errs, udpErr)
		}
	}
	c.closeUDPReplyDispatcher()
	c.waitUDPReplyDispatcher()

	return stderrors.Join(errs...)
}

// DetachBpfHooks immediately detaches all BPF hooks from the system.
// This should be called first when receiving SIGTERM to ensure network is restored
// even if the rest of the shutdown process takes too long and gets SIGKILL'd.
// This is safe to call multiple times - subsequent calls will be no-ops.
func (c *ControlPlane) DetachBpfHooks() error {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.DetachBpfHooks()
}

// MarkRetired signals that this generation is no longer authoritative for
// outbound liveness. After this call, outboundAliveChangeCallback returns
// early and will not write to the shared OutboundConnectivityMap BPF map.
// This must be called before the drain period starts so that stale health
// check results from the retiring generation cannot clobber the successor's
// map entries.
func (c *ControlPlane) MarkRetired() {
	if c == nil || c.core == nil {
		return
	}
	c.core.markOutboundConnectivityRetired()
}

// ResetGlobalUdpState clears all global UDP-related pools.
// Called during process shutdown to stop background goroutines (janitors).
func ResetGlobalUdpState() {
	DefaultUdpEndpointPool.Reset()
	DefaultAnyfromPool.Reset()
	DefaultUdpTaskPool.Close()
	DefaultPacketSnifferSessionMgr.Close() // Close() stops janitor goroutines; safe for shutdown path
	ResetUdpLogLimiters()
}

// ResetGlobalUdpFlowState evicts stale UDP flow state for a fresh-datapath
// reload. Unlike ResetGlobalUdpState it only clears pooled endpoints, anyfrom
// connections and sniffer sessions — each of which may still reference the
// retiring generation's dialer, outbound group and cached routing result —
// without stopping the background janitor goroutines, so the successor
// generation reuses the same pool singletons.
//
// This must be called during a fresh-datapath cutover, after the old
// generation stops accepting traffic and before the new generation starts
// serving, so incoming flows are routed by the fresh policy instead of
// inheriting stale decisions bound to the previous (now detached) maps.
func ResetGlobalUdpFlowState() {
	DefaultUdpEndpointPool.Reset()
	DefaultAnyfromPool.Reset()
	DefaultPacketSnifferSessionMgr.Reset()
}

func (c *ControlPlane) closeTail() error {
	var errs []error

	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			errs = append(errs, e)
		}
	}
	if c.egressRuntime != nil {
		if err := c.egressRuntime.releaseOwner(); err != nil {
			errs = append(errs, err)
		}
	}

	// Clear sync.Maps to prevent memory leak on reload.
	// These maps accumulate data over time and must be explicitly cleared.
	c.realDomainNegSet.Range(func(key, value any) bool {
		c.realDomainNegSet.Delete(key)
		return true
	})
	c.dnsDialerSnapshot.Range(func(key, value any) bool {
		c.dnsDialerSnapshot.Delete(key)
		return true
	})
	c.dnsDialerPenalty.Range(func(key, value any) bool {
		c.dnsDialerPenalty.Delete(key)
		return true
	})
	c.clearAllTcpSniffNegative()
	if c.failedQuicDcidCache != nil {
		c.failedQuicDcidCache.Clear()
		if getFailedQuicDcidCache() == c.failedQuicDcidCache {
			SetFailedQuicDcidCache(nil)
		}
	}

	// Note: inConnections is cleared by AbortConnections() which should be called before Close()
	// Note: core.Close() is invoked synchronously by ControlPlane.Close() BEFORE this
	// function runs, so that BPF hooks and maps are guaranteed to be released before
	// the retirement gate signals completion. Keeping it here would leave hook detach
	// subject to the deferred-cleanup timeout and risk racing with the next reload.

	// Note: ResetGlobalUdpState() is intentionally NOT called here.
	// Global UDP pools (DefaultUdpEndpointPool, DefaultUdpTaskPool, etc.)
	// are shared across reload generations. Calling ResetGlobalUdpState()
	// during closeTail would corrupt the new generation's live UDP state.
	// The caller (shutdownAfterSignalWithHandoff in cmd/run.go) calls
	// ResetGlobalUdpState() after all control planes have been closed
	// during process termination.

	c.releaseRetainedState()

	return stderrors.Join(errs...)
}

// releaseRetainedState releases the resources this generation still owns after
// its datapath has been torn down.
//
// It deliberately does not nil out routingMatcher, outbounds, dnsController,
// core, egressRuntime, sessionManager or the UDP dispatchers. SessionManager
// lets established flows outlive the generation that created them, and those
// flow goroutines keep reading exactly those fields. Clearing them races with
// live readers and turns a reload into a nil dereference. Dropping the fields
// buys nothing either: once the generation itself is unreachable, everything it
// points at is collected with it.
func (c *ControlPlane) releaseRetainedState() {
	if c == nil {
		return
	}

	if handoff, owned := c.takeDNSHandoffController(); owned && handoff != nil {
		_ = handoff.Close()
	}
	c.controlPlaneDatapathJanitor.releaseRetainedState()
	c.ClearReloadDnsCacheSource()
}

func (c *ControlPlane) Close() (err error) {
	if c == nil {
		return nil
	}
	c.closeRoutingEpochExecution()
	c.ClearReloadDnsCacheSource()

	c.closeOnce.Do(func() {
		c.unpublishActiveControlPlane()
		c.unpublishRuntimeStats()
		if c.cancel != nil {
			c.cancel()
		}
		if manager, owned := c.controlPlaneSessionManager(); owned && manager != nil {
			c.closeErr = stderrors.Join(c.closeErr, manager.Close())
		}
		c.closeUDPOrderedDispatcher()
		c.udpIngressAdmission.closeAndWait()
		c.waitUDPOrderedDispatcher()
		c.closeUDPReplyDispatcher()
		c.waitUDPReplyDispatcher()

		var stopWg sync.WaitGroup
		stopWg.Add(2)
		go func() {
			defer stopWg.Done()
			c.stopRealDomainNegJanitor()
		}()
		go func() {
			defer stopWg.Done()
			c.stopConnStateJanitor()
		}()
		stopWg.Wait()

		// Close the core (BPF hooks + maps) synchronously WITHOUT timeout.
		// core.Close() detaches BPF hooks via netlink and must complete before
		// Close() returns; the retirement gate uses Close() completion as the
		// signal that the old generation's TC filters and maps are released.
		// If this were left inside the timed closeTail goroutine, a timeout
		// would let the retirement gate release while old-generation hook
		// detach is still running, racing with the next reload's datapath.
		// Netlink socket timeout (set at core init) bounds individual calls.
		var coreErr error
		if c.core != nil {
			coreErr = c.core.Close()
		}

		done := make(chan error, 1)
		go func() {
			done <- c.closeTail()
		}()

		timer := time.NewTimer(controlPlaneDeferredCleanupTimeout)
		defer timer.Stop()

		select {
		case tailErr := <-done:
			c.closeErr = stderrors.Join(c.closeErr, coreErr, tailErr)
		case <-timer.C:
			timeoutErr := fmt.Errorf("control plane close tail timed out after %v", controlPlaneDeferredCleanupTimeout)
			if c.log != nil {
				c.log.WithError(timeoutErr).Warn("ControlPlane.Close: continuing while tail cleanup finishes in background")
			}
			c.closeErr = stderrors.Join(c.closeErr, coreErr, timeoutErr)
		}
	})
	c.UnlinkRoutingEpochPeer(nil)

	return c.closeErr
}

// StopDNSListener stops the DNS listener if it's running
func (c *ControlPlane) StopDNSListener() error {
	if c == nil {
		return nil
	}
	return c.controlPlaneDNSRuntime.stopOwnedDNSListener()
}

// RestartDNSListener restarts the control plane's DNS listener after it was
// explicitly stopped during reload preparation.
func (c *ControlPlane) RestartDNSListener() error {
	if c == nil {
		return nil
	}
	return c.restartDNSListener(&c.deferFuncs, c.stopOwnedDNSListener)
}

func (c *ControlPlane) ReuseDNSListenerFrom(previous *ControlPlane) bool {
	if c == nil || previous == nil {
		return false
	}
	return c.reuseDNSListenerFrom(&previous.controlPlaneDNSRuntime, c, &c.deferFuncs, c.stopOwnedDNSListener)
}

func (c *ControlPlane) ReuseDNSControllerFrom(previous *ControlPlane) bool {
	if c == nil || previous == nil {
		return false
	}
	return c.reuseDNSControllerFrom(
		&previous.controlPlaneDNSRuntime,
		c.dnsControllerOption(),
		c.dnsRouting,
		c.log,
		previous.SetDNSHandoffController,
	)
}

func (c *ControlPlane) SetPreparedDNSStartHook(hook func() error) {
	if c == nil {
		return
	}
	c.setPreparedDNSStartHook(hook)
}

func (c *ControlPlane) SetPreparedDNSReuseHook(hook func() error) {
	if c == nil {
		return
	}
	c.setPreparedDNSReuseHook(hook)
}

func (c *ControlPlane) WaitDNSUpstreamsReady(timeout time.Duration) error {
	if c == nil {
		return nil
	}
	return c.waitDNSUpstreamsReady(c.ctx, timeout)
}

func (c *ControlPlane) WaitDNSUpstreamAvailable(timeout time.Duration) error {
	if c == nil {
		return nil
	}
	return c.waitDNSUpstreamAvailable(c.ctx, timeout)
}

func (c *ControlPlane) StartPreparedDNSListener() error {
	if c == nil {
		return nil
	}
	return c.startPreparedDNSListener(c.ctx, c.log, &c.deferFuncs, c.stopOwnedDNSListener)
}
