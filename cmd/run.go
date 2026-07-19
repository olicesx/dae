/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/daedns"
	outbounddialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

const (
	PidFilePath                    = "/var/run/dae.pid"
	SignalProgressFilePath         = "/var/run/dae.progress"
	reloadTotalSwitchBudget        = 10 * time.Second
	controlPlaneRetirementLogEvery = 5 * time.Second
	reloadPrepareTimeout           = 45 * time.Second
	reloadReadyTimeout             = 45 * time.Second
)

const (
	reloadBusyActiveMessage   = "reload already in progress"
	reloadBusyRetiringMessage = "reload request ignored: previous reload is still retiring old generation"
)

var (
	CheckNetworkLinks = []string{
		"http://edge.microsoft.com/captiveportal/generate_204",
		"http://www.gstatic.com/generate_204",
		"http://www.qualcomm.cn/generate_204",
	}
	beginReloadProxyFailureSuppression = outbounddialer.BeginReloadProxyFailureSuppression
	endReloadProxyFailureSuppression   = outbounddialer.EndReloadProxyFailureSuppression
	resetReloadProxyRuntimeState       = outbounddialer.ResetGlobalProxyStateForReload
	listenControlPlaneFunc             = func(c *control.ControlPlane, port uint16) (*control.Listener, error) {
		listener, err := c.Listen(port)
		if err != nil {
			return nil, err
		}
		if err := listener.ValidateCurrentNetns(); err != nil {
			_ = listener.Close()
			return nil, err
		}
		return listener, nil
	}
	cloneControlListenerFunc = func(listener *control.Listener) (*control.Listener, error) { return listener.Clone() }
	linkRoutingEpochPeerFunc = func(oldPlane, newPlane *control.ControlPlane) error { return oldPlane.LinkRoutingEpochPeer(newPlane) }
	serveControlPlaneFunc    = func(c *control.ControlPlane, readyChan chan<- bool, listener *control.Listener) error {
		return c.Serve(readyChan, listener)
	}
	restoreListenerSocketsFunc = func(c *control.ControlPlane, listener *control.Listener) error {
		return c.PublishListenerSockets(listener)
	}
	restoreReloadDatapathFunc = func(c *control.ControlPlane) error {
		return c.RebuildReloadDatapath()
	}
	restoreDNSListenerFunc = func(c *control.ControlPlane) error {
		return c.RestartDNSListener()
	}
	withDaeNetnsRequiredFunc = func(op string, f func() error) error {
		return control.GetDaeNetns().WithRequired(op, f)
	}
)

type signalShutdownListener interface {
	Close() error
}

type signalShutdownControlPlane interface {
	DetachBpfHooks() error
	AbortConnections() error
	Close() error
}

type signalShutdownNetns interface {
	Close() error
}

type signalShutdownStagedHandoff struct {
	oldListener     signalShutdownListener
	oldControlPlane signalShutdownControlPlane
	oldCancel       context.CancelFunc
	newListener     signalShutdownListener
	newControlPlane signalShutdownControlPlane
	newCancel       context.CancelFunc
}

type reloadRequest struct {
	isSuspend       bool
	requestedAt     time.Time
	requestedAtMono uint64
}

type reloadRetirementControlPlane interface {
	ActiveSessionCount() int
	DrainIdleCh() <-chan struct{}
}

type retirementDrainPlane interface {
	reloadRetirementControlPlane
	AbortConnections() error
	AbortPendingConnections() error
	StopRoutingEpochExecution()
}

type controlPlaneDrainWaitResult uint8

const (
	controlPlaneDrainIdle controlPlaneDrainWaitResult = iota
	controlPlaneDrainCanceled
	controlPlaneDrainTimeout
)

type reloadReadyWaitResult uint8

const (
	reloadReadyWaitReady reloadReadyWaitResult = iota
	reloadReadyWaitFailed
	reloadReadyWaitSignal
	reloadReadyWaitTimeout
)

func canRecoverReloadReadinessFailure(result reloadReadyWaitResult) bool {
	return result == reloadReadyWaitFailed
}

type stagedReloadHandoff struct {
	preparedGeneration    *runtimeGeneration
	oldControlPlane       *control.ControlPlane
	oldCancel             context.CancelFunc
	oldConf               *config.Config
	oldListener           *control.Listener
	newControlPlane       *control.ControlPlane
	newCancel             context.CancelFunc
	newListener           *control.Listener
	abortConnections      bool
	hasOverlap            bool
	freshDatapath         bool
	preparedDNSHandoff    bool
	bpfTransferred        bool
	sharedBpfHandoff      bool
	routingEpochReady     bool
	oldConnectivityPaused bool
	freshCutoverStarted   bool
	flowDatapathAdopted   bool
	oldRuntimeStopped     bool
	dnsControllerMoved    bool
	dnsListenerMoved      bool
	oldDNSListenerActive  bool
	hookFlipCommitted     bool
	provisionalOwner      bool
}

func tryQueueReloadRequest(
	log *logrus.Logger,
	reloadReqs chan<- reloadRequest,
	reloadActive *atomic.Bool,
	reloadPending *atomic.Bool,
	req reloadRequest,
) bool {
	if reloadPending != nil && !reloadPending.CompareAndSwap(false, true) {
		if log != nil {
			log.Warnln("[Reload] Reload already in progress or handoff pending; ignoring this signal")
		}
		restoreRejectedReloadProgress(reloadActive, false)
		return false
	}
	beginReloadProxyFailureSuppression()
	select {
	case reloadReqs <- req:
		return true
	default:
		if reloadPending != nil {
			reloadPending.Store(false)
		}
		endReloadProxyFailureSuppression()
		if log != nil {
			log.Warnln("[Reload] Last reload request still processing, ignore this one")
		}
		restoreRejectedReloadProgress(reloadActive, true)
		return false
	}
}

var setRunSignalProgress = func(code byte, content string) error {
	return writeSignalProgressFile(SignalProgressFilePath, code, content)
}

var getRunSignalProgress = func() (byte, string, error) {
	return readSignalProgressFile(SignalProgressFilePath)
}

func restoreRejectedReloadProgress(reloadActive *atomic.Bool, forceProcessing bool) {
	if forceProcessing || (reloadActive != nil && reloadActive.Load()) {
		_ = setRunSignalProgress(consts.ReloadBusy, reloadBusyActiveMessage)
		return
	}
	_ = setRunSignalProgress(consts.ReloadBusy, reloadBusyRetiringMessage)
}

func clearRejectedReloadProgress() {
	code, _, err := getRunSignalProgress()
	if err != nil {
		return
	}
	if code == consts.ReloadBusy {
		_ = setRunSignalProgress(consts.ReloadDone, "")
	}
}

func clearReloadPending(flag *atomic.Bool) {
	if flag != nil {
		flag.Store(false)
	}
	endReloadProxyFailureSuppression()
	clearRejectedReloadProgress()
}

func shouldUseStagedHotHandoff(freshDatapathReload, listenerPresent bool) bool {
	return !freshDatapathReload && listenerPresent
}

func shouldStreamStagedDnsCache(
	stagedHotHandoff,
	routingEpochEnabled,
	dnsConfigUnchanged,
	ipVersionPreferenceUnchanged bool,
) bool {
	return stagedHotHandoff && routingEpochEnabled && dnsConfigUnchanged && ipVersionPreferenceUnchanged
}

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

func releaseReloadPendingAfterRetirement(flag *atomic.Bool, retirementDone <-chan struct{}) {
	if flag == nil {
		endReloadProxyFailureSuppression()
		return
	}
	if retirementDone == nil {
		clearReloadPending(flag)
		return
	}
	// The routing epoch bridge has only two reusable slots. Keep reloadPending
	// set until the retiring generation has stopped execution and closed, so a
	// third staged reload cannot overwrite a slot that still belongs to a
	// draining flow.
	go func() {
		<-retirementDone
		clearReloadPending(flag)
	}()
}

func remainingReloadRetirementBudget(startedAt time.Time, budget time.Duration) time.Duration {
	if budget <= 0 {
		return 0
	}
	if startedAt.IsZero() {
		return budget
	}
	remaining := budget - time.Since(startedAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

func monotonicNowNano() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Nano())
}

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file of dae.(required)")
	runCmd.PersistentFlags().StringVar(&logFile, "logfile", "", "Log file to write. Empty means writing to stdout and stderr.")
	runCmd.PersistentFlags().IntVar(&logFileMaxSize, "logfile-maxsize", 30, "Unit: MB. The maximum size in megabytes of the log file before it gets rotated.")
	runCmd.PersistentFlags().IntVar(&logFileMaxBackups, "logfile-maxbackups", 3, "The maximum number of old log files to retain.")
	runCmd.PersistentFlags().BoolVar(&disableTimestamp, "disable-timestamp", false, "Disable timestamp.")
	runCmd.PersistentFlags().BoolVar(&disablePidFile, "disable-pidfile", false, "Not generate /var/run/dae.pid.")
	runCmd.PersistentFlags().BoolVar(&disableAuthSudo, "disable-sudo", false, "Disable sudo prompt ,may cause startup failure due to insufficient permissions")
	rand.Shuffle(len(CheckNetworkLinks), func(i, j int) {
		CheckNetworkLinks[i], CheckNetworkLinks[j] = CheckNetworkLinks[j], CheckNetworkLinks[i]
	})
}

var (
	cfgFile           string
	logFile           string
	logFileMaxSize    int
	logFileMaxBackups int
	disableTimestamp  bool
	disablePidFile    bool
	disableAuthSudo   bool

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "To run dae in the foreground.",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				logrus.Fatalln("Argument \"--config\" or \"-c\" is required but not provided.")
			}
			if disableAuthSudo && os.Geteuid() != 0 {
				logrus.Fatalln("Auto-sudo is disabled and current user is not root.")
			}
			// Require "sudo" if necessary.
			if !disableAuthSudo {
				internal.AutoSu()
			}

			// Read config from --config cfgFile.
			conf, includes, err := readConfig(cfgFile)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"err": err,
				}).Fatalln("Failed to read config")
			}

			var logOpts *lumberjack.Logger
			if logFile != "" {
				logOpts = &lumberjack.Logger{
					Filename:   logFile,
					MaxSize:    logFileMaxSize,
					MaxAge:     0,
					MaxBackups: logFileMaxBackups,
					LocalTime:  true,
					Compress:   true,
				}
			}
			log := logrus.New()
			logger.SetLogger(log, conf.Global.LogLevel, disableTimestamp, logOpts)
			logger.SetLogger(logrus.StandardLogger(), conf.Global.LogLevel, disableTimestamp, logOpts)

			log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			if err := Run(log, conf, []string{filepath.Dir(cfgFile)}); err != nil {
				log.Fatalln(err)
			}
		},
	}
)

func Run(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string) (err error) {
	return newRunner(log, conf, externGeoDataDirs).Run()
}

func (r *Runner) Run() (err error) {
	log := r.log
	conf := r.conf
	externGeoDataDirs := r.externGeoDataDirs
	processSessions := control.NewSessionManager(context.Background())
	defer func() {
		err = errors.Join(err, processSessions.Close())
	}()

	phase1Observability, err := enablePhase1ObservabilityFromEnvironment()
	if err != nil {
		return err
	}
	if phase1Observability != nil {
		defer phase1Observability.Disable()
	}
	phase4DecisionShadow, err := enablePhase4DecisionShadowFromEnvironment()
	if err != nil {
		return err
	}
	if phase4DecisionShadow != nil {
		defer phase4DecisionShadow.Disable()
	}
	semanticRefactorFeatures, err := enableSemanticRefactorFeaturesFromEnvironment()
	if err != nil {
		return err
	}
	if semanticRefactorFeatures != nil {
		defer semanticRefactorFeatures.Disable()
	}
	routingEpochHandoffEnabled := semanticRefactorFeatures.Enabled(control.SemanticRefactorFeatureRoutingEpoch)

	var currCancel context.CancelFunc

	// Remove AbortFile at beginning.
	_ = os.Remove(AbortFile)

	// New ControlPlane.
	ctx, cancel := context.WithCancel(context.Background())
	currCancel = cancel
	configureTransparentHugePages(log, conf.Global.DisableTHP)
	configureGcMemoryLimit(log)
	c, err := newControlPlane(ctx, log, nil, nil, conf, externGeoDataDirs, false, false)
	if err != nil {
		cancel()
		return err
	}
	if err = c.AttachSessionManager(processSessions); err != nil {
		cancel()
		_ = c.Close()
		return fmt.Errorf("attach process session manager: %w", err)
	}
	runtimeSupervisor := newRuntimeSupervisor(&runtimeGeneration{
		controlPlane: c,
		cancel:       currCancel,
		conf:         conf,
	})

	// Serve tproxy TCP/UDP server util signals.
	listener, listenErr := listenControlPlaneInDaeNetns(c, conf.Global.TproxyPort)
	if listenErr != nil {
		cancel()
		_ = c.Close()
		return listenErr
	}
	if supervisorErr := runtimeSupervisor.replaceActive(&runtimeGeneration{
		controlPlane: c,
		listener:     listener,
		cancel:       currCancel,
		conf:         conf,
	}); supervisorErr != nil {
		_ = listener.Close()
		cancel()
		_ = c.Close()
		return fmt.Errorf("record initial runtime generation: %w", supervisorErr)
	}
	var pprofServer *http.Server
	if conf.Global.PprofPort != 0 {
		registerDaeDebugHandlers()
		pprofAddr := fmt.Sprintf("localhost:%d", conf.Global.PprofPort)
		pprofServer = &http.Server{Addr: pprofAddr, Handler: nil}
		go func() { _ = pprofServer.ListenAndServe() }()
	}
	sigs := make(chan os.Signal, 1)
	// Keep internal wake-ups separate so queued OS signals cannot mask reload handoff notifications.
	runStateChanges := make(chan struct{}, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)

	go func() {
		readyChan := make(chan bool, 1)
		go func() {
			if <-readyChan {
				_ = sdnotify.Ready()
				if !disablePidFile {
					_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0644)
				}
				_ = setRunSignalProgress(consts.ReloadDone, "")
			} else {
				log.Warn("Initialization failed; not signaling readiness to supervisor")
			}
		}()
		defer func() {
			select {
			case readyChan <- false:
			default:
			}
		}()
		if runErr := withDaeNetnsRequiredFunc("serve in dae netns", func() error {
			if serveErr := serveControlPlaneFunc(c, readyChan, listener); serveErr != nil {
				log.Errorln("Serve:", serveErr)
				return serveErr
			}
			return nil
		}); runErr != nil {
			log.Errorln("GetDaeNetns.With:", runErr)
		}
		notifyRunStateChange(runStateChanges)
	}()

	reloadReqs := make(chan reloadRequest, 1)
	reloadManager := newReloadManager(reloadReqs, runStateChanges, sigs)
	fastExit := false
	var fatalRunErr error
	failRun := func(err error) {
		fastExit = true
		fatalRunErr = errors.Join(fatalRunErr, err)
		reloadManager.setReloadError(fatalRunErr)
		_ = setRunSignalProgress(consts.ReloadError, fatalRunErr.Error())
	}

	go func() {
		for req := range reloadManager.reloadReqs {
			reloadManager.reloadActive.Store(true)
			req = reloadManager.coalesceReloadRequest(req)
			reloadStartedAt := req.requestedAt
			reloadStartedAtMono := req.requestedAtMono

			if req.isSuspend {
				log.Warnln("[Reload] Received suspend signal; prepare to suspend")
			} else {
				log.Warnln("[Reload] Received reload signal; prepare to reload")
			}
			_ = sdnotify.Reloading()
			_ = setRunSignalProgress(consts.ReloadProcessing, "")
			reloadManager.setReloadError(nil)
			resetReloadProxyRuntimeState()

			// Load new config.
			abortConnections := os.Remove(AbortFile) == nil
			log.Warnln("[Reload] Load new config")
			var newConf *config.Config
			if req.isSuspend {
				newConf, err = emptyConfig()
				if err != nil {
					log.WithFields(logrus.Fields{
						"err": err,
					}).Errorln("[Reload] Failed to reload")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, err.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					continue
				}
				newConf.Global = deepcopy.Copy(conf.Global).(config.Global)
				newConf.Global.WanInterface = nil
				newConf.Global.LanInterface = nil
				newConf.Global.LogLevel = "warning"
			} else {
				var includes []string
				newConf, includes, err = readConfig(cfgFile)
				if err != nil {
					log.WithFields(logrus.Fields{
						"err": err,
					}).Errorln("[Reload] Failed to reload")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, err.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					continue
				}
				log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			}
			// New logger.
			oldLogOutput := log.Out
			log = logrus.New()
			logger.SetLogger(log, newConf.Global.LogLevel, disableTimestamp, nil)
			logger.SetLogger(logrus.StandardLogger(), newConf.Global.LogLevel, disableTimestamp, nil)
			log.SetOutput(oldLogOutput) // NOTE: Restore log output after creating new logger during reload.
			logrus.SetOutput(oldLogOutput)
			if !req.isSuspend {
				if deferred := preserveReloadInterfaceBindings(conf, newConf); len(deferred) > 0 {
					log.WithField("bindings", strings.Join(deferred, ",")).Warnln("[Reload] Deferring interface removal or role change until cold start to preserve established flows")
				}
			}

			portChanged := conf.Global.TproxyPort != newConf.Global.TproxyPort
			datapathChanged := bpfDatapathChanged(conf, newConf)
			freshDatapathReload := portChanged || datapathChanged
			stagedHotHandoff := shouldUseStagedHotHandoff(freshDatapathReload, listener != nil)
			freshDatapathHandoff := freshDatapathReload && listener != nil
			if !reloadManager.beginReloadTransition() {
				reloadErr := errRuntimeSupervisorClosed
				reloadManager.setReloadError(reloadErr)
				log.WithError(reloadErr).Warnln("[Reload] Ignoring reload while shutdown is in progress")
				reloadManager.reloadActive.Store(false)
				clearReloadPending(&reloadManager.reloadPending)
				continue
			}
			transitionHeld := true
			releaseReloadTransition := func() {
				if transitionHeld {
					reloadManager.endReloadTransition()
					transitionHeld = false
				}
			}

			// New control plane.
			obj := c.PeekBpf()
			if freshDatapathReload {
				obj = nil
			} else if !stagedHotHandoff {
				obj = c.EjectBpf()
			}
			var reloadBpf any
			if obj != nil {
				reloadBpf = obj
			}
			if portChanged {
				log.Warnf("[Reload] Tproxy port changed from %d to %d; will perform a full reload of eBPF programs", conf.Global.TproxyPort, newConf.Global.TproxyPort)
			} else if datapathChanged {
				log.Warnln("[Reload] Kernel datapath input changed (interface/somark/map-size); will perform a fresh datapath handoff")
			}

			dnsConfigUnchanged := dnsConfigEqual(conf, newConf)
			ipVersionPreferenceUnchanged := conf.Dns.IpVersionPrefer == newConf.Dns.IpVersionPrefer
			streamStagedDnsCache := shouldStreamStagedDnsCache(
				stagedHotHandoff,
				routingEpochHandoffEnabled,
				dnsConfigUnchanged,
				ipVersionPreferenceUnchanged,
			)
			var dnsCache map[string]*control.DnsCache
			if ipVersionPreferenceUnchanged && !streamStagedDnsCache {
				// Only keep dns cache when ip version preference not change.
				dnsCache = c.CloneDnsCache()
			}
			rollbackDNSCache := dnsCache
			var stagedListener *control.Listener

			if stagedHotHandoff {
				log.Warnln("[Reload] Prepare staged same-port handoff")
				ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
				newC, prepareErr := newPreparedControlPlane(ctx, log, reloadBpf, dnsCache, newConf, externGeoDataDirs, dnsConfigUnchanged, true)
				dnsCache = nil
				if prepareErr == nil {
					prepareErr = newC.AttachSessionManager(processSessions)
					if prepareErr != nil {
						_ = newC.Close()
					}
				}
				if prepareErr != nil {
					reloadErr := wrapReloadTimeoutError("prepare staged reload", prepareErr, reloadPrepareTimeout)
					reloadManager.setReloadError(reloadErr)
					cancel()
					log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					releaseReloadTransition()
					continue
				}

				stagedListener, listenErr := cloneControlListenerFunc(listener)
				if listenErr != nil {
					reloadErr := fmt.Errorf("clone listener: %w", listenErr)
					reloadManager.setReloadError(reloadErr)
					if closeErr := (&runtimeGeneration{controlPlane: newC, cancel: cancel}).cleanup(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Failed to close prepared staged generation")
					}
					log.WithError(reloadErr).Errorln("[Reload] Failed to stage listener; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					releaseReloadTransition()
					continue
				}

				oldC := c
				oldCancel := currCancel
				oldConf := conf
				oldListener := listener
				if routingEpochHandoffEnabled {
					if err := linkRoutingEpochPeerFunc(oldC, newC); err != nil {
						reloadErr := fmt.Errorf("link staged routing epochs: %w", err)
						reloadManager.setReloadError(reloadErr)
						if closeErr := stagedListener.Close(); closeErr != nil {
							log.WithError(closeErr).Warnln("[Reload] Failed to close staged listener after epoch link failure")
						}
						if closeErr := (&runtimeGeneration{controlPlane: newC, cancel: cancel}).cleanup(); closeErr != nil {
							log.WithError(closeErr).Warnln("[Reload] Failed to close staged generation after epoch link failure")
						}
						log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
						_ = sdnotify.Ready()
						_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
						reloadManager.reloadActive.Store(false)
						clearReloadPending(&reloadManager.reloadPending)
						releaseReloadTransition()
						continue
					}
				}

				if routingEpochHandoffEnabled && ipVersionPreferenceUnchanged {
					if streamStagedDnsCache {
						newC.SetReloadDnsCacheStreamSource(oldC.StreamDnsCacheForReload, oldC.PolicyIdentity().Hash())
					} else {
						newC.SetReloadDnsCacheSource(oldC.CloneDnsCache)
					}
				}
				hasOverlap := newC.InheritDialerHealthFrom(oldC)
				configureTransparentHugePages(log, newConf.Global.DisableTHP)
				activeGeneration := &runtimeGeneration{
					controlPlane: oldC,
					listener:     oldListener,
					cancel:       oldCancel,
					conf:         oldConf,
				}
				candidateGeneration := &runtimeGeneration{
					controlPlane: newC,
					listener:     stagedListener,
					cancel:       cancel,
					conf:         newConf,
				}
				if err := runtimeSupervisor.replaceActive(activeGeneration); err != nil {
					reloadErr := fmt.Errorf("record active generation for staged reload: %w", err)
					reloadManager.setReloadError(reloadErr)
					if closeErr := candidateGeneration.cleanup(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Failed to close staged generation after supervisor setup failure")
					}
					log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					releaseReloadTransition()
					continue
				}
				if err := runtimeSupervisor.installPrepared(candidateGeneration); err != nil {
					reloadErr := fmt.Errorf("install staged reload candidate: %w", err)
					reloadManager.setReloadError(reloadErr)
					if closeErr := candidateGeneration.cleanup(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Failed to close staged generation after supervisor install failure")
					}
					log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					releaseReloadTransition()
					continue
				}
				reloadManager.setPendingStagedHandoff(&stagedReloadHandoff{
					preparedGeneration: candidateGeneration,
					oldControlPlane:    oldC,
					oldCancel:          oldCancel,
					oldConf:            oldConf,
					oldListener:        oldListener,
					newControlPlane:    newC,
					newCancel:          cancel,
					newListener:        stagedListener,
					abortConnections:   abortConnections,
					hasOverlap:         hasOverlap,
					preparedDNSHandoff: true,
					sharedBpfHandoff:   true,
					routingEpochReady:  routingEpochHandoffEnabled,
				}, reloadStartedAt, reloadStartedAtMono)
				reloadManager.beginHandoff()
				releaseReloadTransition()
				notifyRunStateChange(runStateChanges)
				continue
			}

			if freshDatapathHandoff {
				log.Warnln("[Reload] Prepare fresh datapath handoff")
				ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
				freshState, prepareErr := c.SnapshotFreshDatapathState()
				var newC *control.ControlPlane
				if prepareErr == nil {
					newC, prepareErr = newPreparedControlPlane(ctx, log, freshState, dnsCache, newConf, externGeoDataDirs, false, true)
				}
				dnsCache = nil
				if prepareErr == nil {
					prepareErr = newC.AttachSessionManager(processSessions)
					if prepareErr != nil {
						_ = newC.Close()
					}
				}
				if prepareErr != nil {
					reloadErr := wrapReloadTimeoutError("prepare fresh datapath reload", prepareErr, reloadPrepareTimeout)
					reloadManager.setReloadError(reloadErr)
					cancel()
					log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath reload; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					releaseReloadTransition()
					continue
				}

				stagedListener, err = listenControlPlaneInDaeNetns(newC, newConf.Global.TproxyPort)
				if err != nil {
					reloadErr := fmt.Errorf("prepare fresh datapath listener: %w", err)
					reloadManager.setReloadError(reloadErr)
					if closeErr := (&runtimeGeneration{controlPlane: newC, listener: stagedListener, cancel: cancel}).cleanup(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Failed to close prepared fresh datapath generation")
					}
					log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath listener; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					releaseReloadTransition()
					continue
				}

				oldC := c
				oldCancel := currCancel
				oldConf := conf
				oldListener := listener

				hasOverlap := newC.InheritDialerHealthFrom(oldC)
				configureTransparentHugePages(log, newConf.Global.DisableTHP)
				activeGeneration := &runtimeGeneration{
					controlPlane: oldC,
					listener:     oldListener,
					cancel:       oldCancel,
					conf:         oldConf,
				}
				candidateGeneration := &runtimeGeneration{
					controlPlane: newC,
					listener:     stagedListener,
					cancel:       cancel,
					conf:         newConf,
				}
				if err := runtimeSupervisor.replaceActive(activeGeneration); err != nil {
					reloadErr := fmt.Errorf("record active generation for fresh datapath reload: %w", err)
					reloadManager.setReloadError(reloadErr)
					if closeErr := candidateGeneration.cleanup(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Failed to close fresh datapath generation after supervisor setup failure")
					}
					log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath reload; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					releaseReloadTransition()
					continue
				}
				if err := runtimeSupervisor.installPrepared(candidateGeneration); err != nil {
					reloadErr := fmt.Errorf("install fresh datapath reload candidate: %w", err)
					reloadManager.setReloadError(reloadErr)
					if closeErr := candidateGeneration.cleanup(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Failed to close fresh datapath generation after supervisor install failure")
					}
					log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath reload; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					releaseReloadTransition()
					continue
				}
				reloadManager.setPendingStagedHandoff(&stagedReloadHandoff{
					preparedGeneration: candidateGeneration,
					oldControlPlane:    oldC,
					oldCancel:          oldCancel,
					oldConf:            oldConf,
					oldListener:        oldListener,
					newControlPlane:    newC,
					newCancel:          cancel,
					newListener:        stagedListener,
					abortConnections:   abortConnections,
					hasOverlap:         hasOverlap,
					freshDatapath:      true,
				}, reloadStartedAt, reloadStartedAtMono)
				reloadManager.beginHandoff()
				releaseReloadTransition()
				notifyRunStateChange(runStateChanges)
				continue
			}

			// Stop old DNS listener before creating new one to avoid port conflicts
			if err := c.StopDNSListener(); err != nil {
				log.Warnf("[Reload] Failed to stop old DNS listener: %v", err)
			}

			log.Warnln("[Reload] Load new control plane")
			ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
			newC, err := newControlPlane(ctx, log, reloadBpf, dnsCache, newConf, externGeoDataDirs, dnsConfigUnchanged, true)
			if err == nil {
				err = newC.AttachSessionManager(processSessions)
				if err != nil {
					_ = newC.Close()
				}
			}
			dnsCache = nil // Allow previous generation's clone to be GC'd.

			var newCancel context.CancelFunc
			if err != nil {
				reloadManager.setReloadError(wrapReloadTimeoutError("build new control plane", err, reloadPrepareTimeout))
				log.WithFields(logrus.Fields{
					"err": err,
				}).Errorln("[Reload] Failed to reload; try to roll back configuration")
				cancel()

				// Load last config back.
				if freshDatapathReload {
					log.Warnln("[Reload] BPF objects already replaced; attempting rollback with fresh eBPF objects")
					obj = nil
					reloadBpf = nil
				}
				ctx, cancel = context.WithTimeout(context.Background(), reloadPrepareTimeout)
				newC, err = newControlPlane(ctx, log, reloadBpf, rollbackDNSCache, conf, externGeoDataDirs, false, true)
				if err == nil {
					err = newC.AttachSessionManager(processSessions)
					if err != nil {
						_ = newC.Close()
					}
				}
				err = wrapReloadTimeoutError("rollback control plane", err, reloadPrepareTimeout)
				if err != nil {
					_ = sdnotify.Stopping()
					if obj != nil && !stagedHotHandoff {
						_ = obj.Close()
					}
					_ = c.Close()
					cancel()
					log.WithFields(logrus.Fields{
						"err": err,
					}).Fatalln("[Reload] Failed to roll back configuration")
				}
				newConf = conf
				newCancel = cancel
				log.Errorln("[Reload] Last reload failed; rolled back configuration")
			} else {
				newCancel = cancel
				log.Warnln("[Reload] Prepared new control plane")
			}

			if stagedListener == nil {
				stagedListener, err = listenControlPlaneInDaeNetns(newC, newConf.Global.TproxyPort)
				if err != nil {
					reloadErr := fmt.Errorf("prepare new listener: %w", err)
					reloadManager.setReloadError(reloadErr)
					if closeErr := (&runtimeGeneration{controlPlane: newC, listener: stagedListener, cancel: newCancel}).cleanup(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Failed to clean up after listener preparation error")
					}
					if obj != nil && !stagedHotHandoff {
						c.InjectBpf(obj)
					}
					if restartErr := c.RestartDNSListener(); restartErr != nil {
						log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after reload preparation error")
					}
					log.WithError(reloadErr).Errorln("[Reload] Failed to prepare listener; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					reloadManager.reloadActive.Store(false)
					clearReloadPending(&reloadManager.reloadPending)
					releaseReloadTransition()
					continue
				}
			}

			// Non-staged shared-BPF paths transfer ownership before the candidate
			// can serve. The supervisor still keeps the old runtime tuple active
			// until the candidate reports ready.
			if !stagedHotHandoff && !freshDatapathReload {
				newC.InjectBpf(obj)
				if c != nil {
					newC.InheritLpmIndices(c.EjectLpmIndices())
				}
			}

			var oldListener *control.Listener
			if listener != nil {
				oldListener = listener
			}

			// Prepare a candidate without replacing the live runtime tuple. The
			// legacy path has already moved its shared BPF object above, so record
			// that ownership transfer to avoid repeating it after readiness.
			oldC := c
			oldCancel := currCancel
			oldConf := conf

			hasOverlap := newC.InheritDialerHealthFrom(oldC)
			configureTransparentHugePages(log, newConf.Global.DisableTHP)
			activeGeneration := &runtimeGeneration{
				controlPlane: oldC,
				listener:     oldListener,
				cancel:       oldCancel,
				conf:         oldConf,
			}
			candidateGeneration := &runtimeGeneration{
				controlPlane: newC,
				listener:     stagedListener,
				cancel:       newCancel,
				conf:         newConf,
			}
			if err := runtimeSupervisor.replaceActive(activeGeneration); err != nil {
				reloadErr := fmt.Errorf("record active generation for reload: %w", err)
				reloadManager.setReloadError(reloadErr)
				if !freshDatapathReload && oldC != nil {
					oldC.InjectBpf(newC.EjectBpf())
					oldC.InheritLpmIndices(newC.EjectLpmIndices())
				}
				if closeErr := candidateGeneration.cleanup(); closeErr != nil {
					log.WithError(closeErr).Warnln("[Reload] Failed to close candidate generation after supervisor setup failure")
				}
				if oldC != nil {
					if restartErr := oldC.RestartDNSListener(); restartErr != nil {
						log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after supervisor setup failure")
					}
				}
				log.WithError(reloadErr).Errorln("[Reload] Failed to prepare reload candidate; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				reloadManager.reloadActive.Store(false)
				clearReloadPending(&reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}
			if err := runtimeSupervisor.installPrepared(candidateGeneration); err != nil {
				reloadErr := fmt.Errorf("install reload candidate: %w", err)
				reloadManager.setReloadError(reloadErr)
				if !freshDatapathReload && oldC != nil {
					oldC.InjectBpf(newC.EjectBpf())
					oldC.InheritLpmIndices(newC.EjectLpmIndices())
				}
				if closeErr := candidateGeneration.cleanup(); closeErr != nil {
					log.WithError(closeErr).Warnln("[Reload] Failed to close candidate generation after supervisor install failure")
				}
				if oldC != nil {
					if restartErr := oldC.RestartDNSListener(); restartErr != nil {
						log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after supervisor install failure")
					}
				}
				log.WithError(reloadErr).Errorln("[Reload] Failed to prepare reload candidate; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				reloadManager.reloadActive.Store(false)
				clearReloadPending(&reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}
			reloadManager.setPendingStagedHandoff(&stagedReloadHandoff{
				preparedGeneration: candidateGeneration,
				oldControlPlane:    oldC,
				oldCancel:          oldCancel,
				oldConf:            oldConf,
				oldListener:        oldListener,
				newControlPlane:    newC,
				newCancel:          newCancel,
				newListener:        stagedListener,
				abortConnections:   abortConnections,
				hasOverlap:         hasOverlap,
				bpfTransferred:     !freshDatapathReload,
			}, reloadStartedAt, reloadStartedAtMono)
			reloadManager.clearPendingRetirement()
			reloadManager.setPendingReloadMetadata(reloadStartedAt, reloadStartedAtMono)
			reloadManager.beginHandoff()
			releaseReloadTransition()

			reloadManager.refreshPprofServer(log, &pprofServer, newConf.Global.PprofPort)

			notifyRunStateChange(runStateChanges)

		}
	}()

loop:
	for {
		select {
		case sig := <-sigs:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL:
				log.Infof("Received termination signal: %v", sig.String())
				fastExit = true
				break loop
			case syscall.SIGUSR2:
				reloadManager.queueReloadRequest(log, reloadRequest{
					isSuspend:       true,
					requestedAt:     time.Now(),
					requestedAtMono: monotonicNowNano(),
				})
			case syscall.SIGUSR1:
				reloadManager.queueReloadRequest(log, reloadRequest{
					isSuspend:       false,
					requestedAt:     time.Now(),
					requestedAtMono: monotonicNowNano(),
				})
			case syscall.SIGHUP:
				// Ignore.
				continue
			default:
				log.Infof("Received signal: %v", sig.String())
			}
		case <-runStateChanges:
			if reloadManager.reloading.Load() {
				if listener == nil {
					log.Warnln("[Reload] Re-listening after reload")
					readyChan := make(chan bool, 1)
					go func() {
						defer func() {
							select {
							case readyChan <- false:
							default:
							}
						}()
						listener, err = listenControlPlaneInDaeNetns(c, conf.Global.TproxyPort)
						if err != nil {
							log.Errorln("Listen:", err)
						} else if err = serveControlPlaneFunc(c, readyChan, listener); err != nil {
							log.Errorln("Serve:", err)
						}
						notifyRunStateChange(runStateChanges)
					}()
					waitResult, termSig := waitReloadReadyOrSignal(log, sigs, readyChan, reloadReadyTimeout)
					if waitResult == reloadReadyWaitSignal && termSig != nil {
						log.Infof("Received termination signal while waiting for reload readiness: %v", termSig.String())
						fastExit = true
						break loop
					}
					if waitResult != reloadReadyWaitReady {
						reloadErr := fmt.Errorf("reload listener failed before becoming ready")
						if waitResult == reloadReadyWaitTimeout {
							reloadErr = fmt.Errorf("reload listener timed out after %v", reloadReadyTimeout)
						}
						reloadManager.setReloadError(reloadErr)
						_ = sdnotify.Ready()
						_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
						log.WithError(reloadErr).Errorln("[Reload] Reload listener failed before becoming ready")
						if !canRecoverReloadReadinessFailure(waitResult) {
							failRun(reloadErr)
							break loop
						}
						reloadManager.reloading.Store(false)
						reloadManager.reloadActive.Store(false)
						clearReloadPending(&reloadManager.reloadPending)
						continue
					}
					_ = sdnotify.Ready()
					if reloadErr := reloadManager.reloadError(); reloadErr == nil {
						_ = setRunSignalProgress(consts.ReloadDone, "OK")
					} else {
						_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					}
					log.Warnln("[Reload] Finished")
					reloadManager.finishReloadSuccess()
					continue
				}
				// Serve.
				reloadManager.reloading.Store(false)
				log.Warnln("[Reload] Serve")
				handoff := reloadManager.currentPendingStagedHandoff()
				serveControlPlane := c
				serveListener := listener
				serveConf := conf
				if handoff != nil {
					if handoff.preparedGeneration == nil || handoff.preparedGeneration.controlPlane == nil || handoff.preparedGeneration.listener == nil || handoff.preparedGeneration.conf == nil {
						reloadErr := fmt.Errorf("staged reload is missing its prepared generation")
						reloadManager.setReloadError(reloadErr)
						log.WithError(reloadErr).Errorln("[Reload] Failed to serve staged reload candidate")
						if candidate := handoff.preparedGeneration; candidate != nil {
							runtimeSupervisor.rollbackPrepared(candidate)
							if handoff.newControlPlane == nil {
								handoff.newControlPlane = candidate.controlPlane
							}
							if handoff.newListener == nil {
								handoff.newListener = candidate.listener
							}
							if handoff.newCancel == nil {
								handoff.newCancel = candidate.cancel
							}
						}
						if handoff.freshDatapath && handoff.freshCutoverStarted {
							recoveredListener, rollbackErr := rollbackFreshDatapathReloadHandoff(log, handoff)
							if rollbackErr != nil {
								log.WithError(rollbackErr).Errorln("[Reload] Failed to recover previous generation from malformed fresh handoff")
								failRun(errors.Join(reloadErr, fmt.Errorf("recover malformed fresh handoff: %w", rollbackErr)))
								break loop
							}
							listener = recoveredListener
							if err := runtimeSupervisor.replaceActive(&runtimeGeneration{
								controlPlane: handoff.oldControlPlane,
								listener:     recoveredListener,
								cancel:       handoff.oldCancel,
								conf:         handoff.oldConf,
							}); err != nil {
								log.WithError(err).Errorln("[Reload] Failed to restore supervisor from malformed fresh handoff")
								failRun(errors.Join(reloadErr, fmt.Errorf("restore supervisor from malformed fresh handoff: %w", err)))
								break loop
							}
							if handoff.oldRuntimeStopped {
								if restartErr := restartRecoveredControlPlane(log, sigs, runStateChanges, handoff.oldControlPlane, listener); restartErr != nil {
									log.WithError(restartErr).Errorln("[Reload] Failed to restart previous generation from malformed fresh handoff")
									failRun(errors.Join(reloadErr, fmt.Errorf("restart previous generation from malformed fresh handoff: %w", restartErr)))
									break loop
								}
							}
						} else {
							if restoreErr := restoreStagedReloadHandoff(log, handoff); restoreErr != nil {
								reloadManager.setReloadError(errors.Join(reloadErr, restoreErr))
								log.WithError(restoreErr).Errorln("[Reload] Failed to recover previous generation from malformed staged handoff")
								reloadManager.clearPendingStagedHandoff()
								failRun(errors.Join(reloadErr, fmt.Errorf("recover malformed staged handoff: %w", restoreErr)))
								break loop
							}
						}
						reloadManager.clearPendingStagedHandoff()
						reloadManager.finishReloadFailure()
						continue
					}
					serveControlPlane = handoff.preparedGeneration.controlPlane
					serveListener = handoff.preparedGeneration.listener
					serveConf = handoff.preparedGeneration.conf
				}
				if handoff != nil && handoff.freshDatapath {
					if cutoverErr := prepareFreshDatapathCutover(log, handoff); cutoverErr != nil {
						reloadErr := fmt.Errorf("prepare fresh datapath cutover: %w", cutoverErr)
						reloadManager.setReloadError(reloadErr)
						_ = sdnotify.Ready()
						_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
						log.WithError(reloadErr).Errorln("[Reload] Fresh datapath cutover failed; restoring previous generation")

						runtimeSupervisor.rollbackPrepared(handoff.preparedGeneration)
						recoveredListener, rollbackErr := rollbackFreshDatapathReloadHandoff(log, handoff)
						if rollbackErr != nil {
							log.WithError(rollbackErr).Errorln("[Reload] Failed to recover previous generation after cutover error")
							failRun(errors.Join(reloadErr, fmt.Errorf("recover previous generation after cutover error: %w", rollbackErr)))
							break loop
						}
						listener = recoveredListener
						if err := runtimeSupervisor.replaceActive(&runtimeGeneration{
							controlPlane: handoff.oldControlPlane,
							listener:     recoveredListener,
							cancel:       handoff.oldCancel,
							conf:         handoff.oldConf,
						}); err != nil {
							log.WithError(err).Errorln("[Reload] Failed to restore supervisor after fresh datapath rollback")
							failRun(errors.Join(reloadErr, fmt.Errorf("restore supervisor after fresh datapath rollback: %w", err)))
							break loop
						}
						reloadManager.clearPendingStagedHandoff()
						if handoff.oldRuntimeStopped {
							if restartErr := restartRecoveredControlPlane(log, sigs, runStateChanges, handoff.oldControlPlane, listener); restartErr != nil {
								log.WithError(restartErr).Errorln("[Reload] Failed to restart previous listener generation after cutover rollback")
								failRun(errors.Join(reloadErr, fmt.Errorf("restart previous generation after cutover rollback: %w", restartErr)))
								break loop
							}
						}
						reloadManager.finishReloadFailure()
						continue
					}
				} else if handoff != nil && handoff.preparedDNSHandoff {
					reloadManager.installPreparedDNSHandoffHooks(log, serveControlPlane, serveConf)
				}
				if handoff != nil && handoff.sharedBpfHandoff && !handoff.freshDatapath && !handoff.oldConnectivityPaused {
					// The prepared generation already suppresses its own health-map
					// writes. Pause the active generation before CommitPreparedDatapath
					// publishes shared BPF state so stale health probes cannot
					// overwrite the candidate's connectivity state.
					if handoff.oldControlPlane != nil {
						handoff.oldControlPlane.PauseOutboundConnectivityUpdates()
						handoff.oldConnectivityPaused = true
					}
				}
				readyChan := make(chan bool, 1)
				go func() {
					defer func() {
						select {
						case readyChan <- false:
						default:
						}
					}()
					if err := serveControlPlaneFunc(serveControlPlane, readyChan, serveListener); err != nil {
						log.Errorln("ListenAndServe:", err)
					}
					notifyRunStateChange(runStateChanges)
				}()
				waitResult, termSig := waitReloadReadyOrSignal(log, sigs, readyChan, reloadReadyTimeout)
				if waitResult == reloadReadyWaitSignal && termSig != nil {
					log.Infof("Received termination signal while waiting for reload readiness: %v", termSig.String())
					fastExit = true
					break loop
				}
				if waitResult != reloadReadyWaitReady {
					reloadErr := fmt.Errorf("reload serve failed before becoming ready")
					if !canRecoverReloadReadinessFailure(waitResult) {
						reloadErr = fmt.Errorf("reload serve timed out after %v", reloadReadyTimeout)
					}
					reloadManager.setReloadError(reloadErr)
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					log.WithError(reloadErr).Errorln("[Reload] Reload serve failed before becoming ready")
					if waitResult == reloadReadyWaitTimeout {
						// Serve may still be mutating shared BPF state. Do not race a
						// rollback against a late commit; terminate and let the service
						// manager start from a clean datapath instead.
						failRun(reloadErr)
						break loop
					}
					if handoff := reloadManager.currentPendingStagedHandoff(); handoff != nil {
						runtimeSupervisor.rollbackPrepared(handoff.preparedGeneration)
						if handoff.freshDatapath {
							recoveredListener, rollbackErr := rollbackFreshDatapathReloadHandoff(log, handoff)
							if rollbackErr != nil {
								log.WithError(rollbackErr).Errorln("[Reload] Failed to recover previous generation after fresh datapath handoff failure")
								failRun(errors.Join(reloadErr, fmt.Errorf("recover previous generation after fresh datapath handoff failure: %w", rollbackErr)))
								break loop
							}
							listener = recoveredListener
							if err := runtimeSupervisor.replaceActive(&runtimeGeneration{
								controlPlane: handoff.oldControlPlane,
								listener:     recoveredListener,
								cancel:       handoff.oldCancel,
								conf:         handoff.oldConf,
							}); err != nil {
								log.WithError(err).Errorln("[Reload] Failed to restore supervisor after fresh datapath rollback")
								failRun(errors.Join(reloadErr, fmt.Errorf("restore supervisor after fresh datapath rollback: %w", err)))
								break loop
							}
							reloadManager.clearPendingStagedHandoff()
							if handoff.oldRuntimeStopped {
								if restartErr := restartRecoveredControlPlane(log, sigs, runStateChanges, handoff.oldControlPlane, listener); restartErr != nil {
									log.WithError(restartErr).Errorln("[Reload] Failed to restart previous listener generation after rollback")
									failRun(errors.Join(reloadErr, fmt.Errorf("restart previous generation after fresh datapath rollback: %w", restartErr)))
									break loop
								}
							}
						} else {
							reloadManager.clearPendingStagedHandoff()
							if restoreErr := restoreStagedReloadHandoff(log, handoff); restoreErr != nil {
								reloadManager.setReloadError(errors.Join(reloadErr, restoreErr))
								log.WithError(restoreErr).Errorln("[Reload] Failed to recover previous generation after staged handoff failure")
								failRun(errors.Join(reloadErr, fmt.Errorf("recover previous generation after staged handoff failure: %w", restoreErr)))
								break loop
							}
							log.Warnln("[Reload] Restored previous listener generation after staged handoff failure")
						}
					}
					reloadManager.finishReloadFailure()
					continue
				}
				dnsHandoffActive := reloadManager.pendingDNSHandoffActive(serveControlPlane)
				if handoff := reloadManager.currentPendingStagedHandoff(); handoff != nil {
					var publishErr error
					if handoff.freshDatapath && !handoff.provisionalOwner {
						publishErr = handoff.newControlPlane.RegisterProvisionalRoutingEpochExecutionOwner()
						if publishErr == nil {
							handoff.provisionalOwner = true
						}
					}
					if handoff.freshDatapath && !handoff.hookFlipCommitted {
						if publishErr == nil {
							publishErr = handoff.newControlPlane.CommitPreparedBpfHookFlip()
						}
						if publishErr == nil {
							handoff.hookFlipCommitted = true
						}
					}
					if handoff.freshDatapath && !handoff.flowDatapathAdopted {
						if publishErr == nil {
							publishErr = handoff.newControlPlane.AdoptProcessFlowDatapath(handoff.oldControlPlane)
						}
						if publishErr == nil {
							handoff.flowDatapathAdopted = true
						}
					}
					var retiringGeneration *runtimeGeneration
					if publishErr == nil {
						retiringGeneration, publishErr = runtimeSupervisor.publishPrepared(handoff.preparedGeneration)
					}
					if publishErr == nil && handoff.provisionalOwner {
						handoff.newControlPlane.UnregisterProvisionalRoutingEpochExecutionOwner()
						handoff.provisionalOwner = false
					}
					if publishErr != nil {
						reloadErr := fmt.Errorf("publish staged reload candidate: %w", publishErr)
						reloadManager.setReloadError(reloadErr)
						log.WithError(reloadErr).Errorln("[Reload] Failed to publish staged reload candidate; keeping current generation active")
						runtimeSupervisor.rollbackPrepared(handoff.preparedGeneration)
						if handoff.freshDatapath {
							recoveredListener, rollbackErr := rollbackFreshDatapathReloadHandoff(log, handoff)
							if rollbackErr != nil {
								log.WithError(rollbackErr).Errorln("[Reload] Failed to recover previous generation after publish error")
								failRun(errors.Join(reloadErr, fmt.Errorf("recover previous generation after publish error: %w", rollbackErr)))
								break loop
							}
							listener = recoveredListener
							if err := runtimeSupervisor.replaceActive(&runtimeGeneration{
								controlPlane: handoff.oldControlPlane,
								listener:     recoveredListener,
								cancel:       handoff.oldCancel,
								conf:         handoff.oldConf,
							}); err != nil {
								log.WithError(err).Errorln("[Reload] Failed to restore supervisor after publish error")
								failRun(errors.Join(reloadErr, fmt.Errorf("restore supervisor after publish error: %w", err)))
								break loop
							}
							if handoff.oldRuntimeStopped {
								if restartErr := restartRecoveredControlPlane(log, sigs, runStateChanges, handoff.oldControlPlane, listener); restartErr != nil {
									log.WithError(restartErr).Errorln("[Reload] Failed to restart previous listener generation after publish error")
									failRun(errors.Join(reloadErr, fmt.Errorf("restart previous generation after publish error: %w", restartErr)))
									break loop
								}
							}
						} else {
							if restoreErr := restoreStagedReloadHandoff(log, handoff); restoreErr != nil {
								reloadManager.setReloadError(errors.Join(reloadErr, restoreErr))
								log.WithError(restoreErr).Errorln("[Reload] Failed to recover previous generation after publish error")
								reloadManager.clearPendingStagedHandoff()
								failRun(errors.Join(reloadErr, fmt.Errorf("recover previous generation after publish error: %w", restoreErr)))
								break loop
							}
						}
						reloadManager.clearPendingStagedHandoff()
						reloadManager.finishReloadFailure()
						continue
					}

					oldListener := handoff.oldListener
					oldC := handoff.oldControlPlane
					oldCancel := handoff.oldCancel
					abortConnections := handoff.abortConnections
					hasOverlap := handoff.hasOverlap
					if oldC != nil && !handoff.freshDatapath && !handoff.bpfTransferred {
						bpf := oldC.EjectBpf()
						serveControlPlane.InjectBpf(bpf)
						serveControlPlane.InheritLpmIndices(oldC.EjectLpmIndices())
					}
					if handoff.sharedBpfHandoff {
						// The supervisor now owns the candidate as active. Publish its
						// current health snapshot only after this point; the old
						// generation remains paused until retirement closes it.
						serveControlPlane.ResumeOutboundConnectivityUpdates()
					}
					if oldC != nil {
						if detachErr := oldC.DetachBpfHooks(); detachErr != nil {
							log.WithError(detachErr).Warnln("[Reload] Failed to detach previous datapath hooks after publish; retrying")
							if retryErr := oldC.DetachBpfHooks(); retryErr != nil {
								detachFatalErr := errors.Join(
									fmt.Errorf("detach previous datapath hooks: %w", retryErr),
									fmt.Errorf("initial detach previous datapath hooks: %w", detachErr),
								)
								reloadManager.setReloadError(detachFatalErr)
								log.WithError(retryErr).Errorln("[Reload] Previous datapath hooks remain attached after publish")
								failRun(detachFatalErr)
								break loop
							}
						}
					}
					c = handoff.preparedGeneration.controlPlane
					currCancel = handoff.preparedGeneration.cancel
					conf = handoff.preparedGeneration.conf
					listener = handoff.preparedGeneration.listener
					reloadManager.clearPendingStagedHandoff()

					if oldListener != nil {
						if err := oldListener.Close(); err != nil {
							log.WithError(err).Warnln("[Reload] Failed to close previous listener generation")
						}
					}
					handoff.oldRuntimeStopped = true

					if oldC != nil {
						reloadManager.startControlPlaneRetirement(log, oldC, c, oldCancel, abortConnections, hasOverlap, runtimeSupervisor, retiringGeneration)
					}
				}
				_ = sdnotify.Ready()
				if reloadErr := reloadManager.reloadError(); reloadErr == nil {
					_ = setRunSignalProgress(consts.ReloadDone, "OK")
				} else {
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				}
				log.Warnln("[Reload] Finished")
				reloadManager.finishReloadSuccess()
				if dnsHandoffActive && log.IsLevelEnabled(logrus.DebugLevel) {
					log.Debugln("[Reload] Shared DNS controller handoff remains available while old generation drains")
				}
			} else if listener == nil {
				// Listening error.
				log.Errorln("[Critical] Listener failed; exiting")
				break loop
			}
		}
	}

	defer func() {
		_ = sdnotify.Stopping()
		if pprofServer != nil {
			log.Infoln("Shutting down pprof server")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = pprofServer.Shutdown(ctx)
			cancel()
		}
		_ = os.Remove(PidFilePath)
	}()

	// Stop accepting new ingress immediately so shutdown does not continue to
	// create fresh UDP/TCP work while the control plane is being torn down.
	shutdownHandoff := buildRunShutdownHandoff(reloadManager, runtimeSupervisor, &runtimeGeneration{
		controlPlane: c,
		listener:     listener,
		cancel:       currCancel,
		conf:         conf,
	}, fastExit)
	shutdownErr := shutdownAfterSignalWithHandoff(log, listener, c, control.GetDaeNetns(), fastExit, shutdownHandoff)
	return errors.Join(fatalRunErr, shutdownErr)
}

// buildRunShutdownHandoff preserves the historical fast-exit path: process
// termination does not wait for reload transitions or retirement cleanup.
// Graceful shutdown freezes the supervisor first so every generation has one
// clear cleanup owner.
func buildRunShutdownHandoff(manager *reloadManager, supervisor *runtimeSupervisor, current *runtimeGeneration, fastExit bool) *signalShutdownStagedHandoff {
	if fastExit {
		return manager.buildShutdownHandoff()
	}
	shutdownSnapshot := manager.shutdownSupervisor(supervisor)
	handoff := manager.buildShutdownHandoffWithSupervisor(shutdownSnapshot, current)
	if current != nil && current.cancel != nil {
		if handoff == nil {
			handoff = &signalShutdownStagedHandoff{}
		}
		if handoff.newCancel == nil {
			handoff.newCancel = current.cancel
		}
	}
	return handoff
}

func notifyRunStateChange(runStateChanges chan<- struct{}) {
	select {
	case runStateChanges <- struct{}{}:
	default:
	}
}

func beginReloadHandoff(reloading *atomic.Bool, runStateChanges chan<- struct{}) {
	if reloading != nil {
		reloading.Store(true)
	}
	notifyRunStateChange(runStateChanges)
}

func waitForControlPlaneDrain(
	log *logrus.Logger,
	ctx context.Context,
	c reloadRetirementControlPlane,
	maxWait time.Duration,
	logEvery time.Duration,
) controlPlaneDrainWaitResult {
	if c == nil || c.ActiveSessionCount() == 0 {
		return controlPlaneDrainIdle
	}

	idleCh := c.DrainIdleCh()

	timer := time.NewTimer(maxWait)
	defer timer.Stop()

	var ticker *time.Ticker
	var tickCh <-chan time.Time
	if logEvery > 0 {
		ticker = time.NewTicker(logEvery)
		defer ticker.Stop()
		tickCh = ticker.C
	}

	for {
		select {
		case <-ctx.Done():
			return controlPlaneDrainCanceled
		case <-idleCh:
			return controlPlaneDrainIdle
		case <-timer.C:
			return controlPlaneDrainTimeout
		case <-tickCh:
			if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
				log.WithField("active_sessions", c.ActiveSessionCount()).
					Debugln("[Reload] Old control plane still draining active sessions")
			}
		}
	}
}

func retireControlPlaneConnections(
	log *logrus.Logger,
	ctx context.Context,
	c retirementDrainPlane,
	abort bool,
	hasOverlap bool,
	maxDrain time.Duration,
) {
	_ = hasOverlap
	observation := control.BeginPhase1ReloadDrainObservation()
	outcome := control.Phase1ReloadDrainCompleted
	defer func() {
		observation.End(outcome)
	}()

	switch {
	case abort:
		log.Warnln("[Reload] Abort requested; aborting stale connections immediately")
		if err := c.AbortConnections(); err != nil {
			outcome = control.Phase1ReloadDrainFailed
		}
	default:
		switch waitForControlPlaneDrain(log, ctx, c, maxDrain, controlPlaneRetirementLogEvery) {
		case controlPlaneDrainIdle:
			log.Infoln("[Reload] Old control plane drained active sessions; retiring immediately")
		case controlPlaneDrainCanceled:
			outcome = control.Phase1ReloadDrainCanceled
			log.Warnln("[Reload] Retirement canceled; aborting generation-owned pending work")
			if err := c.AbortPendingConnections(); err != nil {
				outcome = control.Phase1ReloadDrainFailed
			}
		case controlPlaneDrainTimeout:
			outcome = control.Phase1ReloadDrainTimedOut
			log.WithField("active_sessions", c.ActiveSessionCount()).
				Warnln("[Reload] Old control plane drain timed out; aborting pending generation work")
			if err := c.AbortPendingConnections(); err != nil {
				outcome = control.Phase1ReloadDrainFailed
			}
		default:
			outcome = control.Phase1ReloadDrainFailed
		}
	}
	// Seal generation admission on every retirement path and wait for any lease
	// acquired before abort/drain committed to closing the owner.
	c.StopRoutingEpochExecution()
}

func prepareFreshDatapathCutover(log *logrus.Logger, handoff *stagedReloadHandoff) error {
	if handoff == nil || !handoff.freshDatapath {
		return fmt.Errorf("missing fresh datapath handoff")
	}
	if handoff.oldControlPlane == nil || handoff.newControlPlane == nil {
		return fmt.Errorf("missing control plane for fresh datapath cutover")
	}
	if handoff.oldListener == nil {
		return fmt.Errorf("missing previous listener for fresh datapath cutover")
	}
	handoff.freshCutoverStarted = true
	if err := handoff.oldControlPlane.StopDNSListener(); err != nil {
		return fmt.Errorf("stop previous DNS listener: %w", err)
	}
	if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
		log.Debugln("[Reload] Previous datapath remains active until the fresh candidate is ready")
	}
	return nil
}

func rollbackFreshDatapathReloadHandoff(log *logrus.Logger, handoff *stagedReloadHandoff) (*control.Listener, error) {
	if handoff == nil || handoff.oldControlPlane == nil || handoff.oldConf == nil {
		return nil, fmt.Errorf("missing previous generation for fresh datapath rollback")
	}
	var rollbackCleanupErrs []error
	if handoff.provisionalOwner && handoff.newControlPlane != nil {
		handoff.newControlPlane.UnregisterProvisionalRoutingEpochExecutionOwner()
		handoff.provisionalOwner = false
	}
	if handoff.flowDatapathAdopted && handoff.newControlPlane != nil {
		if err := handoff.oldControlPlane.AdoptProcessFlowDatapath(handoff.newControlPlane); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs, fmt.Errorf("restore process flow datapath: %w", err))
		} else {
			handoff.flowDatapathAdopted = false
		}
	}
	if handoff.hookFlipCommitted && handoff.newControlPlane != nil {
		if err := handoff.newControlPlane.RollbackPreparedBpfHookFlip(); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs, fmt.Errorf("restore previous BPF hook flip: %w", err))
		} else {
			handoff.hookFlipCommitted = false
		}
	}
	if handoff.newControlPlane != nil {
		if err := handoff.newControlPlane.DetachBpfHooks(); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs, fmt.Errorf("detach fresh datapath hooks: %w", err))
		}
	}
	if handoff.preparedGeneration != nil {
		if err := handoff.preparedGeneration.cleanup(); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs, fmt.Errorf("cleanup fresh datapath generation: %w", err))
		}
	} else {
		if handoff.newCancel != nil {
			handoff.newCancel()
		}
		if handoff.newControlPlane != nil {
			if err := handoff.newControlPlane.Close(); err != nil && log != nil {
				log.WithError(err).Warnln("[Reload] Failed to close fresh datapath control plane during rollback")
			}
		}
	}
	if len(rollbackCleanupErrs) > 0 {
		return nil, errors.Join(rollbackCleanupErrs...)
	}
	if !handoff.oldRuntimeStopped {
		if err := handoff.oldControlPlane.RestartDNSListener(); err != nil {
			return nil, fmt.Errorf("restart previous DNS listener: %w", err)
		}
		if log != nil {
			log.Warnln("[Reload] Discarded fresh datapath candidate; previous generation remained active")
		}
		return handoff.oldListener, nil
	}

	recoveredListener, err := listenControlPlaneInDaeNetns(handoff.oldControlPlane, handoff.oldConf.Global.TproxyPort)
	if err != nil {
		return nil, fmt.Errorf("restore previous listener: %w", err)
	}
	if err := handoff.oldControlPlane.RestoreDatapathForReloadRollback(); err != nil {
		_ = recoveredListener.Close()
		return nil, err
	}
	if err := handoff.oldControlPlane.RestartDNSListener(); err != nil {
		_ = recoveredListener.Close()
		return nil, fmt.Errorf("restart previous DNS listener: %w", err)
	}
	if log != nil {
		log.Warnln("[Reload] Restored previous generation after fresh datapath handoff failure")
	}
	return recoveredListener, nil
}

func restartRecoveredControlPlane(
	log *logrus.Logger,
	sigs <-chan os.Signal,
	runStateChanges chan<- struct{},
	c *control.ControlPlane,
	listener *control.Listener,
) error {
	if c == nil || listener == nil {
		return fmt.Errorf("missing recovered control plane or listener")
	}
	readyChan := make(chan bool, 1)
	go func() {
		defer func() {
			select {
			case readyChan <- false:
			default:
			}
		}()
		if err := serveControlPlaneFunc(c, readyChan, listener); err != nil && log != nil {
			log.Errorln("ListenAndServe:", err)
		}
		notifyRunStateChange(runStateChanges)
	}()
	waitResult, termSig := waitReloadReadyOrSignal(log, sigs, readyChan, reloadReadyTimeout)
	if waitResult == reloadReadyWaitSignal && termSig != nil {
		return fmt.Errorf("received termination signal while restoring previous generation: %v", termSig.String())
	}
	if waitResult == reloadReadyWaitTimeout {
		return fmt.Errorf("restored listener timed out after %v", reloadReadyTimeout)
	}
	if waitResult != reloadReadyWaitReady {
		return fmt.Errorf("restored listener failed before becoming ready")
	}
	return nil
}

func restoreStagedReloadHandoff(log *logrus.Logger, handoff *stagedReloadHandoff) error {
	if handoff == nil {
		return fmt.Errorf("staged reload handoff is nil")
	}

	var errs []error
	if err := rollbackStagedReloadHandoff(log, handoff); err != nil {
		errs = append(errs, err)
	}
	if handoff.oldControlPlane == nil {
		errs = append(errs, fmt.Errorf("previous control plane is nil"))
		return errors.Join(errs...)
	}
	if handoff.oldListener == nil {
		errs = append(errs, fmt.Errorf("previous listener is nil"))
	} else if err := restoreListenerSocketsFunc(handoff.oldControlPlane, handoff.oldListener); err != nil {
		errs = append(errs, fmt.Errorf("republish previous listeners: %w", err))
	}
	if err := restoreReloadDatapathFunc(handoff.oldControlPlane); err != nil {
		errs = append(errs, fmt.Errorf("rebuild previous datapath: %w", err))
	}
	if !handoff.oldDNSListenerActive {
		if err := restoreDNSListenerFunc(handoff.oldControlPlane); err != nil {
			errs = append(errs, fmt.Errorf("restart previous DNS listener: %w", err))
		}
	}
	return errors.Join(errs...)
}

func rollbackStagedReloadHandoff(log *logrus.Logger, handoff *stagedReloadHandoff) error {
	if handoff == nil {
		return nil
	}
	var errs []error
	defer func() {
		if handoff.oldConnectivityPaused && handoff.oldControlPlane != nil {
			handoff.oldControlPlane.ResumeOutboundConnectivityUpdates()
			handoff.oldConnectivityPaused = false
		}
	}()

	if handoff.newControlPlane != nil && (handoff.dnsControllerMoved || handoff.dnsListenerMoved) {
		listenerActive, err := handoff.newControlPlane.RestorePreparedDNSRuntimeForRollback(
			handoff.oldControlPlane,
			handoff.dnsControllerMoved,
			handoff.dnsListenerMoved,
		)
		if err != nil {
			errs = append(errs, err)
		} else {
			handoff.dnsControllerMoved = false
			handoff.dnsListenerMoved = false
			handoff.oldDNSListenerActive = listenerActive
		}
	}

	if handoff.bpfTransferred && handoff.oldControlPlane != nil && handoff.newControlPlane != nil {
		handoff.oldControlPlane.InjectBpf(handoff.newControlPlane.EjectBpf())
		handoff.oldControlPlane.InheritLpmIndices(handoff.newControlPlane.EjectLpmIndices())
		handoff.bpfTransferred = false
	}

	if handoff.newControlPlane != nil {
		handoff.newControlPlane.ClearReloadDnsCacheSource()
		if handoff.routingEpochReady {
			if err := handoff.newControlPlane.RollbackPreparedRoutingEpoch(); err != nil {
				errs = append(errs, fmt.Errorf("restore previous routing epoch: %w", err))
				if log != nil {
					log.WithError(err).Errorln("[Reload] Failed to restore previous routing epoch before closing staged control plane")
				}
			}
		}
	}

	if handoff.preparedGeneration != nil {
		if err := handoff.preparedGeneration.cleanup(); err != nil {
			errs = append(errs, fmt.Errorf("clean up staged generation: %w", err))
			if log != nil {
				log.WithError(err).Warnln("[Reload] Failed to clean up staged generation during rollback")
			}
		}
	} else {
		if handoff.newListener != nil {
			if err := handoff.newListener.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close prepared listener: %w", err))
				if log != nil {
					log.WithError(err).Warnln("[Reload] Failed to close prepared listener during rollback")
				}
			}
		}
		if handoff.newCancel != nil {
			handoff.newCancel()
		}
		if handoff.newControlPlane != nil {
			if err := handoff.newControlPlane.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close staged control plane: %w", err))
				if log != nil {
					log.WithError(err).Warnln("[Reload] Failed to close staged control plane during rollback")
				}
			}
		}
	}
	return errors.Join(errs...)
}

func wrapReloadTimeoutError(stage string, err error, timeout time.Duration) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s timed out after %v: %w", stage, timeout, err)
	}
	return err
}

func waitReloadReadyOrSignal(
	log *logrus.Logger,
	sigs <-chan os.Signal,
	readyChan <-chan bool,
	timeout time.Duration,
) (result reloadReadyWaitResult, termSig os.Signal) {
	var timer *time.Timer
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timeoutCh = timer.C
	}

	for {
		select {
		case ready := <-readyChan:
			if ready {
				return reloadReadyWaitReady, nil
			}
			return reloadReadyWaitFailed, nil
		case sig := <-sigs:
			switch sig {
			case nil, syscall.SIGHUP:
				continue
			case syscall.SIGUSR1, syscall.SIGUSR2:
				if log != nil {
					log.Warnln("[Reload] Signal received while current reload is still becoming ready; ignoring it")
				}
				continue
			case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL:
				return reloadReadyWaitSignal, sig
			default:
				if sig != nil && log != nil {
					log.Infof("Received signal while waiting for reload readiness: %v", sig.String())
				}
			}
		case <-timeoutCh:
			return reloadReadyWaitTimeout, nil
		}
	}
}

func shutdownAfterSignalWithHandoff(
	log *logrus.Logger,
	listener signalShutdownListener,
	c signalShutdownControlPlane,
	netns signalShutdownNetns,
	fastExit bool,
	handoff *signalShutdownStagedHandoff,
) error {
	closeListener := func(listener signalShutdownListener) {
		if listener == nil {
			return
		}
		if e := listener.Close(); e != nil {
			log.Warnf("close listener: %v", e)
		}
	}
	detachPlane := func(c signalShutdownControlPlane) {
		if c == nil {
			return
		}
		if e := c.DetachBpfHooks(); e != nil {
			log.Warnf("detach BPF hooks: %v", e)
		}
	}
	abortAndClosePlane := func(c signalShutdownControlPlane) error {
		if c == nil {
			return nil
		}
		if e := c.AbortConnections(); e != nil {
			log.Warnf("abort connections: %v", e)
		}
		if e := c.Close(); e != nil {
			return e
		}
		return nil
	}

	closeListener(listener)
	if handoff != nil {
		if handoff.oldListener != nil && handoff.oldListener != listener {
			closeListener(handoff.oldListener)
		}
		if handoff.newListener != nil && handoff.newListener != listener && handoff.newListener != handoff.oldListener {
			closeListener(handoff.newListener)
		}
	}

	detachPlane(c)
	if handoff != nil {
		if handoff.oldControlPlane != nil && handoff.oldControlPlane != c {
			detachPlane(handoff.oldControlPlane)
		}
		if handoff.newControlPlane != nil && handoff.newControlPlane != c && handoff.newControlPlane != handoff.oldControlPlane {
			detachPlane(handoff.newControlPlane)
		}
	}

	if fastExit {
		log.Infoln("[Shutdown] Fast exit enabled; skipping in-process netns and control-plane teardown. Residual kernel state will be purged on next startup.")
		return nil
	}

	if netns != nil {
		if e := netns.Close(); e != nil {
			log.Warnf("close dae netns: %v", e)
		}
	}
	if handoff != nil {
		if handoff.oldCancel != nil {
			handoff.oldCancel()
		}
		if handoff.newCancel != nil {
			handoff.newCancel()
		}
	}

	var closeErrs []error
	if err := abortAndClosePlane(c); err != nil {
		closeErrs = append(closeErrs, err)
	}
	if handoff != nil {
		if handoff.oldControlPlane != nil && handoff.oldControlPlane != c {
			if err := abortAndClosePlane(handoff.oldControlPlane); err != nil {
				closeErrs = append(closeErrs, err)
			}
		}
		if handoff.newControlPlane != nil && handoff.newControlPlane != c && handoff.newControlPlane != handoff.oldControlPlane {
			if err := abortAndClosePlane(handoff.newControlPlane); err != nil {
				closeErrs = append(closeErrs, err)
			}
		}
	}
	// After all control planes are closed, reset global UDP state to stop
	// background janitors and release pooled sockets. This must only run during
	// process shutdown; hot reload must never reset shared global pools.
	control.ResetGlobalUdpState()

	if len(closeErrs) > 0 {
		return fmt.Errorf("close control plane: %w", errors.Join(closeErrs...))
	}
	return nil
}

func newControlPlane(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, dnsRoutingUnchanged bool, isReloadBuild bool) (c *control.ControlPlane, err error) {
	return newControlPlaneWithMode(ctx, log, bpf, dnsCache, conf, externGeoDataDirs, false, dnsRoutingUnchanged, isReloadBuild)
}

func newPreparedControlPlane(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, dnsRoutingUnchanged bool, isReloadBuild bool) (c *control.ControlPlane, err error) {
	return newControlPlaneWithMode(ctx, log, bpf, dnsCache, conf, externGeoDataDirs, true, dnsRoutingUnchanged, isReloadBuild)
}

// buildControlPlaneRuntime is the final construction boundary after config
// normalization, subscription resolution, and reload safety checks. Keeping
// the seam here lets failure tests exercise the real Runner preparation path
// without replacing the default ControlPlane constructors.
var buildControlPlaneRuntime = buildControlPlaneRuntimeDefault

func buildControlPlaneRuntimeDefault(
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
// An explicit GOMEMLIMIT always wins. Otherwise memory.high participates in
// the detected ceiling so systemd MemoryHigh works even without MemoryMax.
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

// detectCgroupMemLimit returns the smallest finite memory.max or memory.high
// applying to the current cgroup. Parent ceilings still constrain children, so
// the complete path is inspected instead of stopping at the first value.
func detectCgroupMemLimit() int64 {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		// Not in cgroup v2 or can't read; try root-level (container case).
		return readCgroupMemoryCeiling("/sys/fs/cgroup")
	}
	return detectCgroupMemLimitFrom(data, "/sys/fs/cgroup")
}

func detectCgroupMemLimitFrom(data []byte, root string) int64 {
	var limit int64
	for _, line := range strings.Split(string(data), "\n") {
		// cgroup v2 unified hierarchy format: "0::/path"
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		cgPath := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
		for {
			limit = minPositive(limit, readCgroupMemoryCeiling(filepath.Join(root, cgPath)))
			if cgPath == "/" || cgPath == "." || cgPath == "" {
				break
			}
			idx := strings.LastIndexByte(cgPath, '/')
			if idx <= 0 {
				cgPath = "/"
			} else {
				cgPath = cgPath[:idx]
			}
		}
		return limit
	}
	return readCgroupMemoryCeiling(root)
}

// readMemMax reads memory.max from a cgroup v2 directory.
// Returns 0 if the file is missing, set to "max", or unparseable.
func readMemMax(dir string) int64 {
	return readCgroupMemoryValue(dir, "memory.max")
}

func readCgroupMemoryCeiling(dir string) int64 {
	return minPositive(
		readMemMax(dir),
		readCgroupMemoryValue(dir, "memory.high"),
	)
}

func readCgroupMemoryValue(dir, name string) int64 {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func minPositive(values ...int64) int64 {
	var minimum int64
	for _, value := range values {
		if value > 0 && (minimum == 0 || value < minimum) {
			minimum = value
		}
	}
	return minimum
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

func newHTTPClientForDialer(d netproxy.Dialer, timeout time.Duration, soMark uint32, mptcp bool) http.Client {
	soMark = common.EffectiveSoMarkFromDae(soMark)
	return http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := d.DialContext(ctx, common.MagicNetwork("tcp", soMark, mptcp), addr)
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
		Timeout: timeout,
	}
}

func preprocessWanInterfaceAuto(params *config.Config) error {
	// preprocess "auto".
	ifs := make([]string, 0, len(params.Global.WanInterface)+2)
	for _, ifname := range params.Global.WanInterface {
		if ifname == "auto" {
			defaultIfs, err := common.GetDefaultIfnames()
			if err != nil {
				return fmt.Errorf("failed to convert 'auto': %w", err)
			}
			ifs = append(ifs, defaultIfs...)
		} else {
			ifs = append(ifs, ifname)
		}
	}
	params.Global.WanInterface = common.Deduplicate(ifs)
	return nil
}

func readConfig(cfgFile string) (conf *config.Config, includes []string, err error) {
	merger := config.NewMerger(cfgFile)
	sections, includes, err := merger.Merge()
	if err != nil {
		return nil, nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}

func emptyConfig() (conf *config.Config, err error) {
	sections, err := config_parser.Parse(`global{} routing{}`)
	if err != nil {
		return nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, err
	}
	return conf, nil
}

func init() {
	rootCmd.AddCommand(runCmd)
}
