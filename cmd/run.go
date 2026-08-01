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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/consts"
	outbounddialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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

var setRunSignalProgress = func(code byte, content string) error {
	return writeSignalProgressFile(SignalProgressFilePath, code, content)
}

var getRunSignalProgress = func() (byte, string, error) {
	return readSignalProgressFile(SignalProgressFilePath)
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
			stagedHotHandoff := shouldUseStagedHotHandoff(routingEpochHandoffEnabled, freshDatapathReload, listener != nil)
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

				if ipVersionPreferenceUnchanged {
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
func init() {
	rootCmd.AddCommand(runCmd)
}
