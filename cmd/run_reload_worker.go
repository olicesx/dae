/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
)

// reloadWorker drives the reload state machine for one Run invocation: it
// consumes reload requests, loads the new config, prepares a candidate
// generation (staged-hot handoff, fresh datapath handoff, or the legacy
// shared-BPF path), and hands the candidate to Run's signal loop for
// readiness-wait, publish, and retirement of the old generation.
type reloadWorker struct {
	// Immutable run context.
	externGeoDataDirs []string
	processSessions   *control.SessionManager
	runtimeSupervisor *runtimeSupervisor
	reloadManager     *reloadManager
	runStateChanges   chan<- struct{}

	// Mutable run state shared with Run's signal loop. Field names mirror
	// Run's original local variables; the signal loop advances c, conf,
	// currCancel, and listener after publishing a candidate generation, and
	// this worker swaps log when a reload changes the log level.
	log         *logrus.Logger
	conf        *config.Config
	c           *control.ControlPlane
	currCancel  context.CancelFunc
	listener    *control.Listener
	pprofServer *http.Server
}

// run consumes reload requests until the process exits. It is started once by
// Run and performs no generation publication itself; every prepared candidate
// is published from Run's signal loop after it reports readiness.
func (w *reloadWorker) run() {
	var err error
	for req := range w.reloadManager.reloadReqs {
		w.reloadManager.reloadActive.Store(true)
		req = w.reloadManager.coalesceReloadRequest(req)
		reloadStartedAt := req.requestedAt
		reloadStartedAtMono := req.requestedAtMono

		if req.isSuspend {
			w.log.Warnln("[Reload] Received suspend signal; prepare to suspend")
		} else {
			w.log.Warnln("[Reload] Received reload signal; prepare to reload")
		}
		_ = sdnotify.Reloading()
		_ = setRunSignalProgress(consts.ReloadProcessing, "")
		w.reloadManager.setReloadError(nil)
		resetReloadProxyRuntimeState()

		// Load new config.
		abortConnections := os.Remove(AbortFile) == nil
		w.log.Warnln("[Reload] Load new config")
		var newConf *config.Config
		if req.isSuspend {
			newConf, err = emptyConfig()
			if err != nil {
				w.log.WithFields(logrus.Fields{
					"err": err,
				}).Errorln("[Reload] Failed to reload")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, err.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				continue
			}
			newConf.Global = deepcopy.Copy(w.conf.Global).(config.Global)
			newConf.Global.WanInterface = nil
			newConf.Global.LanInterface = nil
			newConf.Global.LogLevel = "warning"
		} else {
			var includes []string
			newConf, includes, err = readConfig(cfgFile)
			if err != nil {
				w.log.WithFields(logrus.Fields{
					"err": err,
				}).Errorln("[Reload] Failed to reload")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, err.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				continue
			}
			w.log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
		}
		// New logger.
		oldLogOutput := w.log.Out
		w.log = logrus.New()
		logger.SetLogger(w.log, newConf.Global.LogLevel, disableTimestamp, nil)
		logger.SetLogger(logrus.StandardLogger(), newConf.Global.LogLevel, disableTimestamp, nil)
		w.log.SetOutput(oldLogOutput) // NOTE: Restore log output after creating new logger during reload.
		logrus.SetOutput(oldLogOutput)
		if !req.isSuspend {
			if deferred := preserveReloadInterfaceBindings(w.conf, newConf); len(deferred) > 0 {
				w.log.WithField("bindings", strings.Join(deferred, ",")).Warnln("[Reload] Deferring interface removal or role change until cold start to preserve established flows")
			}
		}

		portChanged := w.conf.Global.TproxyPort != newConf.Global.TproxyPort
		datapathChanged := bpfDatapathChanged(w.conf, newConf)
		freshDatapathReload := portChanged || datapathChanged
		stagedHotHandoff := shouldUseStagedHotHandoff(freshDatapathReload, w.listener != nil)
		freshDatapathHandoff := freshDatapathReload && w.listener != nil
		if !w.reloadManager.beginReloadTransition() {
			reloadErr := errRuntimeSupervisorClosed
			w.reloadManager.setReloadError(reloadErr)
			w.log.WithError(reloadErr).Warnln("[Reload] Ignoring reload while shutdown is in progress")
			w.reloadManager.reloadActive.Store(false)
			clearReloadPending(&w.reloadManager.reloadPending)
			continue
		}
		transitionHeld := true
		releaseReloadTransition := func() {
			if transitionHeld {
				w.reloadManager.endReloadTransition()
				transitionHeld = false
			}
		}

		// New control plane.
		obj := w.c.PeekBpf()
		if freshDatapathReload {
			obj = nil
		} else if !stagedHotHandoff {
			obj = w.c.EjectBpf()
		}
		var reloadBpf any
		if obj != nil {
			reloadBpf = obj
		}
		if portChanged {
			w.log.Warnf("[Reload] Tproxy port changed from %d to %d; will perform a full reload of eBPF programs", w.conf.Global.TproxyPort, newConf.Global.TproxyPort)
		} else if datapathChanged {
			w.log.Warnln("[Reload] Kernel datapath input changed (interface/somark/map-size); will perform a fresh datapath handoff")
		}

		dnsConfigUnchanged := dnsConfigEqual(w.conf, newConf)
		ipVersionPreferenceUnchanged := w.conf.Dns.IpVersionPrefer == newConf.Dns.IpVersionPrefer
		streamStagedDnsCache := shouldStreamStagedDnsCache(
			stagedHotHandoff,
			dnsConfigUnchanged,
			ipVersionPreferenceUnchanged,
		)
		var dnsCache map[string]*control.DnsCache
		if ipVersionPreferenceUnchanged && !streamStagedDnsCache {
			// Only keep dns cache when ip version preference not change.
			dnsCache = w.c.CloneDnsCache()
		}
		rollbackDNSCache := dnsCache
		var stagedListener *control.Listener

		if stagedHotHandoff {
			w.log.Warnln("[Reload] Prepare staged same-port handoff")
			ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
			newC, prepareErr := newPreparedControlPlane(ctx, w.log, reloadBpf, dnsCache, newConf, w.externGeoDataDirs, dnsConfigUnchanged, true)
			dnsCache = nil
			if prepareErr == nil {
				prepareErr = newC.AttachSessionManager(w.processSessions)
				if prepareErr != nil {
					_ = newC.Close()
				}
			}
			if prepareErr != nil {
				reloadErr := wrapReloadTimeoutError("prepare staged reload", prepareErr, reloadPrepareTimeout)
				w.reloadManager.setReloadError(reloadErr)
				cancel()
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}

			stagedListener, listenErr := cloneControlListenerFunc(w.listener)
			if listenErr != nil {
				reloadErr := fmt.Errorf("clone listener: %w", listenErr)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := (&runtimeGeneration{controlPlane: newC, cancel: cancel}).cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close prepared staged generation")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to stage listener; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}

			oldC := w.c
			oldCancel := w.currCancel
			oldConf := w.conf
			oldListener := w.listener
			if err := linkRoutingEpochPeerFunc(oldC, newC); err != nil {
				reloadErr := fmt.Errorf("link staged routing epochs: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := stagedListener.Close(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close staged listener after epoch link failure")
				}
				if closeErr := (&runtimeGeneration{controlPlane: newC, cancel: cancel}).cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close staged generation after epoch link failure")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
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
			configureTransparentHugePages(w.log, newConf.Global.DisableTHP)
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
			if err := w.runtimeSupervisor.replaceActive(activeGeneration); err != nil {
				reloadErr := fmt.Errorf("record active generation for staged reload: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := candidateGeneration.cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close staged generation after supervisor setup failure")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}
			if err := w.runtimeSupervisor.installPrepared(candidateGeneration); err != nil {
				reloadErr := fmt.Errorf("install staged reload candidate: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := candidateGeneration.cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close staged generation after supervisor install failure")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}
			w.reloadManager.setPendingStagedHandoff(&stagedReloadHandoff{
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
			w.reloadManager.beginHandoff()
			releaseReloadTransition()
			notifyRunStateChange(w.runStateChanges)
			continue
		}

		if freshDatapathHandoff {
			w.log.Warnln("[Reload] Prepare fresh datapath handoff")
			ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
			freshState, prepareErr := w.c.SnapshotFreshDatapathState()
			var newC *control.ControlPlane
			if prepareErr == nil {
				newC, prepareErr = newPreparedControlPlane(ctx, w.log, freshState, dnsCache, newConf, w.externGeoDataDirs, false, true)
			}
			dnsCache = nil
			if prepareErr == nil {
				prepareErr = newC.AttachSessionManager(w.processSessions)
				if prepareErr != nil {
					_ = newC.Close()
				}
			}
			if prepareErr != nil {
				reloadErr := wrapReloadTimeoutError("prepare fresh datapath reload", prepareErr, reloadPrepareTimeout)
				w.reloadManager.setReloadError(reloadErr)
				cancel()
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath reload; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}

			stagedListener, err = listenControlPlaneInDaeNetns(newC, newConf.Global.TproxyPort)
			if err != nil {
				reloadErr := fmt.Errorf("prepare fresh datapath listener: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := (&runtimeGeneration{controlPlane: newC, listener: stagedListener, cancel: cancel}).cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close prepared fresh datapath generation")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath listener; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}

			oldC := w.c
			oldCancel := w.currCancel
			oldConf := w.conf
			oldListener := w.listener

			hasOverlap := newC.InheritDialerHealthFrom(oldC)
			configureTransparentHugePages(w.log, newConf.Global.DisableTHP)
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
			if err := w.runtimeSupervisor.replaceActive(activeGeneration); err != nil {
				reloadErr := fmt.Errorf("record active generation for fresh datapath reload: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := candidateGeneration.cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close fresh datapath generation after supervisor setup failure")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath reload; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}
			if err := w.runtimeSupervisor.installPrepared(candidateGeneration); err != nil {
				reloadErr := fmt.Errorf("install fresh datapath reload candidate: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := candidateGeneration.cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close fresh datapath generation after supervisor install failure")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath reload; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}
			w.reloadManager.setPendingStagedHandoff(&stagedReloadHandoff{
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
			w.reloadManager.beginHandoff()
			releaseReloadTransition()
			notifyRunStateChange(w.runStateChanges)
			continue
		}

		// Stop old DNS listener before creating new one to avoid port conflicts
		if err := w.c.StopDNSListener(); err != nil {
			w.log.Warnf("[Reload] Failed to stop old DNS listener: %v", err)
		}

		w.log.Warnln("[Reload] Load new control plane")
		ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
		newC, err := newControlPlane(ctx, w.log, reloadBpf, dnsCache, newConf, w.externGeoDataDirs, dnsConfigUnchanged, true)
		if err == nil {
			err = newC.AttachSessionManager(w.processSessions)
			if err != nil {
				_ = newC.Close()
			}
		}
		dnsCache = nil // Allow previous generation's clone to be GC'd.

		var newCancel context.CancelFunc
		if err != nil {
			w.reloadManager.setReloadError(wrapReloadTimeoutError("build new control plane", err, reloadPrepareTimeout))
			w.log.WithFields(logrus.Fields{
				"err": err,
			}).Errorln("[Reload] Failed to reload; try to roll back configuration")
			cancel()

			// Load last config back.
			if freshDatapathReload {
				w.log.Warnln("[Reload] BPF objects already replaced; attempting rollback with fresh eBPF objects")
				obj = nil
				reloadBpf = nil
			}
			ctx, cancel = context.WithTimeout(context.Background(), reloadPrepareTimeout)
			newC, err = newControlPlane(ctx, w.log, reloadBpf, rollbackDNSCache, w.conf, w.externGeoDataDirs, false, true)
			if err == nil {
				err = newC.AttachSessionManager(w.processSessions)
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
				_ = w.c.Close()
				cancel()
				w.log.WithFields(logrus.Fields{
					"err": err,
				}).Fatalln("[Reload] Failed to roll back configuration")
			}
			newConf = w.conf
			newCancel = cancel
			w.log.Errorln("[Reload] Last reload failed; rolled back configuration")
		} else {
			newCancel = cancel
			w.log.Warnln("[Reload] Prepared new control plane")
		}

		if stagedListener == nil {
			stagedListener, err = listenControlPlaneInDaeNetns(newC, newConf.Global.TproxyPort)
			if err != nil {
				reloadErr := fmt.Errorf("prepare new listener: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := (&runtimeGeneration{controlPlane: newC, listener: stagedListener, cancel: newCancel}).cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to clean up after listener preparation error")
				}
				if obj != nil && !stagedHotHandoff {
					w.c.InjectBpf(obj)
				}
				if restartErr := w.c.RestartDNSListener(); restartErr != nil {
					w.log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after reload preparation error")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare listener; keeping current generation active")
				_ = sdnotify.Ready()
				_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				w.reloadManager.reloadActive.Store(false)
				clearReloadPending(&w.reloadManager.reloadPending)
				releaseReloadTransition()
				continue
			}
		}

		// Non-staged shared-BPF paths transfer ownership before the candidate
		// can serve. The supervisor still keeps the old runtime tuple active
		// until the candidate reports ready.
		if !stagedHotHandoff && !freshDatapathReload {
			newC.InjectBpf(obj)
		}

		var oldListener *control.Listener
		if w.listener != nil {
			oldListener = w.listener
		}

		// Prepare a candidate without replacing the live runtime tuple. The
		// legacy path has already moved its shared BPF object above, so record
		// that ownership transfer to avoid repeating it after readiness.
		oldC := w.c
		oldCancel := w.currCancel
		oldConf := w.conf

		hasOverlap := newC.InheritDialerHealthFrom(oldC)
		configureTransparentHugePages(w.log, newConf.Global.DisableTHP)
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
		if err := w.runtimeSupervisor.replaceActive(activeGeneration); err != nil {
			reloadErr := fmt.Errorf("record active generation for reload: %w", err)
			w.reloadManager.setReloadError(reloadErr)
			if !freshDatapathReload && oldC != nil {
				oldC.InjectBpf(newC.EjectBpf())
			}
			if closeErr := candidateGeneration.cleanup(); closeErr != nil {
				w.log.WithError(closeErr).Warnln("[Reload] Failed to close candidate generation after supervisor setup failure")
			}
			if oldC != nil {
				if restartErr := oldC.RestartDNSListener(); restartErr != nil {
					w.log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after supervisor setup failure")
				}
			}
			w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare reload candidate; keeping current generation active")
			_ = sdnotify.Ready()
			_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
			w.reloadManager.reloadActive.Store(false)
			clearReloadPending(&w.reloadManager.reloadPending)
			releaseReloadTransition()
			continue
		}
		if err := w.runtimeSupervisor.installPrepared(candidateGeneration); err != nil {
			reloadErr := fmt.Errorf("install reload candidate: %w", err)
			w.reloadManager.setReloadError(reloadErr)
			if !freshDatapathReload && oldC != nil {
				oldC.InjectBpf(newC.EjectBpf())
			}
			if closeErr := candidateGeneration.cleanup(); closeErr != nil {
				w.log.WithError(closeErr).Warnln("[Reload] Failed to close candidate generation after supervisor install failure")
			}
			if oldC != nil {
				if restartErr := oldC.RestartDNSListener(); restartErr != nil {
					w.log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after supervisor install failure")
				}
			}
			w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare reload candidate; keeping current generation active")
			_ = sdnotify.Ready()
			_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
			w.reloadManager.reloadActive.Store(false)
			clearReloadPending(&w.reloadManager.reloadPending)
			releaseReloadTransition()
			continue
		}
		w.reloadManager.setPendingStagedHandoff(&stagedReloadHandoff{
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
		w.reloadManager.clearPendingRetirement()
		w.reloadManager.setPendingReloadMetadata(reloadStartedAt, reloadStartedAtMono)
		w.reloadManager.beginHandoff()
		releaseReloadTransition()

		w.reloadManager.refreshPprofServer(w.log, &w.pprofServer, newConf.Global.PprofPort)

		notifyRunStateChange(w.runStateChanges)

	}
}
