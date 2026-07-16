/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

type controlPlaneBoundaryContextKey struct{}

func newControlPlaneBoundaryConfig(t *testing.T) *config.Config {
	t.Helper()
	conf, err := emptyConfig()
	if err != nil {
		t.Fatalf("emptyConfig() error = %v", err)
	}
	conf.Global.DisableWaitingNetwork = true
	conf.Global.LanInterface = []string{"lan0"}
	conf.Global.WanInterface = []string{"wan0"}
	conf.Node = []config.KeyableString{"node-a"}
	return conf
}

func installControlPlaneRuntimeBuilderForTest(
	t *testing.T,
	builder func(
		context.Context,
		*logrus.Logger,
		any,
		map[string]*control.DnsCache,
		map[string][]string,
		[]config.Group,
		*config.Routing,
		*config.Global,
		*config.Dns,
		[]string,
		bool,
		bool,
		bool,
	) (*control.ControlPlane, error),
) {
	t.Helper()
	previousBuilder := buildControlPlaneRuntime
	buildControlPlaneRuntime = builder
	t.Cleanup(func() {
		buildControlPlaneRuntime = previousBuilder
	})
}

func TestNewControlPlaneWithModeDelegatesAllGenerationModes(t *testing.T) {
	previousConfigFile := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "dae.conf")
	t.Cleanup(func() {
		cfgFile = previousConfigFile
	})

	type buildCall struct {
		ctx                 context.Context
		bpf                 any
		dnsCache            map[string]*control.DnsCache
		tagToNodeList       map[string][]string
		groups              []config.Group
		routing             *config.Routing
		global              *config.Global
		dns                 *config.Dns
		externGeoDataDirs   []string
		prepareOnly         bool
		dnsRoutingUnchanged bool
		isReloadBuild       bool
	}

	for _, testCase := range []struct {
		name                string
		prepareOnly         bool
		dnsRoutingUnchanged bool
		isReloadBuild       bool
	}{
		{name: "initial", prepareOnly: false, dnsRoutingUnchanged: false, isReloadBuild: false},
		{name: "prepared", prepareOnly: true, dnsRoutingUnchanged: true, isReloadBuild: false},
		{name: "reload", prepareOnly: false, dnsRoutingUnchanged: true, isReloadBuild: true},
		{name: "prepared_reload", prepareOnly: true, dnsRoutingUnchanged: false, isReloadBuild: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conf := newControlPlaneBoundaryConfig(t)
			ctx := context.WithValue(context.Background(), controlPlaneBoundaryContextKey{}, testCase.name)
			bpf := &struct{ name string }{name: testCase.name}
			dnsCacheMarker := &control.DnsCache{}
			dnsCache := map[string]*control.DnsCache{
				"boundary": dnsCacheMarker,
			}
			var got buildCall
			installControlPlaneRuntimeBuilderForTest(t, func(
				gotCtx context.Context,
				_ *logrus.Logger,
				gotBpf any,
				gotDnsCache map[string]*control.DnsCache,
				gotTagToNodeList map[string][]string,
				gotGroups []config.Group,
				gotRouting *config.Routing,
				gotGlobal *config.Global,
				gotDns *config.Dns,
				gotExternGeoDataDirs []string,
				gotPrepareOnly, gotDnsRoutingUnchanged, gotIsReloadBuild bool,
			) (*control.ControlPlane, error) {
				got = buildCall{
					ctx:                 gotCtx,
					bpf:                 gotBpf,
					dnsCache:            gotDnsCache,
					tagToNodeList:       gotTagToNodeList,
					groups:              gotGroups,
					routing:             gotRouting,
					global:              gotGlobal,
					dns:                 gotDns,
					externGeoDataDirs:   gotExternGeoDataDirs,
					prepareOnly:         gotPrepareOnly,
					dnsRoutingUnchanged: gotDnsRoutingUnchanged,
					isReloadBuild:       gotIsReloadBuild,
				}
				return &control.ControlPlane{}, nil
			})

			gotPlane, err := newControlPlaneWithMode(
				ctx,
				logrus.New(),
				bpf,
				dnsCache,
				conf,
				[]string{"geo-a", "geo-b"},
				testCase.prepareOnly,
				testCase.dnsRoutingUnchanged,
				testCase.isReloadBuild,
			)
			if err != nil {
				t.Fatalf("newControlPlaneWithMode() error = %v", err)
			}
			if gotPlane == nil {
				t.Fatal("newControlPlaneWithMode() returned nil control plane")
			}
			if got.ctx != ctx || got.bpf != bpf || got.dnsCache["boundary"] != dnsCacheMarker {
				t.Fatal("construction boundary did not preserve context, BPF, or DNS cache identity")
			}
			if !reflect.DeepEqual(got.tagToNodeList, map[string][]string{"": {"node-a"}}) {
				t.Fatalf("tagToNodeList = %#v, want node mapping", got.tagToNodeList)
			}
			if !reflect.DeepEqual(got.externGeoDataDirs, []string{"geo-a", "geo-b"}) {
				t.Fatalf("externGeoDataDirs = %#v", got.externGeoDataDirs)
			}
			if got.prepareOnly != testCase.prepareOnly ||
				got.dnsRoutingUnchanged != testCase.dnsRoutingUnchanged ||
				got.isReloadBuild != testCase.isReloadBuild {
				t.Fatalf("build flags = (%t, %t, %t), want (%t, %t, %t)",
					got.prepareOnly,
					got.dnsRoutingUnchanged,
					got.isReloadBuild,
					testCase.prepareOnly,
					testCase.dnsRoutingUnchanged,
					testCase.isReloadBuild,
				)
			}

			// The caller's configuration is deep-copied before the construction
			// boundary. Mutating the captured global config must not affect it.
			got.global.LanInterface[0] = "mutated-after-copy"
			if conf.Global.LanInterface[0] == "mutated-after-copy" {
				t.Fatal("construction boundary retained caller-owned global config")
			}
		})
	}
}

func TestNewControlPlaneWithModePropagatesConstructionFailure(t *testing.T) {
	previousConfigFile := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "dae.conf")
	t.Cleanup(func() {
		cfgFile = previousConfigFile
	})

	wantErr := stderrors.New("injected control plane construction failure")
	installControlPlaneRuntimeBuilderForTest(t, func(
		context.Context,
		*logrus.Logger,
		any,
		map[string]*control.DnsCache,
		map[string][]string,
		[]config.Group,
		*config.Routing,
		*config.Global,
		*config.Dns,
		[]string,
		bool,
		bool,
		bool,
	) (*control.ControlPlane, error) {
		return nil, wantErr
	})

	gotPlane, err := newControlPlaneWithMode(
		context.Background(),
		logrus.New(),
		nil,
		nil,
		newControlPlaneBoundaryConfig(t),
		nil,
		true,
		true,
		true,
	)
	if gotPlane != nil {
		t.Fatal("failed construction returned a control plane")
	}
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("newControlPlaneWithMode() error = %v, want %v", err, wantErr)
	}
}

func TestNewControlPlaneWithModePropagatesCanceledContext(t *testing.T) {
	previousConfigFile := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "dae.conf")
	t.Cleanup(func() {
		cfgFile = previousConfigFile
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	installControlPlaneRuntimeBuilderForTest(t, func(
		gotCtx context.Context,
		_ *logrus.Logger,
		_ any,
		_ map[string]*control.DnsCache,
		_ map[string][]string,
		_ []config.Group,
		_ *config.Routing,
		_ *config.Global,
		_ *config.Dns,
		_ []string,
		_ bool,
		_ bool,
		_ bool,
	) (*control.ControlPlane, error) {
		return nil, gotCtx.Err()
	})

	gotPlane, err := newControlPlaneWithMode(
		ctx,
		logrus.New(),
		nil,
		nil,
		newControlPlaneBoundaryConfig(t),
		nil,
		true,
		false,
		true,
	)
	if gotPlane != nil {
		t.Fatal("canceled construction returned a control plane")
	}
	if !stderrors.Is(err, context.Canceled) {
		t.Fatalf("newControlPlaneWithMode() error = %v, want context.Canceled", err)
	}
}

const controlPlaneConstructionProcessHelperEnv = "DAE_CONTROL_PLANE_CONSTRUCTION_PROCESS_HELPER"

func TestControlPlaneConstructionProcessBoundary(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestControlPlaneConstructionProcessHelper$")
	command.Env = append(os.Environ(), controlPlaneConstructionProcessHelperEnv+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("control plane construction helper failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("control-plane-construction-process-helper-ok")) {
		t.Fatalf("control plane construction helper did not report success: %s", output)
	}
}

func TestControlPlaneConstructionProcessHelper(t *testing.T) {
	if os.Getenv(controlPlaneConstructionProcessHelperEnv) != "1" {
		t.Skip("child-process construction helper")
	}

	previousConfigFile := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "dae.conf")
	t.Cleanup(func() {
		cfgFile = previousConfigFile
	})

	wantErr := stderrors.New("child injected control plane construction failure")
	installControlPlaneRuntimeBuilderForTest(t, func(
		ctx context.Context,
		_ *logrus.Logger,
		_ any,
		_ map[string]*control.DnsCache,
		_ map[string][]string,
		_ []config.Group,
		_ *config.Routing,
		_ *config.Global,
		_ *config.Dns,
		_ []string,
		_ bool,
		_ bool,
		_ bool,
	) (*control.ControlPlane, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, wantErr
	})

	for iteration := 0; iteration < 256; iteration++ {
		ctx := context.Background()
		if iteration%3 == 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		gotPlane, err := newPreparedControlPlane(
			ctx,
			logrus.New(),
			nil,
			nil,
			newControlPlaneBoundaryConfig(t),
			nil,
			iteration%2 == 0,
			true,
		)
		if gotPlane != nil {
			t.Fatalf("iteration %d returned a control plane after failed construction", iteration)
		}
		want := wantErr
		if iteration%3 == 0 {
			want = context.Canceled
		}
		if !stderrors.Is(err, want) {
			t.Fatalf("iteration %d error = %v, want %v", iteration, err, want)
		}
	}

	_, _ = fmt.Fprintln(os.Stdout, "control-plane-construction-process-helper-ok")
}

func TestRunnerConstructionFailureReleasesSemanticFeatureGate(t *testing.T) {
	previousConfigFile := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "dae.conf")
	t.Cleanup(func() {
		cfgFile = previousConfigFile
	})
	t.Setenv(semanticRefactorFeaturesEnv, "compiled-policy,routing-epoch,dns-resolver,udp-ordered-dispatcher,udp-reply-dispatcher")

	wantErr := stderrors.New("runner construction failure")
	installControlPlaneRuntimeBuilderForTest(t, func(
		context.Context,
		*logrus.Logger,
		any,
		map[string]*control.DnsCache,
		map[string][]string,
		[]config.Group,
		*config.Routing,
		*config.Global,
		*config.Dns,
		[]string,
		bool,
		bool,
		bool,
	) (*control.ControlPlane, error) {
		return nil, wantErr
	})

	err := newRunner(logrus.New(), newControlPlaneBoundaryConfig(t), nil).Run()
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("Runner.Run() error = %v, want %v", err, wantErr)
	}

	handle, err := control.EnableSemanticRefactorFeatures(
		control.SemanticRefactorFeatureCompiledPolicy,
		control.SemanticRefactorFeatureRoutingEpoch,
		control.SemanticRefactorFeatureDNSResolver,
		control.SemanticRefactorFeatureUDPOrderedDispatcher,
		control.SemanticRefactorFeatureUDPReplyDispatcher,
	)
	if err != nil {
		t.Fatalf("feature gate remained owned after failed Runner.Run(): %v", err)
	}
	handle.Disable()
}

const runnerFreshReloadFailureProcessHelperEnv = "DAE_RUNNER_FRESH_RELOAD_FAILURE_PROCESS_HELPER"

func countProcessFileDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read process file descriptors: %v", err)
	}
	return len(entries)
}

func TestRunnerFreshReloadFailureProcessBoundary(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestRunnerFreshReloadFailureProcessHelper$")
	command.Env = append(os.Environ(), runnerFreshReloadFailureProcessHelperEnv+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("runner fresh reload helper failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("runner-fresh-reload-failure-process-helper-ok")) {
		t.Fatalf("runner fresh reload helper did not report success: %s", output)
	}
}

func TestRunnerFreshReloadFailureProcessHelper(t *testing.T) {
	if os.Getenv(runnerFreshReloadFailureProcessHelperEnv) != "1" {
		t.Skip("child-process Runner reload helper")
	}

	previousConfigFile := cfgFile
	previousDisablePidFile := disablePidFile
	previousSetRunSignalProgress := setRunSignalProgress
	previousResetReloadProxyRuntimeState := resetReloadProxyRuntimeState
	previousListenControlPlane := listenControlPlaneFunc
	previousCloneControlListener := cloneControlListenerFunc
	previousServeControlPlane := serveControlPlaneFunc
	previousWithDaeNetnsRequired := withDaeNetnsRequiredFunc
	previousReloadFailureCompletionHook := reloadFailureCompletionHook
	cfgFile = filepath.Join(t.TempDir(), "dae.conf")
	disablePidFile = true
	readyNotificationDone := make(chan struct{})
	var readyNotificationOnce sync.Once
	setRunSignalProgress = func(byte, string) error {
		readyNotificationOnce.Do(func() { close(readyNotificationDone) })
		return nil
	}
	resetReloadProxyRuntimeState = func() {}
	t.Cleanup(func() {
		cfgFile = previousConfigFile
		disablePidFile = previousDisablePidFile
		setRunSignalProgress = previousSetRunSignalProgress
		resetReloadProxyRuntimeState = previousResetReloadProxyRuntimeState
		listenControlPlaneFunc = previousListenControlPlane
		cloneControlListenerFunc = previousCloneControlListener
		serveControlPlaneFunc = previousServeControlPlane
		withDaeNetnsRequiredFunc = previousWithDaeNetnsRequired
		reloadFailureCompletionHook = previousReloadFailureCompletionHook
	})

	var buildCalls atomic.Int32
	installControlPlaneRuntimeBuilderForTest(t, func(
		context.Context,
		*logrus.Logger,
		any,
		map[string]*control.DnsCache,
		map[string][]string,
		[]config.Group,
		*config.Routing,
		*config.Global,
		*config.Dns,
		[]string,
		bool,
		bool,
		bool,
	) (*control.ControlPlane, error) {
		buildCalls.Add(1)
		return &control.ControlPlane{}, nil
	})

	var listenCalls atomic.Int32
	var cloneCalls atomic.Int32
	listenControlPlaneFunc = func(c *control.ControlPlane, port uint16) (*control.Listener, error) {
		listenCalls.Add(1)
		return c.Listen(port)
	}
	cloneControlListenerFunc = func(listener *control.Listener) (*control.Listener, error) {
		cloneCalls.Add(1)
		return listener.Clone()
	}

	withDaeNetnsRequiredFunc = func(_ string, f func() error) error {
		return f()
	}

	const cycles = 64
	baselineFDs := countProcessFileDescriptors(t)
	initialReady := make(chan struct{})
	candidateFailed := make(chan struct{}, cycles)
	recoveredReady := make(chan struct{}, cycles)
	reloadFailureCompleted := make(chan struct{}, cycles)
	serveDone := make(chan struct{}, 1+cycles*2)
	reloadFailureCompletionHook = func() {
		reloadFailureCompleted <- struct{}{}
	}
	serveStop := make(chan struct{})
	var stopOnce sync.Once
	defer stopOnce.Do(func() { close(serveStop) })
	var serveCalls atomic.Int32
	serveControlPlaneFunc = func(_ *control.ControlPlane, readyChan chan<- bool, _ *control.Listener) error {
		call := serveCalls.Add(1)
		switch {
		case call == 1:
			defer func() { serveDone <- struct{}{} }()
			readyChan <- true
			close(initialReady)
			<-serveStop
			return nil
		case call%2 == 0:
			defer func() { serveDone <- struct{}{} }()
			readyChan <- false
			candidateFailed <- struct{}{}
			return stderrors.New("injected fresh candidate readiness failure")
		default:
			defer func() { serveDone <- struct{}{} }()
			readyChan <- true
			recoveredReady <- struct{}{}
			<-serveStop
			return nil
		}
	}

	conf := newControlPlaneBoundaryConfig(t)
	runDone := make(chan error, 1)
	go func() {
		runDone <- newRunner(logrus.New(), conf, nil).Run()
	}()

	wait := func(ch <-chan struct{}, name string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for %s", name)
		}
	}
	wait(initialReady, "initial Runner readiness")
	for cycle := 0; cycle < cycles; cycle++ {
		if err := syscall.Kill(os.Getpid(), syscall.SIGUSR2); err != nil {
			t.Fatalf("cycle %d send suspend/reload signal: %v", cycle, err)
		}
		wait(candidateFailed, fmt.Sprintf("cycle %d fresh candidate readiness failure", cycle))
		wait(recoveredReady, fmt.Sprintf("cycle %d recovered generation readiness", cycle))
		wait(reloadFailureCompleted, fmt.Sprintf("cycle %d reload failure completion", cycle))
	}
	if got := listenCalls.Load(); got != 1+cycles {
		t.Fatalf("listener operation calls = %d, want %d", got, 1+cycles)
	}
	if got := cloneCalls.Load(); got != cycles {
		t.Fatalf("listener clone calls = %d, want %d", got, cycles)
	}
	if got := buildCalls.Load(); got != 1+cycles {
		t.Fatalf("control plane build calls = %d, want %d", got, 1+cycles)
	}
	if got := serveCalls.Load(); got != 1+2*cycles {
		t.Fatalf("serve calls = %d, want %d", got, 1+2*cycles)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send termination signal: %v", err)
	}
	stopOnce.Do(func() { close(serveStop) })

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Runner.Run() error = %v, want clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Runner.Run() did not terminate after fresh reload rollback")
	}
	wait(readyNotificationDone, "initial readiness notification")
	for call := 0; call < 1+2*cycles; call++ {
		wait(serveDone, fmt.Sprintf("serve call %d shutdown", call))
	}
	if got := countProcessFileDescriptors(t); got > baselineFDs {
		t.Fatalf("process file descriptors after fresh rollback cycles = %d, baseline = %d", got, baselineFDs)
	}
	_, _ = fmt.Fprintln(os.Stdout, "runner-fresh-reload-failure-process-helper-ok")
}

const runnerStagedWarmupFailureProcessHelperEnv = "DAE_RUNNER_STAGED_WARMUP_FAILURE_PROCESS_HELPER"

func TestRunnerStagedWarmupFailureProcessBoundary(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestRunnerStagedWarmupFailureProcessHelper$")
	command.Env = append(os.Environ(), runnerStagedWarmupFailureProcessHelperEnv+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("runner staged warmup helper failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("runner-staged-warmup-failure-process-helper-ok")) {
		t.Fatalf("runner staged warmup helper did not report success: %s", output)
	}
}

func TestRunnerStagedWarmupFailureProcessHelper(t *testing.T) {
	if os.Getenv(runnerStagedWarmupFailureProcessHelperEnv) != "1" {
		t.Skip("child-process staged warmup helper")
	}

	previousConfigFile := cfgFile
	previousDisablePidFile := disablePidFile
	previousSetRunSignalProgress := setRunSignalProgress
	previousResetReloadProxyRuntimeState := resetReloadProxyRuntimeState
	previousListenControlPlane := listenControlPlaneFunc
	previousCloneControlListener := cloneControlListenerFunc
	previousLinkRoutingEpochPeer := linkRoutingEpochPeerFunc
	previousServeControlPlane := serveControlPlaneFunc
	previousWithDaeNetnsRequired := withDaeNetnsRequiredFunc
	cfgFile = filepath.Join(t.TempDir(), "dae.conf")
	disablePidFile = true
	readyNotificationDone := make(chan struct{})
	var readyNotificationOnce sync.Once
	setRunSignalProgress = func(code byte, _ string) error {
		if code == consts.ReloadDone {
			readyNotificationOnce.Do(func() { close(readyNotificationDone) })
		}
		return nil
	}
	resetReloadProxyRuntimeState = func() {}
	t.Cleanup(func() {
		cfgFile = previousConfigFile
		disablePidFile = previousDisablePidFile
		setRunSignalProgress = previousSetRunSignalProgress
		resetReloadProxyRuntimeState = previousResetReloadProxyRuntimeState
		listenControlPlaneFunc = previousListenControlPlane
		cloneControlListenerFunc = previousCloneControlListener
		linkRoutingEpochPeerFunc = previousLinkRoutingEpochPeer
		serveControlPlaneFunc = previousServeControlPlane
		withDaeNetnsRequiredFunc = previousWithDaeNetnsRequired
	})
	t.Setenv(semanticRefactorFeaturesEnv, string(control.SemanticRefactorFeatureRoutingEpoch))

	var buildCalls atomic.Int32
	installControlPlaneRuntimeBuilderForTest(t, func(
		context.Context,
		*logrus.Logger,
		any,
		map[string]*control.DnsCache,
		map[string][]string,
		[]config.Group,
		*config.Routing,
		*config.Global,
		*config.Dns,
		[]string,
		bool,
		bool,
		bool,
	) (*control.ControlPlane, error) {
		buildCalls.Add(1)
		return &control.ControlPlane{}, nil
	})

	var listenCalls atomic.Int32
	var cloneCalls atomic.Int32
	var linkCalls atomic.Int32
	listenControlPlaneFunc = func(c *control.ControlPlane, port uint16) (*control.Listener, error) {
		listenCalls.Add(1)
		return c.Listen(port)
	}
	cloneControlListenerFunc = func(listener *control.Listener) (*control.Listener, error) {
		cloneCalls.Add(1)
		return listener.Clone()
	}
	linkRoutingEpochPeerFunc = func(*control.ControlPlane, *control.ControlPlane) error {
		linkCalls.Add(1)
		return nil
	}
	withDaeNetnsRequiredFunc = func(_ string, f func() error) error { return f() }

	initialReady := make(chan struct{})
	candidateFailed := make(chan struct{})
	initialServeDone := make(chan struct{})
	candidateServeDone := make(chan struct{})
	serveStop := make(chan struct{})
	var stopOnce sync.Once
	defer stopOnce.Do(func() { close(serveStop) })
	var serveCalls atomic.Int32
	serveControlPlaneFunc = func(_ *control.ControlPlane, readyChan chan<- bool, _ *control.Listener) error {
		switch serveCalls.Add(1) {
		case 1:
			defer close(initialServeDone)
			readyChan <- true
			close(initialReady)
			<-serveStop
			return nil
		case 2:
			defer close(candidateServeDone)
			readyChan <- false
			close(candidateFailed)
			return stderrors.New("injected DNS warmup failure")
		default:
			return stderrors.New("unexpected extra staged Serve call")
		}
	}

	conf, err := emptyConfig()
	if err != nil {
		t.Fatalf("emptyConfig() error = %v", err)
	}
	conf.Global.DisableWaitingNetwork = true
	runDone := make(chan error, 1)
	go func() {
		runDone <- newRunner(logrus.New(), conf, nil).Run()
	}()

	wait := func(ch <-chan struct{}, name string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for %s", name)
		}
	}
	wait(initialReady, "initial staged Runner readiness")
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR2); err != nil {
		t.Fatalf("send staged reload signal: %v", err)
	}
	wait(candidateFailed, "staged DNS warmup failure")
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send staged termination signal: %v", err)
	}
	stopOnce.Do(func() { close(serveStop) })

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Runner.Run() error = %v, want clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Runner.Run() did not terminate after staged warmup rollback")
	}
	wait(readyNotificationDone, "initial staged readiness notification")
	wait(initialServeDone, "initial staged Serve shutdown")
	wait(candidateServeDone, "candidate staged Serve shutdown")
	if buildCalls.Load() < 2 || cloneCalls.Load() != 1 || linkCalls.Load() != 1 || listenCalls.Load() != 1 || serveCalls.Load() != 2 {
		t.Fatalf("staged operation counts = builds=%d clones=%d links=%d listens=%d serves=%d", buildCalls.Load(), cloneCalls.Load(), linkCalls.Load(), listenCalls.Load(), serveCalls.Load())
	}
	_, _ = fmt.Fprintln(os.Stdout, "runner-staged-warmup-failure-process-helper-ok")
}

const runnerLiveStageFailureProcessHelperEnv = "DAE_RUNNER_LIVE_STAGE_FAILURE_PROCESS_HELPER"

func TestRunnerLiveStageFailureProcessBoundary(t *testing.T) {
	for _, kind := range []string{"bpf", "dns"} {
		t.Run(kind, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestRunnerLiveStageFailureProcessHelper$")
			command.Env = append(os.Environ(),
				runnerLiveStageFailureProcessHelperEnv+"=1",
				"DAE_RUNNER_LIVE_STAGE_FAILURE_KIND="+kind,
			)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("runner %s stage helper failed: %v\n%s", kind, err, output)
			}
			if !bytes.Contains(output, []byte("runner-live-stage-failure-process-helper-ok")) {
				t.Fatalf("runner %s stage helper did not report success: %s", kind, output)
			}
		})
	}
}

func TestRunnerLiveStageFailureProcessHelper(t *testing.T) {
	if os.Getenv(runnerLiveStageFailureProcessHelperEnv) != "1" {
		t.Skip("child-process live stage failure helper")
	}
	kind := os.Getenv("DAE_RUNNER_LIVE_STAGE_FAILURE_KIND")
	if kind != "bpf" && kind != "dns" {
		t.Fatalf("unknown live stage failure kind %q", kind)
	}

	previousConfigFile := cfgFile
	previousDisablePidFile := disablePidFile
	previousSetRunSignalProgress := setRunSignalProgress
	previousResetReloadProxyRuntimeState := resetReloadProxyRuntimeState
	previousListenControlPlane := listenControlPlaneFunc
	previousCloneControlListener := cloneControlListenerFunc
	previousLinkRoutingEpochPeer := linkRoutingEpochPeerFunc
	previousServeControlPlane := serveControlPlaneFunc
	previousWithDaeNetnsRequired := withDaeNetnsRequiredFunc
	previousReloadFailureCompletionHook := reloadFailureCompletionHook
	cfgFile = filepath.Join(t.TempDir(), "dae.conf")
	disablePidFile = true
	readyNotificationDone := make(chan struct{})
	var readyNotificationOnce sync.Once
	setRunSignalProgress = func(code byte, _ string) error {
		if code == consts.ReloadDone {
			readyNotificationOnce.Do(func() { close(readyNotificationDone) })
		}
		return nil
	}
	resetReloadProxyRuntimeState = func() {}
	t.Cleanup(func() {
		cfgFile = previousConfigFile
		disablePidFile = previousDisablePidFile
		setRunSignalProgress = previousSetRunSignalProgress
		resetReloadProxyRuntimeState = previousResetReloadProxyRuntimeState
		listenControlPlaneFunc = previousListenControlPlane
		cloneControlListenerFunc = previousCloneControlListener
		linkRoutingEpochPeerFunc = previousLinkRoutingEpochPeer
		serveControlPlaneFunc = previousServeControlPlane
		withDaeNetnsRequiredFunc = previousWithDaeNetnsRequired
		reloadFailureCompletionHook = previousReloadFailureCompletionHook
	})
	t.Setenv(semanticRefactorFeaturesEnv, string(control.SemanticRefactorFeatureRoutingEpoch))

	var buildCalls atomic.Int32
	installControlPlaneRuntimeBuilderForTest(t, func(
		context.Context,
		*logrus.Logger,
		any,
		map[string]*control.DnsCache,
		map[string][]string,
		[]config.Group,
		*config.Routing,
		*config.Global,
		*config.Dns,
		[]string,
		bool,
		bool,
		bool,
	) (*control.ControlPlane, error) {
		if buildCalls.Add(1) == 1 {
			return &control.ControlPlane{}, nil
		}
		candidate := &control.ControlPlane{}
		wantErr := fmt.Errorf("injected %s stage failure", kind)
		candidate.SetServeLifecycleHooks(control.ServeLifecycleHooks{
			CommitPreparedDatapath: func() error {
				if kind == "bpf" {
					return wantErr
				}
				return nil
			},
			PublishListenerSockets: func(*control.Listener) error { return nil },
			ActivatePreparedRuntime: func() error {
				if kind == "dns" {
					return wantErr
				}
				return nil
			},
		})
		return candidate, nil
	})

	var listenCalls atomic.Int32
	var cloneCalls atomic.Int32
	var linkCalls atomic.Int32
	listenControlPlaneFunc = func(c *control.ControlPlane, port uint16) (*control.Listener, error) {
		listenCalls.Add(1)
		return c.Listen(port)
	}
	cloneControlListenerFunc = func(listener *control.Listener) (*control.Listener, error) {
		cloneCalls.Add(1)
		return listener.Clone()
	}
	linkRoutingEpochPeerFunc = func(*control.ControlPlane, *control.ControlPlane) error {
		linkCalls.Add(1)
		return nil
	}
	withDaeNetnsRequiredFunc = func(_ string, f func() error) error { return f() }

	initialReady := make(chan struct{})
	candidateFailed := make(chan struct{})
	initialServeDone := make(chan struct{})
	candidateServeDone := make(chan struct{})
	reloadFailureCompleted := make(chan struct{})
	serveStop := make(chan struct{})
	var stopOnce sync.Once
	defer stopOnce.Do(func() { close(serveStop) })
	reloadFailureCompletionHook = func() { close(reloadFailureCompleted) }
	var serveCalls atomic.Int32
	serveControlPlaneFunc = func(c *control.ControlPlane, readyChan chan<- bool, listener *control.Listener) error {
		if serveCalls.Add(1) == 1 {
			defer close(initialServeDone)
			readyChan <- true
			close(initialReady)
			<-serveStop
			return nil
		}
		defer close(candidateServeDone)
		err := c.Serve(readyChan, listener)
		close(candidateFailed)
		return err
	}

	conf, err := emptyConfig()
	if err != nil {
		t.Fatalf("emptyConfig() error = %v", err)
	}
	conf.Global.DisableWaitingNetwork = true
	runDone := make(chan error, 1)
	go func() {
		runDone <- newRunner(logrus.New(), conf, nil).Run()
	}()

	wait := func(ch <-chan struct{}, name string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for %s", name)
		}
	}
	wait(initialReady, "initial live-stage readiness")
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR2); err != nil {
		t.Fatalf("send live-stage reload signal: %v", err)
	}
	wait(candidateFailed, kind+" stage failure")
	wait(reloadFailureCompleted, kind+" rollback completion")
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send live-stage termination signal: %v", err)
	}
	stopOnce.Do(func() { close(serveStop) })

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Runner.Run() error = %v, want clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Runner.Run() did not terminate after %s stage rollback", kind)
	}
	wait(readyNotificationDone, "initial live-stage readiness notification")
	wait(initialServeDone, "initial live-stage Serve shutdown")
	wait(candidateServeDone, "candidate live-stage Serve shutdown")
	if buildCalls.Load() != 2 || listenCalls.Load() != 1 || cloneCalls.Load() != 1 || linkCalls.Load() != 1 || serveCalls.Load() != 2 {
		t.Fatalf("%s stage operation counts = builds=%d listens=%d clones=%d links=%d serves=%d", kind, buildCalls.Load(), listenCalls.Load(), cloneCalls.Load(), linkCalls.Load(), serveCalls.Load())
	}
	_, _ = fmt.Fprintln(os.Stdout, "runner-live-stage-failure-process-helper-ok")
}
