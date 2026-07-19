/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type egressRuntimeClosableDialer struct {
	closeCalls atomic.Int32
}

func (d *egressRuntimeClosableDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, io.ErrClosedPipe
}

func (d *egressRuntimeClosableDialer) Close() error {
	d.closeCalls.Add(1)
	return nil
}

func newEgressRuntimeTestDialer(t *testing.T, _ string) (*dialer.Dialer, *egressRuntimeClosableDialer, *dialer.GlobalOption) {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	option := &dialer.GlobalOption{
		Log:            log,
		CheckInterval:  time.Second,
		CheckTolerance: time.Second,
	}
	underlay := &egressRuntimeClosableDialer{}
	d := dialer.NewDialer(
		underlay,
		option,
		dialer.InstanceOption{DisableCheck: true},
		&dialer.Property{},
	)
	return d, underlay, option
}

func TestEgressRuntimeDefersReverseCleanupUntilLastFlow(t *testing.T) {
	var (
		mu    sync.Mutex
		order []int
	)
	runtime := newEgressRuntime(nil, []func() error{
		func() error { mu.Lock(); order = append(order, 1); mu.Unlock(); return nil },
		func() error { mu.Lock(); order = append(order, 2); mu.Unlock(); return nil },
	})
	first, ok := runtime.acquire()
	if !ok {
		t.Fatal("first acquire failed")
	}
	second, ok := runtime.acquire()
	if !ok {
		t.Fatal("second acquire failed")
	}
	if err := runtime.releaseOwner(); err != nil {
		t.Fatalf("releaseOwner() error = %v", err)
	}
	if got := runtime.activeReferences(); got != 2 {
		t.Fatalf("references after owner release = %d, want 2", got)
	}
	if err := first.release(); err != nil {
		t.Fatalf("first release error = %v", err)
	}
	if len(order) != 0 {
		t.Fatalf("cleanup ran with one flow active: %v", order)
	}
	if err := second.release(); err != nil {
		t.Fatalf("second release error = %v", err)
	}
	if !reflect.DeepEqual(order, []int{2, 1}) {
		t.Fatalf("cleanup order = %v, want [2 1]", order)
	}
	if _, ok := runtime.acquire(); ok {
		t.Fatal("acquire succeeded after owner retirement")
	}
}

func TestEgressRuntimeLeaseReleaseIsExactlyOnce(t *testing.T) {
	cleanupCalls := 0
	runtime := newEgressRuntime(nil, []func() error{func() error {
		cleanupCalls++
		return nil
	}})
	lease, ok := runtime.acquire()
	if !ok {
		t.Fatal("acquire failed")
	}
	if err := runtime.releaseOwner(); err != nil {
		t.Fatalf("releaseOwner() error = %v", err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = lease.release()
		}()
	}
	wg.Wait()
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
	}
}

func TestEgressRuntimeRetainsOnlySelectedDialerAfterOwnerRelease(t *testing.T) {
	selected, selectedUnderlay, option := newEgressRuntimeTestDialer(t, "selected")
	unused, unusedUnderlay, _ := newEgressRuntimeTestDialer(t, "unused")
	group := outbound.NewDialerGroup(
		option,
		"proxy",
		[]*dialer.Dialer{selected, unused},
		[]*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random},
		func(bool, *dialer.NetworkType, bool) {},
	)
	cleanupCalls := atomic.Int32{}
	var forgotten []*dialer.Dialer
	runtime := newEgressRuntime(nil, []func() error{func() error {
		cleanupCalls.Add(1)
		return nil
	}})
	runtime.configureResources(
		[]*outbound.DialerGroup{group},
		[]*dialer.Dialer{selected, unused},
		func(dialers []*dialer.Dialer) { forgotten = append(forgotten, dialers...) },
	)

	lease, retainedGroup, ok := runtime.acquireEgress(selected, group)
	if !ok {
		t.Fatal("acquireEgress() failed")
	}
	if retainedGroup == group {
		t.Fatal("flow retained the full outbound group")
	}
	if retainedGroup.Name != group.Name || retainedGroup.GetSelectionPolicy() != group.GetSelectionPolicy() {
		t.Fatalf("retained group metadata = (%q, %v), want (%q, %v)", retainedGroup.Name, retainedGroup.GetSelectionPolicy(), group.Name, group.GetSelectionPolicy())
	}
	if len(retainedGroup.Dialers) != 1 || retainedGroup.Dialers[0] != selected {
		t.Fatalf("retained group dialers = %v, want selected dialer only", retainedGroup.Dialers)
	}

	if err := runtime.releaseOwner(); err != nil {
		t.Fatalf("releaseOwner() error = %v", err)
	}
	if got := unusedUnderlay.closeCalls.Load(); got != 1 {
		t.Fatalf("unused dialer close calls = %d, want 1", got)
	}
	if got := selectedUnderlay.closeCalls.Load(); got != 0 {
		t.Fatalf("selected dialer close calls while flow is active = %d, want 0", got)
	}
	if cleanupCalls.Load() != 0 {
		t.Fatal("transport namespace cleanup ran while selected flow is active")
	}
	if !reflect.DeepEqual(forgotten, []*dialer.Dialer{unused}) {
		t.Fatalf("forgotten dialers = %v, want unused dialer only", forgotten)
	}
	runtime.mu.Lock()
	if len(runtime.groups) != 0 || len(runtime.snapshots) != 0 || len(runtime.dialerRefs) != 1 {
		t.Fatalf("retired runtime retained groups=%d snapshots=%d dialers=%d", len(runtime.groups), len(runtime.snapshots), len(runtime.dialerRefs))
	}
	runtime.mu.Unlock()

	if err := lease.release(); err != nil {
		t.Fatalf("lease.release() error = %v", err)
	}
	if got := selectedUnderlay.closeCalls.Load(); got != 1 {
		t.Fatalf("selected dialer close calls after final flow = %d, want 1", got)
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("transport namespace cleanup calls = %d, want 1", cleanupCalls.Load())
	}
	if !reflect.DeepEqual(forgotten, []*dialer.Dialer{unused, selected}) {
		t.Fatalf("forgotten dialers after final flow = %v, want unused then selected", forgotten)
	}
}

func TestEgressRuntimeResourceReleaseIsConcurrentExactlyOnce(t *testing.T) {
	selected, selectedUnderlay, option := newEgressRuntimeTestDialer(t, "selected")
	group := outbound.NewDialerGroup(
		option,
		"proxy",
		[]*dialer.Dialer{selected},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *dialer.NetworkType, bool) {},
	)
	cleanupCalls := atomic.Int32{}
	runtime := newEgressRuntime(nil, []func() error{func() error {
		cleanupCalls.Add(1)
		return nil
	}})
	runtime.configureResources([]*outbound.DialerGroup{group}, []*dialer.Dialer{selected}, nil)

	const flowCount = 64
	leases := make([]*egressRuntimeLease, 0, flowCount)
	for range flowCount {
		lease, _, ok := runtime.acquireEgress(selected, group)
		if !ok {
			t.Fatal("acquireEgress() failed")
		}
		leases = append(leases, lease)
	}
	if err := runtime.releaseOwner(); err != nil {
		t.Fatalf("releaseOwner() error = %v", err)
	}
	var wg sync.WaitGroup
	for _, lease := range leases {
		for range 2 {
			wg.Add(1)
			go func(lease *egressRuntimeLease) {
				defer wg.Done()
				_ = lease.release()
			}(lease)
		}
	}
	wg.Wait()
	if got := selectedUnderlay.closeCalls.Load(); got != 1 {
		t.Fatalf("selected dialer close calls = %d, want 1", got)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestEgressRuntimeDoesNotCloseSharedTransportThroughUnusedWrapper(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	option := &dialer.GlobalOption{
		Log:            log,
		CheckInterval:  time.Second,
		CheckTolerance: time.Second,
	}
	underlay := &egressRuntimeClosableDialer{}
	selected := dialer.NewDialer(underlay, option, dialer.InstanceOption{DisableCheck: true}, &dialer.Property{})
	unusedWrapper := dialer.NewDialer(underlay, option, dialer.InstanceOption{DisableCheck: true}, &dialer.Property{})
	group := outbound.NewDialerGroup(
		option,
		"proxy",
		[]*dialer.Dialer{selected, unusedWrapper},
		[]*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *dialer.NetworkType, bool) {},
	)
	runtime := newEgressRuntime(nil, nil)
	runtime.configureResources([]*outbound.DialerGroup{group}, []*dialer.Dialer{selected, unusedWrapper}, nil)
	lease, _, ok := runtime.acquireEgress(selected, group)
	if !ok {
		t.Fatal("acquireEgress() failed")
	}

	if err := runtime.releaseOwner(); err != nil {
		t.Fatalf("releaseOwner() error = %v", err)
	}
	if got := underlay.closeCalls.Load(); got != 0 {
		t.Fatalf("shared transport closed through unused wrapper: close calls = %d", got)
	}
	if err := lease.release(); err != nil {
		t.Fatalf("lease.release() error = %v", err)
	}
	if got := underlay.closeCalls.Load(); got != 1 {
		t.Fatalf("shared transport close calls after final flow = %d, want 1", got)
	}
}
