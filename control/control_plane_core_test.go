package control

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func TestControlPlaneCore_Flip_Race(t *testing.T) {
	// coreFlip is global in package control.
	// Reset it to 0 for deterministic test.
	atomic.StoreInt32(&coreFlip, 0)

	// Since Flip() doesn't access any struct fields, we can use an empty struct.
	c := &controlPlaneCore{}

	var wg sync.WaitGroup
	iterations := 1000 // Must be even

	for range iterations {
		wg.Go(func() {
			c.Flip()
		})
	}

	wg.Wait()

	val := atomic.LoadInt32(&coreFlip)
	// If atomic operations are correct, flipping 0 an even number of times should result in 0.
	// If a race occurred (e.g. lost update), the result might be 1.
	if val != 0 {
		t.Errorf("Expected coreFlip to be 0 after %d flips, got %d. Race condition detected.", iterations, val)
	}
}

func TestControlPlaneCore_EjectBpfKeepsHookCleanupForClose(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, false, true)
	calls := 0
	core.addManagedBpfHookCleanup(func() error {
		calls++
		return nil
	})

	core.EjectBpf()
	if core.bpfOwned {
		t.Fatal("expected EjectBpf to transfer BPF ownership")
	}

	if err := core.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	if calls != 1 {
		t.Fatalf("expected hook cleanup to run once after EjectBpf, got %d", calls)
	}
}

func TestControlPlaneCore_InjectBpfClaimsOwnershipForReloadGeneration(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, true, false)
	if core.bpfOwned {
		t.Fatal("expected reload generation to start without BPF ownership")
	}

	core.InjectBpf(nil)

	if !core.bpfOwned {
		t.Fatal("expected InjectBpf to claim BPF ownership")
	}
	if core.bpfEjected {
		t.Fatal("expected InjectBpf to clear the ejected state")
	}
}

func TestControlPlaneCore_FreshReloadGenerationCanOwnBpf(t *testing.T) {
	atomic.StoreInt32(&coreFlip, 0)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, true, true)

	if !core.isReload {
		t.Fatal("expected fresh reload generation to keep reload flip semantics")
	}
	if !core.bpfOwned {
		t.Fatal("expected fresh reload generation to own freshly loaded BPF")
	}
	if got := atomic.LoadInt32(&coreFlip); got != 0 {
		t.Fatalf("coreFlip changed during preparation: got %d, want 0", got)
	}
	if !core.flipPending || core.flip != 1 {
		t.Fatalf("reload flip reservation = (pending=%v, flip=%d), want (true, 1)", core.flipPending, core.flip)
	}
}

func TestControlPlaneCore_ReloadFlipIsCommittedTransactionally(t *testing.T) {
	atomic.StoreInt32(&coreFlip, 0)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	failedPreparation := newControlPlaneCore(logger, nil, nil, nil, true, false)
	if failedPreparation.flip != 1 {
		t.Fatalf("failed preparation reserved flip %d, want 1", failedPreparation.flip)
	}
	if got := atomic.LoadInt32(&coreFlip); got != 0 {
		t.Fatalf("failed preparation changed active flip to %d", got)
	}

	retry := newControlPlaneCore(logger, nil, nil, nil, true, false)
	if retry.flip != 1 {
		t.Fatalf("retry reserved flip %d, want 1", retry.flip)
	}
	if err := retry.commitBpfHookFlip(); err != nil {
		t.Fatalf("commitBpfHookFlip() error = %v", err)
	}
	if got := atomic.LoadInt32(&coreFlip); got != 1 {
		t.Fatalf("active flip after commit = %d, want 1", got)
	}

	next := newControlPlaneCore(logger, nil, nil, nil, true, false)
	if next.flip != 0 {
		t.Fatalf("next reload reserved flip %d, want 0", next.flip)
	}
}

func TestControlPlaneCore_HookDetachRetriesFailureAndCloseIsIdempotent(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	core := newControlPlaneCore(logger, nil, nil, nil, false, false)

	attempts := 0
	core.addManagedBpfHookCleanup(func() error {
		attempts++
		if attempts == 1 {
			return fmt.Errorf("transient detach failure")
		}
		return nil
	})

	if err := core.DetachBpfHooks(); err == nil {
		t.Fatal("first DetachBpfHooks() error = nil, want failure")
	}
	if core.bpfHooksDetached {
		t.Fatal("failed detach must not mark hooks detached")
	}
	if err := core.DetachBpfHooks(); err != nil {
		t.Fatalf("second DetachBpfHooks() error = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("detach attempts after Close = %d, want 2", attempts)
	}
}

func TestControlPlaneCore_HookRegisteredAfterDetachIsRemovedImmediately(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	core := newControlPlaneCore(logger, nil, nil, nil, false, false)

	if err := core.DetachBpfHooks(); err != nil {
		t.Fatalf("DetachBpfHooks() error = %v", err)
	}
	calls := 0
	core.addManagedBpfHookCleanup(func() error {
		calls++
		return nil
	})
	if calls != 1 {
		t.Fatalf("late hook cleanup calls = %d, want 1", calls)
	}
	if got := len(core.bpfHookDetachFuncs); got != 0 {
		t.Fatalf("registered hook count after quiesce = %d, want 0", got)
	}
}

func TestControlPlaneCore_DetachWaitsForInFlightHookAttach(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	core := newControlPlaneCore(logger, nil, nil, nil, false, false)

	if !core.beginBpfHookAttach() {
		t.Fatal("beginBpfHookAttach() rejected before detach")
	}
	detached := make(chan error, 1)
	go func() {
		detached <- core.DetachBpfHooks()
	}()

	select {
	case err := <-detached:
		t.Fatalf("DetachBpfHooks returned before attach completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	core.endBpfHookAttach()
	if err := <-detached; err != nil {
		t.Fatalf("DetachBpfHooks() error = %v", err)
	}
	if core.beginBpfHookAttach() {
		core.endBpfHookAttach()
		t.Fatal("beginBpfHookAttach() accepted after detach quiesced hooks")
	}
}

func TestControlPlaneCore_AttachMatchingInterfacesIsSynchronous(t *testing.T) {
	core := &controlPlaneCore{}
	called := false
	if err := core.attachMatchingInterfaces("lo", func(link netlink.Link) error {
		called = true
		if link.Attrs().Name != "lo" {
			t.Fatalf("matched link = %q, want lo", link.Attrs().Name)
		}
		return nil
	}); err != nil {
		t.Fatalf("attachMatchingInterfaces() error = %v", err)
	}
	if !called {
		t.Fatal("attachMatchingInterfaces returned before invoking the current-link callback")
	}
}

func TestControlPlaneCore_ResetBpfHookDetachForReattach(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, true, true)
	oldDetachCalls := 0
	core.addManagedBpfHookCleanup(func() error {
		oldDetachCalls++
		return nil
	})

	if err := core.DetachBpfHooks(); err != nil {
		t.Fatalf("DetachBpfHooks() error = %v", err)
	}
	if oldDetachCalls != 1 {
		t.Fatalf("old detach calls = %d, want 1", oldDetachCalls)
	}

	core.resetBpfHookDetachForReattach()
	if core.bpfHooksDetached {
		t.Fatal("expected reset to clear detached state before reattach")
	}
	if got := len(core.bpfHookDetachFuncs); got != 0 {
		t.Fatalf("len(bpfHookDetachFuncs) = %d, want 0 after reset", got)
	}

	newDetachCalls := 0
	core.addManagedBpfHookCleanup(func() error {
		newDetachCalls++
		return nil
	})
	if err := core.DetachBpfHooks(); err != nil {
		t.Fatalf("second DetachBpfHooks() error = %v", err)
	}
	if oldDetachCalls != 1 {
		t.Fatalf("old detach calls after reattach = %d, want 1", oldDetachCalls)
	}
	if newDetachCalls != 1 {
		t.Fatalf("new detach calls = %d, want 1", newDetachCalls)
	}
}

func TestControlPlaneCore_InheritLpmIndicesSkipsReusedSlots(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, true, false)
	core.lpmTrieIndices = []uint32{4, 5}

	core.InheritLpmIndices([]uint32{1, 4, 7})

	got := make(map[uint32]struct{}, len(core.lpmTrieIndices))
	for _, idx := range core.lpmTrieIndices {
		got[idx] = struct{}{}
	}

	for _, want := range []uint32{1, 4, 5, 7} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected inherited index set to contain %d, got %#v", want, core.lpmTrieIndices)
		}
	}
	if len(got) != 4 {
		t.Fatalf("expected no duplicate inherited indices, got %#v", core.lpmTrieIndices)
	}
}

func TestControlPlaneCore_EjectLpmIndicesTransfersOwnership(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, false, true)
	core.lpmTrieIndices = []uint32{2, 3, 5}

	indices := core.EjectLpmIndices()

	if len(core.lpmTrieIndices) != 0 {
		t.Fatalf("expected core LPM indices to be cleared after ejection, got %#v", core.lpmTrieIndices)
	}
	if len(indices) != 3 {
		t.Fatalf("expected 3 ejected LPM indices, got %#v", indices)
	}
}

func TestControlPlaneCore_ReplaceLpmIndicesReplacesTrackedSet(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, false, true)
	core.lpmTrieIndices = []uint32{2, 3, 5}

	core.ReplaceLpmIndices([]uint32{7, 11})

	if got := core.lpmTrieIndices; len(got) != 2 || got[0] != 7 || got[1] != 11 {
		t.Fatalf("expected replaced LPM indices [7 11], got %#v", got)
	}
}

type fakeCgroupAttachment struct {
	closeCalls atomic.Int32
}

func (f *fakeCgroupAttachment) Close() error {
	f.closeCalls.Add(1)
	return nil
}

func TestControlPlaneCore_SetupSkPidMonitorRollsBackPartialAttach(t *testing.T) {
	oldDetect := detectCgroupPathFunc
	oldAttach := attachCgroupFunc
	detectCgroupPathFunc = func() (string, error) { return "/sys/fs/cgroup", nil }
	var attachments []*fakeCgroupAttachment
	attachCgroupFunc = func(ciliumLink.CgroupOptions) (cgroupAttachment, error) {
		attachment := &fakeCgroupAttachment{}
		attachments = append(attachments, attachment)
		if len(attachments) == 3 {
			return nil, fmt.Errorf("boom")
		}
		return attachment, nil
	}
	defer func() {
		detectCgroupPathFunc = oldDetect
		attachCgroupFunc = oldAttach
	}()

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	core := newControlPlaneCore(logger, &bpfObjects{
		bpfPrograms: bpfPrograms{
			TproxyWanCgSockCreate:  &ebpf.Program{},
			TproxyWanCgSockRelease: &ebpf.Program{},
			TproxyWanCgConnect4:    &ebpf.Program{},
			TproxyWanCgConnect6:    &ebpf.Program{},
			TproxyWanCgSendmsg4:    &ebpf.Program{},
			TproxyWanCgSendmsg6:    &ebpf.Program{},
		},
	}, nil, nil, false, true)

	if err := core.setupSkPidMonitor(); err == nil {
		t.Fatal("setupSkPidMonitor() error = nil, want failure")
	}
	if got := len(core.bpfHookDetachFuncs); got != 0 {
		t.Fatalf("len(bpfHookDetachFuncs) = %d, want 0 after rollback", got)
	}
	if got := attachments[0].closeCalls.Load(); got != 1 {
		t.Fatalf("first attachment Close() calls = %d, want 1", got)
	}
	if got := attachments[1].closeCalls.Load(); got != 1 {
		t.Fatalf("second attachment Close() calls = %d, want 1", got)
	}
}
