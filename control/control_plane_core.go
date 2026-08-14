/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/component"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// coreFlip should be 0 or 1; accessed atomically.
var coreFlip int32

var configureNetlinkSocketTimeoutOnce sync.Once

var (
	listTCFilters  = netlink.FilterList
	deleteTCFilter = netlink.FilterDel
)

type cgroupAttachment interface {
	io.Closer
}

var detectCgroupPathFunc = detectCgroupPath
var attachCgroupFunc = func(opts ciliumLink.CgroupOptions) (cgroupAttachment, error) {
	return ciliumLink.AttachCgroup(opts)
}

type sharedUdpConnStateTrackerEntry struct {
	tracker *udpConnStateTracker
	refs    int
}

var sharedUdpConnStateTrackerRegistry = struct {
	mu      sync.Mutex
	entries map[*bpfObjects]*sharedUdpConnStateTrackerEntry
}{
	entries: make(map[*bpfObjects]*sharedUdpConnStateTrackerEntry),
}

func acquireSharedUdpConnStateTracker(bpf *bpfObjects) *udpConnStateTracker {
	if bpf == nil {
		return newUdpConnStateTracker()
	}

	sharedUdpConnStateTrackerRegistry.mu.Lock()
	defer sharedUdpConnStateTrackerRegistry.mu.Unlock()

	entry := sharedUdpConnStateTrackerRegistry.entries[bpf]
	if entry == nil {
		entry = &sharedUdpConnStateTrackerEntry{
			tracker: newUdpConnStateTracker(),
		}
		sharedUdpConnStateTrackerRegistry.entries[bpf] = entry
	}
	entry.refs++
	return entry.tracker
}

func releaseSharedUdpConnStateTracker(bpf *bpfObjects, tracker *udpConnStateTracker) {
	if bpf == nil || tracker == nil {
		return
	}

	sharedUdpConnStateTrackerRegistry.mu.Lock()
	defer sharedUdpConnStateTrackerRegistry.mu.Unlock()

	entry := sharedUdpConnStateTrackerRegistry.entries[bpf]
	if entry == nil || entry.tracker != tracker {
		return
	}
	entry.refs--
	if entry.refs <= 0 {
		delete(sharedUdpConnStateTrackerRegistry.entries, bpf)
	}
}

type controlPlaneCore struct {
	mu      sync.Mutex
	deferMu sync.Mutex

	log        *logrus.Logger
	deferFuncs []func() error
	// bpfHookDetachFuncs contains only BPF hook detachment functions (FilterDel, tc detach)
	// These are tracked separately so they can be detached immediately on SIGTERM
	// before other cleanup that might take longer (like dialer shutdown).
	// Protected by bpfHookMu to avoid deadlock with c.mu in _bindLan/_bindWan.
	bpfHookDetachFuncs []func() error
	bpfHookMu          sync.Mutex
	bpfHookDetachMu    sync.Mutex
	bpfHookAttachWg    sync.WaitGroup
	bpf                atomic.Pointer[bpfObjects]
	outboundId2Name    map[uint8]string
	// tcpSockmapOffloadReady is set once setupTCPRelayOffload attaches the
	// sk_skb stream-verdict program to fast_sock (kernel passes the
	// CVE-2025-38165 gate). tryOffloadTCPRelay consults it per relay.
	tcpSockmapOffloadReady atomic.Bool

	kernelVersion *internal.Version

	flip             int
	flipBase         int32
	flipPending      bool
	isReload         bool
	bpfEjected       bool
	bpfHooksDetached bool // Track if BPF hooks were already detached
	bpfHooksQuiesced bool
	retired          atomic.Bool
	// outboundConnectivityMu serializes shared BPF connectivity-map ownership
	// with health callbacks while a prepared generation is cut over or rolled back.
	outboundConnectivityMu     sync.Mutex
	outboundConnectivityPaused bool

	closed                context.Context
	close                 context.CancelFunc
	ifmgr                 *component.InterfaceManager
	interfacePatternMu    sync.Mutex
	registeredLanPatterns map[string]struct{}
	registeredWanPatterns map[string]struct{}

	udpConnStateTracker       atomic.Pointer[udpConnStateTracker]
	domainRouting             *domainRoutingTracker
	domainRoutingSlots        [routingEpochSlotCount]*domainRoutingTracker
	domainRoutingProjectionMu [routingEpochSlotCount]sync.RWMutex
	routingEpochMu            sync.Mutex
	routingEpochSlot          atomic.Uint32
	routingEpochPreviousSlot  atomic.Uint32
	routingEpochRollbackOff   atomic.Bool
	routingEpochPolicyEpoch   atomic.Uint64
	datapathGeneration        atomic.Uint32
	routingEpochStaged        bool
	routingEpochStagedSlot    uint32
	routingEpochStagedEpoch   uint64
	// routingEpochActiveSlotCache short-circuits readActiveRoutingEpochSlot.
	// The active slot only changes on PublishRoutingEpoch/RollbackRoutingEpoch,
	// so the per-packet eBPF lookup on the UDP hot path is pure waste
	// (measured ~15% CPU under saturated UDP ingress).
	routingEpochActiveSlotCachedAt    atomic.Int64
	routingEpochActiveSlotCached      atomic.Uint32
	routingEpochActiveSlotCachedValid atomic.Bool
	lpmTrieIndices                    []uint32
	bpfOwned                          bool
}

func newControlPlaneCore(log *logrus.Logger,
	bpf *bpfObjects,
	outboundId2Name map[uint8]string,
	kernelVersion *internal.Version,
	isReload bool,
	bpfOwned bool,
) *controlPlaneCore {
	configureNetlinkSocketTimeoutOnce.Do(func() {
		if err := netlink.SetSocketTimeout(controlPlaneDeferredCleanupTimeout); err != nil && log != nil {
			log.WithError(err).Warn("Failed to configure netlink socket timeout")
		}
	})

	var flip int
	var flipBase int32
	var flipPending bool
	if isReload {
		flipBase = atomic.LoadInt32(&coreFlip) & 1
		flip = int(flipBase ^ 1)
		flipPending = true
	} else {
		flip = int(atomic.LoadInt32(&coreFlip))
	}
	var deferFuncs []func() error
	closed, toClose := context.WithCancel(context.Background())
	ifmgr := component.NewInterfaceManager(log)
	deferFuncs = append(deferFuncs, ifmgr.Close)
	core := &controlPlaneCore{
		log:                   log,
		deferFuncs:            deferFuncs,
		bpfHookDetachFuncs:    make([]func() error, 0),
		outboundId2Name:       outboundId2Name,
		kernelVersion:         kernelVersion,
		flip:                  flip,
		flipBase:              flipBase,
		flipPending:           flipPending,
		isReload:              isReload,
		bpfEjected:            false,
		bpfHooksDetached:      false,
		bpfHooksQuiesced:      false,
		ifmgr:                 ifmgr,
		registeredLanPatterns: make(map[string]struct{}),
		registeredWanPatterns: make(map[string]struct{}),
		closed:                closed,
		close:                 toClose,
		domainRouting:         newDomainRoutingTracker(),
		bpfOwned:              bpfOwned,
	}
	core.domainRoutingSlots[0] = core.domainRouting
	core.domainRoutingSlots[1] = newDomainRoutingTracker()
	core.routingEpochSlot.Store(routingEpochSlotUnset)
	core.routingEpochPreviousSlot.Store(routingEpochSlotUnset)
	core.routingEpochStagedSlot = routingEpochSlotUnset
	core.datapathGeneration.Store(uint32(bpfDatapathGeneration(bpf)))
	core.bpf.Store(bpf)
	core.udpConnStateTracker.Store(acquireSharedUdpConnStateTracker(bpf))
	core.startIfindexWatcher()
	return core
}

func (c *controlPlaneCore) commitBpfHookFlip() error {
	if c == nil || !c.flipPending {
		return nil
	}
	if !atomic.CompareAndSwapInt32(&coreFlip, c.flipBase, int32(c.flip)) {
		return fmt.Errorf("BPF hook flip changed during reload: active=%d expected=%d", atomic.LoadInt32(&coreFlip)&1, c.flipBase)
	}
	c.flipPending = false
	return nil
}

func (c *controlPlaneCore) rollbackCommittedBpfHookFlip() error {
	if c == nil || c.flipPending || !c.isReload {
		return nil
	}
	active := atomic.LoadInt32(&coreFlip) & 1
	if active == c.flipBase {
		c.flipPending = true
		return nil
	}
	if active != int32(c.flip) {
		return fmt.Errorf("BPF hook flip changed before rollback: active=%d candidate=%d previous=%d", active, c.flip, c.flipBase)
	}
	if !atomic.CompareAndSwapInt32(&coreFlip, int32(c.flip), c.flipBase) {
		return fmt.Errorf("BPF hook flip changed during rollback: active=%d candidate=%d previous=%d", atomic.LoadInt32(&coreFlip)&1, c.flip, c.flipBase)
	}
	c.flipPending = true
	return nil
}

func (c *controlPlaneCore) activateBpfHookFlip() {
	if c == nil {
		return
	}
	atomic.StoreInt32(&coreFlip, int32(c.flip))
	c.flipBase = int32(c.flip)
	c.flipPending = false
}

func (c *controlPlaneCore) getUdpConnStateTracker() *udpConnStateTracker {
	if c == nil {
		return nil
	}
	if tracker := c.udpConnStateTracker.Load(); tracker != nil {
		return tracker
	}
	tracker := acquireSharedUdpConnStateTracker(c.bpf.Load())
	if c.udpConnStateTracker.CompareAndSwap(nil, tracker) {
		return tracker
	}
	releaseSharedUdpConnStateTracker(c.bpf.Load(), tracker)
	return c.udpConnStateTracker.Load()
}

func (c *controlPlaneCore) Flip() {
	// Use CAS loop to avoid race condition between Load and Store.
	for {
		old := atomic.LoadInt32(&coreFlip)
		newVal := old&1 ^ 1
		if atomic.CompareAndSwapInt32(&coreFlip, old, newVal) {
			break
		}
	}
}

// addBpfHookDetach adds a BPF hook detachment function to the dedicated list.
// These functions will be executed immediately on SIGTERM before other cleanup.
// Uses bpfHookMu to avoid deadlock with c.mu held by callers like _bindLan/_bindWan.
func (c *controlPlaneCore) addBpfHookDetach(detachFunc func() error) bool {
	c.bpfHookMu.Lock()
	defer c.bpfHookMu.Unlock()
	if c.bpfHooksQuiesced {
		return false
	}
	c.bpfHookDetachFuncs = append(c.bpfHookDetachFuncs, detachFunc)
	return true
}

func (c *controlPlaneCore) beginBpfHookAttach() bool {
	c.bpfHookMu.Lock()
	defer c.bpfHookMu.Unlock()
	if c.bpfHooksQuiesced {
		return false
	}
	c.bpfHookAttachWg.Add(1)
	return true
}

func (c *controlPlaneCore) endBpfHookAttach() {
	c.bpfHookAttachWg.Done()
}

func (c *controlPlaneCore) addDeferFunc(deferFunc func() error) bool {
	c.deferMu.Lock()
	defer c.deferMu.Unlock()
	select {
	case <-c.closed.Done():
		return false
	default:
	}
	c.deferFuncs = append(c.deferFuncs, deferFunc)
	return true
}

// addManagedBpfHookCleanup registers hook cleanup for both regular close and
// immediate detach paths. Hook cleanup must remain active after EjectBpf():
// ownership transfer only skips bpf.Close(), not removal of this generation's
// TC filters from the system.
func (c *controlPlaneCore) addManagedBpfHookCleanup(detachFunc func() error) {
	var (
		cleanupMu sync.Mutex
		detached  bool
	)
	managedDetach := func() error {
		cleanupMu.Lock()
		defer cleanupMu.Unlock()
		if detached {
			return nil
		}
		if err := detachFunc(); err != nil {
			return err
		}
		detached = true
		return nil
	}

	if !c.addDeferFunc(managedDetach) {
		if err := managedDetach(); err != nil && c.log != nil {
			c.log.WithError(err).Warn("controlPlaneCore: failed to detach hook after close began")
		}
		return
	}
	if !c.addBpfHookDetach(managedDetach) {
		if err := managedDetach(); err != nil && c.log != nil {
			c.log.WithError(err).Warn("controlPlaneCore: failed to detach hook registered after detach began")
		}
	}
}

func (c *controlPlaneCore) resetBpfHookDetachForReattach() {
	c.bpfHookMu.Lock()
	c.bpfHookDetachFuncs = nil
	c.bpfHooksDetached = false
	c.bpfHooksQuiesced = false
	c.bpfHookMu.Unlock()

	c.interfacePatternMu.Lock()
	oldIfmgr := c.ifmgr
	c.ifmgr = component.NewInterfaceManager(c.log)
	c.registeredLanPatterns = make(map[string]struct{})
	c.registeredWanPatterns = make(map[string]struct{})
	newIfmgr := c.ifmgr
	c.interfacePatternMu.Unlock()
	if oldIfmgr != nil {
		_ = oldIfmgr.Close()
	}
	c.addDeferFunc(newIfmgr.Close)
}

// DetachBpfHooks immediately detaches all BPF hooks from the system.
// This should be called first when receiving SIGTERM to ensure network is restored
// even if the rest of the shutdown process takes too long and gets SIGKILL'd.
// This is safe to call multiple times - subsequent calls will be no-ops.
func (c *controlPlaneCore) DetachBpfHooks() error {
	c.bpfHookDetachMu.Lock()
	defer c.bpfHookDetachMu.Unlock()

	c.bpfHookMu.Lock()
	if c.bpfHooksDetached {
		c.bpfHookMu.Unlock()
		return nil
	}
	c.bpfHooksQuiesced = true
	c.bpfHookMu.Unlock()
	if c.ifmgr != nil {
		_ = c.ifmgr.Close()
	}
	c.bpfHookAttachWg.Wait()

	c.bpfHookMu.Lock()
	defer c.bpfHookMu.Unlock()

	c.log.Infoln("[Shutdown] Detaching BPF hooks immediately to restore network")

	var errs []error
	// Execute in reverse order (last attached, first detached)
	for i := len(c.bpfHookDetachFuncs) - 1; i >= 0; i-- {
		if e := c.bpfHookDetachFuncs[i](); e != nil {
			// Log but continue detaching other hooks
			c.log.WithError(e).Warnln("[Shutdown] Failed to detach BPF hook")
			errs = append(errs, e)
		}
	}

	if len(errs) > 0 {
		c.bpfHooksDetached = false
		return errors.Join(errs...)
	}
	c.bpfHooksDetached = true
	c.log.Infoln("[Shutdown] BPF hooks detached, network should be restored")
	return nil
}

func (c *controlPlaneCore) Close() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	bpf := c.bpf.Load()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	// Invoke defer funcs in reverse order and collect errors.
	// Use errors.Join (Go 1.20+) for clean multi-error handling.
	var errs []error
	// Clear LPM slots still owned by this generation. Retired generations hand
	// their slots to the next generation before draining so they cannot delete a
	// slot that has already been reused by a later reload.
	if bpf != nil && bpf.LpmArrayMap != nil && len(c.lpmTrieIndices) > 0 {
		for _, idx := range c.lpmTrieIndices {
			if e := bpf.LpmArrayMap.Delete(idx); e != nil && !errors.Is(e, ebpf.ErrKeyNotExist) {
				c.log.Errorf("Failed to clear BPF LPM slot %d: %v", idx, e)
			}
		}
	}
	c.close()
	c.deferMu.Lock()
	deferFuncs := append([]func() error(nil), c.deferFuncs...)
	c.deferFuncs = nil
	c.deferMu.Unlock()

	for i := len(deferFuncs) - 1; i >= 0; i-- {
		if e := deferFuncs[i](); e != nil {
			errs = append(errs, e)
		}
	}

	if c.bpfOwned && bpf != nil {
		if e := bpf.Close(); e != nil {
			errs = append(errs, e)
		}
		unregisterBpfDatapathGeneration(bpf)
	}
	if tracker := c.udpConnStateTracker.Swap(nil); tracker != nil {
		releaseSharedUdpConnStateTracker(bpf, tracker)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// EjectBpf will resect bpf from destroying life-cycle of control plane core.
func (c *controlPlaneCore) EjectBpf() *bpfObjects {
	c.mu.Lock()
	defer c.mu.Unlock()
	bpf := c.bpf.Load()
	if c.bpfEjected {
		return bpf
	}

	// Transfer ownership: this generation is no longer responsible for closing BPF.
	c.bpfOwned = false
	c.bpfEjected = true

	// Stop link watcher immediately during handover period to avoid race condition
	// between old and new control planes reacting to link events (e.g. PPPoE flapping).
	_ = c.ifmgr.Close()

	return bpf
}

func (c *controlPlaneCore) EjectLpmIndices() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.routingEpochEnabled() {
		// The retiring generation keeps its slot until Close() so a later
		// route retry cannot observe a reused LPM map while it still drains.
		return nil
	}

	indices := c.lpmTrieIndices
	c.lpmTrieIndices = nil
	return indices
}

// InheritLpmIndices adopts retired generations' ring slots. Slots that are no
// longer referenced by the current generation are deleted immediately to free
// memory; slots already reused by the current generation are skipped.
func (c *controlPlaneCore) InheritLpmIndices(indices []uint32) {
	if len(indices) == 0 {
		return
	}
	if c.routingEpochEnabled() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	bpf := c.bpf.Load()

	current := make(map[uint32]struct{}, len(c.lpmTrieIndices))
	for _, idx := range c.lpmTrieIndices {
		current[idx] = struct{}{}
	}

	pending := make([]uint32, 0, len(indices))
	for _, idx := range indices {
		if _, reused := current[idx]; reused {
			continue
		}
		if bpf == nil || bpf.LpmArrayMap == nil {
			pending = append(pending, idx)
			current[idx] = struct{}{}
			continue
		}
		if err := bpf.LpmArrayMap.Delete(idx); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			c.log.Errorf("Failed to clear inherited BPF LPM slot %d: %v", idx, err)
			pending = append(pending, idx)
			current[idx] = struct{}{}
		}
	}
	c.lpmTrieIndices = append(c.lpmTrieIndices, pending...)
}

// ReplaceLpmIndices installs a new active LPM index set for this generation
// and eagerly reclaims the superseded indices when possible.
func (c *controlPlaneCore) ReplaceLpmIndices(indices []uint32) {
	c.mu.Lock()
	bpf := c.bpf.Load()
	old := c.lpmTrieIndices
	c.lpmTrieIndices = append([]uint32(nil), indices...)
	shouldCleanupOld := bpf != nil && bpf.LpmArrayMap != nil && !c.routingEpochEnabled()
	c.mu.Unlock()

	if shouldCleanupOld {
		c.InheritLpmIndices(old)
	}
}

// InjectBpf will inject bpf back.
func (c *controlPlaneCore) InjectBpf(bpf *bpfObjects) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if bpf != nil {
		c.bpf.Store(bpf)
		c.datapathGeneration.Store(uint32(bpfDatapathGeneration(bpf)))
	}
	c.bpfEjected = false
	c.bpfOwned = true
}

// PeekBpf returns the current BPF objects without transferring ownership.
// Background maintenance paths such as janitors and health checks should use
// this accessor instead of EjectBpf to avoid disturbing reload lifecycle.
func (c *controlPlaneCore) PeekBpf() *bpfObjects {
	return c.bpf.Load()
}

// startIfindexWatcher subscribes to netlink RTM_NEWLINK events and hot-updates
// the dae_ifindex_map when dae0 is recreated with a new ifindex by the kernel.
// This avoids silent packet loss that would otherwise require a full BPF reload.
func (c *controlPlaneCore) startIfindexWatcher() {
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	if err := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			select {
			case <-c.closed.Done():
				return
			default:
				c.log.Debug("ifindex watcher LinkSubscribe:", err)
			}
		},
		ListExisting: true,
	}); err != nil {
		c.log.Errorf("Failed to subscribe to link updates for ifindex watcher: %v", err)
		return
	}

	go func() {
		defer close(done)
		for {
			select {
			case <-c.closed.Done():
				return
			case upd, ok := <-ch:
				if !ok {
					return
				}
				if upd.Link.Attrs().Name != HostVethName {
					continue
				}
				newIfindex := uint32(upd.Link.Attrs().Index)
				bpf := c.PeekBpf()
				if bpf == nil || bpf.DaeIfindexMap == nil {
					continue
				}
				var currentIfindex uint32
				if err := bpf.DaeIfindexMap.Lookup(uint32(0), &currentIfindex); err != nil {
					currentIfindex = 0
				}
				if newIfindex == currentIfindex {
					continue
				}
				if err := bpf.DaeIfindexMap.Update(uint32(0), newIfindex, ebpf.UpdateAny); err != nil {
					c.log.Errorf("Failed to update dae_ifindex_map: %v", err)
				} else {
					c.log.Warnf("dae0 ifindex drift detected and recovered: %d -> %d", currentIfindex, newIfindex)
				}
			}
		}
	}()
}
