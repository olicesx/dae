/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

type routingEpochExecutionOwnerPublication uint8

const (
	routingEpochExecutionOwnerProvisional routingEpochExecutionOwnerPublication = 1 << iota
	routingEpochExecutionOwnerPublished
)

var activeControlPlanePublication struct {
	mu     sync.RWMutex
	plane  atomic.Pointer[ControlPlane]
	owners map[*ControlPlane]routingEpochExecutionOwnerPublication
}

func (c *ControlPlane) publishActiveControlPlane() {
	if c == nil {
		return
	}
	activeControlPlanePublication.mu.Lock()
	if activeControlPlanePublication.owners == nil {
		activeControlPlanePublication.owners = make(map[*ControlPlane]routingEpochExecutionOwnerPublication, 2)
	}
	activeControlPlanePublication.owners[c] = routingEpochExecutionOwnerPublished
	activeControlPlanePublication.plane.Store(c)
	activeControlPlanePublication.mu.Unlock()
}

// RegisterProvisionalRoutingEpochExecutionOwner exposes a ready isolated
// reload candidate for generation-attributed ingress before the active/debug
// publication changes. Callers must unregister it on rollback; publication
// promotes it to a regular owner automatically.
func (c *ControlPlane) RegisterProvisionalRoutingEpochExecutionOwner() error {
	if c == nil || c.core == nil {
		return fmt.Errorf("register provisional routing epoch owner: control plane is unavailable")
	}
	if !c.core.isReload || c.sharedBpfReload {
		return fmt.Errorf("register provisional routing epoch owner: candidate is not an isolated reload")
	}
	if c.ready == nil {
		return fmt.Errorf("register provisional routing epoch owner: candidate is not ready")
	}
	select {
	case <-c.ready:
	default:
		return fmt.Errorf("register provisional routing epoch owner: candidate is not ready")
	}
	if uint16(c.core.datapathGeneration.Load()) == 0 {
		return fmt.Errorf("register provisional routing epoch owner: datapath generation is unknown")
	}
	if !c.acceptsRoutingEpochExecutionLocked() {
		return fmt.Errorf("register provisional routing epoch owner: execution gate is closed")
	}

	activeControlPlanePublication.mu.Lock()
	defer activeControlPlanePublication.mu.Unlock()
	if !c.acceptsRoutingEpochExecutionLocked() {
		return fmt.Errorf("register provisional routing epoch owner: execution gate is closed")
	}
	if activeControlPlanePublication.owners == nil {
		activeControlPlanePublication.owners = make(map[*ControlPlane]routingEpochExecutionOwnerPublication, 2)
	}
	state := activeControlPlanePublication.owners[c]
	if state&routingEpochExecutionOwnerPublished != 0 {
		return nil
	}
	activeControlPlanePublication.owners[c] = state | routingEpochExecutionOwnerProvisional
	return nil
}

// UnregisterProvisionalRoutingEpochExecutionOwner removes only provisional
// ownership. A candidate already promoted by active publication remains
// registered until its execution gate closes.
func (c *ControlPlane) UnregisterProvisionalRoutingEpochExecutionOwner() {
	if c == nil {
		return
	}
	activeControlPlanePublication.mu.Lock()
	state := activeControlPlanePublication.owners[c]
	if state&routingEpochExecutionOwnerPublished != 0 {
		activeControlPlanePublication.owners[c] = state &^ routingEpochExecutionOwnerProvisional
	} else {
		delete(activeControlPlanePublication.owners, c)
	}
	activeControlPlanePublication.mu.Unlock()
}

// unregisterRoutingEpochExecutionOwner removes a published generation from
// fresh-datapath attribution before its execution gate is retired. The active
// debug pointer is updated separately when the control plane closes or another
// generation is published.
func (c *ControlPlane) unregisterRoutingEpochExecutionOwner() {
	if c == nil {
		return
	}
	activeControlPlanePublication.mu.Lock()
	delete(activeControlPlanePublication.owners, c)
	activeControlPlanePublication.mu.Unlock()
}

// PublishActiveDebugState makes this control plane the source for read-only
// process debug snapshots. Runtime supervisors call it only after publishing a
// generation as active.
func (c *ControlPlane) PublishActiveDebugState() {
	c.publishActiveControlPlane()
}

func (c *ControlPlane) unpublishActiveControlPlane() {
	if c == nil {
		return
	}
	activeControlPlanePublication.mu.Lock()
	delete(activeControlPlanePublication.owners, c)
	activeControlPlanePublication.plane.CompareAndSwap(c, nil)
	activeControlPlanePublication.mu.Unlock()
}

func (c *ControlPlane) isPublishedActiveControlPlane() bool {
	if c == nil {
		return false
	}
	active := activeControlPlanePublication.plane.Load()
	return active == nil || active == c
}

func withActiveDNSController(
	fallback *ControlPlane,
	ctx context.Context,
	handle func(context.Context, *DnsController) error,
) error {
	if handle == nil {
		return fmt.Errorf("active DNS controller handler is nil")
	}
	activeControlPlanePublication.mu.RLock()
	defer activeControlPlanePublication.mu.RUnlock()

	plane := activeControlPlanePublication.plane.Load()
	if fallback != nil {
		manager, managerOwned := fallback.controlPlaneSessionManager()
		if plane == nil || manager == nil || managerOwned {
			plane = fallback
		}
	}
	if plane == nil {
		return fmt.Errorf("active control plane is not available")
	}
	controller := plane.ActiveDnsController()
	if controller == nil {
		return fmt.Errorf("dns controller is not available")
	}
	if ctx == nil {
		ctx = plane.ctx
	}
	return handle(plane.dnsRequestContext(ctx, controller), controller)
}
