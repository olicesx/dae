/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
)

const geoUpdateKind = "geodata_update"

func (g *geoDataService) AttachOperations(operations *nativeAPIOperations) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.operations != nil || operations == nil {
		return
	}
	g.operations = operations
	operations.geodata = g
	go g.schedule()
}

func (g *geoDataService) GeoDataUpdateAvailable() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.operations != nil && g.operations.manager != nil && g.ctx.Err() == nil
}

func (g *geoDataService) StartGeoDataUpdate(ctx context.Context, scope, key string) (nativeapi.OperationAccepted, error) {
	return g.startUpdate(ctx, scope, key, false)
}

func (g *geoDataService) startUpdate(ctx context.Context, scope, key string, automatic bool) (nativeapi.OperationAccepted, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	operations := g.operations
	if operations == nil || operations.manager == nil || g.ctx.Err() != nil {
		return nativeapi.OperationAccepted{}, geoUnavailable()
	}
	operations.admissionMu.Lock()
	defer operations.admissionMu.Unlock()
	if operations.stopping {
		return nativeapi.OperationAccepted{}, geoUnavailable()
	}
	if accepted, replayed, err := operations.store.Replay(geoUpdateKind, scope, key); replayed || err != nil {
		return accepted, err
	}
	if g.inFlight != "" {
		return nativeapi.OperationAccepted{}, nativeapi.NewAPIError(http.StatusConflict, "state_conflict", "A geodata update is already queued or running.")
	}
	if automatic && (g.nextCheck.IsZero() || time.Now().Before(g.nextCheck)) {
		return nativeapi.OperationAccepted{}, nil
	}
	accepted, replayed, err := operations.store.Accept(geoUpdateKind, scope, key)
	if err != nil || replayed {
		return accepted, err
	}
	g.inFlight = accepted.OperationID
	operations.store.CommitReplayKey(key)
	go g.runUpdate(accepted.OperationID)
	return accepted, nil
}

func geoUnavailable() *nativeapi.APIError {
	return &nativeapi.APIError{
		Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
		Message: "Geodata updates are temporarily unavailable.", RetryAfterSeconds: 1,
	}
}

type geoUpdateError struct {
	code    string
	message string
}

func (e *geoUpdateError) Error() string { return e.message }

func safeGeoUpdateError(err error) *nativeapi.SafeError {
	if err == nil {
		return nil
	}
	var updateErr *geoUpdateError
	if errors.As(err, &updateErr) {
		return &nativeapi.SafeError{Code: updateErr.code, Message: updateErr.message}
	}
	return &nativeapi.SafeError{Code: "update_failed", Message: "Geodata update could not be completed."}
}

func (g *geoDataService) runUpdate(id string) {
	operations := g.operations
	operations.store.Start(id)
	operations.events.publishOperationUpdated(id, "running")
	ctx, cancel := context.WithTimeout(g.ctx, geoUpdateTimeout)
	candidate, err := g.stageUpdate(ctx, id)
	cancel()
	if err != nil || candidate == nil {
		g.finishUpdate(id, false, err)
		return
	}
	g.mu.Lock()
	g.candidate = candidate
	g.mu.Unlock()
	operations.admissionMu.Lock()
	queued := !operations.stopping && g.ctx.Err() == nil && operations.manager.queueReloadRequest(nil, reloadRequest{
		requestedAt: time.Now(), requestedAtMono: monotonicNowNano(), apiOperationID: id,
	})
	operations.admissionMu.Unlock()
	if !queued {
		g.finishUpdate(id, false, &geoUpdateError{"state_conflict", "A runtime transition prevented geodata activation."})
	}
}

func (g *geoDataService) finishReload(id string, success bool) {
	if !success {
		g.finishUpdate(id, false, &geoUpdateError{"activation_failed", "The geodata could not be activated. The previous assets remain in use."})
		return
	}
	g.finishUpdate(id, true, nil)
}

func (g *geoDataService) finishUpdate(id string, reloaded bool, err error) {
	g.mu.Lock()
	if g.inFlight != id {
		g.mu.Unlock()
		return
	}
	candidate := g.candidate
	if reloaded && (candidate == nil || !candidate.committed) {
		err = &geoUpdateError{"activation_failed", "The reload did not publish the geodata assets."}
	}
	if candidate != nil && !candidate.committed {
		_ = os.RemoveAll(candidate.dir)
	}
	g.lastChecked = time.Now()
	g.lastError = safeGeoUpdateError(err)
	if g.lastError != nil {
		g.failures++
	} else {
		g.failures = 0
		if reloaded {
			g.lastUpdated = g.lastChecked
		}
	}
	g.rescheduleLocked(g.lastChecked)
	operations := g.operations
	status := "succeeded"
	if g.lastError != nil {
		operations.store.Fail(id, g.lastError)
		status = "failed"
	} else {
		operations.store.Succeed(id, g.snapshotLocked())
	}
	g.candidate = nil
	g.inFlight = ""
	g.mu.Unlock()
	if candidate != nil && candidate.durable && candidate.oldDir != "" && candidate.oldDir != candidate.dir {
		_ = os.RemoveAll(candidate.oldDir)
	}
	operations.events.publishOperationUpdated(id, status)
}

func (g *geoDataService) schedule() {
	for {
		g.mu.Lock()
		due, busy := g.nextCheck, g.inFlight != ""
		g.mu.Unlock()
		if busy || due.IsZero() {
			select {
			case <-g.ctx.Done():
				return
			case <-g.wake:
				continue
			}
		}
		timer := time.NewTimer(time.Until(due))
		select {
		case <-g.ctx.Done():
			timer.Stop()
			return
		case <-g.wake:
			timer.Stop()
		case <-timer.C:
			if _, err := g.startUpdate(g.ctx, "automatic geodata update", "", true); err != nil && g.ctx.Err() == nil {
				// A competing manual admission will wake us when it finishes.
				// During shutdown there may be no further schedule notification.
				retry := time.NewTimer(time.Minute)
				select {
				case <-g.ctx.Done():
				case <-g.wake:
				case <-retry.C:
				}
				retry.Stop()
			}
		}
	}
}
