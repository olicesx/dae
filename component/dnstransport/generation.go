/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dnstransport

import (
	"net/http"
	"sync"
)

// HTTPClientGeneration is one http.Client lifetime with active-reference
// counting and retirement tracking. Owners (per-upstream or per-forwarder
// caches) track generations in their own containers and drive the lifecycle
// through Acquire/Release semantics below.
type HTTPClientGeneration struct {
	Client    *http.Client
	Active    int
	Retired   bool
	closeOnce sync.Once
}

// Close closes the generation's client exactly once.
func (g *HTTPClientGeneration) Close() {
	if g == nil {
		return
	}
	g.closeOnce.Do(func() {
		CloseHTTPClient(g.Client)
	})
}

// ReleaseHTTPClientGeneration applies the drain-and-forget policy shared by
// all HTTP client caches: the active count is decremented under mu, and once
// a retired generation drains, it is closed and forget (called under mu)
// removes it from the owner's tracking set.
func ReleaseHTTPClientGeneration(mu *sync.Mutex, g *HTTPClientGeneration, forget func()) {
	if g == nil {
		return
	}
	var closeNow bool
	mu.Lock()
	if g.Active > 0 {
		g.Active--
	}
	if g.Retired && g.Active == 0 {
		closeNow = true
	}
	mu.Unlock()
	FinishRetiredHTTPClient(mu, g, closeNow, forget)
}

// RetireHTTPClientLocked marks a generation retired after its owner swapped
// in a successor. The caller must hold the owner's mu; the return reports
// whether the generation has already drained and can be closed immediately.
func RetireHTTPClientLocked(g *HTTPClientGeneration) bool {
	if g == nil {
		return false
	}
	g.Retired = true
	return g.Active == 0
}

// FinishRetiredHTTPClient closes a drained retired generation and removes it
// from the owner's tracking set: the close runs outside mu so transport
// teardown never happens under the owner's lock, and the forget is re-checked
// under mu in case an acquire raced the drain window.
func FinishRetiredHTTPClient(mu *sync.Mutex, g *HTTPClientGeneration, closeNow bool, forget func()) {
	if g == nil || !closeNow {
		return
	}
	g.Close()
	mu.Lock()
	if g.Retired && g.Active == 0 {
		forget()
	}
	mu.Unlock()
}
