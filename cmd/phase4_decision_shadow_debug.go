/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/daeuniverse/dae/control"
)

const phase4DecisionShadowDebugPath = "/debug/dae/phase4-decision-shadow"

var registerDaeDebugHandlersOnce sync.Once

type phase4DecisionShadowSnapshotFunc func() (control.Phase4DecisionShadowSnapshot, bool)

type phase4DecisionShadowDebugResponse struct {
	Enabled         bool   `json:"enabled"`
	Reason          string `json:"reason,omitempty"`
	Sampled         uint64 `json:"sampled"`
	Matched         uint64 `json:"matched"`
	Deferred        uint64 `json:"deferred"`
	Diverged        uint64 `json:"diverged"`
	Errors          uint64 `json:"errors"`
	CutoverEligible bool   `json:"cutover_eligible"`
	EvidenceCount   int    `json:"evidence_count"`
}

func registerDaeDebugHandlers() {
	registerDaeDebugHandlersOnce.Do(func() {
		http.Handle(phase4DecisionShadowDebugPath, newPhase4DecisionShadowDebugHandler(control.SnapshotActivePhase4DecisionShadow))
	})
}

func newPhase4DecisionShadowDebugHandler(snapshot phase4DecisionShadowSnapshotFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(phase4DecisionShadowDebugResponse{
				Reason: "method not allowed",
			})
			return
		}

		state, enabled := snapshot()
		response := phase4DecisionShadowDebugResponse{Enabled: enabled}
		if !enabled {
			response.Reason = "no active decision shadow"
		} else {
			response.Sampled = state.Sampled
			response.Matched = state.Matched
			response.Deferred = state.Deferred
			response.Diverged = state.Diverged
			response.Errors = state.Errors
			// Snapshot counters are updated independently. Require a complete,
			// internally consistent observation before exposing eligibility.
			response.CutoverEligible = state.CutoverEligible &&
				state.Sampled == state.Matched &&
				state.Diverged == 0 &&
				state.Errors == 0
			response.EvidenceCount = len(state.Evidence)
		}
		_ = json.NewEncoder(w).Encode(response)
	})
}
