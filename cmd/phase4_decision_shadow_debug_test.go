/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daeuniverse/dae/control"
)

func TestPhase4DecisionShadowDebugHandlerDisabled(t *testing.T) {
	handler := newPhase4DecisionShadowDebugHandler(func() (control.Phase4DecisionShadowSnapshot, bool) {
		return control.Phase4DecisionShadowSnapshot{}, false
	})

	response := requestPhase4DecisionShadowDebug(t, handler, http.MethodGet)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := decodePhase4DecisionShadowDebugResponse(t, response)
	if body.Enabled || body.Reason == "" {
		t.Fatalf("response = %+v, want a clear disabled response", body)
	}
}

func TestPhase4DecisionShadowDebugHandlerEnabledOmitsEvidence(t *testing.T) {
	handler := newPhase4DecisionShadowDebugHandler(func() (control.Phase4DecisionShadowSnapshot, bool) {
		return control.Phase4DecisionShadowSnapshot{
			Sampled:         11,
			Matched:         10,
			Deferred:        2,
			Diverged:        1,
			Errors:          0,
			CutoverEligible: false,
			Evidence:        make([]control.Phase4DecisionDivergenceEvidence, 1),
		}, true
	})

	response := requestPhase4DecisionShadowDebug(t, handler, http.MethodGet)
	body := decodePhase4DecisionShadowDebugResponse(t, response)
	if !body.Enabled || body.Sampled != 11 || body.Matched != 10 || body.Deferred != 2 || body.Diverged != 1 || body.EvidenceCount != 1 {
		t.Fatalf("response = %+v, want enabled snapshot counters", body)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	if _, exposed := fields["evidence"]; exposed {
		t.Fatal("debug response exposes divergence evidence")
	}
}

func TestPhase4DecisionShadowDebugHandlerRejectsIncompleteEligibleSnapshot(t *testing.T) {
	handler := newPhase4DecisionShadowDebugHandler(func() (control.Phase4DecisionShadowSnapshot, bool) {
		return control.Phase4DecisionShadowSnapshot{
			Sampled:         11,
			Matched:         10,
			CutoverEligible: true,
		}, true
	})

	response := requestPhase4DecisionShadowDebug(t, handler, http.MethodGet)
	body := decodePhase4DecisionShadowDebugResponse(t, response)
	if body.CutoverEligible {
		t.Fatalf("response = %+v, want incomplete snapshot to be ineligible", body)
	}
}

func TestPhase4DecisionShadowDebugHandlerAcceptsConsistentEligibleSnapshot(t *testing.T) {
	handler := newPhase4DecisionShadowDebugHandler(func() (control.Phase4DecisionShadowSnapshot, bool) {
		return control.Phase4DecisionShadowSnapshot{
			Sampled:         11,
			Matched:         11,
			CutoverEligible: true,
		}, true
	})

	response := requestPhase4DecisionShadowDebug(t, handler, http.MethodGet)
	body := decodePhase4DecisionShadowDebugResponse(t, response)
	if !body.CutoverEligible {
		t.Fatalf("response = %+v, want consistent snapshot to be eligible", body)
	}
}

func TestRegisterDaeDebugHandlersIsIdempotent(t *testing.T) {
	registerDaeDebugHandlers()
	registerDaeDebugHandlers()

	request := httptest.NewRequest(http.MethodGet, phase4DecisionShadowDebugPath, nil)
	response := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestPhase4DecisionShadowDebugHandlerRejectsMutationMethods(t *testing.T) {
	handler := newPhase4DecisionShadowDebugHandler(func() (control.Phase4DecisionShadowSnapshot, bool) {
		t.Fatal("snapshot called for rejected mutation method")
		return control.Phase4DecisionShadowSnapshot{}, false
	})

	response := requestPhase4DecisionShadowDebug(t, handler, http.MethodPost)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	if allow := response.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow = %q, want %q", allow, http.MethodGet)
	}
}

func requestPhase4DecisionShadowDebug(t *testing.T, handler http.Handler, method string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, phase4DecisionShadowDebugPath, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodePhase4DecisionShadowDebugResponse(t *testing.T, response *httptest.ResponseRecorder) phase4DecisionShadowDebugResponse {
	t.Helper()
	var body phase4DecisionShadowDebugResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}
