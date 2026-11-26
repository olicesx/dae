/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org
 */

package nativeapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// managingProviders is a provider provider whose providers can be written.
type managingProviders struct {
	caps      ProviderCapabilities
	created   ProviderCreateRequest
	deleted   ProviderDeleteRequest
	createOut ProviderCreateOutcome
	deleteOut ProviderDeleteOutcome
	createErr error
	deleteErr error
}

func (p *managingProviders) ListProviders(context.Context, int, string) (ProviderList, error) {
	return ProviderList{Providers: []Provider{}}, nil
}

func (p *managingProviders) GetProvider(_ context.Context, id string) (*Provider, error) {
	return &Provider{ID: id, Name: "a", Kind: "subscription", Status: "ok"}, nil
}

func (p *managingProviders) ProviderCapabilities() ProviderCapabilities { return p.caps }

func (p *managingProviders) RefreshProvider(context.Context, ProviderRefreshRequest) (OperationAccepted, error) {
	return OperationAccepted{}, errors.New("not used")
}

func (p *managingProviders) CreateProvider(_ context.Context, req ProviderCreateRequest) (ProviderCreateOutcome, error) {
	p.created = req
	if p.createErr != nil {
		return ProviderCreateOutcome{}, p.createErr
	}
	if p.createOut.Provider != nil {
		return p.createOut, nil
	}
	return ProviderCreateOutcome{Accepted: OperationAccepted{
		OperationID: "op-provider-create", Kind: OperationKindProviderCreate, Status: "queued",
		Href: "/api/v1/operations/op-provider-create",
	}}, nil
}

func (p *managingProviders) DeleteProvider(_ context.Context, req ProviderDeleteRequest) (ProviderDeleteOutcome, error) {
	p.deleted = req
	if p.deleteErr != nil {
		return ProviderDeleteOutcome{}, p.deleteErr
	}
	if p.deleteOut.Deleted == 0 {
		return ProviderDeleteOutcome{}, nil
	}
	return ProviderDeleteOutcome{Deleted: 1, Accepted: OperationAccepted{
		OperationID: "op-provider-delete", Kind: OperationKindProviderDelete, Status: "queued",
		Href: "/api/v1/operations/op-provider-delete",
	}}, nil
}

func newProviderManagerServer(t *testing.T, providers ProviderProvider) *Server {
	t.Helper()
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{})
	if providers != nil {
		server.SetProviderProvider(providers)
	}
	return server
}

var manageableProviderCaps = ProviderCapabilities{CanRefresh: true, CanManage: true}

func TestCreateProviderQueuesOperation(t *testing.T) {
	providers := &managingProviders{caps: manageableProviderCaps}
	server := newProviderManagerServer(t, providers)

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/providers",
		`{"name":"provider-b","kind":"subscription","url":"https://subscriptions.example.com/sub?token=secret"}`,
		map[string]string{"Idempotency-Key": "key-1"})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/api/v1/operations/op-provider-create" {
		t.Fatalf("Location = %q", got)
	}
	if got := recorder.Header().Get("Retry-After"); got != operationPollRetryAfter {
		t.Fatalf("Retry-After = %q", got)
	}
	created := providers.created
	if created.Name != "provider-b" || created.URL != "https://subscriptions.example.com/sub?token=secret" ||
		created.UpdateInterval != nil || created.UserAgent != nil || created.Cache != nil || created.IdempotencyKey != "key-1" {
		t.Fatalf("forwarded request = %+v", created)
	}
}

func TestCreateProviderAnswersCreatedWhenActive(t *testing.T) {
	active := Provider{ID: "p_b", Name: "provider-b", Kind: "subscription", Status: "stale"}
	providers := &managingProviders{caps: manageableProviderCaps, createOut: ProviderCreateOutcome{Provider: &active}}
	server := newProviderManagerServer(t, providers)

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/providers",
		`{"name":"provider-b","kind":"subscription","url":"https://subscriptions.example.com/sub"}`, nil)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/api/v1/providers/p_b" {
		t.Fatalf("Location = %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := decodeJSON(t, recorder)["id"]; got != "p_b" {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestProviderWritesWithoutManagementAnswer404(t *testing.T) {
	server := newProviderManagerServer(t, &managingProviders{caps: ProviderCapabilities{CanRefresh: true}})

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/providers",
		`{"name":"provider-b","kind":"subscription","url":"https://subscriptions.example.com/sub"}`, nil)
	if recorder.Code != http.StatusNotFound || errorCode(t, recorder) != codeCapabilityNotSupported {
		t.Fatalf("create: status = %d code = %s, want 404 capability_not_supported", recorder.Code, recorder.Body.String())
	}
	recorder = doConfigRequest(server, http.MethodDelete, "/api/v1/providers/p_a", "", nil)
	if recorder.Code != http.StatusNotFound || errorCode(t, recorder) != codeCapabilityNotSupported {
		t.Fatalf("delete: status = %d code = %s, want 404 capability_not_supported", recorder.Code, recorder.Body.String())
	}
}

func TestCreateProviderRejectsInvalidBodies(t *testing.T) {
	refreshOnly := &managingProviders{caps: manageableProviderCaps}
	server := newProviderManagerServer(t, refreshOnly)
	tests := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{"missing url", `{"name":"a","kind":"subscription"}`, http.StatusBadRequest, codeInvalidRequest},
		{"unknown field", `{"name":"a","kind":"subscription","url":"https://example.com/s","extra":1}`, http.StatusBadRequest, codeInvalidRequest},
		{"wrong kind", `{"name":"a","kind":"file","url":"https://example.com/s"}`, http.StatusUnprocessableEntity, codeUnsupportedValue},
		{"not http", `{"name":"a","kind":"subscription","url":"ftp://example.com/s"}`, http.StatusUnprocessableEntity, codeUnsupportedValue},
		{"no host", `{"name":"a","kind":"subscription","url":"https://"}`, http.StatusUnprocessableEntity, codeUnsupportedValue},
		{"empty name", `{"name":"","kind":"subscription","url":"https://example.com/s"}`, http.StatusBadRequest, codeInvalidRequest},
		{"long name", `{"name":"` + strings.Repeat("n", 65) + `","kind":"subscription","url":"https://example.com/s"}`, http.StatusUnprocessableEntity, codeUnsupportedValue},
		{"control character", `{"name":"a\nb","kind":"subscription","url":"https://example.com/s"}`, http.StatusUnprocessableEntity, codeUnsupportedValue},
		{"unlisted interval", `{"name":"a","kind":"subscription","url":"https://example.com/s","update_interval":3600}`, http.StatusUnprocessableEntity, codeUnsupportedValue},
		{"unlisted cache", `{"name":"a","kind":"subscription","url":"https://example.com/s","cache":false}`, http.StatusUnprocessableEntity, codeUnsupportedValue},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := doConfigRequest(server, http.MethodPost, "/api/v1/providers", test.body, nil)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.status, recorder.Body.String())
			}
			if code := errorCode(t, recorder); code != test.code {
				t.Fatalf("code = %s, want %s", code, test.code)
			}
		})
	}
	if refreshOnly.created.Name != "" {
		t.Fatalf("a rejected body reached the provider: %+v", refreshOnly.created)
	}
}

func TestCreateProviderAcceptsListedOptionsOnly(t *testing.T) {
	providers := &managingProviders{caps: ProviderCapabilities{CanManage: true, CreateOptions: map[string]any{
		"update_interval": 86400, "user_agent": "dae/0", "cache": true,
	}}}
	server := newProviderManagerServer(t, providers)

	accepted := doConfigRequest(server, http.MethodPost, "/api/v1/providers",
		`{"name":"a","kind":"subscription","url":"https://example.com/s","update_interval":3600,"cache":false}`, nil)
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", accepted.Code, accepted.Body.String())
	}
	if providers.created.UpdateInterval == nil || *providers.created.UpdateInterval != 3600 ||
		providers.created.Cache == nil || *providers.created.Cache {
		t.Fatalf("forwarded options = %+v", providers.created)
	}
	for body, want := range map[string]string{
		`{"name":"a","kind":"subscription","url":"https://example.com/s","update_interval":31536001}`:    "update_interval must be",
		`{"name":"a","kind":"subscription","url":"https://example.com/s","user_agent":"bad\u0001agent"}`: "user_agent must be",
	} {
		recorder := doConfigRequest(server, http.MethodPost, "/api/v1/providers", body, nil)
		message, _ := decodeJSON(t, recorder)["error"].(map[string]any)["message"].(string)
		if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(message, want) {
			t.Fatalf("body %s: status = %d message = %q, want 422 containing %q", body, recorder.Code, message, want)
		}
	}
}

func TestCreateProviderRequiresJSON(t *testing.T) {
	server := newProviderManagerServer(t, &managingProviders{caps: manageableProviderCaps})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/providers",
		strings.NewReader(`{"name":"a","kind":"subscription","url":"https://example.com/s"}`))
	req.Host = "127.0.0.1:9527"
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnsupportedMediaType || errorCode(t, recorder) != codeUnsupportedMediaType {
		t.Fatalf("status = %d code = %s, want 415 unsupported_media_type", recorder.Code, recorder.Body.String())
	}
}

func TestProviderCollectionRefusesOtherWrites(t *testing.T) {
	server := newProviderManagerServer(t, &managingProviders{caps: manageableProviderCaps})

	recorder := doConfigRequest(server, http.MethodPut, "/api/v1/providers", "{}", nil)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT collection: status = %d, want 405", recorder.Code)
	}
	recorder = doConfigRequest(server, http.MethodPut, "/api/v1/providers/p_a", "{}", nil)
	if recorder.Code != http.StatusMethodNotAllowed || !strings.Contains(recorder.Header().Get("Allow"), "DELETE") {
		t.Fatalf("PUT item: status = %d Allow = %q, want 405 with DELETE", recorder.Code, recorder.Header().Get("Allow"))
	}
}

func TestDeleteProviderIsIdempotentAndQueues(t *testing.T) {
	providers := &managingProviders{caps: manageableProviderCaps}
	server := newProviderManagerServer(t, providers)

	recorder := doConfigRequest(server, http.MethodDelete, "/api/v1/providers/p_unknown", "", nil)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"deleted":0`) {
		t.Fatalf("unknown id: status = %d body = %s, want 200 deleted 0", recorder.Code, recorder.Body.String())
	}
	if providers.deleted.ProviderID != "p_unknown" {
		t.Fatalf("forwarded delete = %+v", providers.deleted)
	}

	providers.deleteOut.Deleted = 1
	recorder = doConfigRequest(server, http.MethodDelete, "/api/v1/providers/p_a", "", map[string]string{"Idempotency-Key": "k"})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/api/v1/operations/op-provider-delete" {
		t.Fatalf("Location = %q", got)
	}
	if got := decodeJSON(t, recorder)["kind"]; got != "provider_delete" {
		t.Fatalf("kind = %v", got)
	}
	if providers.deleted.IdempotencyKey != "k" {
		t.Fatalf("idempotency key = %q", providers.deleted.IdempotencyKey)
	}
}

func TestProviderCapabilityAdvertisesManagement(t *testing.T) {
	providers := &managingProviders{caps: ProviderCapabilities{CanRefresh: true, CanManage: true, CreateOptions: map[string]any{
		"update_interval": 86400, "user_agent": "dae/0", "cache": true,
	}}}
	server := newProviderManagerServer(t, providers)

	response := doConfigRequest(server, http.MethodGet, "/api/v1/capabilities", "", nil)
	reported := decodeJSON(t, response)["resources"].(map[string]any)["providers"].(map[string]any)
	if reported["can_manage"] != true || reported["can_refresh"] != true {
		t.Fatalf("providers capability = %#v", reported)
	}
	options, ok := reported["create_options"].(map[string]any)
	if !ok || options["update_interval"] != float64(86400) || options["cache"] != true {
		t.Fatalf("create_options = %#v", reported["create_options"])
	}
	if _, listed := reported["create_unfetched"]; listed {
		t.Fatalf("create_unfetched must be absent while false: %#v", reported)
	}

	providers.caps.CreateUnfetched = true
	response = doConfigRequest(server, http.MethodGet, "/api/v1/capabilities", "", nil)
	reported = decodeJSON(t, response)["resources"].(map[string]any)["providers"].(map[string]any)
	if reported["create_unfetched"] != true {
		t.Fatalf("create_unfetched = %#v", reported["create_unfetched"])
	}

	refreshOnly := newProviderManagerServer(t, &refreshingProviders{canRefresh: true})
	response = doConfigRequest(refreshOnly, http.MethodGet, "/api/v1/capabilities", "", nil)
	reported = decodeJSON(t, response)["resources"].(map[string]any)["providers"].(map[string]any)
	if reported["can_manage"] != false {
		t.Fatalf("read-only providers capability = %#v", reported)
	}
	if _, listed := reported["create_options"]; listed {
		t.Fatalf("create_options must be absent when none is supported: %#v", reported)
	}
}
