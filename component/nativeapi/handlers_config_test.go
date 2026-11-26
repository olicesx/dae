/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeConfigProvider struct {
	caps         ConfigCapabilities
	doc          EffectiveConfig
	source       ConfigSourceContent
	complete     bool
	replaceErr   error
	validateErr  error
	replaceReqs  []ReplaceConfigSourceRequest
	validateReqs []ConfigValidationRequest
}

func (p *fakeConfigProvider) ConfigCapabilities() ConfigCapabilities { return p.caps }

func (p *fakeConfigProvider) GetConfig(ctx context.Context) (EffectiveConfig, error) {
	return p.doc, nil
}

func (p *fakeConfigProvider) GetConfigSource(ctx context.Context, sourceID string) (ConfigSourceContent, bool, error) {
	return p.source, p.complete, nil
}

func (p *fakeConfigProvider) ReplaceConfigSource(ctx context.Context, req ReplaceConfigSourceRequest) (OperationAccepted, error) {
	p.replaceReqs = append(p.replaceReqs, req)
	if p.replaceErr != nil {
		return OperationAccepted{}, p.replaceErr
	}
	return OperationAccepted{
		OperationID: "op-config-1",
		Kind:        OperationKindReload,
		Status:      "queued",
		Href:        "/api/v1/operations/op-config-1",
	}, nil
}

func (p *fakeConfigProvider) ValidateConfig(ctx context.Context, req ConfigValidationRequest) (ConfigValidationResult, error) {
	p.validateReqs = append(p.validateReqs, req)
	if p.validateErr != nil {
		return ConfigValidationResult{}, p.validateErr
	}
	return ConfigValidationResult{Valid: true}, nil
}

// newConfigServer wires a fake provider behind the real router.
func newConfigServer(t *testing.T, provider ConfigProvider) *Server {
	t.Helper()
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{})
	if provider != nil {
		server.SetConfigProvider(provider)
	}
	return server
}

func doConfigRequest(server *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:9527"
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	return recorder
}

func writableCaps() ConfigCapabilities {
	return ConfigCapabilities{Writable: true, MaxBytes: 16, MaxSources: 2, Layout: "managed"}
}

func TestConfigEndpointsWithoutProviderAnswer404(t *testing.T) {
	server := newConfigServer(t, nil)
	for _, route := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/config", ""},
		{http.MethodGet, "/api/v1/config/sources/src_abc", ""},
		{http.MethodPut, "/api/v1/config/sources/src_abc", `{"content":""}`},
		{http.MethodPost, "/api/v1/config/validate", `{"mode":"full","sources":[{"content":""}]}`},
	} {
		recorder := doConfigRequest(server, route.method, route.path, route.body, nil)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404", route.method, route.path, recorder.Code)
		}
		if code := errorCode(t, recorder); code != codeCapabilityNotSupported {
			t.Fatalf("%s %s code = %s", route.method, route.path, code)
		}
	}
}

func TestReplaceConfigSourceRequiresIfMatch(t *testing.T) {
	provider := &fakeConfigProvider{caps: writableCaps()}
	server := newConfigServer(t, provider)

	recorder := doConfigRequest(server, http.MethodPut, "/api/v1/config/sources/src_abc", `{"content":""}`, nil)
	if recorder.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428", recorder.Code)
	}
	if code := errorCode(t, recorder); code != codePreconditionRequired {
		t.Fatalf("code = %s, want precondition_required", code)
	}
	if len(provider.replaceReqs) != 0 {
		t.Fatal("a request without If-Match must not reach the provider")
	}
}

func TestReplaceConfigSourceRejectsOversizedContent(t *testing.T) {
	provider := &fakeConfigProvider{caps: writableCaps()}
	server := newConfigServer(t, provider)

	body := `{"content":"` + strings.Repeat("a", 17) + `"}`
	recorder := doConfigRequest(server, http.MethodPut, "/api/v1/config/sources/src_abc", body,
		map[string]string{"If-Match": `"abc"`})
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", recorder.Code)
	}
	if code := errorCode(t, recorder); code != codeRequestTooLarge {
		t.Fatalf("code = %s, want request_too_large", code)
	}
	if len(provider.replaceReqs) != 0 {
		t.Fatal("an oversized body must not reach the provider")
	}
}

func TestReplaceConfigSourceQueuesReloadAndForwardsKey(t *testing.T) {
	provider := &fakeConfigProvider{caps: writableCaps()}
	server := newConfigServer(t, provider)

	recorder := doConfigRequest(server, http.MethodPut, "/api/v1/config/sources/src_abc", `{"content":"global {}"}`,
		map[string]string{"If-Match": `"abc123"`, "Idempotency-Key": "key-1"})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/api/v1/operations/op-config-1" {
		t.Fatalf("Location = %q", got)
	}
	if got := recorder.Header().Get("Retry-After"); got != operationPollRetryAfter {
		t.Fatalf("Retry-After = %q", got)
	}
	if len(provider.replaceReqs) != 1 {
		t.Fatalf("provider calls = %d, want 1", len(provider.replaceReqs))
	}
	got := provider.replaceReqs[0]
	if got.IfMatch != "abc123" {
		t.Fatalf("If-Match not unquoted: %q", got.IfMatch)
	}
	if got.IdempotencyKey != "key-1" || got.Content != "global {}" || got.SourceID != "src_abc" {
		t.Fatalf("forwarded request = %+v", got)
	}
}

func TestReplaceConfigSourceDisabledAnswers403(t *testing.T) {
	caps := writableCaps()
	caps.Writable = false
	provider := &fakeConfigProvider{caps: caps}
	server := newConfigServer(t, provider)

	recorder := doConfigRequest(server, http.MethodPut, "/api/v1/config/sources/src_abc", `{"content":""}`,
		map[string]string{"If-Match": `"abc"`})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if code := errorCode(t, recorder); code != codePermissionDenied {
		t.Fatalf("code = %s, want permission_denied", code)
	}
}

func TestGetConfigSourceSendsETagOnlyWhenComplete(t *testing.T) {
	provider := &fakeConfigProvider{
		caps:     writableCaps(),
		source:   ConfigSourceContent{ID: "src_abc", ContentSHA256: "d1f6"},
		complete: true,
	}
	server := newConfigServer(t, provider)

	recorder := doConfigRequest(server, http.MethodGet, "/api/v1/config/sources/src_abc", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("ETag"); got != `"d1f6"` {
		t.Fatalf("ETag = %q", got)
	}

	provider.complete = false
	recorder = doConfigRequest(server, http.MethodGet, "/api/v1/config/sources/src_abc", "", nil)
	if got := recorder.Header().Get("ETag"); got != "" {
		t.Fatalf("masked content must not carry an ETag, got %q", got)
	}
}

func TestConfigValidateRequiresMode(t *testing.T) {
	provider := &fakeConfigProvider{caps: writableCaps()}
	server := newConfigServer(t, provider)

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/config/validate", `{"sources":[{"content":""}]}`, nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if code := errorCode(t, recorder); code != codeInvalidRequest {
		t.Fatalf("code = %s, want invalid_request", code)
	}
}

func TestConfigValidateRejectsUnknownMode(t *testing.T) {
	provider := &fakeConfigProvider{caps: writableCaps()}
	server := newConfigServer(t, provider)

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/config/validate", `{"mode":"deep","sources":[{"content":""}]}`, nil)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
	if code := errorCode(t, recorder); code != codeUnsupportedValue {
		t.Fatalf("code = %s, want unsupported_value", code)
	}
}

func TestConfigValidateBoundsTheTotalBytes(t *testing.T) {
	// Each source fits within max_bytes on its own; only their sum exceeds it.
	provider := &fakeConfigProvider{caps: writableCaps()}
	server := newConfigServer(t, provider)

	chunk := strings.Repeat("a", 10)
	body := `{"mode":"full","sources":[{"content":"` + chunk + `"},{"content":"` + chunk + `"}]}`
	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/config/validate", body, nil)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", recorder.Code)
	}
	if code := errorCode(t, recorder); code != codeRequestTooLarge {
		t.Fatalf("code = %s, want request_too_large", code)
	}
	if len(provider.validateReqs) != 0 {
		t.Fatal("an oversized candidate must not reach the provider")
	}
}

func TestConfigValidateRejectsTooManySources(t *testing.T) {
	provider := &fakeConfigProvider{caps: writableCaps()}
	server := newConfigServer(t, provider)

	body := `{"mode":"full","sources":[{"content":""},{"content":""},{"content":""}]}`
	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/config/validate", body, nil)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", recorder.Code)
	}
}

func TestCapabilitiesAdvertiseConfigLayout(t *testing.T) {
	caps := writableCaps()
	caps.LayoutReason = ""
	caps.HiddenSources = []string{"api.dae"}
	provider := &fakeConfigProvider{caps: caps}
	server := newConfigServer(t, provider)

	recorder := doConfigRequest(server, http.MethodGet, "/api/v1/capabilities", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	body := decodeJSON(t, recorder)
	resources, _ := body["resources"].(map[string]any)
	config, _ := resources["config"].(map[string]any)
	if config == nil {
		t.Fatalf("config capabilities missing: %v", resources)
	}
	if config["writable"] != true || config["create"] != false {
		t.Fatalf("config caps = %v", config)
	}
	if config["max_bytes"] != float64(caps.MaxBytes) || config["max_sources"] != float64(caps.MaxSources) {
		t.Fatalf("limits = %v / %v", config["max_bytes"], config["max_sources"])
	}
	extension, _ := config[EngineExtension].(map[string]any)
	if extension == nil {
		t.Fatalf("%s block missing: %v", EngineExtension, config)
	}
	layout, _ := extension["layout"].(map[string]any)
	if layout["kind"] != "managed" {
		t.Fatalf("layout = %v", layout)
	}
	hidden, _ := extension["hidden_sources"].([]any)
	if len(hidden) != 1 || hidden[0] != "api.dae" {
		t.Fatalf("hidden_sources = %v", extension["hidden_sources"])
	}
	validate, _ := resources["config_validate"].(map[string]any)
	if validate["available"] != true {
		t.Fatalf("config_validate = %v", validate)
	}
}

// TestReplaceConfigSourcePreconditionPrecedesMediaType pins the contract's
// request-boundary order: 428 is decided before 415, so a client that forgot the
// precondition is told about that rather than about its content type.
func TestReplaceConfigSourcePreconditionPrecedesMediaType(t *testing.T) {
	provider := &fakeConfigProvider{caps: writableCaps()}
	server := newConfigServer(t, provider)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/sources/src_abc", strings.NewReader("not json"))
	req.Host = "127.0.0.1:9527"
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d body=%s, want 428 before the media type check", recorder.Code, recorder.Body.String())
	}
	if len(provider.replaceReqs) != 0 {
		t.Fatal("a request without If-Match must not reach the provider")
	}
}

type fakeConfigCreator struct {
	fakeConfigProvider
	requests []CreateConfigSourceRequest
	err      error
}

func (p *fakeConfigCreator) CreateConfigSource(_ context.Context, req CreateConfigSourceRequest) (OperationAccepted, error) {
	p.requests = append(p.requests, req)
	return OperationAccepted{OperationID: "op-create", Kind: OperationKindReload, Status: "queued", Href: "/api/v1/operations/op-create"}, p.err
}

func TestConfigCreateAcceptsDoonaRequest(t *testing.T) {
	provider := &fakeConfigCreator{fakeConfigProvider: fakeConfigProvider{caps: writableCaps()}}
	provider.caps.Create = true
	server := newConfigServer(t, provider)
	response := doConfigRequest(server, http.MethodPost, configSourcesPath, `{"path":"config.d/extra.dae","content":""}`, map[string]string{"Idempotency-Key": "doona-key"})
	var accepted OperationAccepted
	if response.Code != http.StatusAccepted || json.Unmarshal(response.Body.Bytes(), &accepted) != nil ||
		accepted.Kind != OperationKindReload || accepted.Href != response.Header().Get("Location") ||
		response.Header().Get("Retry-After") != operationPollRetryAfter {
		t.Fatalf("create response = %d, %v, %s", response.Code, response.Header(), response.Body)
	}
	if len(provider.requests) != 1 || provider.requests[0] != (CreateConfigSourceRequest{Path: "config.d/extra.dae", IdempotencyKey: "doona-key"}) {
		t.Fatalf("provider requests = %#v", provider.requests)
	}
}

func TestConfigCreateRequestErrors(t *testing.T) {
	const valid = `{"path":"config.d/x.dae","content":""}`
	for _, tc := range []struct {
		name, body, mediaType, code string
		status                      int
		unavailable, readonly       bool
	}{
		{name: "unavailable", body: valid, code: codeCapabilityNotSupported, status: 404, unavailable: true},
		{name: "read-only", body: valid, code: codePermissionDenied, status: 403, readonly: true},
		{name: "content type", body: valid, mediaType: "text/plain", code: codeUnsupportedMediaType, status: 415},
		{name: "unknown field", body: `{"path":"x.dae","content":"","extra":true}`, code: codeInvalidRequest, status: 400},
		{name: "missing content", body: `{"path":"x.dae"}`, code: codeInvalidRequest, status: 400},
		{name: "null content", body: `{"path":"x.dae","content":null}`, code: codeInvalidRequest, status: 400},
		{name: "absolute path", body: `{"path":"/x.dae","content":""}`, code: codeInvalidRequest, status: 400},
		{name: "traversal", body: `{"path":"config.d/../x.dae","content":""}`, code: codeInvalidRequest, status: 400},
		{name: "empty path segment", body: `{"path":"config.d//x.dae","content":""}`, code: codeInvalidRequest, status: 400},
		{name: "control character", body: `{"path":"config.d/x\u0085.dae","content":""}`, code: codeInvalidRequest, status: 400},
		{name: "invalid UTF-8", body: "{\"path\":\"x.dae\",\"content\":\"\xff\"}", code: codeInvalidRequest, status: 400},
		{name: "content byte limit", body: `{"path":"x.dae","content":"你好你好你好"}`, code: codeRequestTooLarge, status: 413},
		{name: "body byte limit", body: valid + strings.Repeat(" ", 128), code: codeRequestTooLarge, status: 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps := writableCaps()
			caps.Create = !tc.unavailable
			caps.Writable = !tc.readonly
			provider := &fakeConfigCreator{fakeConfigProvider: fakeConfigProvider{caps: caps}}
			server := newConfigServer(t, provider)
			server.cfg.MaxJSONBodyBytes = 128
			headers := map[string]string{}
			if tc.mediaType != "" {
				headers["Content-Type"] = tc.mediaType
			}
			response := doConfigRequest(server, http.MethodPost, configSourcesPath, tc.body, headers)
			if response.Code != tc.status || errorCode(t, response) != tc.code || len(provider.requests) != 0 {
				t.Fatalf("create response = %d %s, requests = %#v", response.Code, response.Body, provider.requests)
			}
		})
	}
}

func TestConfigCreatePreservesProviderDiagnostics(t *testing.T) {
	caps := writableCaps()
	caps.Create = true
	provider := &fakeConfigCreator{
		fakeConfigProvider: fakeConfigProvider{caps: caps},
		err: &APIError{Status: 422, Code: codeUnsupportedValue, Message: "not included", Details: map[string]any{
			"diagnostics": []ConfigDiagnostic{{Level: "error", SourceID: "src_main", Code: "source-not-included", Message: "No include pattern loads this path."}},
		}},
	}
	response := doConfigRequest(newConfigServer(t, provider), http.MethodPost, configSourcesPath, `{"path":"x.dae","content":""}`, nil)
	var body struct {
		Error struct {
			Details struct{ Diagnostics []ConfigDiagnostic }
		}
	}
	if response.Code != 422 || errorCode(t, response) != codeUnsupportedValue || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
		len(body.Error.Details.Diagnostics) != 1 || body.Error.Details.Diagnostics[0].SourceID != "src_main" {
		t.Fatalf("response = %d %s", response.Code, response.Body)
	}
}
