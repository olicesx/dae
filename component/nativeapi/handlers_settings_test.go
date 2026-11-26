/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type fakeRuntimeSettingsProvider struct {
	settings   RuntimeSettings
	patch      RuntimeSettingsPatch
	patchCalls int
	patchErr   error
}

func (p *fakeRuntimeSettingsProvider) RuntimeSettings(context.Context) (RuntimeSettings, error) {
	return p.settings, nil
}

func (p *fakeRuntimeSettingsProvider) PatchRuntimeSettings(_ context.Context, patch RuntimeSettingsPatch) (RuntimeSettings, error) {
	p.patchCalls++
	p.patch = patch
	if p.patchErr != nil {
		return RuntimeSettings{}, p.patchErr
	}
	if patch.Log.Level != nil {
		p.settings.Log.Level = *patch.Log.Level
	}
	if patch.Log.BufferedRecords != nil {
		p.settings.Log.BufferedRecords = *patch.Log.BufferedRecords
	}
	if patch.DNSLog.MaxRecords != nil {
		p.settings.DNSLog.MaxRecords = *patch.DNSLog.MaxRecords
	}
	if patch.Flows.MaxFlows != nil {
		p.settings.Flows.MaxFlows = *patch.Flows.MaxFlows
	}
	if patch.Flows.RetentionSeconds != nil {
		p.settings.Flows.RetentionSeconds = *patch.Flows.RetentionSeconds
	}
	p.settings.Source = "runtime"
	return p.settings, nil
}

func newRuntimeSettingsTestServer(t *testing.T, cfg Config) (*Server, *fakeRuntimeSettingsProvider) {
	t.Helper()
	server := newTestServer(t, cfg, fakeRuntimeProvider{runtime: testRuntime()})
	provider := &fakeRuntimeSettingsProvider{settings: RuntimeSettings{
		ObservedAt: "2026-01-01T00:00:00Z",
		Source:     "config",
		Log:        RuntimeLogSettings{Level: "info", BufferedRecords: LogMaxBufferedRecords},
		DNSLog:     RuntimeDNSLogSettings{MaxRecords: DnsLogMaxRecords},
		Flows:      RuntimeFlowSettings{MaxFlows: FlowMaxFlows, RetentionSeconds: FlowMaxRetentionSeconds},
	}}
	server.SetRuntimeSettingsProvider(provider)
	server.SetLogProvider(fakeSSE{levels: []string{"debug", "info", "warn", "error"}})
	server.SetDnsProvider(fakeDns{})
	server.SetFlowProvider(fakeFlows{})
	return server, provider
}

func settingsPatchRequest(server *Server, contentType, body string, chunked bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPatch, runtimeSettingsPath, strings.NewReader(body))
	request.Host = "127.0.0.1:9527"
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Type", contentType)
	if chunked {
		request.ContentLength = -1
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func TestRuntimeSettingsReadAndPatch(t *testing.T) {
	server, provider := newRuntimeSettingsTestServer(t, Config{AllowAnonymousLoopback: true})
	read := doRequest(server, http.MethodGet, runtimeSettingsPath, "127.0.0.1:1234", nil)
	if read.Code != http.StatusOK {
		t.Fatalf("GET returned %d: %s", read.Code, read.Body)
	}
	want := map[string]any{
		"observed_at": provider.settings.ObservedAt,
		"source":      "config",
		"log":         map[string]any{"level": "info", "buffered_records": float64(1024)},
		"dns_log":     map[string]any{"max_records": float64(1024)},
		"flows":       map[string]any{"max_flows": float64(2048), "retention_seconds": float64(900)},
	}
	if got := decodeJSON(t, read); !reflect.DeepEqual(got, want) {
		t.Fatalf("settings = %#v, want %#v", got, want)
	}
	if routeTemplate(runtimeSettingsPath) != runtimeSettingsPath {
		t.Fatal("runtime settings route template is missing")
	}

	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	request, err := http.NewRequest(http.MethodHead, httpServer.URL+runtimeSettingsPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "127.0.0.1:9527"
	head, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = head.Body.Close() }()
	body, err := io.ReadAll(head.Body)
	if err != nil || len(body) != 0 || head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d, body = %q, read error = %v", head.StatusCode, body, err)
	}
	for _, name := range []string{"Content-Type", "Cache-Control", "X-Content-Type-Options"} {
		if got, want := head.Header.Get(name), read.Header().Get(name); got != want || got == "" {
			t.Errorf("HEAD %s = %q, GET = %q", name, got, want)
		}
	}

	const patchJSON = `{"log":{"level":"debug","buffered_records":64},"dns_log":{"max_records":64},"flows":{"max_flows":64,"retention_seconds":1}}`
	patched := settingsPatchRequest(server, "application/json; charset=utf-8", patchJSON, false)
	if patched.Code != http.StatusOK || provider.patchCalls != 1 {
		t.Fatalf("PATCH status = %d, provider calls = %d, response = %s", patched.Code, provider.patchCalls, patched.Body)
	}
	if got, err := json.Marshal(provider.patch); err != nil || string(got) != patchJSON {
		t.Fatalf("forwarded patch = %s, error = %v, want %s", got, err, patchJSON)
	}
	want["source"] = "runtime"
	want["log"] = map[string]any{"level": "debug", "buffered_records": float64(64)}
	want["dns_log"] = map[string]any{"max_records": float64(64)}
	want["flows"] = map[string]any{"max_flows": float64(64), "retention_seconds": float64(1)}
	if got := decodeJSON(t, patched); !reflect.DeepEqual(got, want) {
		t.Fatalf("PATCH settings = %#v, want %#v", got, want)
	}

	const partialJSON = `{"log":{"level":"info"}}`
	partial := settingsPatchRequest(server, "application/json", partialJSON, false)
	if partial.Code != http.StatusOK || provider.patchCalls != 2 {
		t.Fatalf("partial PATCH status = %d, provider calls = %d", partial.Code, provider.patchCalls)
	}
	want["log"] = map[string]any{"level": "info", "buffered_records": float64(64)}
	if got := decodeJSON(t, partial); !reflect.DeepEqual(got, want) {
		t.Fatalf("partial PATCH settings = %#v, want %#v", got, want)
	}
	if got, err := json.Marshal(provider.patch); err != nil || string(got) != partialJSON {
		t.Fatalf("forwarded partial patch = %s, error = %v, want %s", got, err, partialJSON)
	}
}

func TestRuntimeSettingsRejectsInvalidPatchesWithoutCallingProvider(t *testing.T) {
	server, provider := newRuntimeSettingsTestServer(t, Config{AllowAnonymousLoopback: true, MaxJSONBodyBytes: 256})
	initial := provider.settings
	for _, test := range []struct {
		name        string
		body        string
		status      int
		code        string
		contentType string
		chunked     bool
	}{
		{name: "invalid UTF-8", body: "{\"log\":{\"level\":\"\xff\"}}"},
		{name: "syntax", body: `{"log":`},
		{name: "trailing value", body: `{"log":{"level":"debug"}} {}`},
		{name: "empty", body: `{}`},
		{name: "null body", body: `null`},
		{name: "array", body: `[]`},
		{name: "empty section", body: `{"log":{}}`},
		{name: "null section", body: `{"log":null}`},
		{name: "null field", body: `{"log":{"level":"debug","buffered_records":null}}`},
		{name: "unknown top level", body: `{"other":true}`},
		{name: "unknown nested", body: `{"dns_log":{"maxRecords":100}}`},
		{name: "case sensitive", body: `{"log":{"Level":"debug"}}`},
		{name: "duplicate section", body: `{"log":{"level":"debug"},"log":{"level":"info"}}`},
		{name: "duplicate key", body: `{"log":{"level":"debug","level":"info"}}`},
		{name: "numeric string", body: `{"log":{"buffered_records":"64"}}`},
		{name: "number as level", body: `{"log":{"level":5}}`},
		{name: "fraction", body: `{"flows":{"max_flows":64.5}}`},
		{name: "integer overflow", body: `{"flows":{"max_flows":18446744073709551616}}`},
		{name: "log below floor", body: `{"log":{"buffered_records":63}}`},
		{name: "log above ceiling", body: `{"log":{"buffered_records":1025}}`},
		{name: "DNS below floor", body: `{"dns_log":{"max_records":1}}`},
		{name: "DNS above ceiling", body: `{"log":{"level":"debug"},"dns_log":{"max_records":1025}}`},
		{name: "flows below floor", body: `{"flows":{"max_flows":63}}`},
		{name: "flows above ceiling", body: `{"flows":{"max_flows":2049}}`},
		{name: "retention below floor", body: `{"flows":{"retention_seconds":0}}`},
		{name: "retention above ceiling", body: `{"flows":{"retention_seconds":901}}`},
		{name: "unavailable recorder with invalid type", body: `{"record_logs":true}`},
		{name: "unavailable geodata with invalid member", body: `{"geodata":{"unknown":true}}`},
		{name: "invalid takes priority over unsupported", body: `{"record_flows":"on","flows":{"max_flows":0}}`},
		{name: "unadvertised level", body: `{"log":{"level":"trace"},"dns_log":{"max_records":64}}`, status: 422, code: codeUnsupportedValue},
		{name: "unavailable flow recording", body: `{"record_flows":"on"}`, status: 422, code: codeUnsupportedValue},
		{name: "unavailable log recording", body: `{"record_logs":"off"}`, status: 422, code: codeUnsupportedValue},
		{name: "unavailable DNS recording", body: `{"record_dns_log":"auto"}`, status: 422, code: codeUnsupportedValue},
		{name: "unavailable geodata reset", body: `{"geodata":null}`, status: 422, code: codeUnsupportedValue},
		{name: "unavailable geodata sources", body: `{"geodata":{"geosite":{"urls":["https://example.net/geosite.dat"]}}}`, status: 422, code: codeUnsupportedValue},
		{name: "unsupported content type", body: `{"log":{"level":"debug"}}`, status: 415, code: codeUnsupportedMediaType, contentType: "application/json-patch+json"},
		{name: "oversized body", body: strings.Repeat(" ", 257), status: 413, code: codeRequestTooLarge, chunked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.status == 0 {
				test.status, test.code = http.StatusBadRequest, codeInvalidRequest
			}
			if test.contentType == "" {
				test.contentType = "application/json"
			}
			response := settingsPatchRequest(server, test.contentType, test.body, test.chunked)
			if response.Code != test.status {
				t.Fatalf("PATCH = %d, want %d: %s", response.Code, test.status, response.Body)
			}
			if got := decodeJSON(t, response)["error"].(map[string]any)["code"]; got != test.code {
				t.Fatalf("error code = %v, want %s", got, test.code)
			}
			if provider.patchCalls != 0 || provider.settings != initial {
				t.Fatal("rejected patch reached the provider or changed the settings")
			}
		})
	}
}

func TestRuntimeSettingsAvailabilityAndProviderFailure(t *testing.T) {
	server, provider := newRuntimeSettingsTestServer(t, Config{AllowAnonymousLoopback: true})
	method := doRequest(server, http.MethodPut, runtimeSettingsPath, "127.0.0.1:1234", nil)
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != "GET, HEAD, PATCH" {
		t.Fatalf("PUT status = %d, Allow = %q", method.Code, method.Header().Get("Allow"))
	}
	unauthenticated := doRequest(server, http.MethodPatch, runtimeSettingsPath, "192.0.2.1:1234", nil)
	if unauthenticated.Code != http.StatusUnauthorized || provider.patchCalls != 0 {
		t.Fatalf("unauthenticated PATCH = %d, provider calls = %d", unauthenticated.Code, provider.patchCalls)
	}

	provider.patchErr = errors.New("persistence failed")
	before := provider.settings
	failed := settingsPatchRequest(server, "application/json", `{"log":{"level":"debug"}}`, false)
	if failed.Code != http.StatusServiceUnavailable || failed.Header().Get("Retry-After") != "1" || provider.settings != before {
		t.Fatalf("failed PATCH status = %d, Retry-After = %q, settings = %#v", failed.Code, failed.Header().Get("Retry-After"), provider.settings)
	}
	if got := decodeJSON(t, failed)["error"].(map[string]any)["code"]; got != codeTemporarilyUnavailable {
		t.Fatalf("failure code = %v, want %s", got, codeTemporarilyUnavailable)
	}

	capabilities := func() map[string]any {
		t.Helper()
		response := doRequest(server, http.MethodGet, BasePath+"/capabilities", "127.0.0.1:1234", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("capabilities = %d: %s", response.Code, response.Body)
		}
		return decodeJSON(t, response)["resources"].(map[string]any)
	}
	resources := capabilities()
	wantSettings := map[string]any{
		"available": true,
		"fields":    []any{"log.level", "log.buffered_records", "dns_log.max_records", "flows.max_flows", "flows.retention_seconds"},
		"x-kdae":    map[string]any{"persist": "file", "survives": []any{"activation", "restart"}},
	}
	if got := resources["runtime_settings"]; !reflect.DeepEqual(got, wantSettings) {
		t.Fatalf("runtime_settings capability = %#v, want %#v", got, wantSettings)
	}
	for resource, bounds := range map[string]map[string]float64{
		"logs":    {"min_buffered_records": 64, "max_buffered_records": 1024},
		"dns_log": {"min_records": 64, "max_records": 1024},
		"flows":   {"min_flows": 64, "max_flows": 2048, "retention_seconds": 900},
	} {
		for key, want := range bounds {
			if got := resources[resource].(map[string]any)[key]; got != want {
				t.Errorf("capability %s.%s = %v, want %v", resource, key, got, want)
			}
		}
	}

	server.SetRuntimeSettingsProvider(nil)
	if got := capabilities()["runtime_settings"]; !reflect.DeepEqual(got, map[string]any{"available": false}) {
		t.Fatalf("runtime_settings without provider = %#v", got)
	}
	absent := doRequest(server, http.MethodGet, runtimeSettingsPath, "127.0.0.1:1234", nil)
	if absent.Code != http.StatusNotFound || decodeJSON(t, absent)["error"].(map[string]any)["code"] != codeCapabilityNotSupported {
		t.Fatalf("GET without provider = %d: %s", absent.Code, absent.Body)
	}
}
