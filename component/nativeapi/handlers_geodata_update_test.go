/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type geoHTTPFixture struct {
	fakeRuntimeSettingsProvider
	keys []string
}

func (*geoHTTPFixture) GeoDataSettingsCapabilities() *GeoDataSettingsCapabilities {
	return &GeoDataSettingsCapabilities{MaxURLs: 2, MinIntervalHours: 1, MaxIntervalHours: 168, DefaultHours: 24, Checksum: new("sha256sum")}
}

func (*geoHTTPFixture) GeoData(context.Context) (GeoData, error) {
	return GeoData{GeoDataUpdateStatus: &GeoDataUpdateStatus{RequiredCodes: map[string][]string{"geoip": {}, "geosite": {}}}}, nil
}

func (*geoHTTPFixture) GeoDataUpdateAvailable() bool { return true }

func (f *geoHTTPFixture) StartGeoDataUpdate(_ context.Context, _, key string) (OperationAccepted, error) {
	f.keys = append(f.keys, key)
	return OperationAccepted{OperationID: "op-geo", Kind: "geodata_update", Status: "queued", Href: BasePath + "/operations/op-geo"}, nil
}

func TestGeodataCapabilitiesAndOperationHTTP(t *testing.T) {
	server := newTestServer(t, Config{Secret: "test-geodata-secret"}, fakeRuntimeProvider{runtime: testRuntime()})
	withP3Providers(server)
	server.SetOperationProvider(newFakeOperationProvider())
	fixture := &geoHTTPFixture{}
	fixture.settings = RuntimeSettings{GeoData: &GeoDataSettings{Geosite: GeoDataSources{URLs: []string{"https://example.test/?v=test-geodata-secret"}}}}
	server.SetRuntimeSettingsProvider(fixture)
	server.SetGeoDataProvider(fixture)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Host = "127.0.0.1:9527"
		r.Header.Set("Authorization", "Bearer test-geodata-secret")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "geodata-test")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		return w
	}
	w := request(http.MethodGet, BasePath+"/capabilities", "")
	require.Equal(t, http.StatusOK, w.Code)
	resources := decodeJSON(t, w)["resources"].(map[string]any)
	geo := resources["geodata"].(map[string]any)
	require.Equal(t, true, geo["configurable_sources"])
	require.Equal(t, true, geo["can_update"])
	require.Equal(t, "sha256sum", geo["checksum"])
	require.Contains(t, resources["runtime_settings"].(map[string]any)["fields"], "geodata")
	w = request(http.MethodGet, BasePath+"/geodata", "")
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "\"last_checked_at\":null")
	w = request(http.MethodPatch, runtimeSettingsPath, `{"geodata":{"auto_update":{"interval_hours":24},"verify_checksum":false}}`)
	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), "test-geodata-secret")
	require.Equal(t, 24, *fixture.patch.GeoData.AutoUpdate.IntervalHours)
	require.False(t, *fixture.patch.GeoData.VerifyChecksum)
	w = request(http.MethodPatch, runtimeSettingsPath, `{"geodata":{"auto_update":{"interval_hours":169}}}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	w = request(http.MethodPatch, runtimeSettingsPath, `{"geodata":null}`)
	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, fixture.patch.GeoData.Reset)
	w = request(http.MethodPost, geoDataUpdatePath, "{}")
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Empty(t, fixture.keys)
	w = request(http.MethodPost, geoDataUpdatePath, "")
	require.Equal(t, http.StatusAccepted, w.Code)
	require.Equal(t, BasePath+"/operations/op-geo", w.Header().Get("Location"))
	require.NotEmpty(t, w.Header().Get("Retry-After"))
	require.Equal(t, []string{"geodata-test"}, fixture.keys)
}

func TestGeodataPatchRequiresCredential(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	fixture := &geoHTTPFixture{}
	server.SetRuntimeSettingsProvider(fixture)
	server.SetGeoDataProvider(fixture)
	w := settingsPatchRequest(server, "application/json", `{"geodata":null}`, false)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Zero(t, fixture.patchCalls)
}
