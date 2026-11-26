/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestRuntimeSettingsPersistThroughActivationAndRestart(t *testing.T) {
	oldLevel := logrus.GetLevel()
	t.Cleanup(func() { logrus.SetLevel(oldLevel) })
	ctx := context.Background()
	sessions := control.NewSessionManager(ctx)
	t.Cleanup(func() { require.NoError(t, sessions.Close()) })
	path := filepath.Join(t.TempDir(), "runtime-settings.json")
	log := logrus.New()
	store := newRuntimeSettingsStore(path, log, sessions, "info")
	hub := newFrameHub("instance", "logs", nativeapi.LogMaxBufferedRecords, time.Minute, 1)
	store.attachLogHub(hub)
	for i := range 70 {
		hub.publish("log", i)
	}

	provider := &nativeAPIProvider{}
	server, err := nativeapi.NewServer(nativeapi.Config{Secret: "test-token"}, provider, log)
	require.NoError(t, err)
	server.SetRuntimeSettingsProvider(store)
	server.SetLogProvider(provider)
	request := httptest.NewRequest(http.MethodPatch, "http://127.0.0.1:9527/api/v1/runtime/settings", strings.NewReader(`{
		"log":{"level":"debug","buffered_records":64},
		"dns_log":{"max_records":128},
		"flows":{"max_flows":256,"retention_seconds":60}
	}`))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var snapshot nativeapi.RuntimeSettings
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &snapshot))
	require.Equal(t, "runtime", snapshot.Source)
	require.Equal(t, logrus.DebugLevel, log.GetLevel())
	require.Equal(t, logrus.DebugLevel, logrus.GetLevel())
	require.Equal(t, 64, hub.length)
	require.Equal(t, 6, hub.frames[0].data)
	require.Equal(t, 69, hub.frames[63].data)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	candidate := newRuntimeGeneration(nil, nil, nil, &config.Config{Global: config.Global{LogLevel: "warn"}})
	supervisor := newRuntimeSupervisor(newRuntimeGeneration(nil, nil, nil, nil))
	supervisor.onActivate = store.activate
	require.NoError(t, supervisor.installPrepared(candidate))
	_, err = supervisor.publishPrepared(candidate)
	require.NoError(t, err)
	require.Equal(t, logrus.DebugLevel, log.GetLevel())

	restarted := newRuntimeSettingsStore(path, log, sessions, "warn")
	restored, err := restarted.RuntimeSettings(ctx)
	require.NoError(t, err)
	require.Equal(t, snapshot.Log, restored.Log)
	require.Equal(t, snapshot.DNSLog, restored.DNSLog)
	require.Equal(t, snapshot.Flows, restored.Flows)
	require.Equal(t, "runtime", restored.Source)

	var patch nativeapi.RuntimeSettingsPatch
	patch.Log.Level = new("warn")
	patch.Log.BufferedRecords = new(nativeapi.LogMaxBufferedRecords)
	patch.DNSLog.MaxRecords = new(control.DnsLogCapacity)
	patch.Flows.MaxFlows = new(control.FlowHistoryCapacity)
	patch.Flows.RetentionSeconds = new(int(control.FlowHistoryRetention / time.Second))
	snapshot, err = restarted.PatchRuntimeSettings(ctx, patch)
	require.NoError(t, err)
	require.Equal(t, "config", snapshot.Source)
	require.Equal(t, logrus.WarnLevel, log.GetLevel())
	stored, err := readRuntimeSettings(path)
	require.NoError(t, err)
	require.Zero(t, stored)
}

func TestRuntimeSettingsConcurrentPatchesMergeAcrossActivation(t *testing.T) {
	oldLevel := logrus.GetLevel()
	t.Cleanup(func() { logrus.SetLevel(oldLevel) })
	ctx := context.Background()
	sessions := control.NewSessionManager(ctx)
	t.Cleanup(func() { require.NoError(t, sessions.Close()) })
	path := filepath.Join(t.TempDir(), "runtime-settings.json")
	store := newRuntimeSettingsStore(path, logrus.New(), sessions, "info")
	candidate := newRuntimeGeneration(nil, nil, nil, &config.Config{Global: config.Global{LogLevel: "warn"}})
	supervisor := newRuntimeSupervisor(newRuntimeGeneration(nil, nil, nil, nil))
	supervisor.onActivate = store.activate
	require.NoError(t, supervisor.installPrepared(candidate))

	var logPatch, flowPatch nativeapi.RuntimeSettingsPatch
	logPatch.Log.Level = new("debug")
	flowPatch.Flows.MaxFlows = new(256)
	var workers sync.WaitGroup
	results := make(chan error, 3)
	for _, patch := range []nativeapi.RuntimeSettingsPatch{logPatch, flowPatch} {
		workers.Go(func() {
			_, err := store.PatchRuntimeSettings(ctx, patch)
			results <- err
		})
	}
	workers.Go(func() {
		_, err := supervisor.publishPrepared(candidate)
		results <- err
	})
	workers.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	persisted, err := readRuntimeSettings(path)
	require.NoError(t, err)
	require.Equal(t, "debug", *persisted.Log.Level)
	require.Equal(t, 256, *persisted.Flows.MaxFlows)
	require.Equal(t, logrus.DebugLevel, logrus.GetLevel())
}

func TestRuntimeSettingsGeodataOverridesSurviveRestartAndReset(t *testing.T) {
	oldLevel := logrus.GetLevel()
	t.Cleanup(func() { logrus.SetLevel(oldLevel) })
	ctx := context.Background()
	sessions := control.NewSessionManager(ctx)
	t.Cleanup(func() { require.NoError(t, sessions.Close()) })
	root := t.TempDir()
	path := filepath.Join(root, "runtime-settings.json")
	geo := newGeoDataService(filepath.Join(root, "geodata.d"), logrus.New())
	t.Cleanup(geo.Close)
	store := newRuntimeSettingsStore(path, logrus.New(), sessions, "info", geo)
	patch := nativeapi.RuntimeSettingsPatch{GeoData: &nativeapi.GeoDataSettingsPatch{
		Geosite:    &nativeapi.GeoDataSources{URLs: []string{"https://example.com/rules.dat"}},
		AutoUpdate: &nativeapi.GeoDataAutoUpdatePatch{IntervalHours: new(48)},
		Download:   &nativeapi.GeoDataDownload{Route: "direct"},
	}}
	x, err := store.PatchRuntimeSettings(ctx, patch)
	require.NoError(t, err)
	require.Equal(t, "config", x.Source)
	require.Equal(t, "override", x.GeoData.Source)
	require.Equal(t, "direct", x.GeoData.Download.Route)
	restored := newGeoDataService(filepath.Join(root, "geodata.d"), logrus.New())
	t.Cleanup(restored.Close)
	store = newRuntimeSettingsStore(path, logrus.New(), sessions, "info", restored)
	y, err := store.RuntimeSettings(ctx)
	require.NoError(t, err)
	require.Equal(t, x.GeoData, y.GeoData)
	y, err = store.PatchRuntimeSettings(ctx, nativeapi.RuntimeSettingsPatch{GeoData: &nativeapi.GeoDataSettingsPatch{Reset: true}})
	require.NoError(t, err)
	require.Equal(t, "default", y.GeoData.Source)
	require.Equal(t, "routing", y.GeoData.Download.Route)
	require.False(t, y.GeoData.AutoUpdate.Enabled)
}

func TestRuntimeSettingsInvalidFileUsesConfig(t *testing.T) {
	oldLevel := logrus.GetLevel()
	t.Cleanup(func() { logrus.SetLevel(oldLevel) })
	ctx := context.Background()
	sessions := control.NewSessionManager(ctx)
	t.Cleanup(func() { require.NoError(t, sessions.Close()) })
	path := filepath.Join(t.TempDir(), "runtime-settings.json")
	invalid := []byte(`{"version":1,"overrides":{"log":{"level":"fatal"},"flows":{"max_flows":256}}}`)
	require.NoError(t, os.WriteFile(path, invalid, 0o600))
	log := logrus.New()
	store := newRuntimeSettingsStore(path, log, sessions, "info")
	snapshot, err := store.RuntimeSettings(ctx)
	require.NoError(t, err)
	require.Equal(t, "config", snapshot.Source)
	require.Equal(t, control.FlowHistoryCapacity, snapshot.Flows.MaxFlows)
	require.Equal(t, logrus.InfoLevel, log.GetLevel())
	stored, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, invalid, stored)
}

func TestRuntimeSettingsWriteFailureKeepsEffectiveValues(t *testing.T) {
	oldLevel := logrus.GetLevel()
	t.Cleanup(func() { logrus.SetLevel(oldLevel) })
	ctx := context.Background()
	sessions := control.NewSessionManager(ctx)
	t.Cleanup(func() { require.NoError(t, sessions.Close()) })
	log := logrus.New()
	path := filepath.Join(t.TempDir(), "missing-dir", "runtime-settings.json")
	store := newRuntimeSettingsStore(path, log, sessions, "info")
	patch := nativeapi.RuntimeSettingsPatch{}
	patch.Log.Level = new("debug")
	patch.Flows.MaxFlows = new(256)
	_, err := store.PatchRuntimeSettings(ctx, patch)
	var apiErr *nativeapi.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, 503, apiErr.Status)
	require.Positive(t, apiErr.RetryAfterSeconds)
	snapshot, err := store.RuntimeSettings(ctx)
	require.NoError(t, err)
	require.Equal(t, "config", snapshot.Source)
	require.Equal(t, control.FlowHistoryCapacity, snapshot.Flows.MaxFlows)
	require.Equal(t, logrus.InfoLevel, log.GetLevel())
}
