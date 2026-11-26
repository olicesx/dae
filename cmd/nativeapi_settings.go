/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/sirupsen/logrus"
)

const runtimeSettingsVersion = 1

// runtimeSettingsStore serializes patches and generation activation. The API
// and startup use the same overrides regardless of the active control plane.
type runtimeSettingsStore struct {
	mu        sync.Mutex
	path      string
	log       *logrus.Logger
	sessions  *control.SessionManager
	logHub    *frameHub
	dnsLog    *control.DnsController
	baseLevel logrus.Level
	overrides nativeapi.RuntimeSettingsPatch
	geoData   *geoDataService
}

func newRuntimeSettingsStore(path string, log *logrus.Logger, sessions *control.SessionManager, logLevel string, geodata ...*geoDataService) *runtimeSettingsStore {
	store := &runtimeSettingsStore{path: path, log: log, sessions: sessions, baseLevel: configuredRuntimeLogLevel(logLevel)}
	if len(geodata) != 0 {
		store.geoData = geodata[0]
	}
	overrides, err := readRuntimeSettings(path, store.GeoDataSettingsCapabilities())
	if err == nil && overrides.GeoData != nil {
		err = validateGeoSettings(overrides.GeoData)
	}
	if err == nil && store.geoData != nil {
		store.geoData.ApplySettings(overrides.GeoData)
	}
	if err == nil {
		store.overrides = overrides
	} else if !stderrors.Is(err, os.ErrNotExist) {
		log.WithError(err).Warn("Ignoring runtime settings file")
	}
	store.applyLocked()
	return store
}

func readRuntimeSettings(path string, geodata ...*nativeapi.GeoDataSettingsCapabilities) (nativeapi.RuntimeSettingsPatch, error) {
	file, err := os.Open(path)
	if err != nil {
		return nativeapi.RuntimeSettingsPatch{}, err
	}
	defer func() { _ = file.Close() }()

	const maxBytes = 64 << 10
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nativeapi.RuntimeSettingsPatch{}, err
	}
	if len(data) > maxBytes {
		return nativeapi.RuntimeSettingsPatch{}, fmt.Errorf("runtime settings file exceeds %d bytes", maxBytes)
	}
	var document struct {
		Version   int             `json:"version"`
		Overrides json.RawMessage `json:"overrides"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nativeapi.RuntimeSettingsPatch{}, err
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return nativeapi.RuntimeSettingsPatch{}, fmt.Errorf("runtime settings file contains trailing data")
	}
	if document.Version != runtimeSettingsVersion {
		return nativeapi.RuntimeSettingsPatch{}, fmt.Errorf("unsupported runtime settings version %d", document.Version)
	}
	if document.Overrides == nil {
		return nativeapi.RuntimeSettingsPatch{}, nil
	}
	var caps *nativeapi.GeoDataSettingsCapabilities
	if len(geodata) != 0 {
		caps = geodata[0]
	}
	patch, err := nativeapi.DecodeRuntimeSettingsPatchWithGeoData(document.Overrides, caps)
	if err != nil {
		return nativeapi.RuntimeSettingsPatch{}, err
	}
	if patch.Log.Level != nil {
		if _, ok := logLevelRank[*patch.Log.Level]; !ok {
			return nativeapi.RuntimeSettingsPatch{}, fmt.Errorf("runtime settings file contains an unsupported log level")
		}
	}
	return patch, nil
}

func configuredRuntimeLogLevel(value string) logrus.Level {
	level, err := logrus.ParseLevel(value)
	if err != nil {
		return logrus.InfoLevel
	}
	return level
}

func (s *runtimeSettingsStore) dnsLogCapacity() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return runtimeSettingOr(s.overrides.DNSLog.MaxRecords, control.DnsLogCapacity)
}

func (s *runtimeSettingsStore) activate(generation *runtimeGeneration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsLog = generation.controlPlane.ActiveDnsController()
	if generation.conf != nil {
		s.baseLevel = configuredRuntimeLogLevel(generation.conf.Global.LogLevel)
	}
	s.applyLocked()
}

func (s *runtimeSettingsStore) attachLogHub(hub *frameHub) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logHub = hub
	hub.resize(s.snapshotLocked().Log.BufferedRecords)
}

func (s *runtimeSettingsStore) configureReloadLoggers() {
	s.mu.Lock()
	defer s.mu.Unlock()
	output := s.log.Out
	level := s.logLevelLocked().String()
	logger.SetLogger(s.log, level, disableTimestamp, nil)
	logger.SetLogger(logrus.StandardLogger(), level, disableTimestamp, nil)
	logrus.SetOutput(output)
}

// RuntimeSettings returns the effective settings after the last committed patch
// or activation.
func (s *runtimeSettingsStore) RuntimeSettings(ctx context.Context) (nativeapi.RuntimeSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nativeapi.RuntimeSettings{}, err
	}
	return s.effectiveLocked(), nil
}

func (s *runtimeSettingsStore) GeoDataSettingsCapabilities() *nativeapi.GeoDataSettingsCapabilities {
	return s.geoData.GeoDataSettingsCapabilities()
}

// PatchRuntimeSettings commits the validated merge before changing process state.
func (s *runtimeSettingsStore) PatchRuntimeSettings(ctx context.Context, patch nativeapi.RuntimeSettingsPatch) (nativeapi.RuntimeSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nativeapi.RuntimeSettings{}, err
	}

	next := s.overrides
	if patch.Log.Level != nil {
		next.Log.Level = new(*patch.Log.Level)
		if configuredRuntimeLogLevel(*patch.Log.Level) == s.baseLevel {
			next.Log.Level = nil
		}
	}
	next.Log.BufferedRecords = mergeRuntimeOverride(next.Log.BufferedRecords, patch.Log.BufferedRecords, nativeapi.LogMaxBufferedRecords)
	next.DNSLog.MaxRecords = mergeRuntimeOverride(next.DNSLog.MaxRecords, patch.DNSLog.MaxRecords, control.DnsLogCapacity)
	next.Flows.MaxFlows = mergeRuntimeOverride(next.Flows.MaxFlows, patch.Flows.MaxFlows, control.FlowHistoryCapacity)
	next.Flows.RetentionSeconds = mergeRuntimeOverride(next.Flows.RetentionSeconds, patch.Flows.RetentionSeconds, int(control.FlowHistoryRetention/time.Second))
	if patch.GeoData != nil {
		if s.geoData == nil {
			return nativeapi.RuntimeSettings{}, nativeapi.NewAPIError(http.StatusUnprocessableEntity, "unsupported_value", "geodata settings are unavailable")
		}
		geo, err := s.geoData.MergeSettings(next.GeoData, patch.GeoData, patch.GeoData.Reset)
		if err != nil {
			return nativeapi.RuntimeSettings{}, err
		}
		next.GeoData = geo
	}
	if reflect.DeepEqual(next, s.overrides) {
		return s.effectiveLocked(), nil
	}

	document := struct {
		Version   int                            `json:"version"`
		Overrides nativeapi.RuntimeSettingsPatch `json:"overrides,omitzero"`
	}{Version: runtimeSettingsVersion, Overrides: next}
	data, err := json.MarshalIndent(document, "", "  ")
	if err == nil {
		err = writeFileAtomic(s.path, append(data, '\n'), 0o600)
	}
	if err != nil {
		s.log.WithError(err).Warn("Failed to store runtime settings")
		return nativeapi.RuntimeSettings{}, &nativeapi.APIError{
			Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "runtime settings could not be stored", RetryAfterSeconds: 1,
		}
	}
	s.overrides = next
	if patch.GeoData != nil {
		s.geoData.ApplySettings(next.GeoData, patch.GeoData.Reset)
	}
	s.applyLocked()
	return s.effectiveLocked(), nil
}

func mergeRuntimeOverride[T comparable](current, patch *T, base T) *T {
	if patch == nil {
		return current
	}
	if *patch == base {
		return nil
	}
	return new(*patch)
}

func runtimeSettingOr[T any](override *T, base T) T {
	if override != nil {
		return *override
	}
	return base
}

func (s *runtimeSettingsStore) logLevelLocked() logrus.Level {
	if s.overrides.Log.Level != nil {
		return configuredRuntimeLogLevel(*s.overrides.Log.Level)
	}
	return s.baseLevel
}

func (s *runtimeSettingsStore) snapshotLocked() nativeapi.RuntimeSettings {
	var snapshot nativeapi.RuntimeSettings
	snapshot.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	snapshot.Source = "config"
	if s.overrides.Log != (nativeapi.RuntimeLogSettingsPatch{}) || s.overrides.DNSLog != (nativeapi.RuntimeDNSLogSettingsPatch{}) || s.overrides.Flows != (nativeapi.RuntimeFlowSettingsPatch{}) {
		snapshot.Source = "runtime"
	}
	snapshot.Log.Level = logLevelName(s.logLevelLocked())
	snapshot.Log.BufferedRecords = runtimeSettingOr(s.overrides.Log.BufferedRecords, nativeapi.LogMaxBufferedRecords)
	snapshot.DNSLog.MaxRecords = runtimeSettingOr(s.overrides.DNSLog.MaxRecords, control.DnsLogCapacity)
	snapshot.Flows.MaxFlows = runtimeSettingOr(s.overrides.Flows.MaxFlows, control.FlowHistoryCapacity)
	snapshot.Flows.RetentionSeconds = runtimeSettingOr(s.overrides.Flows.RetentionSeconds, int(control.FlowHistoryRetention/time.Second))
	return snapshot
}

func (s *runtimeSettingsStore) effectiveLocked() nativeapi.RuntimeSettings {
	settings := s.snapshotLocked()
	if s.geoData != nil {
		geo := s.geoData.Settings()
		settings.GeoData = &geo
	}
	return settings
}

func (s *runtimeSettingsStore) applyLocked() {
	settings := s.snapshotLocked()
	level := s.logLevelLocked()
	s.log.SetLevel(level)
	logrus.SetLevel(level)
	if s.logHub != nil {
		s.logHub.resize(settings.Log.BufferedRecords)
	}
	s.dnsLog.SetDNSLogCapacity(settings.DNSLog.MaxRecords)
	s.sessions.SetFlowHistoryLimits(settings.Flows.MaxFlows, time.Duration(settings.Flows.RetentionSeconds)*time.Second)
}

var _ nativeapi.RuntimeSettingsProvider = (*runtimeSettingsStore)(nil)
