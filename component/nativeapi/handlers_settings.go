/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const runtimeSettingsPath = BasePath + "/runtime/settings"

func (s *Server) handleRuntimeSettings(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.runtimeSettings == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}

	var settings RuntimeSettings
	var err error
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		settings, err = s.runtimeSettings.RuntimeSettings(r.Context())
	case http.MethodPatch:
		settings, err = s.patchRuntimeSettings(r)
	default:
		writeMethodNotAllowed(w, requestID, "GET, HEAD, PATCH")
		return
	}
	if err != nil {
		var apiErr *APIError
		if r.Method == http.MethodPatch && (!errors.As(err, &apiErr) ||
			(apiErr != nil && apiErr.Status == http.StatusServiceUnavailable && apiErr.RetryAfterSeconds <= 0)) {
			w.Header().Set("Retry-After", "1")
		}
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if settings.ObservedAt == "" {
		settings.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if settings.GeoData != nil && s.cfg.Secret != "" {
		geo := *settings.GeoData
		geo.Geosite.URLs = maskSettingsURLs(geo.Geosite.URLs, s.cfg.Secret)
		geo.GeoIP.URLs = maskSettingsURLs(geo.GeoIP.URLs, s.cfg.Secret)
		settings.GeoData = &geo
	}
	writeJSON(w, http.StatusOK, settings)
}

func maskSettingsURLs(urls []string, secret string) []string {
	masked := slices.Clone(urls)
	for i, value := range masked {
		for _, variant := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
			value = strings.ReplaceAll(value, variant, "[redacted]")
		}
		masked[i] = value
	}
	return masked
}

func (s *Server) patchRuntimeSettings(r *http.Request) (RuntimeSettings, error) {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		return RuntimeSettings{}, NewAPIError(http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
	}
	var body json.RawMessage
	if err := decodeLimitedJSON(r, s.cfg.MaxJSONBodyBytes, &body); err != nil {
		if errors.Is(err, errLimitedJSONBodyTooLarge) {
			return RuntimeSettings{}, NewAPIError(http.StatusRequestEntityTooLarge, codeRequestTooLarge, "request body is too large")
		}
		return RuntimeSettings{}, NewAPIError(http.StatusBadRequest, codeInvalidRequest, "invalid runtime settings patch JSON")
	}
	patch, err := DecodeRuntimeSettingsPatchWithGeoData(body, s.geoDataSettingsCapabilities())
	if err != nil {
		return RuntimeSettings{}, err
	}
	if patch.GeoData != nil && s.cfg.Secret == "" {
		return RuntimeSettings{}, NewAPIError(http.StatusForbidden, codePermissionDenied, "geodata changes require a credential")
	}
	if patch.Log.Level != nil && (s.logs == nil || !containsString(s.logs.LogLevels(), *patch.Log.Level)) {
		return RuntimeSettings{}, NewAPIError(http.StatusUnprocessableEntity, codeUnsupportedValue, "log.level is not an advertised level")
	}
	return s.runtimeSettings.PatchRuntimeSettings(r.Context(), patch)
}

// DecodeRuntimeSettingsPatch decodes a nonempty patch and validates its schema,
// supported fields and numeric bounds. Callers validate log levels separately
// against the engine's advertised levels.
func DecodeRuntimeSettingsPatch(data []byte) (RuntimeSettingsPatch, error) {
	return DecodeRuntimeSettingsPatchWithGeoData(data, nil)
}

// DecodeRuntimeSettingsPatchWithGeoData additionally accepts geodata settings when advertised.
func DecodeRuntimeSettingsPatchWithGeoData(data []byte, geo *GeoDataSettingsCapabilities) (RuntimeSettingsPatch, error) {
	if !utf8.Valid(data) {
		return RuntimeSettingsPatch{}, NewAPIError(http.StatusBadRequest, codeInvalidRequest, "runtime settings patch must be UTF-8")
	}
	var patch RuntimeSettingsPatch
	var unsupported string
	markUnsupported := func(field string, validate settingsValidator) settingsValidator {
		return func(raw json.RawMessage) error {
			unsupported = field
			return validate(raw)
		}
	}
	validateGeoData := decodeSettingsGeoData(&patch.GeoData, geo)
	if geo == nil {
		validateGeoData = markUnsupported("geodata", validateGeoData)
	}
	err := settingsObject("patch", map[string]settingsValidator{
		"log": settingsObject("log", map[string]settingsValidator{
			"level":            settingsValue("log.level", &patch.Log.Level, nil, "must be a string"),
			"buffered_records": settingsInt("log.buffered_records", &patch.Log.BufferedRecords, LogMinBufferedRecords, LogMaxBufferedRecords),
		}),
		"dns_log": settingsObject("dns_log", map[string]settingsValidator{
			"max_records": settingsInt("dns_log.max_records", &patch.DNSLog.MaxRecords, DnsLogMinRecords, DnsLogMaxRecords),
		}),
		"flows": settingsObject("flows", map[string]settingsValidator{
			"max_flows":         settingsInt("flows.max_flows", &patch.Flows.MaxFlows, FlowMinFlows, FlowMaxFlows),
			"retention_seconds": settingsInt("flows.retention_seconds", &patch.Flows.RetentionSeconds, FlowMinRetentionSeconds, FlowMaxRetentionSeconds),
		}),
		"record_flows":   markUnsupported("record_flows", settingsRecorderMode("record_flows")),
		"record_logs":    markUnsupported("record_logs", settingsRecorderMode("record_logs")),
		"record_dns_log": markUnsupported("record_dns_log", settingsRecorderMode("record_dns_log")),
		"geodata":        validateGeoData,
	})(data)
	if err != nil {
		return RuntimeSettingsPatch{}, NewAPIError(http.StatusBadRequest, codeInvalidRequest, err.Error())
	}
	if unsupported != "" {
		return RuntimeSettingsPatch{}, NewAPIError(http.StatusUnprocessableEntity, codeUnsupportedValue, unsupported+" is not an advertised runtime setting")
	}
	return patch, nil
}

type settingsValidator func(json.RawMessage) error

// settingsObject checks exact field names and duplicate keys. The normal JSON
// struct decoder accepts case-insensitive names and repeats of the same key.
func settingsObject(path string, fields map[string]settingsValidator) settingsValidator {
	return func(raw json.RawMessage) error {
		if !json.Valid(raw) {
			return fmt.Errorf("%s is not valid JSON", path)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		opening, err := decoder.Token()
		if err != nil || opening != json.Delim('{') {
			return fmt.Errorf("%s must be an object", path)
		}
		seen := make(map[string]bool, len(fields))
		for decoder.More() {
			key, _ := decoder.Token() // json.Valid checked the object syntax.
			name := key.(string)
			validate, known := fields[name]
			if !known {
				return fmt.Errorf("%s contains an unknown field", path)
			}
			if seen[name] {
				return fmt.Errorf("%s contains a duplicate field", path)
			}
			seen[name] = true
			var value json.RawMessage
			if err := decoder.Decode(&value); err != nil {
				return fmt.Errorf("%s contains invalid JSON", path)
			}
			if err := validate(value); err != nil {
				return err
			}
		}
		if len(seen) == 0 {
			return fmt.Errorf("%s must not be empty", path)
		}
		return nil
	}
}

func settingsValue[T any](path string, target **T, valid func(T) bool, constraint string) settingsValidator {
	return func(raw json.RawMessage) error {
		var value *T
		if err := json.Unmarshal(raw, &value); err != nil || value == nil || (valid != nil && !valid(*value)) {
			return fmt.Errorf("%s %s", path, constraint)
		}
		if target != nil {
			*target = value
		}
		return nil
	}
}

func settingsInt(path string, target **int, min, max int) settingsValidator {
	return settingsValue(path, target, func(v int) bool { return v >= min && v <= max },
		fmt.Sprintf("must be an integer in %d..%d", min, max))
}

func settingsRecorderMode(path string) settingsValidator {
	return settingsValue(path, nil, func(v string) bool { return v == "on" || v == "off" || v == "auto" },
		"must be on, off or auto")
}

// decodeSettingsGeoData checks the shared shape even where the feature is unavailable.
func decodeSettingsGeoData(target **GeoDataSettingsPatch, caps *GeoDataSettingsCapabilities) settingsValidator {
	return func(raw json.RawMessage) error {
		patch := &GeoDataSettingsPatch{}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			patch.Reset = true
			*target = patch
			return nil
		}
		sources := func(path string, target **GeoDataSources) settingsValidator {
			return func(raw json.RawMessage) error {
				var urls *[]string
				if err := settingsObject(path, map[string]settingsValidator{
					"urls": settingsValue(path+".urls", &urls, validSettingsGeodataURLs, "must contain unique HTTP(S) URLs"),
				})(raw); err != nil {
					return err
				}
				if caps != nil && len(*urls) > caps.MaxURLs {
					return fmt.Errorf("%s.urls must have at most %d URLs", path, caps.MaxURLs)
				}
				*target = &GeoDataSources{URLs: *urls}
				return nil
			}
		}
		var route, group *string
		schedule := &GeoDataAutoUpdatePatch{}
		intervalMin, intervalMax := 1, int(^uint(0)>>1)
		if caps != nil {
			intervalMin, intervalMax = caps.MinIntervalHours, caps.MaxIntervalHours
		}
		if err := settingsObject("geodata", map[string]settingsValidator{
			"geosite": sources("geodata.geosite", &patch.Geosite),
			"geoip":   sources("geodata.geoip", &patch.GeoIP),
			"download": settingsObject("geodata.download", map[string]settingsValidator{
				"route": settingsValue("geodata.download.route", &route, func(v string) bool {
					return v == "routing" || v == "group" || v == "direct"
				}, "must be routing, group or direct"),
				"group_id": settingsValue("geodata.download.group_id", &group, nonemptySettingString, "must be a nonempty string"),
			}),
			"auto_update": settingsObject("geodata.auto_update", map[string]settingsValidator{
				"enabled":        settingsValue("geodata.auto_update.enabled", &schedule.Enabled, nil, "must be a boolean"),
				"interval_hours": settingsInt("geodata.auto_update.interval_hours", &schedule.IntervalHours, intervalMin, intervalMax),
				"cron":           settingsValue("geodata.auto_update.cron", &schedule.Cron, nonemptySettingString, "must be a nonempty string"),
			}),
			"verify_checksum": settingsValue("geodata.verify_checksum", &patch.VerifyChecksum, nil, "must be a boolean"),
		})(raw); err != nil {
			return err
		}
		if schedule.IntervalHours != nil && schedule.Cron != nil {
			return errors.New("geodata.auto_update cannot include both interval_hours and cron")
		}
		if *schedule != (GeoDataAutoUpdatePatch{}) {
			patch.AutoUpdate = schedule
		}
		if (route == nil && group != nil) || (route != nil && (*route == "group") != (group != nil)) {
			return errors.New("geodata.download requires a route and allows group_id only with route group")
		}
		if route != nil {
			patch.Download = &GeoDataDownload{Route: *route, GroupID: group}
		}
		*target = patch
		return nil
	}
}

func nonemptySettingString(value string) bool {
	return value != ""
}

func validSettingsGeodataURLs(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		parsed, err := url.ParseRequestURI(value)
		if err != nil || parsed.Host == "" || parsed.User != nil || len(value) > 4096 ||
			!strings.HasPrefix(value, "https://") && !strings.HasPrefix(value, "http://") || strings.Contains(value, "#") || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
