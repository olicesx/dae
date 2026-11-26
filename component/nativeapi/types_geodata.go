/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"encoding/json"
)

// GeoDataUpdateProvider queues a download under the shared operation registry.
type GeoDataUpdateProvider interface {
	StartGeoDataUpdate(ctx context.Context, scope, idempotencyKey string) (OperationAccepted, error)
	GeoDataUpdateAvailable() bool
}

// GeoDataSettingsProvider supplies bounds for the geodata section of runtime settings.
type GeoDataSettingsProvider interface {
	GeoDataSettingsCapabilities() *GeoDataSettingsCapabilities
}

// GeoDataSettingsCapabilities describes the active engine's update settings.
type GeoDataSettingsCapabilities struct {
	MaxURLs          int
	MinIntervalHours int
	MaxIntervalHours int
	DefaultHours     int
	Checksum         *string
}

// GeoDataSettings reports effective download URLs and update policy.
type GeoDataSettings struct {
	Source         string            `json:"source"`
	Geosite        GeoDataSources    `json:"geosite"`
	GeoIP          GeoDataSources    `json:"geoip"`
	AutoUpdate     GeoDataAutoUpdate `json:"auto_update"`
	Download       GeoDataDownload   `json:"download"`
	VerifyChecksum bool              `json:"verify_checksum"`
}

// GeoDataSources holds URLs in fallback order.
type GeoDataSources struct {
	URLs []string `json:"urls"`
}

// GeoDataAutoUpdate describes the effective schedule.
type GeoDataAutoUpdate struct {
	Enabled       bool    `json:"enabled"`
	IntervalHours int     `json:"interval_hours"`
	Cron          *string `json:"cron,omitempty"`
}

// GeoDataSettingsPatch contains validated optional changes. Reset represents a
// null geodata member on the wire and is only used for live requests.
type GeoDataSettingsPatch struct {
	Reset          bool                    `json:"-"`
	Geosite        *GeoDataSources         `json:"geosite,omitempty"`
	GeoIP          *GeoDataSources         `json:"geoip,omitempty"`
	AutoUpdate     *GeoDataAutoUpdatePatch `json:"auto_update,omitempty"`
	Download       *GeoDataDownload        `json:"download,omitempty"`
	VerifyChecksum *bool                   `json:"verify_checksum,omitempty"`
}

// MarshalJSON emits the patch shape. A response names a null group_id for
// direct and routed downloads, while the patch omits group_id in those modes.
func (p GeoDataSettingsPatch) MarshalJSON() ([]byte, error) {
	if p.Reset {
		return []byte("null"), nil
	}
	type settingsPatch GeoDataSettingsPatch
	type downloadPatch struct {
		Route   string  `json:"route"`
		GroupID *string `json:"group_id,omitempty"`
	}
	var download *downloadPatch
	if p.Download != nil {
		download = &downloadPatch{Route: p.Download.Route, GroupID: p.Download.GroupID}
	}
	return json.Marshal(struct {
		settingsPatch
		Download *downloadPatch `json:"download,omitempty"`
	}{settingsPatch: settingsPatch(p), Download: download})
}

// GeoDataAutoUpdatePatch switches or changes the automatic schedule.
type GeoDataAutoUpdatePatch struct {
	Enabled       *bool   `json:"enabled,omitempty"`
	IntervalHours *int    `json:"interval_hours,omitempty"`
	Cron          *string `json:"cron,omitempty"`
}

// GeoAssetDownload reports how the loaded asset was obtained.
type GeoAssetDownload struct {
	FetchedURLRedacted *string          `json:"fetched_url_redacted"`
	Verified           bool             `json:"verified"`
	DownloadRoute      *GeoDataDownload `json:"download_route"`
}

// GeoDataUpdateStatus is present only on engines with configurable sources.
type GeoDataUpdateStatus struct {
	LastCheckedAt *string             `json:"last_checked_at"`
	LastUpdatedAt *string             `json:"last_updated_at"`
	NextCheckAt   *string             `json:"next_check_at"`
	LastError     *SafeError          `json:"last_error"`
	RequiredCodes map[string][]string `json:"required_codes"`
}
