/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"maps"
	"math/rand/v2"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
)

const (
	geoMaxURLs          = 4
	geoMinIntervalHours = 1
	geoMaxIntervalHours = 168
	geoDefaultHours     = 24
)

func (g *geoDataService) GeoDataSettingsCapabilities() *nativeapi.GeoDataSettingsCapabilities {
	if g == nil {
		return nil
	}
	return &nativeapi.GeoDataSettingsCapabilities{
		MaxURLs: geoMaxURLs, MinIntervalHours: geoMinIntervalHours, MaxIntervalHours: geoMaxIntervalHours,
		DefaultHours: geoDefaultHours, Checksum: stringPointer("sha256sum"),
	}
}

func (g *geoDataService) Settings() nativeapi.GeoDataSettings {
	g.mu.Lock()
	settings := g.settingsLocked()
	g.mu.Unlock()
	settings.Download = g.visibleRoute(settings.Download)
	return settings
}

func (g *geoDataService) settingsLocked() nativeapi.GeoDataSettings {
	settings := nativeapi.GeoDataSettings{
		Source:         "default",
		Geosite:        nativeapi.GeoDataSources{URLs: defaultGeoURLs("geosite")},
		GeoIP:          nativeapi.GeoDataSources{URLs: defaultGeoURLs("geoip")},
		AutoUpdate:     nativeapi.GeoDataAutoUpdate{Enabled: false, IntervalHours: geoDefaultHours},
		Download:       nativeapi.GeoDataDownload{Route: "routing"},
		VerifyChecksum: true,
	}
	if g.fileSettings != nil {
		applyGeoSettings(&settings, g.fileSettings, "config")
	}
	if g.overrides != nil {
		applyGeoSettings(&settings, g.overrides, "override")
	}
	return settings
}

func applyGeoSettings(settings *nativeapi.GeoDataSettings, overrides *nativeapi.GeoDataSettingsPatch, source string) {
	if overrides.Geosite != nil {
		settings.Geosite.URLs = slices.Clone(overrides.Geosite.URLs)
		settings.Source = source
	}
	if overrides.GeoIP != nil {
		settings.GeoIP.URLs = slices.Clone(overrides.GeoIP.URLs)
		settings.Source = source
	}
	if overrides.AutoUpdate != nil {
		settings.AutoUpdate.Enabled = runtimeSettingOr(overrides.AutoUpdate.Enabled, settings.AutoUpdate.Enabled)
		settings.AutoUpdate.IntervalHours = runtimeSettingOr(overrides.AutoUpdate.IntervalHours, settings.AutoUpdate.IntervalHours)
	}
	if overrides.Download != nil {
		settings.Download = *overrides.Download
		if settings.Download.GroupID != nil {
			settings.Download.GroupID = new(*settings.Download.GroupID)
		}
	}
	settings.VerifyChecksum = runtimeSettingOr(overrides.VerifyChecksum, settings.VerifyChecksum)
}

func defaultGeoURLs(kind string) []string {
	return []string{
		"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/" + kind + ".dat",
		"https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/" + kind + ".dat",
	}
}

func (g *geoDataService) MergeSettings(current, patch *nativeapi.GeoDataSettingsPatch, reset bool) (*nativeapi.GeoDataSettingsPatch, error) {
	if reset || patch != nil && patch.Reset {
		return nil, nil
	}
	if patch == nil {
		return current, nil
	}
	if err := validateGeoSettings(patch); err != nil {
		return nil, err
	}
	if patch.Download != nil && patch.Download.GroupID != nil && !g.hasGroup(*patch.Download.GroupID) {
		return nil, nativeapi.NewAPIError(http.StatusConflict, "state_conflict", "geodata.download.group_id is not a current group")
	}
	next := new(nativeapi.GeoDataSettingsPatch)
	if current != nil {
		*next = *current
	}
	if patch.Geosite != nil {
		next.Geosite = &nativeapi.GeoDataSources{URLs: slices.Clone(patch.Geosite.URLs)}
	}
	if patch.GeoIP != nil {
		next.GeoIP = &nativeapi.GeoDataSources{URLs: slices.Clone(patch.GeoIP.URLs)}
	}
	if patch.AutoUpdate != nil {
		schedule := nativeapi.GeoDataAutoUpdatePatch{}
		if next.AutoUpdate != nil {
			schedule = *next.AutoUpdate
		} else {
			// Overriding one member of the schedule preserves its effective
			// companion until the next time file values are taken.
			g.mu.Lock()
			base := g.settingsLocked().AutoUpdate
			g.mu.Unlock()
			schedule.Enabled = new(base.Enabled)
			schedule.IntervalHours = new(base.IntervalHours)
		}
		if patch.AutoUpdate.Enabled != nil {
			schedule.Enabled = new(*patch.AutoUpdate.Enabled)
		}
		if patch.AutoUpdate.IntervalHours != nil {
			schedule.IntervalHours = new(*patch.AutoUpdate.IntervalHours)
		}
		next.AutoUpdate = &schedule
	}
	if patch.Download != nil {
		next.Download = new(*patch.Download)
		if patch.Download.GroupID != nil {
			next.Download.GroupID = new(*patch.Download.GroupID)
		}
	}
	if patch.VerifyChecksum != nil {
		next.VerifyChecksum = new(*patch.VerifyChecksum)
	}
	return next, nil
}

func validateGeoSettings(patch *nativeapi.GeoDataSettingsPatch) error {
	invalid := func(message string) error {
		return nativeapi.NewAPIError(http.StatusBadRequest, "invalid_request", message)
	}
	for _, sources := range []*nativeapi.GeoDataSources{patch.Geosite, patch.GeoIP} {
		if sources == nil {
			continue
		}
		if len(sources.URLs) == 0 || len(sources.URLs) > geoMaxURLs {
			return invalid("geodata source URL count is outside the advertised limits")
		}
		seen := make(map[string]struct{}, len(sources.URLs))
		for _, raw := range sources.URLs {
			if _, err := parseGeoURL(raw); err != nil {
				return invalid(err.Error())
			}
			if _, duplicate := seen[raw]; duplicate {
				return invalid("geodata source URLs must be unique")
			}
			seen[raw] = struct{}{}
		}
	}
	if auto := patch.AutoUpdate; auto != nil {
		if auto.Cron != nil || auto.Enabled == nil && auto.IntervalHours == nil {
			return invalid("geodata requires a supported interval schedule")
		}
		if auto.IntervalHours != nil && (*auto.IntervalHours < geoMinIntervalHours || *auto.IntervalHours > geoMaxIntervalHours) {
			return invalid("geodata interval is outside the advertised limits")
		}
	}
	if route := patch.Download; route != nil {
		switch route.Route {
		case "routing", "direct":
			if route.GroupID == nil {
				return nil
			}
		case "group":
			if route.GroupID != nil && *route.GroupID != "" {
				return nil
			}
		}
		return invalid("invalid geodata download route")
	}
	return nil
}

// TakeFileSettings installs startup file values and drops the stored override
// for each field the file names. The caller persists the returned overrides.
func (g *geoDataService) TakeFileSettings(file, overrides *nativeapi.GeoDataSettingsPatch) (*nativeapi.GeoDataSettingsPatch, error) {
	if file != nil {
		if err := validateGeoSettings(file); err != nil {
			return nil, err
		}
	}
	if overrides != nil {
		if err := validateGeoSettings(overrides); err != nil {
			return nil, err
		}
	}
	if file != nil && overrides != nil {
		next := *overrides
		if file.Geosite != nil {
			next.Geosite = nil
		}
		if file.GeoIP != nil {
			next.GeoIP = nil
		}
		if file.AutoUpdate != nil {
			next.AutoUpdate = nil
		}
		if file.Download != nil {
			next.Download = nil
		}
		if file.VerifyChecksum != nil {
			next.VerifyChecksum = nil
		}
		overrides = &next
		if next == (nativeapi.GeoDataSettingsPatch{}) {
			overrides = nil
		}
	}
	g.mu.Lock()
	g.fileSettings = file
	g.overrides = overrides
	g.rescheduleLocked(time.Now())
	g.mu.Unlock()
	return overrides, nil
}

// ApplySettings is called only after the runtime settings store commits.
func (g *geoDataService) ApplySettings(overrides *nativeapi.GeoDataSettingsPatch, reset ...bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	before := g.settingsLocked().AutoUpdate
	g.overrides = overrides
	if len(reset) != 0 && reset[0] {
		g.fileSettings = nil
	}
	after := g.settingsLocked().AutoUpdate
	if !reflect.DeepEqual(before, after) || g.nextCheck.IsZero() && after.Enabled {
		g.rescheduleLocked(time.Now())
	}
}

func (g *geoDataService) rescheduleLocked(now time.Time) {
	g.nextCheck = time.Time{}
	auto := g.settingsLocked().AutoUpdate
	if auto.Enabled {
		base := g.lastChecked
		if base.IsZero() {
			base = now
		}
		wait := time.Duration(auto.IntervalHours) * time.Hour
		if g.lastError != nil {
			wait = min(wait, time.Duration(1<<min(g.failures-1, 6))*5*time.Minute)
		}
		g.nextCheck = base.Add(wait + rand.N(15*time.Minute))
	}
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

func (g *geoDataService) hasGroup(id string) bool {
	active := g.activeGeneration()
	if active == nil || active.controlPlane == nil {
		return false
	}
	generation := nativeActiveGeneration{generation: active, groups: active.controlPlane.OutboundGroups(), conf: active.conf}
	_, exists := generation.findGroup(id)
	return exists
}

func (g *geoDataService) visibleRoute(route nativeapi.GeoDataDownload) nativeapi.GeoDataDownload {
	if route.GroupID != nil && !g.hasGroup(*route.GroupID) {
		route.GroupID = nil
	}
	return route
}

func copyGeoCodes(codes map[string][]string) map[string][]string {
	out := maps.Clone(codes)
	for kind := range out {
		out[kind] = slices.Clone(out[kind])
	}
	return out
}
