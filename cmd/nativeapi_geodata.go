/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/sirupsen/logrus"
)

var geoKinds = []string{"geosite", "geoip"}

type geoDownloadedAsset struct {
	SHA256     string                     `json:"sha256"`
	Size       int64                      `json:"size"`
	Modified   time.Time                  `json:"modified"`
	FetchedURL *string                    `json:"fetched_url"`
	Verified   bool                       `json:"verified"`
	Route      *nativeapi.GeoDataDownload `json:"route"`
}

type geoAssetStat struct {
	info  os.FileInfo
	asset geoDownloadedAsset
}

type geoCandidate struct {
	id         string
	generation *runtimeGeneration
	dir        string
	oldDir     string
	assets     map[string]geoDownloadedAsset
	committed  bool
	durable    bool
}

type geoDataService struct {
	root    string
	log     *logrus.Logger
	ctx     context.Context
	cancel  context.CancelFunc
	wake    chan struct{}
	active  atomic.Pointer[runtimeGeneration]
	resolve geoResolver

	mu           sync.Mutex
	operations   *nativeAPIOperations
	fileSettings *nativeapi.GeoDataSettingsPatch
	overrides    *nativeapi.GeoDataSettingsPatch
	dir          string
	fileCache    map[string]geoAssetStat
	assets       map[string]geoDownloadedAsset
	required     map[string][]string
	inFlight     string
	candidate    *geoCandidate
	lastChecked  time.Time
	lastUpdated  time.Time
	nextCheck    time.Time
	lastError    *nativeapi.SafeError
	failures     int
}

func newGeoDataService(path string, log *logrus.Logger) *geoDataService {
	ctx, cancel := context.WithCancel(context.Background())
	g := &geoDataService{root: path, log: log, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), resolve: net.DefaultResolver.LookupNetIP, fileCache: make(map[string]geoAssetStat, len(geoKinds))}
	if g.log == nil {
		g.log = logrus.New()
	}
	g.dir = g.readCommittedDir()
	g.rescheduleLocked(time.Now())
	return g
}

func (g *geoDataService) activeGeneration() *runtimeGeneration {
	return g.active.Load()
}

func (g *geoDataService) Close() {
	if g == nil {
		return
	}
	g.cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if candidate := g.candidate; candidate != nil && candidate.committed {
		// A shutdown before the reload observer reports success can follow
		// a fatal datapath finalization error. Boot with the prior assets.
		pointer := filepath.Join(g.root, "current")
		var err error
		if candidate.oldDir == "" {
			err = os.Remove(pointer)
		} else {
			err = writeFileAtomic(pointer, []byte(filepath.Base(candidate.oldDir)+"\n"), 0o600)
		}
		if err == nil {
			err = syncGeoDirectory(g.root)
		}
		if err != nil {
			g.log.WithError(err).Warn("Could not restore previously committed geodata assets during shutdown")
			return
		}
		g.dir = candidate.oldDir
		g.candidate = nil
		_ = os.RemoveAll(candidate.dir)
	}
}

func (g *geoDataService) readCommittedDir() string {
	data, err := readGeoSmallFile(filepath.Join(g.root, "current"), 256)
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(string(data))
	if !strings.HasPrefix(name, "assets-") || name != filepath.Base(name) {
		return ""
	}
	dir := filepath.Join(g.root, name)
	for _, kind := range geoKinds {
		info, err := os.Lstat(filepath.Join(dir, kind+".dat"))
		if err != nil || !info.Mode().IsRegular() || info.Size() > geodata.MaxUpdateSize {
			return ""
		}
	}
	return dir
}

func readGeoSmallFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("geodata metadata exceeds its size limit")
	}
	return data, err
}

// AssetDirs returns the committed search path. An empty managed slot leaves
// the original paths in effect.
func (g *geoDataService) AssetDirs(base []string) []string {
	if g == nil {
		return base
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return prependGeoDir(g.dir, base)
}

func prependGeoDir(dir string, base []string) []string {
	if dir == "" {
		return base
	}
	return append([]string{dir}, base...)
}

// ReloadAssetDirs verifies the candidate still belongs to the generation that
// supplied its routing policy and required codes.
func (g *geoDataService) ReloadAssetDirs(operationID string, base []string) ([]string, error) {
	if g == nil {
		return base, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	candidate := g.candidate
	if candidate == nil || candidate.id != operationID {
		return prependGeoDir(g.dir, base), nil
	}
	if candidate.generation != g.activeGeneration() || g.ctx.Err() != nil {
		return nil, errors.New("active generation changed during geodata download")
	}
	if geoEnvironmentOverridesAssets() {
		return nil, errors.New("DAE_LOCATION_ASSET takes precedence over the candidate geodata assets")
	}
	return prependGeoDir(candidate.dir, base), nil
}

func (g *geoDataService) IsGeoDataReload(operationID string) bool {
	if g == nil || operationID == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.candidate != nil && g.candidate.id == operationID
}

// CommitReload is called from the last fallible step of publishing a prepared
// candidate. Until the atomic pointer changes, both old files remain selected.
func (g *geoDataService) CommitReload(operationID string) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	candidate := g.candidate
	if candidate == nil || candidate.id != operationID {
		return nil
	}
	if candidate.generation != g.activeGeneration() || g.ctx.Err() != nil {
		return errors.New("active generation changed before geodata activation")
	}
	if geoEnvironmentOverridesAssets() {
		return errors.New("DAE_LOCATION_ASSET takes precedence over the candidate geodata assets")
	}
	if err := syncGeoDirectory(candidate.dir); err != nil {
		return fmt.Errorf("sync candidate geodata assets: %w", err)
	}
	if err := syncGeoDirectory(g.root); err != nil {
		return fmt.Errorf("sync geodata storage: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(g.root, "current"), []byte(filepath.Base(candidate.dir)+"\n"), 0o600); err != nil {
		return fmt.Errorf("commit geodata assets: %w", err)
	}
	g.dir = candidate.dir
	candidate.committed = true
	if err := syncGeoDirectory(g.root); err != nil {
		g.log.WithError(err).Warn("Geodata storage sync failed after publish; keeping the previous assets on disk")
	} else {
		candidate.durable = true
	}
	return nil
}

func syncGeoDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// Activate captures only the files used by the generation being published.
// The observation endpoint subsequently reads this snapshot without disk I/O.
func (g *geoDataService) Activate(generation *runtimeGeneration, base []string) {
	if g == nil || generation == nil || generation == g.activeGeneration() {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.required = requiredGeoCodes(generation.conf)
	if candidate := g.candidate; candidate != nil && candidate.committed && g.dir == candidate.dir {
		g.assets = candidate.assets
	} else {
		g.assets = g.readLoadedAssets(base)
	}
	g.active.Store(generation)
}

func (g *geoDataService) readLoadedAssets(base []string) map[string]geoDownloadedAsset {
	found := make(map[string]geoDownloadedAsset, len(geoKinds))
	var metadata map[string]geoDownloadedAsset
	if g.dir != "" {
		if data, err := readGeoSmallFile(filepath.Join(g.dir, "metadata.json"), 32<<10); err == nil {
			_ = json.Unmarshal(data, &metadata)
		}
	}
	finder := assets.NewLocationFinder(prependGeoDir(g.dir, base))
	for _, kind := range geoKinds {
		path, err := finder.GetLocationAsset(g.log, kind+".dat")
		if err != nil {
			continue
		}
		asset, err := g.readGeoAsset(kind, path)
		if err != nil {
			continue
		}
		if stored, ok := metadata[kind]; ok && path == filepath.Join(g.dir, kind+".dat") && stored.SHA256 == asset.SHA256 {
			asset.FetchedURL, asset.Verified, asset.Route = stored.FetchedURL, stored.Verified, stored.Route
			if g.lastChecked.IsZero() && stored.FetchedURL != nil && stored.Modified.After(g.lastUpdated) {
				g.lastUpdated = stored.Modified
			}
		}
		found[kind] = asset
	}
	return found
}

func (g *geoDataService) readGeoAsset(kind, path string) (geoDownloadedAsset, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > geodata.MaxUpdateSize {
		return geoDownloadedAsset{}, errors.New("geodata file is unavailable or exceeds its size limit")
	}
	if cached, ok := g.fileCache[kind]; ok && sameGeoAssetStat(cached.info, info) {
		return cached.asset, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return geoDownloadedAsset{}, err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, geodata.MaxUpdateSize+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || size != info.Size() || !sameGeoAssetStat(info, after) {
		return geoDownloadedAsset{}, errors.New("geodata file changed while reading")
	}
	asset := geoDownloadedAsset{SHA256: hex.EncodeToString(hash.Sum(nil)), Size: size, Modified: info.ModTime()}
	g.fileCache[kind] = geoAssetStat{info, asset}
	return asset, nil
}

func sameGeoAssetStat(a, b os.FileInfo) bool {
	aStat, aOK := a.Sys().(*syscall.Stat_t)
	bStat, bOK := b.Sys().(*syscall.Stat_t)
	return aOK && bOK && aStat.Ctim == bStat.Ctim && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func requiredGeoCodes(conf *config.Config) map[string][]string {
	codes := map[string][]string{"geosite": {}, "geoip": {}}
	if conf == nil {
		return codes
	}
	for _, rules := range [][]*config_parser.RoutingRule{conf.Routing.Rules, conf.Dns.Routing.Request.Rules, conf.Dns.Routing.Response.Rules} {
		for _, rule := range rules {
			for _, fn := range rule.AndFunctions {
				for _, param := range fn.Params {
					kind, value := param.Key, param.Val
					if kind == "ext" {
						file, code, ok := strings.Cut(value, ":")
						if !ok {
							continue
						}
						kind, value = strings.TrimSuffix(file, ".dat"), code
						supported := (kind == "geosite" && (fn.Name == consts.Function_Domain || fn.Name == consts.Function_QName)) ||
							(kind == "geoip" && fn.Name == consts.Function_Ip)
						if !supported {
							continue
						}
					}
					if _, ok := codes[kind]; ok {
						if kind == "geosite" {
							value, _, _ = strings.Cut(value, "@")
						}
						if value != "" {
							codes[kind] = append(codes[kind], strings.ToLower(value))
						}
					}
				}
			}
		}
	}
	for kind := range codes {
		slices.Sort(codes[kind])
		codes[kind] = slices.Compact(codes[kind])
	}
	return codes
}

func (g *geoDataService) GeoData(ctx context.Context) (nativeapi.GeoData, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.GeoData{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.snapshotLocked(), nil
}

func (g *geoDataService) snapshotLocked() nativeapi.GeoData {
	settings := g.settingsLocked()
	secret := ""
	if active := g.activeGeneration(); active != nil && active.conf != nil {
		secret = active.conf.Api.Secret
	}
	result := nativeapi.GeoData{
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		Assets:     make([]nativeapi.GeoAsset, 0, len(g.assets)),
		GeoDataUpdateStatus: &nativeapi.GeoDataUpdateStatus{
			LastCheckedAt: formatTime(g.lastChecked), LastUpdatedAt: formatTime(g.lastUpdated),
			NextCheckAt: formatTime(g.nextCheck), LastError: g.lastError, RequiredCodes: copyGeoCodes(g.required),
		},
	}
	for _, kind := range geoKinds {
		asset, ok := g.assets[kind]
		if !ok {
			continue
		}
		urls := settings.GeoIP.URLs
		if kind == "geosite" {
			urls = settings.Geosite.URLs
		}
		var route *nativeapi.GeoDataDownload
		if asset.Route != nil {
			route = new(g.visibleRoute(*asset.Route))
		}
		result.Assets = append(result.Assets, nativeapi.GeoAsset{
			Kind: kind, SHA256: asset.SHA256, SizeBytes: strconv.FormatInt(asset.Size, 10),
			ModifiedAt: formatTime(asset.Modified), SourceRedacted: maskGeoDisplaySecret(geoDisplayURL(urls[0]), secret),
			GeoAssetDownload: &nativeapi.GeoAssetDownload{FetchedURLRedacted: maskGeoDisplaySecret(asset.FetchedURL, secret), Verified: asset.Verified, DownloadRoute: route},
		})
	}
	return result
}

func maskGeoDisplaySecret(display *string, secret string) *string {
	if display == nil || secret == "" {
		return display
	}
	const replacement = "[redacted]"
	return new(strings.NewReplacer(secret, replacement, url.PathEscape(secret), replacement, url.QueryEscape(secret), replacement).Replace(*display))
}

func geoEnvironmentOverridesAssets() bool {
	dir := os.Getenv("DAE_LOCATION_ASSET")
	if dir == "" {
		return false
	}
	for _, kind := range geoKinds {
		if _, err := os.Stat(filepath.Join(dir, kind+".dat")); !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func (g *geoDataService) stageUpdate(ctx context.Context, id string) (*geoCandidate, error) {
	g.mu.Lock()
	active, settings, required := g.activeGeneration(), g.settingsLocked(), copyGeoCodes(g.required)
	loaded, oldDir := maps.Clone(g.assets), g.dir
	g.mu.Unlock()
	if active == nil || active.controlPlane == nil {
		return nil, &geoUpdateError{"state_conflict", "The active geodata download route is unavailable."}
	}
	if geoEnvironmentOverridesAssets() {
		return nil, &geoUpdateError{"state_conflict", "DAE_LOCATION_ASSET takes precedence over the managed geodata assets."}
	}
	if err := os.MkdirAll(g.root, 0o700); err != nil {
		return nil, &geoUpdateError{"storage_failed", "Geodata update storage is unavailable."}
	}
	dir, err := os.MkdirTemp(g.root, "assets-")
	if err != nil {
		return nil, &geoUpdateError{"storage_failed", "Geodata update storage is unavailable."}
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	candidate := &geoCandidate{id: id, generation: active, dir: dir, oldDir: oldDir, assets: make(map[string]geoDownloadedAsset, len(geoKinds))}
	selectRoute := func(host string, dest netip.AddrPort) (geoDialTarget, error) {
		return selectGeoDialTarget(active, settings.Download, host, dest)
	}
	changed := false
	for _, kind := range geoKinds {
		urls := settings.GeoIP.URLs
		if kind == "geosite" {
			urls = settings.Geosite.URLs
		}
		asset, err := fetchGeoAsset(ctx, g.log, dir, kind, urls, settings.VerifyChecksum, required[kind], g.resolve, selectRoute)
		if err != nil {
			return nil, err
		}
		if prev, ok := loaded[kind]; ok && prev.SHA256 == asset.SHA256 {
			if err := os.Chtimes(filepath.Join(dir, kind+".dat"), prev.Modified, prev.Modified); err != nil {
				return nil, &geoUpdateError{"storage_failed", "Geodata update storage is unavailable."}
			}
			asset = prev
		} else {
			changed = true
		}
		if active.conf != nil {
			asset.FetchedURL = maskGeoDisplaySecret(asset.FetchedURL, active.conf.Api.Secret)
		}
		candidate.assets[kind] = asset
	}
	if g.activeGeneration() != active {
		return nil, &geoUpdateError{"state_conflict", "The active generation changed during the geodata download."}
	}
	if !changed {
		return nil, nil
	}
	data, err := json.Marshal(candidate.assets)
	if err == nil {
		err = writeFileAtomic(filepath.Join(dir, "metadata.json"), data, 0o600)
	}
	if err != nil {
		return nil, &geoUpdateError{"storage_failed", "Geodata update metadata could not be stored."}
	}
	keep = true
	return candidate, nil
}

var _ nativeapi.GeoDataProvider = (*geoDataService)(nil)
var _ nativeapi.GeoDataUpdateProvider = (*geoDataService)(nil)
var _ nativeapi.GeoDataSettingsProvider = (*geoDataService)(nil)
