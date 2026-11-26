/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type geoTestDialer struct {
	mu       sync.Mutex
	requests []string
	handle   func(*http.Request) (int, []byte)
}

func (d *geoTestDialer) DialContext(ctx context.Context, _, addr string) (netproxy.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		d.mu.Lock()
		d.requests = append(d.requests, addr+" "+request.Host+request.URL.RequestURI())
		d.mu.Unlock()
		status, data := d.handle(request)
		_, _ = fmt.Fprintf(server, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nLocation: http://127.0.0.1/\r\nConnection: close\r\n\r\n", status, http.StatusText(status), len(data))
		_, _ = server.Write(data)
	}()
	return client, nil
}

func TestGeoDataDownloadFallbackAndChecksumRoute(t *testing.T) {
	payload, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{CountryCode: "cn"}}})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &geoTestDialer{handle: func(request *http.Request) (int, []byte) {
		switch request.URL.Path {
		case "/redirect":
			return 302, nil
		case "/mismatch", "/good":
			return 200, payload
		case "/mismatch.sha256sum":
			return 200, []byte("bad digest")
		case "/good.sha256sum":
			return 200, []byte(fmt.Sprintf("%x  geosite.dat\n", sha256.Sum256(payload)))
		default:
			return 500, nil
		}
	}}
	resolutions, selections := 0, 0
	resolve := func(context.Context, string, string) ([]netip.Addr, error) {
		resolutions++
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	selectRoute := func(host string, dest netip.AddrPort) (geoDialTarget, error) {
		selections++
		return geoDialTarget{dialer: dialer, address: dest.String(), route: nativeapi.GeoDataDownload{Route: "group", GroupID: new("group-test")}}, nil
	}
	dir := t.TempDir()
	asset, err := fetchGeoAsset(t.Context(), nil, dir, "geosite", []string{"http://example.org/redirect", "http://example.org/mismatch", "http://example.org/good?secret=value"}, true, []string{"cn"}, resolve, selectRoute)
	if err != nil || !asset.Verified || asset.FetchedURL == nil || *asset.FetchedURL != "http://example.org/good" || asset.Route == nil || asset.Route.GroupID == nil || *asset.Route.GroupID != "group-test" {
		t.Fatalf("fetchGeoAsset() = %+v, %v", asset, err)
	}
	want := []string{"1.1.1.1:80 example.org/redirect", "1.1.1.1:80 example.org/mismatch", "1.1.1.1:80 example.org/mismatch.sha256sum", "1.1.1.1:80 example.org/good?secret=value", "1.1.1.1:80 example.org/good.sha256sum?secret=value"}
	if !slices.Equal(dialer.requests, want) || resolutions != 3 || selections != 3 {
		t.Fatalf("requests = %v, resolutions = %d, selections = %d", dialer.requests, resolutions, selections)
	}
	if _, err := os.Stat(filepath.Join(dir, "geosite.dat")); err != nil {
		t.Fatal(err)
	}
}

func TestGeoDataDownloadBlocksPrivateAndMixedDNSAnswers(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1/x", "http://[::ffff:169.254.169.254]/x", "http://[64:ff9b::a00:1]/x", "https://mirror.example/x"} {
		t.Run(raw, func(t *testing.T) {
			resolve := func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}, nil
			}
			_, err := fetchGeoURL(t.Context(), t.TempDir(), "geoip", raw, false, nil, resolve, func(string, netip.AddrPort) (geoDialTarget, error) {
				t.Error("unsafe address reached route selection")
				return geoDialTarget{}, nil
			})
			if err == nil {
				t.Fatal("unsafe address accepted")
			}
		})
	}
}

func TestGeoDataSettingsLifecycle(t *testing.T) {
	g := newGeoDataService(t.TempDir(), nil)
	defer g.Close()
	file := &nativeapi.GeoDataSettingsPatch{GeoIP: &nativeapi.GeoDataSources{URLs: []string{"https://file.example/geoip.dat"}}}
	stored := &nativeapi.GeoDataSettingsPatch{GeoIP: &nativeapi.GeoDataSources{URLs: []string{"https://stored.example/geoip.dat"}}, VerifyChecksum: new(false)}
	merged, err := g.TakeFileSettings(file, stored)
	if err != nil || merged.GeoIP != nil || merged.VerifyChecksum == nil || g.Settings().Source != "config" {
		t.Fatalf("TakeFileSettings() = %+v, %v", merged, err)
	}
	patch := &nativeapi.GeoDataSettingsPatch{Geosite: &nativeapi.GeoDataSources{URLs: []string{"https://override.example/geosite.dat"}}, AutoUpdate: &nativeapi.GeoDataAutoUpdatePatch{Enabled: new(true)}}
	merged, err = g.MergeSettings(merged, patch, false)
	if err != nil || g.Settings().Source != "config" || !g.nextCheck.IsZero() {
		t.Fatalf("MergeSettings() = %+v, %v", merged, err)
	}
	g.ApplySettings(merged)
	if got := g.Settings(); got.Source != "override" || got.VerifyChecksum || !got.AutoUpdate.Enabled || !slices.Equal(got.GeoIP.URLs, file.GeoIP.URLs) {
		t.Fatalf("Settings() = %+v", got)
	}
	if delay := time.Until(g.nextCheck); delay < 23*time.Hour || delay > 25*time.Hour {
		t.Fatalf("initial schedule delay = %v", delay)
	}
	missingGroup := &nativeapi.GeoDataSettingsPatch{Download: &nativeapi.GeoDataDownload{Route: "group", GroupID: new("missing")}}
	if _, err := g.MergeSettings(merged, missingGroup, false); err == nil {
		t.Fatal("missing group accepted")
	}
	g.ApplySettings(nil, true)
	if got := g.Settings(); got.Source != "default" || !got.VerifyChecksum || got.AutoUpdate.Enabled || !g.nextCheck.IsZero() {
		t.Fatalf("reset Settings() = %+v", got)
	}
}

func TestGeoDataCandidateCommitAndRejection(t *testing.T) {
	t.Setenv("DAE_LOCATION_ASSET", "")
	root := t.TempDir()
	g := newGeoDataService(root, nil)
	defer g.Close()
	base := []string{"/package"}
	first := &runtimeGeneration{id: "first"}
	supervisor := newRuntimeSupervisor(first)
	supervisor.onActivate = func(generation *runtimeGeneration) { g.Activate(generation, base) }
	g.Activate(first, base)
	oldDir := filepath.Join(root, "assets-old")
	if err := os.Mkdir(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, kind := range geoKinds {
		if err := os.WriteFile(filepath.Join(oldDir, kind+".dat"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g.dir = oldDir
	if err := os.Mkdir(filepath.Join(root, "assets-new"), 0o700); err != nil {
		t.Fatal(err)
	}
	g.inFlight = "op"
	g.operations = newNativeAPIOperations(nil, nil)
	g.candidate = &geoCandidate{id: "op", generation: g.activeGeneration(), dir: filepath.Join(root, "assets-new"), oldDir: oldDir}
	if got, err := g.ReloadAssetDirs("op", base); err != nil || !reflect.DeepEqual(got, []string{g.candidate.dir, base[0]}) {
		t.Fatalf("ReloadAssetDirs = %q, %v", got, err)
	}
	if got := g.AssetDirs(base); !slices.Equal(got, []string{oldDir, base[0]}) {
		t.Fatalf("candidate leaked before commit: %q", got)
	}
	if err := os.Mkdir(filepath.Join(root, "current"), 0o700); err != nil {
		t.Fatal(err)
	}
	next := &runtimeGeneration{id: "second"}
	if err := supervisor.installPrepared(next); err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.publishPreparedWithCommit(next, func() error { return g.CommitReload("op") }); err == nil || supervisor.activeSnapshot() != first || g.dir != oldDir || g.candidate.committed {
		t.Fatalf("commit error did not preserve the active files and generation: %v", err)
	}
	supervisor.rollbackPrepared(next)
	g.finishReload("op", false)
	if g.lastError == nil || g.lastError.Code != "activation_failed" || g.dir != oldDir || g.candidate != nil {
		t.Fatal("failure did not preserve the active files and clear the candidate")
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	newDir := filepath.Join(root, "assets-new")
	if err := os.Mkdir(newDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, kind := range geoKinds {
		if err := os.WriteFile(filepath.Join(newDir, kind+".dat"), []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g.candidate = &geoCandidate{id: "new", generation: g.activeGeneration(), dir: newDir, oldDir: oldDir}
	if err := supervisor.installPrepared(next); err != nil {
		t.Fatal(err)
	}
	if previous, err := supervisor.publishPreparedWithCommit(next, func() error { return g.CommitReload("new") }); err != nil || previous != first || supervisor.activeSnapshot() != next || g.readCommittedDir() != newDir {
		t.Fatalf("commit did not publish the new asset directory and generation: %v", err)
	}
	g.Close()
	if got := g.readCommittedDir(); got != oldDir {
		t.Fatalf("shutdown before reload completion restored %q, want %q", got, oldDir)
	}
}

func TestGeoDataRequiredCodesAndRedaction(t *testing.T) {
	conf := &config.Config{}
	conf.Routing.Rules = []*config_parser.RoutingRule{{AndFunctions: []*config_parser.Function{{Name: "domain", Params: []*config_parser.Param{{Key: "geosite", Val: "CN@ADS"}, {Key: "ext", Val: "geosite.dat:PRIVATE"}, {Key: "ext", Val: "custom.dat:other"}}}}}}
	conf.Dns.Routing.Response.Rules = []*config_parser.RoutingRule{{AndFunctions: []*config_parser.Function{{Name: "ip", Params: []*config_parser.Param{{Key: "geoip", Val: "US"}, {Key: "geoip", Val: "us"}}}}}}
	if got := requiredGeoCodes(conf); !reflect.DeepEqual(got, map[string][]string{"geosite": {"cn", "private"}, "geoip": {"us"}}) {
		t.Fatalf("requiredGeoCodes() = %v", got)
	}
	raw := "https://example.com:8443/API_KEY/hidden/a=b/12345678-abcd-1234-abcd-123456789abc/abcd/path?secret=value"
	if got := geoDisplayURL(raw); got == nil || *got != "https://example.com:8443/API_KEY/[redacted]/[redacted]/[redacted]/abcd/path" {
		t.Fatalf("geoDisplayURL() = %v", got)
	}
}

func BenchmarkGeoDataLoadedAssetDigest(b *testing.B) {
	file := filepath.Join(b.TempDir(), "geoip.dat")
	if err := os.WriteFile(file, []byte(strings.Repeat("x", 16<<20)), 0o600); err != nil {
		b.Fatal(err)
	}
	g := newGeoDataService(b.TempDir(), nil)
	defer g.Close()
	for _, mode := range []string{"cold", "cached"} {
		b.Run(mode, func(b *testing.B) {
			for b.Loop() {
				if mode == "cold" {
					clear(g.fileCache)
				}
				if _, err := g.readGeoAsset("geoip", file); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestGeoDataOperationReplayAndExclusivity(t *testing.T) {
	g := newGeoDataService(t.TempDir(), nil)
	defer g.Close()
	manager := newReloadManager(make(chan reloadRequest, 1), nil, nil)
	operations := newNativeAPIOperations(manager, nil)
	g.AttachOperations(operations)
	original, _, err := operations.store.Accept(geoUpdateKind, "manual", "pending")
	if err != nil {
		t.Fatal(err)
	}
	operations.store.CommitReplayKey("pending")
	g.mu.Lock()
	g.inFlight = original.OperationID
	g.mu.Unlock()
	if replay, err := g.StartGeoDataUpdate(t.Context(), "manual", "pending"); err != nil || replay != original {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	_, err = g.StartGeoDataUpdate(t.Context(), "manual", "distinct")
	var apiErr *nativeapi.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Fatalf("concurrent admission = %v", err)
	}
	g.finishUpdate(original.OperationID, false, errors.New("fixture finished"))
	accepted, err := g.StartGeoDataUpdate(t.Context(), "manual", "distinct")
	if err != nil || accepted.Kind != geoUpdateKind || accepted.Status != "queued" {
		t.Fatalf("accepted = %+v, %v", accepted, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		operation, ok, err := operations.GetOperation(t.Context(), accepted.OperationID)
		if err == nil && ok && operation.Status == "failed" {
			if operation.Error == nil || operation.Error.Code != "state_conflict" {
				t.Fatalf("failed operation = %+v", operation)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("operation did not record the unreachable active route")
}

func TestGeoDataScheduleUsesSharedOperationAdmission(t *testing.T) {
	g := newGeoDataService(t.TempDir(), nil)
	defer g.Close()
	operations := newNativeAPIOperations(newReloadManager(make(chan reloadRequest, 1), nil, nil), nil)
	g.mu.Lock()
	g.overrides = &nativeapi.GeoDataSettingsPatch{AutoUpdate: &nativeapi.GeoDataAutoUpdatePatch{Enabled: new(true)}}
	g.nextCheck = time.Now().Add(-time.Second)
	g.mu.Unlock()
	g.AttachOperations(operations)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		result, err := g.GeoData(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if result.LastCheckedAt != nil {
			if result.LastError == nil || result.LastError.Code != "state_conflict" || result.NextCheckAt == nil {
				t.Fatalf("automatic outcome = %+v", result.GeoDataUpdateStatus)
			}
			g.mu.Lock()
			delay := g.nextCheck.Sub(g.lastChecked)
			g.mu.Unlock()
			if delay < 5*time.Minute || delay > 20*time.Minute {
				t.Fatalf("failure backoff = %v", delay)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("automatic operation did not report an outcome")
}

func TestGeoDataEnvironmentAssetPrecedence(t *testing.T) {
	envDir := t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", envDir)
	g := newGeoDataService(t.TempDir(), nil)
	defer g.Close()
	active := &runtimeGeneration{id: "active"}
	g.dir = t.TempDir()
	managedFile := filepath.Join(g.dir, "geoip.dat")
	if err := os.WriteFile(managedFile, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.Activate(active, nil)
	g.candidate = &geoCandidate{id: "op", generation: active, dir: t.TempDir()}
	if _, err := g.ReloadAssetDirs("op", nil); err != nil {
		t.Fatalf("empty environment directory rejected operation: %v", err)
	}
	if err := os.WriteFile(filepath.Join(envDir, "geoip.dat"), []byte("environment"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := g.ReloadAssetDirs("op", nil); err == nil {
		t.Fatal("candidate treated as loaded despite the environment asset")
	}
	if err := g.CommitReload("op"); err == nil {
		t.Fatal("candidate committed despite the environment asset")
	}
	g.Activate(&runtimeGeneration{id: "next"}, nil)
	if got, want := g.assets["geoip"].SHA256, fmt.Sprintf("%x", sha256.Sum256([]byte("environment"))); got != want {
		t.Fatalf("observed digest = %q, want environment asset %q", got, want)
	}
}

type geoLoopbackDialer struct {
	endpoint       string
	datapathTarget chan string
}

func (d geoLoopbackDialer) DialContext(ctx context.Context, _, addr string) (netproxy.Conn, error) {
	d.datapathTarget <- addr
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.endpoint)
}

func TestGeoDataDownloadOverTCP(t *testing.T) {
	payload, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{{CountryCode: "cn"}}})
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- request.Host + request.URL.RequestURI()
		if request.URL.Path != "/geoip.dat" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	targets := make(chan string, 2)
	dialer := geoLoopbackDialer{endpoint: server.Listener.Addr().String(), datapathTarget: targets}
	asset, err := fetchGeoURL(t.Context(), t.TempDir(), "geoip", "http://1.1.1.1:8080/geoip.dat?mirror=one", true, []string{"cn"}, nil,
		func(host string, addr netip.AddrPort) (geoDialTarget, error) {
			return geoDialTarget{dialer: dialer, address: addr.String(), route: nativeapi.GeoDataDownload{Route: "routing"}}, nil
		})
	if err != nil || asset.Verified || asset.Route == nil || asset.Route.Route != "routing" {
		t.Fatalf("download with a missing checksum = %+v, %v", asset, err)
	}
	for _, want := range []string{"1.1.1.1:8080/geoip.dat?mirror=one", "1.1.1.1:8080/geoip.dat.sha256sum?mirror=one"} {
		select {
		case got := <-requests:
			if got != want {
				t.Fatalf("request = %q, want %q", got, want)
			}
		default:
			t.Fatalf("missing request %q", want)
		}
		select {
		case got := <-targets:
			if got != "1.1.1.1:8080" {
				t.Fatalf("dial target = %q", got)
			}
		default:
			t.Fatal("missing dial target")
		}
	}
}

type geoFailDialer struct{ called chan<- string }

func (d geoFailDialer) DialContext(_ context.Context, _, addr string) (netproxy.Conn, error) {
	if d.called != nil {
		d.called <- addr
	}
	return nil, errors.New("unreachable proxy")
}

func TestGeoDataDownloadDoesNotSwitchFromGroupToDirect(t *testing.T) {
	directDials := make(chan string, 1)
	resolve := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}, nil
	}
	_, err := fetchGeoURL(t.Context(), t.TempDir(), "geoip", "http://example.org/geoip.dat", false, nil, resolve,
		func(_ string, dest netip.AddrPort) (geoDialTarget, error) {
			target := geoDialTarget{dialer: geoFailDialer{}, address: dest.String(), route: nativeapi.GeoDataDownload{Route: "routing"}}
			if dest.Addr().String() == "1.1.1.1" {
				target.route.GroupID = new("proxy")
			} else {
				target.dialer = geoFailDialer{called: directDials}
			}
			return target, nil
		})
	if err == nil {
		t.Fatal("group connection failure did not fail the download")
	}
	select {
	case addr := <-directDials:
		t.Fatalf("group failure fell back to direct at %s", addr)
	default:
	}
}

// geoHangingDialer never completes a connection; it returns when the caller
// gives up, like an address that is silently unreachable.
type geoHangingDialer struct{}

func (geoHangingDialer) DialContext(ctx context.Context, _, _ string) (netproxy.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// The first resolved address must not consume the whole per-URL deadline:
// once geoDialTimeout passes, the next address is tried.
func TestGeoDataDownloadSkipsAddressThatCannotConnect(t *testing.T) {
	previous := geoDialTimeout
	geoDialTimeout = 150 * time.Millisecond
	t.Cleanup(func() { geoDialTimeout = previous })
	payload, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{{CountryCode: "cn"}}})
	if err != nil {
		t.Fatal(err)
	}
	serving := &geoTestDialer{handle: func(*http.Request) (int, []byte) { return 200, payload }}
	resolve := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.1.1.2")}, nil
	}
	started := time.Now()
	asset, err := fetchGeoURL(t.Context(), t.TempDir(), "geoip", "http://example.org/geoip.dat", false, nil, resolve,
		func(_ string, addr netip.AddrPort) (geoDialTarget, error) {
			d := netproxy.Dialer(serving)
			if addr.Addr() == netip.MustParseAddr("1.1.1.1") {
				d = geoHangingDialer{}
			}
			return geoDialTarget{dialer: d, address: addr.String()}, nil
		})
	if err != nil || asset.SHA256 == "" {
		t.Fatalf("fetchGeoURL() = %+v, %v", asset, err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("unreachable address cost %s", elapsed)
	}
	if got, want := fmt.Sprint(serving.requests), "[1.1.1.2:80 example.org/geoip.dat]"; got != want {
		t.Fatalf("requests = %s, want %s", got, want)
	}
}

type geoFakeDialTargetChooser struct {
	calls    int
	dialMode string
}

func (c *geoFakeDialTargetChooser) DialTargetForResolvedDomain(consts.OutboundIndex, netip.AddrPort, string) string {
	c.calls++
	return c.dialMode
}

// A proxy member gets the datapath's dial target; a direct member and a
// missing host keep the vetted numeric destination.
func TestGeoProxyDialAddressKeepsVettedDestinationForDirectMembers(t *testing.T) {
	dest := netip.MustParseAddrPort("185.199.108.133:443")
	index := consts.OutboundUserDefinedMin + 1
	for _, tt := range []struct {
		name, member, host, dialMode, want string
		wantCalls                          int
	}{
		{name: "proxy member dials by domain", member: "tokyo", host: "raw.githubusercontent.com", dialMode: "raw.githubusercontent.com:443", want: "raw.githubusercontent.com:443", wantCalls: 1},
		{name: "proxy member under ip dial mode", member: "tokyo", host: "raw.githubusercontent.com", dialMode: "185.199.108.133:443", want: "185.199.108.133:443", wantCalls: 1},
		{name: "direct member never resolves again", member: "direct", host: "raw.githubusercontent.com", dialMode: "raw.githubusercontent.com:443", want: "185.199.108.133:443"},
		{name: "ip literal URL", member: "tokyo", host: "", dialMode: "raw.githubusercontent.com:443", want: "185.199.108.133:443"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			chooser := &geoFakeDialTargetChooser{dialMode: tt.dialMode}
			if got := geoProxyDialAddress(chooser, index, dest, tt.host, tt.member); got != tt.want || chooser.calls != tt.wantCalls {
				t.Fatalf("dial address = %q after %d calls, want %q after %d", got, chooser.calls, tt.want, tt.wantCalls)
			}
		})
	}
}

// The operation error stays generic; the log carries the reason of every
// attempt and never the query string of the URL.
func TestGeoDataDownloadLogsAttemptReasonsWithoutCredentials(t *testing.T) {
	var logBuffer bytes.Buffer
	log := logrus.New()
	log.Out = &logBuffer
	dialer := &geoTestDialer{handle: func(request *http.Request) (int, []byte) {
		if request.URL.Path == "/redirect" {
			return 302, nil
		}
		return 200, []byte("not geodata")
	}}
	_, err := fetchGeoAsset(t.Context(), log, t.TempDir(), "geosite", []string{"http://user:pw@127.0.0.1/x", "http://example.org/redirect?token=abc123", "http://example.org/invalid?token=abc123"}, false, nil,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		},
		func(_ string, addr netip.AddrPort) (geoDialTarget, error) {
			return geoDialTarget{dialer: dialer, address: addr.String()}, nil
		})
	var updateErr *geoUpdateError
	if !errors.As(err, &updateErr) || updateErr.code != "validation_failed" {
		t.Fatalf("fetchGeoAsset() = %v, want validation_failed", err)
	}
	logged := logBuffer.String()
	for _, want := range []string{"http status 302", "validation:", `url="http://example.org/redirect"`} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log lacks %q:\n%s", want, logged)
		}
	}
	for _, secret := range []string{"token=abc123", "user:pw"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("log leaks %q:\n%s", secret, logged)
		}
	}
}

// geoStallingDialer sends the headers and a few bytes, then never delivers
// the rest of the body.
type geoStallingDialer struct{}

func (geoStallingDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			return
		}
		_, _ = fmt.Fprint(server, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n"+strings.Repeat("x", 10))
		// Hold the body open until the client gives up and closes its side.
		_, _ = io.Copy(io.Discard, server)
	}()
	return client, nil
}

// A transfer that stops delivering is given up after geoStallTimeout, long
// before the per-URL deadline, and the partial file is not kept.
func TestGeoDataDownloadGivesUpOnStalledTransfer(t *testing.T) {
	previous := geoStallTimeout
	geoStallTimeout = 200 * time.Millisecond
	t.Cleanup(func() { geoStallTimeout = previous })
	dir := t.TempDir()
	resolve := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	started := time.Now()
	_, err := fetchGeoURL(t.Context(), dir, "geoip", "http://example.org/geoip.dat", false, nil, resolve,
		func(_ string, addr netip.AddrPort) (geoDialTarget, error) {
			return geoDialTarget{dialer: geoStallingDialer{}, address: addr.String()}, nil
		})
	if !errors.Is(err, errGeoStalled) {
		t.Fatalf("fetchGeoURL() = %v, want a stalled transfer", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("stalled transfer cost %s", elapsed)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "geoip.dat")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial file kept: %v", statErr)
	}
}
