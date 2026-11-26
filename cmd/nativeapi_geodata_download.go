/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

// geoURLTimeout caps one URL as a whole. It is generous because a mirror
// reached through a slow proxy may need many minutes for the larger asset.
const geoURLTimeout = 30 * time.Minute

// geoUpdateTimeout bounds one update operation: both assets, each allowed its
// own geoURLTimeout, with time for validation and publication.
const geoUpdateTimeout = 2*geoURLTimeout + 5*time.Minute

// geoStallTimeout is how long a transfer may deliver no data before the URL
// is given up. Progress, not a fixed total, decides whether a slow link fails.
var geoStallTimeout = 30 * time.Second

// geoDialTimeout bounds one connection attempt. Without it the first
// unreachable address would consume the whole per-URL deadline and the
// remaining addresses would never be tried.
var geoDialTimeout = consts.DefaultDialTimeout

var geoSpecialAddresses = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var geoGlobalIPv6 = netip.MustParsePrefix("2000::/3")

func geoPublicAddress(address netip.Addr) bool {
	if address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.Is6() && !geoGlobalIPv6.Contains(address) {
		return false
	}
	for _, prefix := range geoSpecialAddresses {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func parseGeoURL(raw string) (*url.URL, error) {
	if len(raw) > 4096 || strings.Contains(raw, "#") || !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://") {
		return nil, errors.New("geodata URL must be an absolute HTTP(S) URL without a fragment")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || strings.HasSuffix(parsed.Host, ":") {
		return nil, errors.New("invalid geodata URL")
	}
	if host := parsed.Hostname(); strings.Contains(host, "%") || strings.ContainsAny(host, " /\\") {
		return nil, errors.New("invalid geodata URL host")
	}
	if port := parsed.Port(); port != "" {
		if value, err := strconv.ParseUint(port, 10, 16); err != nil || value == 0 {
			return nil, errors.New("invalid geodata URL port")
		}
	}
	return parsed, nil
}

var geoCredentialSegment = regexp.MustCompile(`(?i)^(access_key|access_token|api_key|apikey|auth|auth_token|client_secret|credential|key|password|private_token|secret|sig|signature|token)$`)
var geoHexSegment = regexp.MustCompile(`(?i)^(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[0-9a-f]{32})$`)
var geoTokenSegment = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,}$`)

var geoLowerHex = regexp.MustCompile(`^[0-9a-f]+$`)

func geoDisplayURL(raw string) *string {
	parsed, err := parseGeoURL(raw)
	if err != nil {
		return nil
	}
	parts := strings.Split(parsed.EscapedPath(), "/")
	redactNext := false
	for i, part := range parts {
		if redactNext || strings.ContainsAny(part, ":=") || geoHexSegment.MatchString(part) || geoTokenLike(part) {
			parts[i] = "[redacted]"
		}
		redactNext = geoCredentialSegment.MatchString(part)
	}
	return stringPointer(parsed.Scheme + "://" + parsed.Host + strings.Join(parts, "/"))
}

func geoTokenLike(part string) bool {
	if !geoTokenSegment.MatchString(part) {
		return false
	}
	if len(part) >= 32 && !strings.Contains(part, "-") && !geoLowerHex.MatchString(part) {
		return true
	}
	return strings.ContainsAny(part, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
		strings.ContainsAny(part, "abcdefghijklmnopqrstuvwxyz") && strings.ContainsAny(part, "0123456789")
}

type geoDialTarget struct {
	dialer  netproxy.Dialer
	network string
	address string
	route   nativeapi.GeoDataDownload
}

// selectGeoDialTarget applies the active routing policy to the original host
// and vetted IP. A direct dialer only ever receives the vetted numeric
// destination. A proxy dialer receives the dial target forwarded traffic
// would get, so the remote side resolves the host with its own address-family
// reachability; an IP-only target would hang on a node without IPv6 egress.
func selectGeoDialTarget(active *runtimeGeneration, route nativeapi.GeoDataDownload, host string, dest netip.AddrPort) (geoDialTarget, error) {
	if active == nil || active.controlPlane == nil {
		return geoDialTarget{}, errors.New("geodata download route is unavailable")
	}
	plane := active.controlPlane
	groups := plane.OutboundGroups()
	index := consts.OutboundDirect
	mark := plane.SoMarkFromDae()
	result := geoDialTarget{route: nativeapi.GeoDataDownload{Route: route.Route}, address: dest.String()}
	switch route.Route {
	case "routing":
		source := netip.IPv4Unspecified()
		if dest.Addr().Is6() {
			source = netip.IPv6Unspecified()
		}
		chosen, routeMark, _, err := plane.Route(netip.AddrPortFrom(source, 0), dest, host, consts.L4ProtoType_TCP, nil)
		if err != nil {
			return geoDialTarget{}, err
		}
		index = chosen
		if routeMark != 0 {
			mark = routeMark
		}
	case "group":
		index = consts.OutboundBlock
		for i, group := range groups {
			if i >= int(consts.OutboundUserDefinedMin) && group != nil && route.GroupID != nil && groupIDOf(group.Name) == *route.GroupID {
				index = consts.OutboundIndex(i)
				break
			}
		}
	case "direct":
	default:
		return geoDialTarget{}, errors.New("invalid geodata download route")
	}
	mptcp := active.conf != nil && active.conf.Global.Mptcp
	result.network = common.MagicNetwork("tcp", common.EffectiveSoMarkFromDae(mark), mptcp)
	if index == consts.OutboundDirect {
		result.dialer = plane.DirectDialer()
	} else if index >= consts.OutboundUserDefinedMin && int(index) < len(groups) && groups[index] != nil {
		group := groups[index]
		network := &dialer.NetworkType{L4Proto: consts.L4ProtoStr("tcp"), IpVersion: consts.IpVersionFromAddr(dest.Addr())}
		selected, _, err := group.Select(network, true)
		if err != nil || selected == nil {
			return geoDialTarget{}, errors.New("no usable geodata download group member")
		}
		result.dialer = selected
		result.route.GroupID = stringPointer(groupIDOf(group.Name))
		name := ""
		if property := selected.Property(); property != nil {
			name = property.Name
		}
		result.address = geoProxyDialAddress(plane, index, dest, host, name)
	}
	if result.dialer == nil {
		return geoDialTarget{}, errors.New("geodata download route is blocked or unavailable")
	}
	return result, nil
}

// geoDialTargetChooser applies the datapath's dial mode to a host the caller
// has resolved itself.
type geoDialTargetChooser interface {
	DialTargetForResolvedDomain(outbound consts.OutboundIndex, dst netip.AddrPort, domain string) string
}

// geoProxyDialAddress is what a selected proxy dialer receives. The vetted
// numeric destination stays for a direct member, which would otherwise resolve
// the host again outside the address checks.
func geoProxyDialAddress(plane geoDialTargetChooser, index consts.OutboundIndex, dest netip.AddrPort, host, member string) string {
	if member == "direct" || host == "" {
		return dest.String()
	}
	return plane.DialTargetForResolvedDomain(index, dest, host)
}

type geoResolver func(context.Context, string, string) ([]netip.Addr, error)
type geoRouteSelector func(string, netip.AddrPort) (geoDialTarget, error)

func geoTargets(ctx context.Context, parsed *url.URL, resolve geoResolver) ([]netip.AddrPort, error) {
	if resolve == nil {
		resolve = net.DefaultResolver.LookupNetIP
	}
	host := parsed.Hostname()
	addresses := make([]netip.Addr, 0, 1)
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = append(addresses, literal)
	} else {
		addresses, err = resolve(ctx, "ip", strings.TrimSuffix(host, ".")+".")
		if err != nil {
			return nil, fmt.Errorf("host resolution: %w", err)
		}
	}
	if len(addresses) == 0 || len(addresses) > 16 {
		return nil, errors.New("invalid geodata host address count")
	}
	port := parsed.Port()
	if port == "" {
		port = "80"
		if parsed.Scheme == "https" {
			port = "443"
		}
	}
	numericPort, _ := strconv.ParseUint(port, 10, 16)
	local, err := net.InterfaceAddrs()
	if err != nil {
		return nil, errors.New("could not verify local interface addresses")
	}
	localIPs := make(map[netip.Addr]struct{}, len(local))
	for _, address := range local {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			localIPs[prefix.Addr().Unmap()] = struct{}{}
		}
	}
	targets := make([]netip.AddrPort, 0, len(addresses))
	for _, address := range addresses {
		_, isLocal := localIPs[address.Unmap()]
		if isLocal || !geoPublicAddress(address) {
			return nil, errors.New("geodata host resolves to a non-public address")
		}
		targets = append(targets, netip.AddrPortFrom(address.Unmap(), uint16(numericPort)))
	}
	return targets, nil
}

// fetchGeoAsset tries the URLs in order. Only the failure category reaches
// the caller, because that is what the operation error carries; the reason of
// every attempt goes to the log, without credentials.
func fetchGeoAsset(ctx context.Context, log *logrus.Logger, dir, kind string, urls []string, verify bool, required []string, resolve geoResolver, selectRoute geoRouteSelector) (geoDownloadedAsset, error) {
	failure := "download_failed"
	for _, raw := range urls {
		started := time.Now()
		asset, err := fetchGeoURL(ctx, dir, kind, raw, verify, required, resolve, selectRoute)
		if err == nil {
			if log != nil {
				log.WithFields(logrus.Fields{"kind": kind, "url": geoLogURL(raw), "bytes": asset.Size}).Debugf("Geodata file downloaded in %s", time.Since(started).Round(time.Millisecond))
			}
			return asset, nil
		}
		if log != nil {
			log.WithFields(logrus.Fields{"kind": kind, "url": geoLogURL(raw)}).WithError(err).Warnf("Geodata download attempt failed after %s", time.Since(started).Round(time.Millisecond))
		}
		if errors.Is(err, errGeoValidation) {
			failure = "validation_failed"
		}
		if ctx.Err() != nil {
			break
		}
	}
	return geoDownloadedAsset{}, &geoUpdateError{failure, "No configured URL for " + kind + " returned a usable file."}
}

var errGeoValidation = errors.New("geodata validation failed")

var errGeoStalled = fmt.Errorf("no data for %s", geoStallTimeout)

// geoProgressReader re-arms the stall watchdog whenever the server delivers
// data.
type geoProgressReader struct {
	io.Reader
	watchdog *time.Timer
}

func (r *geoProgressReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.watchdog.Reset(geoStallTimeout)
	}
	return n, err
}

// geoValidationError keeps the validation category while carrying the
// parser's reason for the log.
type geoValidationError struct{ cause error }

func (e *geoValidationError) Error() string { return "validation: " + e.cause.Error() }
func (e *geoValidationError) Unwrap() error { return errGeoValidation }

// geoLogURL is the credential-free form of a download URL used in the log.
func geoLogURL(raw string) string {
	if display := geoDisplayURL(raw); display != nil {
		return *display
	}
	return "[invalid URL]"
}

func fetchGeoURL(ctx context.Context, dir, kind, raw string, verify bool, required []string, resolve geoResolver, selectRoute geoRouteSelector) (geoDownloadedAsset, error) {
	ctx, cancel := context.WithTimeout(ctx, geoURLTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	parsed, err := parseGeoURL(raw)
	if err != nil {
		return geoDownloadedAsset{}, err
	}
	targets, err := geoTargets(ctx, parsed, resolve)
	if err != nil {
		return geoDownloadedAsset{}, err
	}
	var dialMu sync.Mutex
	var connected geoDialTarget
	// The stall watchdog only guards the phases that have no timeout of their
	// own: the transfer of a body. Connecting, the TLS handshake and the
	// response headers are bounded by the transport.
	var stalled atomic.Bool
	watchdog := time.AfterFunc(time.Hour, func() {
		stalled.Store(true)
		cancel()
	})
	defer watchdog.Stop()
	watchdog.Stop()
	transport := &http.Transport{
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 32 << 10,
		ResponseHeaderTimeout:  geoStallTimeout,
		TLSHandshakeTimeout:    10 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialMu.Lock()
			defer dialMu.Unlock()
			ctx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			if connected.dialer != nil {
				return dialGeoTarget(ctx, connected)
			}
			preferred, err := selectRoute(parsed.Hostname(), targets[0])
			if err != nil {
				return nil, fmt.Errorf("download route: %w", err)
			}
			dialErr := errors.New("no address was dialable through the download route")
			for i, dest := range targets {
				target := preferred
				if i > 0 {
					if target, err = selectRoute(parsed.Hostname(), dest); err != nil || target.network != preferred.network ||
						target.route.Route != preferred.route.Route ||
						runtimeSettingOr(target.route.GroupID, "") != runtimeSettingOr(preferred.route.GroupID, "") {
						continue
					}
				}
				dialCtx, cancel := context.WithTimeout(ctx, geoDialTimeout)
				conn, err := dialGeoTarget(dialCtx, target)
				cancel()
				if err == nil {
					connected = target
					return conn, nil
				}
				dialErr = fmt.Errorf("dial %s: %w", target.address, err)
				if ctx.Err() != nil {
					break
				}
			}
			return nil, dialErr
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := requestGeoURL(ctx, client, parsed)
	if err != nil {
		return geoDownloadedAsset{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return geoDownloadedAsset{}, fmt.Errorf("http status %d", response.StatusCode)
	}
	if response.ContentLength > geodata.MaxUpdateSize {
		return geoDownloadedAsset{}, fmt.Errorf("response of %d bytes exceeds the size limit", response.ContentLength)
	}
	if encoding := response.Header.Get("Content-Encoding"); !geoIdentityEncoding(encoding) {
		return geoDownloadedAsset{}, fmt.Errorf("content-encoding %q is not accepted", encoding)
	}
	path := filepath.Join(dir, kind+".dat")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return geoDownloadedAsset{}, err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	hash := sha256.New()
	watchdog.Reset(geoStallTimeout)
	body := &geoProgressReader{Reader: response.Body, watchdog: watchdog}
	size, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(body, geodata.MaxUpdateSize+1))
	watchdog.Stop()
	if err != nil {
		if stalled.Load() {
			return geoDownloadedAsset{}, fmt.Errorf("%w after %d bytes", errGeoStalled, size)
		}
		return geoDownloadedAsset{}, fmt.Errorf("transfer stopped after %d bytes: %w", size, err)
	}
	if size > geodata.MaxUpdateSize {
		return geoDownloadedAsset{}, errors.New("geodata response exceeds its size limit")
	}
	_ = response.Body.Close()
	sum := hex.EncodeToString(hash.Sum(nil))
	verified := false
	if verify {
		verified, err = verifyGeoChecksum(ctx, client, parsed, sum, watchdog)
		if err != nil {
			if stalled.Load() {
				return geoDownloadedAsset{}, fmt.Errorf("%w while fetching the checksum", errGeoStalled)
			}
			return geoDownloadedAsset{}, err
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return geoDownloadedAsset{}, err
	}
	if err := geodata.ValidateUpdate(ctx, file, kind, required); err != nil {
		return geoDownloadedAsset{}, &geoValidationError{cause: err}
	}
	if err := file.Sync(); err != nil {
		return geoDownloadedAsset{}, err
	}
	info, err := file.Stat()
	if err != nil {
		return geoDownloadedAsset{}, err
	}
	if err := file.Close(); err != nil {
		return geoDownloadedAsset{}, err
	}
	dialMu.Lock()
	route := connected.route
	dialMu.Unlock()
	keep = true
	return geoDownloadedAsset{SHA256: sum, Size: size, Modified: info.ModTime(), FetchedURL: geoDisplayURL(raw), Verified: verified, Route: &route}, nil
}

func dialGeoTarget(ctx context.Context, target geoDialTarget) (net.Conn, error) {
	conn, err := target.dialer.DialContext(ctx, target.network, target.address)
	if err != nil {
		return nil, err
	}
	return &netproxy.FakeNetConn{Conn: conn}, nil
}

func requestGeoURL(ctx context.Context, client *http.Client, parsed *url.URL) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, errors.New("invalid geodata request")
	}
	response, err := client.Do(request)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			// url.Error repeats the request URL; only its cause is reported.
			err = urlErr.Err
		}
		return nil, fmt.Errorf("http request: %w", err)
	}
	return response, nil
}

func geoIdentityEncoding(encoding string) bool {
	return encoding == "" || strings.EqualFold(encoding, "identity")
}

func verifyGeoChecksum(ctx context.Context, client *http.Client, parsed *url.URL, sum string, watchdog *time.Timer) (bool, error) {
	checksum := *parsed
	checksum.RawPath = parsed.EscapedPath() + ".sha256sum"
	checksum.Path += ".sha256sum"
	if parsed.Path == "" {
		checksum.Path = "/.sha256sum"
		checksum.RawPath = ""
	}
	response, err := requestGeoURL(ctx, client, &checksum)
	if err != nil {
		return false, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotFound {
		return false, nil
	}
	const maxChecksumBytes = 4096
	if response.StatusCode != http.StatusOK || response.ContentLength > maxChecksumBytes || response.Header.Get("Content-Encoding") != "" {
		return false, errors.New("geodata checksum response rejected")
	}
	watchdog.Reset(geoStallTimeout)
	data, err := io.ReadAll(io.LimitReader(&geoProgressReader{Reader: response.Body, watchdog: watchdog}, maxChecksumBytes+1))
	watchdog.Stop()
	if err != nil || len(data) > maxChecksumBytes {
		return false, errors.New("geodata checksum response exceeds its limit")
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 || !strings.EqualFold(fields[0], sum) {
		return false, fmt.Errorf("geodata checksum mismatch")
	}
	return true, nil
}
