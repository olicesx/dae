/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

// ParseFixedDomainTtl parses dns.fixed_domain_ttl entries of the form
// "name: ttl" (quoted as a whole, see pkg/config_parser). It is the only
// consumer of that config field and runs the run path only, so `dae validate`
// dry-runs it too via cmd.validateFixedDomainTtl to keep "validate exits 0 =>
// the daemon starts" true.
func ParseFixedDomainTtl(ks []config.KeyableString) (map[string]int, error) {
	m := make(map[string]int)
	for _, k := range ks {
		key, value, _ := strings.Cut(string(k), ":")
		ttl, err := strconv.ParseInt(strings.TrimSpace(value), 0, strconv.IntSize)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ttl of entry %q: %w", string(k), err)
		}
		// The TTL becomes a cache deadline via time.Duration(ttl) *
		// time.Second. Zero or negative values expire the entry immediately
		// (nonsense for a "fixed TTL"), and values beyond MaxInt32 seconds
		// would overflow the Duration on 64-bit builds to a deadline in the
		// past, silently un-caching the domain. Reject both at parse time:
		// MaxInt32 seconds (~68 years) is beyond any sane fixed TTL while
		// staying Duration-safe on every build.
		if ttl <= 0 || ttl > math.MaxInt32 {
			return nil, fmt.Errorf("invalid ttl %d of entry %q: must be 1..%d seconds", ttl, string(k), int64(math.MaxInt32))
		}
		m[strings.TrimSpace(key)] = int(ttl)
	}
	return m, nil
}

func ParseGroupOverrideOption(group config.Group, global config.Global, log *logrus.Logger) (*dialer.GlobalOption, error) {
	result := global
	changed := false
	if group.TcpCheckUrl != nil {
		result.TcpCheckUrl = group.TcpCheckUrl
		changed = true
	}
	if group.TcpCheckHttpMethod != "" {
		result.TcpCheckHttpMethod = group.TcpCheckHttpMethod
		changed = true
	}
	if group.UdpCheckDns != nil {
		result.UdpCheckDns = group.UdpCheckDns
		changed = true
	}
	if group.CheckInterval != 0 {
		result.CheckInterval = group.CheckInterval
		changed = true
	}
	if group.CheckTolerance != 0 {
		result.CheckTolerance = group.CheckTolerance
		changed = true
	}
	if changed {
		option := dialer.NewGlobalOption(&result, log)
		return option, nil
	}
	return nil, nil
}

func parseGroupOverrideOptionWithRuntime(
	group config.Group,
	global config.Global,
	log *logrus.Logger,
	runtimeSource *dialer.GlobalOption,
) (*dialer.GlobalOption, error) {
	option, err := ParseGroupOverrideOption(group, global, log)
	if err != nil || option == nil {
		return option, err
	}
	inheritGroupOptionRuntime(option, runtimeSource)
	return option, nil
}

// inheritGroupOptionRuntime preserves dependencies that are assembled while
// building the control plane rather than derived from config.Global. Group
// health-check overrides rebuild GlobalOption from config, so every runtime
// dependency must move together with the generation.
func inheritGroupOptionRuntime(dst, src *dialer.GlobalOption) {
	if dst == nil || src == nil {
		return
	}
	dst.DaeDNS = src.DaeDNS
	dst.TransportCacheNamespace = src.TransportCacheNamespace
	dst.SetRuntimeDependencies(src.DirectDialer, src.FullconeDirectDialer, src.SystemDNSResolver)
}
