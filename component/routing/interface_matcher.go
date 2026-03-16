/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

type InterfaceDirection uint8

const (
	InterfaceDirectionIn InterfaceDirection = iota + 1
	InterfaceDirectionOut
)

type InterfaceZone uint8

const (
	InterfaceZoneWan InterfaceZone = iota + 1
	InterfaceZoneLan
)

type InterfaceMatcher struct {
	Zone InterfaceZone
	Name string
}

func InterfaceParserFactory(callback func(f *config_parser.Function, values []InterfaceMatcher, overrideOutbound *Outbound) (err error)) FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		matchers, err := parseInterfaceMatchers(key, paramValueGroup)
		if err != nil {
			return err
		}
		return callback(f, matchers, overrideOutbound)
	}
}

func parseInterfaceMatchers(key string, values []string) ([]InterfaceMatcher, error) {
	var zone InterfaceZone
	switch strings.ToLower(key) {
	case "wan":
		zone = InterfaceZoneWan
	case "lan":
		zone = InterfaceZoneLan
	default:
		return nil, fmt.Errorf("interface: unsupported key: %v (want wan or lan)", key)
	}
	seen := make(map[string]struct{}, len(values))
	ret := make([]InterfaceMatcher, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, fmt.Errorf("interface: empty interface name")
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		ret = append(ret, InterfaceMatcher{Zone: zone, Name: v})
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("interface: no interface provided")
	}
	return ret, nil
}

func MatchInterface(rule InterfaceMatcher, direction InterfaceDirection, ifname string) bool {
	if ifname == "" {
		return false
	}
	switch rule.Zone {
	case InterfaceZoneWan:
		if direction != InterfaceDirectionOut {
			return false
		}
	case InterfaceZoneLan:
		if direction != InterfaceDirectionIn {
			return false
		}
	default:
		return false
	}
	if ifname == rule.Name {
		return true
	}
	if idx := strings.IndexByte(ifname, '.'); idx > 0 {
		return ifname[idx+1:] == rule.Name
	}
	return false
}
