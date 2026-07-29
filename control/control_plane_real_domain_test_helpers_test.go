/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func (c *ControlPlane) isRealDomain(domain string) bool {
	if known, real := c.lookupRealDomainCache(domain); known {
		return real
	}

	v, _, _ := c.realDomainProbeS.Do(domain, func() (any, error) {
		return c.probeAndUpdateRealDomain(domain), nil
	})
	isReal, _ := v.(bool)
	return isReal
}

// newJanitorTestMap loads a real (unpinned) bpf map by spec for janitor tests.
// Recovered from the pruned control_plane_janitor_test.go (Sprint 5 T1).
// No build tag: callers span default and !dae_stub_ebpf builds; a tagless
// helper file is visible in both, matching the original definition's semantics.
func newJanitorTestMap(t *testing.T, mapName string) *ebpf.Map {
	t.Helper()

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock failed: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		if strings.Contains(err.Error(), "stub build") {
			t.Skipf("loadBpf: %v", err)
		}
		t.Fatalf("loadBpf: %v", err)
	}

	mapSpec, ok := spec.Maps[mapName]
	if !ok || mapSpec == nil {
		t.Fatalf("missing map spec %q", mapName)
	}

	cloned := *mapSpec
	cloned.Pinning = ebpf.PinNone
	m, err := ebpf.NewMap(&cloned)
	if err != nil {
		t.Skipf("creating test map %s requires BPF privileges: %v", mapName, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}
