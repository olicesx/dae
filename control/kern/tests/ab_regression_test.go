//go:build linux && dae_bpf_tests
// +build linux,dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package tests

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

const abTestHostUDPPort = 54321

func loadABRegressionObjects(t *testing.T) *bpftestObjects {
	t.Helper()

	obj := &bpftestObjects{}
	spec, err := loadBpftest()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if err = disableAllPinnedMapsForTests(spec); err != nil {
		t.Fatalf("disable pinned maps: %v", err)
	}
	param := struct {
		tproxyPort           uint32
		controlPlanePid      uint32
		dae0Ifindex          uint32
		daeNetnsId           uint32
		dae0peerMac          [6]byte
		paddingAfterMac      [2]uint8
		useRedirectPeer      uint8
		hasBpfGetCurrentTask uint8
		datapathGeneration   uint16
		daeSocketMark        uint32
	}{
		datapathGeneration: 41,
		daeSocketMark:      0x200,
	}
	if err = spec.Variables["PARAM"].Set(param); err != nil {
		t.Fatalf("set PARAM: %v", err)
	}
	if err = spec.LoadAndAssign(obj, &ebpf.CollectionOptions{}); err != nil {
		t.Fatalf("load objects: %v", err)
	}
	return obj
}

func TestABRegression(t *testing.T) {
	obj := loadABRegressionObjects(t)
	defer obj.Close()

	t.Run("custom mark excludes foreign bit 8", func(t *testing.T) {
		data := make([]byte, 4096-256-320)
		ctx := make([]byte, 256)
		status, _, _, err := runBpfProgram(obj.TestAbControlPlaneCustomMark, data, ctx)
		if err != nil || status != 0 {
			t.Fatalf("custom-mark policy: status=%d err=%v", status, err)
		}
	})

	t.Run("IPv6 AH UDP parse", func(t *testing.T) {
		data := make([]byte, 4096-256-320)
		ctx := make([]byte, 256)
		status, _, _, err := runBpfProgram(obj.TestAbIpv6AhUdpParse, data, ctx)
		if err != nil || status != 0 {
			t.Fatalf("AH parse: status=%d err=%v", status, err)
		}
	})

	t.Run("LAN ingress host UDP listener passthrough", func(t *testing.T) {
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: abTestHostUDPPort,
		})
		if err != nil {
			t.Fatalf("bind host-netns UDP listener: %v", err)
		}
		defer func() { _ = listener.Close() }()

		markAllOutboundsAlive(t, obj)
		key := uint32(0)
		activeRulesLen := uint32(testMaxMatchSetLen)
		if err = obj.RoutingMetaMap.Update(key, activeRulesLen, ebpf.UpdateAny); err != nil {
			t.Fatalf("initialize routing metadata: %v", err)
		}

		data := make([]byte, 4096-256-320)
		ctx := make([]byte, 256)
		status, data, ctx, err := runBpfProgram(obj.TestAbLanIngressUdpHostListenerPktgen, data, ctx)
		if err != nil || status != 0 {
			t.Fatalf("packet generation: status=%d err=%v", status, err)
		}
		status, _, _, err = runBpfProgram(obj.TestAbLanIngressUdpHostListener, data, ctx)
		if err != nil {
			t.Fatalf("LAN ingress program: %v", err)
		}
		if status != 0 {
			t.Fatalf("host-netns UDP listener was not passed through: status=%d", status)
		}
	})
}
