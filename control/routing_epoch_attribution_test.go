/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"golang.org/x/sys/unix"
)

func TestDecodeBpfRoutingEpochSlot(t *testing.T) {
	tests := []struct {
		name    string
		encoded uint8
		want    uint32
		known   bool
	}{
		{name: "unknown", encoded: bpfRoutingEpochSlotUnknown},
		{name: "slot zero", encoded: bpfRoutingEpochSlot0Encoded, want: 0, known: true},
		{name: "slot one", encoded: bpfRoutingEpochSlot1Encoded, want: 1, known: true},
		{name: "out of range", encoded: 3},
		{name: "maximum", encoded: ^uint8(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := decodeBpfRoutingEpochSlot(tt.encoded)
			if got != tt.want || known != tt.known {
				t.Fatalf("decodeBpfRoutingEpochSlot(%d) = (%d, %v), want (%d, %v)", tt.encoded, got, known, tt.want, tt.known)
			}
		})
	}
}

func TestRetrieveRoutingResultCarriesBpfRoutingEpochSlot(t *testing.T) {
	tests := []struct {
		name     string
		from     string
		encoded  uint8
		wantSlot uint32
		known    bool
	}{
		{
			name:     "conn state slot one",
			from:     "conn-state",
			encoded:  bpfRoutingEpochSlot1Encoded,
			wantSlot: 1,
			known:    true,
		},
		{
			name:     "handoff slot zero",
			from:     "handoff",
			encoded:  bpfRoutingEpochSlot0Encoded,
			wantSlot: 0,
			known:    true,
		},
		{
			name:    "conn state unknown",
			from:    "conn-state",
			encoded: bpfRoutingEpochSlotUnknown,
		},
		{
			name:    "handoff invalid",
			from:    "handoff",
			encoded: ^uint8(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := common.ConvergeAddrPort(netip.MustParseAddrPort("192.0.2.10:34567"))
			dst := common.ConvergeAddrPort(netip.MustParseAddrPort("198.51.100.20:443"))
			key := tuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_TCP)
			core := &controlPlaneCore{}

			switch tt.from {
			case "conn-state":
				connStateMap := newJanitorTestMap(t, "conn_state_map")
				state := bpfConnState{}
				state.Meta.Data.HasRouting = 1
				state.Meta.Data.Outbound = 9
				state.RoutingEpochSlot = tt.encoded
				if err := connStateMap.Update(key, &state, ebpf.UpdateAny); err != nil {
					t.Fatalf("update conn_state_map: %v", err)
				}
				core.bpf.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connStateMap}})
			case "handoff":
				handoffMap := newJanitorTestMap(t, "routing_handoff_map")
				entry := newRoutingHandoffEntryForTest(monotonicNowNs(t), bpfRoutingResult{
					Outbound:         9,
					RoutingEpochSlot: tt.encoded,
				})
				if err := handoffMap.Update(key, &entry, ebpf.UpdateAny); err != nil {
					t.Fatalf("update routing_handoff_map: %v", err)
				}
				core.bpf.Store(&bpfObjects{bpfMaps: bpfMaps{RoutingHandoffMap: handoffMap}})
			default:
				t.Fatalf("unsupported result source %q", tt.from)
			}

			result, err := core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
			if err != nil {
				t.Fatalf("RetrieveRoutingResult: %v", err)
			}

			wantEncoded := tt.encoded
			if _, ok := decodeBpfRoutingEpochSlot(wantEncoded); !ok {
				wantEncoded = bpfRoutingEpochSlotUnknown
			}
			if result.RoutingEpochSlot != wantEncoded {
				t.Fatalf("routing epoch encoding = %d, want %d", result.RoutingEpochSlot, wantEncoded)
			}

			gotSlot, known := decodeBpfRoutingEpochSlot(result.RoutingEpochSlot)
			if gotSlot != tt.wantSlot || known != tt.known {
				t.Fatalf("decoded routing epoch = (%d, %v), want (%d, %v)", gotSlot, known, tt.wantSlot, tt.known)
			}
		})
	}
}
