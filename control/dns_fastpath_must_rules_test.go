/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// must_rules reserves matched flows for the routing verdict's outbound: the
// kernel already decided, and both DNS fast paths (UDP ingress and TCP port
// 53) must forward such traffic as plain traffic instead of absorbing it
// into the DNS controller.

func TestDNSFastPathPermitted(t *testing.T) {
	if !dnsFastPathPermitted(nil) {
		t.Fatal("a missing routing result carries no must_rules verdict; the DNS fast path must stay eligible")
	}
	if !dnsFastPathPermitted(&bpfRoutingResult{}) {
		t.Fatal("a routing result without a must verdict must keep the DNS fast path eligible")
	}
	if dnsFastPathPermitted(&bpfRoutingResult{Must: 1}) {
		t.Fatal("a must_rules verdict must bar the DNS fast path so the flow forwards as plain traffic")
	}
}

// readCountConn counts Read calls so a test can see whether the TCP DNS fast
// path consumed the query. SetReadDeadline and the other net.Conn methods
// pass through to the pipe.
type readCountConn struct {
	net.Conn
	reads int
}

func (c *readCountConn) Read(p []byte) (int, error) {
	c.reads++
	return c.Conn.Read(p)
}

func TestMustRulesSkipsTCPDnsFastPath(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	packed, err := query.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	frame := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(packed)))
	copy(frame[2:], packed)

	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("192.0.2.53:53")
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	for _, tc := range []struct {
		name string
		must uint8
	}{
		{name: "must forwards as plain tcp", must: 1},
		{name: "without must the dns fast path reads the query", must: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			go func() {
				_, _ = client.Write(frame)
				_ = client.Close()
			}()
			conn := &readCountConn{Conn: server}
			plane := &ControlPlane{log: logger}
			t.Cleanup(func() {
				if mgr, _ := plane.controlPlaneSessionManager(); mgr != nil {
					_ = mgr.Close()
				}
			})
			err := plane.handleConnWithRoutingResultOwned(
				context.Background(),
				conn,
				src,
				dst,
				&bpfRoutingResult{Outbound: uint8(consts.OutboundDirect), Must: tc.must},
				nil,
			)
			if tc.must == 0 {
				// The fast path consumes the query and, with the client already
				// closed, ends the DNS session. It must not fall through to dial.
				if err != nil {
					t.Fatalf("non-must DNS fast path error = %v, want nil", err)
				}
				if conn.reads == 0 {
					t.Fatal("a non-must port-53 flow did not read the DNS query")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "failed to dial") {
				t.Fatalf("handleConnWithRoutingResultOwned() error = %v, want a plain-TCP dial failure", err)
			}
			if conn.reads != 0 {
				t.Fatalf("must_rules consumed the DNS query (%d reads); the fast path must not run", conn.reads)
			}
		})
	}
}

func TestMustRulesUDPDnsUsesPlainIngress(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	src := netip.MustParseAddrPort("192.0.2.10:53000")
	dst := netip.MustParseAddrPort("1.1.1.1:53")

	for _, must := range []uint8{0, 1} {
		must := must
		t.Run(map[uint8]string{0: "fast path", 1: "plain udp"}[must], func(t *testing.T) {
			restore := swapUdpEndpointPoolForTest(t)
			defer restore()

			// cilium/ebpf marshals these structs with encoding/binary, which does
			// not include Go alignment padding. The map sizes have to be that
			// encoding, or Update rejects the entry.
			keySize := binary.Size(bpfTuplesKey{})
			valueSize := binary.Size(bpfRoutingHandoffEntry{})
			if keySize <= 0 || valueSize <= 0 {
				t.Fatalf("handoff key/value size = %d/%d", keySize, valueSize)
			}
			m, err := ebpf.NewMap(&ebpf.MapSpec{
				Type:       ebpf.Hash,
				KeySize:    uint32(keySize),
				ValueSize:  uint32(valueSize),
				MaxEntries: 4,
			})
			if err != nil {
				if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
					t.Skipf("creating a routing handoff map requires BPF privileges: %v", err)
				}
				t.Fatalf("NewMap: %v", err)
			}
			t.Cleanup(func() { _ = m.Close() })

			now, err := monotonicNowNano()
			if err != nil {
				t.Fatalf("monotonicNowNano: %v", err)
			}
			key := bpfTuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_UDP)
			entry := bpfRoutingHandoffEntry{
				LastSeenNs: now,
			}
			entry.Result.Must = must
			entry.Result.Outbound = uint8(consts.OutboundUserDefinedMin)
			if err := m.Update(&key, &entry, ebpf.UpdateAny); err != nil {
				t.Fatalf("seed routing handoff: %v", err)
			}

			cp, _ := newGetCountDialingControlPlane(t)
			core := &controlPlaneCore{}
			core.bpf.Store(&bpfObjects{bpfMaps: bpfMaps{RoutingHandoffMap: m}})
			cp.core = core

			keys := countPoolGets(t, func() {
				runCountedIngressTask(cp, src, dst, payload)
			})
			flow := ClassifyUdpFlow(src, dst, payload)
			ue, pooled := DefaultUdpEndpointPool.Get(flow.FullConeNatEndpointKey())
			if must == 0 {
				if len(keys) != 0 || pooled {
					t.Fatalf("non-must DNS created a UDP endpoint (gets=%v pooled=%v); the fast path must absorb it", keys, pooled)
				}
				return
			}
			if !pooled || ue == nil {
				t.Fatal("must_rules DNS did not reach plain UDP ingress")
			}
			bound, hit := ue.GetBoundRoutingResult(dst, unix.IPPROTO_UDP)
			if !hit || bound == nil || bound.Must == 0 || bound.Outbound != uint8(consts.OutboundUserDefinedMin) {
				t.Fatalf("bound routing = (%v, hit=%v), want the must verdict's outbound", bound, hit)
			}
		})
	}
}
