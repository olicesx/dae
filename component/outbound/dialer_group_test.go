/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	testTcpCheckUrl = "https://connectivitycheck.gstatic.com/generate_204"
	testUdpCheckDns = "1.1.1.1:53"
)

func TestMain(m *testing.M) {
	common.InitPrometheus(prometheus.NewRegistry())
	m.Run()
}

var TestNetworkType = &common.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
}

type mockDialer struct {
	netproxy.Dialer
}

func (m *mockDialer) Alive() bool { return true }
func (m *mockDialer) Name() string  { return "mock" }
func (m *mockDialer) Dial(network, address string) (net.Conn, error) { return nil, nil }
func (m *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) { return nil, nil }
func (m *mockDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) { return nil, nil }

func newDirectDialer(option *dialer.GlobalOption, needAliveState bool) *dialer.Dialer {
	d := dialer.NewDialer(&mockDialer{}, option, &dialer.Property{Property: D.Property{Name: "mock"}}, needAliveState)
	// Use unsafe to set unexported supported field
	supportedField := reflect.ValueOf(d).Elem().FieldByName("supported")
	if supportedField.IsValid() {
		ptr := unsafe.Pointer(supportedField.UnsafeAddr())
		*(*[4]bool)(ptr) = [4]bool{true, true, true, true}
	}
	return d
}

func TestDialerGroup_Select_Fixed(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
		CheckDnsTcp:       false,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, true),
		newDirectDialer(option, false),
	}
	fixedIndex := 1
	g := NewDialerGroup(option, "test-group", dialers, make([]*dialer.Annotation, len(dialers)),
		dialer.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: fixedIndex,
		}, func(alive bool, networkType *common.NetworkType) {})
	for i := 0; i < 10; i++ {
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal("step 1:", err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}

	fixedIndex = 0
	g.selectionPolicy.FixedIndex = fixedIndex
	dialers[fixedIndex].Update(true, 0, TestNetworkType, nil)
	for i := 0; i < 10; i++ {
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal("step 2:", err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}
}

func TestDialerGroup_Select_MinLastLatency(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := make([]*dialer.Dialer, 10)
	for i := range dialers {
		dialers[i] = newDirectDialer(option, false)
	}
	annos := make([]*dialer.Annotation, 10)
	for i := range annos {
		annos[i] = &dialer.Annotation{}
	}
	g := NewDialerGroup(option, "test-group", dialers, annos,
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		}, func(alive bool, networkType *common.NetworkType) {})

	// Test 1000 times.
	for i := 0; i < 1000; i++ {
		var minLatency time.Duration
		jMinLatency := -1
		for j, d := range dialers {
			// Simulate a latency test.
			var (
				latency time.Duration
				alive   bool
			)
			// 20% chance for timeout.
			if fastrand.Intn(5) == 0 {
				// Simulate a timeout test.
				latency = 1000 * time.Millisecond
				alive = false
			} else {
				// Simulate a normal test.
				latency = time.Duration(fastrand.Int63n(int64(1000 * time.Millisecond)))
				alive = true
			}
			d.Update(alive, latency, TestNetworkType, nil)
			if alive && (jMinLatency == -1 || latency < minLatency) {
				jMinLatency = j
				minLatency = latency
			}
		}
		if jMinLatency == -1 {
			continue
		}
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[jMinLatency] {
			// Get index of d.
			indexD := -1
			for j := range dialers {
				if d == dialers[j] {
					indexD = j
					break
				}
			}
			t.Errorf("dialers[%v] expected, but dialers[%v] selected", jMinLatency, indexD)
		}
	}
}

func TestDialerGroup_Select_Random(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := make([]*dialer.Dialer, 5)
	for i := range dialers {
		dialers[i] = newDirectDialer(option, false)
	}
	annos := make([]*dialer.Annotation, 5)
	for i := range annos {
		annos[i] = &dialer.Annotation{}
	}
	g := NewDialerGroup(option, "test-group", dialers, annos,
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *common.NetworkType) {})
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
}

func TestDialerGroup_SetAlive(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := make([]*dialer.Dialer, 5)
	for i := range dialers {
		dialers[i] = newDirectDialer(option, true)
	}
	annos := make([]*dialer.Annotation, 5)
	for i := range annos {
		annos[i] = &dialer.Annotation{}
	}
	g := NewDialerGroup(option, "test-group", dialers, annos,
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *common.NetworkType) {})
	for _, d := range dialers {
		d.Update(true, 0, TestNetworkType, nil)
	}
	zeroTarget := 3
	dialers[zeroTarget].Update(false, 0, TestNetworkType, nil)
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 && i != zeroTarget {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
	if count[zeroTarget] != 0 {
		t.Fail()
	}
}
