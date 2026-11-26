/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
)

// windowFixture drives a tracker with a controllable clock and counter table.
type windowFixture struct {
	tracker  *flowWindowTracker
	now      time.Time
	counters map[string][2]uint64
}

func newWindowFixture(now time.Time) *windowFixture {
	fixture := &windowFixture{now: now, counters: map[string][2]uint64{}}
	fixture.tracker = newFlowWindowTracker(func(yield func(control.FlowByteCounter)) {
		for id, value := range fixture.counters {
			yield(control.FlowByteCounter{ID: id, UploadBytes: value[0], DownloadBytes: value[1]})
		}
	})
	fixture.tracker.now = func() time.Time { return fixture.now }
	return fixture
}

func (f *windowFixture) advance(d time.Duration) {
	f.now = f.now.Add(d)
}

func (f *windowFixture) set(id string, upload, download uint64) {
	f.counters[id] = [2]uint64{upload, download}
}

// snapshotOf builds the flow view a listing would have read at the same time.
func (f *windowFixture) snapshotOf(id string, startedAt time.Time) control.SessionFlowSnapshot {
	counters := f.counters[id]
	return control.SessionFlowSnapshot{ID: id, HasBytes: true, StartedAt: startedAt, UploadBytes: counters[0], DownloadBytes: counters[1]}
}

func TestFlowWindowMeasuresTrailingWindow(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	started := fixture.now.Add(-time.Hour)
	fixture.set("f_1", 0, 1_000)
	flow := fixture.snapshotOf("f_1", started)

	// The first request has no baseline yet, so the window stays unknown.
	if measured := fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, 10*time.Second); len(measured) != 0 {
		t.Fatalf("measured = %v, want nothing before a baseline exists", measured)
	}
	fixture.tracker.sampleOnce()

	fixture.advance(10 * time.Second)
	fixture.set("f_1", 0, 1_500)
	fixture.tracker.sampleOnce()

	fixture.advance(10 * time.Second)
	fixture.set("f_1", 100, 1_800)
	flow = fixture.snapshotOf("f_1", started)
	measured := fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, 10*time.Second)
	if got := measured["f_1"]; got.upload != 100 || got.download != 300 {
		t.Fatalf("window bytes = %+v, want the delta since the sample one window back", got)
	}
}

func TestFlowWindowYoungFlowReportsItsCounters(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	fixture.set("f_new", 10, 900)
	flow := fixture.snapshotOf("f_new", fixture.now.Add(-5*time.Second))

	measured := fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, time.Minute)
	// A flow younger than the window has moved exactly its counters within it.
	if got := measured["f_new"]; got.upload != 10 || got.download != 900 {
		t.Fatalf("window bytes = %+v, want the whole counter of a young flow", got)
	}
}

func TestFlowWindowUnknownWithoutBaseline(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	fixture.set("f_old", 10, 900)
	flow := fixture.snapshotOf("f_old", fixture.now.Add(-time.Hour))

	if measured := fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, time.Minute); len(measured) != 0 {
		t.Fatalf("measured = %v, want an unknown window", measured)
	}
}

func TestFlowWindowRejectsStaleBaseline(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	started := fixture.now.Add(-time.Hour)
	fixture.set("f_1", 0, 1_000)
	fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}, 10*time.Second)
	fixture.tracker.sampleOnce()

	// The only sample is far older than the window, so subtracting it would
	// report a span nobody asked for.
	fixture.advance(time.Minute)
	fixture.set("f_1", 0, 9_000)
	measured := fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}, 10*time.Second)
	if len(measured) != 0 {
		t.Fatalf("measured = %v, want the stale baseline rejected", measured)
	}
}

func TestFlowWindowRejectsCounterRegression(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	started := fixture.now.Add(-time.Hour)
	fixture.set("f_1", 0, 1_000)
	fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}, 10*time.Second)
	fixture.tracker.sampleOnce()

	fixture.advance(10 * time.Second)
	fixture.set("f_1", 0, 500)
	fixture.tracker.sampleOnce()

	fixture.advance(10 * time.Second)
	fixture.set("f_1", 0, 200)
	measured := fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}, 10*time.Second)
	if len(measured) != 0 {
		t.Fatalf("measured = %v, want a replaced connection to stay unknown", measured)
	}
}

func TestFlowWindowSamplerStopsWhenIdle(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	fixture.set("f_1", 0, 10)
	fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", fixture.now)}, 10*time.Second)
	if interval := fixture.tracker.sampleOnce(); interval <= 0 {
		t.Fatalf("interval = %v, want a positive cadence", interval)
	}
	if len(fixture.tracker.rings) != 1 {
		t.Fatalf("rings = %d, want one observed flow", len(fixture.tracker.rings))
	}

	fixture.advance(flowWindowDemandIdle + time.Second)
	if interval := fixture.tracker.sampleOnce(); interval != flowWindowMaxInterval {
		t.Fatalf("interval = %v, want the idle cadence", interval)
	}
	if fixture.tracker.rings != nil {
		t.Fatalf("rings = %d, want history dropped once nobody reads a window", len(fixture.tracker.rings))
	}
}

func TestFlowWindowIntervalCoversTheLongestWindow(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	flow := control.SessionFlowSnapshot{ID: "f_1", HasBytes: true}
	for _, tc := range []struct {
		window time.Duration
		want   time.Duration
	}{
		{3 * time.Second, flowWindowMinInterval},
		{60 * time.Second, 4 * time.Second},
		{300 * time.Second, flowWindowMaxInterval},
	} {
		fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, tc.window)
		if got := fixture.tracker.intervalLocked(); got != tc.want {
			t.Fatalf("interval for %v = %v, want %v", tc.window, got, tc.want)
		}
	}
}

func TestSortConnectionFlowsByCounters(t *testing.T) {
	flows := []control.SessionFlowSnapshot{
		{ID: "a", HasBytes: true, UploadBytes: 1, DownloadBytes: 10},
		{ID: "b", HasBytes: true, UploadBytes: 2, DownloadBytes: 20},
		{ID: "unknown"},
		{ID: "d", HasBytes: true, UploadBytes: 3, DownloadBytes: 5},
	}
	order := func(field, direction string) []string {
		sorted := rankConnections(flows, field, direction, nil)
		ids := make([]string, 0, len(sorted))
		for _, rank := range sorted {
			ids = append(ids, flows[rank.index].ID)
		}
		return ids
	}
	for _, tc := range []struct {
		field, direction string
		want             []string
	}{
		{"download", "desc", []string{"b", "a", "d", "unknown"}},
		{"download", "asc", []string{"d", "a", "b", "unknown"}},
		{"upload", "desc", []string{"d", "b", "a", "unknown"}},
		{"total", "desc", []string{"b", "a", "d", "unknown"}},
	} {
		got := order(tc.field, tc.direction)
		if len(got) != len(tc.want) {
			t.Fatalf("%s %s = %v, want %v", tc.field, tc.direction, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s %s = %v, want %v", tc.field, tc.direction, got, tc.want)
			}
		}
	}
}

func TestSortConnectionFlowsByWindowBytes(t *testing.T) {
	flows := []control.SessionFlowSnapshot{
		{ID: "a", HasBytes: true, UploadBytes: 1, DownloadBytes: 10},
		{ID: "b", HasBytes: true, UploadBytes: 2, DownloadBytes: 20},
		{ID: "no-window", HasBytes: true},
	}
	windows := map[string]flowWindowBytes{"a": {upload: 5, download: 100}, "b": {upload: 50, download: 10}}

	sorted := rankConnections(flows, "window_download", "desc", windows)
	if flows[sorted[0].index].ID != "a" || flows[sorted[1].index].ID != "b" || flows[sorted[2].index].ID != "no-window" {
		t.Fatalf("window_download order = %v", []string{flows[sorted[0].index].ID, flows[sorted[1].index].ID, flows[sorted[2].index].ID})
	}

	sorted = rankConnections(flows, "window_upload", "asc", windows)
	if flows[sorted[0].index].ID != "a" || flows[sorted[1].index].ID != "b" || flows[sorted[2].index].ID != "no-window" {
		t.Fatalf("window_upload order = %v", []string{flows[sorted[0].index].ID, flows[sorted[1].index].ID, flows[sorted[2].index].ID})
	}

	sorted = rankConnections(flows, "window_total", "desc", windows)
	if flows[sorted[0].index].ID != "a" || flows[sorted[1].index].ID != "b" || flows[sorted[2].index].ID != "no-window" {
		t.Fatalf("window_total order = %v", []string{flows[sorted[0].index].ID, flows[sorted[1].index].ID, flows[sorted[2].index].ID})
	}
}

func TestListConnectionSnapshotsOrdersBeforeTruncation(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	provider := &nativeAPIProvider{connectionBytes: true}
	provider.flowsOnce.Do(func() { provider.flowWindow = fixture.tracker })
	src := netip.MustParseAddrPort("192.0.2.1:1234")
	started := fixture.now.Add(-time.Second)
	flows := []control.SessionFlowSnapshot{
		{ID: "ignored", Src: netip.MustParseAddrPort("192.0.2.2:1234"), Network: "tcp", HasBytes: true, StartedAt: started, DownloadBytes: 100},
		{ID: "tcp-1", Src: src, Network: "tcp", HasBytes: true, StartedAt: started, DownloadBytes: 10},
		{ID: "udp-1", Src: src, Network: "udp"},
		{ID: "tcp-2", Src: src, Network: "tcp", HasBytes: true, StartedAt: started, DownloadBytes: 20},
		{ID: "tcp-3", Src: src, Network: "tcp", HasBytes: true, StartedAt: started, DownloadBytes: 20},
	}
	filter := nativeapi.ConnectionFilter{Src: src.Addr().String(), Limit: 2, Sort: "window_download", WindowSeconds: 10}
	list := provider.listConnectionSnapshots(flows, filter, "test-instance")
	if list.TotalTCP != 3 || list.TotalUDP != 1 || !list.Truncated || list.InstanceID != "test-instance" {
		t.Fatalf("unexpected list metadata: %+v", list)
	}
	if len(list.TCP) != 2 || list.TCP[0].ID != "c_tcp-2" || list.TCP[1].ID != "c_tcp-3" {
		t.Fatalf("tcp flows = %+v, want the first two ranked matches in stable order", list.TCP)
	}
	if len(list.UDP) != 1 || list.UDP[0].ID != "c_udp-1" {
		t.Fatalf("udp flows = %+v, want the UDP match", list.UDP)
	}
	if list.Window == nil || list.Window.Seconds != 10 || list.TCP[0].DownloadWindowBytes == nil || *list.TCP[0].DownloadWindowBytes != "20" {
		t.Fatalf("window metadata or counters missing: %+v", list)
	}
	if fixture.tracker.rings["tcp-1"] == nil || fixture.tracker.rings["ignored"] != nil {
		t.Fatalf("window measurements must include truncated matches and skip filtered flows: %v", fixture.tracker.rings)
	}
}

func TestListConnectionSnapshotsEmptyWindowRegistersDemand(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	provider := &nativeAPIProvider{connectionBytes: true}
	provider.flowsOnce.Do(func() { provider.flowWindow = fixture.tracker })
	list := provider.listConnectionSnapshots([]control.SessionFlowSnapshot{{Network: "tcp"}}, nativeapi.ConnectionFilter{Type: "udp", WindowSeconds: 10}, "instance")
	if list.TCP == nil || list.UDP == nil || len(list.TCP) != 0 || len(list.UDP) != 0 || list.TotalTCP != 0 || list.TotalUDP != 0 || list.Truncated {
		t.Fatalf("expected empty arrays and totals: %+v", list)
	}
	if fixture.tracker.demand[10] != fixture.now {
		t.Fatalf("empty listing did not register demand: %v", fixture.tracker.demand)
	}
}

func BenchmarkListConnectionSnapshots(b *testing.B) {
	provider := &nativeAPIProvider{}
	small := []control.SessionFlowSnapshot{
		{ID: "tcp-1", Network: "tcp", HasBytes: true, DownloadBytes: 10},
		{ID: "udp-1", Network: "udp"},
		{ID: "tcp-2", Network: "tcp", HasBytes: true, DownloadBytes: 20},
	}
	large := make([]control.SessionFlowSnapshot, 4096)
	for i := range large {
		large[i] = control.SessionFlowSnapshot{
			ID:            strconv.Itoa(i),
			Network:       small[i%len(small)].Network,
			HasBytes:      i%3 != 1,
			DownloadBytes: uint64(i * 997 % len(large)),
		}
	}
	for _, tc := range []struct {
		name   string
		flows  []control.SessionFlowSnapshot
		filter nativeapi.ConnectionFilter
	}{
		{name: "empty", filter: nativeapi.ConnectionFilter{Sort: "download"}},
		{name: "single", flows: small[:1], filter: nativeapi.ConnectionFilter{Sort: "download"}},
		{name: "mixed_sorted", flows: small, filter: nativeapi.ConnectionFilter{Sort: "download", Limit: 1}},
		{name: "large_sorted", flows: large, filter: nativeapi.ConnectionFilter{Sort: "download", Limit: 100}},
		{name: "filtered_out", flows: small, filter: nativeapi.ConnectionFilter{Type: "other"}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				provider.listConnectionSnapshots(slices.Clone(tc.flows), tc.filter, "instance")
			}
		})
	}
}

func TestConnectionOfAttachesWindowBytes(t *testing.T) {
	provider := &nativeAPIProvider{connectionBytes: true}
	flow := control.SessionFlowSnapshot{ID: "f_1", Network: "tcp", HasBytes: true, UploadBytes: 7, DownloadBytes: 9}

	without := provider.connectionOf(flow, nil)
	if without.UploadWindowBytes != nil || without.DownloadWindowBytes != nil {
		t.Fatalf("unmeasured connection carries window bytes: %+v", without)
	}

	with := provider.connectionOf(flow, map[string]flowWindowBytes{"f_1": {upload: 3, download: 4}})
	if with.UploadWindowBytes == nil || *with.UploadWindowBytes != "3" {
		t.Fatalf("upload_window_bytes = %v, want 3", with.UploadWindowBytes)
	}
	if with.DownloadWindowBytes == nil || *with.DownloadWindowBytes != "4" {
		t.Fatalf("download_window_bytes = %v, want 4", with.DownloadWindowBytes)
	}
}

// The window bytes come from the same counters `disable_connection_bytes`
// suppresses, so a listing that hides the counters must not leak them through
// the window fields.
func TestConnectionWindowAbsentWhenBytesDisabled(t *testing.T) {
	provider := &nativeAPIProvider{connectionBytes: false}
	flow := control.SessionFlowSnapshot{ID: "f_1", Network: "tcp", HasBytes: true, UploadBytes: 7, DownloadBytes: 9}
	connection := provider.connectionOf(flow, map[string]flowWindowBytes{"f_1": {upload: 3, download: 4}})
	if connection.UploadWindowBytes != nil || connection.DownloadWindowBytes != nil {
		t.Fatalf("window bytes leaked while counters are disabled: %+v", connection)
	}
}

// A daemon without an active generation still answers a windowed listing: the
// sampler observes nothing instead of failing the request.
func TestFlowWindowsTolerateMissingGeneration(t *testing.T) {
	provider := &nativeAPIProvider{}
	tracker := provider.flowWindows()
	if tracker == nil || tracker != provider.flowWindows() {
		t.Fatal("the provider must keep one tracker")
	}
	tracker.measure([]control.SessionFlowSnapshot{{ID: "f_1", HasBytes: true, StartedAt: time.Now()}}, time.Second)
	if interval := tracker.sampleOnce(); interval <= 0 {
		t.Fatalf("interval = %v, want a positive cadence", interval)
	}
}

func TestFlowWindowDemandWakesSampler(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	fixture.tracker.measure(nil, time.Second)
	select {
	case <-fixture.tracker.wake:
	default:
		t.Fatal("new window demand did not wake the sampler")
	}
	fixture.tracker.measure(nil, time.Second)
	select {
	case <-fixture.tracker.wake:
		t.Fatal("repeated polling woke the sampler unnecessarily")
	default:
	}
}

// A dashboard that polls at its own cadence works without the sampler: the
// request itself is an observation, so the second poll measures the interval
// between the two polls.
func TestFlowWindowMeasuresBetweenPolls(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	started := fixture.now.Add(-time.Hour)
	fixture.set("f_1", 0, 1_000)

	flows := []control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}
	if measured := fixture.tracker.measure(flows, 20*time.Second); len(measured) != 0 {
		t.Fatalf("first poll = %v, want an unknown window", measured)
	}

	fixture.advance(20 * time.Second)
	fixture.set("f_1", 0, 4_000)
	flows = []control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}
	measured := fixture.tracker.measure(flows, 20*time.Second)
	if got := measured["f_1"]; got.download != 3_000 {
		t.Fatalf("second poll = %+v, want the 3000 bytes between the polls", got)
	}
}
