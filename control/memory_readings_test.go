/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func writeMemoryReadoutFile(t testing.TB, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func memoryReadoutFixture(t testing.TB) (procSelf, directory string) {
	t.Helper()
	procSelf = t.TempDir()
	mount := filepath.Join(t.TempDir(), "cgroup mount")
	directory = filepath.Join(mount, "svc")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMemoryReadoutFile(t, filepath.Join(procSelf, "status"), "Name:\tdae\nVmRSS:\u00a01234\t kB extra\n")
	writeMemoryReadoutFile(t, filepath.Join(procSelf, "cgroup"), "1:cpu:/legacy\n0::\u2003/slice name/svc\u2003\n")
	writeMemoryReadoutFile(t, filepath.Join(procSelf, "mountinfo"),
		strings.Repeat("31 25 0:30 / /run rw,nosuid - tmpfs tmpfs rw\n", 200)+
			"36 25 0:32 / /not-selected rw - cgroup2 cgroup rw\n"+
			"37 25 0:32 /slice\\040name "+strings.ReplaceAll(mount, " ", `\040`)+" rw - cgroup2 cgroup rw\n")
	writeMemoryReadoutFile(t, filepath.Join(directory, "memory.current"), "\u00a042\u2003\n")
	writeMemoryReadoutFile(t, filepath.Join(directory, "memory.max"), "\u2003max\n")
	writeMemoryReadoutFile(t, filepath.Join(directory, "memory.events"), "low 0\nhigh 7\nmax 3\noom 1\noom_kill 0\noom_group_kill 0\n")
	writeMemoryReadoutFile(t, filepath.Join(directory, "cgroup.procs"), strconv.Itoa(os.Getpid())+"\n")
	return procSelf, directory
}

func TestMemoryReadoutParsingAndFreshness(t *testing.T) {
	procSelf, directory := memoryReadoutFixture(t)
	writeMemoryReadoutFile(t, filepath.Join(directory, "memory.events"), "high 5\nhigh\u20037\nhigh 10 extra\nhigh bad\noom 18446744073709551616\noom_kill 0")
	first := readMemorySnapshot(procSelf)
	if first.RSSBytes == nil || *first.RSSBytes != 1234*1024 {
		t.Fatalf("rss = %v, want %d", first.RSSBytes, 1234*1024)
	}
	cgroup := first.Cgroup
	if cgroup == nil || cgroup.Scope != "service" || cgroup.CurrentBytes == nil || *cgroup.CurrentBytes != 42 || !cgroup.LimitUnlimited || cgroup.LimitBytes != nil {
		t.Fatalf("unexpected cgroup reading: %+v", cgroup)
	}
	events := cgroup.Events
	if events == nil || events.High == nil || *events.High != 7 || events.OOM != nil || events.OOMKill == nil || *events.OOMKill != 0 {
		t.Fatalf("unexpected events: %+v", events)
	}

	writeMemoryReadoutFile(t, filepath.Join(procSelf, "status"), "VmRSS: 18446744073709551616 kB\nVmRSS: 1 kB\n")
	writeMemoryReadoutFile(t, filepath.Join(directory, "memory.current"), "99\n")
	writeMemoryReadoutFile(t, filepath.Join(directory, "cgroup.procs"), "0"+strconv.Itoa(os.Getpid())+"\n")
	latest := readMemorySnapshot(procSelf)
	if latest.RSSBytes != nil || latest.Cgroup == nil || latest.Cgroup.Scope != "shared" || latest.Cgroup.CurrentBytes == nil || *latest.Cgroup.CurrentBytes != 99 {
		t.Fatalf("unexpected second reading: %+v cgroup=%+v", latest, latest.Cgroup)
	}

	writeMemoryReadoutFile(t, filepath.Join(procSelf, "cgroup"), "0::/missing\n0::/slice name/svc\n")
	if latest := readMemorySnapshot(procSelf); latest.Cgroup != nil {
		t.Fatalf("cgroup = %+v after membership changed, want nil", latest.Cgroup)
	}
}

func BenchmarkReadMemorySnapshot(b *testing.B) {
	procSelf, _ := memoryReadoutFixture(b)
	b.ReportAllocs()
	for b.Loop() {
		readMemorySnapshot(procSelf)
	}
}
