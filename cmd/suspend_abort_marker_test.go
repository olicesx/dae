/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestSuspendAbortMarkerFollowsSignalDelivery pins the abort-marker lifecycle of
// `dae suspend --abort`: the marker must survive a signal the daemon received
// (dae consumes it and aborts established connections) and must not survive a
// signal the kernel rejected, because a leftover marker aborts the connections
// of the next unrelated `dae reload`.
//
// The command calls os.Exit on both failure paths, so this test runs the test
// binary as a child once per scenario instead of invoking the command in
// process. AbortFile is a constant on purpose — the child therefore drives the
// real /var/run/dae.abort the command always uses, and skips rather than
// touching a marker that is already there.
func TestSuspendAbortMarkerFollowsSignalDelivery(t *testing.T) {
	if os.Geteuid() != 0 {
		// AutoSu() escalates through sudo/doas/polkit for unprivileged users,
		// which would replace this process, and the marker path needs root.
		t.Skip("suspend --abort needs the real /var/run/dae.abort and an unescalated AutoSu(); run as root")
	}
	if _, err := os.Stat(AbortFile); err == nil {
		t.Skipf("%s already exists; refusing to overwrite a marker a running daemon may be waiting for", AbortFile)
	} else if !os.IsNotExist(err) {
		t.Skipf("cannot inspect %s: %v", AbortFile, err)
	}
	t.Cleanup(func() { _ = os.Remove(AbortFile) })

	runSuspend := func(pid int) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.run=TestSuspendAbortMarkerChild")
		cmd.Env = append(os.Environ(), "suspendAbortMarkerChild=1", "suspendAbortMarkerPid="+strconv.Itoa(pid))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// A delivered signal is the normal path: dae is suspended and will read the
	// marker, so it must still be there when the command returns.
	victim := exec.Command("sleep", "30")
	if err := victim.Start(); err != nil {
		t.Fatalf("start signal victim: %v", err)
	}
	t.Cleanup(func() {
		_ = victim.Process.Kill()
		_, _ = victim.Process.Wait()
	})
	out, err := runSuspend(victim.Process.Pid)
	if err != nil {
		t.Fatalf("suspend --abort with a signalable pid failed: %v (output %q)", err, out)
	}
	if _, err := os.Stat(AbortFile); err != nil {
		t.Fatalf("a delivered signal must leave the abort marker in place: %v (output %q)", err, out)
	}
	if err := os.Remove(AbortFile); err != nil {
		t.Fatalf("reset the abort marker: %v", err)
	}

	// A rejected signal has no daemon to consume the marker.
	out, err = runSuspend(1 << 30)
	if err == nil {
		t.Fatalf("suspend --abort with an unsignalable pid exited 0 (output %q)", out)
	}
	if strings.Contains(out, "Failed to create abort marker") {
		t.Fatalf("the child failed before signalling, so this run proves nothing: %q", out)
	}
	if _, statErr := os.Stat(AbortFile); !os.IsNotExist(statErr) {
		t.Fatalf("a rejected signal left the abort marker behind: stat err = %v (output %q)", statErr, out)
	}
}

// TestSuspendAbortMarkerChild is the child half of the test above: it runs the
// real command body, which exits the process on both failure paths — the reason
// the parent cannot call the command in process.
func TestSuspendAbortMarkerChild(t *testing.T) {
	if os.Getenv("suspendAbortMarkerChild") != "1" {
		t.Skip("not the child invocation")
	}
	pid, err := strconv.Atoi(os.Getenv("suspendAbortMarkerPid"))
	if err != nil {
		t.Fatalf("child pid: %v", err)
	}
	// Execute through the root command: cobra redirects a subcommand's Execute
	// to its root, so driving the real `dae suspend <pid> --abort` invocation is
	// both the only working route and the faithful one.
	rootCmd.SetArgs([]string{"suspend", strconv.Itoa(pid), "--abort"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute(): %v", err)
	}
}
