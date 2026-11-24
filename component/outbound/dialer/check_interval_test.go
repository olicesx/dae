/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestClampCheckInterval(t *testing.T) {
	cases := []struct {
		interval time.Duration
		want     time.Duration
	}{
		{0, 0},
		{-time.Second, -time.Second},
		{time.Millisecond, MinCheckInterval},
		{MinCheckInterval - time.Millisecond, MinCheckInterval},
		{MinCheckInterval, MinCheckInterval},
		{5 * time.Second, 5 * time.Second},
	}
	for _, tc := range cases {
		if got := clampCheckInterval(tc.interval); got != tc.want {
			t.Errorf("clampCheckInterval(%v) = %v, want %v", tc.interval, got, tc.want)
		}
	}
}

func TestEffectiveCheckIntervalClampsLowValueOnce(t *testing.T) {
	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)

	d := &Dialer{GlobalOption: &GlobalOption{
		Log:           log,
		CheckInterval: 100 * time.Millisecond,
	}}

	if got := d.effectiveCheckInterval(); got != MinCheckInterval {
		t.Fatalf("effectiveCheckInterval() = %v, want %v", got, MinCheckInterval)
	}
	if got := d.effectiveCheckInterval(); got != MinCheckInterval {
		t.Fatalf("second effectiveCheckInterval() = %v, want %v", got, MinCheckInterval)
	}
	if n := strings.Count(buf.String(), "clamped to minimum 2s"); n != 1 {
		t.Fatalf("low-interval warning logged %d times, want 1: %q", n, buf.String())
	}
	if d.CheckInterval != 100*time.Millisecond {
		t.Fatalf("the configured interval was modified: %v", d.CheckInterval)
	}
}

func TestEffectiveCheckIntervalKeepsValidCadenceAndFloorsMissingValue(t *testing.T) {
	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)

	d := &Dialer{GlobalOption: &GlobalOption{Log: log, CheckInterval: 5 * time.Second}}
	if got := d.effectiveCheckInterval(); got != 5*time.Second {
		t.Fatalf("effectiveCheckInterval() = %v, want 5s", got)
	}
	if buf.String() != "" {
		t.Fatalf("a valid cadence must not warn, got %q", buf.String())
	}

	// A non-positive interval is a missing one: fastrand.Int63n would panic on
	// it, and the fallback cadence takes the same floor as any other.
	for _, missing := range []time.Duration{0, -time.Second} {
		d = &Dialer{GlobalOption: &GlobalOption{Log: log, CheckInterval: missing}}
		if got := d.effectiveCheckInterval(); got != MinCheckInterval {
			t.Fatalf("interval %v: effectiveCheckInterval() = %v, want %v", missing, got, MinCheckInterval)
		}
	}
	if n := strings.Count(buf.String(), "clamped to minimum 2s"); n != 2 {
		t.Fatalf("missing interval warned %d times, want one line per dialer: %q", n, buf.String())
	}
}
