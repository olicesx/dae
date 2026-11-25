/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/panjf2000/ants/v2"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// The TCP-DNS legs are advisory: they tell an operator that udp_check_dns'
// host does not answer over TCP, and nothing else. These tests pin the three
// places that keep them from leaking into node selection.

// fixedProbe returns a probe with a fixed outcome.
func fixedProbe(ok bool, err error) func(ctx context.Context, typ *NetworkType) (bool, error) {
	return func(context.Context, *NetworkType) (bool, error) {
		return ok, err
	}
}

func TestCheckOptions_RegistersAdvisoryTcpDnsLegsOnlyWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		name        string
		checkDnsTcp bool
		wantOpts    int
	}{
		{name: "disabled", checkDnsTcp: false, wantOpts: 4},
		{name: "enabled", checkDnsTcp: true, wantOpts: 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newNamedTestDialer(t, "node")
			d.CheckDnsTcp = tc.checkDnsTcp

			opts := d.checkOptions()
			require.Len(t, opts, tc.wantOpts)

			// The four health probes come first and are never advisory.
			for _, opt := range opts[:4] {
				require.False(t, opt.Advisory, opt.networkType.String())
			}
			advisory := opts[4:]
			require.Len(t, advisory, tc.wantOpts-4)
			wantVersions := []consts.IpVersionStr{consts.IpVersionStr_4, consts.IpVersionStr_6}
			for i, opt := range advisory {
				typ := opt.networkType
				require.True(t, opt.Advisory)
				require.Equal(t, consts.L4ProtoStr_TCP, typ.L4Proto)
				require.Equal(t, wantVersions[i], typ.IpVersion)
				require.True(t, typ.IsDns)
				require.NotNil(t, opt.CheckFunc)
			}
		})
	}
}

// TestCheck_AdvisoryProbeLeavesHealthStateAlone runs the same outcome through
// an advisory probe and through a health probe. newTestNetworkType is a
// TCP+DNS type, which is the collection the advisory legs index into, so a
// missing guard in check() would show up here as a changed collection or as
// a cycle summary that blames the node for what the advisory leg saw.
func TestCheck_AdvisoryProbeLeavesHealthStateAlone(t *testing.T) {
	typ := newTestNetworkType()
	boom := errors.New("connection refused")
	for _, tc := range []struct {
		name      string
		advisory  bool
		ok        bool
		err       error
		wantOK    bool
		wantErr   error
		wantAlive bool
		wantProbe bool
		// wantCycle is what the cycle accumulator must say afterwards.
		wantCycle string
	}{
		{name: "advisory failure", advisory: true, err: boom, wantErr: boom, wantAlive: true, wantProbe: false, wantCycle: ""},
		{name: "advisory success", advisory: true, ok: true, wantOK: true, wantAlive: true, wantProbe: false, wantCycle: ""},
		{name: "health failure", advisory: false, err: boom, wantErr: boom, wantAlive: false, wantProbe: true, wantCycle: "failure"},
		{name: "health success", advisory: false, ok: true, wantOK: true, wantAlive: true, wantProbe: true, wantCycle: "success"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newNamedTestDialer(t, "node")
			require.True(t, d.MustGetAlive(typ), "a new dialer starts alive")

			opt := &CheckOption{
				networkType: typ,
				CheckFunc:   fixedProbe(tc.ok, tc.err),
				Advisory:    tc.advisory,
			}
			cycle := &cycleResult{}
			ok, err := d.check(opt, false, cycle)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantErr, err)

			c := d.mustGetCollection(typ)
			require.Equal(t, tc.wantAlive, c.Alive.Load())
			// The cycle summary feeds the stability notice; an advisory leg must not count.
			require.Equal(t, tc.wantCycle == "success", cycle.tcpSuccess)
			require.Equal(t, tc.wantCycle == "failure", cycle.tcpFailure)
			if tc.wantProbe {
				require.NotEqual(t, DialerProbeObservationSnapshot{}, c.LastProbe)
				return
			}
			require.Equal(t, DialerProbeObservationSnapshot{}, c.LastProbe, "an advisory probe must not record a probe observation")
			require.Zero(t, c.MovingAverage, "an advisory probe must not feed the latency average")
		})
	}
}

// TestCheck_AdvisoryLogsOnVerdictChangeOnly: a steady state is one debug line
// per cycle, a change is loud once.
func TestCheck_AdvisoryLogsOnVerdictChangeOnly(t *testing.T) {
	d := newNamedTestDialer(t, "node")
	hook := test.NewLocal(d.Log)
	// NewLocal keeps the logger level, and a steady state is logged at debug.
	d.Log.SetLevel(logrus.TraceLevel)
	typ := newTestNetworkType()
	boom := errors.New("connection refused")
	opt := &CheckOption{
		networkType: typ,
		CheckFunc:   func(ctx context.Context, typ *NetworkType) (bool, error) { return false, boom },
		Advisory:    true,
	}

	const failing = "Advisory probe failing; node health state is not affected"
	for _, step := range []struct {
		name      string
		ok        bool
		err       error
		wantLevel logrus.Level
		wantMsg   string
	}{
		{name: "first failure", err: boom, wantLevel: logrus.WarnLevel, wantMsg: failing},
		{name: "still failing", err: boom, wantLevel: logrus.DebugLevel, wantMsg: "Advisory probe still failing"},
		{name: "no applicable IP is a skip", err: ErrNoApplicableIP, wantLevel: logrus.DebugLevel, wantMsg: "Advisory probe skipped"},
		{name: "a skip leaves the verdict alone", err: boom, wantLevel: logrus.DebugLevel, wantMsg: "Advisory probe still failing"},
		{name: "recovered", ok: true, wantLevel: logrus.InfoLevel, wantMsg: "Advisory probe recovered"},
		{name: "still fine", ok: true, wantLevel: logrus.DebugLevel, wantMsg: "Advisory probe"},
		{name: "failed again", err: boom, wantLevel: logrus.WarnLevel, wantMsg: failing},
	} {
		opt.CheckFunc = fixedProbe(step.ok, step.err)
		hook.Reset()
		_, _ = d.check(opt, false, nil)

		var advisory []*logrus.Entry
		for _, e := range hook.AllEntries() {
			if len(e.Message) >= len("Advisory probe") && e.Message[:len("Advisory probe")] == "Advisory probe" {
				advisory = append(advisory, e)
			}
		}
		require.Len(t, advisory, 1, step.name)
		require.Equal(t, step.wantLevel, advisory[0].Level, step.name)
		require.Equal(t, step.wantMsg, advisory[0].Message, step.name)
		require.Equal(t, "node", advisory[0].Data["node"], step.name)
		if step.err != nil && step.err != ErrNoApplicableIP {
			require.Equal(t, boom.Error(), advisory[0].Data["err"], step.name)
		}
	}
	mustStayAlive(t, d, typ, "after every advisory verdict")
}

// TestSubmitCheckTasks_SkipsAdvisoryProbesWhenResuscitating: the resuscitation
// path staggers every probe it submits, and only health probes may decide its
// outcome.
func TestSubmitCheckTasks_SkipsAdvisoryProbesWhenResuscitating(t *testing.T) {
	typ := newTestNetworkType()
	boom := errors.New("connection refused")
	for _, tc := range []struct {
		name          string
		resuscitation bool
		wantCalls     int32
	}{
		// check() retries a failing probe once.
		{name: "periodic cycle runs the advisory probe", resuscitation: false, wantCalls: 2},
		{name: "resuscitation cycle skips it", resuscitation: true, wantCalls: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newNamedTestDialer(t, "node")
			// Somebody has to select on the type; otherwise every probe is skipped.
			set := NewAliveDialerSet(
				d.Log,
				"group",
				typ,
				0,
				consts.DialerSelectionPolicy_Random,
				[]*Dialer{d},
				[]*Annotation{{}},
				func(bool) {},
				true,
			)
			d.RegisterAliveDialerSet(set)
			t.Cleanup(func() { d.UnregisterAliveDialerSet(set) })

			var calls atomic.Int32
			opt := &CheckOption{
				networkType: typ,
				CheckFunc: func(ctx context.Context, typ *NetworkType) (bool, error) {
					calls.Add(1)
					return false, boom
				},
				Advisory: true,
			}
			pool, err := ants.NewPool(1)
			require.NoError(t, err)
			t.Cleanup(pool.Release)

			var wg sync.WaitGroup
			d.submitCheckTasks(pool, &wg, []*CheckOption{opt}, tc.resuscitation, nil)
			wg.Wait()
			require.Equal(t, tc.wantCalls, calls.Load())
		})
	}
}

// TestNewGlobalOption_CheckDnsTcpComesFromConfig: check_dns_tcp is a global
// option, so the flag only means something if the dialer is handed the parsed
// value instead of a constant.
func TestNewGlobalOption_CheckDnsTcpComesFromConfig(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	for _, want := range []bool{false, true} {
		got := NewGlobalOption(&config.Global{CheckDnsTcp: want}, log).CheckDnsTcp
		require.Equal(t, want, got)
	}
}
