/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// The production incident behind the evidence ring had its DNS dial argument
// on the TCP leg (the node's generic TCP latency beat its DNS-UDP latency, so
// the chooser picked tcp+4). Those failures used to report through the shared
// traffic-failure path — evidence-blind, threshold 50 — and the class never
// fell. These tests pin the leg-agnostic contract: both legs' forward
// outcomes feed the same DNS-domain evidence ring the chooser gates on.

func newEvidenceTestController(t *testing.T) (*DnsController, *logrus.Logger) {
	t.Helper()
	logger, _ := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	return &DnsController{
		dnsControllerStore: newDnsControllerStore(),
		log:                logger,
	}, logger
}

func newTcpDnsDialArg(t *testing.T, logger *logrus.Logger) *dialArgument {
	t.Helper()
	d := componentdialer.NewDialerContext(t.Context(),
		&scriptedDialer{},
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{},
	)
	t.Cleanup(func() { _ = d.Close() })
	return &dialArgument{
		l4proto:    consts.L4ProtoStr_TCP,
		ipversion:  consts.IpVersionStr_4,
		bestDialer: d,
	}
}

func dnsV4EvidenceType() *componentdialer.NetworkType {
	return &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		IsDns:           true,
		UdpHealthDomain: componentdialer.UdpHealthDomainDns,
	}
}

func TestDnsForwardEvidenceIsLegAgnostic(t *testing.T) {
	controller, logger := newEvidenceTestController(t)

	t.Run("tcp-leg failures convict the dns domain", func(t *testing.T) {
		tcpArg := newTcpDnsDialArg(t, logger)
		typ := dnsV4EvidenceType()
		for range 5 {
			controller.reportDnsForwardFailure(tcpArg, io.ErrUnexpectedEOF)
		}
		require.False(t, tcpArg.bestDialer.MustGetAlive(typ),
			"five TCP-leg forward failures must evict the DNS domain: the traffic-threshold path never evicted anything")
	})

	t.Run("tcp-leg successes feed the same ring", func(t *testing.T) {
		tcpArg := newTcpDnsDialArg(t, logger)
		typ := dnsV4EvidenceType()
		for range 5 {
			controller.reportDnsForwardFailure(tcpArg, io.ErrUnexpectedEOF)
		}
		require.False(t, tcpArg.bestDialer.MustGetAlive(typ), "setup: failures must evict first")
		for !tcpArg.bestDialer.MustGetAlive(typ) {
			controller.reportDnsForwardSuccess(tcpArg)
		}
		require.True(t, tcpArg.bestDialer.MustGetAlive(typ),
			"a stream of real TCP-leg successes must revive the DNS domain")
	})

	t.Run("interleaved tcp-leg storm evicts", func(t *testing.T) {
		tcpArg := newTcpDnsDialArg(t, logger)
		typ := dnsV4EvidenceType()
		for range 6 {
			controller.reportDnsForwardFailure(tcpArg, io.ErrUnexpectedEOF)
			controller.reportDnsForwardFailure(tcpArg, io.ErrUnexpectedEOF)
			controller.reportDnsForwardSuccess(tcpArg)
		}
		require.False(t, tcpArg.bestDialer.MustGetAlive(typ),
			"a 2:1 failure-to-success interleaving on the TCP leg must evict on evidence, not on never-reaching consecutive strikes")
	})
}

// TestChooseGatedDnsDialerCandidate pins the chooser's candidate
// preference: an evidence-gated candidate beats a gated-but-penalized one,
// which beats the ungated fallback, and all-empty returns nil so the caller's
// "no proper dialer" error path stays reachable.
func TestChooseGatedDnsDialerCandidate(t *testing.T) {
	gated := &dnsDialerCandidate{latency: 300}
	penalized := &dnsDialerCandidate{latency: 200}
	ungated := &dnsDialerCandidate{latency: 100}

	cases := []struct {
		name                             string
		gated, gatedPenalized, ungatedIn *dnsDialerCandidate
		want                             *dnsDialerCandidate
		wantPenalized                    bool
	}{
		{"gated wins over penalized and ungated", gated, penalized, ungated, gated, false},
		{"penalized beats ungated fallback", nil, penalized, ungated, penalized, true},
		{"ungated fallback only", nil, nil, ungated, ungated, false},
		{"empty pools", nil, nil, nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotPenalized := chooseGatedDnsDialerCandidate(tc.gated, tc.gatedPenalized, tc.ungatedIn)
			require.Same(t, tc.want, got)
			require.Equal(t, tc.wantPenalized, gotPenalized)
		})
	}
}
