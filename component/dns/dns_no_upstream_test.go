/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus/hooks/test"
)

// TestNewWithoutUpstreamsAndWithoutReadyCallback pins that the zero-upstream
// readiness report is optional. It used to call UpstreamReadyCallback from a
// goroutine unconditionally, so a caller that only wants a Dns without upstreams
// (and therefore passes no callback) crashed the process; a panic in another
// goroutine cannot be recovered by the caller.
func TestNewWithoutUpstreamsAndWithoutReadyCallback(t *testing.T) {
	logger, _ := test.NewNullLogger()
	d, err := New(noUpstreamDnsConfig(), &NewOption{Logger: logger})
	if err != nil {
		t.Fatalf("New without upstreams: %v", err)
	}
	if d == nil {
		t.Fatal("New without upstreams returned a nil Dns")
	}
}

// noUpstreamDnsConfig is a valid configuration with no upstream servers: the
// routing fallbacks are required because New builds both matchers even when
// there is nothing to route to.
func noUpstreamDnsConfig() *config.Dns {
	return &config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "asis"},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	}
}

// TestNewWithoutUpstreamsStillReportsReady pins the other half: when the caller
// does provide the callback, an upstream-less configuration is still reported
// ready without blocking New.
func TestNewWithoutUpstreamsStillReportsReady(t *testing.T) {
	logger, _ := test.NewNullLogger()
	ready := make(chan struct{})
	d, err := New(noUpstreamDnsConfig(), &NewOption{
		Logger: logger,
		UpstreamReadyCallback: func(upstream *Upstream) error {
			if upstream != nil {
				t.Errorf("zero-upstream readiness reported an upstream: %v", upstream)
			}
			close(ready)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New without upstreams: %v", err)
	}
	if d == nil {
		t.Fatal("New without upstreams returned a nil Dns")
	}
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream-ready callback was not invoked for an upstream-less configuration")
	}
}
