// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

// TestNewControlPlaneWithContextOptionsAbortsOnCanceledContext locks in the
// cooperative cancellation contract: when the caller passes a context that is
// already canceled (e.g. an expired reloadPrepareTimeout), the build must fail
// fast at the first checkpoint instead of running through every slow stage.
func TestNewControlPlaneWithContextOptionsAbortsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)

	global := &config.Global{}
	dnsConfig := &config.Dns{}
	routingA := &config.Routing{}

	_, err := newControlPlaneWithContextOptions(
		ctx,
		log,
		nil,
		nil,
		nil,
		nil,
		routingA,
		global,
		dnsConfig,
		nil,
		controlPlaneBuildOptions{},
	)
	if err == nil {
		t.Fatal("newControlPlaneWithContextOptions() error = nil, want cancellation failure")
	}
	if !stderrors.Is(err, context.Canceled) {
		t.Fatalf("newControlPlaneWithContextOptions() error = %v, want context.Canceled", err)
	}
}
