/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// The kernel smoke job waits for the daemon's reload milestones in its rendered
// log (scripts/semantic-refactor-smoke.sh, wait_for_reload_count). Those waits
// accept "[Reload] Finished" and the "Reload: Finished" form that
// ForceFormatting produces, so the rendering of a leading bracketed component
// is an external contract: a formatter change must not make a milestone
// unrecognisable, because the failure only shows up as a 45s timeout inside a
// kernel VM.
func TestReloadMilestoneRenderingStaysRecognisable(t *testing.T) {
	log := logrus.New()
	SetLogger(log, "info", true, nil)
	var buf bytes.Buffer
	log.SetOutput(&buf)

	log.Infoln("[Reload] Finished")

	rendered := buf.String()
	if !strings.Contains(rendered, "Finished") {
		t.Fatalf("reload milestone text was lost while rendering: %q", rendered)
	}
	if !strings.Contains(rendered, "Reload: Finished") && !strings.Contains(rendered, "[Reload] Finished") {
		t.Fatalf("reload milestone rendered in a form the smoke waits do not accept: %q", rendered)
	}
}
