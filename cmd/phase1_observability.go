/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/daeuniverse/dae/control"
)

const phase1SampleEveryEnv = "DAE_PHASE1_SAMPLE_EVERY"

func phase1SampleEveryFromEnvironment() (uint64, bool, error) {
	value, present := os.LookupEnv(phase1SampleEveryEnv)
	return phase1SampleEveryFromValue(value, present)
}

func phase1SampleEveryFromValue(value string, present bool) (uint64, bool, error) {
	if !present || value == "" {
		return 0, false, nil
	}

	sampleEvery, err := strconv.ParseUint(value, 10, 64)
	if err != nil || sampleEvery == 0 {
		return 0, false, fmt.Errorf("%s must be a positive unsigned integer, got %q", phase1SampleEveryEnv, value)
	}
	return sampleEvery, true, nil
}

func enablePhase1ObservabilityFromEnvironment() (*control.Phase1ObservabilityHandle, error) {
	sampleEvery, enabled, err := phase1SampleEveryFromEnvironment()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	return control.EnablePhase1Observability(sampleEvery)
}
