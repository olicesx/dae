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

const phase4DecisionShadowSampleEveryEnv = "DAE_PHASE4_DECISION_SHADOW_SAMPLE_EVERY"

func phase4DecisionShadowSampleEveryFromEnvironment() (uint64, bool, error) {
	value, present := os.LookupEnv(phase4DecisionShadowSampleEveryEnv)
	return phase4DecisionShadowSampleEveryFromValue(value, present)
}

func phase4DecisionShadowSampleEveryFromValue(value string, present bool) (uint64, bool, error) {
	if !present || value == "" {
		return 0, false, nil
	}
	sampleEvery, err := strconv.ParseUint(value, 10, 64)
	if err != nil || sampleEvery == 0 {
		return 0, false, fmt.Errorf("%s must be a positive unsigned integer, got %q", phase4DecisionShadowSampleEveryEnv, value)
	}
	return sampleEvery, true, nil
}

func enablePhase4DecisionShadowFromEnvironment() (*control.Phase4DecisionShadowHandle, error) {
	sampleEvery, enabled, err := phase4DecisionShadowSampleEveryFromEnvironment()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	return control.EnablePhase4DecisionShadow(sampleEvery)
}
