/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/daeuniverse/dae/control"
)

const (
	semanticRefactorFeaturesEnv  = "DAE_SEMANTIC_REFACTOR_FEATURES"
	semanticRefactorDisableValue = "none"
)

// defaultSemanticRefactorFeatures lists every semantic-refactor execution
// path that is enabled by default for production dae runs.
//
// The UDP dispatchers were previously excluded because a mutex+worker-pool
// implementation regressed 2x-2.5x under high concurrency. They have since
// been rewritten to match the lock-free DefaultUdpTaskPool design
// (sync.Map + atomic refs + per-flow convoy goroutine) and now match legacy
// throughput in BenchmarkUDPOrderedDispatcherSubmitDrain. Users can still opt
// out via DAE_SEMANTIC_REFACTOR_FEATURES=none or pick a subset.
func defaultSemanticRefactorFeatures() []control.SemanticRefactorFeature {
	return []control.SemanticRefactorFeature{
		control.SemanticRefactorFeatureCompiledPolicy,
		control.SemanticRefactorFeatureRoutingEpoch,
		control.SemanticRefactorFeatureDNSResolver,
		control.SemanticRefactorFeatureUDPOrderedDispatcher,
		control.SemanticRefactorFeatureUDPReplyDispatcher,
	}
}

func semanticRefactorFeaturesFromEnvironment() ([]control.SemanticRefactorFeature, bool, error) {
	value, present := os.LookupEnv(semanticRefactorFeaturesEnv)
	return semanticRefactorFeaturesFromValue(value, present)
}

func semanticRefactorFeaturesFromValue(value string, present bool) ([]control.SemanticRefactorFeature, bool, error) {
	if !present || value == "" {
		// Default: enable every semantic-refactor path. This makes the new
		// architecture the production experience; opt out with "none" or a
		// comma-separated subset.
		features := defaultSemanticRefactorFeatures()
		return features, true, nil
	}
	if value == semanticRefactorDisableValue {
		return nil, false, nil
	}
	parts := strings.Split(value, ",")
	features := make([]control.SemanticRefactorFeature, 0, len(parts))
	seen := make(map[control.SemanticRefactorFeature]struct{}, len(parts))
	for _, part := range parts {
		feature, err := control.ParseSemanticRefactorFeature(part)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", semanticRefactorFeaturesEnv, err)
		}
		if _, duplicate := seen[feature]; duplicate {
			return nil, false, fmt.Errorf("%s repeats feature %q", semanticRefactorFeaturesEnv, feature)
		}
		seen[feature] = struct{}{}
		features = append(features, feature)
	}
	return features, true, nil
}

func enableSemanticRefactorFeaturesFromEnvironment() (*control.SemanticRefactorFeatureGateHandle, error) {
	features, enabled, err := semanticRefactorFeaturesFromEnvironment()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	return control.EnableSemanticRefactorFeatures(features...)
}
