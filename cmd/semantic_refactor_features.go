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

// defaultSemanticRefactorFeatures returns the production default set of
// semantic-refactor execution paths.
//
// Both UDP dispatchers use bounded schedulers:
//
//   - Queue lookup uses sync.Map and unrelated flows synchronize only on their
//     own queue locks.
//   - A fixed worker cap bounds goroutine and timer pressure under
//     high-cardinality UDP traffic.
//   - Per-endpoint reply backpressure remains owned by
//     UdpEndpoint.replyRuntime.slots.
//
// Both are enabled by default. Opt out via DAE_SEMANTIC_REFACTOR_FEATURES=none
// or pick a subset.
func defaultSemanticRefactorFeatures() []control.SemanticRefactorFeature {
	return []control.SemanticRefactorFeature{
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
		// Apply production defaults. Callers can opt out with "none" or pick a
		// subset by listing feature names in DAE_SEMANTIC_REFACTOR_FEATURES.
		defaults := defaultSemanticRefactorFeatures()
		return defaults, len(defaults) > 0, nil
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
