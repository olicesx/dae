/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"sync/atomic"
)

// SemanticRefactorFeature identifies one internal, opt-in execution path from
// the semantic architecture migration. These gates deliberately do not affect
// the user-facing configuration language.
type SemanticRefactorFeature string

const (
	// SemanticRefactorFeatureCompiledPolicy lets the immutable compiled policy
	// build the kernel and userspace matchers.
	SemanticRefactorFeatureCompiledPolicy SemanticRefactorFeature = "compiled-policy"
	// SemanticRefactorFeatureRoutingEpoch lets BPF publication switch between
	// prepared routing epoch slots during reload.
	SemanticRefactorFeatureRoutingEpoch SemanticRefactorFeature = "routing-epoch"
	// SemanticRefactorFeatureDNSResolver lets the split Resolve/delivery DNS
	// pipeline serve requests.
	SemanticRefactorFeatureDNSResolver SemanticRefactorFeature = "dns-resolver"
	// SemanticRefactorFeatureUDPOrderedDispatcher lets ordered UDP ingress use
	// the bounded generation-owned dispatcher instead of one convoy per flow.
	SemanticRefactorFeatureUDPOrderedDispatcher SemanticRefactorFeature = "udp-ordered-dispatcher"
	// SemanticRefactorFeatureUDPReplyDispatcher lets UDP endpoint replies use
	// bounded generation-owned workers while preserving per-endpoint ordering.
	SemanticRefactorFeatureUDPReplyDispatcher SemanticRefactorFeature = "udp-reply-dispatcher"
)

var (
	// ErrSemanticRefactorFeatureAlreadyEnabled prevents concurrent owners from
	// changing process-wide migration gates during a daemon lifetime.
	ErrSemanticRefactorFeatureAlreadyEnabled = stderrors.New("semantic refactor feature gate is already enabled")
	// ErrSemanticRefactorFeatureEmpty rejects a handle that would not enable an
	// execution path.
	ErrSemanticRefactorFeatureEmpty = stderrors.New("semantic refactor feature gate has no features")
)

// SemanticRefactorFeatureSet is an immutable copy of the process-wide
// migration gate state used by each control-plane generation.
type SemanticRefactorFeatureSet struct {
	CompiledPolicy       bool
	RoutingEpoch         bool
	DNSResolver          bool
	UDPOrderedDispatcher bool
	UDPReplyDispatcher   bool
}

type semanticRefactorFeatureGateSetting struct {
	features SemanticRefactorFeatureSet
}

var semanticRefactorFeatureGateValue atomic.Pointer[semanticRefactorFeatureGateSetting]

// SemanticRefactorFeatureGateHandle owns an internal migration gate setting.
// Disable only clears the setting it created, so an old handle cannot affect a
// later owner.
type SemanticRefactorFeatureGateHandle struct {
	setting  *semanticRefactorFeatureGateSetting
	disabled atomic.Bool
}

// Enabled reports whether this handle owns the supplied migration feature.
func (h *SemanticRefactorFeatureGateHandle) Enabled(feature SemanticRefactorFeature) bool {
	if h == nil || h.setting == nil || h.disabled.Load() {
		return false
	}
	switch feature {
	case SemanticRefactorFeatureCompiledPolicy:
		return h.setting.features.CompiledPolicy
	case SemanticRefactorFeatureRoutingEpoch:
		return h.setting.features.RoutingEpoch
	case SemanticRefactorFeatureDNSResolver:
		return h.setting.features.DNSResolver
	case SemanticRefactorFeatureUDPOrderedDispatcher:
		return h.setting.features.UDPOrderedDispatcher
	case SemanticRefactorFeatureUDPReplyDispatcher:
		return h.setting.features.UDPReplyDispatcher
	default:
		return false
	}
}

// ParseSemanticRefactorFeature parses an internal migration feature name.
func ParseSemanticRefactorFeature(value string) (SemanticRefactorFeature, error) {
	feature := SemanticRefactorFeature(value)
	switch feature {
	case SemanticRefactorFeatureCompiledPolicy, SemanticRefactorFeatureRoutingEpoch, SemanticRefactorFeatureDNSResolver, SemanticRefactorFeatureUDPOrderedDispatcher, SemanticRefactorFeatureUDPReplyDispatcher:
		return feature, nil
	default:
		return "", fmt.Errorf("unknown semantic refactor feature %q", value)
	}
}

// EnableSemanticRefactorFeatures enables the supplied internal migration
// paths for subsequently built control-plane generations.
func EnableSemanticRefactorFeatures(features ...SemanticRefactorFeature) (*SemanticRefactorFeatureGateHandle, error) {
	setting := &semanticRefactorFeatureGateSetting{}
	for _, feature := range features {
		switch feature {
		case SemanticRefactorFeatureCompiledPolicy:
			setting.features.CompiledPolicy = true
		case SemanticRefactorFeatureRoutingEpoch:
			setting.features.RoutingEpoch = true
		case SemanticRefactorFeatureDNSResolver:
			setting.features.DNSResolver = true
		case SemanticRefactorFeatureUDPOrderedDispatcher:
			setting.features.UDPOrderedDispatcher = true
		case SemanticRefactorFeatureUDPReplyDispatcher:
			setting.features.UDPReplyDispatcher = true
		default:
			return nil, fmt.Errorf("unknown semantic refactor feature %q", feature)
		}
	}
	if setting.features == (SemanticRefactorFeatureSet{}) {
		return nil, ErrSemanticRefactorFeatureEmpty
	}
	if !semanticRefactorFeatureGateValue.CompareAndSwap(nil, setting) {
		return nil, ErrSemanticRefactorFeatureAlreadyEnabled
	}
	return &SemanticRefactorFeatureGateHandle{setting: setting}, nil
}

// Disable releases this handle's migration gate setting without affecting a
// newer owner.
func (h *SemanticRefactorFeatureGateHandle) Disable() {
	if h == nil || h.setting == nil || h.disabled.Swap(true) {
		return
	}
	semanticRefactorFeatureGateValue.CompareAndSwap(h.setting, nil)
}

func semanticRefactorFeatureGateSnapshot() SemanticRefactorFeatureSet {
	if setting := semanticRefactorFeatureGateValue.Load(); setting != nil {
		return setting.features
	}
	return SemanticRefactorFeatureSet{}
}

func requiresFullPolicySnapshot(features SemanticRefactorFeatureSet, shadow *phase4DecisionShadowSetting) bool {
	return features.CompiledPolicy || shadow != nil
}
