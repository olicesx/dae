/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

// LegacyRouteOutcome is the policy-terminal tuple returned by the legacy
// userspace matcher. It deliberately excludes runtime dialer selection so the
// shadow adapter cannot affect transport behavior.
type LegacyRouteOutcome struct {
	Outbound consts.OutboundIndex
	Mark     uint32
	Must     bool
}

// LegacyRouteExecutionFacts are the transport facts that affect where a
// policy-terminal legacy route result executes. They are values only so the
// shadow adapter cannot affect forwarding behavior.
type LegacyRouteExecutionFacts struct {
	DstPort uint16
	L4Proto consts.L4ProtoType
}

func (f LegacyRouteExecutionFacts) isDNSQuery() bool {
	return f.DstPort == 53 &&
		(f.L4Proto == consts.L4ProtoType_TCP || f.L4Proto == consts.L4ProtoType_UDP)
}

// AdaptLegacyRouteOutcome converts a policy-terminal legacy matcher result to
// an immutable resolved Decision. evaluation supplies the exact normalized
// rule location, including fallback, without inferring it from the outbound.
// It is intended for shadow evaluation only; callers must continue to use the
// legacy tuple as the authoritative result.
func AdaptLegacyRouteOutcome(
	snapshot *routing.PolicySnapshot,
	evaluation routing.PolicyEvaluation,
	outcome LegacyRouteOutcome,
	facts LegacyRouteExecutionFacts,
	evidence routing.EvidenceSource,
) (routing.Decision, error) {
	if snapshot == nil {
		return routing.Decision{}, fmt.Errorf("nil policy snapshot")
	}
	if snapshot.Epoch() == 0 {
		return routing.Decision{}, fmt.Errorf("legacy route decision requires a non-zero policy epoch")
	}
	if evaluation.Epoch != snapshot.Epoch() {
		return routing.Decision{}, fmt.Errorf("policy evaluation epoch %d does not match snapshot epoch %d", evaluation.Epoch, snapshot.Epoch())
	}

	execution, err := executionForLegacyRouteOutcome(outcome, facts)
	if err != nil {
		return routing.Decision{}, err
	}
	binding, err := routing.BindingProfileFor(outcome.Outbound)
	if err != nil {
		return routing.Decision{}, err
	}
	return routing.NewResolvedDecision(
		evaluation,
		snapshot.RuleCount(),
		execution,
		binding,
		outcome.Outbound,
		outcome.Mark,
		outcome.Must,
		evidence,
	)
}

func executionForLegacyRouteOutcome(outcome LegacyRouteOutcome, facts LegacyRouteExecutionFacts) (routing.ExecutionRequirement, error) {
	switch outcome.Outbound {
	case consts.OutboundDirect:
		// The kernel preserves the direct fast path only when no mark needs
		// userspace socket handling. Non-must DNS queries are handed to the
		// control plane even when their terminal policy result is direct.
		if outcome.Mark == 0 {
			if !outcome.Must && facts.isDNSQuery() {
				return routing.ExecutionUserspace, nil
			}
			return routing.ExecutionKernel, nil
		}
		return routing.ExecutionUserspace, nil
	case consts.OutboundBlock:
		return routing.ExecutionKernel, nil
	case consts.OutboundControlPlaneRouting, consts.OutboundMustRules,
		consts.OutboundLogicalOr, consts.OutboundLogicalAnd:
		return routing.ExecutionUndetermined, fmt.Errorf(
			"legacy route outcome %v is not policy terminal", outcome.Outbound,
		)
	default:
		if outcome.Outbound < consts.OutboundUserDefinedMin || outcome.Outbound > consts.OutboundUserDefinedMax {
			return routing.ExecutionUndetermined, fmt.Errorf(
				"invalid legacy route outbound %d", outcome.Outbound,
			)
		}
		// User-defined outbounds always need userspace transport selection.
		return routing.ExecutionUserspace, nil
	}
}
