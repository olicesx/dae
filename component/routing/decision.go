/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
)

// EvidenceSource identifies how the domain fact used by a routing decision was obtained.
type EvidenceSource uint8

const (
	EvidenceNone EvidenceSource = iota
	EvidenceDNSAssociation
	EvidenceTLSSNI
	EvidenceQUICSNI
)

// DecisionState separates a complete policy result from a result that needs
// more routing facts. A policy-complete proxy decision can still require
// userspace transport setup.
type DecisionState uint8

const (
	DecisionDeferred DecisionState = iota
	DecisionResolved
)

// ExecutionRequirement describes where a policy-complete decision must run.
type ExecutionRequirement uint8

const (
	ExecutionUndetermined ExecutionRequirement = iota
	ExecutionKernel
	ExecutionUserspace
)

// Continuation identifies the earliest rule that could still change the
// outcome when more facts arrive. It is meaningful only for a deferred
// decision and cannot outlive its policy epoch.
type Continuation struct {
	Epoch     PolicyEpoch
	RuleIndex int
}

// Decision is an immutable routing result shared between kernel, userspace,
// DNS, sniffing, and flow-binding adapters. It contains a policy choice, not a
// concrete dialer selection.
type Decision struct {
	Epoch        PolicyEpoch
	State        DecisionState
	Execution    ExecutionRequirement
	Outbound     consts.OutboundIndex
	Mark         uint32
	Must         bool
	Evidence     EvidenceSource
	Continuation Continuation
}

// NewDeferredDecision creates a result that must wait for an earlier rule's
// missing fact before selecting an outbound.
func NewDeferredDecision(continuation Continuation, evidence EvidenceSource) (Decision, error) {
	decision := Decision{
		Epoch:        continuation.Epoch,
		State:        DecisionDeferred,
		Evidence:     evidence,
		Continuation: continuation,
	}
	return decision, decision.Validate()
}

// NewResolvedDecision creates a policy-complete result. Execution explicitly
// distinguishes direct kernel execution from a proxy decision that must enter
// userspace for transport setup.
func NewResolvedDecision(
	epoch PolicyEpoch,
	execution ExecutionRequirement,
	outbound consts.OutboundIndex,
	mark uint32,
	must bool,
	evidence EvidenceSource,
) (Decision, error) {
	decision := Decision{
		Epoch:     epoch,
		State:     DecisionResolved,
		Execution: execution,
		Outbound:  outbound,
		Mark:      mark,
		Must:      must,
		Evidence:  evidence,
	}
	return decision, decision.Validate()
}

// Validate checks the invariants that prevent deferred and resolved decisions
// from being confused at component boundaries.
func (d Decision) Validate() error {
	if d.Epoch == 0 {
		return fmt.Errorf("decision policy epoch must be non-zero")
	}
	switch d.State {
	case DecisionDeferred:
		if d.Execution != ExecutionUndetermined {
			return fmt.Errorf("deferred decision has execution requirement")
		}
		if d.Continuation.Epoch != d.Epoch {
			return fmt.Errorf("continuation epoch does not match decision epoch")
		}
		if d.Continuation.RuleIndex < 0 {
			return fmt.Errorf("continuation rule index is negative")
		}
	case DecisionResolved:
		if d.Execution == ExecutionUndetermined {
			return fmt.Errorf("resolved decision has no execution requirement")
		}
		if d.Continuation != (Continuation{}) {
			return fmt.Errorf("resolved decision has continuation")
		}
	default:
		return fmt.Errorf("unknown decision state: %d", d.State)
	}
	return nil
}
