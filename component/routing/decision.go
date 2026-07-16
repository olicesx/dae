/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"crypto/sha256"
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

// BindingProfile describes the kind of flow binding a resolved policy choice
// creates. ExecutionRequirement remains separate because a direct policy can
// still require userspace handling, for example for a DNS query.
type BindingProfile uint8

const (
	BindingProfileUnspecified BindingProfile = iota
	BindingProfileDirect
	BindingProfileBlock
	BindingProfileProxy
)

// Continuation identifies the earliest immutable predicate instruction that
// could still change the outcome when more facts arrive. InstructionID is -1
// only for a rule-level continuation with no lowered predicate group. It
// contains no runtime pointers; callers retain the matching PolicySnapshot
// while the continuation is live.
type Continuation struct {
	Epoch         PolicyEpoch
	SnapshotHash  [sha256.Size]byte
	RuleIndex     int
	InstructionID int
}

// RuleLocation identifies the resolved rule within an immutable policy
// snapshot. RuleIndex equal to RuleCount denotes the fallback position.
type RuleLocation struct {
	RuleIndex int
	RuleCount int
}

// IsFallback reports whether this location identifies the snapshot fallback.
func (l RuleLocation) IsFallback() bool {
	return l.RuleIndex == l.RuleCount
}

// Decision is an immutable routing result shared between kernel, userspace,
// DNS, sniffing, and flow-binding adapters. It contains a policy choice, not a
// concrete dialer selection.
type Decision struct {
	Epoch        PolicyEpoch
	State        DecisionState
	Execution    ExecutionRequirement
	Rule         RuleLocation
	Binding      BindingProfile
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

// NewResolvedDecision creates a policy-complete result from an exact resolved
// PolicyEvaluation. RuleCount is the immutable snapshot's rule count, making
// the fallback location explicit without inferring it from the outbound.
func NewResolvedDecision(
	evaluation PolicyEvaluation,
	ruleCount int,
	execution ExecutionRequirement,
	binding BindingProfile,
	outbound consts.OutboundIndex,
	mark uint32,
	must bool,
	evidence EvidenceSource,
) (Decision, error) {
	if evaluation.State != DecisionResolved {
		return Decision{}, fmt.Errorf("resolved decision requires a resolved policy evaluation")
	}
	if evaluation.Continuation != (Continuation{}) {
		return Decision{}, fmt.Errorf("resolved policy evaluation has continuation")
	}
	decision := Decision{
		Epoch:     evaluation.Epoch,
		State:     DecisionResolved,
		Execution: execution,
		Rule: RuleLocation{
			RuleIndex: evaluation.RuleIndex,
			RuleCount: ruleCount,
		},
		Binding:  binding,
		Outbound: outbound,
		Mark:     mark,
		Must:     must,
		Evidence: evidence,
	}
	return decision, decision.Validate()
}

// BindingProfileFor returns the binding class implied by a policy-terminal
// outbound. Logical and control-plane sentinel outbounds are not terminal.
func BindingProfileFor(outbound consts.OutboundIndex) (BindingProfile, error) {
	switch outbound {
	case consts.OutboundDirect:
		return BindingProfileDirect, nil
	case consts.OutboundBlock:
		return BindingProfileBlock, nil
	case consts.OutboundControlPlaneRouting, consts.OutboundMustRules,
		consts.OutboundLogicalOr, consts.OutboundLogicalAnd:
		return BindingProfileUnspecified, fmt.Errorf("outbound %v is not policy terminal", outbound)
	default:
		if outbound < consts.OutboundUserDefinedMin || outbound > consts.OutboundUserDefinedMax {
			return BindingProfileUnspecified, fmt.Errorf("invalid outbound %d", outbound)
		}
		return BindingProfileProxy, nil
	}
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
		if d.Rule != (RuleLocation{}) {
			return fmt.Errorf("deferred decision has resolved rule location")
		}
		if d.Binding != BindingProfileUnspecified {
			return fmt.Errorf("deferred decision has binding profile")
		}
		if d.Mark != 0 || d.Must {
			return fmt.Errorf("deferred decision has terminal route fields")
		}
		if d.Outbound != 0 {
			return fmt.Errorf("deferred decision has terminal outbound %v", d.Outbound)
		}
		if d.Continuation.Epoch != d.Epoch {
			return fmt.Errorf("continuation epoch does not match decision epoch")
		}
		if d.Continuation.RuleIndex < 0 {
			return fmt.Errorf("continuation rule index is negative")
		}
		if d.Continuation.SnapshotHash == ([sha256.Size]byte{}) {
			return fmt.Errorf("continuation has no policy snapshot hash")
		}
		if d.Continuation.InstructionID < -1 {
			return fmt.Errorf("continuation instruction index is invalid")
		}
	case DecisionResolved:
		if d.Execution == ExecutionUndetermined {
			return fmt.Errorf("resolved decision has no execution requirement")
		}
		if d.Continuation != (Continuation{}) {
			return fmt.Errorf("resolved decision has continuation")
		}
		if err := d.Rule.validate(); err != nil {
			return fmt.Errorf("resolved decision rule location: %w", err)
		}
		expectedBinding, err := BindingProfileFor(d.Outbound)
		if err != nil {
			return fmt.Errorf("resolved decision outbound: %w", err)
		}
		if d.Binding != expectedBinding {
			return fmt.Errorf("resolved decision binding profile %d does not match outbound %v", d.Binding, d.Outbound)
		}
		if err := validateResolvedExecution(d.Execution, d.Outbound, d.Mark); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown decision state: %d", d.State)
	}
	return nil
}

func (l RuleLocation) validate() error {
	if l.RuleCount < 0 {
		return fmt.Errorf("rule count is negative")
	}
	if l.RuleIndex < 0 || l.RuleIndex > l.RuleCount {
		return fmt.Errorf("rule index %d is outside [0, %d]", l.RuleIndex, l.RuleCount)
	}
	return nil
}

func validateResolvedExecution(execution ExecutionRequirement, outbound consts.OutboundIndex, mark uint32) error {
	switch execution {
	case ExecutionKernel:
		switch outbound {
		case consts.OutboundDirect:
			if mark != 0 {
				return fmt.Errorf("kernel direct decision has mark %d", mark)
			}
		case consts.OutboundBlock:
		default:
			return fmt.Errorf("kernel decision cannot execute outbound %v", outbound)
		}
	case ExecutionUserspace:
		if outbound == consts.OutboundBlock {
			return fmt.Errorf("userspace decision cannot execute block outbound")
		}
	default:
		return fmt.Errorf("unknown resolved execution requirement: %d", execution)
	}
	return nil
}
