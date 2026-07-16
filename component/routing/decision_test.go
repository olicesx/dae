/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"crypto/sha256"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestDecisionSeparatesDeferredAndResolvedStates(t *testing.T) {
	deferred, err := NewDeferredDecision(Continuation{Epoch: 3, SnapshotHash: [sha256.Size]byte{1}, RuleIndex: 2}, EvidenceTLSSNI)
	if err != nil {
		t.Fatalf("NewDeferredDecision() error = %v", err)
	}
	if deferred.State != DecisionDeferred || deferred.Execution != ExecutionUndetermined {
		t.Fatalf("unexpected deferred decision: %+v", deferred)
	}

	resolved, err := NewResolvedDecision(
		PolicyEvaluation{Epoch: 3, State: DecisionResolved, RuleIndex: 1},
		2,
		ExecutionUserspace,
		BindingProfileProxy,
		7,
		42,
		true,
		EvidenceTLSSNI,
	)
	if err != nil {
		t.Fatalf("NewResolvedDecision() error = %v", err)
	}
	if resolved.State != DecisionResolved || resolved.Outbound != 7 || !resolved.Must {
		t.Fatalf("unexpected resolved decision: %+v", resolved)
	}
	if err := resolved.Validate(); err != nil {
		t.Fatalf("resolved Validate() error = %v", err)
	}
	if resolved.Rule.RuleIndex != 1 || resolved.Rule.RuleCount != 2 || resolved.Rule.IsFallback() {
		t.Fatalf("resolved rule location = %+v, want rule 1 of 2", resolved.Rule)
	}
	if resolved.Binding != BindingProfileProxy {
		t.Fatalf("resolved binding = %v, want proxy", resolved.Binding)
	}

	fallback, err := NewResolvedDecision(
		PolicyEvaluation{Epoch: 3, State: DecisionResolved, RuleIndex: 2},
		2,
		ExecutionKernel,
		BindingProfileDirect,
		consts.OutboundDirect,
		0,
		false,
		EvidenceNone,
	)
	if err != nil {
		t.Fatalf("NewResolvedDecision() fallback error = %v", err)
	}
	if !fallback.Rule.IsFallback() {
		t.Fatalf("fallback rule location = %+v, want fallback", fallback.Rule)
	}
}

func TestDecisionRejectsMixedState(t *testing.T) {
	decision := Decision{
		Epoch:        1,
		State:        DecisionDeferred,
		Execution:    ExecutionKernel,
		Outbound:     consts.OutboundDirect,
		Continuation: Continuation{Epoch: 1, RuleIndex: 0},
	}
	if err := decision.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want mixed deferred state rejection")
	}

	decision = Decision{
		Epoch:     1,
		State:     DecisionResolved,
		Execution: ExecutionUserspace,
		Rule:      RuleLocation{RuleIndex: 0, RuleCount: 1},
		Binding:   BindingProfileDirect,
		Outbound:  consts.OutboundDirect,
		Continuation: Continuation{
			Epoch:     1,
			RuleIndex: 0,
		},
	}
	if err := decision.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want continuation rejection")
	}

	decision = Decision{
		Epoch:    1,
		State:    DecisionDeferred,
		Outbound: consts.OutboundUserDefinedMin,
		Continuation: Continuation{
			Epoch:        1,
			SnapshotHash: [sha256.Size]byte{1},
			RuleIndex:    0,
		},
	}
	if err := decision.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want deferred outbound rejection")
	}

	decision = Decision{
		Epoch:        1,
		State:        DecisionDeferred,
		Continuation: Continuation{Epoch: 1, RuleIndex: 0},
	}
	if err := decision.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want unbound continuation rejection")
	}
}

func TestDecisionRejectsInvalidResolvedContract(t *testing.T) {
	tests := []struct {
		name     string
		decision Decision
	}{
		{
			name: "kernel_proxy",
			decision: Decision{
				Epoch:     1,
				State:     DecisionResolved,
				Execution: ExecutionKernel,
				Rule:      RuleLocation{RuleIndex: 0, RuleCount: 1},
				Binding:   BindingProfileProxy,
				Outbound:  consts.OutboundUserDefinedMin,
			},
		},
		{
			name: "userspace_block",
			decision: Decision{
				Epoch:     1,
				State:     DecisionResolved,
				Execution: ExecutionUserspace,
				Rule:      RuleLocation{RuleIndex: 0, RuleCount: 1},
				Binding:   BindingProfileBlock,
				Outbound:  consts.OutboundBlock,
			},
		},
		{
			name: "direct_with_proxy_binding",
			decision: Decision{
				Epoch:     1,
				State:     DecisionResolved,
				Execution: ExecutionKernel,
				Rule:      RuleLocation{RuleIndex: 0, RuleCount: 1},
				Binding:   BindingProfileProxy,
				Outbound:  consts.OutboundDirect,
			},
		},
		{
			name: "marked_kernel_direct",
			decision: Decision{
				Epoch:     1,
				State:     DecisionResolved,
				Execution: ExecutionKernel,
				Rule:      RuleLocation{RuleIndex: 0, RuleCount: 1},
				Binding:   BindingProfileDirect,
				Outbound:  consts.OutboundDirect,
				Mark:      42,
			},
		},
		{
			name: "control_plane_sentinel",
			decision: Decision{
				Epoch:     1,
				State:     DecisionResolved,
				Execution: ExecutionUserspace,
				Rule:      RuleLocation{RuleIndex: 0, RuleCount: 1},
				Binding:   BindingProfileUnspecified,
				Outbound:  consts.OutboundControlPlaneRouting,
			},
		},
		{
			name: "rule_outside_snapshot",
			decision: Decision{
				Epoch:     1,
				State:     DecisionResolved,
				Execution: ExecutionKernel,
				Rule:      RuleLocation{RuleIndex: 2, RuleCount: 1},
				Binding:   BindingProfileDirect,
				Outbound:  consts.OutboundDirect,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.decision.Validate(); err == nil {
				t.Fatalf("Validate() error = nil for %+v", tc.decision)
			}
		})
	}
}

func TestNewResolvedDecisionRejectsNonterminalEvaluation(t *testing.T) {
	_, err := NewResolvedDecision(
		PolicyEvaluation{
			Epoch:        1,
			State:        DecisionDeferred,
			RuleIndex:    0,
			Continuation: Continuation{Epoch: 1, RuleIndex: 0},
		},
		1,
		ExecutionKernel,
		BindingProfileDirect,
		consts.OutboundDirect,
		0,
		false,
		EvidenceNone,
	)
	if err == nil {
		t.Fatal("NewResolvedDecision() error = nil, want nonterminal evaluation rejection")
	}
}
