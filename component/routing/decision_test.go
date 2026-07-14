/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestDecisionSeparatesDeferredAndResolvedStates(t *testing.T) {
	deferred, err := NewDeferredDecision(Continuation{Epoch: 3, RuleIndex: 2}, EvidenceTLSSNI)
	if err != nil {
		t.Fatalf("NewDeferredDecision() error = %v", err)
	}
	if deferred.State != DecisionDeferred || deferred.Execution != ExecutionUndetermined {
		t.Fatalf("unexpected deferred decision: %+v", deferred)
	}

	resolved, err := NewResolvedDecision(3, ExecutionUserspace, 7, 42, true, EvidenceTLSSNI)
	if err != nil {
		t.Fatalf("NewResolvedDecision() error = %v", err)
	}
	if resolved.State != DecisionResolved || resolved.Outbound != 7 || !resolved.Must {
		t.Fatalf("unexpected resolved decision: %+v", resolved)
	}
	if err := resolved.Validate(); err != nil {
		t.Fatalf("resolved Validate() error = %v", err)
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
		Outbound:  consts.OutboundDirect,
		Continuation: Continuation{
			Epoch:     1,
			RuleIndex: 0,
		},
	}
	if err := decision.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want continuation rejection")
	}
}
