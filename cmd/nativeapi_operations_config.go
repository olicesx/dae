/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"

	"github.com/daeuniverse/dae/component/nativeapi"
)

// configWriteCompletion receives whether the candidate became active. A nil
// outcome means activation was interrupted and could not be established.
type configWriteCompletion func(committed *bool) *nativeapi.SafeError

type configCreateQueue interface {
	StartConfigCreate(ctx context.Context, scope, idempotencyKey string, complete configWriteCompletion) (nativeapi.OperationAccepted, error)
}

func (o *nativeAPIOperations) StartConfigCreate(ctx context.Context, scope, idempotencyKey string, complete configWriteCompletion) (nativeapi.OperationAccepted, error) {
	return o.startReloadOperation(ctx, nativeapi.OperationKindReload, scope, idempotencyKey, nil, complete)
}

// StartConfigUpdate queues a reload with both the source completion hook and
// the successful operation result resolver.
func (o *nativeAPIOperations) StartConfigUpdate(ctx context.Context, kind, scope, idempotencyKey string, resolve func() (any, error), complete configWriteCompletion) (nativeapi.OperationAccepted, error) {
	return o.startReloadOperation(ctx, kind, scope, idempotencyKey, resolve, complete)
}

func (o *nativeAPIOperations) setConfigWriteCompletion(id string, complete configWriteCompletion) {
	if complete == nil {
		return
	}
	o.resultMu.Lock()
	defer o.resultMu.Unlock()
	if o.configWriteCompletions == nil {
		o.configWriteCompletions = make(map[string]configWriteCompletion)
	}
	o.configWriteCompletions[id] = complete
}

func (o *nativeAPIOperations) takeConfigWriteCompletion(id string) configWriteCompletion {
	o.resultMu.Lock()
	defer o.resultMu.Unlock()
	complete := o.configWriteCompletions[id]
	delete(o.configWriteCompletions, id)
	return complete
}

// Called after closing reload admission. Shutdown may interrupt a reload
// after publication, so its outcome is unknown and config writes stay on disk.
func (o *nativeAPIOperations) finishInterruptedConfigCreates() {
	o.resultMu.Lock()
	pending := o.configWriteCompletions
	o.configWriteCompletions = nil
	o.resultMu.Unlock()
	for id, complete := range pending {
		o.takeResultResolver(id)
		o.store.Fail(id, complete(nil))
		o.events.publishOperationUpdated(id, "failed")
	}
}
