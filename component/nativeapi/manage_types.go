/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import "context"

// NodeCapabilities describes what a provider allows control callers to do with
// nodes. Only the nodes written in the managed node source are editable; a node
// that a subscription or file provider delivered is managed by that provider.
type NodeCapabilities struct {
	// CanManage reports whether inline nodes can be created, updated and
	// deleted.
	CanManage bool
}

// NodeCreateRequest asks the provider to add one inline node.
type NodeCreateRequest struct {
	Name           string
	Link           string
	IdempotencyKey string
}

// NodeDeleteRequest asks the provider to remove one inline node.
type NodeDeleteRequest struct {
	NodeID         string
	IdempotencyKey string
}

// NodeDeleteOutcome reports what a delete did. Deleted is zero when nothing was
// queued, which makes an unknown id answer 200 with deleted 0 the way the
// contract requires.
type NodeDeleteOutcome struct {
	Accepted OperationAccepted
	Deleted  int
}

// NodeUpdateRequest asks the provider to change one inline node. A nil Name or
// Link keeps the current value; the caller sets at least one of them.
type NodeUpdateRequest struct {
	NodeID         string
	Name           *string
	Link           *string
	IdempotencyKey string
}

// NodeUpdateOutcome reports what an update did. Updated is zero when the
// request named the values the node already has, which answers 200 with
// updated 0 instead of writing the same line and starting a reload.
type NodeUpdateOutcome struct {
	Accepted OperationAccepted
	Updated  int
}

// ProviderCapabilities describes provider actions beyond listing.
type ProviderCapabilities struct {
	// CanRefresh reports whether a subscription can be refetched on demand.
	CanRefresh bool
	// CanManage reports whether subscription providers can be created and
	// subscription or file providers deleted in the managed configuration.
	CanManage bool
	// CreateUnfetched reports that a created provider loads nothing until it
	// is refreshed. False means the engine fetches it during activation and
	// reports its actual state.
	CreateUnfetched bool
	// CreateOptions lists the ProviderCreate fields the engine accepts beyond
	// name, kind and url, each with the value applied when the field is
	// omitted. A field that is not listed is unsupported.
	CreateOptions map[string]any
}

// ProviderCreateRequest asks the provider to add one subscription. The
// optional fields follow ProviderCapabilities.CreateOptions.
type ProviderCreateRequest struct {
	Name           string
	URL            string
	UpdateInterval *int
	UserAgent      *string
	Cache          *bool
	IdempotencyKey string
}

// ProviderCreateOutcome reports what a create did: a queued operation, or the
// provider once it is active.
type ProviderCreateOutcome struct {
	Accepted OperationAccepted
	Provider *Provider
}

// ProviderDeleteRequest asks the provider to remove one subscription or file
// provider.
type ProviderDeleteRequest struct {
	ProviderID     string
	IdempotencyKey string
}

// ProviderDeleteOutcome reports what a delete did. Deleted is zero when
// nothing was queued, which makes an unknown id answer 200 with deleted 0 the
// way the contract requires.
type ProviderDeleteOutcome struct {
	Accepted OperationAccepted
	Deleted  int
}

// ProviderRefreshRequest asks the provider to refetch one subscription.
type ProviderRefreshRequest struct {
	ProviderID     string
	IdempotencyKey string
}

// ProviderManager writes providers into the managed configuration. It is
// optional: a ProviderProvider that does not implement it is read-only.
type ProviderManager interface {
	// CreateProvider writes one subscription provider into the managed
	// configuration.
	CreateProvider(ctx context.Context, req ProviderCreateRequest) (ProviderCreateOutcome, error)
	// DeleteProvider removes one subscription or file provider from the
	// managed configuration.
	DeleteProvider(ctx context.Context, req ProviderDeleteRequest) (ProviderDeleteOutcome, error)
}
