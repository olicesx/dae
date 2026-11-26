/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
)

// The contract requires only content: id is request-local and path is optional.
// A content-only source is merged over the accepted configuration instead of
// being rejected with 404.
func TestConfigValidateAcceptsContentOnlySource(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})

	content := "routing {\n    fallback: direct\n}\n"
	result, err := e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode:    "full",
		Sources: []nativeapi.ConfigValidationSource{{Content: &content}},
	})
	if err != nil {
		t.Fatalf("content-only source: %v", err)
	}
	if !result.Valid {
		t.Fatalf("candidate should be valid, diagnostics: %+v", result.Diagnostics)
	}

	// Syntax mode accepts it too.
	result, err = e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode:    "syntax",
		Sources: []nativeapi.ConfigValidationSource{{Content: &content}},
	})
	if err != nil || !result.Valid {
		t.Fatalf("syntax mode: result=%+v err=%v", result, err)
	}
}

// Every diagnostic names a source: the contract requires an ID of at least one
// character. An error that names no file belongs to the candidate as a whole,
// which the contract anchors on its first source.
func TestConfigValidateUnattributedErrorNamesTheMainSource(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})

	// Parses, but is no routing rule: the failure surfaces while the candidate
	// is built, and nothing in the error names a file.
	bad := "routing {\n  rules {\n  this is not a rule\n  }\n}\n"
	for _, tc := range []struct{ id, want string }{{"", "source-1"}, {"candidate", "candidate"}} {
		result, err := e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
			Mode:    "full",
			Sources: []nativeapi.ConfigValidationSource{{ID: tc.id, Content: &bad}},
		})
		if err != nil {
			t.Fatalf("id %q: %v", tc.id, err)
		}
		if result.Valid || len(result.Diagnostics) == 0 {
			t.Fatalf("id %q: expected diagnostics, got %+v", tc.id, result)
		}
		if got := result.Diagnostics[0].SourceID; got != tc.want {
			t.Fatalf("id %q: diagnostic source id = %q, want %q", tc.id, got, tc.want)
		}
	}
}

// An overridden file is known to the request by the ID it was submitted under,
// and its syntax errors are reported under that ID.
func TestConfigValidateOverrideSyntaxErrorNamesTheOverriddenSource(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})
	target := flowSource(t, e, flowGlobalRel)

	bad := "global {\n"
	result, err := e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode:    "syntax",
		Sources: []nativeapi.ConfigValidationSource{{ID: target.id, Content: &bad}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Diagnostics) == 0 {
		t.Fatalf("expected diagnostics, got %+v", result)
	}
	if got := result.Diagnostics[0].SourceID; got != target.id {
		t.Fatalf("diagnostic source id = %q, want the overridden source %q", got, target.id)
	}
}

// The node editor validates its rewritten node block under a label of its own
// before writing the source. That label is request-local, so an id the tree does
// not know must be a candidate rather than a 404.
func TestConfigValidateAcceptsAnUnknownRequestLocalID(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})

	content := "node {\n  hk-01: 'socks5://user:pass@192.0.2.10:1080'\n}\n"
	result, err := e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode:    "syntax",
		Sources: []nativeapi.ConfigValidationSource{{ID: "node", Content: &content}},
	})
	if err != nil {
		t.Fatalf("request-local id: %v", err)
	}
	if !result.Valid {
		t.Fatalf("candidate should be valid, diagnostics: %+v", result.Diagnostics)
	}

	// A label still names the diagnostics: a broken block reports under it.
	bad := "node {\n  hk-01: 'socks5://\n"
	result, err = e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode:    "syntax",
		Sources: []nativeapi.ConfigValidationSource{{ID: "node", Content: &bad}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Diagnostics) == 0 {
		t.Fatalf("expected diagnostics, got %+v", result)
	}
	if result.Diagnostics[0].SourceID != "node" {
		t.Fatalf("source id = %q, want node (the request-local label)", result.Diagnostics[0].SourceID)
	}
}

func TestConfigValidateContentOnlyReportsItsOwnSourceID(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})

	bad := "global {\n"
	result, err := e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode:    "syntax",
		Sources: []nativeapi.ConfigValidationSource{{Content: &bad}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Diagnostics) == 0 {
		t.Fatalf("expected diagnostics, got %+v", result)
	}
	if result.Diagnostics[0].SourceID != "source-1" {
		t.Fatalf("source id = %q, want source-1 (the contract's default)", result.Diagnostics[0].SourceID)
	}
}
