/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org
 */

package cmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

func noProviderNames() (map[string]bool, error) { return map[string]bool{}, nil }

func namesInUse(names ...string) providerIndexFunc {
	return func() (map[string]bool, error) {
		out := map[string]bool{}
		for _, name := range names {
			out[name] = true
		}
		return out, nil
	}
}

func locate(provider nativeapi.Provider, found bool, err error) providerLocator {
	return func() (nativeapi.Provider, bool, error) { return provider, found, err }
}

func createProviderOrFail(t *testing.T, e *configEditor, name, url string, names providerIndexFunc) nativeapi.OperationAccepted {
	t.Helper()
	accepted, err := e.CreateProvider(context.Background(), nativeapi.ProviderCreateRequest{Name: name, URL: url}, names, nil)
	if err != nil {
		t.Fatalf("CreateProvider(%q): %v", name, err)
	}
	return accepted
}

func TestParseProviderLine(t *testing.T) {
	cases := map[string]struct {
		tag  string
		link string
	}{
		"KL:'https://a.example/s?token=x'":           {"KL", "https://a.example/s?token=x"},
		"  XX: 'https://b.example/s' # trailing\n":   {"XX", "https://b.example/s"},
		"'my tag': \"https://c.example/s\"\n":        {"my tag", "https://c.example/s"},
		"file-nodes: 'file:///nodes.txt'\n":          {"file-nodes", "file:///nodes.txt"},
		"KL: https://a.example/s # comment\n":        {"KL", "https://a.example/s"},
		"\"https://d.example/s\"\n":                  {"", "https://d.example/s"},
		"https://e.example/s\n":                      {"", "https://e.example/s"},
		"subscription://https://f.example/s\n":       {"", "subscription://https://f.example/s"},
		"'tag':subscription://https://g.example/s\n": {"tag", "subscription://https://g.example/s"},
		"# a comment\n":                              {},
		"\n":                                         {},
		"'unterminated\n":                            {},
	}
	for line, want := range cases {
		tag, link, ok := parseProviderLine(line)
		if line == "# a comment\n" || line == "\n" || line == "'unterminated\n" {
			if ok {
				t.Fatalf("%q was read as an entry", line)
			}
			continue
		}
		if !ok || tag != want.tag || link != want.link {
			t.Fatalf("parseProviderLine(%q) = (%q, %q, %v), want (%q, %q)", line, tag, link, ok, want.tag, want.link)
		}
	}
}

func TestProviderEntryIDMatchesRunningIdentity(t *testing.T) {
	// The running generation keys a tagged provider by its tag and an untagged
	// one by a hash of its link; the file reader must derive the same IDs.
	tagged := providerEntry{tag: "KL", link: "https://a.example/s"}
	if got, want := providerEntryID(tagged), providerIDOf("KL"); got != want {
		t.Fatalf("tagged id = %q, want %q", got, want)
	}
	link := "https://b.example/s?token=secret"
	untagged := providerEntry{link: link}
	if got, want := providerEntryID(untagged), providerIDOf(subscription.ProviderKey("", link)); got != want {
		t.Fatalf("untagged id = %q, want %q", got, want)
	}
}

func TestProviderKindOf(t *testing.T) {
	for link, want := range map[string]string{
		"file:///etc/dae/nodes.txt":        "file",
		"my-nodes: 'file://nodes.txt'":     "file",
		"https://a.example/s":              "subscription",
		"subscription://https://a.example": "subscription",
	} {
		if got := providerKindOf(link); got != want {
			t.Fatalf("providerKindOf(%q) = %q, want %q", link, got, want)
		}
	}
}

func TestValidateProviderName(t *testing.T) {
	for _, name := range []string{"KL", "my_tag", "my-tag", "my.tag", "A1"} {
		if err := validateProviderName(name); err != nil {
			t.Fatalf("validateProviderName(%q) = %v, want accepted", name, err)
		}
	}
	// dae's grammar has no quoted key, so a tag is a bare word.
	for _, name := range []string{"my provider", "标签", "it's", "a/b", "", strings.Repeat("n", 65)} {
		if err := validateProviderName(name); err == nil {
			t.Fatalf("validateProviderName(%q) accepted a name the configuration cannot carry", name)
		}
	}
}

func TestConfigCreateProviderWritesManagedModule(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	accepted := createProviderOrFail(t, e, "provider-b", "https://subscriptions.example.com/sub?token=secret", noProviderNames)
	if accepted.Kind != nativeapi.OperationKindProviderCreate || accepted.OperationID == "" {
		t.Fatalf("accepted = %+v, want a queued provider_create", accepted)
	}
	if ops.calls != 1 {
		t.Fatalf("StartOperation calls = %d, want 1", ops.calls)
	}
	target := flowSource(t, e, "config.d/subscription.dae")
	content, _ := os.ReadFile(target.abs)
	if want := "subscription {\n  provider-b: 'https://subscriptions.example.com/sub?token=secret'\n}\n"; string(content) != want {
		t.Fatalf("subscription module = %q, want %q", content, want)
	}
	if bak, _ := os.ReadFile(target.abs + ".bak"); string(bak) != "subscription {}\n" {
		t.Fatalf("backup must hold the previous bytes: %q", bak)
	}
	// The other modules stay untouched.
	if node, _ := os.ReadFile(flowSource(t, e, "config.d/node.dae").abs); string(node) != "node {}\n" {
		t.Fatalf("node module changed: %q", node)
	}
}

func TestConfigCreateProviderRejectsNameTheConfigurationCannotCarry(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	for _, name := range []string{"my provider", "标签", "a/b"} {
		_, err := e.CreateProvider(context.Background(), nativeapi.ProviderCreateRequest{Name: name, URL: "https://a.example/s"}, noProviderNames, nil)
		if apiErr := flowAPIError(t, err); apiErr.Status != 422 || apiErr.Code != "unsupported_value" || !strings.Contains(apiErr.Message, "provider name") {
			t.Fatalf("%q: got %d %s %q, want 422 unsupported_value naming the provider name", name, apiErr.Status, apiErr.Code, apiErr.Message)
		}
	}
	if ops.calls != 0 {
		t.Fatal("a rejected create must not queue a reload")
	}
}

func TestConfigCreateProviderRejectsDuplicateName(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/subscription.dae")
	if err := os.WriteFile(target.abs, []byte("subscription {\n  KL: 'https://a.example/s'\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A name already written to the file, and one the running generation
	// holds, are both taken.
	for name, names := range map[string]providerIndexFunc{"KL": noProviderNames, "XX": namesInUse("XX")} {
		_, err := e.CreateProvider(context.Background(), nativeapi.ProviderCreateRequest{Name: name, URL: "https://b.example/s"}, names, nil)
		if apiErr := flowAPIError(t, err); apiErr.Status != 409 || apiErr.Code != "state_conflict" {
			t.Fatalf("%s: got %d %s, want 409 state_conflict", name, apiErr.Status, apiErr.Code)
		}
	}
	if ops.calls != 0 {
		t.Fatal("a rejected create must not queue a reload")
	}
	if content, _ := os.ReadFile(target.abs); strings.Count(string(content), "https://") != 1 {
		t.Fatalf("a rejected create must not touch the file: %q", content)
	}
}

func TestConfigCreateProviderRejectsControlCharacters(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	_, err := e.CreateProvider(context.Background(), nativeapi.ProviderCreateRequest{
		Name: "provider-b", URL: "https://a.example/s\r\nnode {\n  x: 'y'\n}",
	}, noProviderNames, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 422 || apiErr.Code != "unsupported_value" {
		t.Fatalf("got %d %s, want 422 unsupported_value", apiErr.Status, apiErr.Code)
	}
	if ops.calls != 0 {
		t.Fatal("a rejected create must not queue a reload")
	}
}

func TestConfigCreateProviderNeedsWritesEnabled(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, false, &fakeConfigOperations{})

	_, err := e.CreateProvider(context.Background(), nativeapi.ProviderCreateRequest{Name: "provider-b", URL: "https://a.example/s"}, noProviderNames, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "capability_not_supported" {
		t.Fatalf("got %d %s, want 404 capability_not_supported", apiErr.Status, apiErr.Code)
	}
}

func TestConfigDeleteProviderRemovesTaggedLine(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/subscription.dae")
	body := "# subscriptions\nsubscription {\n  KL: 'https://a.example/s' # keep\n  XX: 'https://b.example/s'\n}\n"
	if err := os.WriteFile(target.abs, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	provider := nativeapi.Provider{ID: providerIDOf("KL"), Name: "KL", Kind: "subscription"}
	outcome, err := e.DeleteProvider(context.Background(), nativeapi.ProviderDeleteRequest{ProviderID: provider.ID}, locate(provider, true, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Deleted != 1 || outcome.Accepted.Kind != nativeapi.OperationKindProviderDelete {
		t.Fatalf("outcome = %+v, want one queued provider_delete", outcome)
	}
	if ops.calls != 1 {
		t.Fatalf("StartOperation calls = %d, want 1", ops.calls)
	}
	content, _ := os.ReadFile(target.abs)
	if want := "# subscriptions\nsubscription {\n  XX: 'https://b.example/s'\n}\n"; string(content) != want {
		t.Fatalf("subscription module = %q, want %q", content, want)
	}
}

func TestConfigDeleteProviderRemovesUntaggedAndNodeSectionLines(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	subscriptions := flowSource(t, e, "config.d/subscription.dae")
	nodes := flowSource(t, e, "config.d/node.dae")
	untagged := "https://c.example/s?token=secret"
	if err := os.WriteFile(subscriptions.abs, []byte("subscription {\n  'https://a.example/s'\n  '"+untagged+"'\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodes.abs, []byte("node {\n  inline: '"+mockLink+"'\n  my-nodes: 'file:///etc/dae/nodes.txt'\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// An untagged subscription is identified by the key derived from its link.
	untaggedID := providerIDOf(subscription.ProviderKey("", untagged))
	outcome, err := e.DeleteProvider(context.Background(), nativeapi.ProviderDeleteRequest{ProviderID: untaggedID},
		locate(nativeapi.Provider{ID: untaggedID, Name: "sub_x", Kind: "subscription"}, true, nil), nil)
	if err != nil || outcome.Deleted != 1 {
		t.Fatalf("untagged delete = %+v, %v", outcome, err)
	}
	if content, _ := os.ReadFile(subscriptions.abs); string(content) != "subscription {\n  'https://a.example/s'\n}\n" {
		t.Fatalf("subscription module = %q", content)
	}

	// A file provider written in the node section is removed there, next to
	// the inline nodes, which stay.
	ops.calls = 0
	fileID := providerIDOf("my-nodes")
	outcome, err = e.DeleteProvider(context.Background(), nativeapi.ProviderDeleteRequest{ProviderID: fileID},
		locate(nativeapi.Provider{ID: fileID, Name: "my-nodes", Kind: "file"}, true, nil), nil)
	if err != nil || outcome.Deleted != 1 || ops.calls != 1 {
		t.Fatalf("file delete = %+v, %v, calls = %d", outcome, err, ops.calls)
	}
	if content, _ := os.ReadFile(nodes.abs); string(content) != "node {\n  inline: '"+mockLink+"'\n}\n" {
		t.Fatalf("node module = %q", content)
	}
}

func TestConfigDeleteProviderRejectsInlineProvider(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	provider := nativeapi.Provider{ID: inlineProviderID, Name: "inline", Kind: "inline"}
	_, err := e.DeleteProvider(context.Background(), nativeapi.ProviderDeleteRequest{ProviderID: inlineProviderID}, locate(provider, true, nil), nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "capability_not_supported" {
		t.Fatalf("got %d %s, want 404 capability_not_supported", apiErr.Status, apiErr.Code)
	}
	if ops.calls != 0 {
		t.Fatal("a rejected delete must not queue a reload")
	}
}

func TestConfigDeleteProviderIsIdempotent(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	// An id the running generation does not know.
	unknown := nativeapi.Provider{}
	outcome, err := e.DeleteProvider(context.Background(), nativeapi.ProviderDeleteRequest{ProviderID: "p_missing"}, locate(unknown, false, nil), nil)
	if err != nil || outcome.Deleted != 0 {
		t.Fatalf("unknown id = %+v, %v, want a no-op", outcome, err)
	}
	// A provider the generation still lists whose line is no longer on disk:
	// a write removed it and has not reloaded yet.
	known := nativeapi.Provider{ID: providerIDOf("gone"), Name: "gone", Kind: "subscription"}
	outcome, err = e.DeleteProvider(context.Background(), nativeapi.ProviderDeleteRequest{ProviderID: known.ID}, locate(known, true, nil), nil)
	if err != nil || outcome.Deleted != 0 {
		t.Fatalf("missing line = %+v, %v, want a no-op", outcome, err)
	}
	if ops.calls != 0 {
		t.Fatalf("StartOperation calls = %d, want 0", ops.calls)
	}
	// A locator failure surfaces instead of being read as "nothing to do".
	wantErr := errors.New("generation unavailable")
	if _, err = e.DeleteProvider(context.Background(), nativeapi.ProviderDeleteRequest{ProviderID: "p_x"}, locate(unknown, false, wantErr), nil); !errors.Is(err, wantErr) {
		t.Fatalf("locator error = %v, want %v", err, wantErr)
	}
}

func TestConfigProviderCreateReplaysIdempotencyKey(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	req := nativeapi.ProviderCreateRequest{Name: "provider-b", URL: "https://a.example/s", IdempotencyKey: "key-1"}
	first, err := e.CreateProvider(context.Background(), req, noProviderNames, nil)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := e.CreateProvider(context.Background(), req, noProviderNames, nil)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.OperationID != first.OperationID || ops.calls != 1 {
		t.Fatalf("replay = %+v, calls = %d; want the original operation and one start", replayed, ops.calls)
	}
}

func TestProjectProvidersReportsFileKindAndWrittenURL(t *testing.T) {
	subscriptionHealthRegistry.mu.Lock()
	previous := subscriptionHealthRegistry.records
	subscriptionHealthRegistry.records = map[string]subscriptionHealthRecord{
		"KL": {err: "fetch: 503"},
		"XX": {updatedAt: time.Now(), err: "fetch: timeout"},
		"OK": {updatedAt: time.Now()},
	}
	subscriptionHealthRegistry.mu.Unlock()
	t.Cleanup(func() {
		subscriptionHealthRegistry.mu.Lock()
		subscriptionHealthRegistry.records = previous
		subscriptionHealthRegistry.mu.Unlock()
	})

	active := &nativeActiveGeneration{conf: &config.Config{
		Subscription: []config.KeyableString{
			"KL:https://a.example/s?token=secret-a",
			"XX:https://b.example/s",
			"OK:https://c.example/s",
			"my-nodes:file:///etc/dae/nodes.txt",
		},
		Node: []config.KeyableString{"inline: '" + mockLink + "'"},
		Api:  config.Api{Secret: "flow-secret"},
	}}
	option := &dialer.GlobalOption{Log: logrus.New()}
	mustParse := func(tag, link string) *dialer.Dialer {
		d, err := dialer.NewFromLinkContext(context.Background(), option, dialer.InstanceOption{DisableCheck: true}, link, tag)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Close() })
		return d
	}
	nodes := []nodeInventoryEntry{
		{id: "n1", dialer: mustParse("", mockLink)},
		{id: "n2", dialer: func() *dialer.Dialer {
			d := mustParse("", mockLink)
			d.SetProviderTag("XX")
			return d
		}()},
		{id: "n3", dialer: func() *dialer.Dialer {
			d := mustParse("", mockLink)
			d.SetProviderTag("OK")
			return d
		}()},
	}

	providers := active.projectProviders(nodes)
	byName := map[string]nativeapi.Provider{}
	for _, provider := range providers {
		byName[provider.Name] = provider
	}
	kl := byName["KL"]
	if kl.Kind != "subscription" || kl.Status != "error" || kl.LastError == nil || kl.LastError.Code != "fetch_failed" {
		t.Fatalf("a failed load with no node = %+v, want status error with fetch_failed", kl)
	}
	if kl.URLRedacted == nil || *kl.URLRedacted != "https://a.example/s?token=secret-a" {
		t.Fatalf("url_redacted = %v, want the URL as written", kl.URLRedacted)
	}
	xx := byName["XX"]
	if xx.Status != "stale" || xx.NodeCount != 1 || xx.UpdatedAt == nil || xx.LastError == nil {
		t.Fatalf("a failed refresh that kept cached nodes = %+v, want stale with last_error", xx)
	}
	if ok := byName["OK"]; ok.Status != "ok" || ok.LastError != nil || ok.NodeCount != 1 {
		t.Fatalf("a loaded provider = %+v, want ok", ok)
	}
	// A provider that never loaded and never failed has no node either: it is
	// stale, not an error.
	if fresh := byName["my-nodes"]; fresh.Status != "stale" || fresh.LastError != nil {
		t.Fatalf("a never-fetched provider = %+v, want stale without error", fresh)
	}
	file := byName["my-nodes"]
	if file.Kind != "file" || file.URLRedacted != nil {
		t.Fatalf("file provider = %+v, want kind file and no URL", file)
	}
	if inline := byName["inline"]; inline.Kind != "inline" || inline.NodeCount != 1 {
		t.Fatalf("inline provider = %+v", inline)
	}
}

func TestProjectProvidersMasksListenerSecret(t *testing.T) {
	active := &nativeActiveGeneration{conf: &config.Config{
		Subscription: []config.KeyableString{"KL:https://a.example/s?token=flow-secret"},
		Api:          config.Api{Secret: "flow-secret"},
	}}
	providers := active.projectProviders(nil)
	if len(providers) != 1 || providers[0].URLRedacted == nil || *providers[0].URLRedacted != "https://a.example/s?token=[redacted]" {
		t.Fatalf("providers = %+v, want the listener secret masked", providers)
	}
}
