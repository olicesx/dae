/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org
 */

package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/nativeapi"
)

// providerSourceName is the module that owns subscriptions in the managed
// layout. A provider is created here; deleting one also looks in the node
// section, where a subscription or file link may be written.
const providerSourceName = "subscription.dae"

// providerIndexFunc returns the provider names the running generation uses.
// A create rejects a name any provider already holds.
type providerIndexFunc func() (map[string]bool, error)

// providerLocator reports the provider an ID names in the running generation.
// found is false for an id that names nothing, which makes a delete a no-op.
type providerLocator func() (provider nativeapi.Provider, found bool, err error)

// providerSource returns the writable module that holds the subscription
// section.
func (e *configEditor) providerSource(all []configSourceFile) (configSourceFile, error) {
	target := filepath.Join(e.baseDir, "config.d", providerSourceName)
	for _, s := range all {
		if s.abs != target {
			continue
		}
		if !e.sourceWritable(s) {
			return configSourceFile{}, permissionDenied("this source is read-only", "entry_source")
		}
		return s, nil
	}
	return configSourceFile{}, &nativeapi.APIError{
		Status:  404,
		Code:    "capability_not_supported",
		Message: "the managed layout has no " + providerSourceName,
	}
}

// CreateProvider writes one subscription provider into the managed
// subscription source. resolve turns the completed operation into the
// Provider body the contract asks for.
func (e *configEditor) CreateProvider(ctx context.Context, req nativeapi.ProviderCreateRequest, names providerIndexFunc, resolve func() (any, error)) (nativeapi.OperationAccepted, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	fingerprint := rawSHA256([]byte("provider_create\x00" + req.Name + "\x00" + req.URL))
	if err := validateProviderName(req.Name); err != nil {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value", Message: err.Error(),
		}
	}
	key := req.Name
	if strings.ContainsAny(req.URL, "\r\n\x00") {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value", Message: "the subscription URL must not contain control characters",
		}
	}
	quotedURL, err := quoteNodeValue(req.URL)
	if err != nil {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value", Message: err.Error(),
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	all, err := e.loadSources()
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if ok, _ := e.layoutOK(all); !ok {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported", Message: "provider management is not supported by this engine",
		}
	}
	target, err := e.providerSource(all)
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if accepted, replayed, err := e.replaySourceUpdate(nativeapi.OperationKindProviderCreate, sourceUpdateScope(target.abs, fingerprint), req.IdempotencyKey); err != nil || replayed {
		return accepted, err
	}
	taken := providerTags(string(target.raw))
	if names != nil {
		used, err := names()
		if err != nil {
			return nativeapi.OperationAccepted{}, err
		}
		for name := range used {
			taken[name] = true
		}
	}
	if taken[req.Name] {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 409, Code: "state_conflict",
			Message: "A provider named " + req.Name + " already exists",
		}
	}
	updated, err := insertSectionEntry(string(target.raw), "subscription", key, quotedURL)
	if err != nil {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value", Message: err.Error(),
		}
	}
	return e.commitSourceUpdate(ctx, target, []byte(updated), nativeapi.OperationKindProviderCreate, req.IdempotencyKey, fingerprint, resolve)
}

// DeleteProvider removes one subscription or file provider's line from the
// managed sources. An inline provider is the node section itself and is not
// deleted; an id that names nothing, or whose line is no longer on disk, is a
// no-op.
func (e *configEditor) DeleteProvider(ctx context.Context, req nativeapi.ProviderDeleteRequest, locate providerLocator, resolve func() (any, error)) (nativeapi.ProviderDeleteOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.ProviderDeleteOutcome{}, err
	}
	fingerprint := rawSHA256([]byte("provider_delete\x00" + req.ProviderID))

	e.mu.Lock()
	defer e.mu.Unlock()
	all, err := e.loadSources()
	if err != nil {
		return nativeapi.ProviderDeleteOutcome{}, err
	}
	if ok, _ := e.layoutOK(all); !ok {
		return nativeapi.ProviderDeleteOutcome{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported", Message: "provider management is not supported by this engine",
		}
	}
	target, err := e.providerSource(all)
	if err != nil {
		return nativeapi.ProviderDeleteOutcome{}, err
	}
	if accepted, replayed, err := e.replaySourceUpdate(nativeapi.OperationKindProviderDelete, sourceUpdateScope(target.abs, fingerprint), req.IdempotencyKey); err != nil || replayed {
		return nativeapi.ProviderDeleteOutcome{Accepted: accepted, Deleted: 1}, err
	}
	provider, found, err := locate()
	if err != nil {
		return nativeapi.ProviderDeleteOutcome{}, err
	}
	if !found {
		return nativeapi.ProviderDeleteOutcome{}, nil
	}
	if provider.Kind == "inline" {
		return nativeapi.ProviderDeleteOutcome{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported",
			Message: "The inline provider is the node section itself; delete its nodes instead",
		}
	}
	// The subscription module is searched first; a link may also sit in the
	// node section, where dae accepts subscriptions next to inline nodes.
	sources := make([]configSourceFile, 0, len(all))
	sources = append(sources, target)
	for _, s := range all {
		if s.abs != target.abs && e.sourceWritable(s) && filepath.Dir(s.abs) == filepath.Join(e.baseDir, "config.d") {
			sources = append(sources, s)
		}
	}
	for _, s := range sources {
		text := string(s.raw)
		for _, section := range []string{"subscription", "node"} {
			for _, entry := range providerEntries(text, section) {
				if providerEntryID(entry) != provider.ID {
					continue
				}
				updated := text[:entry.offset] + text[entry.offset+entry.length:]
				accepted, err := e.commitSourceUpdate(ctx, s, []byte(updated), nativeapi.OperationKindProviderDelete, req.IdempotencyKey, fingerprint, resolve)
				if err != nil {
					return nativeapi.ProviderDeleteOutcome{}, err
				}
				return nativeapi.ProviderDeleteOutcome{Accepted: accepted, Deleted: 1}, nil
			}
		}
	}
	// The generation may be ahead of the file: a write that removed the line
	// has not reloaded yet. Nothing is left to remove.
	return nativeapi.ProviderDeleteOutcome{}, nil
}

// validateProviderName rejects a name the configuration cannot carry. dae's
// grammar has no quoted key, so a tag is a bare word: the same shape an inline
// node name has.
func validateProviderName(name string) error {
	if !nodeNamePattern.MatchString(name) {
		return fmt.Errorf("provider name %q must be 1-64 characters of letters, digits, '_', '.' or '-'", name)
	}
	return nil
}

// providerEntry is one subscription line of a configuration source: the byte
// span it occupies, and its tag and link as the configuration reads them.
type providerEntry struct {
	offset int
	length int
	tag    string
	link   string
}

// providerEntries lists the subscription lines of the first block that opens
// section, in file order. A line is "tag: link", "'tag': link" or a bare link.
func providerEntries(text, section string) []providerEntry {
	start := sectionBlockPattern(section).FindStringIndex(text)
	if start == nil {
		return nil
	}
	open := strings.Index(text[start[0]:], "{") + start[0]
	closeIdx := matchingBrace(text, open)
	if closeIdx < 0 {
		return nil
	}
	var entries []providerEntry
	offset := open + 1
	for _, line := range strings.SplitAfter(text[open+1:closeIdx], "\n") {
		if tag, link, ok := parseProviderLine(line); ok {
			entries = append(entries, providerEntry{offset: offset, length: len(line), tag: tag, link: link})
		}
		offset += len(line)
	}
	return entries
}

// providerTags maps the tags the subscription lines of text define.
func providerTags(text string) map[string]bool {
	tags := map[string]bool{}
	for _, entry := range providerEntries(text, "subscription") {
		if entry.tag != "" {
			tags[entry.tag] = true
		}
	}
	return tags
}

// parseProviderLine reads one subscription line. The configuration unquotes
// values before dae sees them, so the link is returned without its quotes.
func parseProviderLine(line string) (tag, link string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	if trimmed[0] == '\'' || trimmed[0] == '"' {
		key, quoted := unquoteToken(trimmed)
		if !quoted {
			return "", "", false
		}
		rest := strings.TrimLeft(trimmed[len(key)+2:], " \t")
		if strings.HasPrefix(rest, ":") {
			return key, providerValue(rest[1:]), true
		}
		// A quoted link on its own is an untagged subscription.
		return "", key, true
	}
	if colon := providerTagColon(trimmed); colon > 0 && !strings.ContainsAny(trimmed[:colon], "'\" ") {
		return trimmed[:colon], providerValue(trimmed[colon+1:]), true
	}
	return "", providerValue(trimmed), true
}

// providerTagColon is the index of the colon that ends a tag, or -1. Like
// dae's own split, a colon that belongs to "://" does not end a tag.
func providerTagColon(text string) int {
	colon := strings.IndexByte(text, ':')
	if colon < 0 || strings.HasPrefix(text[colon:], "://") {
		return -1
	}
	return colon
}

// unquoteToken reads a quoted token at the start of text and reports whether
// it was closed. The configuration has no escape sequences.
func unquoteToken(text string) (token string, quoted bool) {
	quote := text[0]
	end := strings.IndexByte(text[1:], quote)
	if end < 0 {
		return "", false
	}
	return text[1 : 1+end], true
}

// providerValue reads the link after a tag's colon, without quotes, a trailing
// comment or the line ending.
func providerValue(rest string) string {
	if value, ok := nodeLineValue("x:" + strings.TrimLeft(rest, " \t")); ok {
		return value
	}
	return ""
}

// providerEntryID is the provider ID the running generation derives for an
// entry: its tag when it has one, otherwise a key derived from the link.
func providerEntryID(entry providerEntry) string {
	raw := entry.link
	if entry.tag != "" {
		raw = entry.tag + ":" + entry.link
	}
	return providerIDOf(subscription.ProviderKey(entry.tag, raw))
}

// providerKindOf classifies a subscription link: a file link is read from
// disk, everything else is fetched.
func providerKindOf(link string) string {
	_, afterTag := common.GetTagFromLinkLikePlaintext(link)
	afterTag = strings.Trim(strings.TrimSpace(afterTag), "'\"")
	if strings.HasPrefix(strings.ToLower(afterTag), "file:") {
		return "file"
	}
	return "subscription"
}

// blockIndent returns the indentation the entries inside a block use,
// defaulting to two spaces when the block has no entry to copy from.
func blockIndent(text string, from int) string {
	for _, line := range strings.Split(text[from:], "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "}") {
			break
		}
		return line[:len(line)-len(trimmed)]
	}
	return "  "
}

// insertSectionEntry adds one "key: value" line to the first block that opens
// section. An existing block gets the line first, so the surrounding text,
// comments included, stays byte for byte as it was; a file without the block
// gets one appended.
func insertSectionEntry(text, section, key, quoted string) (string, error) {
	entry := func(indent string) string {
		return indent + key + ": " + quoted + "\n"
	}
	// "section {}" is an empty block written on one line; the entry opens it.
	empty := regexp.MustCompile(`^([ \t]*)` + regexp.QuoteMeta(section) + `[ \t]*\{\}[ \t]*(?:#[^\r\n]*)?(?:\r?\n|$)`)
	if loc := empty.FindStringSubmatchIndex(text); loc != nil {
		indent := text[loc[2]:loc[3]]
		return text[:loc[0]] + indent + section + " {\n" + entry(indent+"  ") + indent + "}\n" + text[loc[1]:], nil
	}
	if loc := sectionBlockPattern(section).FindStringIndex(text); loc != nil {
		insertAt := loc[1]
		if nl := strings.IndexByte(text[insertAt:], '\n'); nl >= 0 {
			insertAt += nl + 1
		}
		return text[:insertAt] + entry(blockIndent(text, insertAt)) + text[insertAt:], nil
	}
	trimmed := strings.TrimRight(text, "\n")
	if trimmed == "" {
		return section + " {\n" + entry("  ") + "}\n", nil
	}
	return trimmed + "\n\n" + section + " {\n" + entry("  ") + "}\n", nil
}
