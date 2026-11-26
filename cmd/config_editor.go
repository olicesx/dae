/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	// hiddenConfigSourceName is the file the control API must never expose.
	hiddenConfigSourceName = "api.dae"
	// configMaxBytes bounds one source, matching the contract default (max_bytes 61440).
	configMaxBytes = 61440
	// configMaxSources bounds the number of sources in one request (contract default 16).
	configMaxSources  = 16
	configRedacted    = "<redacted>"
	hiddenSourceLabel = "<hidden source>"
)

// apiSecretPattern matches the listener secret inside an api { } block.
//
// The run up to "secret" treats a comment and a quoted literal as opaque units.
// Without that, a "# }" comment ended the block early and left the real secret
// in the output, and a commented-out "# secret: 'old'" was the match that got
// redacted while the live one stayed visible.
var apiSecretPattern = regexp.MustCompile(`(?s)(\bapi\s*\{(?:#[^\n]*\n|'[^'\n]*'|"[^"\n]*"|[^}#])*?\bsecret\s*:\s*)(?:'[^']*'|"[^"]*"|[^\s;}\n]+)`)

// operationQueue is the subset of the operations adapter a write path needs: it
// queues the reload and says what the completed operation must report.
type operationQueue interface {
	// StartOperation creates the operation, installs the result resolver and
	// queues the reload in one step. A resolver registered afterwards could miss
	// an operation that completed in the meantime, and the operation would then
	// report the reload's generation ids instead of the written resource.
	StartOperationWithResult(ctx context.Context, kind, scope, idempotencyKey string, resolve func() (any, error)) (nativeapi.OperationAccepted, error)
	// StartConfigUpdate also registers completion for a source already written to disk.
	StartConfigUpdate(ctx context.Context, kind, scope, idempotencyKey string, resolve func() (any, error), complete configWriteCompletion) (nativeapi.OperationAccepted, error)
	// ReplayOperation reports a keyed request that already has an accepted
	// operation, before the write path performs any filesystem side effect.
	ReplayOperation(kind, scope, idempotencyKey string) (nativeapi.OperationAccepted, bool, error)
}

// configEditor implements nativeapi.ConfigProvider over the on-disk config
// tree. Writes go to disk first and then queue a reload, which re-reads disk.
type configEditor struct {
	mu         sync.Mutex
	log        *logrus.Logger
	mainPath   string
	baseDir    string
	apiAtStart config.Api
	enabled    bool
	operations operationQueue
	reload     *reloadManager
	busy       func() bool
	generation func() string
	supervisor *runtimeSupervisor
}

// configSourceFile is one loaded source with its raw bytes.
type configSourceFile struct {
	id      string
	path    string
	abs     string
	kind    string
	raw     []byte
	modTime time.Time
}

func newConfigEditor(cfgFile string, api config.Api, operations operationQueue,
	reload *reloadManager, supervisor *runtimeSupervisor, log *logrus.Logger) (*configEditor, error) {
	mainPath, err := filepath.Abs(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}
	if log == nil {
		log = logrus.New()
	}
	e := &configEditor{
		log:        log,
		mainPath:   filepath.Clean(mainPath),
		baseDir:    filepath.Dir(mainPath),
		apiAtStart: api,
		enabled:    api.ConfigWrite && operations != nil,
		operations: operations,
		reload:     reload,
		supervisor: supervisor,
	}
	e.busy = func() bool {
		return reload != nil && (reload.reloadActive.Load() || reload.reloadPending.Load())
	}
	e.generation = func() string {
		if supervisor == nil {
			return ""
		}
		if g := supervisor.activeSnapshot(); g != nil {
			return g.id
		}
		return ""
	}
	return e, nil
}

func (e *configEditor) ConfigCapabilities() nativeapi.ConfigCapabilities {
	e.mu.Lock()
	all, err := e.loadSources()
	e.mu.Unlock()
	managed, reason := false, "layout_unmanaged"
	if err == nil {
		managed, reason = detectManagedLayout(e.mainPath, sourcePaths(all))
	}
	_, canCreate := e.operations.(configCreateQueue)
	caps := nativeapi.ConfigCapabilities{
		Create:        managed && canCreate,
		Writable:      e.enabled && managed,
		MaxBytes:      configMaxBytes,
		MaxSources:    configMaxSources,
		Layout:        "unmanaged",
		HiddenSources: []string{hiddenConfigSourceName},
	}
	if managed {
		caps.Layout = "managed"
	}
	switch {
	case !e.enabled:
		caps.LayoutReason = "writes_disabled"
	case !managed:
		caps.LayoutReason = reason
	}
	return caps
}

func sourcePaths(all []configSourceFile) []string {
	paths := make([]string, 0, len(all))
	for _, s := range all {
		paths = append(paths, s.abs)
	}
	return paths
}

// errHiddenSourceRef answers any request that names the hidden source. It is a
// 400 rather than a 404 because the request itself is disallowed.
var errHiddenSourceRef = &nativeapi.APIError{Status: 400, Code: "invalid_request", Message: "config source cannot be referenced"}

// readOnlyReason explains why s cannot be written; it is empty when s is writable.
func (e *configEditor) readOnlyReason(all []configSourceFile, s configSourceFile) string {
	if ok, reason := e.layoutOK(all); !ok {
		return reason
	}
	if !e.sourceWritable(s) {
		return "entry_source"
	}
	return ""
}

// layoutOK is the write gate: the feature flag plus the managed layout.
func (e *configEditor) layoutOK(all []configSourceFile) (bool, string) {
	if !e.enabled {
		return false, "writes_disabled"
	}
	paths := make([]string, 0, len(all))
	for _, s := range all {
		paths = append(paths, s.abs)
	}
	return detectManagedLayout(e.mainPath, paths)
}

// sourceWritable limits writes to config.d/*.dae; config.dae is the read-only entry.
func (e *configEditor) sourceWritable(s configSourceFile) bool {
	return s.kind == "include" && filepath.Dir(s.abs) == filepath.Join(e.baseDir, "config.d") && filepath.Ext(s.abs) == ".dae"
}

// contractReadOnlyReason keeps a read-only cause the contract enumerates. The
// member is defined as present only while one of its listed causes applies,
// and the other causes have no listed value: the entry source is read-only by
// role, and an unmanaged layout is reported through the config capability.
// Writing still stays refused for them; only the reported cause is dropped.
func contractReadOnlyReason(reason string) string {
	switch reason {
	case "writes_disabled", "store_blocked", "listener_secret_source", "listener_secret_in_content":
		return reason
	}
	return ""
}

func permissionDenied(message, reason string) error {
	return &nativeapi.APIError{
		Status:  403,
		Code:    "permission_denied",
		Message: message,
		Details: map[string]any{"reason": reason},
	}
}

// loadSources reads every source the merger reaches, excluding nothing; the
// hidden filter is applied by visibleSources so validation can still see it.
func (e *configEditor) loadSources() ([]configSourceFile, error) {
	_, entries, err := config.NewMerger(e.mainPath).Merge()
	if err != nil {
		return nil, errors.New(e.scrub(err.Error()))
	}
	out := make([]configSourceFile, 0, len(entries))
	for _, entry := range entries {
		abs := filepath.Clean(entry)
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(e.baseDir, abs)
		}
		raw, err := os.ReadFile(abs)
		if err != nil {
			return nil, errors.New(e.scrub(err.Error()))
		}
		fi, err := os.Stat(abs)
		if err != nil {
			return nil, errors.New(e.scrub(err.Error()))
		}
		rel, err := filepath.Rel(e.baseDir, abs)
		if err != nil {
			rel = filepath.Base(abs)
		}
		kind := "include"
		if abs == e.mainPath {
			kind = "main"
		}
		out = append(out, configSourceFile{
			id:      sourceIDFor(rel),
			path:    filepath.ToSlash(rel),
			abs:     abs,
			kind:    kind,
			raw:     raw,
			modTime: fi.ModTime(),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].kind != out[j].kind {
			return out[i].kind == "main"
		}
		return out[i].path < out[j].path
	})
	return out, nil
}

// visibleSources drops the hidden source. The main file is never hidden.
func (e *configEditor) visibleSources(all []configSourceFile) []configSourceFile {
	out := make([]configSourceFile, 0, len(all))
	for _, s := range all {
		if s.abs != e.mainPath && filepath.Base(s.abs) == hiddenConfigSourceName {
			continue
		}
		out = append(out, s)
	}
	return out
}

func sourceIDFor(rel string) string {
	sum := sha256.Sum256([]byte(filepath.ToSlash(rel)))
	return "src_" + hex.EncodeToString(sum[:8])
}

func rawSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// maskSource redacts the listener secret. It reports whether anything changed,
// which makes the content incomplete and suppresses the ETag.
func maskSource(content string) (string, bool) {
	if !apiSecretPattern.MatchString(content) {
		return content, false
	}
	masked := apiSecretPattern.ReplaceAllString(content, "${1}'"+configRedacted+"'")
	return masked, masked != content
}

// scrub removes the hidden source's name and absolute path from any text that
// may leave the process.
func (e *configEditor) scrub(text string) string {
	hidden := filepath.Join(e.baseDir, hiddenConfigSourceName)
	text = strings.ReplaceAll(text, hidden, hiddenSourceLabel)
	return strings.ReplaceAll(text, hiddenConfigSourceName, hiddenSourceLabel)
}

func (e *configEditor) sourceView(s configSourceFile, readOnlyReason string) (nativeapi.ConfigSource, bool) {
	content, masked := maskSource(string(s.raw))
	lines := strings.Count(content, "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		lines++
	}
	view := nativeapi.ConfigSource{
		ConfigSourceContent: nativeapi.ConfigSourceContent{
			ID:            s.id,
			Path:          s.path,
			Kind:          s.kind,
			ContentSHA256: rawSHA256(s.raw),
			Bytes:         len(s.raw),
			Content:       content,
			LineCount:     lines,
		},
		Writable:       readOnlyReason == "",
		ReadOnlyReason: contractReadOnlyReason(readOnlyReason),
		LoadedAt:       s.modTime,
	}
	return view, masked
}

func (e *configEditor) GetConfig(ctx context.Context) (nativeapi.EffectiveConfig, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.EffectiveConfig{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	all, err := e.loadSources()
	if err != nil {
		return nativeapi.EffectiveConfig{}, err
	}
	visible := e.visibleSources(all)
	result := nativeapi.EffectiveConfig{
		GenerationID: e.generation(),
		Revision:     e.sourceRevision(all),
		Sources:      make([]nativeapi.ConfigSource, 0, len(visible)),
		Diagnostics:  []nativeapi.ConfigDiagnostic{},
	}
	for _, s := range visible {
		view, masked := e.sourceView(s, e.readOnlyReason(all, s))
		if masked {
			result.SecretsRedacted = true
		}
		result.Sources = append(result.Sources, view)
	}
	return result, nil
}

// sourceRevision returns the revision of the configuration these sources
// describe. It uses the same function the running generation reports as
// runtime.generation.config_revision, so a client can compare the two: they are
// equal while the on-disk tree is what the engine loaded, and differ once a
// write has not been reloaded yet. An earlier source-set hash could not be
// reproduced by a client (it included the hidden api.dae) and never matched.
func (e *configEditor) sourceRevision(all []configSourceFile) string {
	candidate, err := e.buildCandidate(nil, nil)
	if err != nil {
		return ""
	}
	return candidate.Revision()
}

// findSource returns the visible source with the given id, or 404. Hidden
// sources are absent from visible, so their ids are indistinguishable from unknown ones.
func findSource(visible []configSourceFile, id string) (configSourceFile, error) {
	for _, s := range visible {
		if s.id == id {
			return s, nil
		}
	}
	return configSourceFile{}, &nativeapi.APIError{
		Status:  404,
		Code:    "resource_not_found",
		Message: "config source not found",
	}
}

func (e *configEditor) GetConfigSource(ctx context.Context, sourceID string) (nativeapi.ConfigSourceContent, bool, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.ConfigSourceContent{}, false, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	all, err := e.loadSources()
	if err != nil {
		return nativeapi.ConfigSourceContent{}, false, err
	}
	s, err := findSource(e.visibleSources(all), sourceID)
	if err != nil {
		return nativeapi.ConfigSourceContent{}, false, err
	}
	view, masked := e.sourceView(s, e.readOnlyReason(all, s))
	return view.ConfigSourceContent, !masked, nil
}

// buildCandidate merges the main file with the given overrides and parses the
// result. Only overrides of visible sources reach this function.
func (e *configEditor) buildCandidate(overrides map[string][]byte, extra []*config_parser.Section) (*config.Config, error) {
	sections, _, err := config.NewMergerWithOverrides(e.mainPath, overrides).Merge()
	if err != nil {
		return nil, err
	}
	if len(extra) > 0 {
		sections = mergeCandidateSections(sections, extra)
	}
	return config.New(sections)
}

// mergeCandidateSections merges a submitted source that has no place in the
// include tree over the accepted configuration. The merger concatenates items
// of the same section, with the later source winning on decode; this mirrors
// that order so a single-section candidate can be validated without knowing
// which file declares the section.
func mergeCandidateSections(base []*config_parser.Section, extra []*config_parser.Section) []*config_parser.Section {
	index := make(map[string]int, len(base))
	for i, section := range base {
		index[section.Name] = i
	}
	for _, section := range extra {
		if i, ok := index[section.Name]; ok {
			base[i].Items = append(base[i].Items, section.Items...)
			continue
		}
		index[section.Name] = len(base)
		base = append(base, section)
	}
	return base
}

// fullValidate runs the same checks the validate command runs on top of the
// parsed candidate. The API must not be laxer than `dae validate`, otherwise a
// replacement is stored and the reload that follows it fails.
func (e *configEditor) fullValidate(conf *config.Config) error {
	if _, err := parseFallbackResolver(conf.Global.FallbackResolver); err != nil {
		return err
	}
	if err := conf.Api.Validate(); err != nil {
		return err
	}
	if err := validateRoutingRules(e.log, conf, []string{e.baseDir}); err != nil {
		return err
	}
	if err := dns.ValidateRouting(e.log, &conf.Dns, []string{e.baseDir}); err != nil {
		return err
	}
	return validateFixedDomainTtl(conf)
}

// anonymousValidationSource is a submitted source with no place in the include
// tree. The contract requires only content, so its sections are merged over the
// resulting configuration rather than replacing a file.
type anonymousValidationSource struct {
	id      string
	content string
}

// candidateOverrides maps validation sources to absolute paths. Only visible
// sources can be overridden; anything else is treated as not found. A source
// with neither id nor path is anonymous: the contract requires only content, so
// its sections are merged over the resulting configuration instead of replacing
// a file.
func (e *configEditor) candidateOverrides(all []configSourceFile, reqs []nativeapi.ConfigValidationSource) (map[string][]byte, map[string]string, []anonymousValidationSource, error) {
	visible := e.visibleSources(all)
	byID := map[string]configSourceFile{}
	byAbs := map[string]configSourceFile{}
	for _, s := range visible {
		byID[s.id] = s
		byAbs[s.abs] = s
	}
	overrides := map[string][]byte{}
	absToID := map[string]string{}
	var anonymous []anonymousValidationSource
	hiddenIDs := map[string]bool{}
	for _, s := range all {
		if s.abs != e.mainPath && filepath.Base(s.abs) == hiddenConfigSourceName {
			hiddenIDs[s.id] = true
		}
	}
	for index, r := range reqs {
		if r.Content == nil {
			return nil, nil, nil, &nativeapi.APIError{Status: 422, Code: "unsupported_value", Message: "source content is required"}
		}
		var target configSourceFile
		var ok bool
		switch {
		case r.Path != "":
			abs := filepath.Clean(filepath.Join(e.baseDir, filepath.FromSlash(r.Path)))
			if filepath.Base(abs) == hiddenConfigSourceName {
				return nil, nil, nil, errHiddenSourceRef
			}
			target, ok = byAbs[abs]
			if !ok && abs != e.mainPath && filepath.Base(abs) != hiddenConfigSourceName {
				// A path the include tree does not reach can never be part of the
				// merged candidate: the merger reads files by globbing the disk, so
				// accepting the bytes here validated nothing and silently dropped
				// whatever the caller submitted.
				return nil, nil, nil, &nativeapi.APIError{
					Status:  422,
					Code:    "unsupported_value",
					Message: "the path is not part of the include tree, so its content cannot be validated",
				}
			}
		case r.ID != "":
			if hiddenIDs[r.ID] {
				return nil, nil, nil, errHiddenSourceRef
			}
			target, ok = byID[r.ID]
			if !ok {
				// The contract's id is a request-local diagnostic label; only a
				// path names a file. An id that matches a visible source still
				// overrides it, which is what the config editor uses. A label the
				// tree does not know is a standalone candidate, not an error: the
				// node editor validates a node block under a label of its own.
				anonymous = append(anonymous, anonymousValidationSource{id: r.ID, content: *r.Content})
				continue
			}
		default:
			// Request-local ID, defaulted exactly as the contract describes.
			anonymous = append(anonymous, anonymousValidationSource{id: fmt.Sprintf("source-%d", index+1), content: *r.Content})
			continue
		}
		if !ok {
			return nil, nil, nil, &nativeapi.APIError{Status: 404, Code: "resource_not_found", Message: "config source not found"}
		}
		// Two requests that resolve to the same file describe one source twice,
		// so the candidate would be ambiguous.
		if _, dup := overrides[target.abs]; dup {
			return nil, nil, nil, &nativeapi.APIError{Status: 400, Code: "invalid_request", Message: "duplicate configuration source"}
		}
		overrides[target.abs] = []byte(*r.Content)
		absToID[target.abs] = target.id
	}
	return overrides, absToID, anonymous, nil
}

func (e *configEditor) ValidateConfig(ctx context.Context, req nativeapi.ConfigValidationRequest) (nativeapi.ConfigValidationResult, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.ConfigValidationResult{}, err
	}
	if req.Mode != "" && req.Mode != "syntax" && req.Mode != "full" {
		return nativeapi.ConfigValidationResult{}, &nativeapi.APIError{Status: 422, Code: "unsupported_value", Message: "unknown validation mode"}
	}
	if len(req.Sources) > configMaxSources {
		return nativeapi.ConfigValidationResult{}, &nativeapi.APIError{Status: 413, Code: "request_too_large", Message: "too many sources"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	all, err := e.loadSources()
	if err != nil {
		return nativeapi.ConfigValidationResult{}, err
	}
	overrides, absToID, anonymous, err := e.candidateOverrides(all, req.Sources)
	if err != nil {
		return nativeapi.ConfigValidationResult{}, err
	}
	mainID := requestMainSourceID(req.Sources, all)

	diags := []nativeapi.ConfigDiagnostic{}
	failed := false
	// A source with only content has no file to override, so it is parsed here
	// and merged over the resulting configuration in full mode.
	var anonymousSections []*config_parser.Section
	for _, src := range anonymous {
		sections, parseErr := config_parser.Parse(src.content)
		if parseErr != nil {
			failed = true
			diags = append(diags, e.diagnosticsFor(parseErr, absToID, src.id, "config_invalid")...)
			continue
		}
		anonymousSections = append(anonymousSections, sections...)
	}
	if req.Mode == "syntax" {
		// Syntax mode parses the submitted texts only; no merge or full checks run.
		for abs, raw := range overrides {
			if _, err := config_parser.Parse(string(raw)); err != nil {
				failed = true
				diags = append(diags, e.diagnosticsFor(err, map[string]string{abs: absToID[abs]}, absToID[abs], "config_invalid")...)
			}
		}
	} else if !failed {
		conf, buildErr := e.buildCandidate(overrides, anonymousSections)
		if buildErr != nil {
			failed = true
			diags = append(diags, e.diagnosticsFor(buildErr, absToID, mainID, "config_invalid")...)
		} else if fullErr := e.fullValidate(conf); fullErr != nil {
			failed = true
			diags = append(diags, e.diagnosticsFor(fullErr, absToID, mainID, "validation_failed")...)
		}
	}
	if failed && len(diags) == 0 {
		// Every error pointed only at the hidden source and was dropped; keep the failure visible.
		diags = append(diags, invalidDiagnostic(mainID))
	}
	return nativeapi.ConfigValidationResult{
		Valid:        !failed,
		Diagnostics:  diags,
		GenerationID: e.generation(),
		ValidatedAt:  time.Now(),
	}, nil
}

// invalidDiagnostic keeps a failure visible when every error behind it pointed
// only at the hidden source. It still names a source, because the contract
// requires every diagnostic to carry an ID of at least one character.
func invalidDiagnostic(sourceID string) nativeapi.ConfigDiagnostic {
	return nativeapi.ConfigDiagnostic{Level: "error", SourceID: sourceID, Code: "config_invalid", Message: "configuration is invalid"}
}

// requestMainSourceID names the source an error belongs to when the error names
// no file of its own. The contract calls the first submitted source the main
// one and defaults its ID to source-1, so that is the anchor; with nothing
// submitted, the candidate is the accepted tree and its entry file is.
func requestMainSourceID(reqs []nativeapi.ConfigValidationSource, all []configSourceFile) string {
	if len(reqs) > 0 {
		if reqs[0].ID != "" {
			return reqs[0].ID
		}
		return "source-1"
	}
	for _, s := range all {
		if s.kind == "main" {
			return s.id
		}
	}
	return "source-1"
}

// parseErrorLinePattern matches the "line L:C" prefixes the parser emits.
var parseErrorLinePattern = regexp.MustCompile(`(?m)^line (\d+):(\d+)`)

// diagnosticsFor converts err into visible diagnostics, with line and column
// when the parser reported them. Text is scrubbed of the hidden source's name
// and path. An error that points only at the hidden source yields nil so the
// caller can fall back to a generic diagnostic.
func (e *configEditor) diagnosticsFor(err error, absToID map[string]string, fallbackID, code string) []nativeapi.ConfigDiagnostic {
	text := err.Error()
	sourceID := fallbackID
	for abs, id := range absToID {
		if id != "" && strings.Contains(text, abs) {
			sourceID = id
			break
		}
	}
	if sourceID == "" && strings.Contains(text, filepath.Join(e.baseDir, hiddenConfigSourceName)) {
		return nil
	}
	locs := parseErrorLinePattern.FindAllStringSubmatchIndex(text, -1)
	if len(locs) == 0 {
		return []nativeapi.ConfigDiagnostic{{Level: "error", SourceID: sourceID, Code: code, Message: e.scrub(text)}}
	}
	diags := make([]nativeapi.ConfigDiagnostic, 0, len(locs))
	for i, loc := range locs {
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		line, _ := strconv.Atoi(text[loc[2]:loc[3]])
		column, _ := strconv.Atoi(text[loc[4]:loc[5]])
		diags = append(diags, nativeapi.ConfigDiagnostic{
			Level:    "error",
			SourceID: sourceID,
			Line:     &line,
			Column:   &column,
			Code:     code,
			Message:  e.scrub(strings.TrimSpace(text[loc[0]:end])),
		})
	}
	return diags
}

// CreateConfigSource validates and stores a supplemental source before queueing reload.
func (e *configEditor) CreateConfigSource(ctx context.Context, req nativeapi.CreateConfigSourceRequest) (nativeapi.OperationAccepted, error) {
	var rejected nativeapi.OperationAccepted
	if err := ctx.Err(); err != nil {
		return rejected, err
	}
	queue, supported := e.operations.(configCreateQueue)
	if !supported {
		return rejected, nativeapi.NewAPIError(404, "capability_not_supported", "configuration source creation is unavailable")
	}
	if !e.enabled {
		return rejected, permissionDenied("config writes are not available", "writes_disabled")
	}
	if !nativeapi.ValidConfigSourceCreatePath(req.Path) || filepath.Base(req.Path) == hiddenConfigSourceName {
		return rejected, nativeapi.NewAPIError(400, "invalid_request", "invalid configuration source path")
	}
	if len(req.Content) > configMaxBytes {
		return rejected, nativeapi.NewAPIError(413, "request_too_large", "config source is too large")
	}
	if !utf8.ValidString(req.Content) {
		return rejected, nativeapi.NewAPIError(400, "invalid_request", "source content must be UTF-8")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	abs := filepath.Join(e.baseDir, req.Path)
	target := configSourceFile{id: sourceIDFor(req.Path), abs: abs}
	scope := sourceUpdateScope(abs, rawSHA256([]byte("config_create\x00"+req.Content)))
	if accepted, replayed, err := e.replaySourceUpdate(nativeapi.OperationKindReload, scope, req.IdempotencyKey); err != nil || replayed {
		return accepted, err
	}
	if err := e.checkConfigCreateParent(abs); err != nil {
		return rejected, err
	}
	if _, err := os.Lstat(abs); err == nil {
		return rejected, configSourceExists()
	} else if !errors.Is(err, os.ErrNotExist) {
		return rejected, configCreateUnavailable()
	}
	if filepath.Dir(req.Path) != "config.d" {
		return rejected, configCreateDiagnostic(sourceIDFor("config.dae"), "source-not-included", "No managed include pattern loads this path.")
	}

	// Pin the destination directory. A concurrent rename or symlink swap
	// cannot redirect creation or cleanup through the caller's path.
	dir, err := e.openConfigCreateDir()
	if err != nil {
		return rejected, err
	}
	keepDir := false
	defer func() {
		if !keepDir {
			_ = dir.Close()
		}
	}()
	all, err := e.loadSources()
	if err != nil {
		return rejected, configCreateUnavailable()
	}
	if ok, reason := e.layoutOK(all); !ok {
		return rejected, permissionDenied("config writes are not available", reason)
	}
	if len(e.visibleSources(all)) >= configMaxSources {
		return rejected, nativeapi.NewAPIError(413, "request_too_large", "too many config sources")
	}
	if e.apiAtStart.Secret != "" && strings.Contains(req.Content, e.apiAtStart.Secret) {
		return rejected, permissionDenied("source must not contain the listener secret", "listener_secret_in_content")
	}
	sections, err := config_parser.Parse(req.Content)
	if err != nil {
		return rejected, e.unprocessable(err, target)
	}
	for _, section := range sections {
		switch section.Name {
		case "api":
			return rejected, permissionDenied("the api section may only be declared in the listener source", "listener_secret_in_content")
		case "include":
			return rejected, configCreateDiagnostic(target.id, "config_invalid", "A managed source must not contain an include block.")
		}
		if slices.Contains(managedConfigModules, section.Name+".dae") {
			return rejected, configCreateDiagnostic(target.id, "config_invalid", "This section belongs to a required managed source.")
		}
	}
	// Keep the existing detector's conservative include check for candidate
	// text too, so a successful create cannot disable managed editing.
	if includeKeywordPattern.MatchString(req.Content) {
		return rejected, configCreateDiagnostic(target.id, "config_invalid", "A managed source must not contain an include block.")
	}
	content := []byte(req.Content)
	merged, entries, origins, err := config.NewMergerWithNewSource(e.mainPath, abs, content).MergeWithSourcesAndOrigins()
	if err != nil {
		return rejected, e.unprocessable(err, target)
	}
	if !slices.Contains(entries, abs) {
		return rejected, configCreateDiagnostic(sourceIDFor("config.dae"), "source-not-included", "No include pattern loads this path.")
	}
	for _, occurrences := range origins {
		for _, origin := range occurrences[1:] {
			if origin.File != occurrences[0].File {
				return rejected, configCreateDiagnostic(target.id, "config_invalid", "A section is declared by more than one file.")
			}
		}
	}
	candidate, err := config.New(merged)
	if err != nil {
		return rejected, e.unprocessable(err, target)
	}
	if err := e.guardApiUnchanged(candidate); err != nil {
		return rejected, err
	}
	if err := e.fullValidate(candidate); err != nil {
		return rejected, e.unprocessable(err, target)
	}
	accepted, err := e.commitConfigCreate(ctx, queue, dir, all, target, candidate, content, scope, req.IdempotencyKey)
	keepDir = err == nil
	return accepted, err
}

func configSourceExists() *nativeapi.APIError {
	return nativeapi.NewAPIError(409, "state_conflict", "a config source already exists at this path")
}

func configCreateUnavailable() *nativeapi.APIError {
	return nativeapi.NewAPIError(503, "temporarily_unavailable", "the config store cannot create a source right now")
}

func configCreateDiagnostic(sourceID, code, message string) error {
	return &nativeapi.APIError{
		Status: 422, Code: "unsupported_value", Message: "configuration validation failed",
		Details: map[string]any{"diagnostics": []nativeapi.ConfigDiagnostic{{
			Level: "error", SourceID: sourceID, Code: code, Message: message,
		}}},
	}
}

// Inspect existing ancestors so even an unmatched path cannot traverse a
// symlink outside the configuration root. Missing parents are never created.
func (e *configEditor) checkConfigCreateParent(path string) error {
	root, err := filepath.EvalSymlinks(e.baseDir)
	if err != nil {
		return configCreateUnavailable()
	}
	parent := filepath.Dir(path)
	for parent != e.baseDir {
		resolved, err := filepath.EvalSymlinks(parent)
		if errors.Is(err, os.ErrNotExist) {
			parent = filepath.Dir(parent)
			continue
		}
		rel, relErr := filepath.Rel(root, resolved)
		if err != nil || relErr != nil || !filepath.IsLocal(rel) {
			return nativeapi.NewAPIError(400, "invalid_request", "config source parent must stay inside the config root")
		}
		return nil
	}
	return nil
}

func (e *configEditor) openConfigCreateDir() (*os.File, error) {
	root, err := os.Open(e.baseDir)
	if err != nil {
		return nil, configCreateUnavailable()
	}
	defer func() { _ = root.Close() }()
	fd, err := unix.Openat(int(root.Fd()), "config.d", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return nil, nativeapi.NewAPIError(400, "invalid_request", "config.d must be a real directory")
	}
	if err != nil {
		return nil, configCreateUnavailable()
	}
	return os.NewFile(uintptr(fd), "config.d"), nil
}

func (e *configEditor) commitConfigCreate(ctx context.Context, queue configCreateQueue, dir *os.File,
	all []configSourceFile, target configSourceFile, candidate *config.Config, content []byte, scope, key string,
) (nativeapi.OperationAccepted, error) {
	var rejected nativeapi.OperationAccepted
	unlock := e.lockConfigRead()
	defer unlock()
	if err := ctx.Err(); err != nil {
		return rejected, err
	}
	if e.busy() {
		return rejected, &nativeapi.APIError{
			Status: 409, Code: "state_conflict", Message: "a reload is already in progress",
			Details: map[string]any{"reason": "reload_in_progress"},
		}
	}
	if e.reload != nil && e.reload.status != nil && e.reload.status.getState() != string(runtimeStateRunning) {
		return rejected, nativeapi.NewAPIError(409, "state_conflict", "config source creation requires a running generation")
	}
	if e.supervisor != nil {
		active := e.supervisor.activeSnapshot()
		if active == nil || active.conf == nil {
			return rejected, nativeapi.NewAPIError(409, "state_conflict", "config source creation requires an active generation")
		}
		probe := *candidate
		if err := preprocessWanInterfaceAuto(&probe); err != nil {
			return rejected, configCreateDiagnostic(target.id, "interface-resolution-failed", "Could not resolve the automatic WAN interfaces.")
		}
		if len(preserveReloadInterfaceBindings(active.conf, &probe)) != 0 {
			return rejected, configCreateDiagnostic(target.id, "restart-required", "Interface removal or role changes require a restart.")
		}
	}
	if !e.isCurrentConfigCreateDir(dir) {
		return rejected, configCreateUnavailable()
	}
	name := filepath.Base(target.abs)
	var info unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &info, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return rejected, configSourceExists()
	} else if !errors.Is(err, unix.ENOENT) {
		return rejected, configCreateUnavailable()
	}
	current, err := e.loadSources()
	if err != nil || !slices.EqualFunc(all, current, func(a, b configSourceFile) bool {
		return a.abs == b.abs && bytes.Equal(a.raw, b.raw)
	}) {
		return rejected, nativeapi.NewAPIError(409, "state_conflict", "the source set changed during validation")
	}
	var mode os.FileMode
	for _, source := range current {
		stat, err := os.Lstat(source.abs)
		if err != nil || !stat.Mode().IsRegular() {
			return rejected, configCreateUnavailable()
		}
		if source.abs == e.mainPath {
			mode = stat.Mode().Perm()
		}
	}
	identity, err := installConfigSource(dir, name, content, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return rejected, configSourceExists()
		}
		e.log.WithError(err).Warn("cannot store new config source")
		return rejected, configCreateUnavailable()
	}
	// Keep the directory and created inode alive until completion so a
	// replacement cannot reuse the created file's identity.
	complete := func(committed *bool) *nativeapi.SafeError {
		defer func() { _ = identity.Close() }()
		defer func() { _ = dir.Close() }()
		e.mu.Lock()
		defer e.mu.Unlock()
		unlock := e.lockConfigRead()
		defer unlock()
		if committed == nil {
			return configWriteFailure(true, nil, "reload was interrupted before its activation could be confirmed")
		}
		if *committed {
			return nil
		}
		if !e.isCurrentConfigCreateDir(dir) || !removeCreatedConfigSource(dir, name, identity, content) {
			return configWriteFailure(true, committed, "reload was rejected and cleanup conflicted with the config store")
		}
		return configWriteFailure(false, committed, "reload was rejected and the new source was removed")
	}
	var accepted nativeapi.OperationAccepted
	if e.isCurrentConfigCreateDir(dir) {
		accepted, err = queue.StartConfigCreate(ctx, scope, key, complete)
	} else {
		err = configCreateUnavailable()
	}
	if err != nil {
		defer func() { _ = identity.Close() }()
		if !removeCreatedConfigSource(dir, name, identity, content) {
			no := false
			failure := configWriteFailure(true, &no, "reload admission failed and cleanup conflicted with the config store")
			return rejected, &nativeapi.APIError{Status: 503, Code: "temporarily_unavailable", Message: failure.Message, Details: failure.Details}
		}
		return rejected, err
	}
	return accepted, nil
}

func (e *configEditor) isCurrentConfigCreateDir(dir *os.File) bool {
	pinned, err := dir.Stat()
	if err != nil {
		return false
	}
	current, err := os.Lstat(filepath.Join(e.baseDir, "config.d"))
	return err == nil && os.SameFile(pinned, current)
}

func installConfigSource(dir *os.File, name string, content []byte, mode os.FileMode) (*os.File, error) {
	file, err := stageConfigSource(dir, content, mode)
	if err != nil {
		return nil, err
	}
	fd := int(dir.Fd())
	if err := unix.Renameat2(fd, file.Name(), fd, name, unix.RENAME_NOREPLACE); err != nil {
		_ = file.Close()
		_ = unix.Unlinkat(fd, file.Name(), 0)
		return nil, err
	}
	return file, nil
}

func stageConfigSource(dir *os.File, content []byte, mode os.FileMode) (*os.File, error) {
	fd := int(dir.Fd())
	tmp := ".dae-config-" + rand.Text() + ".tmp"
	created, err := unix.Openat(fd, tmp, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(created), tmp)
	if _, err = file.Write(content); err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		_ = file.Close()
		_ = unix.Unlinkat(fd, tmp, 0)
		return nil, err
	}
	return file, nil
}

func removeCreatedConfigSource(dir *os.File, name string, identity *os.File, content []byte) bool {
	fd := int(dir.Fd())
	matched, absent := matchesConfigSource(fd, name, identity, nil, content, false)
	if !matched {
		return absent
	}
	// Move the directory entry before deleting it so a replacement published
	// between the check and rename can be detected and restored. If another
	// writer has since taken the original name, preserve both entries.
	quarantine := ".dae-config-" + rand.Text() + ".tmp"
	if err := unix.Renameat2(fd, name, fd, quarantine, unix.RENAME_NOREPLACE); err != nil {
		return errors.Is(err, unix.ENOENT)
	}
	if matched, _ := matchesConfigSource(fd, quarantine, identity, nil, content, false); matched {
		if err := unix.Unlinkat(fd, quarantine, 0); err == nil {
			return true
		}
	}
	_ = unix.Renameat2(fd, quarantine, fd, name, unix.RENAME_NOREPLACE)
	return false
}

func matchesConfigSource(fd int, name string, identity *os.File, expected os.FileInfo, content []byte, followSymlink bool) (matched, absent bool) {
	created, err := identity.Stat()
	if err != nil {
		return false, false
	}
	openFlags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC
	statFlags := 0
	if !followSymlink {
		openFlags |= unix.O_NOFOLLOW
		statFlags = unix.AT_SYMLINK_NOFOLLOW
	}
	currentFD, err := unix.Openat(fd, name, openFlags, 0)
	if err != nil {
		return false, errors.Is(err, unix.ENOENT)
	}
	current := os.NewFile(uintptr(currentFD), name)
	defer func() { _ = current.Close() }()
	var before unix.Stat_t
	if err := unix.Fstat(currentFD, &before); err != nil {
		return false, false
	}
	stat, err := current.Stat()
	if err != nil || !stat.Mode().IsRegular() || !os.SameFile(created, stat) || stat.Size() != int64(len(content)) {
		return false, false
	}
	if expected != nil && (stat.Mode() != expected.Mode() || !stat.ModTime().Equal(expected.ModTime())) {
		return false, false
	}
	raw, err := io.ReadAll(io.LimitReader(current, int64(len(content))+1))
	if err != nil || !bytes.Equal(raw, content) {
		return false, false
	}
	var latest unix.Stat_t
	if err := unix.Fstatat(fd, name, &latest, statFlags); err != nil {
		return false, errors.Is(err, unix.ENOENT)
	}
	return latest.Ino == before.Ino && latest.Dev == before.Dev && latest.Ctim == before.Ctim, false
}

func configWriteFailure(written bool, committed *bool, message string) *nativeapi.SafeError {
	return &nativeapi.SafeError{
		Code: "reload_rejected", Message: message,
		Details: map[string]any{"written": written, "committed": committed},
	}
}

func fingerprintReplace(req nativeapi.ReplaceConfigSourceRequest) string {
	return rawSHA256([]byte(req.SourceID + "\x00" + req.IfMatch + "\x00" + req.Content))
}

// sourceUpdateScope is the request identity shared by the preflight replay
// check and the operation store. The fingerprint already covers the target,
// the expected revision and the requested content.
func sourceUpdateScope(targetAbs, fingerprint string) string {
	return targetAbs + "\x00" + fingerprint
}

// replaySourceUpdate checks the operation store before a write path performs
// any filesystem side effect. The store is the single replay authority: keeping
// a second, smaller editor-side cache let a key evicted there write disk and
// then replay an operation that never queued a reload.
func (e *configEditor) replaySourceUpdate(kind, scope, idempotencyKey string) (nativeapi.OperationAccepted, bool, error) {
	if idempotencyKey == "" || e.operations == nil {
		return nativeapi.OperationAccepted{}, false, nil
	}
	return e.operations.ReplayOperation(kind, scope, idempotencyKey)
}

func (e *configEditor) ReplaceConfigSource(ctx context.Context, req nativeapi.ReplaceConfigSourceRequest) (nativeapi.OperationAccepted, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	fingerprint := fingerprintReplace(req)
	all, err := e.loadSources()
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if ok, reason := e.layoutOK(all); !ok {
		return nativeapi.OperationAccepted{}, permissionDenied("config writes are not available", reason)
	}
	if len(req.Content) > configMaxBytes {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 413, Code: "request_too_large", Message: "config source is too large",
		}
	}

	target, err := findSource(e.visibleSources(all), req.SourceID)
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if !e.sourceWritable(target) {
		return nativeapi.OperationAccepted{}, permissionDenied("this source is read-only", "entry_source")
	}
	scope := sourceUpdateScope(target.abs, fingerprint)
	if accepted, replayed, err := e.replaySourceUpdate(nativeapi.OperationKindReload, scope, req.IdempotencyKey); err != nil || replayed {
		return accepted, err
	}
	if e.apiAtStart.Secret != "" && strings.Contains(req.Content, e.apiAtStart.Secret) {
		return nativeapi.OperationAccepted{}, permissionDenied("source must not contain the listener secret", "listener_secret_in_content")
	}
	if req.IfMatch != rawSHA256(target.raw) {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 412, Code: nativeapi.CodeStaleRevision,
			Message: "config source changed since it was read",
		}
	}
	if err := e.guardConfigWrite(target, []byte(req.Content)); err != nil {
		return nativeapi.OperationAccepted{}, err
	}

	// Validate the candidate with full checks before touching disk.
	candidate, buildErr := e.buildCandidate(map[string][]byte{target.abs: []byte(req.Content)}, nil)
	if buildErr != nil {
		return nativeapi.OperationAccepted{}, e.unprocessable(buildErr, target)
	}
	if fullErr := e.fullValidate(candidate); fullErr != nil {
		return nativeapi.OperationAccepted{}, e.unprocessable(fullErr, target)
	}
	if err := e.guardApiUnchanged(candidate); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	return e.commitValidatedSource(ctx, target, []byte(req.Content), nativeapi.OperationKindReload, scope, req.IdempotencyKey, nil)
}

// candidateLayoutReason checks the candidate bytes, not just the tree on disk.
// The managed layout requires one section name per file: a write that declares
// a second dns/group/node section from another file passed semantic validation,
// then made detectManagedLayout reject every later write, including the one
// that would repair it.
func (e *configEditor) candidateLayoutReason(targetAbs string, content []byte) string {
	if includeKeywordPattern.Match(content) {
		return "a managed source must not contain an include block"
	}
	_, origins, err := config.NewMergerWithOverrides(e.mainPath, map[string][]byte{targetAbs: content}).MergeWithOrigins()
	if err != nil {
		// Parse and merge failures are reported by the validation that follows.
		return ""
	}
	for _, occurrences := range origins {
		files := map[string]struct{}{}
		for _, origin := range occurrences {
			files[origin.File] = struct{}{}
		}
		if len(files) > 1 {
			return "a section is declared by more than one file"
		}
	}
	return ""
}

// guardConfigWrite applies the checks every configuration write must pass before
// it touches disk, so the config PUT path and the node write paths cannot drift
// apart. A node write that skipped them could plant the listener secret in a
// visible source or race a running reload.
func (e *configEditor) guardConfigWrite(target configSourceFile, content []byte) error {
	if e.apiAtStart.Secret != "" && strings.Contains(string(content), e.apiAtStart.Secret) {
		return permissionDenied("source must not contain the listener secret", "listener_secret_in_content")
	}
	// The listener block belongs to api.dae. A second api section elsewhere
	// leaves the effective settings unchanged, so the value comparison lets it
	// through, but the layout check then sees one section declared by two files
	// and refuses every later write, including the one that would repair it.
	if !e.isApiSource(target.abs) && declaresApiSection(string(content)) {
		return permissionDenied("the api section may only be declared in the listener source", "listener_secret_in_content")
	}
	if !slices.Contains(managedConfigModules, filepath.Base(target.abs)) && takesManagedSection(target.raw, content) {
		return configCreateDiagnostic(target.id, "config_invalid", "This section belongs to a required managed source.")
	}
	if reason := e.candidateLayoutReason(target.abs, content); reason != "" {
		return &nativeapi.APIError{
			Status: 422, Code: "unsupported_value",
			Message: "the write would make the managed configuration layout unmanaged: " + reason,
		}
	}
	if err := e.guardReloadIdle(); err != nil {
		return err
	}
	// W_OK check: an unwritable file would fail after the backup was taken.
	if syscall.Access(target.abs, 2) != nil {
		return &nativeapi.APIError{
			Status: 503, Code: "temporarily_unavailable", Message: "config source is not writable right now",
			Details: map[string]any{"reason": "file_unwritable"},
		}
	}
	return nil
}

func (e *configEditor) guardReloadIdle() error {
	if e.busy() {
		return &nativeapi.APIError{
			Status:  409,
			Code:    "state_conflict",
			Message: "a reload is already in progress",
			Details: map[string]any{"reason": "reload_in_progress"},
		}
	}
	return nil
}

// A supplemental file cannot claim a required module's section, even when
// that module is empty. Preserve the ability to edit any existing owner.
func takesManagedSection(previous, content []byte) bool {
	sections, err := config_parser.Parse(string(content))
	if err != nil {
		return false
	}
	prior, _ := config_parser.Parse(string(previous))
	for _, section := range sections {
		if slices.Contains(managedConfigModules, section.Name+".dae") && !slices.ContainsFunc(prior, func(old *config_parser.Section) bool {
			return old.Name == section.Name
		}) {
			return true
		}
	}
	return false
}

func (e *configEditor) isApiSource(abs string) bool {
	return filepath.Base(abs) == hiddenConfigSourceName
}

// declaresApiSection reports whether a source text declares an api block.
func declaresApiSection(content string) bool {
	sections, err := config_parser.Parse(content)
	if err != nil {
		// An unparsable candidate is rejected by the validation that follows.
		return false
	}
	for _, section := range sections {
		if section.Name == "api" {
			return true
		}
	}
	return false
}

// lockConfigRead blocks the reload worker from reading the tree until the write
// either queued its operation or restored the previous bytes. Without it a
// reload could read the candidate between the write and the rollback and
// publish an edit the caller was told was rejected.
func (e *configEditor) lockConfigRead() func() {
	if e.reload == nil {
		return func() {}
	}
	e.reload.configReadMu.Lock()
	return e.reload.configReadMu.Unlock
}

// guardApiUnchanged refuses a candidate that would move the process-owned
// listener settings. The API config cannot be changed through the config API, and
// a node write is a config write too.
func (e *configEditor) guardApiUnchanged(candidate *config.Config) error {
	if candidate == nil || reflect.DeepEqual(candidate.Api, e.apiAtStart) {
		return nil
	}
	return &nativeapi.APIError{
		Status: 403, Code: "permission_denied",
		Message: "api listener settings cannot be changed through the config API",
	}
}

func (e *configEditor) unprocessable(err error, target configSourceFile) error {
	// A parse error carries a line but no path, so the target is the fallback.
	diags := e.diagnosticsFor(err, map[string]string{target.abs: target.id}, target.id, "config_invalid")
	if len(diags) == 0 {
		diags = []nativeapi.ConfigDiagnostic{invalidDiagnostic(target.id)}
	}
	return &nativeapi.APIError{
		Status:  422,
		Code:    "unsupported_value",
		Message: "configuration is invalid",
		Details: map[string]any{"diagnostics": diags},
	}
}

// writeFileAtomic writes via a temp file in the same directory and renames it
// into place, so readers see either the old or the new bytes.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".dae-config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
