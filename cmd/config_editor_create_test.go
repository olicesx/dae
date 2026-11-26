/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/stretchr/testify/require"
)

func TestConfigCreateWithAutoWAN(t *testing.T) {
	e, _, manager := newCreateEditor(t)
	require.NoError(t, os.WriteFile(filepath.Join(e.baseDir, "config.d", "global.dae"), []byte(`global {
 wan_interface: auto
}
`), 0o600))
	active, err := e.buildCandidate(nil, nil)
	require.NoError(t, err)
	require.NoError(t, preprocessWanInterfaceAuto(active))
	if len(active.Global.WanInterface) == 0 {
		t.Skip("requires a default route")
	}
	e.supervisor = newRuntimeSupervisor(newRuntimeGeneration(nil, nil, nil, active))
	_, err = e.CreateConfigSource(context.Background(), nativeapi.CreateConfigSourceRequest{Path: "config.d/extra.dae"})
	require.NoError(t, err)
	require.Len(t, manager.reloadReqs, 1)
}

// A single-homed host binds one link as both LAN and WAN. Creating a source
// keeps that link and its roles, so the preflight must accept it.
func TestConfigCreateOnDualRoleLink(t *testing.T) {
	e, _, manager := newCreateEditor(t)
	module := "global {\n lan_interface: eth0\n wan_interface: eth0\n}\n"
	require.NoError(t, os.WriteFile(filepath.Join(e.baseDir, "config.d", "global.dae"), []byte(module), 0o600))
	active, err := e.buildCandidate(nil, nil)
	require.NoError(t, err)
	e.supervisor = newRuntimeSupervisor(newRuntimeGeneration(nil, nil, nil, active))
	_, err = e.CreateConfigSource(context.Background(), nativeapi.CreateConfigSourceRequest{Path: "config.d/extra.dae"})
	require.NoError(t, err)
	require.Len(t, manager.reloadReqs, 1)
}

func newCreateEditor(t *testing.T) (*configEditor, *nativeAPIOperations, *reloadManager) {
	t.Helper()
	main, _ := newManagedTree(t)
	operations, manager := newTestOperations()
	manager.setRuntimeStatus(newRuntimeStatus())
	manager.status.setState(runtimeStateRunning)
	manager.setReloadObserver(operations.FollowReload)
	t.Cleanup(operations.finishInterruptedConfigCreates)
	return newFlowEditorWithReload(t, main, true, operations, manager), operations, manager
}

func TestCreateConfigSourceEmptyAndReplay(t *testing.T) {
	e, operations, manager := newCreateEditor(t)
	require.True(t, e.ConfigCapabilities().Create)
	ctx := context.Background()
	require.NoError(t, os.Chmod(e.mainPath, 0o640))
	before, err := e.GetConfig(ctx)
	require.NoError(t, err)
	req := nativeapi.CreateConfigSourceRequest{Path: "config.d/extra.dae", IdempotencyKey: "create-key"}
	accepted, err := e.CreateConfigSource(ctx, req)
	require.NoError(t, err)
	require.Equal(t, nativeapi.OperationKindReload, accepted.Kind)
	request := <-manager.reloadReqs
	require.Equal(t, accepted.OperationID, request.apiOperationID)
	manager.beginRuntimeReload(request)
	manager.finishReloadSuccess()
	operation, found, err := operations.GetOperation(ctx, accepted.OperationID)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, nativeapi.OperationStatusSucceeded, operation.Status)
	require.IsType(t, nativeapi.ReloadResult{}, operation.Result)

	after, err := e.GetConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, before.Revision, after.Revision, "an empty source does not change the semantic revision")
	require.Len(t, after.Sources, len(before.Sources)+1)
	source, complete, err := e.GetConfigSource(ctx, sourceIDFor(req.Path))
	require.NoError(t, err)
	require.True(t, complete)
	require.Equal(t, req.Path, source.Path)
	require.Zero(t, source.LineCount)
	require.Equal(t, rawSHA256(nil), source.ContentSHA256)
	file, err := os.Stat(filepath.Join(e.baseDir, req.Path))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), file.Mode().Perm())
	require.True(t, e.ConfigCapabilities().Writable)

	replayed, err := e.CreateConfigSource(ctx, req)
	require.NoError(t, err)
	require.Equal(t, accepted, replayed)
	require.Empty(t, manager.reloadReqs)
	req.Content = "# revised\n"
	_, err = e.CreateConfigSource(ctx, req)
	require.Equal(t, "idempotency_conflict", flowAPIError(t, err).Code)
	req.IdempotencyKey = ""
	_, err = e.CreateConfigSource(ctx, req)
	require.Equal(t, "state_conflict", flowAPIError(t, err).Code)
}

func TestCreateConfigSourceValidation(t *testing.T) {
	for _, tc := range []struct {
		name, path, content string
		status              int
		diagnostic          string
	}{
		{"traversal", "config.d/../extra.dae", "", 400, ""},
		{"wrong extension", "config.d/extra.conf", "", 400, ""},
		{"hidden", "config.d/api.dae", "", 400, ""},
		{"missing include", "elsewhere/extra.dae", "", 422, "source-not-included"},
		{"section owner", "config.d/extra.dae", "node {}", 422, "config_invalid"},
		{"invalid syntax", "config.d/extra.dae", "node {", 422, "config_invalid"},
		{"nested include", "config.d/extra.dae", "include { x.dae }", 422, "config_invalid"},
		{"unknown section", "config.d/extra.dae", "unknown {}", 422, "config_invalid"},
		{"listener", "config.d/extra.dae", "api {}", 403, ""},
		{"secret", "config.d/extra.dae", "# flow-secret", 403, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _, manager := newCreateEditor(t)
			_, err := e.CreateConfigSource(context.Background(), nativeapi.CreateConfigSourceRequest{Path: tc.path, Content: tc.content})
			apiErr := flowAPIError(t, err)
			require.Equal(t, tc.status, apiErr.Status, apiErr)
			if tc.diagnostic != "" {
				diagnostics := apiErr.Details.(map[string]any)["diagnostics"].([]nativeapi.ConfigDiagnostic)
				require.Equal(t, tc.diagnostic, diagnostics[0].Code)
				id := sourceIDFor(tc.path)
				if tc.diagnostic == "source-not-included" {
					id = sourceIDFor("config.dae")
					require.Nil(t, diagnostics[0].Line)
				}
				require.Equal(t, id, diagnostics[0].SourceID)
			}
			require.NoFileExists(t, filepath.Join(e.baseDir, tc.path))
			require.Empty(t, manager.reloadReqs)
		})
	}
}

func TestCreateConfigSourceGuardsStoreAndRuntime(t *testing.T) {
	t.Run("symlinks and existing file", func(t *testing.T) {
		e, _, manager := newCreateEditor(t)
		outside := t.TempDir()
		require.NoError(t, os.Symlink(outside, filepath.Join(e.baseDir, "escape")))
		_, err := e.CreateConfigSource(context.Background(), nativeapi.CreateConfigSourceRequest{Path: "escape/missing/extra.dae"})
		require.Equal(t, 400, flowAPIError(t, err).Status)
		link := filepath.Join(e.baseDir, "config.d/extra.dae")
		require.NoError(t, os.Symlink(filepath.Join(outside, "no-file.dae"), link))
		_, err = e.CreateConfigSource(context.Background(), nativeapi.CreateConfigSourceRequest{Path: "config.d/extra.dae"})
		require.Equal(t, 409, flowAPIError(t, err).Status)
		require.NoFileExists(t, filepath.Join(outside, "no-file.dae"))
		require.Empty(t, manager.reloadReqs)
	})
	t.Run("suspended or busy", func(t *testing.T) {
		e, _, manager := newCreateEditor(t)
		manager.status.setState(runtimeStateSuspended)
		req := nativeapi.CreateConfigSourceRequest{Path: "config.d/extra.dae"}
		_, err := e.CreateConfigSource(context.Background(), req)
		require.Equal(t, 409, flowAPIError(t, err).Status)
		manager.status.setState(runtimeStateRunning)
		manager.reloadActive.Store(true)
		_, err = e.CreateConfigSource(context.Background(), req)
		require.Equal(t, 409, flowAPIError(t, err).Status)
		require.NoFileExists(t, filepath.Join(e.baseDir, req.Path))
		require.Empty(t, manager.reloadReqs)
	})
	t.Run("restart required", func(t *testing.T) {
		e, _, manager := newCreateEditor(t)
		active, err := e.buildCandidate(nil, nil)
		require.NoError(t, err)
		active.Global.LanInterface = []string{"old-lan"}
		e.supervisor = newRuntimeSupervisor(newRuntimeGeneration(nil, nil, nil, active))
		req := nativeapi.CreateConfigSourceRequest{Path: "config.d/extra.dae"}
		_, err = e.CreateConfigSource(context.Background(), req)
		apiErr := flowAPIError(t, err)
		require.Equal(t, 422, apiErr.Status)
		require.Equal(t, "restart-required", apiErr.Details.(map[string]any)["diagnostics"].([]nativeapi.ConfigDiagnostic)[0].Code)
		require.NoFileExists(t, filepath.Join(e.baseDir, req.Path))
		require.Empty(t, manager.reloadReqs)
	})
	t.Run("source count", func(t *testing.T) {
		e, _, manager := newCreateEditor(t)
		before, err := e.GetConfig(context.Background())
		require.NoError(t, err)
		for i := len(before.Sources); i < configMaxSources; i++ {
			path := filepath.Join(e.baseDir, fmt.Sprintf("config.d/extra-%d.dae", i))
			require.NoError(t, os.WriteFile(path, nil, 0o600))
		}
		_, err = e.CreateConfigSource(context.Background(), nativeapi.CreateConfigSourceRequest{Path: "config.d/extra.dae"})
		require.Equal(t, 413, flowAPIError(t, err).Status)
		require.Empty(t, manager.reloadReqs)
	})
}

func TestSupplementCannotClaimAnEmptyRequiredOwner(t *testing.T) {
	e, _, manager := newCreateEditor(t)
	ctx := context.Background()
	require.NoError(t, os.WriteFile(filepath.Join(e.baseDir, "config.d/node.dae"), nil, 0o600))
	path := "config.d/extra.dae"
	_, err := e.CreateConfigSource(ctx, nativeapi.CreateConfigSourceRequest{Path: path})
	require.NoError(t, err)
	manager.beginRuntimeReload(<-manager.reloadReqs)
	manager.finishReloadSuccess()
	_, err = e.ReplaceConfigSource(ctx, nativeapi.ReplaceConfigSourceRequest{
		SourceID: sourceIDFor(path), IfMatch: rawSHA256(nil), Content: "node {}",
	})
	require.Equal(t, 422, flowAPIError(t, err).Status)
	actual, err := os.ReadFile(filepath.Join(e.baseDir, path))
	require.NoError(t, err)
	require.Empty(t, actual)
	require.Empty(t, manager.reloadReqs)
}

func TestCreateConfigSourceRollback(t *testing.T) {
	t.Run("admission rejection", func(t *testing.T) {
		e, operations, manager := newCreateEditor(t)
		operations.stopAcceptingReloads()
		req := nativeapi.CreateConfigSourceRequest{Path: "config.d/extra.dae"}
		_, err := e.CreateConfigSource(context.Background(), req)
		require.Equal(t, 503, flowAPIError(t, err).Status)
		require.NoFileExists(t, filepath.Join(e.baseDir, req.Path))
		require.Empty(t, manager.reloadReqs)
	})
	for _, tc := range []struct {
		name                                   string
		replace, modify, restored, interrupted bool
	}{
		{name: "rejected"},
		{name: "legacy restore", restored: true},
		{name: "replacement with identical bytes", replace: true},
		{name: "edited in place", modify: true},
		{name: "unknown activation", interrupted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, operations, manager := newCreateEditor(t)
			ctx := context.Background()
			req := nativeapi.CreateConfigSourceRequest{Path: "config.d/extra.dae", Content: "# extra\n"}
			accepted, err := e.CreateConfigSource(ctx, req)
			require.NoError(t, err)
			manager.beginRuntimeReload(<-manager.reloadReqs)
			path := filepath.Join(e.baseDir, req.Path)
			if tc.replace {
				require.NoError(t, writeFileAtomic(path, []byte(req.Content), 0o600))
			}
			if tc.modify {
				require.NoError(t, os.WriteFile(path, []byte("# independently edited\n"), 0o600))
			}
			manager.setReloadError(errors.New("candidate failed"))
			switch {
			case tc.interrupted:
				operations.finishInterruptedConfigCreates()
			case tc.restored:
				manager.finishReloadSuccess()
			default:
				manager.finishReloadFailure()
			}
			operation, ok, err := operations.GetOperation(ctx, accepted.OperationID)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, nativeapi.OperationStatusFailed, operation.Status)
			details := operation.Error.Details.(map[string]any)
			kept := tc.replace || tc.modify || tc.interrupted
			require.Equal(t, kept, details["written"])
			if tc.interrupted {
				require.Nil(t, details["committed"])
			} else {
				require.False(t, *details["committed"].(*bool))
			}
			if kept {
				require.FileExists(t, path)
			} else {
				require.NoFileExists(t, path)
			}
		})
	}
}

func TestInstallConfigSourceDoesNotOverwrite(t *testing.T) {
	e, _, _ := newCreateEditor(t)
	dir, err := e.openConfigCreateDir()
	require.NoError(t, err)
	defer func() { _ = dir.Close() }()
	path := filepath.Join(e.baseDir, "config.d", "race.dae")
	require.NoError(t, os.WriteFile(path, []byte("winner"), 0o600))
	_, err = installConfigSource(dir, "race.dae", []byte("other"), 0o600)
	require.ErrorIs(t, err, os.ErrExist)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "winner", string(data))
	files, err := filepath.Glob(filepath.Join(e.baseDir, "config.d", ".dae-config-*.tmp"))
	require.NoError(t, err)
	require.Empty(t, files)
}

func TestCreateConfigSourceOverHTTP(t *testing.T) {
	e, operations, manager := newCreateEditor(t)
	server, err := nativeapi.NewServer(nativeapi.Config{Listen: "127.0.0.1:9527", AllowAnonymousLoopback: true}, e2eRuntime{}, e.log)
	require.NoError(t, err)
	server.SetConfigProvider(e)
	server.SetOperationProvider(operations)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Host = "127.0.0.1:9527"
		req.RemoteAddr = "127.0.0.1:50000"
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "doona-create")
		}
		result := httptest.NewRecorder()
		server.ServeHTTP(result, req)
		return result
	}
	const path = "config.d/doona.dae"
	accepted := request(http.MethodPost, "/api/v1/config/sources", `{"path":"config.d/doona.dae","content":""}`)
	require.Equal(t, http.StatusAccepted, accepted.Code, accepted.Body.String())
	location := accepted.Header().Get("Location")
	require.NotEmpty(t, location)
	manager.beginRuntimeReload(<-manager.reloadReqs)
	manager.finishReloadSuccess()
	operation := request(http.MethodGet, location, "")
	require.Equal(t, http.StatusOK, operation.Code, operation.Body.String())
	var state nativeapi.Operation
	require.NoError(t, json.Unmarshal(operation.Body.Bytes(), &state))
	require.Equal(t, nativeapi.OperationStatusSucceeded, state.Status)
	config := request(http.MethodGet, "/api/v1/config", "")
	require.Equal(t, http.StatusOK, config.Code, config.Body.String())
	var document nativeapi.EffectiveConfig
	require.NoError(t, json.Unmarshal(config.Body.Bytes(), &document))
	for _, source := range document.Sources {
		if source.Path == path {
			require.Equal(t, sourceIDFor(path), source.ID)
			require.True(t, source.Writable)
			return
		}
	}
	t.Fatal("the newly created source was not listed after reload")
}
