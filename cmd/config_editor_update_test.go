/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/stretchr/testify/require"
)

func TestConfigUpdateRestoresSourceOnReloadRejection(t *testing.T) {
	for _, tc := range []struct {
		name, source, kind string
		write              func(context.Context, *configEditor, configSourceFile, func() (any, error)) (nativeapi.OperationAccepted, error)
	}{
		{"config PUT", flowGlobalRel, nativeapi.OperationKindReload, func(ctx context.Context, e *configEditor, target configSourceFile, _ func() (any, error)) (nativeapi.OperationAccepted, error) {
			return e.ReplaceConfigSource(ctx, nativeapi.ReplaceConfigSourceRequest{
				SourceID: target.id, IfMatch: rawSHA256(target.raw), Content: flowValidGlobal, IdempotencyKey: "update",
			})
		}},
		{"node create", "config.d/node.dae", nativeapi.OperationKindNodeCreate, func(ctx context.Context, e *configEditor, _ configSourceFile, resolve func() (any, error)) (nativeapi.OperationAccepted, error) {
			return e.CreateNode(ctx, nativeapi.NodeCreateRequest{Name: "inline", Link: "socks5://127.0.0.1:1080", IdempotencyKey: "update"}, nil, resolve)
		}},
		{"provider create", "config.d/subscription.dae", nativeapi.OperationKindProviderCreate, func(ctx context.Context, e *configEditor, _ configSourceFile, resolve func() (any, error)) (nativeapi.OperationAccepted, error) {
			return e.CreateProvider(ctx, nativeapi.ProviderCreateRequest{Name: "subscription", URL: "https://a.example/s", IdempotencyKey: "update"}, noProviderNames, resolve)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, ops, manager := newCreateEditor(t)
			target := flowSource(t, e, tc.source)
			require.NoError(t, os.Chmod(target.abs, 0o640))
			resolve := func() (any, error) {
				t.Fatal("rejected reload resolved a successful result")
				return nil, nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			accepted, err := tc.write(ctx, e, target, resolve)
			require.NoError(t, err)
			require.Equal(t, tc.kind, accepted.Kind)
			candidate, err := os.ReadFile(target.abs)
			require.NoError(t, err)
			require.NotEqual(t, target.raw, candidate)
			cancel()
			manager.beginRuntimeReload(<-manager.reloadReqs)
			// A second API writer cannot modify the tree during this reload.
			_, err = e.ReplaceConfigSource(t.Context(), nativeapi.ReplaceConfigSourceRequest{
				SourceID: target.id, IfMatch: rawSHA256(candidate), Content: string(target.raw),
			})
			require.Equal(t, 409, flowAPIError(t, err).Status)
			manager.setReloadError(errors.New("candidate rejected"))
			manager.finishReloadFailure()
			op, ok, err := ops.GetOperation(t.Context(), accepted.OperationID)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, nativeapi.OperationStatusFailed, op.Status)
			require.Equal(t, "reload_rejected", op.Error.Code)
			committed := false
			require.Equal(t, map[string]any{"written": false, "committed": &committed}, op.Error.Details)
			require.Empty(t, ops.resultResolvers)
			for _, path := range []string{target.abs, target.abs + ".bak"} {
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, target.raw, data)
			}
			info, err := os.Stat(target.abs)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
			replay, err := tc.write(t.Context(), e, target, resolve)
			require.NoError(t, err)
			require.Equal(t, accepted, replay)
			require.Empty(t, manager.reloadReqs)
		})
	}
}

func TestConfigUpdateReloadCompletion(t *testing.T) {
	for _, scenario := range []string{"success", "result unavailable", "legacy restore", "external backup edit", "unknown activation", "external replace", "external edit", "external chmod", "external delete", "external directory replace"} {
		t.Run(scenario, func(t *testing.T) {
			e, ops, manager := newCreateEditor(t)
			target := flowSource(t, e, "config.d/subscription.dae")
			resolve := func() (any, error) {
				if scenario == "result unavailable" {
					return nil, errors.New("unavailable")
				}
				return "provider result", nil
			}
			accepted, err := e.CreateProvider(t.Context(), nativeapi.ProviderCreateRequest{Name: "sub", URL: "https://a.example/s"}, noProviderNames, resolve)
			require.NoError(t, err)
			manager.beginRuntimeReload(<-manager.reloadReqs)
			candidate, err := os.ReadFile(target.abs)
			require.NoError(t, err)
			want := candidate
			switch scenario {
			case "success", "result unavailable":
				manager.finishReloadSuccess()
			case "legacy restore":
				want = target.raw
				manager.setReloadError(errors.New("legacy reload restored the previous runtime config"))
				manager.finishReloadSuccess()
			case "external backup edit":
				want = target.raw
				require.NoError(t, os.WriteFile(target.abs+".bak", []byte("# external backup\n"), 0o600))
				manager.finishReloadFailure()
			case "unknown activation":
				ops.stopAcceptingReloads()
				ops.finishInterruptedConfigCreates()
				manager.finishReloadFailure()
			default:
				switch scenario {
				case "external replace":
					require.NoError(t, writeFileAtomic(target.abs, candidate, 0o600))
				case "external edit":
					want = []byte(string(candidate) + "# external edit\n")
					require.NoError(t, os.WriteFile(target.abs, want, 0o600))
				case "external chmod":
					require.NoError(t, os.Chmod(target.abs, 0o640))
				case "external delete":
					require.NoError(t, os.Remove(target.abs))
				case "external directory replace":
					parent := filepath.Dir(target.abs)
					require.NoError(t, os.Rename(parent, parent+".moved"))
					require.NoError(t, os.Mkdir(parent, 0o700))
					want = []byte("# external replacement directory\n")
					require.NoError(t, os.WriteFile(target.abs, want, 0o600))
				}
				manager.finishReloadFailure()
			}
			op, ok, err := ops.GetOperation(t.Context(), accepted.OperationID)
			require.NoError(t, err)
			require.True(t, ok)
			switch scenario {
			case "success":
				require.Equal(t, nativeapi.OperationStatusSucceeded, op.Status)
				require.Equal(t, "provider result", op.Result)
			case "result unavailable":
				require.Equal(t, nativeapi.OperationStatusFailed, op.Status)
				require.Equal(t, "result_unavailable", op.Error.Code)
			default:
				require.Equal(t, nativeapi.OperationStatusFailed, op.Status)
				require.Equal(t, "reload_rejected", op.Error.Code)
				var committed *bool
				if scenario != "unknown activation" {
					value := false
					committed = &value
				}
				require.Equal(t, map[string]any{"written": scenario != "legacy restore" && scenario != "external backup edit", "committed": committed}, op.Error.Details)
			}
			require.Empty(t, ops.resultResolvers)
			require.Empty(t, ops.configWriteCompletions)
			data, err := os.ReadFile(target.abs)
			if scenario == "external delete" {
				require.ErrorIs(t, err, os.ErrNotExist)
			} else {
				require.NoError(t, err)
				require.Equal(t, want, data)
			}
			if scenario == "external backup edit" {
				backup, err := os.ReadFile(target.abs + ".bak")
				require.NoError(t, err)
				require.Equal(t, "# external backup\n", string(backup))
			}
			if scenario == "external chmod" {
				info, err := os.Stat(target.abs)
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
			}
			if scenario == "external directory replace" {
				data, err := os.ReadFile(filepath.Join(filepath.Dir(target.abs)+".moved", filepath.Base(target.abs)))
				require.NoError(t, err)
				require.Equal(t, candidate, data)
			}
		})
	}
}

func TestConfigUpdateRechecksReloadBeforeStaging(t *testing.T) {
	e, _, manager := newCreateEditor(t)
	target := flowSource(t, e, flowGlobalRel)
	busy := e.busy
	checks := 0
	e.busy = func() bool {
		checks++
		if checks == 2 {
			require.True(t, manager.queueReloadRequest(nil, reloadRequest{}))
		}
		return busy()
	}
	_, err := e.ReplaceConfigSource(t.Context(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id, IfMatch: rawSHA256(target.raw), Content: flowValidGlobal,
	})
	require.Equal(t, 409, flowAPIError(t, err).Status)
	require.NoFileExists(t, target.abs+".bak")
	data, err := os.ReadFile(target.abs)
	require.NoError(t, err)
	require.Equal(t, target.raw, data)
	require.Empty(t, (<-manager.reloadReqs).apiOperationID)
	clearReloadPending(&manager.reloadPending)
}

type configUpdateAdmissionHook struct {
	*nativeAPIOperations
	beforeAdmission func()
}

func (q configUpdateAdmissionHook) StartConfigUpdate(ctx context.Context, kind, scope, key string, resolve func() (any, error), complete configWriteCompletion) (nativeapi.OperationAccepted, error) {
	q.beforeAdmission()
	return q.nativeAPIOperations.StartConfigUpdate(ctx, kind, scope, key, resolve, complete)
}

func TestConfigUpdateRestoresWhenReloadWinsAdmission(t *testing.T) {
	e, ops, manager := newCreateEditor(t)
	target := flowSource(t, e, flowGlobalRel)
	e.operations = configUpdateAdmissionHook{nativeAPIOperations: ops, beforeAdmission: func() {
		// A signal can reserve reload admission after the editor stages the
		// candidate, but its worker cannot read the candidate before rollback.
		require.False(t, manager.configReadMu.TryLock())
		data, err := os.ReadFile(target.abs)
		require.NoError(t, err)
		require.Equal(t, flowValidGlobal, string(data))
		require.True(t, manager.queueReloadRequest(nil, reloadRequest{}))
	}}
	accepted, err := e.ReplaceConfigSource(t.Context(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id, IfMatch: rawSHA256(target.raw), Content: flowValidGlobal, IdempotencyKey: "retry",
	})
	require.Equal(t, 409, flowAPIError(t, err).Status)
	require.Empty(t, accepted.OperationID)
	require.Empty(t, ops.configWriteCompletions)
	data, err := os.ReadFile(target.abs)
	require.NoError(t, err)
	require.Equal(t, target.raw, data)
	require.Empty(t, (<-manager.reloadReqs).apiOperationID)
	clearReloadPending(&manager.reloadPending)

	e.operations = ops
	accepted, err = e.ReplaceConfigSource(t.Context(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id, IfMatch: rawSHA256(target.raw), Content: flowValidGlobal, IdempotencyKey: "retry",
	})
	require.NoError(t, err)
	require.Equal(t, accepted.OperationID, (<-manager.reloadReqs).apiOperationID)
}
