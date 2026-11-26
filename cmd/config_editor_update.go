/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/daeuniverse/dae/component/nativeapi"
	"golang.org/x/sys/unix"
)

// commitValidatedSource is shared by config PUT and managed node and provider
// writes. The caller holds e.mu across validation and admission.
func (e *configEditor) commitValidatedSource(
	ctx context.Context,
	target configSourceFile,
	content []byte,
	kind, scope, idempotencyKey string,
	resolve func() (any, error),
) (nativeapi.OperationAccepted, error) {
	var rejected nativeapi.OperationAccepted
	unlock := e.lockConfigRead()
	defer unlock()
	if err := ctx.Err(); err != nil {
		return rejected, err
	}

	if err := e.guardReloadIdle(); err != nil {
		return rejected, err
	}

	parent, name := filepath.Dir(target.abs), filepath.Base(target.abs)
	dir, err := os.Open(parent)
	if err != nil {
		return rejected, fmt.Errorf("open config source directory: %w", err)
	}
	identity, written, err := storeConfigUpdate(dir, parent, name, target.raw, content)
	if err != nil {
		_ = dir.Close()
		return rejected, err
	}
	closeFiles := func() {
		_ = identity.Close()
		_ = dir.Close()
	}
	restore := func() bool {
		return restoreConfigUpdate(dir, parent, name, identity, written, target.raw, content)
	}
	complete := func(committed *bool) *nativeapi.SafeError {
		defer closeFiles()
		if committed == nil {
			return configWriteFailure(true, nil, "reload was interrupted before its activation could be confirmed")
		}
		if *committed {
			return nil
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		unlock := e.lockConfigRead()
		defer unlock()
		if !restore() {
			return configWriteFailure(true, committed, "reload was rejected and the previous source could not be safely restored")
		}
		return configWriteFailure(false, committed, "reload was rejected and the previous source was restored")
	}
	var accepted nativeapi.OperationAccepted
	if isCurrentConfigDir(dir, parent) {
		accepted, err = e.operations.StartConfigUpdate(ctx, kind, scope, idempotencyKey, resolve, complete)
	} else {
		err = staleConfigSource()
	}
	if err != nil {
		defer closeFiles()
		if !restore() {
			e.log.Error("failed to safely restore config source after rejected reload admission")
		}
		return rejected, err
	}
	return accepted, nil
}

func storeConfigUpdate(dir *os.File, parent, name string, previous, content []byte) (*os.File, os.FileInfo, error) {
	fd := int(dir.Fd())
	opened, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("re-read config source: %w", err)
	}
	onDisk := os.NewFile(uintptr(opened), name)
	defer func() { _ = onDisk.Close() }()
	info, err := onDisk.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat config source: %w", err)
	}
	if matched, _ := matchesConfigSource(fd, name, onDisk, info, previous, true); !matched || !isCurrentConfigDir(dir, parent) {
		return nil, nil, staleConfigSource()
	}

	backup, err := stageConfigSource(dir, previous, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("write config backup: %w", err)
	}
	defer func() {
		_ = backup.Close()
		_ = unix.Unlinkat(fd, backup.Name(), 0)
	}()
	candidate, err := stageConfigSource(dir, content, info.Mode().Perm())
	if err != nil {
		return nil, nil, fmt.Errorf("write config source: %w", err)
	}
	defer func() { _ = unix.Unlinkat(fd, candidate.Name(), 0) }()
	written, err := candidate.Stat()
	if err != nil {
		_ = candidate.Close()
		return nil, nil, fmt.Errorf("stat staged config source: %w", err)
	}
	// Validation and staging can take time. Check the source again just before
	// publishing the backup and atomically replacing the source.
	if matched, _ := matchesConfigSource(fd, name, onDisk, info, previous, true); !matched || !isCurrentConfigDir(dir, parent) {
		_ = candidate.Close()
		return nil, nil, staleConfigSource()
	}
	if err := unix.Renameat(fd, backup.Name(), fd, name+".bak"); err != nil {
		_ = candidate.Close()
		return nil, nil, fmt.Errorf("write config backup: %w", err)
	}
	if err := unix.Renameat(fd, candidate.Name(), fd, name); err != nil {
		_ = candidate.Close()
		return nil, nil, fmt.Errorf("write config source: %w", err)
	}
	return candidate, written, nil
}

func staleConfigSource() *nativeapi.APIError {
	return &nativeapi.APIError{Status: 412, Code: nativeapi.CodeStaleRevision, Message: "config source changed since it was read"}
}

func isCurrentConfigDir(dir *os.File, parent string) bool {
	pinned, err := dir.Stat()
	if err != nil {
		return false
	}
	current, err := os.Stat(parent)
	return err == nil && os.SameFile(pinned, current)
}

func restoreConfigUpdate(dir *os.File, parent, name string, identity *os.File, written os.FileInfo, previous, content []byte) bool {
	fd := int(dir.Fd())
	if matched, _ := matchesConfigSource(fd, name, identity, written, content, false); !matched || !isCurrentConfigDir(dir, parent) {
		return false
	}
	restored, err := stageConfigSource(dir, previous, written.Mode().Perm())
	if err != nil {
		return false
	}
	defer func() {
		_ = restored.Close()
		_ = unix.Unlinkat(fd, restored.Name(), 0)
	}()
	// Check the exact entry moved out of the way. If an external writer
	// changed it or takes the name during rollback, preserve their entry.
	quarantine := ".dae-config-" + rand.Text() + ".tmp"
	if err := unix.Renameat2(fd, name, fd, quarantine, unix.RENAME_NOREPLACE); err != nil {
		return false
	}
	if matched, _ := matchesConfigSource(fd, quarantine, identity, written, content, false); matched && isCurrentConfigDir(dir, parent) {
		if err := unix.Renameat2(fd, restored.Name(), fd, name, unix.RENAME_NOREPLACE); err == nil {
			_ = unix.Unlinkat(fd, quarantine, 0)
			return isCurrentConfigDir(dir, parent)
		}
	}
	// If the name was claimed again, the displaced entry remains recoverable
	// at the temporary path in the same directory.
	_ = unix.Renameat2(fd, quarantine, fd, name, unix.RENAME_NOREPLACE)
	return false
}
