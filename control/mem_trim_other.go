//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"runtime"
	"runtime/debug"
)

const DefaultTrimThreshold = 3

func ReleasePhysicalPages(b []byte) (int, bool) {
	return 0, false
}

type ManagedMemoryArena struct{}

func NewManagedMemoryArena(totalBytes, chunkSize int) (*ManagedMemoryArena, error) {
	return nil, errors.New("managed arena not supported on non-linux")
}

func (a *ManagedMemoryArena) Alloc() ([]byte, int, bool) {
	return nil, -1, false
}

func (a *ManagedMemoryArena) Free(chunkIdx int) {}

func (a *ManagedMemoryArena) Trim(threshold int) (int, bool) {
	return 0, false
}

func (a *ManagedMemoryArena) Destroy() error {
	return nil
}

func TrimProcessMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}
