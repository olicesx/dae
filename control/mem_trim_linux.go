//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DefaultTrimThreshold is the number of consecutive idle rounds before pages are reclaimed.
const DefaultTrimThreshold = 3

// ReleasePhysicalPages inspects the slice's underlying memory address and aligns it
// to OS page boundaries (start aligned up, end aligned down). It then invokes
// madvise(MADV_DONTNEED) to immediately hand idle physical pages back to the kernel
// without releasing the virtual address space.
//
// When the application subsequently writes to this range, the kernel automatically
// allocates new zeroed physical pages via minor page faults.
func ReleasePhysicalPages(b []byte) (int, bool) {
	if len(b) == 0 {
		return 0, false
	}
	pageSize := uintptr(os.Getpagesize())
	ptr := uintptr(unsafe.Pointer(&b[0]))

	// Align start up to the nearest page boundary
	start := (ptr + pageSize - 1) &^ (pageSize - 1)
	// Align end down to the nearest page boundary
	end := (ptr + uintptr(len(b))) &^ (pageSize - 1)

	if end <= start {
		return 0, false
	}

	length := end - start
	slice := unsafe.Slice((*byte)(unsafe.Pointer(start)), length)
	err := unix.Madvise(slice, unix.MADV_DONTNEED)
	if err != nil {
		return 0, false
	}
	return int(length), true
}

// ManagedMemoryArena manages a contiguous block of anonymous memory (allocated via mmap)
// for high-throughput packet processing, with adaptive idle compaction and page reclamation.
type ManagedMemoryArena struct {
	mu           sync.Mutex
	data         []byte
	chunkSize    int
	totalChunks  int
	freeChunks   []int
	inUseCount   int
	idleRounds   int
	isDecommitted bool
}

// NewManagedMemoryArena allocates a contiguous virtual memory arena of totalBytes via mmap.
func NewManagedMemoryArena(totalBytes, chunkSize int) (*ManagedMemoryArena, error) {
	if totalBytes <= 0 || chunkSize <= 0 {
		panic("invalid arena size")
	}

	// Align totalBytes to page size
	pageSize := os.Getpagesize()
	totalBytes = (totalBytes + pageSize - 1) &^ (pageSize - 1)

	data, err := unix.Mmap(
		-1,
		0,
		totalBytes,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE,
	)
	if err != nil {
		return nil, err
	}

	numChunks := totalBytes / chunkSize
	freeChunks := make([]int, numChunks)
	for i := 0; i < numChunks; i++ {
		freeChunks[i] = i
	}

	return &ManagedMemoryArena{
		data:        data,
		chunkSize:   chunkSize,
		totalChunks: numChunks,
		freeChunks:  freeChunks,
	}, nil
}

// Alloc acquires a chunk from the arena.
func (a *ManagedMemoryArena) Alloc() ([]byte, int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.freeChunks) == 0 {
		return nil, -1, false
	}

	idx := a.freeChunks[len(a.freeChunks)-1]
	a.freeChunks = a.freeChunks[:len(a.freeChunks)-1]
	a.inUseCount++
	a.idleRounds = 0
	a.isDecommitted = false

	offset := idx * a.chunkSize
	return a.data[offset : offset+a.chunkSize], idx, true
}

// Free returns a chunk back to the arena.
func (a *ManagedMemoryArena) Free(chunkIdx int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if chunkIdx < 0 || chunkIdx >= a.totalChunks {
		return
	}

	a.freeChunks = append(a.freeChunks, chunkIdx)
	a.inUseCount--
	if a.inUseCount < 0 {
		a.inUseCount = 0
	}
}

// Trim checks if all chunks are free. If it remains completely idle for at least
// threshold rounds, it yields its physical pages back to the kernel.
func (a *ManagedMemoryArena) Trim(threshold int) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.inUseCount > 0 {
		a.idleRounds = 0
		return 0, false
	}

	a.idleRounds++
	if a.idleRounds >= threshold && !a.isDecommitted {
		freed, ok := ReleasePhysicalPages(a.data)
		if ok {
			a.isDecommitted = true
			return freed, true
		}
	}
	return 0, false
}

// Destroy unmaps the arena.
func (a *ManagedMemoryArena) Destroy() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.data) > 0 {
		err := unix.Munmap(a.data)
		a.data = nil
		return err
	}
	return nil
}

// TrimProcessMemory performs a coordinated heap and system memory reclamation,
// suitable for execution during long quiet/idle windows on resource-constrained routers.
func TrimProcessMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}
