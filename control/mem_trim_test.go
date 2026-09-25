//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryTrimmer_PageAlignment(t *testing.T) {
	pageSize := os.Getpagesize()
	raw := make([]byte, pageSize*4)

	// Dirty the memory so kernel commits physical frames
	for i := range raw {
		raw[i] = 0xef
	}

	freed, ok := ReleasePhysicalPages(raw)
	require.True(t, ok)
	require.Positive(t, freed)
	require.Equal(t, len(raw), freed)

	// Memory remains valid and accessible after MADV_DONTNEED (re-zeroed on read)
	require.Equal(t, byte(0), raw[0])
	require.Equal(t, byte(0), raw[len(raw)-1])

	// Re-dirtying succeeds without panic
	raw[0] = 0x42
	require.Equal(t, byte(0x42), raw[0])
}

func TestManagedMemoryArena_Lifecycle(t *testing.T) {
	chunkSize := 4096
	totalBytes := 64 * 1024 // 64 KiB = 16 chunks

	arena, err := NewManagedMemoryArena(totalBytes, chunkSize)
	require.NoError(t, err)
	defer func() {
		_ = arena.Destroy()
	}()

	// 1. Allocate a chunk and verify write
	chunk1, id1, ok := arena.Alloc()
	require.True(t, ok)
	require.Len(t, chunk1, chunkSize)
	chunk1[0] = 0xaa
	chunk1[chunkSize-1] = 0xbb

	// 2. While chunk is in use, Trim should NOT release
	freed, trimmed := arena.Trim(1)
	require.False(t, trimmed)
	require.Equal(t, 0, freed)

	// 3. Free the chunk
	arena.Free(id1)

	// 4. Tick idle rounds until threshold (DefaultTrimThreshold = 3)
	for i := 0; i < DefaultTrimThreshold-1; i++ {
		_, trimmed = arena.Trim(DefaultTrimThreshold)
		require.False(t, trimmed)
	}

	// 5. Reaching threshold should trigger page handback
	freed, trimmed = arena.Trim(DefaultTrimThreshold)
	require.True(t, trimmed)
	require.Positive(t, freed)

	// 6. Next Alloc wakes arena back up
	chunk2, _, ok := arena.Alloc()
	require.True(t, ok)
	chunk2[0] = 0x55
	require.Equal(t, byte(0x55), chunk2[0])
}
