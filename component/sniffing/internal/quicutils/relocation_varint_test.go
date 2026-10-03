/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"errors"
	"testing"
)

// quicVarint8Bytes returns the 8-byte QUIC variable-length encoding of v
// (RFC 9000 §16), for values that must exercise the 62-bit range.
func quicVarint8Bytes(v uint64) []byte {
	return []byte{0xc0 | byte(v>>56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// TestExtractCryptoFrameOffsetRejectsHugeVarints pins the uint64-domain
// bounds: the CRYPTO frame's length and offset varints are attacker-controlled
// and can reach ~2^62. A length of 2^31 wraps int on 32-bit builds (the guard
// used to pass and the slice panicked), and an offset at or above the Initial
// crypto bound is garbage on every arch (it used to be silently truncated into
// UpperAppOffset on 32-bit and accepted on 64-bit).
func TestExtractCryptoFrameOffsetRejectsHugeVarints(t *testing.T) {
	// Length 2^31 with a one-byte payload buffer: must be ErrOutOfRange on
	// every arch, not a panic on 386.
	f := append([]byte{Quic_FrameType_Crypto, 0}, quicVarint8Bytes(1<<31)...)
	_, _, err := ExtractCryptoFrameOffset(f, 0)
	if !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("length 2^31: err = %v, want ErrOutOfRange", err)
	}

	// Offset at the Initial crypto bound with a zero-length payload: rejected
	// before any int conversion.
	f = append([]byte{Quic_FrameType_Crypto, 0}, quicVarint8Bytes(quicMaxInitialCryptoOffset)...)
	f = append(f, 0) // length 0
	_, _, err = ExtractCryptoFrameOffset(f, 0)
	if !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("offset at bound: err = %v, want ErrOutOfRange", err)
	}

	// Control: an in-bounds frame still parses and reports its offset.
	f = []byte{Quic_FrameType_Crypto, 0x10, 3, 'a', 'b', 'c'} // offset 16, length 3
	o, frameSize, err := ExtractCryptoFrameOffset(f, 0)
	if err != nil {
		t.Fatalf("in-bounds frame: %v", err)
	}
	if o == nil || o.UpperAppOffset != 16 || string(o.Data) != "abc" || frameSize != len(f) {
		t.Fatalf("in-bounds frame = %+v, size %d, want offset 16 data abc size %d", o, frameSize, len(f))
	}
	ReleaseCryptoFrameOffset(o)
}
