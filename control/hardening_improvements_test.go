/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
)

// Locks the raw UDP fallback payload bound: the 16-bit UDP length field would
// wrap above 65507 bytes (65535 - 20 IPv4 header - 8 UDP header).
func TestValidateUDPRawPayloadLength(t *testing.T) {
	if err := validateUDPRawPayloadLength(0); err != nil {
		t.Fatalf("empty payload should pass: %v", err)
	}
	if err := validateUDPRawPayloadLength(maxUDPRawPayloadLength); err != nil {
		t.Fatalf("boundary payload should pass: %v", err)
	}
	if err := validateUDPRawPayloadLength(maxUDPRawPayloadLength + 1); err == nil {
		t.Fatal("oversized payload must be rejected (UDP length field would wrap)")
	}
}

// Locks ParsePortRange against a slice-out-of-bounds panic on short input.
func TestParsePortRangeShortInput(t *testing.T) {
	for n := 0; n < 4; n++ {
		buf := make([]byte, n)
		start, end := ParsePortRange(buf) // must not panic
		if start != 0 || end != 0 {
			t.Fatalf("len=%d: expected (0,0), got (%d,%d)", n, start, end)
		}
	}
	start, end := ParsePortRange([]byte{0x01, 0x00, 0xFF, 0x00})
	if start != 1 || end != 0xFF {
		t.Fatalf("expected (1,255), got (%d,%d)", start, end)
	}
}

// Locks releaseQueueCh idempotence: Close and the exiting convoy goroutine
// race over the same channel; a double-put would let sync.Pool hand the same
// channel to two queues.
func TestReleaseQueueChIdempotent(t *testing.T) {
	p := NewUdpTaskPool()
	ch1 := make(chan UdpTask)

	q := &UdpTaskQueue{p: p, ch: ch1}
	p.releaseQueueCh(q)
	p.releaseQueueCh(q) // second call must be a no-op

	// A single Put lands in the pool's private slot; the first Get returns it.
	if got := p.queueChPool.Get().(chan UdpTask); got != ch1 {
		t.Fatal("expected pooled channel to be returned")
	}
	// A double-put would have also placed ch1 in the shared queue, so a second
	// Get would return ch1 again instead of a fresh channel from New.
	if got := p.queueChPool.Get().(chan UdpTask); got == ch1 {
		t.Fatal("double-put handed the same channel out twice")
	}
}

// Locks the reply-drop telemetry: local reinjection failures are swallowed by
// design (endpoint survives), but must be countable.
func TestForwardUdpEndpointReplyToClientCountsDrops(t *testing.T) {
	before := udpReplyReinjectionDrops.Load()
	recorded := 0
	send := udpEndpointReplySender(func(log *logrus.Logger, data []byte, from netip.AddrPort, realTo netip.AddrPort, slot udpEndpointResponseConnSlot) error {
		return errors.New("reinjection failed")
	})
	err := forwardUdpEndpointReplyToClient(
		logrus.New(), nil, []byte("d"),
		netip.MustParseAddrPort("1.1.1.1:1"), netip.MustParseAddrPort("2.2.2.2:2"),
		send, func(n int64) { recorded += int(n) })
	if err != nil {
		t.Fatalf("reply drop must be swallowed, got %v", err)
	}
	if udpReplyReinjectionDrops.Load() != before+1 {
		t.Fatal("expected drop counter to increment exactly once")
	}
	if recorded != 0 {
		t.Fatalf("download must not be recorded for a dropped reply, got %d", recorded)
	}
}
