/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

type nonComparableUdpConnStateOwner []int

func (nonComparableUdpConnStateOwner) RetainUdpConnStateTuples([]bpfTuplesKey) {}

func (nonComparableUdpConnStateOwner) TransferRetainedUdpConnStateTuplesFrom(udpConnStateOwner, []bpfTuplesKey) {
}

func (nonComparableUdpConnStateOwner) ReleaseUdpConnStateTuples([]bpfTuplesKey) error {
	return nil
}

func TestSameUdpConnStateOwnerHandlesNonComparableValues(t *testing.T) {
	owner := nonComparableUdpConnStateOwner{1}
	other := nonComparableUdpConnStateOwner{1}

	if sameUdpConnStateOwner(owner, owner) {
		t.Fatal("non-comparable owner unexpectedly has a stable equality identity")
	}
	if sameUdpConnStateOwner(owner, other) {
		t.Fatal("distinct non-comparable owners unexpectedly compare equal")
	}

	endpoint := &UdpEndpoint{udpConnStateOwner: owner}
	if endpoint.markDeadIfOwnedBy(owner) {
		t.Fatal("endpoint with non-comparable owner was unexpectedly retired")
	}
}
