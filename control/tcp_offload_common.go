/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/outbound/netproxy"
)

// canAnnotateTCPRelayOffload reports whether the connection is offload-capable
// (both ends resolve to concrete TCP sockets), so link logs can annotate
// offload outcome and skip reasons.
func canAnnotateTCPRelayOffload(conn netproxy.Conn) bool {
	return canResolveTCPRelayOffloadConn(conn)
}

func canResolveTCPRelayOffloadConn(conn netproxy.Conn) bool {
	if conn == nil {
		return false
	}
	_, ok := unwrapRelayTCPConn(conn)
	return ok
}
