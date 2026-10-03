/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/outbound/netproxy"
)

// canResolveTCPRelayOffloadConn reports whether the connection is
// offload-capable (both ends resolve to concrete TCP sockets through
// transparent wrappers only), so link logs can annotate offload outcome and
// skip reasons. It must use the same data-movement unwrap as the offload gate
// itself; a peeling predicate would annotate wrapped legs as capable while the
// session gate refuses them.
func canResolveTCPRelayOffloadConn(conn netproxy.Conn) bool {
	if conn == nil {
		return false
	}
	_, ok := unwrapRelayTransparentTCPConn(conn)
	return ok
}
