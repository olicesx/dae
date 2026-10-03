//go:build !linux

package control

import (
	"context"

	"github.com/daeuniverse/outbound/netproxy"
)

// tryRelayGatherWrite is a no-op off Linux: the gather path depends on
// writev(2) and the pending-byte socket probes. DAE_TCP_RELAY_WRITE_GATHER
// is likewise inert here (see relaySteadyGatherCopy below).
func tryRelayGatherWrite(_ context.Context, _ netproxy.Conn, _ netproxy.Conn, _ func(int64), _ func(int64)) (written int64, err error, ok bool) {
	return 0, nil, false
}

func relaySteadyGatherCopy(_ context.Context, _ netproxy.Conn, _ netproxy.Conn, _ func(int64), _ func(int64)) (written int64, err error, ok bool) {
	return 0, nil, false
}
