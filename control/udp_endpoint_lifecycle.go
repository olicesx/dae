/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

// sameUdpConnStateOwner compares owner identities without panicking when an
// implementation contains a non-comparable value. Such values cannot provide
// a stable equality identity and are treated as distinct owners.
func sameUdpConnStateOwner(left, right udpConnStateOwner) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftType := reflect.TypeOf(left)
	if leftType != reflect.TypeOf(right) || !leftType.Comparable() {
		return false
	}
	return left == right
}

// FlowBinding returns the immutable route and egress selections made when the endpoint was created.
func (ue *UdpEndpoint) FlowBinding() UdpFlowBinding {
	if ue == nil || !ue.flowBindingSet {
		return UdpFlowBinding{}
	}
	egress := UdpEgressBinding{
		Dialer:        ue.Dialer,
		Outbound:      ue.Outbound,
		Target:        ue.DialTarget,
		Network:       ue.flowNetwork,
		NetworkType:   ue.endpointNetworkType,
		SniffedDomain: ue.SniffedDomain,
		IsDialIp:      ue.flowBindingDialIP,
	}
	if ue.flowEgressOverride != nil {
		egress = *ue.flowEgressOverride
	}
	return UdpFlowBinding{Route: ue.flowRouteBinding, Egress: egress}
}

func (ue *UdpEndpoint) replySoMark() uint32 {
	if ue != nil && ue.flowBindingSet {
		return ue.flowRouteBinding.Mark
	}
	return soMarkFromDae.Load()
}

func (ue *UdpEndpoint) setFlowBinding(binding UdpFlowBinding) {
	if ue == nil || binding == (UdpFlowBinding{}) {
		return
	}
	ue.flowRouteBinding = binding.Route
	ue.flowNetwork = binding.Egress.Network
	ue.flowBindingDialIP = binding.Egress.IsDialIp
	ue.flowBindingSet = true
	if got := ue.FlowBinding().Egress; got != binding.Egress {
		override := binding.Egress
		ue.flowEgressOverride = &override
	}
}

func (ue *UdpEndpoint) TrackUdpConnStateTuplePair(src, dst netip.AddrPort) {
	if ue == nil || !src.IsValid() || !dst.IsValid() {
		return
	}
	if ue.udpConnStateLastPair.Load().matches(src, dst) {
		return
	}

	forward := bpfTuplesKeyFromAddrPorts(src, dst, uint8(syscall.IPPROTO_UDP))
	reverse := bpfTuplesKeyFromAddrPorts(dst, src, uint8(syscall.IPPROTO_UDP))

	ue.udpConnStateMu.Lock()
	defer ue.udpConnStateMu.Unlock()

	if ue.udpConnStateClosed || ue.udpConnStateOwner == nil {
		return
	}
	if ue.udpConnStateTuples == nil {
		ue.udpConnStateTuples = make(map[bpfTuplesKey]struct{}, 4)
	}
	forwardNew := false
	if _, ok := ue.udpConnStateTuples[forward]; !ok {
		ue.udpConnStateTuples[forward] = struct{}{}
		forwardNew = true
	}
	reverseNew := false
	if _, ok := ue.udpConnStateTuples[reverse]; !ok {
		ue.udpConnStateTuples[reverse] = struct{}{}
		reverseNew = true
	}
	if forwardNew || reverseNew {
		switch {
		case forwardNew && reverseNew:
			newKeys := [2]bpfTuplesKey{forward, reverse}
			ue.udpConnStateOwner.RetainUdpConnStateTuples(newKeys[:])
		case forwardNew:
			ue.udpConnStateOwner.RetainUdpConnStateTuples([]bpfTuplesKey{forward})
		default:
			ue.udpConnStateOwner.RetainUdpConnStateTuples([]bpfTuplesKey{reverse})
		}
		ue.udpConnStateLastPair.Store(&udpConnStateTuplePairSnapshot{src: src, dst: dst})
	}
}

func (ue *UdpEndpoint) releaseTrackedUdpConnState() {
	if ue == nil {
		return
	}

	ue.udpConnStateMu.Lock()
	owner := ue.udpConnStateOwner
	if ue.udpConnStateClosed {
		ue.udpConnStateMu.Unlock()
		return
	}
	ue.udpConnStateClosed = true
	ue.udpConnStateLastPair.Store(nil)
	if owner == nil || len(ue.udpConnStateTuples) == 0 {
		ue.udpConnStateMu.Unlock()
		return
	}
	keys := make([]bpfTuplesKey, 0, len(ue.udpConnStateTuples))
	for key := range ue.udpConnStateTuples {
		keys = append(keys, key)
	}
	ue.udpConnStateTuples = nil
	ue.udpConnStateMu.Unlock()

	if err := owner.ReleaseUdpConnStateTuples(keys); err != nil &&
		ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.WithError(err).Debug("[UdpEndpoint] Failed to release tracked UDP conn-state tuples")
	}
}

func isProxyBackedDialer(d *dialer.Dialer) bool {
	if d == nil {
		return false
	}
	property := d.Property()
	return property != nil && property.Address != ""
}

func isStatelessProxyBackedUdpProtocol(d *dialer.Dialer) bool {
	if !isProxyBackedDialer(d) {
		return false
	}
	property := d.Property()
	if property == nil {
		return false
	}
	switch strings.ToLower(property.Protocol) {
	case "shadowsocks", "shadowsocksr", "socks4", "socks5":
		return true
	default:
		return false
	}
}

func proxyBackedUdpNatTimeout(requested time.Duration) time.Duration {
	if requested <= 0 {
		return requested
	}
	// Proxy-backed UDP sessions are multiplexed over a longer-lived transport.
	// Recreating them too aggressively causes avoidable session churn and log
	// spam for interactive traffic such as games.
	if requested < QuicNatTimeout {
		return QuicNatTimeout
	}
	return requested
}

func effectiveUdpEndpointNatTimeout(d *dialer.Dialer, requested time.Duration) time.Duration {
	if !isProxyBackedDialer(d) || isStatelessProxyBackedUdpProtocol(d) {
		return requested
	}
	return proxyBackedUdpNatTimeout(requested)
}

func isTransientLocalUdpDialCreateError(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, syscall.EADDRINUSE) ||
		stderrors.Is(err, syscall.EADDRNOTAVAIL) ||
		stderrors.Is(err, syscall.EAGAIN) ||
		stderrors.Is(err, syscall.ENOBUFS) ||
		stderrors.Is(err, syscall.EMFILE) ||
		stderrors.Is(err, syscall.ENFILE) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "bind: address already in use") ||
		strings.Contains(errStr, "cannot assign requested address")
}

func udpEndpointIgnoresDialerHealth(ue *UdpEndpoint) bool {
	return ue != nil &&
		ue.Outbound != nil &&
		ue.Outbound.GetSelectionPolicy() == consts.DialerSelectionPolicy_Fixed
}

func (ue *UdpEndpoint) logEndpointExit(err error, msg string) {
	if ue.log == nil {
		return
	}
	natTimeout := ue.natTimeout()
	fields := logrus.Fields{
		"lAddr":       ue.lAddr.String(),
		"dialer":      ue.Dialer.Property().Name,
		"proxy_addr":  ue.DialTarget,
		"sniffed":     ue.SniffedDomain,
		"nat_timeout": natTimeout.String(),
	}
	entry := ue.log.WithFields(fields).WithError(err)
	if err == nil || errors.IsUDPEndpointNormalClose(err) {
		entry.Debugln("UdpEndpoint " + msg + " closed normally")
	} else {
		if opErr, ok := err.(*net.OpError); ok {
			fields["op"] = opErr.Op
			fields["err_type"] = fmt.Sprintf("%T", err)
		}
		entry.WithFields(fields).Warnln("UdpEndpoint " + msg + " exited with error")
	}
}

func (ue *UdpEndpoint) shouldRetireOnReadError(err error) bool {
	if err == nil {
		return false
	}
	// Connection-refused class errors must still retire the endpoint so proxy IP
	// failure handling can evict the bad upstream target immediately.
	if ue.isConnectionRefused(err) {
		return true
	}
	if !errors.IsUDPEndpointNormalClose(err) {
		return true
	}
	// Delegate the "normal close" policy to the lifecycle model so all UDP
	// session managers use the same rule.
	if lifecycle, ok := newUdpSessionLifecycleContext(ue, ""); ok {
		return lifecycle.shouldRetireOnNormalClose(err)
	}
	return false
}

// isConnectionRefused checks if the error indicates connection was refused.
// Uses typed syscall matching first (handles kernel ICMP errors), then falls
// back to string matching for wrapped errors from SOCKS5 and other proxy protocols.
func (ue *UdpEndpoint) isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	// Fast path: typed syscall errors from kernel ICMP responses.
	if stderrors.Is(err, syscall.ECONNREFUSED) || stderrors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var sysErr *os.SyscallError
	if stderrors.As(err, &sysErr) {
		if stderrors.Is(sysErr.Err, syscall.ECONNREFUSED) || stderrors.Is(sysErr.Err, syscall.EHOSTUNREACH) {
			return true
		}
	}
	// Slow path: string matching for proxy-protocol wrapped errors (e.g. SOCKS5 replies).
	// containsFoldASCII is allocation-free and equivalent to ToLower+Contains.
	errStr := err.Error()
	return containsFoldASCII(errStr, "connection refused") ||
		containsFoldASCII(errStr, "port unreachable") ||
		containsFoldASCII(errStr, "host unreachable")
}

// handleProxyServerFailure is called when the proxy server refuses the connection.
// It invalidates the cached proxy IP so that subsequent connections can try a different IP.
func (ue *UdpEndpoint) handleProxyServerFailure() {
	if ue.Dialer == nil {
		return
	}

	// Get the proxy address from the dialer property
	proxyAddr := ue.Dialer.Property().Address
	if proxyAddr == "" {
		return
	}

	// Notify the dialer about the proxy server failure.
	// This invalidates the failed UDP family cache so retries can pivot immediately.
	networkType := udpEndpointNetworkType(ue)
	ue.Dialer.NotifyProxyFailure(proxyAddr, &networkType)

	if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"dialer":     ue.Dialer.Property().Name,
		}).Debug("[UdpEndpoint] Proxy server UDP connection refused - invalidated cached IP")
	}
}

// containsFoldASCII reports whether s contains substr under ASCII
// case-insensitive comparison. It is allocation-free on the ASCII path and is
// byte-for-byte equivalent to strings.Contains(strings.ToLower(s), substr):
//   - Pure-ASCII s: inline 'A'-'Z' folding matches strings.ToLower exactly.
//   - Any non-ASCII byte in s: falls back to strings.ToLower+Contains to
//     preserve full Unicode correctness (avoids divergence on chars like
//     U+212A KELVIN SIGN whose Unicode lowercase is ASCII 'k'). Proxy and
//     syscall error messages are ASCII in practice, so the fallback branch is
//     effectively never hit in production but guarantees identical behavior.
//
// substr MUST be ASCII lowercase (true for all current call sites).
func containsFoldASCII(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return strings.Contains(strings.ToLower(s), substr)
		}
	}
	n := len(s) - len(substr)
	for i := 0; i <= n; i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// selfRemoveFromPool performs a best-effort CAS delete of this endpoint from
// its owning pool. It is called by the read loop on exit so that the dead entry
// is evicted immediately — before any writer goroutine has a chance to observe
// it and be forced through the slower dead-check recovery path.
func (ue *UdpEndpoint) selfRemoveFromPool() {
	if ue.poolRef == nil {
		return
	}
	shard := ue.poolRef.shardFor(ue.poolKey)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if v, ok := shard.pool[ue.poolKey]; ok && v == ue {
		delete(shard.pool, ue.poolKey)
	}
}

func (ue *UdpEndpoint) markDeadIfOwnedBy(owner udpConnStateOwner) bool {
	if ue == nil || owner == nil {
		return false
	}

	ue.udpConnStateMu.Lock()
	defer ue.udpConnStateMu.Unlock()
	if ue.udpConnStateClosed || !sameUdpConnStateOwner(ue.udpConnStateOwner, owner) {
		return false
	}
	ue.dead.Store(true)
	ue.expiresAtNano.Store(1)
	return true
}

func (ue *UdpEndpoint) retire() {
	ue.dead.Store(true)
	ue.expiresAtNano.Store(1)
	ue.selfRemoveFromPool()
	_ = ue.Close()
}

// udpEndpointWriteTimeout bounds how long one proxy-side write may block. A
// UDP datagram normally leaves the socket immediately, but many proxies carry
// UDP over a TCP transport whose peer can stop ACKing; without a deadline one
// stalled upstream parks its calling goroutine forever, and under a shared
// dispatcher a handful of stalled flows would park every worker. A write that
// hits the deadline errors out and retires the endpoint, which is the correct
// outcome for a transport that has stopped draining.
const udpEndpointWriteTimeout = 10 * time.Second

// writeSoftErrorThreshold bounds consecutive tolerated transport write errors
// before the endpoint retires. A genuinely dead transport is still surfaced by
// the read loop (EOF/error), so the threshold only guards a write-only flow
// against lingering on a transport that accepts no writes.
const writeSoftErrorThreshold = 3

// udpEndpointWriteToleratedError wraps a transient transport write error that
// the endpoint absorbed without retiring. Callers must drop the datagram and
// keep the session alive instead of removing/redialing it.
type udpEndpointWriteToleratedError struct{ err error }

func (e *udpEndpointWriteToleratedError) Error() string { return e.err.Error() }
func (e *udpEndpointWriteToleratedError) Unwrap() error { return e.err }

func isUdpEndpointWriteTolerated(err error) bool {
	var tolerated *udpEndpointWriteToleratedError
	return stderrors.As(err, &tolerated)
}

// armWriteDeadline keeps a write deadline of [T/2, T] ahead of every write
// while re-arming at most once per T/2 window. Transports that do not support
// write deadlines return an error, which is deliberately ignored: they simply
// keep their previous unbounded behaviour.
func (ue *UdpEndpoint) armWriteDeadline(now time.Time) {
	// QUIC-backed transports (hysteria2/tuic) expose a transport-lifecycle
	// channel: connection death is signalled via TransportDone and retired by
	// the pool watcher. Their datagram send queue fills under backpressure,
	// which is a normal congestion signal rather than a dead peer — arming a
	// write deadline here tears the session down on a merely-full queue where
	// xray/sing-box simply delay the write and keep the connection alive.
	if endpointTransportDoneChannel(ue) != nil {
		return
	}
	last := ue.writeDeadlineArmedAtNano.Load()
	if now.UnixNano()-last < int64(udpEndpointWriteTimeout/2) {
		return
	}
	if !ue.writeDeadlineArmedAtNano.CompareAndSwap(last, now.UnixNano()) {
		// Another writer is re-arming this window.
		return
	}
	_ = ue.conn.SetWriteDeadline(now.Add(udpEndpointWriteTimeout))
}

func (ue *UdpEndpoint) WriteTo(b []byte, addr string) (int, error) {
	// Fast dead check: avoid work on an already-dead endpoint.
	if ue.dead.Load() {
		return 0, net.ErrClosed
	}
	if !ue.hasSent.Load() && !ue.hasReply.Load() {
		// Publish pending intent before taking the mutex. Pool lookups use this
		// atomic state while holding shard locks, so they can preserve a first
		// write without waiting for it to complete.
		ue.initialWritesPending.Add(1)
		defer ue.initialWritesPending.Add(-1)
		ue.initialWriteMu.Lock()
		defer ue.initialWriteMu.Unlock()
		if ue.dead.Load() {
			return 0, net.ErrClosed
		}
	}

	if !ue.hasReply.Load() {
		ue.rememberPendingReplyPeer(addr)
	}

	// Refresh TTL on write to keep endpoint alive for active connections
	ue.RefreshTtl()

	ue.armWriteDeadline(time.Now())

	// Check again - endpoint may have died.
	// The underlying conn.WriteTo is thread-safe; we accept a small race window
	// for performance. Write errors will mark the endpoint dead for cleanup.
	n, err := ue.conn.WriteTo(b, addr)
	if err != nil {
		// Connection-refused is a hard failure: evict the bad upstream now.
		if ue.isConnectionRefused(err) {
			ue.retire()
			ue.handleProxyServerFailure()
			return n, err
		}
		// Tolerate transient write errors up to a threshold so brief transport
		// backpressure does not retire a healthy long-lived session. A closed
		// conn and a genuinely dead transport are still retired promptly: the
		// former by this threshold, the latter by the read loop (EOF/error).
		if ue.writeSoftErrorCount.Add(1) <= writeSoftErrorThreshold &&
			!stderrors.Is(err, net.ErrClosed) {
			return n, &udpEndpointWriteToleratedError{err: err}
		}
		ue.retire()
		return n, err
	}
	ue.writeSoftErrorCount.Store(0)
	// UDP datagrams are atomic: a successful WriteTo either wrote the whole
	// encapsulated datagram or returned an error. Some protocol dialers
	// (e.g. shadowsocks AEAD, vmess) legitimately return the encapsulated
	// packet size (len(b) + overhead) rather than the payload length, so only
	// a short write (n < len(b)) is a real failure. Treating n > len(b) as a
	// short write would retire healthy endpoints and drop packets.
	if n < len(b) {
		ue.retire()
		return n, fmt.Errorf("%w: udp endpoint wrote %d/%d bytes to %s", io.ErrShortWrite, n, len(b), addr)
	}
	ue.hasSent.Store(true)
	return n, nil
}

func (ue *UdpEndpoint) Close() error {
	ue.closeOnce.Do(func() {
		ue.dead.Store(true)
		ue.expiresAtNano.Store(0)
		ue.stopPacketReceiver()
		if ue.replyRuntime != nil {
			ue.stopReplyDispatcher()
			ue.replyRuntime.dispatcher.closeInput(ue)
		}
		ue.releaseCachedResponseConns()
		if ue.poolRef != nil {
			ue.poolRef.unregisterEndpoint(ue)
		}

		ue.routingMu.Lock()
		ue.hasRoutingCache = false
		ue.routingMu.Unlock()
		ue.releaseTrackedUdpConnState()

		// conn is nil for negatively-cached failure entries; guard against panic.
		if ue.conn != nil {
			ue.closeErr = ue.conn.Close()
		}

		ue.udpConnStateMu.Lock()
		drainRelease := ue.drainRelease
		ue.drainRelease = nil
		ue.drainTracker = nil
		ue.udpConnStateMu.Unlock()
		if drainRelease != nil {
			drainRelease()
		}
		if ue.sessionRuntime != nil {
			ue.sessionRuntime.finish()
		}
	})
	return ue.closeErr
}

// RefreshTtl updates the expiration time. Uses throttling to reduce atomic
// store overhead.
func (ue *UdpEndpoint) RefreshTtl() {
	ue.RefreshTtlWithTime(0)
}

func (ue *UdpEndpoint) natTimeout() time.Duration {
	ue.natTimeoutMu.RLock()
	defer ue.natTimeoutMu.RUnlock()
	return ue.NatTimeout
}

func (ue *UdpEndpoint) setNatTimeout(timeout time.Duration) {
	ue.natTimeoutMu.Lock()
	ue.NatTimeout = timeout
	ue.natTimeoutMu.Unlock()
}

// requiresInitialReplyGuard reports whether dae needs to verify the first
// upstream reply itself before promoting the endpoint to established state.
// Proxy-backed PacketConn implementations already demultiplex packets by
// protocol session, so an extra address-based guard here is redundant and can
// incorrectly strand valid flows whose first reply address is rewritten by the
// proxy layer.
func (ue *UdpEndpoint) requiresInitialReplyGuard() bool {
	return ue == nil || !isProxyBackedDialer(ue.Dialer)
}

// markReplied promotes the endpoint from probing to established state.
// Once a reply has been observed, the normal sliding NAT timeout applies.
func (ue *UdpEndpoint) markReplied(nowNano int64) {
	if nowNano == 0 {
		nowNano = time.Now().UnixNano()
	}
	if !ue.hasReply.Swap(true) {
		ue.clearPendingReplyPeers()
		ue.lastRefreshNano.Store(nowNano)
		ue.expiresAtNano.Store(nowNano + int64(ue.natTimeout()))
		return
	}
	ue.RefreshTtlWithTime(nowNano)
}

func (ue *UdpEndpoint) rememberPendingReplyPeer(addr string) {
	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil || !addrPort.IsValid() {
		return
	}

	ue.pendingReplyMu.Lock()
	defer ue.pendingReplyMu.Unlock()

	for i := 0; i < ue.pendingReplyPeerCount; i++ {
		if ue.pendingReplyPeers[i] == addrPort {
			return
		}
	}

	if ue.pendingReplyPeerCount < len(ue.pendingReplyPeers) {
		ue.pendingReplyPeers[ue.pendingReplyPeerCount] = addrPort
		ue.pendingReplyPeerCount++
		return
	}

	ue.pendingReplyPeers[ue.pendingReplyPeerNext] = addrPort
	ue.pendingReplyPeerNext = (ue.pendingReplyPeerNext + 1) % len(ue.pendingReplyPeers)
}

func (ue *UdpEndpoint) clearPendingReplyPeers() {
	ue.pendingReplyMu.Lock()
	defer ue.pendingReplyMu.Unlock()

	ue.pendingReplyPeerCount = 0
	ue.pendingReplyPeerNext = 0
	for i := range ue.pendingReplyPeers {
		ue.pendingReplyPeers[i] = netip.AddrPort{}
	}
}

func (ue *UdpEndpoint) acceptsInitialReplyFrom(from netip.AddrPort) bool {
	if !from.IsValid() {
		return false
	}
	if !ue.requiresInitialReplyGuard() {
		return true
	}

	ue.pendingReplyMu.Lock()
	defer ue.pendingReplyMu.Unlock()

	if ue.pendingReplyPeerCount == 0 {
		return ue.poolKey.Dst.IsValid() && from == ue.poolKey.Dst
	}

	allowSameIPFallback := ue.poolKey.Dst.Port() == 0
	for i := 0; i < ue.pendingReplyPeerCount; i++ {
		expected := ue.pendingReplyPeers[i]
		if from == expected {
			return true
		}
		if allowSameIPFallback && from.Addr() == expected.Addr() {
			return true
		}
	}

	if ue.poolKey.Dst.IsValid() && from == ue.poolKey.Dst {
		return true
	}
	return false
}

func (ue *UdpEndpoint) setExpiry(deadlineNano int64, refreshCachedResponseConns bool) {
	ue.expiresAtNano.Store(deadlineNano)
	if refreshCachedResponseConns {
		ue.refreshCachedResponseConnsWithTime(deadlineNano)
	}
}

// RefreshTtlWithTime updates the expiration time using a pre-calculated
// timestamp (Unix nanoseconds). If nowNano is 0, time.Now() is used.
func (ue *UdpEndpoint) RefreshTtlWithTime(nowNano int64) {
	timeout := ue.natTimeout()
	if timeout <= 0 {
		return
	}
	if nowNano == 0 {
		nowNano = time.Now().UnixNano()
	}
	last := ue.lastRefreshNano.Load()
	// Throttle: skip if refreshed recently.
	// For long TTLs, use TTL/50 as interval; for short TTLs, use minimum.
	minInterval := ttlRefreshMinInterval
	if ttlNano := int64(timeout); ttlNano > 10*ttlRefreshMinInterval {
		minInterval = ttlNano / 50
	}
	if nowNano-last < minInterval {
		return
	}
	// CAS to avoid thundering herd on the same connection.
	if ue.lastRefreshNano.CompareAndSwap(last, nowNano) {
		deadlineNano := nowNano + int64(timeout)
		ue.setExpiry(deadlineNano, true)
		// Keep cached reply sockets alive as long as the endpoint is alive.
		// Without this, Anyfrom entries can expire before the owning UDP
		// endpoint does, forcing a bind syscall on a later reply and causing
		// a latency spike for active proxy-backed sessions whose
		// server->client traffic is sparse on a given source address.
	}
}

// UpdateNatTimeout updates the NAT timeout and refreshes TTL with the new timeout.
// This allows the timeout to adapt to changing forwarding state (e.g., QUIC upgrade, fixed policy).
func (ue *UdpEndpoint) UpdateNatTimeout(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	ue.setNatTimeout(timeout)
	now := time.Now().UnixNano()
	// Force immediate refresh on timeout change (bypass throttling).
	ue.lastRefreshNano.Store(now)
	ue.setExpiry(now+int64(timeout), true)
}

func (ue *UdpEndpoint) IsExpired(nowNano int64) bool {
	expiresAt := ue.expiresAtNano.Load()
	return expiresAt > 0 && nowNano >= expiresAt
}

// IsDead returns true if the endpoint's read loop has exited and should not be reused.
func (ue *UdpEndpoint) IsDead() bool {
	return ue.dead.Load()
}

// GetBoundRoutingResult returns the route handoff bound to this endpoint for
// one original destination. Unlike the short-lived cache accessor, a bound
// result remains valid for the endpoint lifetime so ordinary flow packets do
// not re-read the BPF handoff map after their initial policy evaluation.
func (ue *UdpEndpoint) GetBoundRoutingResult(dst netip.AddrPort, l4proto uint8) (*bpfRoutingResult, bool) {
	ue.routingMu.RLock()
	defer ue.routingMu.RUnlock()
	if !ue.hasRoutingCache || ue.routingCacheProto != l4proto || ue.routingCacheDst != dst {
		return nil, false
	}
	result := ue.routingCache
	return &result, true
}

func (ue *UdpEndpoint) GetCachedRoutingResult(dst netip.AddrPort, l4proto uint8) (*bpfRoutingResult, bool) {
	ttl := UdpRoutingResultCacheTtl
	if ttl <= 0 {
		return nil, false
	}

	ue.routingMu.RLock()
	defer ue.routingMu.RUnlock()

	if !ue.hasRoutingCache {
		return nil, false
	}
	if ue.routingCacheProto != l4proto || ue.routingCacheDst != dst {
		return nil, false
	}
	if time.Since(ue.routingCacheAt) > ttl {
		return nil, false
	}

	result := ue.routingCache
	return &result, true
}

func (ue *UdpEndpoint) UpdateCachedRoutingResult(dst netip.AddrPort, l4proto uint8, result *bpfRoutingResult) {
	if result == nil {
		return
	}
	if UdpRoutingResultCacheTtl <= 0 {
		return
	}

	ue.routingMu.Lock()
	ue.routingCacheDst = dst
	ue.routingCacheProto = l4proto
	ue.routingCacheAt = time.Now()
	ue.routingCache = *result
	ue.hasRoutingCache = true
	ue.routingMu.Unlock()
}

// UdpEndpointKey is the pool key. Dst=0 for Full-Cone NAT, non-zero for
// destination-affine flows such as QUIC or userspace-routed UDP. RouteScope is
// only populated when UDP routing depends on packet metadata that userspace
// cannot safely infer from payload reuse alone.

// endpointSurvivesDialerInvalidation reports whether an endpoint should remain
// reusable after its dialer transitions to not alive.
//
// Control-plane health is an admission signal for new selections, not a hard
// kill switch for live sessions. Once an endpoint has successfully forwarded at
// least one packet, proactively retiring it based only on health probes causes
// avoidable redials and session churn. Real failures are still surfaced by
// WriteTo/ReadFrom errors, transport lifecycle end, or NAT timeout expiry.
func (p *UdpEndpointPool) endpointSurvivesDialerInvalidation(ue *UdpEndpoint) bool {
	return ue != nil && ue.survivesDialerHealthInvalidation()
}

func (ue *UdpEndpoint) survivesDialerHealthInvalidation() bool {
	return ue.hasSent.Load() || ue.hasReply.Load() || ue.initialWritesPending.Load() != 0
}

// retireIfUnforwardedForDialerHealth retires only an endpoint that is still
// probing. The initial-write handshake makes a health transition race-safe:
// an in-flight first write either establishes the endpoint or fails and
// retires it itself.
func (ue *UdpEndpoint) retireIfUnforwardedForDialerHealth() bool {
	if ue == nil || ue.dead.Load() || ue.survivesDialerHealthInvalidation() {
		return false
	}

	ue.initialWriteMu.Lock()
	defer ue.initialWriteMu.Unlock()
	if ue.dead.Load() || ue.survivesDialerHealthInvalidation() {
		return false
	}
	ue.retire()
	return true
}
