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
	"github.com/daeuniverse/outbound/netproxy"
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

// FlowBinding returns the immutable route and egress selections made when the
// endpoint was created. Production code reads only Route.Mark (via
// replySoMark); the full binding is a verification surface for tests.
func (ue *UdpEndpoint) FlowBinding() UdpFlowBinding {
	if ue == nil || !ue.flowBindingSet {
		return UdpFlowBinding{}
	}
	return UdpFlowBinding{
		Route: ue.flowRouteBinding,
		Egress: UdpEgressBinding{
			Dialer:        ue.Dialer,
			Outbound:      ue.Outbound,
			Target:        ue.DialTarget,
			Network:       ue.flowNetwork,
			NetworkType:   ue.endpointNetworkType,
			SniffedDomain: ue.SniffedDomain,
			IsDialIp:      ue.flowBindingDialIP,
		},
	}
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
}

// TrackUdpConnStateTuplePair keeps this endpoint's conn_state tuples pinned for
// the tuple pair it currently serves.
//
// The tracked set MOVES with the pair: a pair change releases the previous
// pair's keys that the new pair does not use. Accumulating them instead (the
// previous behavior) leaked one pin per observed pair for the endpoint's whole
// lifetime, so a long-lived endpoint could pin an unbounded set of long-dead
// tuples against the janitor. ReleaseUdpConnStateTuples deletes the kernel
// entry only when the shared refcount reaches zero, so a tuple another endpoint
// (or another flow) still pins survives the move.
//
// Lock order: udpConnStateMu protects the tuple set and the last-pair snapshot
// together; it is never held while calling into the owner (Retain/Release take
// udpStateMu downstream), matching releaseTrackedUdpConnState.
func (ue *UdpEndpoint) TrackUdpConnStateTuplePair(src, dst netip.AddrPort) {
	if ue == nil || !src.IsValid() || !dst.IsValid() {
		return
	}
	forward := bpfTuplesKeyFromAddrPorts(src, dst, uint8(syscall.IPPROTO_UDP))
	reverse := bpfTuplesKeyFromAddrPorts(dst, src, uint8(syscall.IPPROTO_UDP))

	ue.udpConnStateMu.Lock()
	if ue.udpConnStateClosed {
		ue.udpConnStateMu.Unlock()
		return
	}
	owner := ue.udpConnStateOwner
	if owner == nil {
		ue.udpConnStateMu.Unlock()
		return
	}
	// Swap publishes the new pair and hands back the previous one atomically
	// with respect to the pin bookkeeping below.
	previous := ue.udpConnStateLastPair.Swap(&udpConnStateTuplePairSnapshot{src: src, dst: dst})
	if previous.matches(src, dst) {
		ue.udpConnStateMu.Unlock()
		return
	}
	if ue.udpConnStateTuples == nil {
		ue.udpConnStateTuples = make(map[bpfTuplesKey]struct{}, 4)
	}
	var retain []bpfTuplesKey
	for _, key := range [2]bpfTuplesKey{forward, reverse} {
		if _, ok := ue.udpConnStateTuples[key]; !ok {
			ue.udpConnStateTuples[key] = struct{}{}
			retain = append(retain, key)
		}
	}
	var release []bpfTuplesKey
	if previous != nil {
		for _, key := range [2]bpfTuplesKey{
			bpfTuplesKeyFromAddrPorts(previous.src, previous.dst, uint8(syscall.IPPROTO_UDP)),
			bpfTuplesKeyFromAddrPorts(previous.dst, previous.src, uint8(syscall.IPPROTO_UDP)),
		} {
			if key == forward || key == reverse {
				// Still part of the pair this endpoint serves.
				continue
			}
			if _, held := ue.udpConnStateTuples[key]; !held {
				continue
			}
			delete(ue.udpConnStateTuples, key)
			release = append(release, key)
		}
	}
	ue.udpConnStateMu.Unlock()

	if len(retain) > 0 {
		owner.RetainUdpConnStateTuples(retain)
	}
	if len(release) > 0 {
		if err := owner.ReleaseUdpConnStateTuples(release); err != nil &&
			ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
			ue.log.WithError(err).Debug("[UdpEndpoint] Failed to release superseded UDP conn-state tuples")
		}
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
	dialerName := ""
	if ue.Dialer != nil {
		if prop := ue.Dialer.Property(); prop != nil {
			dialerName = prop.Name
		}
	}
	fields := logrus.Fields{
		"lAddr":       ue.lAddr.String(),
		"dialer":      dialerName,
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
	if sysErr, ok := stderrors.AsType[*os.SyscallError](err); ok {
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

// markRetiredFromReceiver is the push-mode equivalent of retire() for a
// goroutine that already owns the reply-sender lifecycle. Close() waits for
// replyQueueDone, which only the sender itself closes, so calling retire()
// from handleReceivedPacket or replySender would deadlock on <-done.
func (ue *UdpEndpoint) markRetiredFromReceiver() {
	ue.dead.Store(true)
	ue.expiresAtNano.Store(1)
	ue.selfRemoveFromPool()
	// The conn still has to be released, and after selfRemoveFromPool nobody
	// else references the endpoint: pool scans and Remove(key, ...) can no
	// longer find it. Run Close() on a fresh goroutine — never on the sender
	// or transport-callback stack — so it may wait for this sender to drain
	// and exit before closing the conn.
	go func() { _ = ue.Close() }()
}

// udpEndpointWriteTimeout bounds how long one proxy-side write may block. A
// UDP datagram normally leaves the socket immediately, but many proxies carry
// UDP over a TCP transport whose peer can stop ACKing; without a deadline one
// stalled upstream parks its calling goroutine forever, and under a shared
// dispatcher a handful of stalled flows would park every worker. Hitting the
// deadline means the transport stopped draining: handleWriteError retires the
// endpoint immediately (fail fast). Transports whose SetWriteDeadline is
// destructive (declared via netproxy.WriteDeadlineBehavior, e.g. the
// QUIC-session-backed TUIC and Hysteria2 UDP relays, where the deadline is a
// session-close timer rather than a write abort) never arm this deadline: a
// merely-full datagram queue must be absorbed as a dropped datagram instead.
const udpEndpointWriteTimeout = 10 * time.Second

// udpEndpointReplyDroughtWindow is how long an established data-session
// endpoint may go without any upstream reply — while the client keeps writing —
// before the next write rebuilds the session. Silence alone carries no
// information: a pause shorter than the transport's own session lifetime
// (Hysteria2 recreates an idle session after its UDPIdleTimeout; dae expires
// pooled endpoints on the NAT timeout) is indistinguishable from a healthy
// flow, and rebuilding there only changes the forwarding source port that QUIC
// and WireGuard peers track. What IS observable is the absence of replies
// during sustained transmission: a live peer of any protocol answers, so a
// reply drought identifies a session whose remote side no longer recognizes it
// (a game server or conntrack entry that reaped the mapping). That makes this
// the only session-recovery signal dae owns; recovering a long pause belongs to
// the transport/server layer, not here.
const udpEndpointReplyDroughtWindow = 30 * time.Second

// udpEndpointReplyDroughtProbeWindow is the width of the recent-activity
// measurement that complements the lifetime average in droughtSendRate: the
// gate also acts when the client sent at least
// udpEndpointReplyDroughtMinRate*udpEndpointReplyDroughtProbeWindow datagrams
// inside this window. A burst is what a low-average flow produces — a game that
// syncs state every tens of seconds, or any flow resuming after a long pause —
// and the lifetime average dilutes it below the threshold forever. The window
// must stay long enough that a genuinely sparse keepalive cannot fake a rate
// (5s at 2 pkt/s is 10 datagrams, while WireGuard's 25s keepalive puts at most
// one datagram in it) and short enough that "the client is transmitting now" is
// still true when the decision is made.
const udpEndpointReplyDroughtProbeWindow = 5 * time.Second

// udpEndpointReplyDroughtMinHealthyReplies is how many upstream replies a
// session must have produced before it is allowed to retire itself for a reply
// drought when its key already went through one. A key that never needed a
// recovery is never held back: a mapping can be reaped while a session is still
// young, and that first recovery is the whole point. The budget exists for the
// replacement: without it, a peer that answers once and then goes quiet would
// be rebuilt every window, re-keying the flow each time for a single reply of
// benefit. Three replies is proof of a working two-way path, not a lucky one.
//
// The budget follows the key, not the flow, for as long as the pool's rebuild
// ledger remembers it (see udpEndpointDroughtSuccessorTTL): a client that
// restarts and reuses the same local port within that window inherits the
// budget of the flow that had it before.
const udpEndpointReplyDroughtMinHealthyReplies = 3

// udpEndpointReplyDroughtMinRate is the client write rate, in packets per
// second, required to act on a reply drought. Wall-clock silence alone must
// never rebuild: WireGuard's one-way persistent keepalive (about one packet per
// 25s) gets no replies while idle and would otherwise be rebuilt every window,
// moving its source port for no reason. Requiring traffic separates a dead
// session (games heartbeat at 10-120 Hz) from a quiet but healthy one. The rate
// is measured two ways and the larger one decides (see droughtSendRate): the
// lifetime average over the drought, which is what a steady flow produces, and
// the datagrams observed in the most recent
// udpEndpointReplyDroughtProbeWindow, which is what a burst produces. Without
// the second measurement a flow whose average stays below the threshold — a
// game syncing state every tens of seconds, or any flow resuming after a long
// pause — would keep a dead session forever. A flow that genuinely stopped
// writing reaches neither measurement, so the transport layer recovers it
// instead. The rebuild is also self-limiting, because the replacement session
// starts probing and cannot be rebuilt again until its peer replies at least
// once, so a false positive costs one dial rather than a loop.
//
// These three constants (window, probe window, min rate) are a documented
// choice inside the envelope of TestUdpEndpointDroughtThresholdEnvelope, not a
// measured operating point: this tree has no field distribution of client
// write rates. The judgment fails if real interactive flows cluster near
// 2 packets/s over 30s; that is the only band in which retuning MinRate or
// Window would change a decision. Interactive ≥5 pps vs sparse ≤0.2 pps is
// invariant across the swept range and would not move.
const udpEndpointReplyDroughtMinRate = 2

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
// dialTargetForWrite returns the string form of the datagram's upstream
// destination for WriteTo. Symmetric endpoints (non-zero Dst in the pool
// key) have a fixed dial target stored once at creation, so the per-packet
// netip.AddrPort.String() allocation is skipped; FullCone endpoints
// (zero Dst) serve multiple destinations and must format per call.
func (ue *UdpEndpoint) dialTargetForWrite(realDst netip.AddrPort) string {
	if ue != nil && ue.poolKey.Dst.IsValid() {
		return ue.DialTarget
	}
	return realDst.String()
}

// rebuildsOnReplyDrought reports whether this endpoint's lifecycle profile
// enables the reply-drought session rebuild. Endpoints created outside the pool
// (tests, ad-hoc dials) carry no profile and fall back to the data-session
// profile, matching newUdpSessionLifecycleContext.
func (ue *UdpEndpoint) rebuildsOnReplyDrought() bool {
	profile := ue.lifecycleProfile
	if profile.Kind == 0 {
		profile = newDataSessionLifecycleProfile(ue.Dialer)
	}
	return profile.RebuildOnReplyDrought
}

// maybeRebuildOnReplyDrought retires an established endpoint whose upstream
// stopped replying while the client kept writing. It returns the same
// ErrClosedConnection classification as a normal close, so the caller's retry
// dials a fresh session — and therefore a fresh forwarding source port —
// without penalizing the dialer. Probing endpoints (no reply evidence yet) and
// transactional flows (DNS owns its own timeout/discard policy) are never
// touched.
func (ue *UdpEndpoint) maybeRebuildOnReplyDrought(now time.Time) error {
	if ue == nil {
		return nil
	}
	lastReply := ue.lastReplyNano.Load()
	if lastReply == 0 {
		// Still probing: no reply has ever been observed, so no drought exists.
		return nil
	}
	drought := now.UnixNano() - lastReply
	if drought < int64(udpEndpointReplyDroughtWindow) {
		return nil
	}
	if !ue.rebuildsOnReplyDrought() {
		return nil
	}
	if ue.droughtRebuildGeneration > 0 && ue.replyCount.Load() < udpEndpointReplyDroughtMinHealthyReplies {
		// This session is already a recovery attempt and has not proven
		// two-way health since: spend no more recovery budget on it.
		return nil
	}
	writes := ue.writesSinceReply.Load()
	if ue.droughtSendRate(writes, drought, now) < float64(udpEndpointReplyDroughtMinRate) {
		// Too little traffic to call the session dead: a sparse one-way flow
		// such as WireGuard's persistent keepalive must keep its source port.
		return nil
	}
	ue.retiredByReplyDrought.Store(true)
	if ue.poolRef != nil {
		// Carry the recovery budget of this key forward before the endpoint is
		// marked dead: a concurrent replacement could otherwise retire the
		// stale entry, dial, and read the ledger in between, leaving the
		// replacement with a fresh flow's budget.
		ue.poolRef.rememberDroughtRebuild(ue.poolKey, ue.droughtRebuildGeneration+1)
	}
	ue.retire()
	if ue.log != nil {
		dialerName := ""
		if ue.Dialer != nil {
			if property := ue.Dialer.Property(); property != nil {
				dialerName = property.Name
			}
		}
		ue.log.WithFields(logrus.Fields{
			"dialer":             dialerName,
			"proxy_addr":         ue.DialTarget,
			"drought":            time.Duration(drought).String(),
			"writes_since_reply": writes,
		}).Debug("[UdpEndpoint] Rebuilding UDP session after reply drought")
	}
	return fmt.Errorf("%w: no reply for %s while %d packets were sent, rebuilding session",
		errors.ErrClosedConnection, time.Duration(drought), writes)
}

// droughtSendRate reports the client's transmission rate into a session whose
// upstream stopped replying, in packets per second. It takes the larger of two
// measurements because they cover different traffic shapes: the lifetime
// average over the drought, which a steady flow produces and which keeps the
// original recovery latency, and the datagrams counted in the current
// udpEndpointReplyDroughtProbeWindow, which is where a burst shows up even when
// the average stays below the threshold. The second measurement cannot be faked
// by a sparse flow: a window that short holds at most a couple of its
// datagrams. A bucket from an older window is ignored; otherwise a burst before
// a reply could be mistaken for traffic after a long quiet pause.
func (ue *UdpEndpoint) droughtSendRate(writes, droughtNano int64, now time.Time) float64 {
	bucket := now.UnixNano() / int64(udpEndpointReplyDroughtProbeWindow)
	recent := int64(0)
	if ue.recentWriteBucket.Load() == bucket {
		recent = ue.recentWriteBucketWrites.Load()
	}
	return droughtSendRateFrom(writes, droughtNano, recent)
}

// observeSendRate records transmitted datagrams for the recent-activity
// measurement used by the reply-drought gate. It is called from the two
// accounting sites that already own hasSent/writesSinceReply — the synchronous
// write path and the batched flush reporter — so a healthy session pays two
// uncontended atomics per datagram and the gate itself does no per-packet work
// beyond reading them.
//
// The counter covers the current absolute probe window; datagrams are counted
// only after the transport accepted them, so evidence is never fabricated from
// a datagram that was merely queued. The bucket is published after its counter
// is cleared, so a reader that observes the new bucket cannot pair it with the
// previous bucket's count. Concurrent writers may still lose a count, which
// under-counts the window and therefore delays a rebuild instead of causing a
// spurious one.
func (ue *UdpEndpoint) observeSendRate(now time.Time, datagrams int) {
	if ue == nil || datagrams <= 0 {
		return
	}
	bucket := now.UnixNano() / int64(udpEndpointReplyDroughtProbeWindow)
	if ue.recentWriteBucket.Load() != bucket {
		ue.recentWriteBucketWrites.Store(0)
		ue.recentWriteBucket.Store(bucket)
	}
	ue.recentWriteBucketWrites.Add(int64(datagrams))
}

func (ue *UdpEndpoint) armWriteDeadline(now time.Time) {
	// Transports that declare a session-closing write deadline via the
	// netproxy.WriteDeadlineBehavior contract (TUIC/Hysteria2: their
	// SetWriteDeadline delegates to SetDeadline, a session-close timer
	// rather than a write abort) never arm the deadline. Connection death
	// there is signalled via TransportDone and retired by the pool watcher;
	// a full send queue is congestion and is absorbed as a dropped datagram
	// by handleWriteError. This is deliberately decoupled from
	// TransportLifecycle: a transport may publish a transport-death signal
	// while still supporting standard (write-abort) write deadlines.
	if netproxy.WriteDeadlineClosesSession(ue.conn) {
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

	// Single wall-clock sample shared by the reply-drought check and the write
	// deadline arming below.
	now := time.Now()

	// Session recovery is evidence-based: only a reply drought during sustained
	// transmission may rebuild an established session. Silence alone is not a
	// signal (see udpEndpointReplyDroughtWindow).
	if err := ue.maybeRebuildOnReplyDrought(now); err != nil {
		return 0, err
	}

	ue.armWriteDeadline(now)

	if ue.writeBatch != nil {
		// Aggregated path: copy into the batch buffer and return immediately;
		// the flush (batched syscall) happens when the batch fills or after
		// udpWriteBatchWindow. Write errors are classified asynchronously by
		// handleWriteError with the same retirement policy as below, so the
		// caller still sees a successful submission for accepted datagrams.
		if err := ue.writeBatch.Append(b, addr); err != nil {
			if !stderrors.Is(err, errUDPWriteBatchOversized) {
				// Aggregator closed: propagate like a closed conn.
				return 0, err
			}
			// Oversized datagram: fall through to the direct path.
		} else {
			// Do not refresh hasSent/writesSinceReply here. Append only
			// queues the datagram; reportFlushed is the sole writer of
			// those fields after WriteBatch actually succeeds. A premature
			// stamp would count a datagram the transport never accepted as
			// evidence of client transmission.
			return len(b), nil
		}
	}

	// Check again - endpoint may have died.
	// The underlying conn.WriteTo is thread-safe; we accept a small race window
	// for performance. Write errors will mark the endpoint dead for cleanup.
	n, err := ue.conn.WriteTo(b, addr)
	if err != nil {
		return n, ue.handleWriteError(err)
	}
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
	ue.writesSinceReply.Add(1)
	ue.observeSendRate(now, 1)
	ue.notePeerWrite(addr, now)
	if ue.writeBatch != nil && ue.sentReporter != nil {
		// A batched endpoint that reached this point sent the datagram
		// synchronously (the batch rejected it as oversized, see Append), and
		// its caller skips the inline accounting because the aggregator owns
		// it. Report it here so the bytes are not silently uncounted.
		ue.sentReporter(ue, 1, len(b))
	}
	return n, nil
}

// handleWriteError applies the endpoint's write-error policy shared by the
// synchronous WriteTo path and the asynchronous batched-flush path. Hard
// failures retire the endpoint immediately; every other failure only drops
// the datagram and keeps the session. Returns the error to propagate (nil is
// never returned; tolerated errors are wrapped so callers can distinguish
// drop-and-keep from retire-and-redial).
//
// Session death is deliberately NOT inferred from write-error counting: a
// transport whose send queue is full (congestion) or that reports transient
// failures is still alive. Death is owned by three disjoint signals:
// TransportDone / read-loop EOF for the transport, the armed write deadline
// (non-QUIC transports) for a transport that stopped draining, and the
// bidirectional-silence rebuild check for a reaped remote session.
func (ue *UdpEndpoint) handleWriteError(err error) error {
	// Close marks the endpoint dead before synchronously flushing its batch.
	// A flush error on that stack must not re-enter Close's sync.Once.
	if ue.dead.Load() {
		return err
	}
	// Connection-refused is a hard failure: evict the bad upstream now.
	if ue.isConnectionRefused(err) {
		ue.retire()
		ue.handleProxyServerFailure()
		return err
	}
	// A closed conn cannot recover.
	if stderrors.Is(err, net.ErrClosed) {
		ue.retire()
		return err
	}
	// Only transports that armed the write deadline (non-destructive
	// write-deadline semantics) can hit this: the deadline is the stall
	// probe, so hitting it is the fail-fast signal. Transports that declare
	// a session-closing deadline via netproxy.WriteDeadlineBehavior (TUIC/
	// Hysteria2) never arm it — their deadline would close the whole session
	// instead of aborting the write — so a merely full datagram queue
	// (ErrDatagramQueueFullTimeout) falls through to the tolerated path
	// below instead of tearing down a healthy QUIC session.
	if stderrors.Is(err, os.ErrDeadlineExceeded) {
		ue.retire()
		return err
	}
	return &udpEndpointWriteToleratedError{err: err}
}

func (ue *UdpEndpoint) Close() error {
	ue.closeOnce.Do(func() {
		ue.dead.Store(true)
		ue.expiresAtNano.Store(0)
		ue.stopTransportReceiver()
		ue.releaseCachedResponseConns()
		if ue.poolRef != nil {
			ue.poolRef.unregisterEndpoint(ue)
		}

		ue.routingMu.Lock()
		ue.hasRoutingCache = false
		ue.routingMu.Unlock()
		ue.releaseTrackedUdpConnState()

		// conn is nil for negatively-cached failure entries; guard against panic.
		if ue.writeBatch != nil {
			// Drain any buffered datagrams before the conn closes.
			ue.writeBatch.Close()
		}
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
func (ue *UdpEndpoint) markReplied(nowNano int64, from netip.AddrPort) {
	if nowNano == 0 {
		nowNano = time.Now().UnixNano()
	}
	ue.lastReplyNano.Store(nowNano)
	// A reply is proof of life: the drought evidence starts over. The reply is
	// also attributed to the peer it came from, which is what keeps a healthy
	// peer from masking a reaped one on a shared full-cone session.
	ue.writesSinceReply.Store(0)
	ue.replyCount.Add(1)
	ue.notePeerReply(from, nowNano)
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

func (ue *UdpEndpoint) setExpiry(deadlineNano int64) {
	ue.expiresAtNano.Store(deadlineNano)
	ue.refreshCachedResponseConnsWithTime(deadlineNano)
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
		ue.setExpiry(deadlineNano)
		// Keep cached reply sockets alive as long as the endpoint is alive.
		// Without this, Anyfrom entries can expire before the owning UDP
		// endpoint does, forcing a bind syscall on a later reply and causing
		// a latency spike for active proxy-backed sessions whose
		// server->client traffic is sparse on a given source address.
	}
}

// UpdateNatTimeout updates the NAT timeout and refreshes TTL with the new timeout.
// This allows the timeout to adapt to changing forwarding state (e.g., QUIC upgrade, fixed policy).
//
// An unchanged timeout does not take the write lock nor force a deadline bump:
// the fast paths recompute the same effective value on every packet, and
// forcing it there cost a write-locked store plus an unconditional expiry store
// and cached-reply-socket refresh per packet. The renewal is handed back to the
// existing throttled RefreshTtl instead.
func (ue *UdpEndpoint) UpdateNatTimeout(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	if ue.natTimeout() == timeout {
		ue.RefreshTtl()
		return
	}
	ue.setNatTimeout(timeout)
	now := time.Now().UnixNano()
	// Force immediate refresh on timeout change (bypass throttling).
	ue.lastRefreshNano.Store(now)
	ue.setExpiry(now + int64(timeout))
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

func (ue *UdpEndpoint) UpdateCachedRoutingResult(dst netip.AddrPort, l4proto uint8, result *bpfRoutingResult) {
	if result == nil {
		return
	}

	ue.routingMu.Lock()
	ue.routingCacheDst = dst
	ue.routingCacheProto = l4proto
	ue.routingCache = *result
	ue.hasRoutingCache = true
	ue.routingMu.Unlock()
}

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
	if ue.hasSent.Load() || ue.hasReply.Load() || ue.initialWritesPending.Load() != 0 {
		return true
	}
	return ue.writeBatch != nil && ue.writeBatch.hasUnflushedFirst()
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
