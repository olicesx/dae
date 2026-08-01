/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

type udpEndpointReplyRuntime struct {
	receiverMu   sync.Mutex
	receiverStop func()
	receiveMu    sync.Mutex

	dispatcher        *udpReplyDispatcher
	slots             chan struct{}
	stop              chan struct{}
	stopOnce          sync.Once
	admissionMu       sync.Mutex
	admissionClosed   bool
	admissions        int
	admissionsDrained chan struct{}
	failed            atomic.Bool
	tasks             sync.WaitGroup
	drainTracker      *controlPlaneDrainTracker
}

func newUdpEndpointReplyRuntime(dispatcher *udpReplyDispatcher, drainTracker *controlPlaneDrainTracker, queueCapacity int) *udpEndpointReplyRuntime {
	if dispatcher == nil {
		return nil
	}
	if queueCapacity <= 0 {
		queueCapacity = udpEndpointReplyQueueSize
	}
	return &udpEndpointReplyRuntime{
		dispatcher:        dispatcher,
		slots:             make(chan struct{}, queueCapacity),
		stop:              make(chan struct{}),
		admissionsDrained: make(chan struct{}),
		drainTracker:      drainTracker,
	}
}

func (runtime *udpEndpointReplyRuntime) beginReplyAdmission() bool {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if runtime.admissionClosed {
		return false
	}
	runtime.admissions++
	return true
}

func (runtime *udpEndpointReplyRuntime) finishReplyAdmission() {
	runtime.admissionMu.Lock()
	runtime.admissions--
	if runtime.admissionClosed && runtime.admissions == 0 {
		close(runtime.admissionsDrained)
	}
	runtime.admissionMu.Unlock()
}

func (runtime *udpEndpointReplyRuntime) stopReplyAdmissions() {
	runtime.stopOnce.Do(func() {
		runtime.admissionMu.Lock()
		runtime.admissionClosed = true
		close(runtime.stop)
		if runtime.admissions == 0 {
			close(runtime.admissionsDrained)
		}
		runtime.admissionMu.Unlock()
		<-runtime.admissionsDrained
	})
}

type udpEndpointResponseCacheEntry struct {
	bindAddr netip.AddrPort
	conn     *Anyfrom
}

type udpConnStateTuplePairSnapshot struct {
	src netip.AddrPort
	dst netip.AddrPort
}

func (p *udpConnStateTuplePairSnapshot) matches(src, dst netip.AddrPort) bool {
	if p == nil {
		return false
	}
	return p.src == src && p.dst == dst || p.src == dst && p.dst == src
}

type udpEndpointResponseConnSlot interface {
	Load() *Anyfrom
	Swap(next *Anyfrom)
	CompareAndSwap(old, next *Anyfrom) bool
}

type udpEndpointSymmetricResponseConnSlot struct {
	endpoint *UdpEndpoint
}

func (s udpEndpointSymmetricResponseConnSlot) Load() *Anyfrom {
	if s.endpoint == nil {
		return nil
	}
	return s.endpoint.loadResponseConn()
}

func (s udpEndpointSymmetricResponseConnSlot) Swap(next *Anyfrom) {
	if s.endpoint == nil {
		return
	}
	s.endpoint.swapResponseConn(next)
}

func (s udpEndpointSymmetricResponseConnSlot) CompareAndSwap(old, next *Anyfrom) bool {
	if s.endpoint == nil {
		return false
	}
	return s.endpoint.compareAndSwapResponseConn(old, next)
}

func (ue *UdpEndpoint) responseConnSlot() udpEndpointResponseConnSlot {
	if ue == nil {
		return nil
	}
	// Only fixed-destination sessions (Symmetric NAT) may reuse a cached
	// Anyfrom response socket. Full-Cone sessions must re-resolve on every
	// packet because the remote source can legitimately change.
	if ue.poolKey.Dst.Port() == 0 {
		return nil
	}
	return udpEndpointSymmetricResponseConnSlot{endpoint: ue}
}

func (ue *UdpEndpoint) cachedResponseConn(bindAddr netip.AddrPort) *Anyfrom {
	if ue == nil || !bindAddr.IsValid() || ue.poolKey.Dst.Port() != 0 {
		return nil
	}
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		entry := ue.fullConeRespCache[i]
		if entry.bindAddr == bindAddr {
			return entry.conn
		}
	}
	return nil
}

func (ue *UdpEndpoint) storeCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom) {
	if ue == nil || !bindAddr.IsValid() || conn == nil || ue.poolKey.Dst.Port() != 0 {
		return
	}
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		if ue.fullConeRespCache[i].bindAddr == bindAddr {
			if ue.fullConeRespCache[i].conn == conn {
				return
			}
			conn.Pin()
			if old := ue.fullConeRespCache[i].conn; old != nil {
				old.Unpin()
			}
			ue.fullConeRespCache[i].conn = conn
			return
		}
	}
	conn.Pin()
	if old := ue.fullConeRespCache[ue.fullConeRespCacheNext].conn; old != nil {
		old.Unpin()
	}
	ue.fullConeRespCache[ue.fullConeRespCacheNext] = udpEndpointResponseCacheEntry{
		bindAddr: bindAddr,
		conn:     conn,
	}
	ue.fullConeRespCacheNext = (ue.fullConeRespCacheNext + 1) % len(ue.fullConeRespCache)
}

func (ue *UdpEndpoint) clearCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom) {
	if ue == nil || !bindAddr.IsValid() || ue.poolKey.Dst.Port() != 0 {
		return
	}
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		entry := &ue.fullConeRespCache[i]
		if entry.bindAddr == bindAddr && (conn == nil || entry.conn == conn) {
			if entry.conn != nil {
				entry.conn.Unpin()
			}
			entry.bindAddr = netip.AddrPort{}
			entry.conn = nil
		}
	}
}

func (ue *UdpEndpoint) prewarmResponseConn(target string) {
	if ue == nil || !ue.lAddr.IsValid() {
		return
	}

	replyPeer := ue.poolKey.Dst
	if !replyPeer.IsValid() || replyPeer.Port() == 0 {
		parsedTarget, err := netip.ParseAddrPort(target)
		if err != nil || !parsedTarget.IsValid() || parsedTarget.Port() == 0 {
			return
		}
		replyPeer = parsedTarget
	}

	bindAddr, _ := normalizeSendPktAddrFamily(replyPeer, ue.lAddr)
	replySoMark := ue.replySoMark()
	key := anyfromPoolKey{lAddr: bindAddr, soMark: replySoMark}
	var af *Anyfrom
	if DefaultAnyfromPool != nil {
		shard := DefaultAnyfromPool.shardForKey(key)
		nowNano := time.Now().UnixNano()
		shard.mu.RLock()
		if cached, ok := shard.pool[key]; ok && cached != nil && !cached.failed.Load() && !cached.IsExpired(nowNano) {
			af = cached
		}
		shard.mu.RUnlock()
		if af != nil {
			af.RefreshTtlWithTime(nowNano)
		}
	}

	if af == nil {
		if GetDaeNetns() == nil || DefaultAnyfromPool == nil {
			return
		}
		var err error
		af, _, err = DefaultAnyfromPool.getOrCreateWithMark(bindAddr, replySoMark, AnyfromTimeout)
		if err != nil {
			return
		}
	}

	if ue.poolKey.Dst.Port() != 0 {
		ue.swapResponseConn(af)
		return
	}
	ue.storeCachedResponseConn(bindAddr, af)
}

type udpEndpointResponseConnCache interface {
	CachedResponseConn(bindAddr netip.AddrPort) *Anyfrom
	StoreCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom)
	ClearCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom)
}

func (ue *UdpEndpoint) CachedResponseConn(bindAddr netip.AddrPort) *Anyfrom {
	return ue.cachedResponseConn(bindAddr)
}

func (ue *UdpEndpoint) StoreCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom) {
	ue.storeCachedResponseConn(bindAddr, conn)
}

func (ue *UdpEndpoint) ClearCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom) {
	ue.clearCachedResponseConn(bindAddr, conn)
}

func (ue *UdpEndpoint) loadResponseConn() *Anyfrom {
	if ue == nil {
		return nil
	}
	ue.respConnMu.Lock()
	defer ue.respConnMu.Unlock()
	return ue.respConn
}

func (ue *UdpEndpoint) swapResponseConn(next *Anyfrom) {
	if ue == nil {
		return
	}
	ue.respConnMu.Lock()
	defer ue.respConnMu.Unlock()
	swapPinnedAnyfrom(&ue.respConn, next)
}

func (ue *UdpEndpoint) compareAndSwapResponseConn(old, next *Anyfrom) bool {
	if ue == nil {
		return false
	}
	ue.respConnMu.Lock()
	defer ue.respConnMu.Unlock()
	if ue.respConn != old {
		return false
	}
	swapPinnedAnyfrom(&ue.respConn, next)
	return true
}

func (ue *UdpEndpoint) refreshCachedResponseConnsWithTime(deadlineNano int64) {
	if ue == nil {
		return
	}
	if conn := ue.loadResponseConn(); conn != nil {
		conn.ExtendExpiryTo(deadlineNano)
	}
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		if conn := ue.fullConeRespCache[i].conn; conn != nil {
			conn.ExtendExpiryTo(deadlineNano)
		}
	}
}

func (ue *UdpEndpoint) releaseCachedResponseConns() {
	if ue == nil {
		return
	}
	ue.swapResponseConn(nil)
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		if ue.fullConeRespCache[i].conn != nil {
			ue.fullConeRespCache[i].conn.Unpin()
			ue.fullConeRespCache[i].conn = nil
		}
		ue.fullConeRespCache[i].bindAddr = netip.AddrPort{}
	}
}

// udpEndpointReplyQueueSize is the buffer depth for the async reply dispatch
// channel in UdpEndpoint.start(). This decouples the protocol-layer read loop
// (which must drain the upstream ReceiveCh as fast as possible) from the
// potentially slower sendPkt path (Anyfrom bind, tproxy write). The value is
// generous enough to absorb burst game server ticks without dropping, while
// still bounded to avoid unbounded memory under pathological conditions.
const udpEndpointReplyQueueSize = 256

type udpEndpointReply struct {
	data pool.PB
	from netip.AddrPort
}

var udpEndpointReplyObjects = sync.Pool{
	New: func() any { return new(udpEndpointReply) },
}

// putUdpEndpointReplyData is a package-local seam for tests that need to observe
// reply-buffer release without changing the production hot path.
var putUdpEndpointReplyData = func(data pool.PB) {
	data.Put()
}

func takeUdpEndpointReply(data pool.PB, from netip.AddrPort) *udpEndpointReply {
	reply := udpEndpointReplyObjects.Get().(*udpEndpointReply)
	reply.data = data
	reply.from = from
	return reply
}

func recycleUdpEndpointReply(reply *udpEndpointReply, releaseData bool) {
	if reply == nil {
		return
	}
	if releaseData {
		putUdpEndpointReplyData(reply.data)
	}
	*reply = udpEndpointReply{}
	udpEndpointReplyObjects.Put(reply)
}

func releaseUdpEndpointReplies(replies []*udpEndpointReply) {
	for i := range replies {
		recycleUdpEndpointReply(replies[i], true)
	}
}

func releaseUdpEndpointReply(reply udpEndpointReply, release func()) {
	if release != nil {
		release()
		return
	}
	putUdpEndpointReplyData(reply.data)
}

// submitReplyWithMode returns whether the reply was accepted and whether the
// transport-owned reader should remain registered. A full bounded queue drops
// only the current packet and keeps the receiver alive; a closed dispatcher
// requires the transport reader to unregister.
func (ue *UdpEndpoint) submitReplyWithMode(reply udpEndpointReply, release func(), nonBlocking bool) (accepted, keepReceiver bool) {
	if ue == nil || ue.replyRuntime == nil {
		return false, false
	}
	runtime := ue.replyRuntime
	if !runtime.beginReplyAdmission() {
		return false, false
	}
	if nonBlocking {
		select {
		case runtime.slots <- struct{}{}:
		case <-runtime.stop:
			runtime.finishReplyAdmission()
			return false, false
		default:
			runtime.finishReplyAdmission()
			releaseUdpEndpointReply(reply, release)
			return false, true
		}
	} else {
		select {
		case runtime.slots <- struct{}{}:
		case <-runtime.stop:
			runtime.finishReplyAdmission()
			return false, false
		}
	}

	runtime.admissionMu.Lock()
	if runtime.admissionClosed {
		runtime.admissionMu.Unlock()
		<-runtime.slots
		runtime.finishReplyAdmission()
		return false, false
	}
	drainRelease := runtime.drainTracker.Acquire()
	runtime.tasks.Add(1)
	complete := func() {
		releaseUdpEndpointReply(reply, release)
		<-runtime.slots
		drainRelease()
		runtime.tasks.Done()
	}
	run := func() {
		defer complete()
		if runtime.failed.Load() {
			return
		}
		if err := ue.handler(ue, reply.data, reply.from); err != nil {
			runtime.failed.Store(true)
			ue.retire()
			ue.stopReplyDispatcher()
			runtime.dispatcher.abortInput(ue)
			ue.logEndpointExit(err, "reply sender")
		}
	}
	submitted := runtime.dispatcher.submit(ue, run, complete)
	runtime.admissionMu.Unlock()
	runtime.finishReplyAdmission()
	if submitted {
		return true, true
	}
	// udpReplyDispatcher.submit documents that a rejected task leaves
	// the reply buffer owned by the caller. Release the bookkeeping here,
	// while the read loop releases the buffer itself.
	<-runtime.slots
	drainRelease()
	runtime.tasks.Done()
	ue.stopReplyDispatcher()
	ue.retire()
	return false, false
}

func (ue *UdpEndpoint) submitReply(reply udpEndpointReply) bool {
	accepted, _ := ue.submitReplyWithMode(reply, nil, false)
	return accepted
}

func (ue *UdpEndpoint) submitReplyFromReceiver(reply udpEndpointReply, release func()) (accepted, keepReceiver bool) {
	return ue.submitReplyWithMode(reply, release, true)
}

func (ue *UdpEndpoint) stopReplyDispatcher() {
	if ue == nil || ue.replyRuntime == nil {
		return
	}
	runtime := ue.replyRuntime
	runtime.stopReplyAdmissions()
}

// replySender is the dedicated goroutine that drains the reply channel and
// calls the handler (which invokes sendPkt). Running this off the read loop
// avoids blocking the upstream protocol layer's ReceiveCh.
func (ue *UdpEndpoint) replySender(replyCh <-chan *udpEndpointReply, stop chan<- struct{}, done chan<- struct{}) {
	defer close(done)
	batch := make([]*udpEndpointReply, 0, 8)
	for reply := range replyCh {
		batch = append(batch[:0], reply)
		for len(batch) < cap(batch) {
			select {
			case next, ok := <-replyCh:
				if !ok {
					replyCh = nil
					goto drainBatch
				}
				batch = append(batch, next)
			default:
				goto drainBatch
			}
		}

	drainBatch:
		for i := range batch {
			queued := batch[i]
			// Do NOT skip queued replies when dead: these were already received
			// from the upstream before the read loop exited, and must be forwarded
			// to the client. The handler (forwardUdpEndpointReplyToClient) only
			// writes to the local tproxy socket, which is independent of the
			// upstream endpoint's liveness.
			if err := ue.handler(ue, queued.data, queued.from); err != nil {
				releaseUdpEndpointReplies(batch[i:])
				ue.retire()
				close(stop)
				ue.logEndpointExit(err, "reply sender")
				// Drain remaining queued replies to release pool buffers.
				if replyCh != nil {
					for r := range replyCh {
						recycleUdpEndpointReply(r, true)
					}
				}
				return
			}
			recycleUdpEndpointReply(queued, true)
		}
		if replyCh == nil {
			return
		}
	}
}
