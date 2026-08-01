/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/sirupsen/logrus"
)

func (ue *UdpEndpoint) startTransportReceiver() bool {
	if ue != nil && ue.replyRuntime != nil {
		runtime := ue.replyRuntime
		if receiver, ok := ue.conn.(netproxy.PacketReceiver); ok {
			if stop, registered := receiver.RegisterPacketReceiver(ue.handleReceivedPacket); registered {
				runtime.receiverMu.Lock()
				runtime.receiverStop = stop
				runtime.receiverMu.Unlock()
				if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
					ue.log.Debug("[UdpEndpoint] Using transport-owned packet receiver")
				}
				return true
			}
		}
	}
	return false
}

func (ue *UdpEndpoint) stopPacketReceiver() {
	if ue == nil || ue.replyRuntime == nil {
		return
	}
	runtime := ue.replyRuntime
	runtime.receiverMu.Lock()
	stop := runtime.receiverStop
	runtime.receiverStop = nil
	runtime.receiverMu.Unlock()
	if stop != nil {
		stop()
	}
}

func (ue *UdpEndpoint) handleReceivedPacket(packet *netproxy.ReceivedPacket) bool {
	if packet == nil {
		return false
	}

	// Some transport implementations can deliver packets concurrently from
	// multiple stream readers. Keep the endpoint's probing/error counters and
	// initial-peer admission serialized exactly as they are in ReadFrom mode.
	runtime := ue.replyRuntime
	if runtime == nil {
		packet.Release()
		return false
	}
	runtime.receiveMu.Lock()
	defer runtime.receiveMu.Unlock()

	if packet.Err != nil {
		if errors.IsReplayAttackError(packet.Err) || errors.IsAuthError(packet.Err) {
			threshold := 3
			if ue.hasReply.Load() {
				threshold = 100
			}
			if ue.softErrorCount < threshold {
				ue.softErrorCount++
				packet.Release()
				return true
			}
		}
		if ue.shouldRetireOnReadError(packet.Err) {
			ue.retire()
			if ue.isConnectionRefused(packet.Err) {
				ue.handleProxyServerFailure()
			}
		}
		ue.logEndpointExit(packet.Err, "packet receiver")
		packet.Release()
		ue.stopPacketReceiver()
		return false
	}

	ue.softErrorCount = 0
	from := packet.From
	if !ue.hasReply.Load() && !ue.acceptsInitialReplyFrom(from) {
		packet.Release()
		return true
	}
	if lifecycle, ok := newUdpSessionLifecycleContext(ue, consts.IpVersionFromAddr(from.Addr())); ok {
		lifecycle.handleReply(ue, time.Now().UnixNano())
	} else {
		ue.markReplied(time.Now().UnixNano())
	}

	reply := udpEndpointReply{data: pool.PB(packet.Data), from: from}
	accepted, keepReceiver := ue.submitReplyFromReceiver(reply, packet.Release)
	if accepted || keepReceiver {
		return true
	}
	packet.Release()
	ue.stopPacketReceiver()
	return false
}

func (ue *UdpEndpoint) startReadLoop() {
	if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.WithFields(logrus.Fields{
			"lAddr":      ue.lAddr.String(),
			"dialer":     ue.Dialer.Property().Name,
			"proxy_addr": ue.DialTarget,
		}).Debug("[UdpEndpoint] Read loop started")
	}

	// Async reply dispatch keeps slow sendPkt operations off the blocking read
	// loop. The gated dispatcher preserves the legacy bounded backlog and
	// endpoint FIFO while sharing workers across endpoint generations.
	var replyCh chan *udpEndpointReply
	var senderStop chan struct{}
	var senderDone chan struct{}
	runtime := ue.replyRuntime

	buf := pool.GetFullCap(consts.EthernetMtu)
	defer func() {
		// The read loop owns exactly one buffer at a time: buf is replaced only
		// after its ownership has been transferred to a reply consumer, so this
		// is the single release point for whichever buffer is still held.
		putUdpEndpointReplyData(buf)
		if runtime == nil {
			if replyCh != nil {
				close(replyCh)
				<-senderDone
			}
			return
		}
		runtime.dispatcher.closeInputAndWait(ue)
		runtime.tasks.Wait()
	}()
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			// Fast path for soft errors (authentication failures/replay attacks from network noise)
			if errors.IsReplayAttackError(err) || errors.IsAuthError(err) {
				// Dynamic threshold:
				// If we haven't received any valid packet yet, keep threshold low (3) to fail fast on wrong passwords/nodes.
				// If we have successfully received packets, the proxy works. Subsequent errors are likely network noise, so use high threshold (100).
				threshold := 3
				if ue.hasReply.Load() {
					threshold = 100
				}

				if ue.softErrorCount < threshold {
					ue.softErrorCount++
					// Optimize logging condition to avoid unnecessary log object allocation when debug is off
					if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) && ue.softErrorCount%10 == 1 {
						ue.log.WithFields(logrus.Fields{
							"lAddr":      ue.lAddr.String(),
							"dialer":     ue.Dialer.Property().Name,
							"proxy_addr": ue.DialTarget,
							"sniffed":    ue.SniffedDomain,
						}).WithError(err).Debugf("UdpEndpoint read loop soft error (hit %d/%d, ignored)", ue.softErrorCount, threshold)
					}
					continue
				}
			}

			if ue.shouldRetireOnReadError(err) {
				ue.retire()

				// Check if this is a connection refused error from proxy server
				// If so, invalidate the cached proxy IP so we can try a different one
				if ue.isConnectionRefused(err) {
					ue.handleProxyServerFailure()
				}
			}

			ue.logEndpointExit(err, "read loop")
			break
		}
		ue.softErrorCount = 0
		if !ue.hasReply.Load() && !ue.acceptsInitialReplyFrom(from) {
			if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
				ue.log.WithFields(logrus.Fields{
					"lAddr":      ue.lAddr.String(),
					"dialer":     ue.Dialer.Property().Name,
					"proxy_addr": ue.DialTarget,
					"from":       from.String(),
				}).Debug("[UdpEndpoint] Dropped unmatched initial UDP reply during probing")
			}
			continue
		}
		if lifecycle, ok := newUdpSessionLifecycleContext(ue, consts.IpVersionFromAddr(from.Addr())); ok {
			lifecycle.handleReply(ue, time.Now().UnixNano())
		} else {
			ue.markReplied(time.Now().UnixNano())
		}
		// Dispatch reply asynchronously by transferring ownership of the current
		// read buffer to the sender goroutine. This removes one per-packet copy
		// from the hot reply path while keeping the same backpressure semantics.
		reply := udpEndpointReply{data: buf[:n], from: from}
		if runtime != nil {
			if !ue.submitReply(reply) {
				// submitReply returns false before transferring ownership when
				// the dispatcher rejects the task, so the read loop still owns
				// the buffer. reply.data aliases buf, so returning here lets the
				// deferred pool.Put(buf) release it exactly once. Releasing it
				// again through reply.data would put the same backing array into
				// the pool twice and alias it across unrelated flows.
				return
			}
			buf = pool.GetFullCap(consts.EthernetMtu)
			continue
		}
		if replyCh == nil {
			replyCh = make(chan *udpEndpointReply, udpEndpointReplyQueueSize)
			senderStop = make(chan struct{})
			senderDone = make(chan struct{})
			go ue.replySender(replyCh, senderStop, senderDone)
		}
		queued := takeUdpEndpointReply(reply.data, reply.from)
		select {
		case replyCh <- queued:
			buf = pool.GetFullCap(consts.EthernetMtu)
		case <-senderStop:
			recycleUdpEndpointReply(queued, false)
			return
		}
	}
}

func endpointTransportDoneChannel(ue *UdpEndpoint) <-chan struct{} {
	if ue == nil {
		return nil
	}
	if value := ue.transportDone.Load(); value != nil {
		return value.(<-chan struct{})
	}
	if ue.conn == nil {
		return nil
	}
	lifecycle, ok := ue.conn.(netproxy.TransportLifecycle)
	if !ok {
		return nil
	}
	return lifecycle.TransportDone()
}

func (p *UdpEndpointPool) registerTransportEndpoint(ue *UdpEndpoint) {
	transportDone := endpointTransportDoneChannel(ue)
	if transportDone == nil {
		return
	}
	if !ue.transportDone.CompareAndSwap(nil, transportDone) {
		transportDone = ue.transportDone.Load().(<-chan struct{})
	}

	// Reset holds the write side of this lock while stopping all existing
	// transport watchers. A registration that starts after Reset has completed
	// therefore cannot be stranded in an index that was already drained.
	p.transportWatchMu.RLock()
	defer p.transportWatchMu.RUnlock()
	for {
		actual, _ := p.transportIndex.LoadOrStore(transportDone, &udpEndpointTransportBucket{
			endpoints: make(map[*UdpEndpoint]struct{}),
			stop:      make(chan struct{}),
			done:      make(chan struct{}),
		})
		bucket := actual.(*udpEndpointTransportBucket)
		bucket.mu.Lock()
		if bucket.closed {
			bucket.mu.Unlock()
			p.transportIndex.CompareAndDelete(transportDone, bucket)
			continue
		}
		bucket.endpoints[ue] = struct{}{}
		bucket.mu.Unlock()

		bucket.watchOnce.Do(func() {
			go p.watchTransportLifecycle(transportDone, bucket)
		})
		return
	}
}

func (p *UdpEndpointPool) watchTransportLifecycle(transportDone <-chan struct{}, bucket *udpEndpointTransportBucket) {
	defer close(bucket.done)
	select {
	case <-transportDone:
	case <-bucket.stop:
		return
	}
	p.transportIndex.CompareAndDelete(transportDone, bucket)

	bucket.mu.Lock()
	if bucket.closed {
		bucket.mu.Unlock()
		return
	}
	bucket.closed = true
	endpoints := make([]*UdpEndpoint, 0, len(bucket.endpoints))
	for ue := range bucket.endpoints {
		endpoints = append(endpoints, ue)
	}
	bucket.endpoints = make(map[*UdpEndpoint]struct{})
	bucket.mu.Unlock()

	for _, ue := range endpoints {
		if ue != nil && ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
			ue.log.WithFields(logrus.Fields{
				"lAddr": ue.lAddr.String(),
			}).Debug("[UdpEndpoint] Retiring endpoint after transport lifecycle ended")
		}
		if ue != nil {
			ue.retire()
		}
	}
}

func (bucket *udpEndpointTransportBucket) stopWatching() {
	if bucket == nil {
		return
	}
	bucket.stopOnce.Do(func() { close(bucket.stop) })
}

// stopTransportWatchers cancels every transport lifecycle watcher owned by the
// pool and waits for the watcher goroutines to exit. It is called after pooled
// endpoints have been closed, so no endpoint remains eligible for retirement
// from a reset generation.
func (p *UdpEndpointPool) stopTransportWatchers() {
	if p == nil {
		return
	}
	p.transportWatchMu.Lock()
	defer p.transportWatchMu.Unlock()

	var done []<-chan struct{}
	p.transportIndex.Range(func(key, value any) bool {
		bucket, ok := value.(*udpEndpointTransportBucket)
		if !ok || bucket == nil {
			p.transportIndex.CompareAndDelete(key, value)
			return true
		}
		bucket.mu.Lock()
		bucket.closed = true
		bucket.endpoints = make(map[*UdpEndpoint]struct{})
		bucket.mu.Unlock()
		p.transportIndex.CompareAndDelete(key, bucket)
		bucket.stopWatching()
		done = append(done, bucket.done)
		return true
	})
	for _, wait := range done {
		<-wait
	}
}
