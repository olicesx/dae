/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
	"time"
)

type udpOrderedDispatchTask struct {
	run     UdpTask
	discard UdpTask
}

type udpOrderedDispatchQueue struct {
	dispatcher   *udpOrderedDispatcher
	key          UdpFlowKey
	ch           chan udpOrderedDispatchTask
	wake         chan struct{}
	agingTime    time.Duration
	overflow     []udpOrderedDispatchTask
	overflowLen  atomic.Int32
	overflowMode bool
	refs         atomic.Int32
	enqueueMu    sync.Mutex
}

// udpOrderedDispatcher executes ordered UDP ingress tasks with the same
// lock-free fast path as DefaultUdpTaskPool: sync.Map for queue lookup,
// atomic.Int32 refs for queue ownership, per-queue channel + overflow slice,
// and one convoy goroutine per active flow.
//
// Differences vs the legacy pool:
//   - Each task carries an optional discard callback invoked on Close/Reset so
//     ingress buffers can be released by the caller.
//   - Close/Reset coordinate with every live convoy through per-queue refs
//     signaling instead of a global mutex, so submit stays out of any global
//     critical section.
type udpOrderedDispatcher struct {
	queues      sync.Map // map[UdpFlowKey]*udpOrderedDispatchQueue
	closed      atomic.Bool
	closeMu     sync.Once
	queueChPool sync.Pool

	// pendingConvoys tracks live convoy goroutines. done closes once the last
	// convoy exits, so wait() can observe shutdown without racing a WaitGroup
	// Add that happens after a concurrent close().
	pendingConvoys atomic.Int32
	done           chan struct{}
	doneOnce       sync.Once
}

func newDefaultUDPOrderedDispatcher() *udpOrderedDispatcher {
	return newUDPOrderedDispatcher(0, 0)
}

func newUDPOrderedDispatcherForFeatures(features SemanticRefactorFeatureSet) *udpOrderedDispatcher {
	if !features.UDPOrderedDispatcher {
		return nil
	}
	return newDefaultUDPOrderedDispatcher()
}

// newUDPOrderedDispatcher retains the (workers, drainQuantum) signature used
// by tests, but the rewritten implementation uses one convoy goroutine per
// flow so both arguments are intentionally ignored. Keeping the signature
// avoids touching every test call site.
func newUDPOrderedDispatcher(_, _ int) *udpOrderedDispatcher {
	return &udpOrderedDispatcher{
		queueChPool: sync.Pool{New: func() any {
			return make(chan udpOrderedDispatchTask, UdpTaskQueueLength)
		}},
		done: make(chan struct{}),
	}
}

// startConvoy accounts a new convoy goroutine against pendingConvoys and
// launches it. The convoy signals its exit through convoExited so the last
// exiting convoy closes d.done exactly once.
func (d *udpOrderedDispatcher) startConvoy(q *udpOrderedDispatchQueue) {
	d.pendingConvoys.Add(1)
	go func() {
		defer d.convoExited()
		q.convoy()
	}()
}

func (d *udpOrderedDispatcher) convoExited() {
	if d.pendingConvoys.Add(-1) == 0 {
		d.doneOnce.Do(func() { close(d.done) })
	}
}

// dispatcherAgingTime returns the current idle-GC interval. It reads the
// legacy var at call time because UdpTaskPoolAgingTime is mutable for tests.
func dispatcherAgingTime() time.Duration {
	return UdpTaskPoolAgingTime
}

func (d *udpOrderedDispatcher) submit(key UdpFlowKey, run, discard UdpTask) bool {
	if d == nil || run == nil {
		return false
	}
	q := d.acquireQueue(key)
	if q == nil {
		return false
	}
	q.enqueue(udpOrderedDispatchTask{run: run, discard: discard})
	q.refs.Add(-1)
	return true
}

func (d *udpOrderedDispatcher) acquireQueue(key UdpFlowKey) *udpOrderedDispatchQueue {
	if d.closed.Load() {
		return nil
	}
	// Fast path: reuse an existing flow without any global lock.
	if v, ok := d.queues.Load(key); ok {
		q := v.(*udpOrderedDispatchQueue)
		for {
			refs := q.refs.Load()
			if refs < 0 {
				goto createNew
			}
			if q.refs.CompareAndSwap(refs, refs+1) {
				return q
			}
		}
	}

createNew:
	ch := d.queueChPool.Get().(chan udpOrderedDispatchTask)
	newQ := &udpOrderedDispatchQueue{
		dispatcher: d,
		key:        key,
		ch:         ch,
		wake:       make(chan struct{}, 1),
		agingTime:  dispatcherAgingTime(),
	}
	actual, loaded := d.queues.LoadOrStore(key, newQ)
	if loaded {
		// Lost the race; return the channel and acquire the existing queue.
		d.queueChPool.Put(ch)
		q := actual.(*udpOrderedDispatchQueue)
		for {
			refs := q.refs.Load()
			if refs < 0 {
				d.queues.CompareAndDelete(key, q)
				goto createNew
			}
			if q.refs.CompareAndSwap(refs, refs+1) {
				return q
			}
		}
	}
	q := actual.(*udpOrderedDispatchQueue)
	q.refs.Add(1)
	d.startConvoy(q)
	return q
}

func (q *udpOrderedDispatchQueue) enqueue(task udpOrderedDispatchTask) {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()
	if q.overflowMode {
		q.overflow = append(q.overflow, task)
		q.overflowLen.Store(int32(len(q.overflow)))
		q.notifyWake()
		return
	}
	select {
	case q.ch <- task:
		return
	default:
		// Hot-key degradation: switch to overflow so submit stays non-blocking.
		q.overflowMode = true
		q.overflow = append(q.overflow, task)
		q.overflowLen.Store(int32(len(q.overflow)))
		q.notifyWake()
	}
}

func (q *udpOrderedDispatchQueue) notifyWake() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *udpOrderedDispatchQueue) popOverflowTask() (udpOrderedDispatchTask, bool) {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()
	if len(q.overflow) == 0 {
		q.overflowMode = false
		q.overflowLen.Store(0)
		return udpOrderedDispatchTask{}, false
	}
	task := q.overflow[0]
	q.overflow[0] = udpOrderedDispatchTask{}
	q.overflow = q.overflow[1:]
	if len(q.overflow) == 0 {
		q.overflowMode = false
		q.overflowLen.Store(0)
		// Retain a small preallocated slice for the next burst.
		if cap(q.overflow) > UdpTaskQueueLength*2 {
			q.overflow = make([]udpOrderedDispatchTask, 0, UdpTaskQueueLength/4)
		} else {
			q.overflow = q.overflow[:0]
		}
	} else {
		q.overflowLen.Store(int32(len(q.overflow)))
		// Shrink drift: release large backing arrays once we drain most tasks.
		if len(q.overflow) < cap(q.overflow)/4 && cap(q.overflow) > UdpTaskQueueLength {
			shrunk := make([]udpOrderedDispatchTask, len(q.overflow))
			copy(shrunk, q.overflow)
			q.overflow = shrunk
		}
	}
	return task, true
}

func (q *udpOrderedDispatchQueue) popReadyTask() (udpOrderedDispatchTask, bool) {
	select {
	case task := <-q.ch:
		return task, true
	default:
	}
	return q.popOverflowTask()
}

func (q *udpOrderedDispatchQueue) safeTimerReset(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(q.agingTime)
}

func (q *udpOrderedDispatchQueue) convoy() {
	defer func() {
		if r := recover(); r != nil {
			// Defensive: drop the queue so a future packet re-creates it.
			if q.dispatcher.queues.CompareAndDelete(q.key, q) {
				q.dispatcher.queueChPool.Put(q.ch)
			}
		}
	}()
	timer := time.NewTimer(q.agingTime)
	defer timer.Stop()

	for {
		if task, ok := q.popReadyTask(); ok {
			runUDPOrderedTask(task)
			q.safeTimerReset(timer)
			continue
		}

		select {
		case task := <-q.ch:
			runUDPOrderedTask(task)
			q.safeTimerReset(timer)
		case <-q.wake:
			// Wake fires on overflow enqueue or shutdown.
			if q.refs.Load() < 0 {
				return
			}
		case <-timer.C:
			if q.refs.Load() > 0 || len(q.ch) > 0 || q.overflowLen.Load() > 0 {
				q.safeTimerReset(timer)
				continue
			}
			// Reserve the queue so no new submit attaches to it.
			if !q.refs.CompareAndSwap(0, -1) {
				q.safeTimerReset(timer)
				continue
			}
			if q.dispatcher.queues.CompareAndDelete(q.key, q) {
				q.dispatcher.queueChPool.Put(q.ch)
				return
			}
			// Lost the race to some other reaper; let it clean up.
			if v, ok := q.dispatcher.queues.Load(q.key); !ok || v.(*udpOrderedDispatchQueue) != q {
				q.dispatcher.queueChPool.Put(q.ch)
				return
			}
			q.refs.Store(0)
			q.safeTimerReset(timer)
		}
	}
}

func (d *udpOrderedDispatcher) close() {
	if d == nil {
		return
	}
	d.closeMu.Do(func() {
		d.closed.Store(true)
		d.reapQueues()
		// If no convoy is in flight, close done immediately so wait() and
		// any external observer of d.done does not block forever. When
		// convoys are still draining, the last convoExited closes done.
		if d.pendingConvoys.Load() == 0 {
			d.doneOnce.Do(func() { close(d.done) })
		}
	})
}

func (d *udpOrderedDispatcher) reset() {
	if d == nil {
		return
	}
	d.reapQueues()
}

// reapQueues walks every live queue, signals its convoy to exit, and discards
// every pending task. Close marks the dispatcher closed first; reset leaves
// the dispatcher open so new flows can attach afterwards.
func (d *udpOrderedDispatcher) reapQueues() {
	d.queues.Range(func(key, value any) bool {
		q := value.(*udpOrderedDispatchQueue)
		// Set refs to a sentinel so new submits cannot attach; in-flight
		// acquireQueue loops will see refs<0 and create a fresh queue.
		q.refs.Store(-1)
		pending := q.drainPending()
		q.notifyWake()
		for _, task := range pending {
			discardUDPOrderedTask(task)
		}
		if d.queues.CompareAndDelete(key, q) {
			d.queueChPool.Put(q.ch)
		}
		return true
	})
}

func (q *udpOrderedDispatchQueue) drainPending() []udpOrderedDispatchTask {
	var pending []udpOrderedDispatchTask
	for {
		select {
		case task := <-q.ch:
			pending = append(pending, task)
		default:
			goto overflow
		}
	}
overflow:
	q.enqueueMu.Lock()
	pending = append(pending, q.overflow...)
	q.overflow = nil
	q.overflowMode = false
	q.overflowLen.Store(0)
	q.enqueueMu.Unlock()
	return pending
}

func (d *udpOrderedDispatcher) wait() {
	if d == nil {
		return
	}
	// done only closes once the last convoy exits. If no convoy ever started
	// (e.g. AttachSessionManager swaps out a dispatcher before any packet),
	// return immediately instead of blocking on an unclosed channel.
	if d.pendingConvoys.Load() == 0 {
		return
	}
	<-d.done
}

func (d *udpOrderedDispatcher) queueCount() int {
	if d == nil {
		return 0
	}
	count := 0
	d.queues.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// isClosed reports whether close() has executed. It reads only an atomic, so
// hot-path submit calls do not pay for a lock to check dispatcher state.
func (d *udpOrderedDispatcher) isClosed() bool {
	if d == nil {
		return true
	}
	return d.closed.Load()
}

func runUDPOrderedTask(task udpOrderedDispatchTask) {
	defer func() {
		_ = recover()
	}()
	task.run()
}

func discardUDPOrderedTask(task udpOrderedDispatchTask) {
	if task.discard == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	task.discard()
}
