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

type udpReplyDispatchTask struct {
	run     func()
	discard func()
}

type udpReplyDispatchQueue struct {
	dispatcher   *udpReplyDispatcher
	endpoint     *UdpEndpoint
	ch           chan udpReplyDispatchTask
	wake         chan struct{}
	inputStop    chan struct{}
	done         chan struct{}
	overflow     []udpReplyDispatchTask
	overflowLen  atomic.Int32
	overflowMode bool
	refs         atomic.Int32
	// inputClosed is set by closeInputLocked and observed by submit, convoy,
	// and the lifecycle hooks. abortInput and dispatcher close both route
	// through closeInputLocked, so inputClosed fully covers the abort case.
	inputClosed atomic.Bool
	doneOnce    sync.Once
	enqueueMu   sync.Mutex
}

// udpReplyDispatcher executes UDP endpoint replies with the same lock-free
// fast path as the ordered dispatcher and DefaultUdpTaskPool. Each endpoint
// owns one queue and one convoy goroutine; submit acquires the queue through
// sync.Map + atomic refs, then takes one per-endpoint backlog slot before
// enqueuing.
//
// Lifecycle hooks beyond the ordered dispatcher:
//   - closeInputAndWait / closeInput let the read loop drain already-accepted
//     replies after ReadFrom returns normally.
//   - abortInput releases pending replies without delivering them; it is safe
//     to call from inside a running reply handler because it never blocks on
//     the in-flight task.
type udpReplyDispatcher struct {
	queues        sync.Map // map[*UdpEndpoint]*udpReplyDispatchQueue
	closed        atomic.Bool
	closeMu       sync.Once
	queueChPool   sync.Pool
	queueCapacity int

	// pendingConvoys / done mirror the ordered dispatcher so close() and
	// wait() stay race-free without a WaitGroup that could race with a
	// concurrent Add from a submit that already passed the closed check.
	pendingConvoys atomic.Int32
	done           chan struct{}
	doneOnce       sync.Once
}

func newUDPReplyDispatcherForFeatures(features SemanticRefactorFeatureSet) *udpReplyDispatcher {
	if !features.UDPReplyDispatcher {
		return nil
	}
	return newDefaultUDPReplyDispatcher()
}

func newDefaultUDPReplyDispatcher() *udpReplyDispatcher {
	return newUDPReplyDispatcher(0, 0, udpEndpointReplyQueueSize)
}

// newUDPReplyDispatcher retains the (workers, drainQuantum, queueCapacity)
// signature used by tests, but the rewritten implementation uses one convoy
// goroutine per endpoint so workers and drainQuantum are intentionally
// ignored. queueCapacity controls per-endpoint backlog (slots).
func newUDPReplyDispatcher(_, _ int, queueCapacity int) *udpReplyDispatcher {
	if queueCapacity <= 0 {
		queueCapacity = udpEndpointReplyQueueSize
	}
	return &udpReplyDispatcher{
		queueChPool:   sync.Pool{New: func() any { return make(chan udpReplyDispatchTask, UdpTaskQueueLength) }},
		queueCapacity: queueCapacity,
		done:          make(chan struct{}),
	}
}

func (d *udpReplyDispatcher) startConvoy(q *udpReplyDispatchQueue) {
	d.pendingConvoys.Add(1)
	go func() {
		defer d.convoExited()
		q.convoy()
	}()
}

func (d *udpReplyDispatcher) convoExited() {
	if d.pendingConvoys.Add(-1) == 0 {
		d.doneOnce.Do(func() { close(d.done) })
	}
}

func (d *udpReplyDispatcher) submit(endpoint *UdpEndpoint, run, discard func()) bool {
	return d.submitMode(endpoint, run, discard, false)
}

func (d *udpReplyDispatcher) submitNonBlocking(endpoint *UdpEndpoint, run, discard func()) bool {
	return d.submitMode(endpoint, run, discard, true)
}

func (d *udpReplyDispatcher) submitMode(endpoint *UdpEndpoint, run, discard func(), nonBlocking bool) bool {
	if d == nil || endpoint == nil || run == nil {
		return false
	}
	if d.closed.Load() {
		return false
	}
	q := d.acquireQueue(endpoint)
	if q == nil {
		return false
	}

	// Backpressure is provided by UdpEndpoint.replyRuntime.slots, which the
	// caller (submitReplyWithMode) takes before invoking the dispatcher.
	// Adding a second slot channel here would just double the per-reply
	// channel bookkeeping without bounding memory any tighter.

	// Re-check input flags under the acquired ref so a concurrent close cannot
	// strand the task. inputClosed covers both normal endpoint close and
	// abort paths because abortInput / dispatcher close both call
	// closeInputLocked first.
	if q.inputClosed.Load() {
		q.refs.Add(-1)
		return false
	}

	accepted := q.enqueue(udpReplyDispatchTask{run: run, discard: discard})
	if !accepted {
		q.refs.Add(-1)
		return false
	}
	q.refs.Add(-1)
	return true
}

func (d *udpReplyDispatcher) acquireQueue(endpoint *UdpEndpoint) *udpReplyDispatchQueue {
	if d.closed.Load() {
		return nil
	}
	if v, ok := d.queues.Load(endpoint); ok {
		q := v.(*udpReplyDispatchQueue)
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
	ch := d.queueChPool.Get().(chan udpReplyDispatchTask)
	newQ := &udpReplyDispatchQueue{
		dispatcher: d,
		endpoint:   endpoint,
		ch:         ch,
		wake:       make(chan struct{}, 1),
		inputStop:  make(chan struct{}),
		done:       make(chan struct{}),
	}
	actual, loaded := d.queues.LoadOrStore(endpoint, newQ)
	if loaded {
		d.queueChPool.Put(ch)
		q := actual.(*udpReplyDispatchQueue)
		for {
			refs := q.refs.Load()
			if refs < 0 {
				d.queues.CompareAndDelete(endpoint, q)
				goto createNew
			}
			if q.refs.CompareAndSwap(refs, refs+1) {
				return q
			}
		}
	}
	q := actual.(*udpReplyDispatchQueue)
	q.refs.Add(1)
	d.startConvoy(q)
	return q
}

func (q *udpReplyDispatchQueue) enqueue(task udpReplyDispatchTask) bool {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()
	// A concurrent close/abort/reap may have flipped refs<0 or inputClosed
	// between submitMode's check and here. Reject so the caller releases the
	// slot and invokes discard instead of leaking the task (and its
	// runtime.slots / WaitGroup / drain-tracker bookkeeping).
	if q.refs.Load() < 0 || q.inputClosed.Load() {
		return false
	}
	if q.overflowMode {
		q.overflow = append(q.overflow, task)
		q.overflowLen.Store(int32(len(q.overflow)))
		q.notifyWake()
		return true
	}
	select {
	case q.ch <- task:
		return true
	default:
		q.overflowMode = true
		q.overflow = append(q.overflow, task)
		q.overflowLen.Store(int32(len(q.overflow)))
		q.notifyWake()
		return true
	}
}

func (q *udpReplyDispatchQueue) notifyWake() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *udpReplyDispatchQueue) popOverflowTask() (udpReplyDispatchTask, bool) {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()
	if len(q.overflow) == 0 {
		q.overflowMode = false
		q.overflowLen.Store(0)
		return udpReplyDispatchTask{}, false
	}
	task := q.overflow[0]
	q.overflow[0] = udpReplyDispatchTask{}
	q.overflow = q.overflow[1:]
	if len(q.overflow) == 0 {
		q.overflowMode = false
		q.overflowLen.Store(0)
		if cap(q.overflow) > UdpTaskQueueLength*2 {
			q.overflow = make([]udpReplyDispatchTask, 0, UdpTaskQueueLength/4)
		} else {
			q.overflow = q.overflow[:0]
		}
	} else {
		q.overflowLen.Store(int32(len(q.overflow)))
		if len(q.overflow) < cap(q.overflow)/4 && cap(q.overflow) > UdpTaskQueueLength {
			shrunk := make([]udpReplyDispatchTask, len(q.overflow))
			copy(shrunk, q.overflow)
			q.overflow = shrunk
		}
	}
	return task, true
}

func (q *udpReplyDispatchQueue) popReadyTask() (udpReplyDispatchTask, bool) {
	select {
	case task := <-q.ch:
		return task, true
	default:
	}
	return q.popOverflowTask()
}

func (q *udpReplyDispatchQueue) convoy() {
	defer func() {
		if r := recover(); r != nil {
			q.releaseAndCleanup()
		}
	}()

	timer := time.NewTimer(dispatcherAgingTime())
	defer timer.Stop()

	for {
		// Normal drain: once input is closed, finish any queued replies and
		// exit. The queue removes itself from the dispatcher map so future
		// submits for this endpoint create a fresh queue.
		if q.inputClosed.Load() {
			// Batch-drain everything that is immediately ready so we exit
			// quickly without per-task timer churn.
			drainedAny := false
			for {
				if task, ok := q.popReadyTask(); ok {
					runUDPReplyTask(task)
					drainedAny = true
					continue
				}
				break
			}
			if drainedAny {
				continue
			}
			// Queue looks empty. Re-check under enqueueMu so we cannot race
			// with a late enqueue and strand a task without its discard.
			q.enqueueMu.Lock()
			overflowEmpty := len(q.overflow) == 0
			chanLen := len(q.ch)
			q.enqueueMu.Unlock()
			if overflowEmpty && chanLen == 0 && q.refs.Load() <= 0 {
				q.releaseAndCleanup()
				return
			}
			// Either there is pending work we lost the race on, or a submit
			// is still in flight. Fall through to the select to wait.
		}

		// Batch drain for the normal (input-open) path.
		drainedAny := false
		for {
			if task, ok := q.popReadyTask(); ok {
				runUDPReplyTask(task)
				drainedAny = true
				continue
			}
			break
		}
		if drainedAny {
			q.safeTimerReset(timer)
			continue
		}

		select {
		case task := <-q.ch:
			runUDPReplyTask(task)
			for {
				if task, ok := q.popReadyTask(); ok {
					runUDPReplyTask(task)
					continue
				}
				break
			}
			q.safeTimerReset(timer)
		case <-q.wake:
			if q.refs.Load() < 0 {
				q.releaseAndCleanup()
				return
			}
		case <-timer.C:
			// Idle GC: if no in-flight submit and no pending work, retire
			// this convoy so we do not leak a goroutine per idle endpoint.
			if q.refs.Load() > 0 || len(q.ch) > 0 || q.overflowLen.Load() > 0 {
				q.safeTimerReset(timer)
				continue
			}
			if !q.refs.CompareAndSwap(0, -1) {
				q.safeTimerReset(timer)
				continue
			}
			// Re-check for late work under the lock before tearing down.
			q.enqueueMu.Lock()
			lateWork := len(q.overflow) > 0 || len(q.ch) > 0
			q.enqueueMu.Unlock()
			if lateWork {
				q.refs.Store(0)
				q.safeTimerReset(timer)
				continue
			}
			// Remove from map BEFORE closing done so a concurrent
			// closeInputAndWait observes queueCount==0 once it unblocks.
			if q.dispatcher.queues.CompareAndDelete(q.endpoint, q) {
				q.dispatcher.queueChPool.Put(q.ch)
				q.finishOnce()
				return
			}
			if v, ok := q.dispatcher.queues.Load(q.endpoint); !ok || v.(*udpReplyDispatchQueue) != q {
				q.dispatcher.queueChPool.Put(q.ch)
				q.finishOnce()
				return
			}
			q.refs.Store(0)
			q.safeTimerReset(timer)
		}
	}
}

// releaseAndCleanup drains any leftover overflow, invokes each pending task's
// discard hook (so the caller's runtime.slots / WaitGroup / drain-tracker /
// reply-buffer bookkeeping is released exactly once), releases the slot each
// pending task still holds, and removes the queue from the dispatcher map.
// The queue is removed from the map BEFORE done is closed so any
// closeInputAndWait caller observes queueCount==0 once it unblocks.
func (q *udpReplyDispatchQueue) releaseAndCleanup() {
	pending := q.drainPending()
	for _, task := range pending {
		discardUDPReplyTask(task)
	}
	if q.dispatcher.queues.CompareAndDelete(q.endpoint, q) {
		q.dispatcher.queueChPool.Put(q.ch)
	}
	q.finishOnce()
}

func (q *udpReplyDispatchQueue) safeTimerReset(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(dispatcherAgingTime())
}

func (q *udpReplyDispatchQueue) finishOnce() {
	q.doneOnce.Do(func() { close(q.done) })
}

func (d *udpReplyDispatcher) closeInput(endpoint *UdpEndpoint) {
	if d == nil || endpoint == nil {
		return
	}
	v, ok := d.queues.Load(endpoint)
	if !ok {
		return
	}
	q := v.(*udpReplyDispatchQueue)
	q.closeInputLocked()
	q.notifyWake()
}

// closeInputAndWait marks the endpoint's input as closed and waits for the
// convoy to finish draining already-accepted replies.
func (d *udpReplyDispatcher) closeInputAndWait(endpoint *UdpEndpoint) {
	if d == nil || endpoint == nil {
		return
	}
	v, ok := d.queues.Load(endpoint)
	if !ok {
		return
	}
	q := v.(*udpReplyDispatchQueue)
	q.closeInputLocked()
	q.notifyWake()
	<-q.done
}

// abortInput closes the endpoint input and releases every queued reply
// without delivering it. It never waits for a currently running handler, so
// it is safe to call from that handler's worker.
func (d *udpReplyDispatcher) abortInput(endpoint *UdpEndpoint) {
	if d == nil || endpoint == nil {
		return
	}
	v, ok := d.queues.Load(endpoint)
	if !ok {
		return
	}
	q := v.(*udpReplyDispatchQueue)
	q.closeInputLocked()
	// Flip refs under enqueueMu so late enqueues from in-flight submits are
	// rejected by enqueue() instead of landing after we drain.
	q.enqueueMu.Lock()
	q.refs.Store(-1)
	q.enqueueMu.Unlock()
	pending := q.drainPending()
	q.notifyWake()
	for _, task := range pending {
		discardUDPReplyTask(task)
	}
}

func (q *udpReplyDispatchQueue) closeInputLocked() {
	if q.inputClosed.Swap(true) {
		return
	}
	close(q.inputStop)
}

func (q *udpReplyDispatchQueue) drainPending() []udpReplyDispatchTask {
	var pending []udpReplyDispatchTask
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

func (d *udpReplyDispatcher) close() {
	if d == nil {
		return
	}
	d.closeMu.Do(func() {
		d.closed.Store(true)
		d.queues.Range(func(key, value any) bool {
			q := value.(*udpReplyDispatchQueue)
			q.closeInputLocked()
			// Flip refs under enqueueMu so a late enqueue observes refs<0
			// inside enqueue() and rejects the task. Without this, a submit
			// that already passed acquireQueue + the inputClosed check could
			// land a task into overflow after drainPending returns, leaking
			// the discard hook (runtime.slots, WaitGroup, drain tracker).
			q.enqueueMu.Lock()
			q.refs.Store(-1)
			q.enqueueMu.Unlock()
			pending := q.drainPending()
			q.notifyWake()
			for _, task := range pending {
				discardUDPReplyTask(task)
			}
			if d.queues.CompareAndDelete(key, q) {
				d.queueChPool.Put(q.ch)
			}
			return true
		})
		if d.pendingConvoys.Load() == 0 {
			d.doneOnce.Do(func() { close(d.done) })
		}
	})
}

func (d *udpReplyDispatcher) wait() {
	if d == nil {
		return
	}
	// See the ordered dispatcher: if no convoy ever started there is nothing
	// to observe on d.done.
	if d.pendingConvoys.Load() == 0 {
		return
	}
	<-d.done
}

func (d *udpReplyDispatcher) queueCount() int {
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

func runUDPReplyTask(task udpReplyDispatchTask) {
	defer func() {
		_ = recover()
	}()
	task.run()
}

func discardUDPReplyTask(task udpReplyDispatchTask) {
	if task.discard == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	task.discard()
}
