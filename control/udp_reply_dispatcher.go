/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
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
	slots        chan struct{}
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

	// Take a backlog slot before enqueuing so one slow endpoint cannot consume
	// unbounded reply memory. Slot release happens in the convoy after the
	// task runs (or on discard paths).
	if nonBlocking {
		select {
		case q.slots <- struct{}{}:
		case <-q.inputStop:
			q.refs.Add(-1)
			return false
		default:
			q.refs.Add(-1)
			return false
		}
	} else {
		select {
		case q.slots <- struct{}{}:
		case <-q.inputStop:
			q.refs.Add(-1)
			return false
		}
	}

	// Re-check the closed/input flags under the slot so a concurrent close
	// cannot strand the slot. If we miss, release the slot and bail out.
	// inputClosed covers both normal endpoint close and abort paths because
	// abortInput / dispatcher close both call closeInputLocked first.
	if d.closed.Load() || q.inputClosed.Load() {
		<-q.slots
		q.refs.Add(-1)
		return false
	}

	q.enqueue(udpReplyDispatchTask{run: run, discard: discard})
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
		slots:      make(chan struct{}, d.queueCapacity),
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

func (q *udpReplyDispatchQueue) enqueue(task udpReplyDispatchTask) {
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
		q.overflowMode = true
		q.overflow = append(q.overflow, task)
		q.overflowLen.Store(int32(len(q.overflow)))
		q.notifyWake()
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

	for {
		// Normal drain: once input is closed, finish any queued replies and
		// exit. The queue removes itself from the dispatcher map so future
		// submits for this endpoint create a fresh queue.
		if q.inputClosed.Load() {
			if task, ok := q.popReadyTask(); ok {
				runUDPReplyTask(task)
				q.releaseSlot()
				continue
			}
			q.enqueueMu.Lock()
			overflowEmpty := len(q.overflow) == 0
			q.enqueueMu.Unlock()
			if overflowEmpty && len(q.ch) == 0 {
				q.releaseAndCleanup()
				return
			}
		}

		if task, ok := q.popReadyTask(); ok {
			runUDPReplyTask(task)
			q.releaseSlot()
			continue
		}

		select {
		case task := <-q.ch:
			runUDPReplyTask(task)
			q.releaseSlot()
		case <-q.wake:
			if q.refs.Load() < 0 {
				q.releaseAndCleanup()
				return
			}
		}
	}
}

// releaseAndCleanup drains any leftover overflow, releases the slot each
// pending task still holds, and removes the queue from the dispatcher map.
// Called once when the convoy is about to exit. Safe to call even if the
// queue was already removed.
func (q *udpReplyDispatchQueue) releaseAndCleanup() {
	pending := q.drainPending()
	for range pending {
		// Each pending task acquired a slot in submitMode; release it now.
		q.releaseSlot()
	}
	q.finishOnce()
	if q.dispatcher.queues.CompareAndDelete(q.endpoint, q) {
		q.dispatcher.queueChPool.Put(q.ch)
	}
}

func (q *udpReplyDispatchQueue) releaseSlot() {
	select {
	case <-q.slots:
	default:
	}
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
	pending := q.drainPending()
	q.notifyWake()
	for _, task := range pending {
		discardUDPReplyTask(task)
		q.releaseSlot()
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
			pending := q.drainPending()
			q.refs.Store(-1)
			q.notifyWake()
			for _, task := range pending {
				discardUDPReplyTask(task)
				q.releaseSlot()
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
