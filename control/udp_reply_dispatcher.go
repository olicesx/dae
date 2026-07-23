/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultUDPReplyDispatcherWorkerCap = 8
	defaultUDPReplyDispatcherQuantum   = 32
)

type udpReplyDispatchTask struct {
	run     func()
	discard func()
}

type udpReplyDispatchQueue struct {
	endpoint *UdpEndpoint
	done     chan struct{}
	doneOnce sync.Once

	mu          sync.Mutex
	tasks       []udpReplyDispatchTask
	taskHead    int
	idleSince   time.Time
	running     bool
	ready       bool
	retired     bool
	inputClosed bool
}

// udpReplyDispatcher preserves endpoint FIFO with a bounded worker set. The
// caller owns per-endpoint backlog admission through replyRuntime.slots, while
// this dispatcher owns scheduling and endpoint lifecycle coordination.
type udpReplyDispatcher struct {
	queues sync.Map // map[*UdpEndpoint]*udpReplyDispatchQueue

	lifecycleMu sync.RWMutex
	closed      atomic.Bool
	closeMu     sync.Once

	readyMu   sync.Mutex
	ready     []*udpReplyDispatchQueue
	readyHead int
	wake      chan struct{}
	stop      chan struct{}
	done      chan struct{}
	workers   sync.WaitGroup

	workerCount  int
	drainQuantum int
	panicCount   atomic.Uint64
}

func newUDPReplyDispatcherForFeatures(features SemanticRefactorFeatureSet) *udpReplyDispatcher {
	if !features.UDPReplyDispatcher {
		return nil
	}
	return newDefaultUDPReplyDispatcher()
}

func newDefaultUDPReplyDispatcher() *udpReplyDispatcher {
	return newUDPReplyDispatcher(0, defaultUDPReplyDispatcherQuantum)
}

func newUDPReplyDispatcher(workers, drainQuantum int) *udpReplyDispatcher {
	workers = normalizeUDPReplyDispatcherWorkers(workers)
	if drainQuantum <= 0 {
		drainQuantum = defaultUDPReplyDispatcherQuantum
	}
	d := &udpReplyDispatcher{
		wake:         make(chan struct{}, workers),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		workerCount:  workers,
		drainQuantum: drainQuantum,
	}
	for range workers {
		d.workers.Add(1)
		go d.worker()
	}
	d.workers.Add(1)
	go d.janitor()
	go func() {
		d.workers.Wait()
		close(d.done)
	}()
	return d
}

func normalizeUDPReplyDispatcherWorkers(workers int) int {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		return 1
	}
	if workers > defaultUDPReplyDispatcherWorkerCap {
		return defaultUDPReplyDispatcherWorkerCap
	}
	return workers
}

func (d *udpReplyDispatcher) submit(endpoint *UdpEndpoint, run, discard func()) bool {
	if d == nil || endpoint == nil || run == nil {
		return false
	}

	d.lifecycleMu.RLock()
	defer d.lifecycleMu.RUnlock()
	if d.closed.Load() {
		return false
	}

	for {
		q := d.acquireQueue(endpoint)
		q.mu.Lock()
		if q.retired {
			q.mu.Unlock()
			d.queues.CompareAndDelete(endpoint, q)
			continue
		}
		if q.inputClosed {
			q.mu.Unlock()
			return false
		}
		q.tasks = append(q.tasks, udpReplyDispatchTask{run: run, discard: discard})
		q.idleSince = time.Time{}
		shouldWake := !q.running && !q.ready
		if shouldWake {
			q.ready = true
		}
		q.mu.Unlock()

		if shouldWake {
			d.enqueueReady(q)
		}
		return true
	}
}

func (d *udpReplyDispatcher) acquireQueue(endpoint *UdpEndpoint) *udpReplyDispatchQueue {
	if value, ok := d.queues.Load(endpoint); ok {
		return value.(*udpReplyDispatchQueue)
	}
	created := &udpReplyDispatchQueue{
		endpoint: endpoint,
		done:     make(chan struct{}),
	}
	actual, _ := d.queues.LoadOrStore(endpoint, created)
	return actual.(*udpReplyDispatchQueue)
}

func (d *udpReplyDispatcher) enqueueReady(q *udpReplyDispatchQueue) {
	d.readyMu.Lock()
	if d.readyHead > 0 && len(d.ready) == cap(d.ready) {
		copy(d.ready, d.ready[d.readyHead:])
		d.ready = d.ready[:len(d.ready)-d.readyHead]
		d.readyHead = 0
	}
	d.ready = append(d.ready, q)
	d.readyMu.Unlock()
	d.notify()
}

func (d *udpReplyDispatcher) notify() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *udpReplyDispatcher) worker() {
	defer d.workers.Done()
	for {
		if q := d.takeReadyQueue(); q != nil {
			d.runTurn(q)
			continue
		}
		select {
		case <-d.stop:
			return
		case <-d.wake:
		}
	}
}

func (d *udpReplyDispatcher) takeReadyQueue() *udpReplyDispatchQueue {
	for {
		d.readyMu.Lock()
		if d.readyHead == len(d.ready) {
			d.ready = d.ready[:0]
			d.readyHead = 0
			d.readyMu.Unlock()
			return nil
		}
		q := d.ready[d.readyHead]
		d.ready[d.readyHead] = nil
		d.readyHead++
		wakeAnother := d.readyHead < len(d.ready)
		d.readyMu.Unlock()
		if wakeAnother {
			d.notify()
		}

		q.mu.Lock()
		if q.retired || !q.ready || q.running {
			q.mu.Unlock()
			continue
		}
		q.ready = false
		q.running = true
		q.mu.Unlock()
		return q
	}
}

func (d *udpReplyDispatcher) runTurn(q *udpReplyDispatchQueue) {
	for range d.drainQuantum {
		q.mu.Lock()
		if q.retired || q.taskHead == len(q.tasks) {
			q.mu.Unlock()
			break
		}
		task := q.tasks[q.taskHead]
		q.tasks[q.taskHead] = udpReplyDispatchTask{}
		q.taskHead++
		if q.taskHead == len(q.tasks) {
			q.tasks = q.tasks[:0]
			q.taskHead = 0
		}
		q.mu.Unlock()
		d.runTask(task)
	}
	d.finishTurn(q)
}

func (d *udpReplyDispatcher) finishTurn(q *udpReplyDispatchQueue) {
	d.lifecycleMu.RLock()
	defer d.lifecycleMu.RUnlock()

	finish := false
	reschedule := false
	q.mu.Lock()
	q.running = false
	switch {
	case q.retired || d.closed.Load():
		q.retired = true
		d.queues.CompareAndDelete(q.endpoint, q)
		finish = true
	case q.taskHead == len(q.tasks):
		q.idleSince = time.Now()
		if q.inputClosed {
			q.retired = true
			d.queues.CompareAndDelete(q.endpoint, q)
			finish = true
		}
	default:
		q.ready = true
		reschedule = true
	}
	q.mu.Unlock()

	if finish {
		q.finishOnce()
		return
	}
	if reschedule {
		d.enqueueReady(q)
	}
}

func (d *udpReplyDispatcher) closeInput(endpoint *UdpEndpoint) {
	_ = d.closeInputQueue(endpoint)
}

func (d *udpReplyDispatcher) closeInputAndWait(endpoint *UdpEndpoint) {
	if done := d.closeInputQueue(endpoint); done != nil {
		<-done
	}
}

func (d *udpReplyDispatcher) closeInputQueue(endpoint *UdpEndpoint) <-chan struct{} {
	if d == nil || endpoint == nil {
		return nil
	}

	d.lifecycleMu.Lock()
	value, ok := d.queues.Load(endpoint)
	if !ok {
		d.lifecycleMu.Unlock()
		return nil
	}
	q := value.(*udpReplyDispatchQueue)
	finish := false
	q.mu.Lock()
	q.inputClosed = true
	done := q.done
	if !q.running && q.taskHead == len(q.tasks) {
		q.retired = true
		q.ready = false
		d.queues.CompareAndDelete(endpoint, q)
		finish = true
	}
	q.mu.Unlock()
	d.lifecycleMu.Unlock()
	if finish {
		q.finishOnce()
	}
	return done
}

// abortInput rejects new endpoint work and discards queued replies without
// waiting for the currently running handler.
func (d *udpReplyDispatcher) abortInput(endpoint *UdpEndpoint) {
	if d == nil || endpoint == nil {
		return
	}

	var pending []udpReplyDispatchTask
	var finishQueue *udpReplyDispatchQueue
	d.lifecycleMu.Lock()
	if value, ok := d.queues.Load(endpoint); ok {
		q := value.(*udpReplyDispatchQueue)
		q.mu.Lock()
		q.inputClosed = true
		q.retired = true
		q.ready = false
		pending = append(pending, q.tasks[q.taskHead:]...)
		clear(q.tasks[q.taskHead:])
		q.tasks = nil
		q.taskHead = 0
		d.queues.CompareAndDelete(endpoint, q)
		if !q.running {
			finishQueue = q
		}
		q.mu.Unlock()
	}
	d.lifecycleMu.Unlock()
	if finishQueue != nil {
		finishQueue.finishOnce()
	}

	for _, task := range pending {
		d.discardTask(task)
	}
}

func (d *udpReplyDispatcher) close() {
	if d == nil {
		return
	}
	d.closeMu.Do(func() {
		var pending []udpReplyDispatchTask
		var finish []*udpReplyDispatchQueue
		d.lifecycleMu.Lock()
		d.closed.Store(true)
		d.queues.Range(func(key, value any) bool {
			q := value.(*udpReplyDispatchQueue)
			q.mu.Lock()
			q.inputClosed = true
			q.retired = true
			q.ready = false
			pending = append(pending, q.tasks[q.taskHead:]...)
			clear(q.tasks[q.taskHead:])
			q.tasks = nil
			q.taskHead = 0
			d.queues.CompareAndDelete(key, q)
			if !q.running {
				finish = append(finish, q)
			}
			q.mu.Unlock()
			return true
		})
		d.readyMu.Lock()
		clear(d.ready)
		d.ready = nil
		d.readyHead = 0
		d.readyMu.Unlock()
		close(d.stop)
		d.lifecycleMu.Unlock()

		for _, q := range finish {
			q.finishOnce()
		}
		for _, task := range pending {
			d.discardTask(task)
		}
	})
}

func (d *udpReplyDispatcher) janitor() {
	defer d.workers.Done()
	interval := udpDispatcherAgingTime()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stop:
			return
		case now := <-ticker.C:
			d.reapIdleQueues(now, interval)
		}
	}
}

func (d *udpReplyDispatcher) reapIdleQueues(now time.Time, maxIdle time.Duration) {
	d.lifecycleMu.RLock()
	defer d.lifecycleMu.RUnlock()
	if d.closed.Load() {
		return
	}
	d.queues.Range(func(key, value any) bool {
		q := value.(*udpReplyDispatchQueue)
		finish := false
		q.mu.Lock()
		if !q.retired && !q.running && !q.ready && q.taskHead == len(q.tasks) &&
			!q.idleSince.IsZero() && now.Sub(q.idleSince) >= maxIdle {
			q.retired = true
			q.tasks = nil
			q.taskHead = 0
			d.queues.CompareAndDelete(key, q)
			finish = true
		}
		q.mu.Unlock()
		if finish {
			q.finishOnce()
		}
		return true
	})
}

func (d *udpReplyDispatcher) wait() {
	if d == nil {
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

func (q *udpReplyDispatchQueue) finishOnce() {
	q.doneOnce.Do(func() { close(q.done) })
}

func (d *udpReplyDispatcher) runTask(task udpReplyDispatchTask) {
	defer func() {
		if recovered := recover(); recovered != nil {
			reportUDPDispatcherPanic("reply", "run", &d.panicCount, recovered)
		}
	}()
	task.run()
}

func (d *udpReplyDispatcher) discardTask(task udpReplyDispatchTask) {
	if task.discard == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			reportUDPDispatcherPanic("reply", "discard", &d.panicCount, recovered)
		}
	}()
	task.discard()
}
