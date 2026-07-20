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
	defaultUDPOrderedDispatcherWorkerCap = 8
	defaultUDPOrderedDispatcherQuantum   = 32
)

type udpOrderedDispatchTask struct {
	run     UdpTask
	discard UdpTask
}

type udpOrderedDispatchQueue struct {
	key UdpFlowKey

	mu        sync.Mutex
	tasks     []udpOrderedDispatchTask
	taskHead  int
	idleSince time.Time
	running   bool
	ready     bool
	retired   bool
}

// udpOrderedDispatcher executes same-flow UDP ingress in FIFO order with a
// bounded worker set. Queue lookup is lock-free across unrelated flows; the
// lifecycle barrier is shared by submits and taken exclusively only by the
// rare Close/Reset paths.
type udpOrderedDispatcher struct {
	queues sync.Map // map[UdpFlowKey]*udpOrderedDispatchQueue

	lifecycleMu sync.RWMutex
	closed      atomic.Bool
	closeMu     sync.Once

	readyMu   sync.Mutex
	ready     []*udpOrderedDispatchQueue
	readyHead int
	wake      chan struct{}
	stop      chan struct{}
	done      chan struct{}
	workers   sync.WaitGroup

	workerCount  int
	drainQuantum int
}

func newDefaultUDPOrderedDispatcher() *udpOrderedDispatcher {
	return newUDPOrderedDispatcher(0, defaultUDPOrderedDispatcherQuantum)
}

func newUDPOrderedDispatcherForFeatures(features SemanticRefactorFeatureSet) *udpOrderedDispatcher {
	if !features.UDPOrderedDispatcher {
		return nil
	}
	return newDefaultUDPOrderedDispatcher()
}

func newUDPOrderedDispatcher(workers, drainQuantum int) *udpOrderedDispatcher {
	workers = normalizeUDPOrderedDispatcherWorkers(workers)
	if drainQuantum <= 0 {
		drainQuantum = defaultUDPOrderedDispatcherQuantum
	}
	d := &udpOrderedDispatcher{
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

func normalizeUDPOrderedDispatcherWorkers(workers int) int {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		return 1
	}
	if workers > defaultUDPOrderedDispatcherWorkerCap {
		return defaultUDPOrderedDispatcherWorkerCap
	}
	return workers
}

func (d *udpOrderedDispatcher) submit(key UdpFlowKey, run, discard UdpTask) bool {
	if d == nil || run == nil {
		return false
	}

	d.lifecycleMu.RLock()
	defer d.lifecycleMu.RUnlock()
	if d.closed.Load() {
		return false
	}

	for {
		q := d.acquireQueue(key)
		q.mu.Lock()
		if q.retired {
			q.mu.Unlock()
			d.queues.CompareAndDelete(key, q)
			continue
		}
		q.tasks = append(q.tasks, udpOrderedDispatchTask{run: run, discard: discard})
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

func (d *udpOrderedDispatcher) acquireQueue(key UdpFlowKey) *udpOrderedDispatchQueue {
	if value, ok := d.queues.Load(key); ok {
		return value.(*udpOrderedDispatchQueue)
	}
	created := &udpOrderedDispatchQueue{key: key}
	actual, _ := d.queues.LoadOrStore(key, created)
	return actual.(*udpOrderedDispatchQueue)
}

func (d *udpOrderedDispatcher) enqueueReady(q *udpOrderedDispatchQueue) {
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

func (d *udpOrderedDispatcher) notify() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *udpOrderedDispatcher) worker() {
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

func (d *udpOrderedDispatcher) takeReadyQueue() *udpOrderedDispatchQueue {
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

func (d *udpOrderedDispatcher) runTurn(q *udpOrderedDispatchQueue) {
	for range d.drainQuantum {
		q.mu.Lock()
		if q.retired || q.taskHead == len(q.tasks) {
			q.mu.Unlock()
			break
		}
		task := q.tasks[q.taskHead]
		q.tasks[q.taskHead] = udpOrderedDispatchTask{}
		q.taskHead++
		if q.taskHead == len(q.tasks) {
			q.tasks = q.tasks[:0]
			q.taskHead = 0
		}
		q.mu.Unlock()
		runUDPOrderedTask(task)
	}
	d.finishTurn(q)
}

func (d *udpOrderedDispatcher) finishTurn(q *udpOrderedDispatchQueue) {
	// Exclude Close/Reset while deciding whether this queue must be rescheduled.
	d.lifecycleMu.RLock()
	defer d.lifecycleMu.RUnlock()

	q.mu.Lock()
	q.running = false
	if q.retired || d.closed.Load() {
		q.retired = true
		d.queues.CompareAndDelete(q.key, q)
		q.mu.Unlock()
		return
	}
	if q.taskHead == len(q.tasks) {
		q.idleSince = time.Now()
		q.mu.Unlock()
		return
	}
	q.ready = true
	q.mu.Unlock()
	d.enqueueReady(q)
}

func (d *udpOrderedDispatcher) close() {
	if d == nil {
		return
	}
	d.closeMu.Do(func() {
		var pending []udpOrderedDispatchTask
		d.lifecycleMu.Lock()
		d.closed.Store(true)
		d.queues.Range(func(key, value any) bool {
			q := value.(*udpOrderedDispatchQueue)
			q.mu.Lock()
			q.retired = true
			q.ready = false
			pending = append(pending, q.tasks[q.taskHead:]...)
			clear(q.tasks[q.taskHead:])
			q.tasks = nil
			q.taskHead = 0
			d.queues.CompareAndDelete(key, q)
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

		for _, task := range pending {
			discardUDPOrderedTask(task)
		}
	})
}

func (d *udpOrderedDispatcher) reset() {
	if d == nil {
		return
	}
	var pending []udpOrderedDispatchTask
	d.lifecycleMu.Lock()
	if d.closed.Load() {
		d.lifecycleMu.Unlock()
		return
	}
	d.queues.Range(func(key, value any) bool {
		q := value.(*udpOrderedDispatchQueue)
		q.mu.Lock()
		pending = append(pending, q.tasks[q.taskHead:]...)
		clear(q.tasks[q.taskHead:])
		q.tasks = nil
		q.taskHead = 0
		q.ready = false
		if !q.running {
			q.retired = true
			d.queues.CompareAndDelete(key, q)
		}
		q.mu.Unlock()
		return true
	})
	d.readyMu.Lock()
	clear(d.ready)
	d.ready = nil
	d.readyHead = 0
	d.readyMu.Unlock()
	d.lifecycleMu.Unlock()

	for _, task := range pending {
		discardUDPOrderedTask(task)
	}
}

func (d *udpOrderedDispatcher) janitor() {
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

func (d *udpOrderedDispatcher) reapIdleQueues(now time.Time, maxIdle time.Duration) {
	d.lifecycleMu.RLock()
	defer d.lifecycleMu.RUnlock()
	if d.closed.Load() {
		return
	}
	d.queues.Range(func(key, value any) bool {
		q := value.(*udpOrderedDispatchQueue)
		q.mu.Lock()
		if !q.retired && !q.running && !q.ready && q.taskHead == len(q.tasks) &&
			!q.idleSince.IsZero() && now.Sub(q.idleSince) >= maxIdle {
			q.retired = true
			q.tasks = nil
			q.taskHead = 0
			d.queues.CompareAndDelete(key, q)
		}
		q.mu.Unlock()
		return true
	})
}

func udpDispatcherAgingTime() time.Duration {
	if UdpTaskPoolAgingTime <= 0 {
		return time.Millisecond
	}
	return UdpTaskPoolAgingTime
}

func (d *udpOrderedDispatcher) wait() {
	if d == nil {
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
