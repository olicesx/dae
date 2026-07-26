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

	"github.com/sirupsen/logrus"
)

const (
	// The worker cap bounds scheduler pressure, not throughput: tasks are
	// per-packet and short. Worst-case liveness under stalled upstreams is
	// owned by udpEndpointWriteTimeout, which unparks a worker in bounded
	// time, so the cap does not need to scale with core count.
	defaultUDPOrderedDispatcherWorkerCap = 8
	defaultUDPOrderedDispatcherQuantum   = 32
	// Bound queued packet buffers even when a flow handler or all workers are
	// slower than ingress. Running tasks are bounded by the fixed worker count.
	defaultUDPOrderedDispatcherMaxPending        = UdpTaskQueueLength * defaultUDPOrderedDispatcherWorkerCap
	defaultUDPOrderedDispatcherMaxPendingPerFlow = UdpTaskQueueLength * 2
	// Preserve the base hot-worker budget while endpoint dials wait on proxy
	// handshakes, without allowing unbounded dial goroutines.
	defaultUDPOrderedDispatcherMaxCompensatingWorkers = defaultUDPOrderedDispatcherWorkerCap * 8
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

	ready   *readyRing[udpOrderedDispatchQueue]
	stop    chan struct{}
	done    chan struct{}
	workers sync.WaitGroup

	// compensationSlots bounds cold endpoint creations that borrow a temporary
	// worker. The channel is never closed because release may race teardown.
	compensationSlots              chan struct{}
	compensatingWorkerCount        atomic.Int32
	endpointCreateAdmissionRejects atomic.Uint64

	workerCount  int
	drainQuantum int
	maxPending   int64
	maxPerFlow   int
	pending      atomic.Int64
	panicCount   atomic.Uint64
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
	return newUDPOrderedDispatcherWithLimits(
		workers,
		drainQuantum,
		defaultUDPOrderedDispatcherMaxPending,
		defaultUDPOrderedDispatcherMaxPendingPerFlow,
	)
}

func newUDPOrderedDispatcherWithLimits(workers, drainQuantum, maxPending, maxPerFlow int) *udpOrderedDispatcher {
	return newUDPOrderedDispatcherWithLimitsAndCompensation(
		workers,
		drainQuantum,
		maxPending,
		maxPerFlow,
		defaultUDPOrderedDispatcherMaxCompensatingWorkers,
	)
}

func newUDPOrderedDispatcherWithLimitsAndCompensation(workers, drainQuantum, maxPending, maxPerFlow, maxCompensatingWorkers int) *udpOrderedDispatcher {
	workers = normalizeUDPOrderedDispatcherWorkers(workers)
	if drainQuantum <= 0 {
		drainQuantum = defaultUDPOrderedDispatcherQuantum
	}
	if maxPending <= 0 {
		maxPending = defaultUDPOrderedDispatcherMaxPending
	}
	if maxPerFlow <= 0 {
		maxPerFlow = defaultUDPOrderedDispatcherMaxPendingPerFlow
	}
	if maxPerFlow > maxPending {
		maxPerFlow = maxPending
	}
	if maxCompensatingWorkers <= 0 {
		maxCompensatingWorkers = defaultUDPOrderedDispatcherMaxCompensatingWorkers
	}
	d := &udpOrderedDispatcher{
		ready:             newReadyRing[udpOrderedDispatchQueue](workers),
		stop:              make(chan struct{}),
		done:              make(chan struct{}),
		workerCount:       workers,
		drainQuantum:      drainQuantum,
		maxPending:        int64(maxPending),
		maxPerFlow:        maxPerFlow,
		compensationSlots: make(chan struct{}, maxCompensatingWorkers),
	}
	for range workers {
		d.startWorker(nil)
	}
	d.workers.Add(1)
	go d.janitor()
	go func() {
		d.workers.Wait()
		close(d.done)
	}()
	return d
}

func (d *udpOrderedDispatcher) startWorker(retire <-chan struct{}) {
	d.workers.Add(1)
	go d.worker(retire)
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
		if len(q.tasks)-q.taskHead >= d.maxPerFlow || !d.reservePending() {
			q.mu.Unlock()
			return false
		}
		q.tasks = append(q.tasks, udpOrderedDispatchTask{run: run, discard: discard})
		q.idleSince = time.Time{}
		shouldWake := !q.running && !q.ready
		if shouldWake {
			q.ready = true
		}
		q.mu.Unlock()

		if shouldWake {
			d.ready.push(q)
		}
		return true
	}
}

func (d *udpOrderedDispatcher) reservePending() bool {
	for {
		pending := d.pending.Load()
		if pending >= d.maxPending {
			return false
		}
		if d.pending.CompareAndSwap(pending, pending+1) {
			return true
		}
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

func (d *udpOrderedDispatcher) worker(retire <-chan struct{}) {
	defer d.workers.Done()
	if retire != nil {
		defer func() {
			d.compensatingWorkerCount.Add(-1)
			<-d.compensationSlots
		}()
	}
	for {
		select {
		case <-d.stop:
			return
		case <-retire:
			return
		default:
		}
		if q := d.takeReadyQueue(); q != nil {
			d.runTurn(q)
			continue
		}
		select {
		case <-d.stop:
			return
		case <-retire:
			return
		case <-d.ready.wake:
		}
	}
}

// acquireEndpointCreateAdmission reserves a bounded cold-path slot before a
// task waits for endpoint creation or DialContext. Its temporary worker keeps
// the base worker budget available to already-established UDP and QUIC flows.
func (d *udpOrderedDispatcher) acquireEndpointCreateAdmission() (release func(), ok bool) {
	if d == nil {
		return func() {}, true
	}
	select {
	case d.compensationSlots <- struct{}{}:
	default:
		d.reportEndpointCreateAdmissionSaturated()
		return nil, false
	}
	// Close takes lifecycleMu exclusively before closing stop. Holding its read
	// side prevents a WaitGroup Add after worker shutdown has begun.
	d.lifecycleMu.RLock()
	if d.closed.Load() {
		d.lifecycleMu.RUnlock()
		<-d.compensationSlots
		return nil, false
	}
	retire := make(chan struct{})
	d.compensatingWorkerCount.Add(1)
	d.startWorker(retire)
	d.lifecycleMu.RUnlock()
	var once sync.Once
	return func() {
		once.Do(func() { close(retire) })
	}, true
}

func (d *udpOrderedDispatcher) endpointCreateAdmissionState() (reserved, workers int) {
	if d == nil {
		return 0, 0
	}
	return len(d.compensationSlots), int(d.compensatingWorkerCount.Load())
}

func (d *udpOrderedDispatcher) reportEndpointCreateAdmissionSaturated() {
	count := d.endpointCreateAdmissionRejects.Add(1)
	if count&(count-1) != 0 {
		return
	}
	logrus.WithFields(logrus.Fields{
		"dispatcher":        "ordered",
		"event":             "endpoint_create_admission_saturated",
		"rejected_requests": count,
	}).Warn("UDP ordered endpoint creation admission is saturated")
}

func (d *udpOrderedDispatcher) takeReadyQueue() *udpOrderedDispatchQueue {
	for {
		q := d.ready.pop()
		if q == nil {
			return nil
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
		d.pending.Add(-1)
		if q.taskHead == len(q.tasks) {
			q.tasks = q.tasks[:0]
			q.taskHead = 0
		}
		q.mu.Unlock()
		d.runTask(task)
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
	d.ready.push(q)
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
			queued := q.tasks[q.taskHead:]
			pending = append(pending, queued...)
			d.pending.Add(-int64(len(queued)))
			clear(q.tasks[q.taskHead:])
			q.tasks = nil
			q.taskHead = 0
			d.queues.CompareAndDelete(key, q)
			q.mu.Unlock()
			return true
		})
		d.ready.reset()
		close(d.stop)
		d.lifecycleMu.Unlock()

		for _, task := range pending {
			d.discardTask(task)
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
		queued := q.tasks[q.taskHead:]
		pending = append(pending, queued...)
		d.pending.Add(-int64(len(queued)))
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
	d.ready.reset()
	d.lifecycleMu.Unlock()

	for _, task := range pending {
		d.discardTask(task)
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

func (d *udpOrderedDispatcher) pendingTaskCount() int64 {
	if d == nil {
		return 0
	}
	return d.pending.Load()
}

func (d *udpOrderedDispatcher) isClosed() bool {
	if d == nil {
		return true
	}
	return d.closed.Load()
}

func (d *udpOrderedDispatcher) runTask(task udpOrderedDispatchTask) {
	defer func() {
		if recovered := recover(); recovered != nil {
			reportUDPDispatcherPanic("ordered", "run", &d.panicCount, recovered)
		}
	}()
	task.run()
}

func (d *udpOrderedDispatcher) discardTask(task udpOrderedDispatchTask) {
	if task.discard == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			reportUDPDispatcherPanic("ordered", "discard", &d.panicCount, recovered)
		}
	}()
	task.discard()
}

func reportUDPDispatcherPanic(dispatcher, taskKind string, panicCount *atomic.Uint64, recovered any) {
	count := panicCount.Add(1)
	if count&(count-1) != 0 {
		return
	}
	logrus.WithFields(logrus.Fields{
		"dispatcher":  dispatcher,
		"task_kind":   taskKind,
		"panic":       recovered,
		"panic_count": count,
	}).Error("recovered panic in UDP dispatcher task")
}
