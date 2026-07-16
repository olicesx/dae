/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"runtime"
	"sync"
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
	endpoint    *UdpEndpoint
	tasks       []udpReplyDispatchTask
	slots       chan struct{}
	inputStop   chan struct{}
	done        chan struct{}
	running     bool
	ready       bool
	inputClosed bool
	doneOnce    sync.Once
}

// udpReplyDispatcher executes endpoint replies with a fixed worker set. It
// retains the legacy sender contract: each endpoint is FIFO, accepted work is
// bounded, and a normal endpoint close drains replies already accepted by the
// read loop. Abort and process shutdown instead discard pending work through
// its caller-provided release function.
type udpReplyDispatcher struct {
	mu      sync.Mutex
	queues  map[*UdpEndpoint]*udpReplyDispatchQueue
	ready   []*udpReplyDispatchQueue
	wake    chan struct{}
	stop    chan struct{}
	done    chan struct{}
	closed  bool
	closeMu sync.Once
	wg      sync.WaitGroup

	workerCount   int
	drainQuantum  int
	queueCapacity int
}

func newUDPReplyDispatcherForFeatures(features SemanticRefactorFeatureSet) *udpReplyDispatcher {
	if !features.UDPReplyDispatcher {
		return nil
	}
	return newDefaultUDPReplyDispatcher()
}

func newDefaultUDPReplyDispatcher() *udpReplyDispatcher {
	return newUDPReplyDispatcher(0, defaultUDPReplyDispatcherQuantum, udpEndpointReplyQueueSize)
}

func newUDPReplyDispatcher(workers, drainQuantum, queueCapacity int) *udpReplyDispatcher {
	workers = normalizeUDPReplyDispatcherWorkers(workers)
	if drainQuantum <= 0 {
		drainQuantum = defaultUDPReplyDispatcherQuantum
	}
	if queueCapacity <= 0 {
		queueCapacity = udpEndpointReplyQueueSize
	}
	d := &udpReplyDispatcher{
		queues:        make(map[*UdpEndpoint]*udpReplyDispatchQueue),
		wake:          make(chan struct{}, workers),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		workerCount:   workers,
		drainQuantum:  drainQuantum,
		queueCapacity: queueCapacity,
	}
	for range workers {
		d.wg.Add(1)
		go d.worker()
	}
	go func() {
		d.wg.Wait()
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

// submit blocks when this endpoint already has its bounded reply backlog. It
// returns false only when the endpoint input or dispatcher has closed; the
// caller retains ownership of work in that case.
func (d *udpReplyDispatcher) submit(endpoint *UdpEndpoint, run, discard func()) bool {
	return d.submitMode(endpoint, run, discard, false)
}

// submitNonBlocking rejects work when the endpoint's bounded reply backlog is
// full. It is used by transport-owned readers so one slow endpoint cannot
// block delivery for unrelated sockets sharing the reader.
func (d *udpReplyDispatcher) submitNonBlocking(endpoint *UdpEndpoint, run, discard func()) bool {
	return d.submitMode(endpoint, run, discard, true)
}

func (d *udpReplyDispatcher) submitMode(endpoint *UdpEndpoint, run, discard func(), nonBlocking bool) bool {
	if d == nil || endpoint == nil || run == nil {
		return false
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return false
	}
	queue := d.queues[endpoint]
	if queue == nil {
		queue = &udpReplyDispatchQueue{
			endpoint:  endpoint,
			slots:     make(chan struct{}, d.queueCapacity),
			inputStop: make(chan struct{}),
			done:      make(chan struct{}),
		}
		d.queues[endpoint] = queue
	}
	if queue.inputClosed {
		d.mu.Unlock()
		return false
	}
	d.mu.Unlock()

	if nonBlocking {
		select {
		case queue.slots <- struct{}{}:
		case <-queue.inputStop:
			return false
		case <-d.stop:
			return false
		default:
			return false
		}
	} else {
		select {
		case queue.slots <- struct{}{}:
		case <-queue.inputStop:
			return false
		case <-d.stop:
			return false
		}
	}

	d.mu.Lock()
	if d.closed || queue.inputClosed || d.queues[endpoint] != queue {
		d.mu.Unlock()
		<-queue.slots
		return false
	}
	queue.tasks = append(queue.tasks, udpReplyDispatchTask{run: run, discard: discard})
	shouldWake := !queue.running && !queue.ready
	if shouldWake {
		queue.ready = true
		d.ready = append(d.ready, queue)
	}
	d.mu.Unlock()
	if shouldWake {
		d.notify()
	}
	return true
}

// closeInputAndWait prevents additional work for one endpoint and delivers
// every reply accepted before the close. It is used by the endpoint read loop
// after ReadFrom exits normally.
func (d *udpReplyDispatcher) closeInputAndWait(endpoint *UdpEndpoint) {
	if d == nil || endpoint == nil {
		return
	}
	d.mu.Lock()
	queue := d.queues[endpoint]
	if queue == nil {
		d.mu.Unlock()
		return
	}
	d.closeQueueInputLocked(queue)
	if !queue.running && len(queue.tasks) == 0 {
		d.finishQueueLocked(queue)
	}
	done := queue.done
	d.mu.Unlock()
	<-done
}

func (d *udpReplyDispatcher) closeInput(endpoint *UdpEndpoint) {
	if d == nil || endpoint == nil {
		return
	}
	d.mu.Lock()
	queue := d.queues[endpoint]
	if queue != nil {
		d.closeQueueInputLocked(queue)
		if !queue.running && len(queue.tasks) == 0 {
			d.finishQueueLocked(queue)
		}
	}
	d.mu.Unlock()
}

// abortInput prevents additional work for one endpoint and releases queued
// replies without delivering them. It never waits for a currently running
// handler, so it is safe to call from that handler's worker.
func (d *udpReplyDispatcher) abortInput(endpoint *UdpEndpoint) {
	if d == nil || endpoint == nil {
		return
	}
	d.mu.Lock()
	queue := d.queues[endpoint]
	if queue == nil {
		d.mu.Unlock()
		return
	}
	d.closeQueueInputLocked(queue)
	pending := queue.tasks
	queue.tasks = nil
	queue.ready = false
	if !queue.running {
		d.finishQueueLocked(queue)
	}
	d.mu.Unlock()
	d.discardTasks(queue, pending)
}

func (d *udpReplyDispatcher) close() {
	if d == nil {
		return
	}
	d.closeMu.Do(func() {
		d.mu.Lock()
		d.closed = true
		var pending []udpReplyDispatchTask
		var pendingQueues []*udpReplyDispatchQueue
		for _, queue := range d.queues {
			d.closeQueueInputLocked(queue)
			for range queue.tasks {
				pendingQueues = append(pendingQueues, queue)
			}
			pending = append(pending, queue.tasks...)
			queue.tasks = nil
			queue.ready = false
			if !queue.running {
				d.finishQueueLocked(queue)
			}
		}
		clear(d.ready)
		d.ready = nil
		d.mu.Unlock()

		for index, task := range pending {
			discardUDPReplyTask(task)
			d.releaseSlot(pendingQueues[index])
		}
		close(d.stop)
		d.notify()
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
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.queues)
}

func (d *udpReplyDispatcher) closeQueueInputLocked(queue *udpReplyDispatchQueue) {
	if queue == nil || queue.inputClosed {
		return
	}
	queue.inputClosed = true
	close(queue.inputStop)
}

func (d *udpReplyDispatcher) finishQueueLocked(queue *udpReplyDispatchQueue) {
	if queue == nil {
		return
	}
	if d.queues[queue.endpoint] == queue {
		delete(d.queues, queue.endpoint)
	}
	queue.doneOnce.Do(func() { close(queue.done) })
}

func (d *udpReplyDispatcher) notify() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *udpReplyDispatcher) worker() {
	defer d.wg.Done()
	for {
		queue := d.takeReadyQueue()
		if queue != nil {
			d.runTurn(queue)
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
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.ready) > 0 {
		queue := d.ready[0]
		d.ready[0] = nil
		d.ready = d.ready[1:]
		if len(d.ready) == 0 {
			d.ready = nil
		}
		if queue == nil || !queue.ready || d.closed || len(queue.tasks) == 0 {
			continue
		}
		queue.ready = false
		queue.running = true
		if len(d.ready) > 0 {
			d.notify()
		}
		return queue
	}
	return nil
}

func (d *udpReplyDispatcher) runTurn(queue *udpReplyDispatchQueue) {
	for range d.drainQuantum {
		task, ok := d.takeQueueTask(queue)
		if !ok {
			break
		}
		runUDPReplyTask(task)
		d.releaseSlot(queue)
	}
	d.finishTurn(queue)
}

func (d *udpReplyDispatcher) takeQueueTask(queue *udpReplyDispatchQueue) (udpReplyDispatchTask, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if queue == nil || d.closed || len(queue.tasks) == 0 {
		return udpReplyDispatchTask{}, false
	}
	task := queue.tasks[0]
	queue.tasks[0] = udpReplyDispatchTask{}
	queue.tasks = queue.tasks[1:]
	return task, true
}

func (d *udpReplyDispatcher) finishTurn(queue *udpReplyDispatchQueue) {
	if queue == nil {
		return
	}
	d.mu.Lock()
	queue.running = false
	shouldWake := false
	if !d.closed && len(queue.tasks) > 0 {
		queue.ready = true
		d.ready = append(d.ready, queue)
		shouldWake = true
	} else if queue.inputClosed || d.closed {
		d.finishQueueLocked(queue)
	}
	d.mu.Unlock()
	if shouldWake {
		d.notify()
	}
}

func (d *udpReplyDispatcher) discardTasks(queue *udpReplyDispatchQueue, tasks []udpReplyDispatchTask) {
	for _, task := range tasks {
		discardUDPReplyTask(task)
		d.releaseSlot(queue)
	}
}

func (d *udpReplyDispatcher) releaseSlot(queue *udpReplyDispatchQueue) {
	if queue == nil {
		return
	}
	<-queue.slots
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
