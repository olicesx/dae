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
	defaultUDPOrderedDispatcherWorkerCap = 8
	defaultUDPOrderedDispatcherQuantum   = 32
)

type udpOrderedDispatchTask struct {
	run     UdpTask
	discard UdpTask
}

type udpOrderedDispatchQueue struct {
	key     UdpFlowKey
	tasks   []udpOrderedDispatchTask
	running bool
	ready   bool
}

// udpOrderedDispatcher provides bounded, per-generation execution for UDP
// flows that require FIFO ingress. It intentionally does not use the control
// plane context: Close must release accepted ingress work before callers wait
// on the admission gate.
type udpOrderedDispatcher struct {
	mu      sync.Mutex
	queues  map[UdpFlowKey]*udpOrderedDispatchQueue
	ready   []*udpOrderedDispatchQueue
	wake    chan struct{}
	stop    chan struct{}
	done    chan struct{}
	closed  bool
	closeMu sync.Once
	wg      sync.WaitGroup

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
		queues:       make(map[UdpFlowKey]*udpOrderedDispatchQueue),
		wake:         make(chan struct{}, workers),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		workerCount:  workers,
		drainQuantum: drainQuantum,
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

// submit accepts one ordered ingress task. Once accepted, the task runs or is
// discarded exactly once by Close; false leaves ownership with the caller.
func (d *udpOrderedDispatcher) submit(key UdpFlowKey, run, discard UdpTask) bool {
	if d == nil || run == nil {
		return false
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return false
	}
	queue := d.queues[key]
	if queue == nil {
		queue = &udpOrderedDispatchQueue{key: key}
		d.queues[key] = queue
	}
	queue.tasks = append(queue.tasks, udpOrderedDispatchTask{run: run, discard: discard})
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

func (d *udpOrderedDispatcher) close() {
	if d == nil {
		return
	}
	d.closeMu.Do(func() {
		pending := d.discardPending(true)
		for _, task := range pending {
			discardUDPOrderedTask(task)
		}
		close(d.stop)
		d.notify()
	})
}

func (d *udpOrderedDispatcher) reset() {
	if d == nil {
		return
	}
	for _, task := range d.discardPending(false) {
		discardUDPOrderedTask(task)
	}
}

func (d *udpOrderedDispatcher) discardPending(closing bool) []udpOrderedDispatchTask {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	if closing {
		d.closed = true
	}
	var pending []udpOrderedDispatchTask
	for key, queue := range d.queues {
		pending = append(pending, queue.tasks...)
		queue.tasks = nil
		queue.ready = false
		if closing || !queue.running {
			delete(d.queues, key)
		}
	}
	clear(d.ready)
	d.ready = nil
	return pending
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
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.queues)
}

func (d *udpOrderedDispatcher) notify() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *udpOrderedDispatcher) worker() {
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

func (d *udpOrderedDispatcher) takeReadyQueue() *udpOrderedDispatchQueue {
	d.mu.Lock()
	if d.closed || len(d.ready) == 0 {
		d.mu.Unlock()
		return nil
	}
	queue := d.ready[0]
	d.ready[0] = nil
	d.ready = d.ready[1:]
	if len(d.ready) == 0 {
		d.ready = nil
	}
	queue.ready = false
	queue.running = true
	wakeAnother := len(d.ready) > 0
	d.mu.Unlock()
	if wakeAnother {
		d.notify()
	}
	return queue
}

func (d *udpOrderedDispatcher) runTurn(queue *udpOrderedDispatchQueue) {
	for range d.drainQuantum {
		task, ok := d.takeQueueTask(queue)
		if !ok {
			break
		}
		if d.isClosed() {
			discardUDPOrderedTask(task)
			continue
		}
		runUDPOrderedTask(task)
	}
	d.finishTurn(queue)
}

func (d *udpOrderedDispatcher) takeQueueTask(queue *udpOrderedDispatchQueue) (udpOrderedDispatchTask, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || queue == nil || len(queue.tasks) == 0 {
		return udpOrderedDispatchTask{}, false
	}
	task := queue.tasks[0]
	queue.tasks[0] = udpOrderedDispatchTask{}
	queue.tasks = queue.tasks[1:]
	return task, true
}

func (d *udpOrderedDispatcher) finishTurn(queue *udpOrderedDispatchQueue) {
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
	} else {
		delete(d.queues, queue.key)
	}
	d.mu.Unlock()
	if shouldWake {
		d.notify()
	}
}

func (d *udpOrderedDispatcher) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
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
