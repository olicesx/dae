/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// DnsTask represents a DNS request to be processed by the worker pool
type DnsTask struct {
	msg       *dnsmessage.Msg
	req       *dnsRequest
	queryInfo queryInfo
	ctx       context.Context
	done      chan struct{} // Closed when worker finishes processing
}

// DnsWorkerPool manages a pool of goroutines to process DNS requests
// This replaces the per-request goroutine creation pattern, reducing overhead
type DnsWorkerPool struct {
	workers     int
	taskQueue   chan *DnsTask
	bufferPool  *sync.Pool // Pre-allocated buffers for each worker
	stopChan    chan struct{}
	stopOnce    sync.Once   // Ensures Stop() is idempotent
	stopped     atomic.Bool // Tracks if the pool has been stopped
	wg          sync.WaitGroup
	activeTasks int64 // Counter for active tasks (for metrics)
}

// NewDnsWorkerPool creates a new DNS worker pool
// workers: number of worker goroutines (default: runtime.NumCPU())
// queueSize: size of the task queue (default: 1000)
func NewDnsWorkerPool(workers, queueSize int) *DnsWorkerPool {
	if workers <= 0 {
		workers = 8 // Default to 8 workers
	}
	if queueSize <= 0 {
		queueSize = 1000 // Default queue size
	}

	pool := &DnsWorkerPool{
		workers:   workers,
		taskQueue: make(chan *DnsTask, queueSize),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				// Pre-allocate 512-byte buffer for DNS messages
				b := make([]byte, 0, 512)
				return &b
			},
		},
		stopChan: make(chan struct{}),
	}

	// Start worker goroutines
	pool.Start()

	return pool
}

// Start launches the worker goroutines
func (p *DnsWorkerPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.workerLoop(i)
	}

	log.Infof("DNS worker pool started with %d workers", p.workers)
}

// workerLoop is the main processing loop for each worker
func (p *DnsWorkerPool) workerLoop(workerID int) {
	defer p.wg.Done()

	// Each worker gets its own buffer from the pool
	bufPtr := p.bufferPool.Get().(*[]byte)
	defer p.bufferPool.Put(bufPtr)

	log.Debugf("DNS worker %d started", workerID)

	for {
		select {
		case task := <-p.taskQueue:
			if task == nil {
				// Poison pill - stop this worker
				log.Debugf("DNS worker %d stopping", workerID)
				return
			}

			// Increment active task counter
			atomic.AddInt64(&p.activeTasks, 1)
			defer atomic.AddInt64(&p.activeTasks, -1)

			// Process the DNS request
			p.processTask(task, workerID)

		case <-p.stopChan:
			log.Debugf("DNS worker %d received stop signal", workerID)
			return
		}
	}
}

// processTask handles a single DNS task
func (p *DnsWorkerPool) processTask(task *DnsTask, workerID int) {
	startTime := time.Now()

	// Get the controller from the request (stored in task.req)
	controller := task.req.controller

	// Process the DNS request using the controller's processDnsRequest method
	// This method handles all the logic including error handling and response building
	controller.processDnsRequest(task.msg, task.req, task.queryInfo, task.msg.Id)

	// Signal that processing is complete
	close(task.done)

	elapsed := time.Since(startTime)
	if log.IsLevelEnabled(log.TraceLevel) {
		log.WithFields(log.Fields{
			"worker":  workerID,
			"qname":   task.queryInfo.qname,
			"qtype":   task.queryInfo.qtype,
			"elapsed": elapsed,
		}).Tracef("DNS worker processed request")
	}
}

// Submit adds a new task to the worker pool queue
// Returns false if the queue is full or the pool has been stopped
func (p *DnsWorkerPool) Submit(task *DnsTask) bool {
	// Check if the pool has been stopped
	if p.stopped.Load() {
		log.Warnf("DNS worker pool is stopped, rejecting task")
		return false
	}

	select {
	case p.taskQueue <- task:
		return true
	default:
		// Queue is full
		atomic.AddInt64(&p.activeTasks, 1)
		log.Warnf("DNS worker pool queue is full (active tasks: %d)", atomic.LoadInt64(&p.activeTasks))
		return false
	}
}

// SubmitWithTimeout adds a new task to the worker pool queue with a timeout
func (p *DnsWorkerPool) SubmitWithTimeout(task *DnsTask, timeout time.Duration) bool {
	select {
	case p.taskQueue <- task:
		return true
	case <-time.After(timeout):
		log.Warnf("DNS worker pool submit timeout after %v", timeout)
		return false
	}
}

// Stop gracefully shuts down the worker pool
// This method is idempotent and can be called multiple times safely
func (p *DnsWorkerPool) Stop() {
	p.stopOnce.Do(func() {
		log.Info("Stopping DNS worker pool...")

		// Mark as stopped before closing channels
		p.stopped.Store(true)

		// Send stop signal to all workers
		close(p.stopChan)

		// Wait for all workers to finish
		p.wg.Wait()

		// Close the task queue
		close(p.taskQueue)

		log.Info("DNS worker pool stopped")
	})
}

// Stats returns statistics about the worker pool
func (p *DnsWorkerPool) Stats() (activeTasks int64, queueLen int) {
	return atomic.LoadInt64(&p.activeTasks), len(p.taskQueue)
}

// GetBuffer retrieves a buffer from the pool
func (p *DnsWorkerPool) GetBuffer() *[]byte {
	return p.bufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool
func (p *DnsWorkerPool) PutBuffer(buf *[]byte) {
	p.bufferPool.Put(buf)
}
