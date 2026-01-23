/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"runtime"
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
	priority  int           // Task priority (0 = highest, higher = lower)
}

// DnsWorkerPool manages a pool of goroutines with work stealing scheduler
// and dynamic scaling based on queue length
type DnsWorkerPool struct {
	workers            int             // Current number of worker goroutines
	minWorkers         int             // Minimum number of workers
	maxWorkers         int             // Maximum number of workers
	workerQueues       []chan *DnsTask // Each worker has its own queue
	workerQueuesMu     sync.RWMutex    // Protects workerQueues slice
	bufferPool         *sync.Pool      // Pre-allocated buffers for each worker
	stopChan           chan struct{}   // Stop signal
	stopOnce           sync.Once       // Ensures Stop() is idempotent
	stopped            atomic.Bool     // Tracks if the pool has been stopped
	wg                 sync.WaitGroup  // WaitGroup for worker goroutines
	activeTasks        atomic.Int64    // Counter for active tasks (for metrics)
	stealCount         atomic.Int64    // Counter for work stealing operations
	queueSize          int             // Size of each worker's queue
	scaleTicker        *time.Ticker    // Ticker for scaling checks
	scaleDone          chan struct{}   // Channel to stop scaling goroutine
	lastScaleTime      time.Time       // Last time scaling was performed
	scaleCooldown      time.Duration   // Minimum time between scaling operations
	scaleUpThreshold   float64         // Queue fill ratio to trigger scale up (0.8 = 80%)
	scaleDownThreshold float64         // Queue fill ratio to trigger scale down (0.2 = 20%)
}

// OptimalWorkerCount calculates the optimal number of workers based on CPU cores
// Formula: min(GOMAXPROCS * 2, 32) with special considerations for DNS workload
//
// Rationale:
// 1. DNS queries are I/O bound (network latency), not CPU bound
// 2. Each worker spends most time waiting for network response
// 3. Can safely oversubscribe CPUs (2x GOMAXPROCS is a good starting point)
// 4. Cap at 32 to avoid excessive context switching overhead
//
// Examples:
// - 4 cores: 8 workers (4 * 2)
// - 8 cores: 16 workers (8 * 2)
// - 16 cores: 32 workers (16 * 2, capped)
// - 32+ cores: 32 workers (capped)
func OptimalWorkerCount() int {
	numCPU := runtime.GOMAXPROCS(0)

	// For I/O bound workloads like DNS, we can use 2x CPU cores
	workers := numCPU * 2

	// Cap at reasonable maximum to avoid excessive overhead
	if workers > 32 {
		workers = 32
	}

	// Minimum of 4 workers for even small systems
	if workers < 4 {
		workers = 4
	}

	return workers
}

// NewDnsWorkerPool creates a new DNS worker pool with work stealing scheduler
// and dynamic scaling based on queue length
// queueSize: size of each worker's queue (default: 256 per worker)
func NewDnsWorkerPool(queueSize int) *DnsWorkerPool {
	workers := OptimalWorkerCount()
	minWorkers := workers / 2 // Minimum: 50% of optimal
	maxWorkers := workers * 2 // Maximum: 200% of optimal
	if minWorkers < 2 {
		minWorkers = 2
	}
	if maxWorkers > 64 {
		maxWorkers = 64
	}

	if queueSize <= 0 {
		// Smaller per-worker queue (256) since we have multiple queues
		// Total capacity = workers * 256
		queueSize = 256
	}

	pool := &DnsWorkerPool{
		workers:      workers,
		minWorkers:   minWorkers,
		maxWorkers:   maxWorkers,
		workerQueues: make([]chan *DnsTask, workers),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				// Pre-allocate 512-byte buffer for DNS messages
				b := make([]byte, 0, 512)
				return &b
			},
		},
		stopChan:           make(chan struct{}),
		scaleDone:          make(chan struct{}),
		queueSize:          queueSize,
		scaleCooldown:      5 * time.Second, // Wait 5s between scaling operations
		scaleUpThreshold:   0.8,             // Scale up when queues are 80% full
		scaleDownThreshold: 0.2,             // Scale down when queues are 20% full
	}

	// Initialize individual worker queues
	for i := 0; i < workers; i++ {
		pool.workerQueues[i] = make(chan *DnsTask, queueSize)
	}

	// Start worker goroutines
	pool.Start()

	// Start auto-scaling goroutine
	pool.startScaling()

	log.Infof("DNS worker pool started with %d workers (work stealing + auto-scaling), %d queue size per worker",
		workers, queueSize)
	log.Infof("Auto-scaling: min=%d, max=%d, scale_up_threshold=%.0f%%, scale_down_threshold=%.0f%%",
		minWorkers, maxWorkers, pool.scaleUpThreshold*100, pool.scaleDownThreshold*100)

	return pool
}

// Start launches the worker goroutines
func (p *DnsWorkerPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.workerLoop(i)
	}
}

// workerLoop is the main processing loop for each worker with work stealing
func (p *DnsWorkerPool) workerLoop(workerID int) {
	defer p.wg.Done()

	// Each worker gets its own buffer from the pool
	bufPtr := p.bufferPool.Get().(*[]byte)
	defer p.bufferPool.Put(bufPtr)

	log.Debugf("DNS worker %d started (work stealing + auto-scaling mode)", workerID)

	for {
		// Get current queues (may change due to scaling)
		p.workerQueuesMu.RLock()
		if workerID >= len(p.workerQueues) {
			// This worker was removed, exit
			p.workerQueuesMu.RUnlock()
			log.Debugf("DNS worker %d removed by scaling", workerID)
			return
		}
		myQueue := p.workerQueues[workerID]
		numWorkers := len(p.workerQueues)
		p.workerQueuesMu.RUnlock()

		// Build steal order (avoid own queue)
		stealOrder := make([]int, 0, numWorkers-1)
		for i := 0; i < numWorkers; i++ {
			if i != workerID {
				stealOrder = append(stealOrder, i)
			}
		}

		// Step 1: Try to get task from own queue
		select {
		case task := <-myQueue:
			if task == nil {
				// Poison pill - stop this worker
				log.Debugf("DNS worker %d stopping (poison pill)", workerID)
				return
			}
			p.processTask(task, workerID)
			continue
		case <-p.stopChan:
			log.Debugf("DNS worker %d received stop signal", workerID)
			return
		default:
			// Own queue is empty, try to steal from others
		}

		// Step 2: Try to steal from other workers' queues
		stolen := false
		p.workerQueuesMu.RLock()
		for _, targetID := range stealOrder {
			if targetID >= len(p.workerQueues) {
				continue
			}
			select {
			case task := <-p.workerQueues[targetID]:
				p.workerQueuesMu.RUnlock()
				if task == nil {
					// Poison pill
					return
				}
				// Successfully stolen task
				p.stealCount.Add(1)
				p.processTask(task, workerID)
				stolen = true
				break
			default:
				// Target queue is also empty, try next
				continue
			}
		}
		if !stolen {
			p.workerQueuesMu.RUnlock()
		}

		// Step 3: If no task to steal, wait briefly for new task
		if !stolen {
			select {
			case task := <-myQueue:
				if task == nil {
					return
				}
				p.processTask(task, workerID)
			case <-p.stopChan:
				return
			case <-time.After(10 * time.Millisecond):
				// Timeout, loop again to check for new tasks
				continue
			}
		}
	}
}

// processTask handles a single DNS task
func (p *DnsWorkerPool) processTask(task *DnsTask, workerID int) {
	p.activeTasks.Add(1)
	defer p.activeTasks.Add(-1)

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

// Submit adds a new task to the worker pool
// Uses round-robin to distribute tasks across workers
// Returns false if all queues are full or the pool has been stopped
func (p *DnsWorkerPool) Submit(task *DnsTask) bool {
	// Check if the pool has been stopped
	if p.stopped.Load() {
		log.Warnf("DNS worker pool is stopped, rejecting task")
		return false
	}

	// Use atomic counter for round-robin distribution
	// This ensures fair distribution across all workers
	submitCount := p.activeTasks.Add(1)
	workerID := int(submitCount) % p.workers

	// Try to submit to selected worker's queue
	p.workerQueuesMu.RLock()
	queues := p.workerQueues
	p.workerQueuesMu.RUnlock()

	select {
	case queues[workerID] <- task:
		return true
	default:
		// Selected worker's queue is full, try other workers
		for i := 0; i < len(queues); i++ {
			if i == workerID {
				continue
			}
			select {
			case queues[i] <- task:
				return true
			default:
				continue
			}
		}
		// All queues are full
		log.Warnf("DNS worker pool all queues full (active tasks: %d)", p.activeTasks.Load())
		return false
	}
}

// SubmitWithTimeout adds a new task to the worker pool with a timeout
func (p *DnsWorkerPool) SubmitWithTimeout(task *DnsTask, timeout time.Duration) bool {
	if p.stopped.Load() {
		return false
	}

	submitCount := p.activeTasks.Add(1)
	workerID := int(submitCount) % p.workers

	p.workerQueuesMu.RLock()
	queues := p.workerQueues
	p.workerQueuesMu.RUnlock()

	select {
	case queues[workerID] <- task:
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

		// Stop auto-scaling goroutine
		close(p.scaleDone)

		// Send poison pill to all workers
		p.workerQueuesMu.Lock()
		for i := 0; i < len(p.workerQueues); i++ {
			close(p.workerQueues[i])
		}
		p.workerQueuesMu.Unlock()

		// Send stop signal
		close(p.stopChan)

		// Wait for all workers to finish
		p.wg.Wait()

		log.Info("DNS worker pool stopped")
	})
}

// Stats returns statistics about the worker pool
func (p *DnsWorkerPool) Stats() (activeTasks int64, stealCount int64, queueLens []int, workers int, minWorkers int, maxWorkers int) {
	activeTasks = p.activeTasks.Load()
	stealCount = p.stealCount.Load()

	p.workerQueuesMu.RLock()
	workers = len(p.workerQueues)
	queueLens = make([]int, workers)
	for i := 0; i < workers; i++ {
		queueLens[i] = len(p.workerQueues[i])
	}
	p.workerQueuesMu.RUnlock()

	minWorkers = p.minWorkers
	maxWorkers = p.maxWorkers

	return
}

// startScaling launches the auto-scaling goroutine
func (p *DnsWorkerPool) startScaling() {
	p.scaleTicker = time.NewTicker(1 * time.Second)
	p.wg.Add(1)

	go func() {
		defer p.wg.Done()
		defer p.scaleTicker.Stop()

		for {
			select {
			case <-p.scaleTicker.C:
				p.checkAndScale()
			case <-p.scaleDone:
				return
			case <-p.stopChan:
				return
			}
		}
	}()
}

// checkAndScale checks queue lengths and scales workers up or down
func (p *DnsWorkerPool) checkAndScale() {
	// Don't scale too frequently
	if time.Since(p.lastScaleTime) < p.scaleCooldown {
		return
	}

	p.workerQueuesMu.RLock()
	currentWorkers := len(p.workerQueues)
	p.workerQueuesMu.RUnlock()

	// Calculate average queue fill ratio
	totalQueueLen := 0
	totalQueueCap := currentWorkers * p.queueSize

	p.workerQueuesMu.RLock()
	for i := 0; i < currentWorkers; i++ {
		totalQueueLen += len(p.workerQueues[i])
	}
	p.workerQueuesMu.RUnlock()

	fillRatio := float64(totalQueueLen) / float64(totalQueueCap)

	// Scale up if queues are too full
	if fillRatio > p.scaleUpThreshold && currentWorkers < p.maxWorkers {
		newWorkers := currentWorkers + 1
		log.Infof("Scaling up worker pool: %d -> %d (fill ratio: %.2f%%)",
			currentWorkers, newWorkers, fillRatio*100)
		p.addWorker(newWorkers - 1)
		p.lastScaleTime = time.Now()
		return
	}

	// Scale down if queues are mostly empty
	if fillRatio < p.scaleDownThreshold && currentWorkers > p.minWorkers {
		newWorkers := currentWorkers - 1
		log.Infof("Scaling down worker pool: %d -> %d (fill ratio: %.2f%%)",
			currentWorkers, newWorkers, fillRatio*100)
		p.removeWorker(currentWorkers - 1)
		p.lastScaleTime = time.Now()
		return
	}
}

// addWorker adds a new worker to the pool
func (p *DnsWorkerPool) addWorker(workerID int) {
	p.workerQueuesMu.Lock()
	defer p.workerQueuesMu.Unlock()

	// Create new queue for this worker
	newQueue := make(chan *DnsTask, p.queueSize)
	p.workerQueues = append(p.workerQueues, newQueue)

	// Start the worker goroutine
	p.wg.Add(1)
	go p.workerLoop(workerID)

	p.workers = len(p.workerQueues)
}

// removeWorker removes a worker from the pool
func (p *DnsWorkerPool) removeWorker(workerID int) {
	p.workerQueuesMu.Lock()
	defer p.workerQueuesMu.Unlock()

	if len(p.workerQueues) <= p.minWorkers {
		return
	}

	// Send poison pill to the worker
	close(p.workerQueues[workerID])

	// Remove the worker's queue from the slice
	p.workerQueues = append(p.workerQueues[:workerID], p.workerQueues[workerID+1:]...)

	p.workers = len(p.workerQueues)
}
