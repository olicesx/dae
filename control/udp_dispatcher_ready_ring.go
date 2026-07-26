/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "sync"

// readyRing is the FIFO of per-key queues waiting for a dispatcher worker,
// together with the wake signal that hands one of them to an idle worker.
//
// The ordered-ingress and reply dispatchers schedule different work but share
// this structure exactly, including the two parts that are easy to get subtly
// wrong: compacting the backing slice instead of growing it without bound, and
// re-arming the wake signal when a pop leaves another queue behind. Keeping one
// implementation means a fix to either lands in both.
//
// It is generic over the queue type rather than an interface so that a pointer
// queue stays a pointer in the slice: no boxing and no dynamic dispatch on a
// per-packet path.
type readyRing[T any] struct {
	mu    sync.Mutex
	items []*T
	head  int

	// wake carries at most one pending signal per waiting worker. It is never
	// closed, because a notify may race dispatcher teardown.
	wake chan struct{}
}

func newReadyRing[T any](workers int) *readyRing[T] {
	if workers < 1 {
		workers = 1
	}
	return &readyRing[T]{wake: make(chan struct{}, workers)}
}

// push appends item and wakes one worker.
func (r *readyRing[T]) push(item *T) {
	r.mu.Lock()
	// Reclaim the consumed prefix instead of letting append grow the slice
	// forever: the ring is append-at-tail, consume-at-head, so without this the
	// backing array would keep expanding for the lifetime of the dispatcher.
	if r.head > 0 && len(r.items) == cap(r.items) {
		copy(r.items, r.items[r.head:])
		r.items = r.items[:len(r.items)-r.head]
		r.head = 0
	}
	r.items = append(r.items, item)
	r.mu.Unlock()
	r.notify()
}

// pop returns the next waiting queue, or nil when none is ready. If more queues
// remain it re-arms the wake signal, so a worker that consumes one item cannot
// leave the others parked.
func (r *readyRing[T]) pop() *T {
	r.mu.Lock()
	if r.head == len(r.items) {
		r.items = r.items[:0]
		r.head = 0
		r.mu.Unlock()
		return nil
	}
	item := r.items[r.head]
	r.items[r.head] = nil
	r.head++
	more := r.head < len(r.items)
	r.mu.Unlock()
	if more {
		r.notify()
	}
	return item
}

// notify wakes at most one idle worker. A full channel already guarantees a
// worker is about to look at the ring, so dropping the signal is correct.
func (r *readyRing[T]) notify() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// reset drops every waiting queue. Callers own draining the tasks those queues
// still hold.
func (r *readyRing[T]) reset() {
	r.mu.Lock()
	clear(r.items)
	r.items = nil
	r.head = 0
	r.mu.Unlock()
}
