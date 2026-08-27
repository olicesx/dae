/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"golang.org/x/sys/unix"
)

const (
	janitorBatchLookupSize = 1024
	janitorDeleteInitCap   = 256
	janitorDeleteRetainMax = 8192
)

func ensureJanitorLookupScratch[T any](buf []T) []T {
	if cap(buf) < janitorBatchLookupSize {
		return make([]T, janitorBatchLookupSize)
	}
	return buf[:janitorBatchLookupSize]
}

func takeJanitorDeleteScratch[T any](buf []T) []T {
	if cap(buf) < janitorDeleteInitCap {
		return make([]T, 0, janitorDeleteInitCap)
	}
	return buf[:0]
}

func keepJanitorDeleteScratch[T any](buf []T) []T {
	if cap(buf) > janitorDeleteRetainMax {
		return make([]T, 0, janitorDeleteInitCap)
	}
	return buf[:0]
}

var (
	// UDP connection state timeout constants (matching former bpf_timer values).
	// DNS connections are shorter-lived since they're typically query/response.
	udpConnStateTimeoutDNS = 17 * time.Second

	// DNS port in network byte order for connection state cleanup.
	// Precomputed to avoid repeated Htons() calls during janitor iterations.
	dnsPortNetworkOrder = common.Htons(53)
	// connStateJanitorPressureInterval is the fast-path scan interval used
	// while the connection-state maps are under pressure (overflow or high
	// usage).
	connStateJanitorPressureInterval = 1 * time.Second
	// connStateJanitorMaxInterval caps the poll backoff when the maps are
	// calm. Kernel overflow events still wake the janitor immediately, so
	// the relaxed cadence only delays the periodic non-event cleanups.
	connStateJanitorMaxInterval = 30 * time.Second
	// connStateJanitorSteadyInterval is the default scan interval for steady
	// state. This keeps cleanup prompt without paying a full-table cost every
	// second when map pressure is low.
	connStateJanitorSteadyInterval = 5 * time.Second
	// connStateJanitorPressureEnterUsage is the usage percentage that activates
	// pressure mode for connection-state cleanup.
	connStateJanitorPressureEnterUsage = 70
	// connStateJanitorPressureExitUsage is the usage percentage below which the
	// janitor starts counting down to leave pressure mode.
	connStateJanitorPressureExitUsage = 50
	// connStateJanitorPressureExitRounds is the number of consecutive low-usage
	// cleanup rounds required before leaving pressure mode.
	connStateJanitorPressureExitRounds = 3

	// TCP ACTIVE state has no age timeout because an idle socket can remain valid
	// indefinitely. FIN/RST transitions state to CLOSING for prompt cleanup.
	tcpConnStateTimeoutClosing = 10 * time.Second
)

type mapCleanupStats struct {
	entries      int
	deleted      int
	usagePercent int
	maxEntries   int
}

type connStateJanitorPressureState struct {
	active               bool
	belowThresholdRounds int
	lastUdpOverflow      uint64
	lastTcpOverflow      uint64
}

func updateConnStateJanitorPressure(
	state connStateJanitorPressureState,
	overflowDelta bool,
	maxUsagePercent int,
) connStateJanitorPressureState {
	if overflowDelta || maxUsagePercent >= connStateJanitorPressureEnterUsage {
		state.active = true
		state.belowThresholdRounds = 0
		return state
	}
	if !state.active {
		return state
	}
	if maxUsagePercent < connStateJanitorPressureExitUsage {
		state.belowThresholdRounds++
		if state.belowThresholdRounds >= connStateJanitorPressureExitRounds {
			state.active = false
			state.belowThresholdRounds = 0
		}
		return state
	}
	state.belowThresholdRounds = 0
	return state
}

// startConnStateJanitor launches a background goroutine that periodically cleans up
// UDP and TCP connection state entries from the eBPF maps. This replaces the
// former bpf_timer-based automatic cleanup, providing better hot path performance
// and avoiding CVE-2024-41045.
func (c *ControlPlane) startConnStateJanitor() {
	if c == nil || !c.connStateJanitorStarted.CompareAndSwap(false, true) {
		return
	}
	go func() {
		interval := connStateJanitorPressureInterval
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(c.connStateJanitorDone)

		// Overflow events from the kernel ringbuf wake the janitor
		// immediately instead of waiting for the next poll round.
		overflowEvent := make(chan struct{}, 4)
		c.startEventRingbufReader(overflowEvent)

		var (
			lastConnCleanup      time.Time
			lastRedirectCleanup  time.Time
			lastCookiePidCleanup time.Time
			lastRoutingHandoff   time.Time
			lastHealthCheck      time.Time
			pressureState        connStateJanitorPressureState
		)

		runJanitorRound := func(now time.Time, overflowHint bool) {
			bpf := c.currentBpf()

			var udpOverflow, tcpOverflow uint64
			overflowDelta := overflowHint
			if bpf != nil && bpf.BpfStatsMap != nil {
				udpOverflow, tcpOverflow = c.readMapOverflowCounters(bpf.BpfStatsMap)
				if !overflowDelta {
					overflowDelta = udpOverflow > pressureState.lastUdpOverflow ||
						tcpOverflow > pressureState.lastTcpOverflow
				}
				pressureState.lastUdpOverflow = udpOverflow
				pressureState.lastTcpOverflow = tcpOverflow
			}
			if overflowDelta {
				pressureState.active = true
				pressureState.belowThresholdRounds = 0
			}

			connCleanupInterval := connStateJanitorSteadyInterval
			redirectCleanupInterval := redirectTrackJanitorSteadyInterval
			if pressureState.active {
				connCleanupInterval = connStateJanitorPressureInterval
				redirectCleanupInterval = redirectTrackJanitorPressureInterval
			}

			cleaned := 0
			mapEntries := 0
			if lastRedirectCleanup.IsZero() || now.Sub(lastRedirectCleanup) >= redirectCleanupInterval {
				cleaned += c.cleanupRedirectTrackMap()
				lastRedirectCleanup = now
			}
			if lastCookiePidCleanup.IsZero() || now.Sub(lastCookiePidCleanup) >= redirectCleanupInterval {
				cleaned += c.cleanupCookiePidMap()
				lastCookiePidCleanup = now
			}
			routingHandoffInterval := routingHandoffSteadyInterval
			if pressureState.active {
				routingHandoffInterval = routingHandoffPressureInterval
			}
			if lastRoutingHandoff.IsZero() || now.Sub(lastRoutingHandoff) >= routingHandoffInterval {
				cleaned += c.cleanupRoutingHandoffMap()
				lastRoutingHandoff = now
			}

			if lastConnCleanup.IsZero() || now.Sub(lastConnCleanup) >= connCleanupInterval {
				udpStats, tcpStats := c.cleanupConnStateMap(pressureState.active)
				mapEntries = udpStats.entries + tcpStats.entries

				maxUsagePercent := 0
				if udpStats.maxEntries > 0 {
					maxUsagePercent = (udpStats.entries + tcpStats.entries) * 100 / udpStats.maxEntries
				}
				pressureState = updateConnStateJanitorPressure(pressureState, overflowDelta, maxUsagePercent)
				lastConnCleanup = now
				cleaned += udpStats.deleted + tcpStats.deleted
			}

			if lastHealthCheck.IsZero() || now.Sub(lastHealthCheck) >= 5*time.Second {
				c.checkBpfMapHealth(udpOverflow, tcpOverflow)
				lastHealthCheck = now
			}

			// Back off the poll cadence only while the maps are empty and
			// calm. Any live entries, cleanup activity, or overflow event
			// keeps the fast cadence; the relaxed poll only covers a fully
			// idle datapath (and serves as a fallback if ringbuf events are
			// lost).
			if pressureState.active || cleaned > 0 || overflowHint || mapEntries > 0 {
				interval = connStateJanitorPressureInterval
			} else if interval < connStateJanitorMaxInterval {
				interval *= 2
				if interval > connStateJanitorMaxInterval {
					interval = connStateJanitorMaxInterval
				}
			}
			ticker.Reset(interval)
		}

		for {
			select {
			case <-c.connStateJanitorStop:
				return
			case <-c.ctx.Done():
				return
			case <-overflowEvent:
				runJanitorRound(time.Now(), true)
			case now := <-ticker.C:
				runJanitorRound(now, false)
			}
		}
	}()
}

// stopConnStateJanitor signals the conn state janitor to stop and waits
// for it to exit gracefully.
func (c *ControlPlane) stopConnStateJanitor() {
	if c == nil || !c.connStateJanitorStarted.Load() {
		return
	}
	c.connStateJanitorOnce.Do(func() {
		if c.connStateJanitorStop != nil {
			close(c.connStateJanitorStop)
		}
		// Wake the ringbuf reader goroutine blocked in ReadInto so the
		// janitor (which waits on connStateJanitorDone) is not held up by a
		// reader that never observes the stop signal on its own.
		if r := c.connEventReader.Load(); r != nil {
			_ = r.Close()
		}
		if c.connStateJanitorDone != nil {
			timer := time.NewTimer(gracefulShutdownWaitTimeout)
			defer timer.Stop()
			select {
			case <-c.connStateJanitorDone:
			case <-timer.C:
				c.log.Warn("stopConnStateJanitor: timeout waiting for janitor to exit")
			}
		}
	})
}

// cleanupConnStateMap performs a single-pass scan of ConnStateMap, classifying
// entries by L4 protocol and applying protocol-specific timeout/expiry logic.
// This replaces the former separate cleanupUdpConnStateMap + cleanupTcpConnStateMap
// pair, halving the BatchLookup syscalls and ClockGettime overhead per tick.
func (c *ControlPlane) cleanupConnStateMap(aggressiveCleanup bool) (udpStats, tcpStats mapCleanupStats) {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupConnStateMapBeforeLocked(aggressiveCleanup, 0)
}

// cleanupConnStateMapBeforeLocked scans ConnStateMap under connStateCleanupMu.
// aggressiveCleanup halves the protocol TTLs under map pressure. A nonzero
// staleBeforeNs (monotonic reload-request timestamp) additionally retires
// entries not refreshed since the retired generation; pinned entries are
// exempt via the pin snapshots and the scan-to-delete recheck below.
func (c *ControlPlane) cleanupConnStateMapBeforeLocked(aggressiveCleanup bool, staleBeforeNs uint64) (udpStats, tcpStats mapCleanupStats) {
	select {
	case <-c.connStateJanitorStop:
		return
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.ConnStateMap == nil {
		return
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupConnStateMap: failed to get monotonic time: %v", err)
		return
	}
	nowNano := ts.Nano()

	dnsTimeoutNano := udpConnStateTimeoutDNS.Nanoseconds()
	normalTimeoutNano := QuicNatTimeout.Nanoseconds()
	aggressiveTimeout := normalTimeoutNano / 2
	aggressiveDnsTimeout := dnsTimeoutNano / 2

	closingTimeoutNano := tcpConnStateTimeoutClosing.Nanoseconds()
	aggressiveClosingTimeout := closingTimeoutNano / 2

	scratch := c.connStateJanitorScratch()
	udpKeysToDelete := takeJanitorDeleteScratch(scratch.udpDelete)
	tcpKeysToDelete := takeJanitorDeleteScratch(scratch.tcpDelete)
	keysOut := ensureJanitorLookupScratch(scratch.udpKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.udpValues)
	defer func() {
		scratch.udpDelete = keepJanitorDeleteScratch(udpKeysToDelete)
		scratch.tcpDelete = keepJanitorDeleteScratch(tcpKeysToDelete)
		scratch.udpKeys = keysOut
		scratch.udpValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	manager, _ := c.controlPlaneSessionManager()

	// Snapshot pin sets once to avoid per-entry RLock/RUnlock during the scan.
	// The final recheck at the bottom still acquires both locks for precise
	// scan-to-delete race prevention.
	pinnedUDPSnap := manager.snapshotPinnedUDP()
	pinnedTCPSnap := manager.snapshotPinnedTCP()

	for {
		count, err := bpf.ConnStateMap.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				key := keysOut[i]
				value := valuesOut[i]
				switch key.L4proto {
				case unix.IPPROTO_UDP:
					udpStats.entries++
					if _, pinned := pinnedUDPSnap[key]; pinned {
						continue
					}
					isDNS := key.Sport == dnsPortNetworkOrder || key.Dport == dnsPortNetworkOrder
					timeout := normalTimeoutNano
					if isDNS {
						timeout = dnsTimeoutNano
					}
					if aggressiveCleanup {
						if isDNS {
							timeout = aggressiveDnsTimeout
						} else {
							timeout = aggressiveTimeout
						}
					}
					age := nowNano - int64(value.LastSeenNs)
					if age > timeout ||
						(staleBeforeNs > 0 && (value.LastSeenNs == 0 || value.LastSeenNs < staleBeforeNs)) {
						udpKeysToDelete = append(udpKeysToDelete, key)
					}
				case unix.IPPROTO_TCP:
					tcpStats.entries++
					if _, pinned := pinnedTCPSnap[key]; pinned {
						continue
					}
					closingTimeout := closingTimeoutNano
					if aggressiveCleanup {
						closingTimeout = aggressiveClosingTimeout
					}
					shouldDelete := false
					if value.State == 1 {
						age := nowNano - int64(value.LastSeenNs)
						if age > closingTimeout {
							shouldDelete = true
						}
					}
					// Established TCP has no TTL here (pin-governed), so the stale
					// threshold is the only retirement path for orphaned entries.
					if !shouldDelete && staleBeforeNs > 0 &&
						(value.LastSeenNs == 0 || value.LastSeenNs < staleBeforeNs) {
						shouldDelete = true
					}
					if shouldDelete {
						tcpKeysToDelete = append(tcpKeysToDelete, key)
					}
				}
			}
		}
		if err != nil {
			if !isIgnorableBatchLookupErr(err) {
				c.log.Errorf("cleanupConnStateMap: BatchLookup error: %v", err)
			}
			break
		}
	}

	maxEntries := bpf.ConnStateMap.MaxEntries()
	if maxEntries > 0 {
		udpStats.maxEntries = int(maxEntries)
		tcpStats.maxEntries = int(maxEntries)
		udpStats.usagePercent = udpStats.entries * 100 / int(maxEntries)
		tcpStats.usagePercent = tcpStats.entries * 100 / int(maxEntries)
	}

	// Recheck pins while blocking process-owned flow adoption and release. This
	// closes the scan-to-delete race without holding the manager locks during a
	// potentially large map walk. generationsMu guards flow registration and
	// refcount mutation; pinnedUDP keeps its dedicated lock.
	if manager != nil && (len(udpKeysToDelete) > 0 || len(tcpKeysToDelete) > 0) {
		manager.generationsMu.Lock()
		manager.udpStateMu.RLock()
		defer manager.generationsMu.Unlock()
		defer manager.udpStateMu.RUnlock()

		udpPinnedFiltered := udpKeysToDelete[:0]
		for _, key := range udpKeysToDelete {
			if manager.pinnedUDP[key] == 0 {
				udpPinnedFiltered = append(udpPinnedFiltered, key)
			}
		}
		udpKeysToDelete = udpPinnedFiltered

		tcpPinnedFiltered := tcpKeysToDelete[:0]
		for _, key := range tcpKeysToDelete {
			shard := &manager.pinnedShards[tuplesShardIndex(&key)]
			shard.mu.Lock()
			refs := shard.keys[key]
			shard.mu.Unlock()
			if refs == 0 {
				tcpPinnedFiltered = append(tcpPinnedFiltered, key)
			}
		}
		tcpKeysToDelete = tcpPinnedFiltered
	}

	if len(udpKeysToDelete) > 0 {
		if _, err := BpfMapBatchDelete(bpf.ConnStateMap, udpKeysToDelete); err != nil {
			c.log.Debugf("cleanupConnStateMap: UDP batch delete error: %v", err)
		}
	}
	udpStats.deleted = len(udpKeysToDelete)

	if len(tcpKeysToDelete) > 0 {
		if _, err := BpfMapBatchDelete(bpf.ConnStateMap, tcpKeysToDelete); err != nil {
			c.log.Debugf("cleanupConnStateMap: TCP batch delete error: %v", err)
		}
	}
	tcpStats.deleted = len(tcpKeysToDelete)

	if len(udpKeysToDelete) > 0 {
		if aggressiveCleanup {
			c.log.Debugf("cleanupConnStateMap: aggressive cleanup removed %d UDP entries (%d%% usage)",
				len(udpKeysToDelete), udpStats.usagePercent)
		} else {
			c.log.Debugf("cleanupConnStateMap: removed %d expired UDP entries", len(udpKeysToDelete))
		}
	}
	if len(tcpKeysToDelete) > 0 {
		if aggressiveCleanup {
			c.log.Debugf("cleanupConnStateMap: aggressive cleanup removed %d TCP entries (%d%% usage)",
				len(tcpKeysToDelete), tcpStats.usagePercent)
		} else {
			c.log.Debugf("cleanupConnStateMap: removed %d expired TCP entries", len(tcpKeysToDelete))
		}
	}

	return udpStats, tcpStats
}

func (c *ControlPlane) connStateJanitorScratch() *connStateJanitorScratch {
	if c == nil {
		return nil
	}
	return c.scratch()
}
