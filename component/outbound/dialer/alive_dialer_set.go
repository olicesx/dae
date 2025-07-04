/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
)

const (
	Init = 1 + iota
	NotAlive
)

type minLatency struct {
	sortingLatency time.Duration
	priority       int
	dialer         *Dialer
}

// AliveDialerSet assumes mapping between index and dialer MUST remain unchanged.
//
// It is thread-safe.
type AliveDialerSet struct {
	log             *logrus.Logger
	dialerGroupName string
	networkType     *NetworkType
	tolerance       time.Duration

	aliveChangeCallback func(alive bool, networkType *NetworkType)

	mu                      sync.Mutex
	dialerToIndex           map[*Dialer]int // *Dialer -> index of inorderedAliveDialerSet
	dialerToLatency         map[*Dialer]time.Duration
	dialerToLatencyOffset   map[*Dialer]time.Duration
	dialerToPriority        map[*Dialer]int
	inorderedAliveDialerSet []*Dialer

	selectionPolicy DialerSelectionPolicy
	minLatency      minLatency

	fixedDialer *Dialer

	alive bool
}

func NewAliveDialerSet(
	log *logrus.Logger,
	dialerGroupName string,
	networkType *NetworkType,
	tolerance time.Duration,
	selectionPolicy DialerSelectionPolicy,
	dialers []*Dialer,
	dialersAnnotations []*Annotation,
	aliveChangeCallback func(alive bool, networkType *NetworkType),
) *AliveDialerSet {
	if len(dialers) != len(dialersAnnotations) {
		panic(fmt.Sprintf("unmatched annotations length: %v dialers and %v annotations", len(dialers), len(dialersAnnotations)))
	}
	a := &AliveDialerSet{
		log:                     log,
		dialerGroupName:         dialerGroupName,
		networkType:             networkType,
		tolerance:               tolerance,
		aliveChangeCallback:     aliveChangeCallback,
		dialerToIndex:           make(map[*Dialer]int),
		dialerToPriority:        make(map[*Dialer]int),
		dialerToLatency:         make(map[*Dialer]time.Duration),
		dialerToLatencyOffset:   make(map[*Dialer]time.Duration),
		inorderedAliveDialerSet: make([]*Dialer, 0, len(dialers)),
		selectionPolicy:         selectionPolicy,
		minLatency: minLatency{
			sortingLatency: time.Hour,
		},
	}
	for i, d := range dialers {
		a.dialerToIndex[d] = -Init
		a.dialerToPriority[d] = dialersAnnotations[i].Priority
		a.dialerToLatencyOffset[d] = dialersAnnotations[i].AddLatency
	}
	if selectionPolicy.Policy == consts.DialerSelectionPolicy_Fixed {
		a.fixedDialer = dialers[selectionPolicy.FixedIndex]
	}
	return a
}

func (a *AliveDialerSet) getHighestPriorityDialers() []*Dialer {
	if len(a.inorderedAliveDialerSet) == 0 {
		return nil
	}

	highestPriority := math.MinInt
	for _, d := range a.inorderedAliveDialerSet {
		if priority := a.GetPriority(d); priority > highestPriority {
			highestPriority = priority
		}
	}

	var highPriorityDialers []*Dialer
	for _, d := range a.inorderedAliveDialerSet {
		if a.GetPriority(d) == highestPriority {
			highPriorityDialers = append(highPriorityDialers, d)
		}
	}
	return highPriorityDialers
}

func (a *AliveDialerSet) GetRand() *Dialer {
	a.mu.Lock()
	defer a.mu.Unlock()

	highPriorityDialers := a.getHighestPriorityDialers()
	if len(highPriorityDialers) == 0 {
		return nil
	}
	return highPriorityDialers[rand.Intn(len(highPriorityDialers))]
}

func (a *AliveDialerSet) GetSortingLatency(d *Dialer) time.Duration {
	return a.dialerToLatency[d] + a.dialerToLatencyOffset[d]
}

func (a *AliveDialerSet) GetPriority(d *Dialer) int {
	return a.dialerToPriority[d]
}

func (a *AliveDialerSet) GetMinLatency() (d *Dialer, latency time.Duration) {
	return a.minLatency.dialer, a.minLatency.sortingLatency
}

func (a *AliveDialerSet) setMinLatency(d *Dialer, sortingLatency time.Duration, priority int) {
	a.minLatency.sortingLatency = sortingLatency
	a.minLatency.priority = priority
	a.minLatency.dialer = d
}

func (a *AliveDialerSet) printLatencies() {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", a.dialerGroupName, a.networkType.String()))
	samePriority := true

	var alive []*struct {
		dialer         *Dialer
		latency        time.Duration
		offset         time.Duration
		sortingLatency time.Duration
		priority       int
	}
	for _, dialer := range a.inorderedAliveDialerSet {
		latency, ok := a.dialerToLatency[dialer]
		if !ok {
			continue
		}
		offset := a.dialerToLatencyOffset[dialer]
		priority := a.GetPriority(dialer)
		if len(alive) > 0 {
			samePriority = samePriority && priority == alive[len(alive)-1].priority
		}
		alive = append(alive, &struct {
			dialer         *Dialer
			latency        time.Duration
			offset         time.Duration
			sortingLatency time.Duration
			priority       int
		}{dialer, latency, offset, latency + offset, priority})
	}
	sort.SliceStable(alive, func(i, j int) bool {
		// First sort by priority (higher priority first)
		if alive[i].priority != alive[j].priority {
			return alive[i].priority > alive[j].priority
		}
		// Then sort by latency (lower latency first)
		return alive[i].sortingLatency < alive[j].sortingLatency
	})
	for i, dialer := range alive {
		priorityStr := ""
		if !samePriority {
			priorityStr = fmt.Sprintf(" (priority: %d)", dialer.priority)
		}
		tagStr := ""
		if dialer.dialer.property.SubscriptionTag != "" {
			tagStr = fmt.Sprintf(" [%v]", dialer.dialer.property.SubscriptionTag)
		}
		builder.WriteString(fmt.Sprintf("%4d.%v %v: %v%s\n", i+1, tagStr, dialer.dialer.property.Name, latencyString(dialer.latency, dialer.offset), priorityStr))
	}
	// TODO: Log level?
	a.log.Warnln(strings.TrimSuffix(builder.String(), "\n"))
}

// latencyData 包含延迟相关的数据
type latencyData struct {
	rawLatency time.Duration
	minPolicy  bool
}

// getLatencyData 根据选择策略获取延迟数据
func (a *AliveDialerSet) getLatencyData(dialer *Dialer, networkType *NetworkType) (data latencyData, hasLatency bool) {
	switch a.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		data.rawLatency, hasLatency = dialer.mustGetCollection(networkType).Latencies10.LastLatency()
		data.minPolicy = true
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		data.rawLatency, hasLatency = dialer.mustGetCollection(networkType).Latencies10.AvgLatency()
		data.minPolicy = true
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		data.rawLatency = dialer.mustGetCollection(networkType).MovingAverage
		hasLatency = data.rawLatency > 0
		data.minPolicy = true
	}
	return
}

func (a *AliveDialerSet) updateDialerAliveState(dialer *Dialer, alive bool) {
	if alive {
		a.addAliveDialer(dialer)
	} else if !alive {
		a.removeAliveDialer(dialer)
	}
}

func (a *AliveDialerSet) addAliveDialer(dialer *Dialer) {
	index := a.dialerToIndex[dialer]
	if index >= 0 {
		return
	}

	if index != -Init {
		a.log.WithFields(logrus.Fields{
			"dialer": dialer.property.Name,
			"group":  a.dialerGroupName,
		}).Warnf("[NOT ALIVE --%v-> ALIVE]", a.networkType.String())
	}

	a.dialerToIndex[dialer] = len(a.inorderedAliveDialerSet)
	a.inorderedAliveDialerSet = append(a.inorderedAliveDialerSet, dialer)
}

func (a *AliveDialerSet) removeAliveDialer(dialer *Dialer) {
	index := a.dialerToIndex[dialer]
	if index < -Init {
		return
	}

	if index == -Init {
		a.log.WithFields(logrus.Fields{
			"dialer": dialer.property.Name,
			"group":  a.dialerGroupName,
		}).Infof("[ALIVE --%v-> NOT ALIVE]", a.networkType.String())
	} else {
		a.log.WithFields(logrus.Fields{
			"dialer": dialer.property.Name,
			"group":  a.dialerGroupName,
		}).Warnf("[ALIVE --%v-> NOT ALIVE]", a.networkType.String())

		// TODO: Debug, for get which dialer still alive
		a.printLatencies()
	}

	if index >= len(a.inorderedAliveDialerSet) {
		a.log.Panicf("index:%v >= len(a.inorderedAliveDialerSet):%v", index, len(a.inorderedAliveDialerSet))
	}

	a.dialerToIndex[dialer] = -NotAlive

	if index == -Init {
		return
	}

	if index < len(a.inorderedAliveDialerSet)-1 {
		// 将该元素与最后一个元素交换
		lastDialer := a.inorderedAliveDialerSet[len(a.inorderedAliveDialerSet)-1]
		if dialer == lastDialer {
			a.log.Panicf("dialer[%p] == lastDialer[%p]", dialer, lastDialer)
		}

		a.dialerToIndex[lastDialer] = index
		a.inorderedAliveDialerSet[index], a.inorderedAliveDialerSet[len(a.inorderedAliveDialerSet)-1] =
			a.inorderedAliveDialerSet[len(a.inorderedAliveDialerSet)-1], a.inorderedAliveDialerSet[index]
	}

	// 弹出最后一个元素
	a.inorderedAliveDialerSet = a.inorderedAliveDialerSet[:len(a.inorderedAliveDialerSet)-1]
}

func (a *AliveDialerSet) shouldUpdateMinLatency(dialer *Dialer, sortingLatency time.Duration, priority int) bool {
	// no dialer is available
	if a.minLatency.dialer == nil {
		return true
	}

	// Higher priority
	if priority > a.minLatency.priority {
		return true
	} else if priority < a.minLatency.priority {
		return false
	}

	// Same priority and smaller latency
	if sortingLatency <= a.minLatency.sortingLatency-a.tolerance {
		return true
	}

	return false
}

// updateLatency should only called for alive dialer.
func (a *AliveDialerSet) updateLatency(dialer *Dialer) {
	sortingLatency := a.GetSortingLatency(dialer)
	priority := a.GetPriority(dialer)

	if a.shouldUpdateMinLatency(dialer, sortingLatency, priority) {
		a.setMinLatency(dialer, sortingLatency, priority)
	} else if a.minLatency.dialer == dialer {
		latencyIncreased := sortingLatency > a.minLatency.sortingLatency
		a.minLatency.sortingLatency = sortingLatency
		// If the latency of the current dialer increases, recalculate the minimum latency dialer.
		if latencyIncreased {
			minDialer, minLatency, highestPriority := a.calcMinLatency()
			if minLatency <= sortingLatency-a.tolerance {
				a.setMinLatency(minDialer, minLatency, highestPriority)
			}
		}
	}
}

func (a *AliveDialerSet) handleAliveStateChange(alive bool) {
	if a.alive == alive {
		return
	}

	if alive {
		a.log.WithFields(logrus.Fields{
			"group":   a.dialerGroupName,
			"network": a.networkType.String(),
		}).Infof("Group is alive")
	} else {
		a.log.WithFields(logrus.Fields{
			"group":   a.dialerGroupName,
			"network": a.networkType.String(),
		}).Infof("Group has no dialer alive")
	}
	a.alive = alive
	a.printLatencies()
	a.aliveChangeCallback(alive, a.networkType)
}

// logDialerSelection 记录拨号器选择日志
func (a *AliveDialerSet) logDialerSelection(oldBestDialer *Dialer, newBestDialer *Dialer) {
	re := "re-"
	var oldDialerName string

	if oldBestDialer == nil {
		re = ""
		oldDialerName = "<nil>"
	} else {
		oldDialerName = oldBestDialer.property.Name
	}

	if oldBestDialer == nil {
		a.log.WithFields(logrus.Fields{
			string(a.selectionPolicy.Policy): latencyString(a.dialerToLatency[a.minLatency.dialer], a.dialerToLatencyOffset[a.minLatency.dialer]),
			"_new_dialer":                    newBestDialer.property.Name,
			"_old_dialer":                    oldDialerName,
			"group":                          a.dialerGroupName,
			"network":                        a.networkType.String(),
		}).Warnf("Group %vselects dialer", re)
	} else {
		a.log.WithFields(logrus.Fields{
			string(a.selectionPolicy.Policy): latencyString(a.dialerToLatency[a.minLatency.dialer], a.dialerToLatencyOffset[a.minLatency.dialer]),
			"_new_dialer":                    newBestDialer.property.Name,
			"_old_dialer":                    oldDialerName,
			"group":                          a.dialerGroupName,
			"network":                        a.networkType.String(),
		}).Infof("Group %vselects dialer", re)
	}
}

// NotifyLatencyChange should be invoked when dialer every time latency and alive state changes.
func (a *AliveDialerSet) NotifyLatencyChange(dialer *Dialer, alive bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.updateDialerAliveState(dialer, alive)

	latencyData, hasLatency := a.getLatencyData(dialer, a.networkType)

	if latencyData.minPolicy {
		oldMinLatency := a.minLatency.dialer
		if alive {
			if hasLatency {
				a.dialerToLatency[dialer] = latencyData.rawLatency // Update latency
				a.updateLatency(dialer)                            // calculate min latency dialer
			} // TODO: else?
		} else if dialer == a.minLatency.dialer {
			minDialer, minLatency, highestPriority := a.calcMinLatency()
			a.setMinLatency(minDialer, minLatency, highestPriority)
		}
		if a.minLatency.dialer != nil && a.minLatency.dialer != oldMinLatency {
			a.logDialerSelection(oldMinLatency, a.minLatency.dialer)
		}
	}

	if a.selectionPolicy.Policy == consts.DialerSelectionPolicy_Fixed {
		if dialer == a.fixedDialer {
			a.handleAliveStateChange(alive)
		}
	} else {
		a.handleAliveStateChange(len(a.inorderedAliveDialerSet) > 0)
	}
}

// calcMinLatency return the dialer with the minimum latency and highest priority
func (a *AliveDialerSet) calcMinLatency() (dialer *Dialer, latency time.Duration, priority int) {
	var minLatency = time.Hour
	var highestPriority = math.MinInt
	var minDialer *Dialer

	for _, d := range a.inorderedAliveDialerSet {
		priority := a.GetPriority(d)
		sortingLatency := a.GetSortingLatency(d)

		switch {
		case priority > highestPriority:
		case sortingLatency < minLatency && priority == highestPriority:
			minLatency = sortingLatency
			highestPriority = priority
			minDialer = d
		}
	}

	return minDialer, minLatency, highestPriority
}
