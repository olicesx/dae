/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRuntimeDNSLogCapacityPreservesRecordIDs(t *testing.T) {
	controller := newTestDnsController()
	controller.SetDNSLogCapacity(4)
	question := dnsmessage.Question{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET}
	for i := 1; i <= 6; i++ {
		controller.recordDnsLog(question, nil, strconv.Itoa(i), false, "", nil, time.Time{})
	}
	controller.SetDNSLogCapacity(2)
	rows := controller.DnsLogRecords()
	require.Len(t, rows, 2)
	require.Equal(t, "dl_5", rows[0].ID)
	require.Equal(t, "dl_6", rows[1].ID)
	controller.SetDNSLogCapacity(4)
	controller.recordDnsLog(question, nil, "NOERROR", false, "", nil, time.Time{})
	rows = controller.DnsLogRecords()
	require.Len(t, rows, 3)
	require.Equal(t, "dl_7", rows[2].ID)
}

func TestRuntimeFlowHistoryIncreaseDoesNotReviveExpiredRows(t *testing.T) {
	manager := &SessionManager{}
	manager.SetFlowHistoryLimits(64, time.Second)
	manager.appendFlowHistory(SessionFlowSnapshot{ID: "expired"}, time.Now().Add(-2*time.Second))
	manager.SetFlowHistoryLimits(64, time.Minute)
	rows, revision := manager.FlowHistorySnapshots()
	require.Empty(t, rows)
	require.EqualValues(t, 1, revision)
}

func TestRuntimeFlowHistoryLimitsPreserveRevisions(t *testing.T) {
	manager := &SessionManager{}
	now := time.Now()
	manager.SetFlowHistoryLimits(4, time.Minute)
	for i := 1; i <= 6; i++ {
		manager.appendFlowHistory(SessionFlowSnapshot{ID: strconv.Itoa(i)}, now.Add(time.Duration(i-6)*time.Second))
	}
	manager.SetFlowHistoryLimits(2, time.Minute)
	rows, revision := manager.FlowHistorySnapshots()
	require.Len(t, rows, 2)
	require.EqualValues(t, 5, rows[0].Revision)
	require.EqualValues(t, 6, rows[1].Revision)
	require.EqualValues(t, 6, revision)
	manager.SetFlowHistoryLimits(4, time.Nanosecond)
	rows, revision = manager.FlowHistorySnapshots()
	require.Empty(t, rows)
	require.EqualValues(t, 6, revision)
}
