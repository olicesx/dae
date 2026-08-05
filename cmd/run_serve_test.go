package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// mockRetirementPlane records retirement calls for reload drain tests.
type mockRetirementPlane struct {
	activeSessions        int
	idleCh                chan struct{}
	abortConnectionsCalls int
	abortPendingCalls     int
	stopRoutingCalls      int
}

func (m *mockRetirementPlane) ActiveSessionCount() int { return m.activeSessions }

func (m *mockRetirementPlane) DrainIdleCh() <-chan struct{} { return m.idleCh }

func (m *mockRetirementPlane) AbortConnections() error {
	m.abortConnectionsCalls++
	return nil
}

func (m *mockRetirementPlane) AbortPendingConnections() error {
	m.abortPendingCalls++
	return nil
}

func (m *mockRetirementPlane) StopRoutingEpochExecution() { m.stopRoutingCalls++ }

// TestRetireDrainIdleAbortsResidual guards against leaking relay goroutines on
// reload: the drain tracker only counts routing-epoch/ingress leases, which can
// be released before the guarded relay goroutines finish. Half-open relays
// block in Read forever, so even a "drained" generation can own stuck relays;
// retirement must close residual flows explicitly via AbortConnections.
func TestRetireDrainIdleAbortsResidual(t *testing.T) {
	plane := &mockRetirementPlane{activeSessions: 0, idleCh: make(chan struct{})}
	retireControlPlaneConnections(logrus.New(), context.Background(), plane, false, false, time.Second)
	if plane.abortConnectionsCalls != 1 {
		t.Fatalf("drain-idle retirement must call AbortConnections to close residual flows, got %d calls", plane.abortConnectionsCalls)
	}
	if plane.stopRoutingCalls != 1 {
		t.Fatalf("expected StopRoutingEpochExecution, got %d", plane.stopRoutingCalls)
	}
}

// TestRetireDrainCanceledAbortsResidual covers the retirement-canceled path:
// pending work is aborted and residual flows are still closed.
func TestRetireDrainCanceledAbortsResidual(t *testing.T) {
	plane := &mockRetirementPlane{activeSessions: 1, idleCh: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled immediately
	retireControlPlaneConnections(logrus.New(), ctx, plane, false, false, time.Second)
	if plane.abortPendingCalls != 1 {
		t.Fatalf("canceled retirement must abort pending connections, got %d", plane.abortPendingCalls)
	}
	if plane.abortConnectionsCalls != 1 {
		t.Fatalf("canceled retirement must also call AbortConnections for residual flows, got %d", plane.abortConnectionsCalls)
	}
}

// TestRetireDrainTimeoutAbortsResidual covers the drain-timeout path: pending
// work is aborted and residual flows are still closed so stuck relays exit.
func TestRetireDrainTimeoutAbortsResidual(t *testing.T) {
	plane := &mockRetirementPlane{activeSessions: 1, idleCh: make(chan struct{})} // never closes
	retireControlPlaneConnections(logrus.New(), context.Background(), plane, false, false, 50*time.Millisecond)
	if plane.abortPendingCalls != 1 {
		t.Fatalf("timeout retirement must abort pending connections, got %d", plane.abortPendingCalls)
	}
	if plane.abortConnectionsCalls != 1 {
		t.Fatalf("timeout retirement must also call AbortConnections for residual flows, got %d", plane.abortConnectionsCalls)
	}
}

// TestRetireAbortPathKeepsBehavior guards the immediate-abort path.
func TestRetireAbortPathKeepsBehavior(t *testing.T) {
	plane := &mockRetirementPlane{activeSessions: 1, idleCh: make(chan struct{})}
	retireControlPlaneConnections(logrus.New(), context.Background(), plane, true, false, time.Second)
	if plane.abortConnectionsCalls != 1 {
		t.Fatalf("abort retirement must call AbortConnections, got %d", plane.abortConnectionsCalls)
	}
	if plane.abortPendingCalls != 0 {
		t.Fatalf("abort retirement must not call AbortPendingConnections, got %d", plane.abortPendingCalls)
	}
}
