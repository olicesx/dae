package cmd

import (
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

func shutdownAfterSignal(
	log *logrus.Logger,
	listener signalShutdownListener,
	c signalShutdownControlPlane,
	netns signalShutdownNetns,
	fastExit bool,
) error {
	return shutdownAfterSignalWithHandoff(log, listener, c, netns, fastExit, nil)
}

// newTestRuntimeGeneration returns a minimal runtimeGeneration for runtime
// supervisor tests. Recovered from the pruned runtime_supervisor_test.go
// (Sprint 5 T1).
func newTestRuntimeGeneration() *runtimeGeneration {
	return &runtimeGeneration{
		controlPlane: &control.ControlPlane{},
		listener:     &control.Listener{},
		cancel:       func() {},
		conf:         &config.Config{},
	}
}
