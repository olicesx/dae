//go:build linux && dae_bpf_tests

package control

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func loadBpfObjectsWithConstants(obj interface{}, opts *ebpf.CollectionOptions, constants map[string]interface{}) error {
	return loadBpfObjectsWithConstantsAndCustomizer(obj, opts, constants, nil)
}

func TestLoadMainBPFObjects(t *testing.T) {
	testLoadMainBPFObjects(t, 0)
}

func TestLoadMainBPFObjectsWithDaeSocketMark(t *testing.T) {
	testLoadMainBPFObjects(t, 0x73ae)
}

func testLoadMainBPFObjects(t *testing.T, daeSocketMark uint32) {
	t.Helper()

	var obj bpfObjects
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelInstruction,
			LogSizeStart: 1 << 20,
		},
	}

	constants := map[string]interface{}{
		"PARAM": struct {
			tproxyPort         uint32
			controlPlanePid    uint32
			dae0Ifindex        uint32
			daeNetnsId         uint32
			dae0peerMac        [6]byte
			paddingAfterMac    [2]uint8
			useRedirectPeer    uint8
			hasCurrentTask     uint8
			datapathGeneration uint16
			daeSocketMark      uint32
		}{
			datapathGeneration: 41,
			daeSocketMark:      daeSocketMark,
		},
	}

	if err := loadBpfObjectsWithConstantsAndCustomizer(&obj, opts, constants, disableAllPinnedMapsForTests); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load main bpf objects: verifier:\n%+v", ve)
		}
		t.Fatalf("load main bpf objects: %+v", err)
	}
	defer func() { _ = obj.Close() }()
}

func TestLoadMainBPFObjectsWithFreshFlowMapReplacements(t *testing.T) {
	var previous bpfObjects
	previousOptions := &ebpf.CollectionOptions{}
	previousConstants := map[string]interface{}{
		"PARAM": bpfDaeParam{DatapathGeneration: 51},
	}
	if err := loadBpfObjectsWithConstantsAndCustomizer(
		&previous,
		previousOptions,
		previousConstants,
		disableAllPinnedMapsForTests,
	); err != nil {
		t.Fatalf("load previous BPF objects: %v", err)
	}
	defer func() { _ = previous.Close() }()

	var successor bpfObjects
	successorOptions := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"conn_state_map": previous.ConnStateMap,
			"redirect_track": previous.RedirectTrack,
			"cookie_pid_map": previous.CookiePidMap,
		},
	}
	successorConstants := map[string]interface{}{
		"PARAM": bpfDaeParam{DatapathGeneration: 52},
	}
	if err := loadBpfObjectsWithConstantsAndCustomizer(
		&successor,
		successorOptions,
		successorConstants,
		disableAllPinnedMapsForTests,
	); err != nil {
		t.Fatalf("load successor with flow map replacements: %v", err)
	}
	defer func() { _ = successor.Close() }()
}
