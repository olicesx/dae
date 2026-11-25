//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org
 */

package control

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"golang.org/x/sys/unix"
)

var verifierProcessedInsns = regexp.MustCompile(`processed \d+ insns \(limit \d+\)`)

// TestProductionProgramsLoad loads every program of the production object once
// for each combination of the .rodata switches that change which code the
// verifier walks. It checks that the verifier accepts each program, not a
// particular processed-instruction count, because that count moves with the
// clang and kernel versions; the counts are logged so growth stays visible.
// Each combination is also loaded with BPF_F_STRICT_ALIGNMENT, which applies
// the packet alignment rules of kernels without efficient unaligned access,
// such as LoongArch with ARCH_STRICT_ALIGN (daeuniverse/dae#1159), on any host.
//
// Nothing is attached, and the collection is closed, so a loaded program
// leaves nothing behind in the kernel.
func TestProductionProgramsLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock limit: %v", err)
	}
	for _, redirectPeer := range []uint8{0, 1} {
		for _, currentTask := range []uint8{0, 1} {
			for _, strictAlign := range []bool{false, true} {
				name := fmt.Sprintf("redirect_peer=%d,current_task=%d,strict_align=%t", redirectPeer, currentTask, strictAlign)
				t.Run(name, func(t *testing.T) {
					loadProductionProgramsOnce(t, redirectPeer, currentTask, strictAlign)
				})
			}
		}
	}
}

// loadProductionProgramsOnce prepares the object the way
// loadBpfObjectsWithConstantsAndCustomizer does, then loads it. Nothing is
// attached.
func loadProductionProgramsOnce(t *testing.T, useRedirectPeer, hasBpfGetCurrentTask uint8, strictAlign bool) {
	t.Helper()
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	// Same shape and values as the constants map in fullLoadBpfObjects.
	param := struct {
		tproxyPort           uint32
		controlPlanePid      uint32
		dae0Ifindex          uint32
		daeNetnsId           uint32
		dae0peerMac          [6]byte
		paddingAfterMac      [2]uint8
		useRedirectPeer      uint8
		hasBpfGetCurrentTask uint8
		datapathGeneration   uint16
		daeSocketMark        uint32
	}{
		controlPlanePid:      uint32(os.Getpid()),
		useRedirectPeer:      useRedirectPeer,
		hasBpfGetCurrentTask: hasBpfGetCurrentTask,
		// The values a running daemon has, not the zero values. A cold start
		// stamps its socket mark and a non-zero generation, and both change
		// which branches the verifier keeps: with a zero mark the socket-mark
		// test folds away, and so do packet paths behind it. Loading with the
		// production values is what makes this gate stand for the configuration
		// users actually run.
		datapathGeneration: 1,
		daeSocketMark:      common.InternalSoMarkFromDae,
	}
	if err := spec.Variables["PARAM"].Set(param); err != nil {
		t.Fatalf("set PARAM: %v", err)
	}
	if err := spec.Variables["EVENT_RATE"].Set(eventRateValue()); err != nil {
		t.Fatalf("set EVENT_RATE: %v", err)
	}
	if err := customizeBpfMapSpecs(spec, 0, 0); err != nil {
		t.Fatalf("customize maps: %v", err)
	}
	if err := tuneEventRateMap(spec); err != nil {
		t.Fatalf("tune event rate map: %v", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	if strictAlign {
		for _, p := range spec.Programs {
			p.Flags |= unix.BPF_F_STRICT_ALIGNMENT
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		// The collection loader wraps a verifier rejection in its own error,
		// and formatting that wrapper prints only the summary line. Unwrap to
		// the VerifierError for the instruction and register detail that is
		// needed to diagnose a compiler-specific rejection.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load programs: %+v", ve)
		}
		t.Fatalf("load programs: %v", err)
	}
	defer coll.Close()
	names := make([]string, 0, len(coll.Programs))
	for name := range coll.Programs {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		t.Logf("%s: %s", name, verifierProcessedInsns.FindString(coll.Programs[name].VerifierLog))
	}
	t.Logf("loaded %d programs and %d maps", len(coll.Programs), len(coll.Maps))
}
