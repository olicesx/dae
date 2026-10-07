/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var objectPath string
	var outputDir string
	var hold bool
	flag.StringVar(&objectPath, "object", "", "path to the compiled eBPF ELF object")
	flag.StringVar(&outputDir, "output-dir", "build/ebpf-audit", "directory to write audit artifacts")
	flag.BoolVar(&hold, "hold", false, "keep the collection loaded until the process receives SIGINT or SIGTERM")
	flag.Parse()

	if err := run(objectPath, outputDir, hold); err != nil {
		fmt.Fprintf(os.Stderr, "dae-ebpf-audit: %v\n", err)
		os.Exit(1)
	}
}

func run(objectPath string, outputDir string, hold bool) error {
	if objectPath == "" {
		return fmt.Errorf("object path is required")
	}
	if outputDir == "" {
		return fmt.Errorf("output directory is required")
	}

	specDir := filepath.Join(outputDir, "spec")
	verifierDir := filepath.Join(outputDir, "verifier")
	for _, dir := range []string{
		outputDir,
		specDir,
		verifierDir,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}
	for _, m := range spec.Maps {
		if m == nil {
			continue
		}
		m.Pinning = ebpf.PinNone
		if m.InnerMap != nil {
			m.InnerMap.Pinning = ebpf.PinNone
		}
	}
	if err := writeSpecSummaries(spec, specDir); err != nil {
		return err
	}

	if variable, ok := spec.Variables["PARAM"]; ok {
		// The audit tool only needs PARAM zeroed so the collection loads; the
		// concrete field layout belongs to the generated bindings, so take the
		// size from the spec instead of mirroring the struct here.
		if err := variable.Set(make([]byte, variable.Size())); err != nil {
			return fmt.Errorf("set PARAM variable: %w", err)
		}
	} else {
		return fmt.Errorf("missing PARAM variable in %s", objectPath)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelInstruction,
			LogSizeStart: 1 << 20,
		},
	})
	if err != nil {
		_ = os.WriteFile(filepath.Join(outputDir, "load-error.txt"), []byte(err.Error()+"\n"), 0o644)
		if ve, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			_ = os.WriteFile(filepath.Join(verifierDir, "load-main-bpf.log"), fmt.Appendf(nil, "%+v\n", ve), 0o644)
		}
		return err
	}
	defer coll.Close()

	if err := writeProgramVerifierLogs(coll.Programs, verifierDir); err != nil {
		return err
	}
	if err := writeLiveObjectManifest(coll, outputDir); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "audit.ready"), fmt.Appendf(nil, "pid=%d\n", os.Getpid()), 0o644); err != nil {
		return fmt.Errorf("write ready marker: %w", err)
	}
	if hold {
		return waitForTermination()
	}
	return nil
}

func writeSpecSummaries(spec *ebpf.CollectionSpec, specDir string) error {
	var programs []string
	for name, prog := range spec.Programs {
		if prog == nil {
			continue
		}
		programs = append(programs, fmt.Sprintf("%s\t%s\t%s", name, prog.Type, prog.SectionName))
	}
	sort.Strings(programs)
	if err := os.WriteFile(filepath.Join(specDir, "programs.tsv"), []byte(strings.Join(programs, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write program spec summary: %w", err)
	}

	var maps []string
	for name, m := range spec.Maps {
		if m == nil {
			continue
		}
		maps = append(maps, fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%d", name, m.Type, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags))
	}
	sort.Strings(maps)
	if err := os.WriteFile(filepath.Join(specDir, "maps.tsv"), []byte(strings.Join(maps, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write map spec summary: %w", err)
	}

	var variables []string
	for name, variable := range spec.Variables {
		if variable == nil {
			continue
		}
		variables = append(variables, fmt.Sprintf("%s\tconstant=%t", name, variable.Constant()))
	}
	sort.Strings(variables)
	if err := os.WriteFile(filepath.Join(specDir, "variables.tsv"), []byte(strings.Join(variables, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write variable spec summary: %w", err)
	}
	return nil
}

func writeProgramVerifierLogs(programs map[string]*ebpf.Program, verifierDir string) error {
	names := sortedKeys(programs)
	for _, name := range names {
		prog := programs[name]
		if prog == nil || prog.VerifierLog == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(verifierDir, name+".log"), []byte(prog.VerifierLog), 0o644); err != nil {
			return fmt.Errorf("write verifier log for %s: %w", name, err)
		}
	}
	return nil
}

func writeLiveObjectManifest(coll *ebpf.Collection, outputDir string) error {
	var manifest []string

	for _, name := range sortedKeys(coll.Programs) {
		prog := coll.Programs[name]
		if prog == nil {
			continue
		}
		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("inspect program %s: %w", name, err)
		}
		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("program %s id unavailable", name)
		}
		manifest = append(manifest, fmt.Sprintf("program\t%s\t%d", name, id))
	}

	for _, name := range sortedKeys(coll.Maps) {
		m := coll.Maps[name]
		if m == nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			return fmt.Errorf("inspect map %s: %w", name, err)
		}
		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("map %s id unavailable", name)
		}
		manifest = append(manifest, fmt.Sprintf("map\t%s\t%d", name, id))
	}

	sort.Strings(manifest)
	if err := os.WriteFile(filepath.Join(outputDir, "manifest.tsv"), []byte(strings.Join(manifest, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func waitForTermination() error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
	return nil
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for name := range m {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}
