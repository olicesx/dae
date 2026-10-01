/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package assets

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestGetLocationAssetRejectsParentTraversal(t *testing.T) {
	root := t.TempDir()
	assetDir := filepath.Join(root, "assets")
	if err := os.Mkdir(assetDir, 0o755); err != nil {
		t.Fatalf("mkdir asset dir: %v", err)
	}
	outside := filepath.Join(root, "outside.dat")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	log := logrus.New()
	log.SetOutput(io.Discard)
	finder := NewLocationFinder([]string{assetDir})
	if _, err := finder.GetLocationAsset(log, filepath.Join("..", filepath.Base(outside))); err == nil {
		t.Fatal("parent traversal unexpectedly resolved an asset")
	}
}

// TestGetLocationAssetNamesEnvVarWhenMissing pins the diagnostic that tells a
// user whether the process even saw DAE_LOCATION_ASSET: a value exported in an
// interactive shell is invisible to a daemon started by systemd or by a bare
// "sudo dae run" that resets the environment.
func TestGetLocationAssetNamesEnvVarWhenMissing(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	assetDir := t.TempDir()
	const filename = "dae-asset-probe-does-not-exist.dat"

	t.Setenv("DAE_LOCATION_ASSET", "")
	_, err := NewLocationFinder([]string{assetDir}).GetLocationAsset(log, filename)
	if err == nil {
		t.Fatal("missing asset unexpectedly resolved")
	}
	if !strings.Contains(err.Error(), "DAE_LOCATION_ASSET is not set") {
		t.Fatalf("unset-env error lacks the hint: %v", err)
	}

	envDir := t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", envDir)
	_, err = NewLocationFinder([]string{assetDir}).GetLocationAsset(log, filename)
	if err == nil {
		t.Fatal("missing asset unexpectedly resolved with DAE_LOCATION_ASSET set")
	}
	if !strings.Contains(err.Error(), "DAE_LOCATION_ASSET="+strconv.Quote(envDir)) {
		t.Fatalf("set-env error does not echo the variable: %v", err)
	}
}
