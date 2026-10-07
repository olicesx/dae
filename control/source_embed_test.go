/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import _ "embed"

// Source-level parity tests embed their inputs rather than reading them at run
// time: the datapath whitelist harness in .github/workflows/bpf-test.yml runs a
// test binary from the repository root, so a relative os.ReadFile would not
// resolve there, while go:embed resolves at compile time against this file's
// own directory and therefore works from any working directory. These
// declarations carry no build tag, so the stub unit-test gate and a
// real-datapath test run pin the same contracts.

// tproxySource is the kernel datapath source.
//
//go:embed kern/tproxy.c
var tproxySource string

// bpfUtilsSource is the real-datapath loader and mirror source, which the stub
// build excludes from compilation.
//
//go:embed bpf_utils.go
var bpfUtilsSource string
