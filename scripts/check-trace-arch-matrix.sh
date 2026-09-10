#!/usr/bin/env bash
# P2-22 ledger gate for the "dae trace is not built for this GOARCH" declaration.
#
# TRACE_UNSUPPORTED_GOARCH is a checked-in claim about what the toolchain can do.
# Without a gate it rots in both directions:
#   * an architecture listed there that CAN generate trace ships a crippled
#     binary for no reason (its `dae trace` diagnostics are silently missing);
#   * an architecture removed from the list without proof turns a shipped
#     degradation into a failed release leg (or, worse, gets re-added only
#     because someone remembered).
# So this runs the real generator for every listed architecture (each must FAIL)
# and once for a control architecture (must SUCCEED — otherwise a missing clang
# would make every architecture "unsupported" and the gate would pass vacuously).
#
# The invocation mirrors the Makefile's `ebpf` recipe (same bpf2go directive,
# BPF_TARGET/BPF_CFLAGS/BPF_STRIP_FLAG). CI passes CLANG=clang-<version>.
#
# Usage: scripts/check-trace-arch-matrix.sh [control-goarch]
# Exit: 0 ledger matches reality; 1 otherwise.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

unsupported="$(make -s print-trace-unsupported)"
control="${1:-$(go env GOARCH)}"

if [ -z "$unsupported" ]; then
  echo "::error::TRACE_UNSUPPORTED_GOARCH is empty; refusing to run (the Makefile fail-closed path would then break every release leg that cannot generate trace)" >&2
  exit 1
fi

for arch in $unsupported; do
  if [ "$arch" = "$control" ]; then
    echo "::error::control architecture $control is also listed in TRACE_UNSUPPORTED_GOARCH; pass a supported architecture as the argument" >&2
    exit 1
  fi
done

CLANG_BIN="${CLANG:-${BPF_CLANG:-clang}}"
if ! command -v "$CLANG_BIN" >/dev/null 2>&1; then
  echo "::error::compiler '$CLANG_BIN' not found; the ledger cannot be verified" >&2
  exit 1
fi
STRIP_BIN="${STRIP:-llvm-strip}"
if STRIP_PATH="$(command -v "$STRIP_BIN" 2>/dev/null)"; then
  export BPF_STRIP_FLAG="-strip=${STRIP_PATH}"
else
  export BPF_STRIP_FLAG="-no-strip"
fi
export BPF_CLANG="$CLANG_BIN"
export BPF_CFLAGS="${BPF_CFLAGS:--O2 -Wall -Werror -DMAX_MATCH_SET_LEN=${MAX_MATCH_SET_LEN:-1024}}"
export BPF_TARGET="${TARGET:-bpfel,bpfeb}"

# generate <arch>; returns the generator's status (output kept in the log file).
generate() {
  local arch="$1" log="$2"
  GOARCH="$arch" BPF_TRACE_TARGET="$arch" go generate ./trace/trace.go >"$log" 2>&1
}

fail=0
for arch in $unsupported; do
  log="/tmp/trace-arch-${arch}.log"
  if generate "$arch" "$log"; then
    echo "::error::GOARCH=$arch is declared in TRACE_UNSUPPORTED_GOARCH but its trace program GENERATED successfully; remove it from the list (or keep it only if the declaration is still wanted, which now needs a different justification)" >&2
    tail -5 "$log" >&2
    fail=1
  else
    echo "trace lint: GOARCH=$arch cannot generate trace, as declared ($(grep -m1 -E 'unsupported target|no compiler specified|error:' "$log" | cut -c1-100))"
  fi
done

control_log="/tmp/trace-arch-${control}.log"
if generate "$control" "$control_log"; then
  echo "trace lint: control GOARCH=$control generates trace (so a failure above is a real per-architecture limitation, not a broken environment)"
else
  echo "::error::control GOARCH=$control must generate trace but failed; the ledger cannot be trusted" >&2
  tail -10 "$control_log" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "trace architecture ledger: OK (declared trace-less: $(echo $unsupported | tr ' ' ','), control: $control)"
