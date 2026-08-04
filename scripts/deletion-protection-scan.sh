#!/usr/bin/env bash
# Scan build-system files for references to candidate deletion files.
#
# Standard Go import-based deletion_protection misses build-tag-gated files:
# files with `//go:build dae_bpf_tests` are invisible to `go vet`/`go test`
# but are referenced by Makefile `go generate` directives and CI workflows.
# Sprint 5 ISSUE-1 (lesson L16): deleting bpf_bug_verification_test.go broke
# `make ebpf-test` because Makefile referenced it via `go generate`.
#
# Usage: deletion-protection-scan.sh <file1> [file2 ...]
# Exit: 0 if no references found (safe to delete); 1 if any reference found;
#       2 on usage error.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <file1> [file2 ...]" >&2
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# Build the list of build-system files to scan. Skip generated/ephemeral
# artifacts (e.g. .gitmodules.d.mk) — only source-controlled files matter.
search_files=(Makefile)
shopt -s nullglob
for f in .github/workflows/*.yml .github/workflows/*.yaml \
         scripts/*.sh scripts/*.pl scripts/*.py; do
  search_files+=("$f")
done

self_path="$(basename "$0")"
candidates=("$@")
hits=0
for cand in "${candidates[@]}"; do
  # Match by basename — path prefixes vary across build-system contexts
  # (Makefile uses ./control/foo.go, workflows may use control/foo.go).
  basename_only="$(basename "$cand")"
  for sf in "${search_files[@]}"; do
    [[ -f "$sf" ]] || continue
    # Skip this script itself — its comments legitimately mention the
    # very files it warns about (ISSUE-1 background note).
    [[ "$(basename "$sf")" == "$self_path" ]] && continue
    # Fixed-string grep avoids regex metacharacter surprises in filenames.
    while IFS= read -r line; do
      echo "HIT: ${cand} -> ${sf}:${line}"
      hits=$((hits + 1))
    done < <(grep -nF "$basename_only" "$sf" || true)
  done
done

if [[ $hits -gt 0 ]]; then
  echo "deletion_protection: ${hits} reference(s) found in build system; refusing deletion." >&2
  exit 1
fi

echo "deletion_protection: 0 references in build system; safe to delete."
exit 0
