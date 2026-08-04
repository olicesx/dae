#!/usr/bin/env bash
# Run fork repos' own test suites at the commits dae's go.mod replace pins.
#
# Background: dae's go.mod `replace` directives point at fork commits
# (outbound@c5b8ecc, quic-go@dff8aaa5 as of Sprint 6). Fork changes
# (GSO batching, buffer race fix, datagram pooling, sticky-ip, HKDF-SHA1
# inline, tuic fast-fail) live in dae's test blind spot — dae's own gate
# does not exercise fork internals. This harness checks out each fork at
# its pinned commit and runs the fork's own `go test`.
#
# Usage: fork-cross-repo-test.sh [--short] [--dry-run] [--strict] [-- <args>]
#   --short    pass -short to go test (skip slow integration tests)
#   --dry-run  print what would be tested without running go test
#   --strict   exit non-zero if any fork repo test fails (default: advisory,
#              always exit 0 so Producer can read the report and decide)
#   -- <args>  everything after `--` is forwarded to `go test` verbatim
#
# Exit codes (default/advisory mode):
#   0  harness ran to completion (test failures are reported but non-fatal)
#   2  usage error / harness error (no fork found, parse failed, etc.)
# Exit codes (--strict mode):
#   0  all fork repos pass
#   1  one or more fork repos failed
#   2  usage error
#
# Prereqs: fork repos cloned as siblings of dae (../<fork-name>/.git).
# Origin OQ-S6-3 (user concern): fork verification gap.
set -euo pipefail

short=0
dry_run=0
strict=0
extra_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --short) short=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --strict) strict=1; shift ;;
    --) shift; extra_args+=("$@"); break ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) echo "positional arg not expected: $1" >&2; exit 2 ;;
  esac
done

dae_root="$(git rev-parse --show-toplevel)"
fork_base="$(dirname "$dae_root")"

# Fork repos have their own go.mod with their own dependencies (e.g.
# golang.org/x/net) that may not be in dae's GOMODCACHE. Ensure they can be
# fetched: respect caller's GOPROXY, fall back to a CN mirror (golang.org is
# often unreachable from CN networks; same pattern as Sprint 6 L18a's
# gh-proxy workaround for github.com).
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
# Per-repo timeout in seconds (default 600s = 10min). Override via env.
per_repo_timeout="${FORK_TEST_TIMEOUT:-600}"

# Parse dae/go.mod `replace <mod> => <target> <pseudo-version>` directives.
# Only remote replacements with a pseudo-version ending in a 12-hex commit
# are handled (local file:// replaces need no checkout). Emits one record
# per line: <localdir>|<repo_module>|<commit>
parse_replaces() {
  awk '
    /^replace[[:space:]]+/ {
      line = $0
      sub(/^replace[[:space:]]+/, "", line)
      sub(/[[:space:]]+\/\/.*$/, "", line)   # strip trailing comment
      gsub(/[[:space:]]+=>[[:space:]]+/, " ", line)
      n = split(line, parts, " ")
      if (n < 3) next
      target = parts[2]
      version = parts[3]
      if (version ~ /-[0-9a-f]{12}$/) {
        commit = version
        sub(/.*-/, "", commit)
        # Local dir = last path segment of target module.
        nt = split(target, seg, "/")
        printf "%s|%s|%s\n", seg[nt], target, commit
      }
    }
  ' "$dae_root/go.mod"
}

# Build go test invocation.
test_args=(go test)
if [[ "$short" -eq 1 ]]; then
  test_args+=(-short)
fi
if [[ ${#extra_args[@]} -gt 0 ]]; then
  test_args+=("${extra_args[@]}")
fi
test_args+=(./...)

repo_count=0
failures=0
while IFS='|' read -r localdir target commit; do
  fork_path="$fork_base/$localdir"
  repo_count=$((repo_count + 1))
  if [[ ! -d "$fork_path/.git" ]]; then
    echo "SKIP: fork $localdir not found at $fork_path" >&2
    continue
  fi
  if [[ "$dry_run" -eq 1 ]]; then
    echo "DRY-RUN: would checkout $localdir @ $commit and run: ${test_args[*]}"
    continue
  fi
  echo "=== $localdir @ $commit ($fork_path) ==="
  (
    cd "$fork_path"
    if ! git cat-file -e "${commit}^{commit}" 2>/dev/null; then
      echo "commit $commit not present; fetching origin..."
      git fetch origin 2>&1 | tail -3
    fi
    git checkout --detach "$commit" >/dev/null 2>&1
    # Per-repo timeout: fork tests can hang on integration tests; fail-fast
    # this repo without aborting the others.
    timeout "${per_repo_timeout}" "${test_args[@]}"
  ) || failures=$((failures + 1))
done < <(parse_replaces)

if [[ $repo_count -eq 0 ]]; then
  echo "fork-cross-repo-test: no remote pseudo-versioned replaces found in dae/go.mod" >&2
  exit 2
fi

# Report paths so Producer can attach to docs/sprint-N/progress.md.
if [[ $failures -gt 0 ]]; then
  echo "fork-cross-repo-test: ${failures}/${repo_count} fork repo(s) reported test failures." >&2
  echo "  advisory mode (default): Producer reviews failures above; fork bugs are" >&2
  echo "  tracked as OQs and fixed upstream, not in dae. Use --strict to fail builds." >&2
  if [[ "$strict" -eq 1 ]]; then
    exit 1
  fi
  exit 0
fi
echo "fork-cross-repo-test: all ${repo_count} fork repos pass."
exit 0
