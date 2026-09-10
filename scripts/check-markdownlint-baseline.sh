#!/usr/bin/env bash
#
# markdownlint baseline ratchet.
#
# `.github/workflows/check-docs.yml` used to trigger on `main` only, while
# `kdae` is the branch that receives this fork's documentation changes - so the
# markdownlint gate had never actually run here. Pointing the branch filter at
# `kdae` turned a dead gate into a live one and reported 163 violations on the
# first run: all of them pre-existing documentation debt, none of it introduced
# by the change that woke the gate up.
#
# Repairing 163 historical violations in the same change would bury the change
# itself, and putting `kdae` back out of the branch filter would make the gate
# dead again. So the gate runs and the debt is held in a ledger:
# `.markdownlint-baseline.txt` lists every violation that already existed. The
# ledger is a RATCHET - it may only shrink.
#
# It fails when:
#   * markdownlint reports a violation that is not in the ledger (new debt);
#   * the lint output does not look like markdownlint output, or the number of
#     violation lines does not match its own summary (a broken `npm ci` must
#     never be mistaken for a clean tree).
# It only reports when:
#   * the ledger lists a violation that no longer occurs (shrink the ledger).
#
# Usage:
#   npm run markdown-lint > /tmp/markdownlint.log 2>&1 || true
#   bash scripts/check-markdownlint-baseline.sh /tmp/markdownlint.log
#   bash scripts/check-markdownlint-baseline.sh /tmp/markdownlint.log --update-baseline
#
# The parsing here is plain sed/grep, so it can be exercised without node/npm:
#   bash scripts/test-markdownlint-ratchet.sh
#
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
# MARKDOWNLINT_BASELINE points the ratchet at a scratch ledger; the self-test
# uses it so it never touches the tracked one.
ledger="${MARKDOWNLINT_BASELINE:-${repo_root}/.markdownlint-baseline.txt}"
ledger_rel="${ledger#"${repo_root}/"}"

# ESC, used to strip the colour markdownlint-cli2 emits on a terminal.
esc=$'\033'

usage() {
  echo "usage: ${0#"${repo_root}/"} <markdownlint-output-file> [--update-baseline]" >&2
}

update_baseline=0
input="${1:-}"
if [[ "${input}" == "--update-baseline" ]]; then
  usage
  exit 2
fi
if [[ "${2:-}" == "--update-baseline" ]]; then
  update_baseline=1
elif [[ -n "${2:-}" ]]; then
  usage
  exit 2
fi
if [[ -z "${input}" ]]; then
  usage
  exit 2
fi
if [[ ! -f "${input}" ]]; then
  echo "::error::markdownlint output ${input} not found" >&2
  usage
  exit 2
fi

# lint_violations prints one normalized line per violation. ANSI colour and CR
# are removed so a terminal run and a redirected run compare equal, and the
# result is sorted so the ledger and the current run can be diffed as sets.
lint_violations() {
  sed -e "s/${esc}\[[0-9;]*m//g" -e 's/\r$//' "${input}" |
    grep -E '^[^[:space:]]+\.md:[0-9]+(:[0-9]+)?[[:space:]]' |
    LC_ALL=C sort -u || true
}

# Ledger entries drop blank lines and `#` comment lines. Only whole-line
# comments are dropped: a violation's `[Context: ...]` field can itself contain
# a `#` (e.g. `[Context: "# Schema"]`), so it must survive intact.
ledger_entries() {
  sed -e 's/[[:space:]]*$//' "${ledger}" |
    sed '/^[[:space:]]*#/d' |
    sed '/^$/d' |
    LC_ALL=C sort -u || true
}

# 1. The output has to prove markdownlint ran, and its own summary has to agree
#    with what we parsed. Without this, a failed install or a renamed script
#    would leave zero parsed violations and silently pass the gate.
summary="$(grep -E '^Summary: [0-9]+ error\(s\)$' "${input}" | tail -1 || true)"
if [[ -z "${summary}" ]]; then
  echo "::error::${input} is not markdownlint output (no 'Summary: N error(s)' line)" >&2
  echo "         refusing to treat an unparsed run as a clean tree" >&2
  exit 1
fi
reported="$(sed -E 's/^Summary: ([0-9]+) error\(s\)$/\1/' <<<"${summary}")"

current="$(lint_violations)"
parsed=0
if [[ -n "${current}" ]]; then
  parsed="$(wc -l <<<"${current}" | tr -d ' ')"
fi
if [[ "${parsed}" != "${reported}" ]]; then
  echo "::error::parsed ${parsed} violation line(s) but markdownlint reported ${reported}" >&2
  echo "         the parser and the linter disagree; fix the parser before trusting this gate" >&2
  exit 1
fi

if [[ "${update_baseline}" -eq 1 ]]; then
  {
    echo "# markdownlint violations that already existed on \`kdae\` when this gate"
    echo "# started running here, as of $(git -C "${repo_root}" rev-parse --short HEAD 2>/dev/null || echo 'unknown revision')."
    echo "#"
    echo "# Regenerate with:"
    echo "#   npm run markdown-lint > /tmp/markdownlint.log 2>&1 || true"
    echo "#   bash scripts/check-markdownlint-baseline.sh /tmp/markdownlint.log --update-baseline"
    echo "#"
    echo "# This ledger is a ratchet: it may only shrink. Fixing a violation? Delete"
    echo "# its line in the same commit. Adding a new one? The gate fails until it is"
    echo "# listed here, which is the point."
    echo
    echo "${current}"
  } >"${ledger}"
  echo "::notice::${ledger_rel} rewritten with ${parsed} entr(ies)"
  exit 0
fi

if [[ ! -f "${ledger}" ]]; then
  echo "::error::missing ledger ${ledger_rel}" >&2
  exit 1
fi

known="$(ledger_entries)"

status=0

# 2. New debt: a violation the ledger does not declare.
new_violations="$(LC_ALL=C comm -23 <(printf '%s\n' "${current}") <(printf '%s\n' "${known}") || true)"
if [[ -n "${new_violations}" ]]; then
  while IFS= read -r violation; do
    [[ -z "${violation}" ]] && continue
    echo "::error::new markdownlint violation not in ${ledger_rel}: ${violation}"
  done <<<"${new_violations}"
  echo "         fix it, or - if this is genuinely pre-existing debt - add the line to ${ledger_rel}" >&2
  status=1
fi

# 3. Shrunk debt: the ledger is stale and may now be tightened. Not a failure.
gone="$(LC_ALL=C comm -13 <(printf '%s\n' "${current}") <(printf '%s\n' "${known}") || true)"
if [[ -n "${gone}" ]]; then
  while IFS= read -r violation; do
    [[ -z "${violation}" ]] && continue
    echo "::notice::${ledger_rel} lists a violation that no longer occurs; remove this line to tighten the ratchet: ${violation}"
  done <<<"${gone}"
fi

if [[ "${status}" -eq 0 ]]; then
  known_count=0
  if [[ -n "${known}" ]]; then
    known_count="$(wc -l <<<"${known}" | tr -d ' ')"
  fi
  echo "markdownlint baseline ratchet OK: ${parsed} known pre-existing violation(s), 0 new"
  if [[ "${parsed}" -gt 0 ]]; then
    echo "::notice::markdownlint: ${parsed} pre-existing violation(s) carried in ${ledger_rel}, 0 new"
  fi
fi

exit "${status}"
