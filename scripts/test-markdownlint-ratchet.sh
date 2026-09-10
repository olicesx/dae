#!/usr/bin/env bash
#
# Self-test for scripts/check-markdownlint-baseline.sh.
#
# The ratchet is deliberately plain sed/grep: it has to be verifiable on a
# machine with no working npm registry, and a bug in a gate that decides pass
# or fail is exactly the kind of thing that must not be taken on faith. This
# script exercises the three behaviours the ratchet promises, plus the two
# guards that stop a broken run from looking like a clean tree.
#
# scripts/testdata/markdownlint-ci-sample.txt is a verbatim copy of the
# markdownlint output from the run that woke this gate up (run 34457659306,
# job 102807720664): "Summary: 163 error(s)" followed by those 163 violations.
#
#   bash scripts/test-markdownlint-ratchet.sh
#
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
checker="${script_dir}/check-markdownlint-baseline.sh"
sample="${script_dir}/testdata/markdownlint-ci-sample.txt"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

passed=0
failed=0

# run_case <name> <expected-rc> <lint-file> <ledger-file> [required-output...]
# Every required-output string has to appear in the checker's combined output.
run_case() {
  local name="$1" expected_rc="$2" lint="$3" ledger="$4"
  shift 4
  local rc=0 out=""

  out="$(MARKDOWNLINT_BASELINE="${ledger}" bash "${checker}" "${lint}" 2>&1)" || rc=$?

  if [[ "${rc}" -ne "${expected_rc}" ]]; then
    echo "FAIL ${name}: expected exit ${expected_rc}, got ${rc}"
    sed 's/^/     | /' <<<"${out}"
    failed=$((failed + 1))
    return
  fi

  local needle
  for needle in "$@"; do
    if ! grep -qF -- "${needle}" <<<"${out}"; then
      echo "FAIL ${name}: exit ${rc} was right, but the output never said: ${needle}"
      sed 's/^/     | /' <<<"${out}"
      failed=$((failed + 1))
      return
    fi
  done

  echo "ok   ${name} (exit ${rc})"
  passed=$((passed + 1))
}

ledger="${tmp}/ledger.txt"

# A scratch ledger is built from the sample through --update-baseline, so the
# regeneration path is covered too.
rc=0
MARKDOWNLINT_BASELINE="${ledger}" bash "${checker}" "${sample}" \
  --update-baseline >"${tmp}/update.out" 2>&1 || rc=$?
entries="$(sed '/^[[:space:]]*#/d;/^$/d' "${ledger}" | wc -l | tr -d ' ')"
if [[ "${rc}" -ne 0 || "${entries}" != "163" ]]; then
  echo "FAIL --update-baseline: exit ${rc}, ${entries} entr(ies) written (want 0 and 163)"
  sed 's/^/     | /' "${tmp}/update.out"
  exit 1
fi
echo "ok   --update-baseline wrote a 163-entry ledger from the CI sample"

# 1. Current violations identical to the ledger: the ratchet passes.
run_case "1. lint run matches the ledger exactly -> pass" \
  0 "${sample}" "${ledger}" \
  "markdownlint baseline ratchet OK: 163 known pre-existing violation(s), 0 new"

# 2. One violation outside the ledger: the ratchet fails and names it. The
#    summary is bumped too, otherwise this would pass for the wrong reason
#    (the parser/summary guard below would fire instead of the new-debt check).
sed 's/^Summary: 163 error(s)$/Summary: 164 error(s)/' "${sample}" >"${tmp}/added.log"
printf '%s\n' 'docs/zh/README.md:999 MD022/blanks-around-headings/blanks-around-headers Headings should be surrounded by blank lines [Context: "## Injected by the self-test"]' \
  >>"${tmp}/added.log"
run_case "2. one violation outside the ledger -> fail and name it" \
  1 "${tmp}/added.log" "${ledger}" \
  "new markdownlint violation not in" \
  "docs/zh/README.md:999"

# 3. A ledger entry that no longer occurs: not a failure, but the ratchet says
#    it can be tightened.
cp "${ledger}" "${tmp}/stale.txt"
printf '%s\n' 'docs/en/retired-by-the-self-test.md:1 MD022/blanks-around-headings/blanks-around-headers Headings should be surrounded by blank lines' \
  >>"${tmp}/stale.txt"
run_case "3. ledger entry that no longer occurs -> pass, report tightening" \
  0 "${sample}" "${tmp}/stale.txt" \
  "no longer occurs" \
  "docs/en/retired-by-the-self-test.md:1"

# 4. Guard: a failed install or a renamed script must not read as a clean tree.
printf 'npm ERR! code ELIFECYCLE\nnpm ERR! Missing script: "markdown-lint"\n' >"${tmp}/broken.log"
run_case "4. output that is not markdownlint output -> fail" \
  1 "${tmp}/broken.log" "${ledger}" \
  "is not markdownlint output"

# 5. Guard: a parser that drops violations must not silently pass them.
sed 's/^Summary: 163 error(s)$/Summary: 164 error(s)/' "${sample}" >"${tmp}/mismatch.log"
run_case "5. summary disagrees with the parsed violations -> fail" \
  1 "${tmp}/mismatch.log" "${ledger}" \
  "parsed 163 violation line(s) but markdownlint reported 164"

echo
if [[ "${failed}" -ne 0 ]]; then
  echo "markdownlint ratchet self-test FAILED: ${passed} passed, ${failed} failed"
  exit 1
fi
echo "markdownlint ratchet self-test OK: ${passed} passed"
