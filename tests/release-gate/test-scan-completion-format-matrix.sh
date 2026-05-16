#!/usr/bin/env bash
# test-scan-completion-format-matrix.sh -- iterate scan-completion-gate.sh
# across representative package formats so a regression in any one format's
# scanner pipeline fails the release gate.
#
# Covers artifact-keeper-test#62: the lite gate (PR #60) tests one fixture
# (npm tarball with package-lock.json). The customer's #888 complaint was
# precisely the format-coverage gap ("works for npm, silently fails for
# docker"). Matrixing across formats turns that gap into a loud failure.
#
# This script is for LOCAL developer use. CI uses the workflow-level
# matrix in release-gate.yml directly (parallel runner jobs surface
# per-format outcomes in the Actions UI).
#
# Matrix entries (current):
#   - npm: wired (delegates to test-scan-completes.sh via the gate primitive)
#
# Deferred formats (no fixture yet, NOT in the matrix; tracked under #62):
#   oci, maven, pypi, cargo, helm. Adding any of these requires landing
#   a format-specific fixture builder AND adding the format to BOTH:
#     1. release-gate.yml workflow matrix (so CI runs it)
#     2. SUPPORTED_FORMATS below (so local runs accept it)
#
# Why one driver script rather than per-format siblings in tests/security/:
#   - Pacing: each format's scan can take 30-60s. Sequential pass over
#     all formats would blow the release-gate 5-min budget. CI runs each
#     matrix entry in its own workflow job (parallel).
#   - Single source of truth: the gate primitive lives in one file. A
#     fix to the polling logic propagates to every format automatically.
#
# Environment:
#   FORMATS    comma-separated list of formats to run (default: npm)
#              e.g. FORMATS=npm ./test-scan-completion-format-matrix.sh
#   BASE_URL, ADMIN_PASS, RUN_ID -- per usual

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default matrix: only formats whose fixtures exist. Keep this in sync
# with the workflow matrix in .github/workflows/release-gate.yml.
SUPPORTED_FORMATS="npm"
FORMATS="${FORMATS:-${SUPPORTED_FORMATS}}"

# Track per-format outcomes for the final summary.
declare -a PASSED=()
declare -a FAILED=()
declare -a REJECTED=()

# Per-format RUN_ID suffixes so concurrent runs don't clobber each other's
# repos. Each format gets its own repo key derived from the base RUN_ID.
BASE_RUN_ID="${RUN_ID:-matrix-$(date +%s)}"

echo "========================================"
echo "  scan-completion format matrix"
echo "  formats: ${FORMATS}"
echo "  base run_id: ${BASE_RUN_ID}"
echo "========================================"

# We deliberately keep going on failure so the operator sees ALL format
# regressions in one run, not just the first. The aggregate exit code
# at the end fails the gate if any format failed or was rejected.
overall_exit=0

IFS=',' read -ra FORMAT_LIST <<< "$FORMATS"
for fmt in "${FORMAT_LIST[@]}"; do
  fmt_trim=$(echo "$fmt" | tr -d '[:space:]')
  [ -z "$fmt_trim" ] && continue
  echo ""
  echo "--- format=${fmt_trim} ---"

  # Per-format RUN_ID so the repo key (e.g. scan-complete-<RUN_ID>) is unique.
  fmt_run_id="${BASE_RUN_ID}-${fmt_trim}"

  # The gate primitive now exits 2 for unknown FIXTURE_FORMAT values
  # rather than silently exiting 0. That removes the previous ambiguity
  # between "format passed" and "format scaffolded": we no longer need
  # a sentinel file, the exit code distinguishes the three outcomes.
  if FIXTURE_FORMAT="$fmt_trim" RUN_ID="$fmt_run_id" \
       "${SCRIPT_DIR}/scan-completion-gate.sh"; then
    PASSED+=("$fmt_trim")
  else
    rc=$?
    if [ "$rc" = "2" ]; then
      REJECTED+=("${fmt_trim}(no fixture; see #62)")
    else
      FAILED+=("${fmt_trim}(exit=${rc})")
    fi
    overall_exit=1
  fi
done

echo ""
echo "========================================"
echo "  scan-completion matrix summary"
echo "----------------------------------------"
echo "  passed:   ${PASSED[*]:-<none>}"
echo "  rejected: ${REJECTED[*]:-<none>}  (no fixture builder; artifact-keeper-test#62)"
echo "  failed:   ${FAILED[*]:-<none>}"
echo "========================================"

if [ "$overall_exit" -ne 0 ]; then
  echo ""
  echo "FAIL: one or more formats failed or were rejected."
  if [ "${#REJECTED[@]}" -gt 0 ]; then
    echo "  Rejected formats lack a fixture builder. To run only wired"
    echo "  formats locally: FORMATS=${SUPPORTED_FORMATS} \$0"
  fi
  exit 1
fi

if [ "${#PASSED[@]}" -eq 0 ]; then
  echo ""
  echo "FAIL: no formats ran. At minimum the npm fixture must be exercised."
  exit 1
fi

echo ""
echo "PASS: scan-completion gate passed for all formats."
exit 0
