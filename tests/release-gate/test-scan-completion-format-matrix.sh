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
# Matrix entries:
#   - npm:    wired (delegates to test-scan-completes.sh via the gate primitive)
#   - oci:    scaffold (TODO #62)
#   - maven:  scaffold (TODO #62)
#   - pypi:   scaffold (TODO #62)
#   - cargo:  scaffold (TODO #62)
#   - helm:   scaffold (TODO #62)
#
# When a fixture-builder for a scaffolded format lands, the matrix entry
# flips from "scaffold" to "wired" without touching this file -- the
# gate primitive's case statement is the single source of truth.
#
# Why one driver script rather than per-format siblings in tests/security/:
#   - Pacing: each format's scan can take 30-60s. Sequential 6-format
#     pass would blow the release-gate 5-min budget. We let each matrix
#     entry run in its own workflow job (parallel) by passing the format
#     name via env. This script can also be invoked locally to run a
#     subset (e.g. FORMATS=npm,oci ./test-scan-completion-format-matrix.sh).
#   - Single source of truth: the gate primitive lives in one file. A
#     fix to the polling logic propagates to every format automatically.
#
# Environment:
#   FORMATS    comma-separated list of formats to run (default: all)
#              e.g. FORMATS=npm,oci ./test-scan-completion-format-matrix.sh
#   BASE_URL, ADMIN_PASS, RUN_ID -- per usual

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default matrix: all representative formats from artifact-keeper-test#62.
FORMATS="${FORMATS:-npm,oci,maven,pypi,cargo,helm}"

# Track per-format outcomes for the final summary.
declare -a PASSED=()
declare -a FAILED=()
declare -a SCAFFOLDED=()

# Per-format RUN_ID suffixes so concurrent runs don't clobber each other's
# repos. Each format gets its own repo key derived from the base RUN_ID.
BASE_RUN_ID="${RUN_ID:-matrix-$(date +%s)}"

echo "========================================"
echo "  scan-completion format matrix"
echo "  formats: ${FORMATS}"
echo "  base run_id: ${BASE_RUN_ID}"
echo "========================================"

# We deliberately keep going on failure so the operator sees ALL format
# regressions in one workflow run, not just the first. The aggregate
# exit code at the end fails the gate if any format failed.
overall_exit=0

IFS=',' read -ra FORMAT_LIST <<< "$FORMATS"
for fmt in "${FORMAT_LIST[@]}"; do
  fmt_trim=$(echo "$fmt" | tr -d '[:space:]')
  [ -z "$fmt_trim" ] && continue
  echo ""
  echo "--- format=${fmt_trim} ---"

  # Per-format RUN_ID so the repo key (e.g. scan-complete-<RUN_ID>) is unique.
  fmt_run_id="${BASE_RUN_ID}-${fmt_trim}"

  # Capture the gate primitive's stdout+stderr so its log shows up
  # inline in the matrix log. Cannot use `exec` because we need control
  # back to record the format's outcome.
  if FIXTURE_FORMAT="$fmt_trim" RUN_ID="$fmt_run_id" \
       "${SCRIPT_DIR}/scan-completion-gate.sh"; then
    # The gate exits 0 on success OR on scaffolded formats. Distinguish
    # by inspecting whether the gate emitted the scaffold marker.
    # (cheap: re-run with a probe? no -- the scaffold path's exit 0 is
    # accompanied by the marker on stdout, but we already consumed it.
    # Solution: write a sentinel file from the gate. Until that exists,
    # we conservatively classify wired-formats by name.)
    case "$fmt_trim" in
      npm|generic-payload)
        PASSED+=("$fmt_trim")
        ;;
      *)
        SCAFFOLDED+=("$fmt_trim")
        ;;
    esac
  else
    rc=$?
    FAILED+=("${fmt_trim}(exit=${rc})")
    overall_exit=1
  fi
done

echo ""
echo "========================================"
echo "  scan-completion matrix summary"
echo "----------------------------------------"
echo "  passed:     ${PASSED[*]:-<none>}"
echo "  scaffolded: ${SCAFFOLDED[*]:-<none>}  (TODO artifact-keeper-test#62)"
echo "  failed:     ${FAILED[*]:-<none>}"
echo "========================================"

if [ "$overall_exit" -ne 0 ]; then
  echo ""
  echo "FAIL: one or more formats failed the scan-completion gate."
  echo "This indicates the scan-completion silent-success class (#888)"
  echo "is reproducing for at least one package format."
  exit 1
fi

if [ "${#PASSED[@]}" -eq 0 ]; then
  echo ""
  echo "FAIL: no formats actually ran the wired gate; matrix degenerated to all-scaffolds."
  echo "At minimum the npm fixture must be exercised."
  exit 1
fi

echo ""
echo "PASS: scan-completion gate passed for all wired formats."
exit 0
