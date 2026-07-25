#!/usr/bin/env bash
# run-suite.sh - Discover and run test scripts for a given suite
#
# Usage:
#   ./run-suite.sh --suite <name> [--filter <pattern>] [--exclude <pat[,pat]>] [--run-id <id>]
#
# Discovers test scripts by globbing tests/<suite>/**/test-*.sh, applies an
# optional include filter and/or an exclude list, then runs each script with a
# timeout. Prints a summary and exits non-zero if any test failed.
#
# --filter  <pattern>      keep only scripts whose path contains <pattern>.
# --exclude <pat[,pat...]> drop scripts whose path contains ANY comma-separated
#                          substring. Used by the release gate to carve a single
#                          known-flaky script (e.g. a waivered Grype scan) out of
#                          an otherwise-blocking suite so the rest can hard-gate.
#
# Environment variables:
#   TEST_TIMEOUT  - Per-test timeout in seconds (default: 120)
#   BASE_URL      - Backend URL passed through to test scripts
#   RUN_ID        - Run identifier passed through to test scripts

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

SUITE=""
FILTER=""
EXCLUDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)   SUITE="$2"; shift 2 ;;
    --filter)  FILTER="$2"; shift 2 ;;
    --exclude) EXCLUDE="$2"; shift 2 ;;
    --run-id)  export RUN_ID="$2"; shift 2 ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: run-suite.sh --suite <name> [--filter <pattern>] [--exclude <pat[,pat]>] [--run-id <id>]"
      exit 1
      ;;
  esac
done

if [ -z "$SUITE" ]; then
  echo "ERROR: --suite is required"
  exit 1
fi

TIMEOUT="${TEST_TIMEOUT:-120}"

# ---------------------------------------------------------------------------
# Discover test scripts
# ---------------------------------------------------------------------------

SUITE_DIR="${REPO_ROOT}/tests/${SUITE}"

if [ ! -d "$SUITE_DIR" ]; then
  echo "ERROR: suite directory not found: ${SUITE_DIR}"
  exit 1
fi

# Glob for test-*.sh in the suite directory and all subdirectories
mapfile -t ALL_SCRIPTS < <(find "$SUITE_DIR" -name 'test-*.sh' -type f | sort)

if [ ${#ALL_SCRIPTS[@]} -eq 0 ]; then
  echo "ERROR: no test scripts found in ${SUITE_DIR}"
  exit 1
fi

# Parse the exclude list (comma-separated substrings) once.
EXCLUDE_PATS=()
if [ -n "$EXCLUDE" ]; then
  IFS=',' read -r -a EXCLUDE_PATS <<< "$EXCLUDE"
fi

# Apply include filter, then exclude list.
SCRIPTS=()
EXCLUDED=()
for script in "${ALL_SCRIPTS[@]}"; do
  # Include filter (substring): if set, script path must contain it.
  if [ -n "$FILTER" ] && [[ "$script" != *"$FILTER"* ]]; then
    continue
  fi
  # Exclude list (substring): drop if it matches ANY exclude pattern.
  skip_this=false
  for pat in "${EXCLUDE_PATS[@]}"; do
    [ -z "$pat" ] && continue
    if [[ "$script" == *"$pat"* ]]; then
      skip_this=true
      break
    fi
  done
  if [ "$skip_this" = true ]; then
    EXCLUDED+=("$script")
    continue
  fi
  SCRIPTS+=("$script")
done

if [ ${#EXCLUDED[@]} -gt 0 ]; then
  echo "Excluded ${#EXCLUDED[@]} script(s) via --exclude '${EXCLUDE}':"
  for script in "${EXCLUDED[@]}"; do
    echo "  - $(basename "$script")"
  done
  echo ""
fi

if [ ${#SCRIPTS[@]} -eq 0 ]; then
  echo "ERROR: no test scripts matched filter '${FILTER}' after exclude '${EXCLUDE}'"
  exit 1
fi

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

echo "========================================"
echo "  Suite: ${SUITE}"
echo "  Scripts: ${#SCRIPTS[@]}"
echo "  Timeout: ${TIMEOUT}s per test"
echo "========================================"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

for script in "${SCRIPTS[@]}"; do
  name="$(basename "$script")"
  echo "--- Running: ${name} ---"

  if timeout "$TIMEOUT" bash "$script"; then
    echo "  RESULT: PASS"
    PASS_COUNT=$(( PASS_COUNT + 1 ))
  else
    echo "  RESULT: FAIL (exit code: $?)"
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  fi

  echo ""
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

TOTAL=$(( PASS_COUNT + FAIL_COUNT ))

echo "========================================"
echo "  Suite: ${SUITE}"
echo "  Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed (${TOTAL} total)"
echo "========================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
