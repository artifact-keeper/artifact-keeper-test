#!/usr/bin/env bash
# run-suite.sh - Discover and run test scripts for a given suite
#
# Usage:
#   ./run-suite.sh --suite <name> [--filter <pattern>]
#
# Discovers test scripts by globbing tests/<suite>/**/test-*.sh, applies an
# optional filter pattern, then runs each script with a timeout. Prints a
# summary and exits non-zero if any test failed.
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)  SUITE="$2"; shift 2 ;;
    --filter) FILTER="$2"; shift 2 ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: run-suite.sh --suite <name> [--filter <pattern>]"
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

# Apply filter if provided
SCRIPTS=()
for script in "${ALL_SCRIPTS[@]}"; do
  if [ -n "$FILTER" ]; then
    if [[ "$script" == *"$FILTER"* ]]; then
      SCRIPTS+=("$script")
    fi
  else
    SCRIPTS+=("$script")
  fi
done

if [ ${#SCRIPTS[@]} -eq 0 ]; then
  echo "ERROR: no test scripts matched filter '${FILTER}'"
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
