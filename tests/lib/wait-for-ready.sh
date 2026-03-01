#!/usr/bin/env bash
# wait-for-ready.sh - Poll health endpoints until the stack is up
#
# Usage: ./wait-for-ready.sh <base_url> [timeout_seconds]
#
# Polls the backend /health endpoint at the given base URL until it returns
# a successful response, or until the timeout expires. Prints progress dots
# while waiting.
#
# Exit codes:
#   0 - Backend is healthy
#   1 - Timed out waiting for backend

set -euo pipefail

BASE_URL="${1:?Usage: wait-for-ready.sh <base_url> [timeout_seconds]}"
TIMEOUT="${2:-120}"
POLL_INTERVAL=5

# Strip trailing slash if present
BASE_URL="${BASE_URL%/}"

echo "Waiting for backend at ${BASE_URL}/health (timeout: ${TIMEOUT}s)"

elapsed=0
while [ "$elapsed" -lt "$TIMEOUT" ]; do
  if curl -sf -o /dev/null "${BASE_URL}/health" 2>/dev/null; then
    echo ""
    echo "Backend is healthy (took ${elapsed}s)"
    exit 0
  fi

  printf "."
  sleep "$POLL_INTERVAL"
  elapsed=$(( elapsed + POLL_INTERVAL ))
done

echo ""
echo "ERROR: Backend did not become healthy within ${TIMEOUT}s"
exit 1
