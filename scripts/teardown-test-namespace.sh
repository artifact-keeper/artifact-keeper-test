#!/usr/bin/env bash
# teardown-test-namespace.sh - Collect logs and destroy the test namespace
#
# Usage:
#   ./teardown-test-namespace.sh --run-id <id> [--logs-dir <path>]
#
# Collects pod logs, runs helm uninstall, and deletes the namespace.
# Also cleans up any mesh namespaces associated with the run.
# All operations use || true so this script never fails.

set -uo pipefail

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

RUN_ID=""
LOGS_DIR="/tmp/test-logs"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)    RUN_ID="$2"; shift 2 ;;
    --logs-dir)  LOGS_DIR="$2"; shift 2 ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: teardown-test-namespace.sh --run-id <id> [--logs-dir <path>]"
      exit 1
      ;;
  esac
done

if [ -z "$RUN_ID" ]; then
  echo "ERROR: --run-id is required"
  exit 1
fi

# Primary namespace and mesh namespaces to clean up
NAMESPACES=(
  "test-${RUN_ID}"
  "test-${RUN_ID}-mesh-main"
  "test-${RUN_ID}-mesh-peer1"
  "test-${RUN_ID}-mesh-peer2"
  "test-${RUN_ID}-mesh-peer3"
)

mkdir -p "$LOGS_DIR"

# ---------------------------------------------------------------------------
# Process each namespace
# ---------------------------------------------------------------------------

for NS in "${NAMESPACES[@]}"; do
  # Check if namespace exists before trying to collect from it
  if ! kubectl get namespace "$NS" &>/dev/null; then
    continue
  fi

  echo "Processing namespace: ${NS}"

  # -------------------------------------------------------------------------
  # Collect logs from all pods
  # -------------------------------------------------------------------------

  echo "  Collecting pod logs to ${LOGS_DIR}/${NS}/"
  NS_LOG_DIR="${LOGS_DIR}/${NS}"
  mkdir -p "$NS_LOG_DIR"

  pods=$(kubectl get pods -n "$NS" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null) || true
  for pod in $pods; do
    containers=$(kubectl get pod "$pod" -n "$NS" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null) || true
    for container in $containers; do
      kubectl logs "$pod" -n "$NS" -c "$container" \
        > "${NS_LOG_DIR}/${pod}_${container}.log" 2>/dev/null || true
    done
  done

  # -------------------------------------------------------------------------
  # Helm uninstall
  # -------------------------------------------------------------------------

  RELEASE_NAME="ak-${RUN_ID}"
  # For mesh namespaces, adjust the release name
  case "$NS" in
    *-mesh-main)  RELEASE_NAME="ak-${RUN_ID}-mesh-main" ;;
    *-mesh-peer1) RELEASE_NAME="ak-${RUN_ID}-mesh-peer1" ;;
    *-mesh-peer2) RELEASE_NAME="ak-${RUN_ID}-mesh-peer2" ;;
    *-mesh-peer3) RELEASE_NAME="ak-${RUN_ID}-mesh-peer3" ;;
  esac

  echo "  Helm uninstall: ${RELEASE_NAME}"
  helm uninstall "$RELEASE_NAME" --namespace "$NS" 2>/dev/null || true

  # -------------------------------------------------------------------------
  # Delete namespace
  # -------------------------------------------------------------------------

  echo "  Deleting namespace: ${NS}"
  kubectl delete namespace "$NS" --wait=false 2>/dev/null || true
done

echo "Teardown complete. Logs saved to ${LOGS_DIR}/"
