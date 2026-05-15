#!/usr/bin/env bash
# clean-install-smoke-with-deps.sh - Full-stack clean-install smoke (issue #53)
#
# Variant of scripts/clean-install-smoke.sh that enables Trivy,
# Dependency-Track, edge replication, and ingress. Catches chart-wiring
# regressions in subsystems the basic smoke disables.
#
# OpenSCAP is intentionally NOT enabled here: the chart has no openscap
# subsystem (verified 2026-05-14, see helm/values-smoke-with-deps.yaml
# header comment). When the chart grows one, add it to the expected
# deployments list and re-enable it in the overlay.
#
# Usage:
#   ./clean-install-smoke-with-deps.sh \
#       --run-id <id> \
#       --backend-tag <tag> \
#       [--web-tag <tag>] \
#       [--iac-ref <ref>] \
#       [--timeout <seconds>] \
#       [--keep-namespace]
#
# Exit codes:
#   0 - All Deployments + StatefulSets Ready, /readyz returned 200
#   1 - Usage / helm install failed
#   2 - Rollout did not complete within timeout
#   3 - /readyz did not return 200 within timeout
#   4 - At least one optional subsystem did not reach Ready

set -euo pipefail

RUN_ID=""
BACKEND_TAG=""
WEB_TAG="dev"
IAC_REF="main"
TIMEOUT_SECONDS=600
KEEP_NAMESPACE=false

CHART_TMPDIR=""
GHCR_CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)         RUN_ID="${2:-}"; shift 2 ;;
    --backend-tag)    BACKEND_TAG="${2:-}"; shift 2 ;;
    --web-tag)        WEB_TAG="${2:-}"; shift 2 ;;
    --iac-ref)        IAC_REF="${2:-}"; shift 2 ;;
    --timeout)        TIMEOUT_SECONDS="${2:-}"; shift 2 ;;
    --keep-namespace) KEEP_NAMESPACE=true; shift ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "$RUN_ID" ] || [ -z "$BACKEND_TAG" ]; then
  echo "ERROR: --run-id and --backend-tag are required" >&2
  exit 1
fi

NAMESPACE="smoke-deps-${RUN_ID}"
RELEASE_NAME="ak-smoke-deps-${RUN_ID}"

# Repo root: this script lives in tests/release-gate; go up two.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VALUES_OVERLAY="${REPO_ROOT}/helm/values-smoke-with-deps.yaml"

if [ ! -f "$VALUES_OVERLAY" ]; then
  echo "ERROR: values overlay not found at ${VALUES_OVERLAY}" >&2
  exit 1
fi

echo "=================================================================="
echo "Clean-install smoke WITH dependencies (issue #53)"
echo "  Namespace:    ${NAMESPACE}"
echo "  Release:      ${RELEASE_NAME}"
echo "  Backend tag:  ${BACKEND_TAG}"
echo "  Web tag:      ${WEB_TAG}"
echo "  Timeout:      ${TIMEOUT_SECONDS}s"
echo "  iac ref:      ${IAC_REF}"
echo "  Values:       ${VALUES_OVERLAY}"
echo "=================================================================="

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
  local exit_code=$?
  if [ "$KEEP_NAMESPACE" = "true" ]; then
    echo ""
    echo "Skipping teardown (--keep-namespace set). Namespace ${NAMESPACE} retained."
    exit "$exit_code"
  fi
  echo ""
  echo "Teardown: removing ${NAMESPACE}"
  if [ "$exit_code" -ne 0 ]; then
    LOGS_DIR="/tmp/test-logs/smoke-deps-${RUN_ID}"
    if mkdir -p "$LOGS_DIR" 2>/dev/null; then
      kubectl get pods -n "$NAMESPACE" -o wide > "${LOGS_DIR}/pods.txt" 2>/dev/null || true
      kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' \
        > "${LOGS_DIR}/events.txt" 2>/dev/null || true
      pods=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
      for pod in $pods; do
        kubectl logs "$pod" -n "$NAMESPACE" --all-containers --tail=500 \
          > "${LOGS_DIR}/${pod}.log" 2>/dev/null || true
      done
      echo "Diagnostics saved to ${LOGS_DIR}/"
    fi
  fi
  helm uninstall "$RELEASE_NAME" --namespace "$NAMESPACE" --wait=false 2>/dev/null || true
  kubectl delete namespace "$NAMESPACE" --wait=false 2>/dev/null || true
  [ -n "$CHART_TMPDIR" ] && [ -d "$CHART_TMPDIR" ] && rm -rf "$CHART_TMPDIR" 2>/dev/null || true
  [ -n "$GHCR_CONFIG_FILE" ] && [ -f "$GHCR_CONFIG_FILE" ] && rm -f "$GHCR_CONFIG_FILE" 2>/dev/null || true
  exit "$exit_code"
}
trap cleanup EXIT

# -----------------------------------------------------------------------
# Resolve chart
# -----------------------------------------------------------------------

CHART_TMPDIR="$(mktemp -d)"
echo "Cloning artifact-keeper-iac@${IAC_REF}"
git clone --depth 1 --branch "$IAC_REF" \
  https://github.com/artifact-keeper/artifact-keeper-iac.git \
  "$CHART_TMPDIR/iac"
CHART_DIR="${CHART_TMPDIR}/iac/charts/artifact-keeper"

if [ ! -f "${CHART_DIR}/Chart.yaml" ]; then
  echo "ERROR: chart not found at ${CHART_DIR}" >&2
  exit 1
fi

# -----------------------------------------------------------------------
# Namespace + GHCR secret
# -----------------------------------------------------------------------

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

if [ -n "${GHCR_DOCKER_CONFIG:-}" ]; then
  GHCR_CONFIG_FILE="$(mktemp)"
  echo "$GHCR_DOCKER_CONFIG" | base64 -d > "$GHCR_CONFIG_FILE"
  kubectl create secret generic ghcr-creds \
    --namespace "$NAMESPACE" \
    --type=kubernetes.io/dockerconfigjson \
    --from-file=".dockerconfigjson=${GHCR_CONFIG_FILE}" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

# -----------------------------------------------------------------------
# Helm install with the with-deps overlay
# -----------------------------------------------------------------------

echo ""
echo "Installing release ${RELEASE_NAME} with full deps"
helm upgrade --install "$RELEASE_NAME" "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  --values "$VALUES_OVERLAY" \
  --set backend.image.tag="$BACKEND_TAG" \
  --set web.image.tag="$WEB_TAG" \
  --wait=false || {
    echo "ERROR: helm install failed" >&2
    exit 1
  }

# -----------------------------------------------------------------------
# Wait for each optional subsystem
#
# We walk the expected deployment/statefulset list and rollout-wait
# each. A specific subsystem timing out is more useful than a
# generic "stack did not come up" message.
# -----------------------------------------------------------------------

# Resource shape verified via `helm template charts/artifact-keeper -f
# helm/values-smoke-with-deps.yaml` against artifact-keeper-iac@main
# on 2026-05-14. Single-replica OpenSearch renders as a Deployment
# (Recreate strategy), Postgres alone is a StatefulSet, DependencyTrack
# is named `dtrack` not `dependency-track`, and the chart has no
# openscap subsystem (see overlay header comment).
EXPECTED_DEPLOYMENTS=(
  "artifact-keeper-backend"
  "artifact-keeper-web"
  "artifact-keeper-trivy"
  "artifact-keeper-dtrack"
  "artifact-keeper-edge"
  "artifact-keeper-opensearch"
)

EXPECTED_STATEFULSETS=(
  "artifact-keeper-postgres"
)

failed_subsystems=()

wait_for_workload_exists() {
  local kind="$1"  # deployment or statefulset
  local name="$2"
  local timeout=60
  local elapsed=0
  while [ "$elapsed" -lt "$timeout" ]; do
    if kubectl get "$kind" "$name" -n "$NAMESPACE" >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  return 1
}

for d in "${EXPECTED_DEPLOYMENTS[@]}"; do
  echo ""
  echo "Waiting for deployment/${d} to exist..."
  if ! wait_for_workload_exists deployment "$d"; then
    echo "  deployment/${d} did not appear (likely chart wiring regression for this subsystem)"
    failed_subsystems+=("deployment/${d}:missing")
    continue
  fi
  echo "Polling deployment/${d} rollout (timeout ${TIMEOUT_SECONDS}s)"
  if ! kubectl rollout status "deployment/${d}" -n "$NAMESPACE" \
        --timeout="${TIMEOUT_SECONDS}s"; then
    failed_subsystems+=("deployment/${d}:not-ready")
  fi
done

for s in "${EXPECTED_STATEFULSETS[@]}"; do
  echo ""
  echo "Waiting for statefulset/${s} to exist..."
  if ! wait_for_workload_exists statefulset "$s"; then
    echo "  statefulset/${s} did not appear"
    failed_subsystems+=("statefulset/${s}:missing")
    continue
  fi
  echo "Polling statefulset/${s} rollout (timeout ${TIMEOUT_SECONDS}s)"
  if ! kubectl rollout status "statefulset/${s}" -n "$NAMESPACE" \
        --timeout="${TIMEOUT_SECONDS}s"; then
    failed_subsystems+=("statefulset/${s}:not-ready")
  fi
done

# -----------------------------------------------------------------------
# Ingress: verify the chart rendered the resource
# -----------------------------------------------------------------------

echo ""
echo "Checking Ingress resource exists"
if ! kubectl get ingress -n "$NAMESPACE" -o name 2>/dev/null | grep -q .; then
  echo "  No Ingress resource found in ${NAMESPACE} (chart wiring regression?)"
  failed_subsystems+=("ingress:missing")
fi

# -----------------------------------------------------------------------
# Probe /readyz
# -----------------------------------------------------------------------

echo ""
SERVICE_URL="http://artifact-keeper-backend.${NAMESPACE}.svc.cluster.local:8080"
BACKEND_POD=$(kubectl get pods -n "$NAMESPACE" \
  -l "app.kubernetes.io/component=backend" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [ -n "$BACKEND_POD" ]; then
  echo "Polling ${SERVICE_URL}/readyz from ${BACKEND_POD}"
  ready_ok=false
  elapsed=0
  while [ "$elapsed" -lt 180 ]; do
    if out=$(kubectl exec -n "$NAMESPACE" "$BACKEND_POD" -- \
        sh -c "curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 ${SERVICE_URL}/readyz \
               || wget -q --timeout=5 -O - --server-response ${SERVICE_URL}/readyz 2>&1 \
                  | grep -i 'HTTP/'" 2>&1); then
      if echo "$out" | grep -qE '\b200\b'; then
        ready_ok=true
        break
      fi
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  if ! $ready_ok; then
    failed_subsystems+=("readyz:not-200")
  fi
else
  failed_subsystems+=("readyz:no-backend-pod")
fi

# -----------------------------------------------------------------------
# Final verdict
# -----------------------------------------------------------------------

echo ""
echo "=================================================================="
if [ "${#failed_subsystems[@]}" -eq 0 ]; then
  echo "Clean-install smoke WITH deps PASSED"
  echo "  All subsystems reached Ready and /readyz returned 200."
  echo "=================================================================="
  exit 0
fi

echo "Clean-install smoke WITH deps FAILED"
echo ""
echo "Failing subsystems:"
for f in "${failed_subsystems[@]}"; do
  echo "  - ${f}"
done
echo "=================================================================="
exit 4
