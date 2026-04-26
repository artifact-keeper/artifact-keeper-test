#!/usr/bin/env bash
# clean-install-smoke.sh - Clean-cluster Helm install smoke test
#
# Usage:
#   ./clean-install-smoke.sh --run-id <id> --backend-tag <tag> [--web-tag <tag>] \
#       [--iac-repo <path>] [--timeout <seconds>] [--keep-namespace]
#
# Boots a fresh namespace, performs `helm install` against the documented
# values-production.yaml (with test-only secret overrides), and polls
# `kubectl rollout status` plus `/readyz` until the backend reports ready
# or the timeout expires.
#
# This gate exists to catch startup panics (e.g. the v1.1.8 Debian route
# panic) that crash the backend before it can ever serve traffic. If the
# pod never reaches Ready in the window, the script exits non-zero and the
# release-gate fails.
#
# Exit codes:
#   0  Pod ready, /readyz returns 200, smoke test passed
#   1  Helm install failed
#   2  Rollout did not complete within timeout
#   3  /readyz did not return 200 within timeout

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# SCRIPT_DIR retained for future use; this script does not currently
# reference files in the repo root.
: "${SCRIPT_DIR}"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

RUN_ID=""
BACKEND_TAG=""
WEB_TAG="dev"
IAC_REPO=""
TIMEOUT_SECONDS=120
KEEP_NAMESPACE=false

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)         RUN_ID="$2"; shift 2 ;;
    --backend-tag)    BACKEND_TAG="$2"; shift 2 ;;
    --web-tag)        WEB_TAG="$2"; shift 2 ;;
    --iac-repo)       IAC_REPO="$2"; shift 2 ;;
    --timeout)        TIMEOUT_SECONDS="$2"; shift 2 ;;
    --keep-namespace) KEEP_NAMESPACE=true; shift ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: clean-install-smoke.sh --run-id <id> --backend-tag <tag> [--web-tag <tag>] [--iac-repo <path>] [--timeout <seconds>] [--keep-namespace]" >&2
      exit 1
      ;;
  esac
done

if [ -z "$RUN_ID" ] || [ -z "$BACKEND_TAG" ]; then
  echo "ERROR: --run-id and --backend-tag are required" >&2
  exit 1
fi

NAMESPACE="smoke-${RUN_ID}"
RELEASE_NAME="ak-smoke-${RUN_ID}"

echo "=================================================================="
echo "Clean-install smoke test"
echo "  Namespace:   ${NAMESPACE}"
echo "  Release:     ${RELEASE_NAME}"
echo "  Backend tag: ${BACKEND_TAG}"
echo "  Web tag:     ${WEB_TAG}"
echo "  Timeout:     ${TIMEOUT_SECONDS}s"
echo "=================================================================="

# ---------------------------------------------------------------------------
# Teardown handler (always cleans up unless --keep-namespace)
# ---------------------------------------------------------------------------

cleanup() {
  local exit_code=$?
  if [ "$KEEP_NAMESPACE" = "true" ]; then
    echo ""
    echo "Skipping teardown (--keep-namespace set). Namespace ${NAMESPACE} retained for debugging."
    exit "$exit_code"
  fi

  echo ""
  echo "------------------------------------------------------------------"
  echo "Teardown: collecting diagnostics and removing ${NAMESPACE}"
  echo "------------------------------------------------------------------"

  # Capture pod state and logs on failure for debugging the release-gate
  if [ "$exit_code" -ne 0 ]; then
    echo ""
    echo "Pods in ${NAMESPACE}:"
    kubectl get pods -n "$NAMESPACE" -o wide 2>/dev/null || true
    echo ""
    echo "Recent events in ${NAMESPACE}:"
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' 2>/dev/null | tail -30 || true

    # Save backend logs for the workflow artifact step
    LOGS_DIR="${LOGS_DIR:-/tmp/test-logs}/smoke-${RUN_ID}"
    mkdir -p "$LOGS_DIR"
    pods=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
    for pod in $pods; do
      kubectl logs "$pod" -n "$NAMESPACE" --all-containers --tail=500 \
        > "${LOGS_DIR}/${pod}.log" 2>/dev/null || true
      kubectl logs "$pod" -n "$NAMESPACE" --all-containers --previous --tail=500 \
        > "${LOGS_DIR}/${pod}.previous.log" 2>/dev/null || true
    done
    echo "Logs saved to ${LOGS_DIR}/"
  fi

  helm uninstall "$RELEASE_NAME" --namespace "$NAMESPACE" --wait=false 2>/dev/null || true
  kubectl delete namespace "$NAMESPACE" --wait=false 2>/dev/null || true

  exit "$exit_code"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Resolve Helm chart source
# ---------------------------------------------------------------------------

CHART_TMPDIR=""
if [ -n "$IAC_REPO" ]; then
  CHART_DIR="${IAC_REPO}/charts/artifact-keeper"
else
  CHART_TMPDIR="$(mktemp -d)"
  echo "Cloning artifact-keeper-iac for Helm chart..."
  git clone --depth 1 https://github.com/artifact-keeper/artifact-keeper-iac.git "$CHART_TMPDIR/iac"
  CHART_DIR="${CHART_TMPDIR}/iac/charts/artifact-keeper"
fi

if [ ! -f "${CHART_DIR}/Chart.yaml" ]; then
  echo "ERROR: Helm chart not found at ${CHART_DIR}" >&2
  exit 1
fi

PROD_VALUES="${CHART_DIR}/values-production.yaml"
if [ ! -f "$PROD_VALUES" ]; then
  echo "ERROR: values-production.yaml not found at ${PROD_VALUES}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Create fresh namespace
# ---------------------------------------------------------------------------

echo ""
echo "Creating fresh namespace ${NAMESPACE}"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

if [ -n "${GHCR_DOCKER_CONFIG:-}" ]; then
  kubectl create secret docker-registry ghcr-creds \
    --namespace "$NAMESPACE" \
    --docker-server=ghcr.io \
    --from-file=.dockerconfigjson=<(echo "$GHCR_DOCKER_CONFIG" | base64 -d) \
    --dry-run=client -o yaml | kubectl apply -f -
fi

# ---------------------------------------------------------------------------
# Helm install with documented production values + test-only overrides
# ---------------------------------------------------------------------------
#
# values-production.yaml is an example template that ships with empty
# strings for ADMIN_PASSWORD, jwtSecret, RDS host, ingress host, etc. The
# point of this gate is to verify the chart's documented install path,
# not to exercise external infrastructure, so we override:
#
#   - fullnameOverride       stable service DNS for /readyz polling
#   - backend image tag      under-test build
#   - ADMIN_PASSWORD         test-only credential
#   - secrets.jwtSecret      test-only credential
#   - postgres.enabled=true  in-cluster DB instead of RDS
#   - externalDatabase       cleared so chart uses in-cluster postgres
#   - externalSecrets        disabled (no AWS Secrets Manager in CI)
#   - ingress                disabled (no public domain)
#   - serviceMonitor         disabled (no Prometheus operator in test cluster)
#   - autoscaling/PDB        single replica is enough for a startup smoke
#
# These overrides keep the chart on its documented values-production.yaml
# code path while cutting external dependencies the smoke test can't
# satisfy.

echo ""
echo "Installing Helm release ${RELEASE_NAME}"
helm upgrade --install "$RELEASE_NAME" "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  --values "$PROD_VALUES" \
  --set fullnameOverride=ak-smoke \
  --set backend.image.tag="$BACKEND_TAG" \
  --set backend.image.pullPolicy=Always \
  --set backend.replicaCount=1 \
  --set "backend.env.ADMIN_PASSWORD=Smoke!2026secure" \
  --set web.image.tag="$WEB_TAG" \
  --set web.replicaCount=1 \
  --set secrets.jwtSecret="smoke-jwt-secret-not-for-production" \
  --set postgres.enabled=true \
  --set "postgres.auth.username=registry" \
  --set "postgres.auth.password=smoke-db-password" \
  --set "postgres.auth.database=artifact_registry" \
  --set externalDatabase.host="" \
  --set externalDatabase.existingSecret="" \
  --set externalSecrets.enabled=false \
  --set ingress.enabled=false \
  --set serviceMonitor.enabled=false \
  --set "backend.autoscaling.enabled=false" \
  --set "backend.podDisruptionBudget.enabled=false" \
  --set "web.podDisruptionBudget.enabled=false" \
  --set edge.enabled=false \
  --set trivy.enabled=false \
  --set dependencyTrack.enabled=false \
  --set networkPolicy.enabled=false \
  --wait=false || {
    echo "ERROR: helm install failed" >&2
    exit 1
  }

# ---------------------------------------------------------------------------
# Poll rollout status AND /readyz in parallel-ish
# ---------------------------------------------------------------------------
#
# The v1.1.8 panic was a startup crash: the pod went CrashLoopBackOff, the
# rollout never progressed, and the chart never reported ready. We watch
# both the deployment rollout (catches CrashLoopBackOff) and the actual
# /readyz endpoint (catches "running but not serving") so either failure
# mode trips the gate.

DEPLOYMENT="ak-smoke-backend"
SERVICE_URL="http://ak-smoke-backend.${NAMESPACE}.svc.cluster.local:8080"

echo ""
echo "Polling rollout status for deployment/${DEPLOYMENT} (timeout: ${TIMEOUT_SECONDS}s)"

# kubectl rollout status itself respects --timeout. If the deployment is
# stuck (image pull, CrashLoopBackOff, etc.), this exits non-zero.
if ! kubectl rollout status "deployment/${DEPLOYMENT}" \
      --namespace "$NAMESPACE" \
      --timeout="${TIMEOUT_SECONDS}s"; then
  echo "ERROR: deployment/${DEPLOYMENT} did not reach Ready within ${TIMEOUT_SECONDS}s" >&2
  echo ""
  echo "Pod state:"
  kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/component=backend" -o wide || true
  exit 2
fi

echo ""
echo "Polling ${SERVICE_URL}/readyz (timeout: ${TIMEOUT_SECONDS}s)"

# /readyz is checked from inside the cluster via a short-lived curl pod so
# we don't need ingress or port-forwarding from the runner. This matches
# how application traffic actually reaches the backend in production.

start=$(date +%s)
deadline=$(( start + TIMEOUT_SECONDS ))

while true; do
  now=$(date +%s)
  if [ "$now" -ge "$deadline" ]; then
    echo "ERROR: /readyz did not return 200 within ${TIMEOUT_SECONDS}s" >&2
    exit 3
  fi

  # Run curl from a throwaway pod inside the namespace. -fsS makes curl
  # exit non-zero on HTTP >= 400 and stay quiet on success.
  if kubectl run "smoke-probe-$$" \
        --namespace "$NAMESPACE" \
        --image=curlimages/curl:8.10.1 \
        --restart=Never \
        --rm -i --quiet --timeout=20s \
        --command -- curl -fsS -o /dev/null -w "%{http_code}\n" \
          --max-time 5 "${SERVICE_URL}/readyz" 2>/dev/null | grep -q '^200$'; then
    elapsed=$(( now - start ))
    echo "Backend /readyz returned 200 (took ${elapsed}s after rollout completed)"
    break
  fi

  printf "."
  sleep 5
done

echo ""
echo "=================================================================="
echo "Clean-install smoke test PASSED"
echo "  Backend tag ${BACKEND_TAG} reached Ready and served /readyz 200."
echo "=================================================================="

# Cleanup happens via trap on EXIT
exit 0
