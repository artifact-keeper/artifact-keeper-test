#!/usr/bin/env bash
# chart-upgrade-smoke.sh - In-place chart upgrade smoke (issue #54)
#
# Installs the previous stable release tag, pushes a small artifact
# through the management API to establish state, runs `helm upgrade`
# to the current backend image, then asserts:
#   - the upgrade completes within the timeout
#   - the previously-pushed artifact is still retrievable
#   - /readyz returns 200 (covers post-upgrade migration health)
#
# Usage:
#   ./chart-upgrade-smoke.sh \
#       --run-id <id> \
#       --previous-tag <tag> \
#       --backend-tag <tag> \
#       [--web-tag <tag>] \
#       [--iac-ref <ref>] \
#       [--timeout <seconds>]
#
# Exit codes:
#   0 - upgrade succeeded, state preserved, /readyz 200
#   1 - usage / install / upgrade failed
#   2 - rollout did not complete within timeout
#   3 - /readyz did not return 200 after upgrade
#   4 - artifact pushed before upgrade is no longer retrievable

set -euo pipefail

RUN_ID=""
PREVIOUS_TAG=""
BACKEND_TAG=""
WEB_TAG="dev"
IAC_REF="main"
TIMEOUT_SECONDS=600

CHART_TMPDIR=""
GHCR_CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)        RUN_ID="${2:-}"; shift 2 ;;
    --previous-tag)  PREVIOUS_TAG="${2:-}"; shift 2 ;;
    --backend-tag)   BACKEND_TAG="${2:-}"; shift 2 ;;
    --web-tag)       WEB_TAG="${2:-}"; shift 2 ;;
    --iac-ref)       IAC_REF="${2:-}"; shift 2 ;;
    --timeout)       TIMEOUT_SECONDS="${2:-}"; shift 2 ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "$RUN_ID" ] || [ -z "$BACKEND_TAG" ] || [ -z "$PREVIOUS_TAG" ]; then
  echo "ERROR: --run-id, --backend-tag, --previous-tag are required" >&2
  exit 1
fi

# Strip leading v if a caller passed a raw git tag. Docker tags drop
# the prefix per CLAUDE.md "Docker tags use semver without v".
PREVIOUS_TAG="${PREVIOUS_TAG#v}"
BACKEND_TAG="${BACKEND_TAG#v}"

NAMESPACE="smoke-upgrade-${RUN_ID}"
RELEASE_NAME="ak-upgrade-${RUN_ID}"
ADMIN_USER="admin"
ADMIN_PASS="ChartUp!2026secure"

echo "=================================================================="
echo "Chart upgrade smoke (issue #54)"
echo "  Namespace:        ${NAMESPACE}"
echo "  Release:          ${RELEASE_NAME}"
echo "  Previous tag:     ${PREVIOUS_TAG}"
echo "  Current tag:      ${BACKEND_TAG}"
echo "  Web tag:          ${WEB_TAG}"
echo "  Timeout:          ${TIMEOUT_SECONDS}s"
echo "  iac ref:          ${IAC_REF}"
echo "=================================================================="

# shellcheck disable=SC2329
cleanup() {
  local exit_code=$?
  echo ""
  echo "Teardown: removing ${NAMESPACE}"
  if [ "$exit_code" -ne 0 ]; then
    LOGS_DIR="/tmp/test-logs/upgrade-${RUN_ID}"
    if mkdir -p "$LOGS_DIR" 2>/dev/null; then
      kubectl get pods -n "$NAMESPACE" -o wide > "${LOGS_DIR}/pods.txt" 2>/dev/null || true
      kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' \
        > "${LOGS_DIR}/events.txt" 2>/dev/null || true
      kubectl describe pods -n "$NAMESPACE" > "${LOGS_DIR}/describe.txt" 2>/dev/null || true
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
# Resolve the iac chart. We use the same iac ref for both install and
# upgrade: the chart-template change being validated is what the
# release pipeline ships, not a hypothetical bisect across chart
# refs. If a release ever needs to upgrade a chart from ref-A to
# ref-B, that's a separate flow.
# -----------------------------------------------------------------------

CHART_TMPDIR="$(mktemp -d)"
echo ""
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
# Common helm overrides. Minimal, single-replica, in-cluster postgres.
# Use the same shape as scripts/clean-install-smoke.sh so the upgrade
# trajectory matches what we already exercise for fresh installs.
# -----------------------------------------------------------------------

HELM_BASE_OVERRIDES=(
  --set fullnameOverride=ak-upgrade
  --set "backend.env.ADMIN_PASSWORD=${ADMIN_PASS}"
  --set backend.replicaCount=1
  --set web.replicaCount=1
  --set secrets.jwtSecret="upgrade-jwt-secret-not-for-production"
  --set postgres.enabled=true
  --set "postgres.auth.username=registry"
  --set "postgres.auth.password=upgrade-db-password"
  --set "postgres.auth.database=artifact_registry"
  --set externalDatabase.host=""
  --set externalDatabase.existingSecret=""
  --set externalSecrets.enabled=false
  --set ingress.enabled=false
  --set serviceMonitor.enabled=false
  --set "backend.autoscaling.enabled=false"
  --set "backend.podDisruptionBudget.enabled=false"
  --set "web.podDisruptionBudget.enabled=false"
  --set edge.enabled=false
  --set trivy.enabled=false
  --set dependencyTrack.enabled=false
  --set networkPolicy.enabled=false
  --set opensearch.replicaCount=1
  --set opensearch.persistence.enabled=false
  --set 'opensearch.javaOpts=-Xms512m -Xmx512m'
  --set 'opensearch.resources.requests.memory=1Gi'
  --set 'opensearch.resources.limits.memory=1Gi'
  --set 'meilisearch.masterKey=ak-upgrade-meilisearch-test-master-key'
)

# -----------------------------------------------------------------------
# Step 1: install the previous tag
# -----------------------------------------------------------------------

PROD_VALUES="${CHART_DIR}/values-production.yaml"
if [ ! -f "$PROD_VALUES" ]; then
  echo "ERROR: values-production.yaml not found at ${PROD_VALUES}" >&2
  exit 1
fi

echo ""
echo "Step 1: helm install previous tag ${PREVIOUS_TAG}"
helm upgrade --install "$RELEASE_NAME" "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  --values "$PROD_VALUES" \
  --set backend.image.tag="$PREVIOUS_TAG" \
  --set web.image.tag="$PREVIOUS_TAG" \
  "${HELM_BASE_OVERRIDES[@]}" \
  --wait=false || {
    echo "ERROR: helm install (previous tag) failed" >&2
    exit 1
  }

echo "Waiting for backend rollout..."
kubectl wait --for=condition=Available deployment/ak-upgrade-backend \
  -n "$NAMESPACE" --timeout="${TIMEOUT_SECONDS}s" || exit 2
kubectl wait --for=condition=Available deployment/ak-upgrade-web \
  -n "$NAMESPACE" --timeout="${TIMEOUT_SECONDS}s" || exit 2

# Probe /readyz to confirm the previous-tag stack is fully usable
# before we put state into it.
SERVICE_URL="http://ak-upgrade-backend.${NAMESPACE}.svc.cluster.local:8080"
BACKEND_POD=$(kubectl get pods -n "$NAMESPACE" \
  -l "app.kubernetes.io/component=backend" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -z "$BACKEND_POD" ]; then
  echo "ERROR: no backend pod found after install" >&2
  exit 3
fi

probe_readyz() {
  local timeout="${1:-180}"
  local elapsed=0
  while [ "$elapsed" -lt "$timeout" ]; do
    if out=$(kubectl exec -n "$NAMESPACE" "$BACKEND_POD" -- \
        sh -c "curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 ${SERVICE_URL}/readyz \
               || wget -q --timeout=5 -O - --server-response ${SERVICE_URL}/readyz 2>&1 \
                  | grep -i 'HTTP/'" 2>&1); then
      if echo "$out" | grep -qE '\b200\b'; then
        return 0
      fi
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  return 1
}

echo ""
echo "Probing /readyz on previous-tag stack"
if ! probe_readyz 180; then
  echo "ERROR: /readyz did not return 200 on previous-tag stack" >&2
  exit 3
fi

# -----------------------------------------------------------------------
# Step 2: push state through the management API
#
# We use the generic artifact handler (POST /api/v1/repositories/.../upload)
# rather than a format-native client to keep this script free of
# format-tool installation. The goal is "did the upgrade preserve
# state", not "did the npm protocol survive an upgrade". Format-
# specific upgrade verification is a future enhancement.
# -----------------------------------------------------------------------

PORT_FORWARD_PID=""
# shellcheck disable=SC2329
stop_port_forward() {
  if [ -n "$PORT_FORWARD_PID" ]; then
    kill "$PORT_FORWARD_PID" 2>/dev/null || true
    PORT_FORWARD_PID=""
  fi
}

echo ""
echo "Step 2: push artifact to establish state"

# Port-forward to the backend so we can call the management API from
# this runner. The 18080:8080 mapping avoids collision with whatever
# other workflows on the same runner have bound to 8080.
LOCAL_PORT="18080"
kubectl port-forward -n "$NAMESPACE" "svc/ak-upgrade-backend" \
  "${LOCAL_PORT}:8080" >/tmp/upgrade-pf.log 2>&1 &
PORT_FORWARD_PID=$!
# Give port-forward time to bind. The first request after the bg
# spawn races the listen.
sleep 5

trap "stop_port_forward; cleanup" EXIT

BASE_URL="http://127.0.0.1:${LOCAL_PORT}"

# Auth as admin. Retry: the previous-tag backend just finished its
# readyz check but may still settle the rate-limiter window for a
# brief moment.
TOKEN=""
for i in 1 2 3 4 5; do
  resp=$(curl -sf --max-time 10 \
    -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    2>/dev/null || echo "")
  TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty' 2>/dev/null || echo "")
  if [ -n "$TOKEN" ]; then
    break
  fi
  echo "  auth attempt ${i}/5 failed, retrying..."
  sleep 5
done

if [ -z "$TOKEN" ]; then
  echo "ERROR: could not authenticate on previous-tag backend" >&2
  exit 1
fi

REPO_KEY="upgrade-state-${RUN_ID}"
ARTIFACT_NAME="upgrade-state.txt"
ARTIFACT_BODY="hello from previous-tag at $(date -u +%FT%TZ)"

# Create a generic repo
curl -sf --max-time 15 \
  -X POST "${BASE_URL}/api/v1/repositories" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" \
  >/dev/null || {
    echo "ERROR: could not create repository on previous-tag backend" >&2
    exit 1
  }

# Push the artifact via the generic format endpoint
PUSH_PATH="/generic/${REPO_KEY}/${ARTIFACT_NAME}"
push_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
  -X PUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "${ARTIFACT_BODY}" \
  "${BASE_URL}${PUSH_PATH}" 2>/dev/null || echo "000")

if [ "$push_status" != "200" ] && [ "$push_status" != "201" ] && [ "$push_status" != "204" ]; then
  echo "ERROR: artifact push returned HTTP ${push_status}" >&2
  exit 1
fi
echo "  pushed ${PUSH_PATH} (HTTP ${push_status})"

# Sanity: confirm we can pull it before the upgrade (so a post-
# upgrade failure indicates the upgrade, not the initial push).
pulled_body=$(curl -sf --max-time 15 \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${BASE_URL}${PUSH_PATH}" 2>/dev/null || echo "")
if [ "$pulled_body" != "$ARTIFACT_BODY" ]; then
  echo "ERROR: pre-upgrade pull did not match push body" >&2
  echo "  expected: ${ARTIFACT_BODY}"
  echo "  got:      ${pulled_body}"
  exit 1
fi

stop_port_forward

# -----------------------------------------------------------------------
# Step 3: helm upgrade to the current tag
# -----------------------------------------------------------------------

echo ""
echo "Step 3: helm upgrade to ${BACKEND_TAG}"
helm upgrade "$RELEASE_NAME" "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  --values "$PROD_VALUES" \
  --set backend.image.tag="$BACKEND_TAG" \
  --set web.image.tag="$WEB_TAG" \
  "${HELM_BASE_OVERRIDES[@]}" \
  --wait=false || {
    echo "ERROR: helm upgrade failed" >&2
    exit 1
  }

# Watch for any pod stuck in Pending for >30s (the #54 acceptance
# criterion about resource that get re-created instead of preserved).
echo ""
echo "Watching for Pending pods >30s during upgrade window..."
STUCK_AT=""
WATCH_START=$(date +%s)
WATCH_DEADLINE=$((WATCH_START + TIMEOUT_SECONDS))
while [ "$(date +%s)" -lt "$WATCH_DEADLINE" ]; do
  pending_pods=$(kubectl get pods -n "$NAMESPACE" \
    --field-selector=status.phase=Pending \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}' 2>/dev/null || true)
  if [ -z "$pending_pods" ]; then
    STUCK_AT=""
    # No pending pods; check rollout completion.
    if kubectl rollout status deployment/ak-upgrade-backend \
        -n "$NAMESPACE" --timeout=10s >/dev/null 2>&1; then
      echo "  backend rollout completed"
      break
    fi
  else
    if [ -z "$STUCK_AT" ]; then
      STUCK_AT=$(date +%s)
      echo "  Pending pods first seen: ${pending_pods}"
    else
      now=$(date +%s)
      if [ $((now - STUCK_AT)) -gt 30 ]; then
        echo "ERROR: pods stayed Pending >30s during upgrade: ${pending_pods}" >&2
        exit 2
      fi
    fi
  fi
  sleep 5
done

# Final rollout check (web + backend).
kubectl wait --for=condition=Available deployment/ak-upgrade-backend \
  -n "$NAMESPACE" --timeout="${TIMEOUT_SECONDS}s" || exit 2
kubectl wait --for=condition=Available deployment/ak-upgrade-web \
  -n "$NAMESPACE" --timeout="${TIMEOUT_SECONDS}s" || exit 2

# -----------------------------------------------------------------------
# Step 4: probe /readyz on the upgraded stack
# -----------------------------------------------------------------------

echo ""
echo "Step 4: probe /readyz post-upgrade"
# Re-resolve backend pod (rollout may have rotated it).
BACKEND_POD=$(kubectl get pods -n "$NAMESPACE" \
  -l "app.kubernetes.io/component=backend" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -z "$BACKEND_POD" ]; then
  echo "ERROR: no backend pod found after upgrade" >&2
  exit 3
fi

if ! probe_readyz 180; then
  echo "ERROR: /readyz did not return 200 after upgrade" >&2
  exit 3
fi

# -----------------------------------------------------------------------
# Step 5: confirm the artifact pushed at step 2 is still retrievable.
#
# This indirectly verifies:
#   - DB migrations applied (artifact metadata table survived)
#   - Storage path didn't change (the file blob is still where the
#     backend looks for it)
#   - The deserialization path for older rows still works
# -----------------------------------------------------------------------

echo ""
echo "Step 5: verify pre-upgrade artifact survives"
kubectl port-forward -n "$NAMESPACE" "svc/ak-upgrade-backend" \
  "${LOCAL_PORT}:8080" >/tmp/upgrade-pf2.log 2>&1 &
PORT_FORWARD_PID=$!
sleep 5

pulled_body=$(curl -sf --max-time 15 \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${BASE_URL}${PUSH_PATH}" 2>/dev/null || echo "")
if [ "$pulled_body" != "$ARTIFACT_BODY" ]; then
  echo "ERROR: post-upgrade pull did not match pre-upgrade push body" >&2
  echo "  expected: ${ARTIFACT_BODY}"
  echo "  got:      ${pulled_body}"
  exit 4
fi
echo "  pre-upgrade artifact still retrievable (state preserved)"

# -----------------------------------------------------------------------
# Step 6: confirm a migration-touched endpoint works
#
# /api/v1/health/details (or /health) returns a JSON payload that
# depends on the latest schema (notably the migrations table being
# queryable). If a migration failed mid-upgrade, this would 500.
# -----------------------------------------------------------------------

echo ""
echo "Step 6: probe a schema-dependent endpoint"
schema_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo "000")
if [ "$schema_status" != "200" ]; then
  echo "ERROR: /api/v1/repositories returned HTTP ${schema_status} (migration regression?)" >&2
  exit 4
fi
echo "  /api/v1/repositories returns HTTP 200 (schema healthy)"

stop_port_forward

echo ""
echo "=================================================================="
echo "Chart upgrade smoke PASSED"
echo "  Upgrade from ${PREVIOUS_TAG} to ${BACKEND_TAG} preserved state."
echo "=================================================================="
exit 0
