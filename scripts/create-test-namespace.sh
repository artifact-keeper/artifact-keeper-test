#!/usr/bin/env bash
# create-test-namespace.sh - Create an isolated Kubernetes namespace for testing
#
# Usage:
#   ./create-test-namespace.sh --run-id <id> [--backend-tag <tag>] [--web-tag <tag>] [--iac-repo <path>] [--values <file>] [--full-stack]
#
# Creates namespace test-<run-id>, deploys the Helm chart with test overlays,
# and waits for the backend to become healthy.
#
# Environment variables:
#   GHCR_DOCKER_CONFIG     - Base64-encoded Docker config for ghcr.io pull secret

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

RUN_ID=""
BACKEND_TAG="dev"
WEB_TAG="dev"
IAC_REPO=""
EXTRA_VALUES=""
FULL_STACK=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)      RUN_ID="$2"; shift 2 ;;
    --backend-tag) BACKEND_TAG="$2"; shift 2 ;;
    --web-tag)     WEB_TAG="$2"; shift 2 ;;
    --iac-repo)    IAC_REPO="$2"; shift 2 ;;
    --values)      EXTRA_VALUES="$2"; shift 2 ;;
    --full-stack)  FULL_STACK=true; shift ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: create-test-namespace.sh --run-id <id> [--backend-tag <tag>] [--web-tag <tag>] [--iac-repo <path>] [--values <file>] [--full-stack]"
      exit 1
      ;;
  esac
done

if [ -z "$RUN_ID" ]; then
  echo "ERROR: --run-id is required"
  exit 1
fi

NAMESPACE="test-${RUN_ID}"
RELEASE_NAME="ak-${RUN_ID}"

echo "Creating test namespace: ${NAMESPACE}"
echo "  Backend tag: ${BACKEND_TAG}"
echo "  Web tag:     ${WEB_TAG}"

# ---------------------------------------------------------------------------
# Create namespace
# ---------------------------------------------------------------------------

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# ---------------------------------------------------------------------------
# Create image pull secret (if GHCR_DOCKER_CONFIG is set)
# ---------------------------------------------------------------------------

if [ -n "${GHCR_DOCKER_CONFIG:-}" ]; then
  echo "Creating ghcr-creds image pull secret"
  kubectl create secret docker-registry ghcr-creds \
    --namespace "$NAMESPACE" \
    --docker-server=ghcr.io \
    --from-file=.dockerconfigjson=<(echo "$GHCR_DOCKER_CONFIG" | base64 -d) \
    --dry-run=client -o yaml | kubectl apply -f -
fi

# ---------------------------------------------------------------------------
# Resolve Helm chart source
# ---------------------------------------------------------------------------

if [ -n "$IAC_REPO" ]; then
  CHART_DIR="${IAC_REPO}/charts/artifact-keeper"
else
  echo "Cloning artifact-keeper-iac for Helm chart..."
  TMPDIR="$(mktemp -d)"
  trap "rm -rf '$TMPDIR'" EXIT
  git clone --depth 1 https://github.com/artifact-keeper/artifact-keeper-iac.git "$TMPDIR/iac"
  CHART_DIR="${TMPDIR}/iac/charts/artifact-keeper"
fi

if [ ! -f "${CHART_DIR}/Chart.yaml" ]; then
  echo "ERROR: Helm chart not found at ${CHART_DIR}"
  exit 1
fi

# ---------------------------------------------------------------------------
# Storage emulators (full-stack only)
#
# The backend registers its named object-storage backends (s3, azure) at
# boot from env vars, so MinIO and Azurite must be up and their bucket/
# container provisioned BEFORE the Helm install starts the backend pod.
# values-test-full.yaml carries the matching S3_* / AZURE_STORAGE_* env.
# ---------------------------------------------------------------------------

if [ "$FULL_STACK" = true ]; then
  echo "Deploying storage emulators (MinIO, Azurite)"
  kubectl apply --namespace "$NAMESPACE" -f "${REPO_ROOT}/helm/storage-emulators.yaml"
  kubectl rollout status --namespace "$NAMESPACE" deployment/storage-minio --timeout=120s
  kubectl rollout status --namespace "$NAMESPACE" deployment/storage-azurite --timeout=120s
  kubectl wait --namespace "$NAMESPACE" --for=condition=complete \
    job/storage-minio-init job/storage-azurite-init --timeout=180s
  echo "Storage emulators ready (bucket/container provisioned)"
fi

# ---------------------------------------------------------------------------
# Helm install
# ---------------------------------------------------------------------------

echo "Installing Helm release: ${RELEASE_NAME}"

# Select base values file: --full-stack enables Trivy + scan workspace
if [ "$FULL_STACK" = true ]; then
  VALUES_FILE="${REPO_ROOT}/helm/values-test-full.yaml"
  echo "  Mode: full-stack (Trivy + scan workspace + storage emulators enabled)"
else
  VALUES_FILE="${REPO_ROOT}/helm/values-test.yaml"
fi

HELM_CMD=(helm upgrade --install "$RELEASE_NAME" "$CHART_DIR"
  --namespace "$NAMESPACE"
  --values "$VALUES_FILE"
  --set backend.image.tag="$BACKEND_TAG"
  --set web.image.tag="$WEB_TAG"
  --wait
  --timeout 10m
)

if [ -n "$EXTRA_VALUES" ]; then
  HELM_CMD+=(--values "${REPO_ROOT}/${EXTRA_VALUES}")
fi

# No Trivy DB pull credentials are injected. #298 appended a deploy-time
# GITHUB_TOKEN as scannerAdapter.env.TRIVY_USERNAME/TRIVY_PASSWORD, but a
# deploy-time-injected GITHUB_TOKEN outlives its ~1h TTL before late gate jobs
# run (pinned-cve-image-gate runs ~90min after deploy), and ghcr then rejects
# the expired credential outright ("DENIED: invalid token") with no anonymous
# fallback. The scanner-adapter pulls the public org mirror
# ghcr.io/artifact-keeper/trivy-db (values-test-full.yaml, #300/#301)
# anonymously, which needs no auth. See artifact-keeper-test#304.

"${HELM_CMD[@]}"

# ---------------------------------------------------------------------------
# Wait for backend health
# ---------------------------------------------------------------------------

BACKEND_SVC="http://artifact-keeper-backend.${NAMESPACE}.svc.cluster.local:8080"

echo "Waiting for backend to become healthy..."
"${REPO_ROOT}/tests/lib/wait-for-ready.sh" "$BACKEND_SVC" 120

# ---------------------------------------------------------------------------
# Pre-seed the scanner-adapter's Trivy vulnerability DB (artifact-keeper-test#306)
#
# ghcr throttles the cluster's ANONYMOUS token allowance during the deploy
# image-pull burst, so the scanner-adapter's first DB pull can fail with
# "DENIED: invalid token" even though the identical anonymous pull from the
# public org mirror ghcr.io/artifact-keeper/trivy-db succeeds once the burst
# subsides (verified inside the adapter image on the cluster: ~102MB in ~6s,
# anonymous, from the mirror). Rather than let a scan fail later, pull the DB
# now with retries into the pod's emptyDir cache, so scan-time trivy never
# touches the network.
#
# This lands where scans look: the adapter reads its cache dir from
# SCANNER_TRIVY_CACHE_DIR (default /home/scanner/.cache/trivy) and runs every
# scan with `--cache-dir <that dir>` (backend docker/scanner-adapter/config.go:69
# + scan.go:67/328); the download below uses the same env/default and the same
# `image --download-db-only` form as the adapter's own DownloadDB (scan.go:206).
# TRIVY_DB_REPOSITORY is read from the pod env (set from values-test-full.yaml)
# with the same priority-ordered list as a hardcoded fallback; trivy honours
# that env natively and splits it on commas into repositories tried in order.
# No credentials are involved: both entries are pulled anonymously. The list is
# upstream-first so the seeded DB is fresh -- seeding from a stale-but-reachable
# mirror is what froze the gate's DB for three weeks (artifact-keeper-test#346).
# ---------------------------------------------------------------------------
if [ "$FULL_STACK" = true ]; then
  echo "Pre-seeding scanner-adapter Trivy vulnerability DB..."
  ADAPTER_POD=$(kubectl -n "$NAMESPACE" get pods \
    -l app.kubernetes.io/component=scanner-adapter \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [ -z "$ADAPTER_POD" ]; then
    echo "ERROR: no scanner-adapter pod found (label app.kubernetes.io/component=scanner-adapter) in namespace ${NAMESPACE}" >&2
    exit 1
  fi
  db_seeded=false
  for attempt in $(seq 1 10); do
    echo "  Trivy DB preseed attempt ${attempt}/10 (pod ${ADAPTER_POD})..."
    if kubectl -n "$NAMESPACE" exec "$ADAPTER_POD" -- sh -c \
        'TRIVY_DB_REPOSITORY="${TRIVY_DB_REPOSITORY:-ghcr.io/aquasecurity/trivy-db,ghcr.io/artifact-keeper/trivy-db}" trivy image --download-db-only --cache-dir "${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}"'; then
      db_seeded=true
      echo "  Trivy DB preseed succeeded on attempt ${attempt}/10"
      break
    fi
    echo "  attempt ${attempt}/10 failed (likely ghcr anonymous-token throttling during the deploy pull burst); retrying in 30s"
    sleep 30
  done
  if [ "$db_seeded" != true ]; then
    echo "ERROR: scanner-adapter Trivy DB preseed failed after 10 attempts; ghcr anonymous-token throttling did not clear within ~5m. Image scans will fail without a cached DB. See artifact-keeper-test#306." >&2
    exit 1
  fi
fi

echo ""
echo "Test environment ready."
echo "BACKEND_URL=${BACKEND_SVC}"
