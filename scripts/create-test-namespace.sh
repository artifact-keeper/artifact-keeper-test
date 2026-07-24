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
#   GHCR_DOCKER_CONFIG       - Base64-encoded Docker config for ghcr.io pull secret
#   SCANNER_TRIVY_PULL_TOKEN - Optional. When set (and --full-stack), injected as
#                              scannerAdapter.env.TRIVY_USERNAME/TRIVY_PASSWORD via
#                              helm --set-string so the scanner-adapter's in-process
#                              Trivy authenticates its ghcr vuln-DB pull (#293).
#                              Never written to a values file.

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

# Authenticated Trivy DB pull for the scanner-adapter (artifact-keeper-test#293).
# The scanner-adapter's in-process Trivy pulls its vuln DB from ghcr; when the
# Trivy SERVER has already pulled anonymously from the same ghcr endpoint, ghcr
# denies the adapter's anonymous token, so the adapter needs its own
# credentials. The token is injected here from the environment (SCANNER_TRIVY_-
# PULL_TOKEN, set by the workflow) and NEVER stored in a values file. helm
# --set deep-merges per key with the -f values file, and the chart's
# scanner-adapter-deployment.yaml ranges over the whole scannerAdapter.env map,
# so the TRIVY_DB_REPOSITORY / SCANNER_TRIVY_INSECURE keys already in
# values-test-full.yaml survive. --set-string forces the token to a string and
# is appended last so it wins over any values-file key. Other callers that do
# not set the token env simply get no injection (no-op).
if [ -n "${SCANNER_TRIVY_PULL_TOKEN:-}" ]; then
  HELM_CMD+=(
    --set-string scannerAdapter.env.TRIVY_USERNAME=x-access-token
    --set-string "scannerAdapter.env.TRIVY_PASSWORD=${SCANNER_TRIVY_PULL_TOKEN}"
  )
fi

"${HELM_CMD[@]}"

# ---------------------------------------------------------------------------
# Wait for backend health
# ---------------------------------------------------------------------------

BACKEND_SVC="http://artifact-keeper-backend.${NAMESPACE}.svc.cluster.local:8080"

echo "Waiting for backend to become healthy..."
"${REPO_ROOT}/tests/lib/wait-for-ready.sh" "$BACKEND_SVC" 120

echo ""
echo "Test environment ready."
echo "BACKEND_URL=${BACKEND_SVC}"
