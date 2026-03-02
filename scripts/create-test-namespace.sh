#!/usr/bin/env bash
# create-test-namespace.sh - Create an isolated Kubernetes namespace for testing
#
# Usage:
#   ./create-test-namespace.sh --run-id <id> [--backend-tag <tag>] [--web-tag <tag>] [--iac-repo <path>] [--values <file>]
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)      RUN_ID="$2"; shift 2 ;;
    --backend-tag) BACKEND_TAG="$2"; shift 2 ;;
    --web-tag)     WEB_TAG="$2"; shift 2 ;;
    --iac-repo)    IAC_REPO="$2"; shift 2 ;;
    --values)      EXTRA_VALUES="$2"; shift 2 ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: create-test-namespace.sh --run-id <id> [--backend-tag <tag>] [--web-tag <tag>] [--iac-repo <path>] [--values <file>]"
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
  CHART_DIR="${IAC_REPO}/helm"
else
  echo "Cloning artifact-keeper-iac for Helm chart..."
  TMPDIR="$(mktemp -d)"
  trap "rm -rf '$TMPDIR'" EXIT
  git clone --depth 1 https://github.com/artifact-keeper/artifact-keeper-iac.git "$TMPDIR/iac"
  CHART_DIR="${TMPDIR}/iac/helm"
fi

if [ ! -f "${CHART_DIR}/Chart.yaml" ]; then
  echo "ERROR: Helm chart not found at ${CHART_DIR}"
  exit 1
fi

# ---------------------------------------------------------------------------
# Helm install
# ---------------------------------------------------------------------------

echo "Installing Helm release: ${RELEASE_NAME}"

HELM_CMD=(helm upgrade --install "$RELEASE_NAME" "$CHART_DIR"
  --namespace "$NAMESPACE"
  --values "${REPO_ROOT}/helm/values-test.yaml"
  --set backend.image.tag="$BACKEND_TAG"
  --set web.image.tag="$WEB_TAG"
  --wait
  --timeout 10m
)

if [ -n "$EXTRA_VALUES" ]; then
  HELM_CMD+=(--values "${REPO_ROOT}/${EXTRA_VALUES}")
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
