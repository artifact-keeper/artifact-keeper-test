#!/usr/bin/env bash
# deploy-s3-formats-namespace.sh - the nightly S3 format matrix's one namespace
# (artifact-keeper#6121): MinIO from helm/storage-emulators.yaml, then the
# chart with values-test-full.yaml + values-nightly-s3.yaml, whose
# STORAGE_BACKEND=s3 makes MinIO the backend's DEFAULT storage.
#
# It follows create-test-namespace.sh --full-stack (emulators up and the bucket
# provisioned BEFORE the backend boots, since the backend builds its storage
# at startup) with three differences: the namespace gets a ResourceQuota
# first, only MinIO is applied (Azurite is not wired to the backend, see
# storage-emulators.yaml), and the stack is the lean overlay (no web, Trivy,
# scanner adapter or Dependency-Track, so no Trivy DB preseed).
#
# Usage: deploy-s3-formats-namespace.sh --run-id <id> --backend-tag <tag[@digest]> [--iac-ref <ref>]
# Env:   GHCR_DOCKER_CONFIG (optional, base64 docker config for ghcr.io),
#        AK_TEST_SSRF_ALLOW_PRIVATE_CIDRS (optional, as in create-test-namespace.sh)
# Namespace test-<id>, release ak-<id>: the names teardown-test-namespace.sh removes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RUN_ID="" BACKEND_TAG="" IAC_REF="main"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)      RUN_ID="$2"; shift 2 ;;
    --backend-tag) BACKEND_TAG="$2"; shift 2 ;;
    --iac-ref)     IAC_REF="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$RUN_ID" && -n "$BACKEND_TAG" ]] || { echo "usage: $0 --run-id <id> --backend-tag <tag> [--iac-ref <ref>]" >&2; exit 2; }

NAMESPACE="test-${RUN_ID}"
RELEASE_NAME="ak-${RUN_ID}"

# Requests budget for the whole namespace. The stack requests about 0.5 CPU and
# 1.1 Gi (backend 100m/256Mi, Postgres 100m/128Mi, OpenSearch 100m/512Mi,
# MinIO 50m/128Mi, init containers and the proof pods 10m each); the quota
# leaves room for a rolling restart but stops a mis-sized overlay from taking
# the shared node. Limits are not capped: they are what lets a suite burst.
QUOTA_CPU="${S3_LANE_QUOTA_CPU:-1500m}"
QUOTA_MEM="${S3_LANE_QUOTA_MEMORY:-3Gi}"
QUOTA_PODS="${S3_LANE_QUOTA_PODS:-15}"

echo "Creating ${NAMESPACE} (backend ${BACKEND_TAG}, iac ${IAC_REF}, default storage s3)"
# Labels go in at create time: the runner's ClusterRole cannot patch namespaces.
kubectl apply -f - <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
  labels:
    app.kubernetes.io/part-of: artifact-keeper-test
    ak-test/lane: nightly-s3-formats
YAML

kubectl apply -n "$NAMESPACE" -f - <<YAML
apiVersion: v1
kind: ResourceQuota
metadata:
  name: nightly-s3-formats
spec:
  hard:
    requests.cpu: "${QUOTA_CPU}"
    requests.memory: "${QUOTA_MEM}"
    pods: "${QUOTA_PODS}"
YAML

if [[ -n "${GHCR_DOCKER_CONFIG:-}" ]]; then
  kubectl create secret docker-registry ghcr-creds --namespace "$NAMESPACE" \
    --docker-server=ghcr.io \
    --from-file=.dockerconfigjson=<(echo "$GHCR_DOCKER_CONFIG" | base64 -d) \
    --dry-run=client -o yaml | kubectl apply -f -
fi

# MinIO only: the documents of storage-emulators.yaml whose metadata.name is
# storage-minio (Deployment, Service) or storage-minio-init (Job).
echo "Deploying MinIO (bucket ak-e2e)"
awk 'function flush(){ if (doc ~ /\nmetadata:\n  name: storage-minio(-init)?\n/) printf "---\n%s", doc; doc="" }
     /^---[[:space:]]*$/ { flush(); next }
     { doc = doc $0 "\n" }
     END { flush() }' "${REPO_ROOT}/helm/storage-emulators.yaml" \
  | kubectl apply --namespace "$NAMESPACE" -f -
kubectl rollout status --namespace "$NAMESPACE" deployment/storage-minio --timeout=180s
kubectl wait --namespace "$NAMESPACE" --for=condition=complete job/storage-minio-init --timeout=180s

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
git clone -q --depth 1 --branch "$IAC_REF" https://github.com/artifact-keeper/artifact-keeper-iac.git "$TMP/iac" 2>/dev/null \
  || { git clone -q https://github.com/artifact-keeper/artifact-keeper-iac.git "$TMP/iac" && git -C "$TMP/iac" checkout -q "$IAC_REF"; }
CHART_DIR="$TMP/iac/charts/artifact-keeper"
[[ -f "$CHART_DIR/Chart.yaml" ]] || { echo "ERROR: no chart at ${CHART_DIR}" >&2; exit 1; }

HELM_CMD=(helm upgrade --install "$RELEASE_NAME" "$CHART_DIR"
  --namespace "$NAMESPACE"
  --values "${REPO_ROOT}/helm/values-test-full.yaml"
  --values "${REPO_ROOT}/helm/values-nightly-s3.yaml"
  --set backend.image.tag="$BACKEND_TAG"
  --wait --timeout 10m)
if [[ -n "${AK_TEST_SSRF_ALLOW_PRIVATE_CIDRS:-}" ]]; then
  HELM_CMD+=(--set-string "backend.env.AK_SSRF_ALLOW_PRIVATE_CIDRS=${AK_TEST_SSRF_ALLOW_PRIVATE_CIDRS//,/\\,}")
fi
"${HELM_CMD[@]}"

"${REPO_ROOT}/tests/lib/wait-for-ready.sh" "http://artifact-keeper-backend.${NAMESPACE}.svc.cluster.local:8080" 180

# The env the backend actually runs with, not the values file's intent.
got=$(kubectl -n "$NAMESPACE" get deploy artifact-keeper-backend \
  -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' | grep -E '^STORAGE_BACKEND=' || true)
[[ "$got" == "STORAGE_BACKEND=s3" ]] || { echo "ERROR: backend runs with '${got:-no STORAGE_BACKEND}', want STORAGE_BACKEND=s3" >&2; exit 1; }
# Read the log into a variable first: `kubectl logs | grep -q` under pipefail
# fails when grep exits early and kubectl takes SIGPIPE.
boot_log=$(kubectl -n "$NAMESPACE" logs deploy/artifact-keeper-backend --tail=-1 2>/dev/null || true)
if ! grep -q 'S3 storage backend initialized' <<<"$boot_log"; then
  echo "ERROR: the backend log has no 'S3 storage backend initialized' line" >&2
  exit 1
fi

kubectl -n "$NAMESPACE" describe resourcequota nightly-s3-formats
echo "BACKEND_URL=http://artifact-keeper-backend.${NAMESPACE}.svc.cluster.local:8080"
