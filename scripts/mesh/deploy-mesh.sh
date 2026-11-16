#!/usr/bin/env bash
# deploy-mesh.sh - stand up the nightly mesh topology in ONE namespace
# (artifact-keeper/artifact-keeper#6120)
#
# Usage:
#   scripts/mesh/deploy-mesh.sh --namespace <ns> --backend-image <tag[@digest]>
#       [--peer-backend-image <tag[@digest]>] [--iac-ref <ref>] [--iac-dir <path>]
#
# Installs, with plain helm (no Argo), from the artifact-keeper-iac chart:
#   ak-hub    hub, the candidate image
#   ak-peer1  peer, the candidate image
#   ak-peer2  peer, the candidate image
#   ak-legacy peer, --peer-backend-image (only when given): the mixed-version case
# Each is its own release with its own Postgres StatefulSet and storage PVC,
# its own PEER_INSTANCE_NAME / PEER_PUBLIC_ENDPOINT / PEER_API_KEY and JWT
# secret (helm/values-nightly-mesh.yaml explains why that matters).
#
# Before the first install it labels the namespace and applies a
# ResourceQuota (rocky is one node that also runs production). The installs
# run in parallel and each waits for its rollout; the script then waits for
# /readyz on every backend through its Service DNS name.
#
# Writes, to $GITHUB_OUTPUT when set (and always to stdout):
#   hub_url, peer1_url, peer2_url, legacy_url (empty without a legacy peer)
#
# Exit codes: 0 ready, 1 an install or readiness wait failed, 2 usage.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VALUES="${REPO_ROOT}/helm/values-nightly-mesh.yaml"

NS=""
BACKEND_IMAGE=""
PEER_BACKEND_IMAGE=""
IAC_REF="main"
IAC_DIR=""

usage() {
  echo "Usage: $0 --namespace <ns> --backend-image <tag[@digest]> [--peer-backend-image <tag[@digest]>] [--iac-ref <ref>] [--iac-dir <path>]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)          NS="$2"; shift 2 ;;
    --backend-image)      BACKEND_IMAGE="$2"; shift 2 ;;
    --peer-backend-image) PEER_BACKEND_IMAGE="$2"; shift 2 ;;
    --iac-ref)            IAC_REF="$2"; shift 2 ;;
    --iac-dir)            IAC_DIR="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$NS" ] && [ -n "$BACKEND_IMAGE" ] || usage

# Inputs reach helm --set and kubectl: hold them to the gate's shapes.
name_re='^[A-Za-z0-9._/-]{1,128}$'
image_re='^[A-Za-z0-9._-]{1,128}(@sha256:[0-9a-f]{64})?$'
ns_re='^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'
[[ "$NS" =~ $ns_re ]] || { echo "ERROR: bad namespace '${NS}'" >&2; exit 2; }
[[ "$BACKEND_IMAGE" =~ $image_re ]] || { echo "ERROR: bad --backend-image '${BACKEND_IMAGE}'" >&2; exit 2; }
if [ -n "$PEER_BACKEND_IMAGE" ] && ! [[ "$PEER_BACKEND_IMAGE" =~ $image_re ]]; then
  echo "ERROR: bad --peer-backend-image '${PEER_BACKEND_IMAGE}'" >&2; exit 2
fi
[[ "$IAC_REF" =~ $name_re ]] || { echo "ERROR: bad --iac-ref '${IAC_REF}'" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Chart source: artifact-keeper-iac at IAC_REF, as create-test-namespace.sh
# and the gate's deploy job clone it.
# ---------------------------------------------------------------------------
if [ -z "$IAC_DIR" ]; then
  IAC_DIR="$(mktemp -d)/iac"
  git clone --quiet --depth 1 --branch "$IAC_REF" \
    https://github.com/artifact-keeper/artifact-keeper-iac.git "$IAC_DIR"
fi
CHART_DIR="${IAC_DIR}/charts/artifact-keeper"
[ -f "${CHART_DIR}/Chart.yaml" ] || { echo "ERROR: no chart at ${CHART_DIR}" >&2; exit 1; }
echo "Chart: artifact-keeper-iac@${IAC_REF} ($(git -C "$IAC_DIR" rev-parse --short HEAD 2>/dev/null || echo local))"

# ---------------------------------------------------------------------------
# Namespace + quota
#
# The quota caps what this lane can take from the node. Peak requests with
# four instances: 4 x (backend 100m/192Mi + postgres 50m/128Mi + the
# backend's wait-for-postgres init 10m/16Mi, which does not overlap the main
# containers) = 600m CPU / 1280Mi requested, and 6 CPU / 6Gi of limits
# (backend 1/1Gi + postgres 500m/512Mi each). The cap leaves headroom for a
# rollout restart, and the limits cap is what bounds a runaway on the
# production node. Every rendered container sets both, and ephemeral
# containers are not counted, so the fault-injection container is unaffected.
# ---------------------------------------------------------------------------
# The runner may create and delete namespaces but not patch them, so the
# labels (which teardown's stale sweep selects on) go on at creation.
if ! kubectl get namespace "$NS" -o name >/dev/null 2>&1; then
  kubectl create -f - >/dev/null <<NSYAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS}
  labels:
    app.kubernetes.io/part-of: artifact-keeper-test
    artifact-keeper.io/lane: nightly-mesh
NSYAML
fi

kubectl apply -n "$NS" -f - <<'QUOTA'
apiVersion: v1
kind: ResourceQuota
metadata:
  name: nightly-mesh-cap
spec:
  hard:
    requests.cpu: "1500m"
    requests.memory: 3Gi
    limits.cpu: "8"
    limits.memory: 8Gi
    requests.storage: 12Gi
    persistentvolumeclaims: "10"
    pods: "16"
    services: "16"
QUOTA
# Until the quota controller has computed status.hard, admission refuses
# every pod, PVC and Service in the namespace ("status unknown for quota").
kubectl -n "$NS" wait --for=jsonpath='{.status.hard.pods}'=16 \
  resourcequota/nightly-mesh-cap --timeout=60s >/dev/null

# ---------------------------------------------------------------------------
# Installs (parallel)
# ---------------------------------------------------------------------------
LOG_DIR="${RUNNER_TEMP:-/tmp}/mesh-deploy-logs"
mkdir -p "$LOG_DIR"

install_one() {
  local release="$1" image="$2" instance="$3"
  local endpoint="http://${release}-backend.${NS}.svc.cluster.local:8080"
  local jwt peer_key
  jwt="$(openssl rand -base64 48 | tr -d '\n')"
  peer_key="$(openssl rand -hex 24)"
  helm upgrade --install "$release" "$CHART_DIR" \
    --namespace "$NS" \
    --values "$VALUES" \
    --set-string fullnameOverride="$release" \
    --set-string backend.image.tag="$image" \
    --set-string backend.env.PEER_INSTANCE_NAME="$instance" \
    --set-string backend.env.PEER_PUBLIC_ENDPOINT="$endpoint" \
    --set-string backend.env.PEER_API_KEY="$peer_key" \
    --set-string secrets.jwtSecret="$jwt" \
    --wait --timeout 10m
}

RELEASES=(ak-hub ak-peer1 ak-peer2)
IMAGES=("$BACKEND_IMAGE" "$BACKEND_IMAGE" "$BACKEND_IMAGE")
INSTANCES=(mesh-hub mesh-peer1 mesh-peer2)
if [ -n "$PEER_BACKEND_IMAGE" ]; then
  RELEASES+=(ak-legacy); IMAGES+=("$PEER_BACKEND_IMAGE"); INSTANCES+=(mesh-legacy)
fi

declare -A PIDS=()
for i in "${!RELEASES[@]}"; do
  r="${RELEASES[$i]}"
  echo "Installing ${r} (backend ${IMAGES[$i]})"
  install_one "$r" "${IMAGES[$i]}" "${INSTANCES[$i]}" > "${LOG_DIR}/${r}.log" 2>&1 &
  PIDS[$r]=$!
done

failed=0
for r in "${RELEASES[@]}"; do
  if wait "${PIDS[$r]}"; then
    echo "  ${r}: installed"
  else
    echo "::error::helm install of ${r} failed"
    sed 's/^/    | /' "${LOG_DIR}/${r}.log"
    failed=1
  fi
done

if [ "$failed" -ne 0 ]; then
  kubectl -n "$NS" get pods -o wide || true
  kubectl -n "$NS" get events --sort-by=.lastTimestamp | tail -40 || true
  kubectl -n "$NS" describe resourcequota nightly-mesh-cap || true
  exit 1
fi

# ---------------------------------------------------------------------------
# Readiness through Service DNS (what peers and tests use)
# ---------------------------------------------------------------------------
for r in "${RELEASES[@]}"; do
  "${REPO_ROOT}/tests/lib/wait-for-ready.sh" "http://${r}-backend.${NS}.svc.cluster.local:8080" 180
done

kubectl -n "$NS" get pods -o wide
kubectl -n "$NS" describe resourcequota nightly-mesh-cap | sed -n '/Resource/,$p'

url() { printf 'http://%s-backend.%s.svc.cluster.local:8080' "$1" "$NS"; }
{
  echo "hub_url=$(url ak-hub)"
  echo "peer1_url=$(url ak-peer1)"
  echo "peer2_url=$(url ak-peer2)"
  if [ -n "$PEER_BACKEND_IMAGE" ]; then echo "legacy_url=$(url ak-legacy)"; else echo "legacy_url="; fi
} | tee -a "${GITHUB_OUTPUT:-/dev/null}"
