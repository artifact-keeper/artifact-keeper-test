#!/usr/bin/env bash
# clean-install-smoke.sh - Clean-cluster Helm install smoke test
#
# Usage:
#   ./clean-install-smoke.sh --run-id <id> --backend-tag <tag> [--web-tag <tag>] \
#       [--iac-repo <path>] [--iac-ref <git-ref>] [--timeout <seconds>] \
#       [--keep-namespace] [--expect-failure]
#
# Boots a fresh namespace, performs `helm install` against the documented
# values-production.yaml (with test-only secret overrides), waits for the
# backend AND web Deployments to reach Ready, then probes `/readyz` from
# inside the cluster until 200.
#
# This gate exists to catch startup panics (e.g. the v1.1.8 Debian route
# panic) that crash the backend before it can serve traffic. If any
# Deployment never reaches Ready in the window, the script exits non-zero
# and the release-gate fails.
#
# What this gate is NOT:
#   - It is NOT a search/scan/format/auth E2E (those live in matrix jobs).
#   - It does NOT exercise ingress, externalDatabase, externalSecrets,
#     openSCAP, edge, dependencyTrack, or trivy. Those are disabled via
#     overrides so the smoke focuses on backend+web startup. Coverage of
#     those subsystems is the role of `clean-install-smoke-with-deps`
#     (filed as a follow-up).
#   - It does NOT exercise OpenSearch in production-shape (3-replica
#     StatefulSet with 3x 50Gi PVCs). Production OpenSearch is exercised
#     by the search-tests matrix job.
#
# Exit codes:
#   0  All Deployments Ready, /readyz returns 200, smoke passed
#   1  Usage error, missing arg, or helm install failed
#   2  Rollout did not complete within timeout (CrashLoopBackOff,
#      ImagePullBackOff, etc.)
#   3  /readyz did not return 200 within timeout
#   4  Self-test mode: gate did NOT fail when --expect-failure was set
#      (used by the smoke meta-test that pins the gate's semantics)
#   11 INFRA: the in-cluster /readyz probe could not be set up (the
#      ephemeral probe pod could not be created or did not become Ready
#      within the budget, after one retry on an image-pull failure). The
#      candidate was never probed, so this is NOT a product verdict. Same
#      number as the DTF's INFRA/SETUP code (deploy-test/harness/lib/
#      exit_codes.sh). Under --expect-failure it is passed through, not
#      counted as the gate rejecting the fixture.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

RUN_ID=""
BACKEND_TAG=""
WEB_TAG="dev"
IAC_REPO=""
IAC_REF="main"
TIMEOUT_SECONDS=300
KEEP_NAMESPACE=false
EXPECT_FAILURE=false

# Exit code for "the probe could not be set up" (see the table above).
SMOKE_EXIT_INFRA=11

# Image for the ephemeral /readyz probe pod, used only when the backend image
# has neither wget nor curl. It is the ghcr.io/artifact-keeper/ci-mirror copy of
# docker.io/library/alpine:3.24 (byte-identical multi-arch index), pinned by
# digest: reproducible, and not exposed to Docker Hub pull latency or rate
# limits the way the old unpinned curlimages/curl:8.10.1 tag was
# (artifact-keeper-test#835). Busybox wget does the probe.
PROBE_IMAGE="${SMOKE_PROBE_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf}"

# Track resources to clean up. Set after first use.
CHART_TMPDIR=""
GHCR_CONFIG_FILE=""

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

require_value() {
  local flag="$1"
  local value="${2:-}"
  if [ -z "$value" ]; then
    echo "ERROR: $flag requires a value" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)         require_value "$1" "${2:-}"; RUN_ID="$2"; shift 2 ;;
    --backend-tag)    require_value "$1" "${2:-}"; BACKEND_TAG="$2"; shift 2 ;;
    --web-tag)        require_value "$1" "${2:-}"; WEB_TAG="$2"; shift 2 ;;
    --iac-repo)       require_value "$1" "${2:-}"; IAC_REPO="$2"; shift 2 ;;
    --iac-ref)        require_value "$1" "${2:-}"; IAC_REF="$2"; shift 2 ;;
    --timeout)        require_value "$1" "${2:-}"; TIMEOUT_SECONDS="$2"; shift 2 ;;
    --keep-namespace) KEEP_NAMESPACE=true; shift ;;
    --expect-failure) EXPECT_FAILURE=true; shift ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: clean-install-smoke.sh --run-id <id> --backend-tag <tag> [--web-tag <tag>] [--iac-repo <path>] [--iac-ref <git-ref>] [--timeout <seconds>] [--keep-namespace] [--expect-failure]" >&2
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
echo "  Namespace:        ${NAMESPACE}"
echo "  Release:          ${RELEASE_NAME}"
echo "  Backend tag:      ${BACKEND_TAG}"
echo "  Web tag:          ${WEB_TAG}"
echo "  Timeout:          ${TIMEOUT_SECONDS}s"
echo "  iac ref:          ${IAC_REF}"
echo "  Expect failure:   ${EXPECT_FAILURE}"
echo "=================================================================="

# ---------------------------------------------------------------------------
# Diagnostic helpers
# ---------------------------------------------------------------------------

# Classify pod failure reason so the gate's diagnostic line tells operators
# whether to suspect the build (CrashLoopBackOff), the registry/secret path
# (ImagePullBackOff/ErrImagePull), or PVC binding (Pending).
classify_pod_failure() {
  local ns="$1"
  local label="$2"
  local reasons
  reasons=$(kubectl get pods -n "$ns" -l "$label" \
    -o jsonpath='{range .items[*].status.containerStatuses[*]}{.state.waiting.reason}{"\n"}{end}{range .items[*].status.initContainerStatuses[*]}{.state.waiting.reason}{"\n"}{end}' \
    2>/dev/null | sort -u | grep -v '^$' || true)
  if [ -z "$reasons" ]; then
    local phase
    phase=$(kubectl get pods -n "$ns" -l "$label" -o jsonpath='{.items[*].status.phase}' 2>/dev/null || echo "")
    echo "no-waiting-reason (phase=${phase:-unknown})"
    return
  fi
  echo "$reasons" | tr '\n' ',' | sed 's/,$//'
}

# ---------------------------------------------------------------------------
# Teardown handler (always cleans up unless --keep-namespace)
# ---------------------------------------------------------------------------

# shellcheck disable=SC2329  # invoked via `trap cleanup EXIT`
cleanup() {
  local exit_code=$?

  # Self-test mode: invert the meaning of exit code so a *real* failure
  # is reported as success and a missing-failure is reported as code 4.
  # An INFRA exit says nothing about the fixture, so it is never inverted.
  if [ "$EXPECT_FAILURE" = "true" ]; then
    if [ "$exit_code" -eq "$SMOKE_EXIT_INFRA" ]; then
      echo "" >&2
      echo "ERROR: --expect-failure was set but the gate could not run its probe (INFRA, exit ${SMOKE_EXIT_INFRA}); the fixture was not judged." >&2
    elif [ "$exit_code" -eq 0 ]; then
      echo "" >&2
      echo "ERROR: --expect-failure was set but the gate passed. The gate is broken or the test fixture is wrong." >&2
      exit_code=4
    else
      echo ""
      echo "Self-test PASSED: gate exited with code ${exit_code} as expected."
      exit_code=0
    fi
  fi

  if [ "$KEEP_NAMESPACE" = "true" ]; then
    echo ""
    echo "Skipping teardown (--keep-namespace set). Namespace ${NAMESPACE} retained for debugging."
    [ -n "$CHART_TMPDIR" ] && [ -d "$CHART_TMPDIR" ] && \
      echo "Helm chart workdir at ${CHART_TMPDIR} also retained."
    exit "$exit_code"
  fi

  echo ""
  echo "------------------------------------------------------------------"
  echo "Teardown: collecting diagnostics and removing ${NAMESPACE}"
  echo "------------------------------------------------------------------"

  # Capture pod state and logs on failure for debugging the release-gate.
  # Tolerate every kubectl call here so cleanup never fails on a missing
  # resource. mkdir is best-effort: a read-only /tmp should not abort
  # cleanup, just skip log capture.
  if [ "$exit_code" -ne 0 ]; then
    echo ""
    echo "Pods in ${NAMESPACE}:"
    kubectl get pods -n "$NAMESPACE" -o wide 2>/dev/null || true
    echo ""
    echo "Backend pod failure classification:"
    classify_pod_failure "$NAMESPACE" "app.kubernetes.io/component=backend" || true
    echo ""
    echo "Web pod failure classification:"
    classify_pod_failure "$NAMESPACE" "app.kubernetes.io/component=web" || true
    echo ""
    echo "Recent events in ${NAMESPACE}:"
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' 2>/dev/null | tail -50 || true

    LOGS_DIR="${LOGS_DIR:-/tmp/test-logs}/smoke-${RUN_ID}"
    if mkdir -p "$LOGS_DIR" 2>/dev/null; then
      pods=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
      for pod in $pods; do
        kubectl logs "$pod" -n "$NAMESPACE" --all-containers --tail=500 \
          > "${LOGS_DIR}/${pod}.log" 2>/dev/null || true
        kubectl logs "$pod" -n "$NAMESPACE" --all-containers --previous --tail=500 \
          > "${LOGS_DIR}/${pod}.previous.log" 2>/dev/null || true
        # describe is where ImagePullBackOff messages and init container
        # status surface most readably.
        kubectl describe pod "$pod" -n "$NAMESPACE" \
          > "${LOGS_DIR}/${pod}.describe.txt" 2>/dev/null || true
      done
      kubectl get pvc -n "$NAMESPACE" -o yaml > "${LOGS_DIR}/pvcs.yaml" 2>/dev/null || true
      echo "Logs and describe saved to ${LOGS_DIR}/"
    else
      echo "Could not create ${LOGS_DIR}; skipping log capture."
    fi
  fi

  helm uninstall "$RELEASE_NAME" --namespace "$NAMESPACE" --wait=false 2>/dev/null || true
  kubectl delete namespace "$NAMESPACE" --wait=false 2>/dev/null || true

  if [ -n "$CHART_TMPDIR" ] && [ -d "$CHART_TMPDIR" ]; then
    rm -rf "$CHART_TMPDIR" 2>/dev/null || true
  fi

  # Tempfile holding the dockerconfigjson for the GHCR pull secret. The
  # secret is created from this file then cleaned up here on EXIT (rather
  # than via a RETURN trap, which only fires from inside a function).
  if [ -n "$GHCR_CONFIG_FILE" ] && [ -f "$GHCR_CONFIG_FILE" ]; then
    rm -f "$GHCR_CONFIG_FILE" 2>/dev/null || true
  fi

  exit "$exit_code"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Resolve Helm chart source. The iac repo is cloned at $IAC_REF (default
# `main`) so the gate can be pinned to a chart ref that matches the
# release being validated. Pinning matters because chart drift on iac
# main can break the gate retroactively or, worse, silently change the
# semantics of what `values-production.yaml` enables.
# ---------------------------------------------------------------------------

if [ -n "$IAC_REPO" ]; then
  CHART_DIR="${IAC_REPO}/charts/artifact-keeper"
else
  CHART_TMPDIR="$(mktemp -d)"
  echo "Cloning artifact-keeper-iac@${IAC_REF} for Helm chart..."
  git clone --depth 1 --branch "$IAC_REF" \
    https://github.com/artifact-keeper/artifact-keeper-iac.git \
    "$CHART_TMPDIR/iac"
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

# Wire the GHCR pull secret if the workflow provided it. The workflow's
# step env MUST set GHCR_DOCKER_CONFIG (base64-encoded ~/.docker/config.json)
# for private image tags to pull. If unset, we explicitly warn so a silent
# auth failure is visible in workflow logs.
#
# kubectl notes: `create secret docker-registry --docker-username/--docker-server`
# is mutually exclusive with `--from-file`. The first form expects raw
# credentials and builds the dockerconfigjson itself. Since we already
# have the full dockerconfigjson, we use `create secret generic` with the
# correct `--type=kubernetes.io/dockerconfigjson` so the resulting Secret
# is valid for `imagePullSecrets`. (Cleanup of GHCR_CONFIG_FILE happens in
# the EXIT trap above.)
if [ -n "${GHCR_DOCKER_CONFIG:-}" ]; then
  GHCR_CONFIG_FILE="$(mktemp)"
  echo "$GHCR_DOCKER_CONFIG" | base64 -d > "$GHCR_CONFIG_FILE"
  kubectl create secret generic ghcr-creds \
    --namespace "$NAMESPACE" \
    --type=kubernetes.io/dockerconfigjson \
    --from-file=".dockerconfigjson=${GHCR_CONFIG_FILE}" \
    --dry-run=client -o yaml | kubectl apply -f -
  echo "Created ghcr-creds pull secret in ${NAMESPACE}"
  echo ""
  echo "NOTE: The chart at /Users/khan/ak/artifact-keeper-iac currently does"
  echo "      not plumb global.imagePullSecrets onto pod specs, so this"
  echo "      secret is created but unused until the chart adds the wiring."
  echo "      Tracked as a chart follow-up. Public ghcr.io tags work without"
  echo "      this secret."
else
  echo "WARN: GHCR_DOCKER_CONFIG is not set. Private images will fail to pull."
  echo "      Public images will work fine. To wire creds, add:"
  echo "        env:"
  echo "          GHCR_DOCKER_CONFIG: \${{ secrets.GHCR_DOCKER_CONFIG }}"
  echo "      to the workflow step that runs this script."
fi

# ---------------------------------------------------------------------------
# Compose Helm overrides.
#
# values-production.yaml is the chart's example template. It assumes a
# real production environment: RDS, AWS Secrets Manager, ingress, full
# 3-replica OpenSearch StatefulSet with 50Gi PVCs each, and a Prometheus
# operator. Our smoke namespace has none of those. We override carefully
# so the chart still goes through values-production.yaml's code path,
# minus the deps we cannot satisfy.
#
# Overrides and their justification:
#
#   fullnameOverride=ak-smoke
#     Stable service DNS for /readyz polling (avoids release-name
#     suffixing). Matches the v1.1.0-rc.6 lesson.
#
#   backend.image.tag, web.image.tag
#     Pin to the build under test.
#
#   backend.replicaCount=1, web.replicaCount=1
#     Single-replica is enough for a startup smoke. Production uses 3.
#
#   ADMIN_PASSWORD=Smoke!2026secure
#     Required by the chart to clear the setup_required flag so /readyz
#     returns 200. Without this the gate would hang on /readyz forever.
#
#   secrets.jwtSecret=...
#     Test-only credential. Never reuse outside CI.
#
#   postgres.enabled=true, externalDatabase.host=""
#     RDS is unavailable in CI, so use the in-cluster postgres subchart.
#     This means we exercise a different code path than RDS-backed prod
#     installs — that gap is documented in the PR body and tracked as a
#     separate `clean-install-smoke-with-deps` follow-up.
#
#   externalSecrets.enabled=false
#     No External Secrets Operator in CI; secrets come from inline values.
#
#   ingress.enabled=false
#     No public domain in CI; backend is reached via in-cluster Service.
#
#   serviceMonitor.enabled=false
#     No Prometheus operator in the test cluster.
#
#   backend.autoscaling.enabled=false, podDisruptionBudget.enabled=false
#     Single-replica install. HPA + PDB are exercised by the resilience
#     suite, not here.
#
#   edge.enabled=false
#     The edge image isn't published yet (tracked in iac); leaving on
#     would ImagePullBackOff every run.
#
#   trivy.enabled=false, dependencyTrack.enabled=false
#     Heavy subsystems with 4-8 GB memory needs. Out of scope for a
#     startup smoke. Covered by the security-tests matrix.
#
#   networkPolicy.enabled=false
#     Default-deny would block the in-cluster /readyz probe pod.
#
#   opensearch.enabled=false
#     The backend does NOT hard-depend on OpenSearch: with opensearch
#     disabled the chart drops both the `wait-for-opensearch` init container
#     (backend-deployment.yaml guards it on `.Values.opensearch.enabled`) and
#     the OPENSEARCH_URL env, and the backend falls back to Postgres-native
#     search. Verified by the DTF `search` tier (73 cases green with no
#     OpenSearch at all). Keeping OpenSearch ON in this boot smoke was the
#     root cause of the release-gate cascade: a flaky/slow single-node
#     OpenSearch that never reached `_cluster/health` green/yellow left the
#     backend blocked in `wait-for-opensearch` (Init:1/2) until the 300s
#     rollout timeout, failing clean-install-smoke and, because deploy and all
#     ~15 *-tests jobs `needs` it, skipping the entire gate (run 29649800319,
#     the v1.6.0 gate). A startup smoke must not hard-block on a heavy optional
#     service. Production OpenSearch shape stays covered by search-tests, which
#     run against the separate `deploy` stack.
#
#   cosign.enabled=false (default already)
#     No signature verification in CI; would block on cosign tooling.

# The fixed overrides above live in helm/smoke-overrides.yaml, not here, so the
# chart's CI and the backend Release Candidate render this exact profile from
# helm/gate-profiles.txt (scripts/render-gate-profiles.sh,
# artifact-keeper/artifact-keeper#4722). Only the per-run values stay `--set`.
SMOKE_OVERRIDES="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/helm/smoke-overrides.yaml"
if [ ! -f "$SMOKE_OVERRIDES" ]; then
  echo "ERROR: smoke overrides not found at ${SMOKE_OVERRIDES}" >&2
  exit 1
fi

# Build the override flags once and reuse for both the dry-run and the
# install. Drift between the two would defeat the lint pass. The overrides
# file follows values-production.yaml, so it wins over it, and the --set
# flags win over both.
HELM_OVERRIDES=(
  --values "$SMOKE_OVERRIDES"
  --set backend.image.tag="$BACKEND_TAG"
  --set web.image.tag="$WEB_TAG"
)

# Fixture override: when SMOKE_BACKEND_REPO_OVERRIDE is set (used by the
# self-test workflow's CrashLoopBackOff fixture), repurpose the backend
# image repository to a public crash-on-startup image. This preserves
# the array's quoting through word-splitting, which inline `:+` expansion
# would not.
if [ -n "${SMOKE_BACKEND_REPO_OVERRIDE:-}" ]; then
  HELM_OVERRIDES+=(--set "backend.image.repository=${SMOKE_BACKEND_REPO_OVERRIDE}")
fi

echo ""
echo "Helm template dry-run (catches misnamed --set keys)"
# `--debug` is intentionally omitted — it would print rendered manifests
# (including the test-only Secret block with jwtSecret/postgres password)
# to stderr, which is captured in workflow logs. `--dry-run=server` runs
# server-side validation including CRD existence; replaces the deprecated
# `--validate` flag (helm 3.13+).
helm install "$RELEASE_NAME" "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  --values "$PROD_VALUES" \
  "${HELM_OVERRIDES[@]}" \
  --dry-run=server \
  >/dev/null

echo ""
echo "Installing Helm release ${RELEASE_NAME}"
helm upgrade --install "$RELEASE_NAME" "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  --values "$PROD_VALUES" \
  "${HELM_OVERRIDES[@]}" \
  --wait=false || {
    echo "ERROR: helm install failed" >&2
    exit 1
  }

# ---------------------------------------------------------------------------
# Wait for Deployments to exist before polling rollout.
#
# `helm install --wait=false` returns before the API server has finished
# creating the Deployment objects. `kubectl rollout status` against a
# not-yet-existent Deployment fails immediately ("not found") which
# bypasses the timeout budget entirely. So we poll for existence first.
# ---------------------------------------------------------------------------

wait_for_deployment_exists() {
  local name="$1"
  local timeout=30
  local elapsed=0
  while [ "$elapsed" -lt "$timeout" ]; do
    if kubectl get deployment "$name" -n "$NAMESPACE" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "ERROR: deployment/${name} did not appear in ${NAMESPACE} within ${timeout}s" >&2
  return 1
}

echo ""
echo "Waiting for backend and web Deployments to exist"
wait_for_deployment_exists "ak-smoke-backend"
wait_for_deployment_exists "ak-smoke-web"

# ---------------------------------------------------------------------------
# Poll rollout status for backend AND web.
#
# The v1.1.8 panic was a backend startup crash, but a web crash is also
# a broken release. We check both. `kubectl rollout status` returns
# non-zero on CrashLoopBackOff because the new ReplicaSet never reaches
# `availableReplicas == replicas`.
# ---------------------------------------------------------------------------

watch_rollout() {
  local deployment="$1"
  local component="$2"
  echo ""
  echo "Polling rollout status for deployment/${deployment} (timeout: ${TIMEOUT_SECONDS}s)"
  if ! kubectl rollout status "deployment/${deployment}" \
        --namespace "$NAMESPACE" \
        --timeout="${TIMEOUT_SECONDS}s"; then
    echo "ERROR: deployment/${deployment} did not reach Ready within ${TIMEOUT_SECONDS}s" >&2
    echo ""
    echo "Pod state:"
    kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/component=${component}" -o wide || true
    echo ""
    echo "Failure classification: $(classify_pod_failure "$NAMESPACE" "app.kubernetes.io/component=${component}")"
    return 2
  fi
}

watch_rollout "ak-smoke-backend" "backend" || exit $?
watch_rollout "ak-smoke-web"     "web"     || exit $?

# ---------------------------------------------------------------------------
# Poll /readyz from inside the cluster.
#
# `/readyz` is a deeper probe than `kubectl rollout status`: it verifies
# the backend can reach Postgres, has applied migrations, and has cleared
# the setup_required flag (which is why helm/smoke-overrides.yaml sets ADMIN_PASSWORD).
# A backend that booted but cannot serve will trip this even when
# rollout status reports Ready.
#
# We exec into the backend pod itself when it has wget or curl. Otherwise one
# long-lived probe pod is started from the digest-pinned PROBE_IMAGE and
# reused for every iteration.
#
# Budget: TIMEOUT_SECONDS starts when the rollout completes and covers the
# probe pod start AND the /readyz polling, so a slow probe pod cannot push the
# job past its timeout. At least one /readyz probe always runs once the probe
# pod is Ready, so the backend always gets its full TIMEOUT_SECONDS of wall
# clock after rollout before a non-200 is reported.
#
# Exit 3 means the probe ran and /readyz never returned 200 (product).
# Exit SMOKE_EXIT_INFRA means the probe pod could not be created or started
# (infra): the candidate was never probed.
# ---------------------------------------------------------------------------

# Print the probe pod's waiting reason, describe tail and events.
probe_pod_diagnostics() {
  local pod="$1"
  echo "Probe pod ${pod} state:" >&2
  kubectl get pod "$pod" -n "$NAMESPACE" -o wide >&2 2>&1 || true
  echo "Probe pod ${pod} describe (tail):" >&2
  kubectl describe pod "$pod" -n "$NAMESPACE" 2>&1 | tail -30 >&2 || true
  echo "Probe pod ${pod} events:" >&2
  kubectl get events -n "$NAMESPACE" \
    --field-selector "involvedObject.name=${pod}" \
    --sort-by='.lastTimestamp' 2>&1 | tail -20 >&2 || true
}

# Wait until the probe pod is Ready or the deadline passes.
#   0  Ready
#   1  did not become Ready (pending past the deadline, failed, or vanished)
#   2  image-pull failure (ErrImagePull / ImagePullBackOff)
# The last observed state is left in PROBE_POD_STATE for the error message.
PROBE_POD_STATE=""
wait_probe_pod_ready() {
  local pod="$1" deadline="$2" now phase ready reason
  while true; do
    PROBE_POD_STATE=$(kubectl get pod "$pod" -n "$NAMESPACE" \
      -o jsonpath='{.status.phase}|{.status.containerStatuses[0].ready}|{.status.containerStatuses[0].state.waiting.reason}' \
      2>/dev/null || true)
    IFS='|' read -r phase ready reason <<<"$PROBE_POD_STATE"
    if [ "$ready" = "true" ]; then
      return 0
    fi
    case "$reason" in
      ErrImagePull|ImagePullBackOff) return 2 ;;
    esac
    case "$phase" in
      Failed|Succeeded) return 1 ;;
    esac
    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
      return 1
    fi
    sleep 2
  done
}

# Create the probe pod and wait for it, retrying ONCE on an image-pull
# failure. Prints the Ready pod's name on stdout; returns non-zero if no probe
# pod could be started.
start_probe_pod() {
  local deadline="$1" base="ak-smoke-probe-${RUN_ID}" attempt pod rc
  for attempt in 1 2; do
    pod="$base"
    [ "$attempt" -gt 1 ] && pod="${base}-retry"
    echo "Provisioning ephemeral probe pod ${pod} (image ${PROBE_IMAGE}, attempt ${attempt}/2)" >&2
    if ! kubectl run "$pod" -n "$NAMESPACE" \
        --image="$PROBE_IMAGE" \
        --image-pull-policy=IfNotPresent \
        --restart=Never \
        --labels="app.kubernetes.io/component=smoke-probe" \
        --command -- sleep 600 >/dev/null 2>&1; then
      echo "ERROR: INFRA: could not create ephemeral probe pod ${pod}" >&2
      return 1
    fi
    rc=0
    wait_probe_pod_ready "$pod" "$deadline" || rc=$?
    if [ "$rc" -eq 0 ]; then
      echo "$pod"
      return 0
    fi
    echo "ERROR: INFRA: probe pod ${pod} did not become Ready (phase|ready|waiting-reason: ${PROBE_POD_STATE:-unknown})" >&2
    probe_pod_diagnostics "$pod"
    if [ "$rc" -ne 2 ] || [ "$attempt" -ge 2 ]; then
      return 1
    fi
    echo "Image-pull failure on the probe pod; retrying once with a fresh pod" >&2
    kubectl delete pod "$pod" -n "$NAMESPACE" --wait=false >/dev/null 2>&1 || true
    sleep 5
  done
  return 1
}

readyz_probe_loop() {
  local service_url="http://ak-smoke-backend.${NAMESPACE}.svc.cluster.local:8080"
  echo ""

  local start deadline now elapsed output
  start=$(date +%s)
  deadline=$(( start + TIMEOUT_SECONDS ))

  local backend_pod
  backend_pod=$(kubectl get pods -n "$NAMESPACE" \
    -l "app.kubernetes.io/component=backend" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [ -z "$backend_pod" ]; then
    echo "ERROR: no backend pod found for /readyz probe" >&2
    return 3
  fi

  # Pick a probe pod. Preference order:
  #   1. Backend pod if it has wget or curl (no extra image pull)
  #   2. Ephemeral probe pod in the same namespace (one image pull, reused
  #      across all probe iterations)
  #
  # Production backend images on the v1.1.x line are slim and may have
  # neither curl nor wget. Falling back to a probe pod keeps the smoke
  # test functional without requiring shell utilities in production
  # images. The ephemeral pod is reaped automatically when the namespace
  # is torn down.
  #
  # GNU wget indents response headers with two spaces; busybox wget uses
  # one. Match either with `-i 'HTTP/'`.
  local wget_cmd="wget -q --timeout=5 -O - --server-response ${service_url}/readyz 2>&1 | grep -i 'HTTP/'"
  local probe_pod="$backend_pod"
  local probe_cmd=""
  if kubectl exec -n "$NAMESPACE" "$backend_pod" -- sh -c 'command -v wget >/dev/null' 2>/dev/null; then
    probe_cmd="$wget_cmd"
    echo "Polling ${service_url}/readyz from backend pod (wget; timeout: ${TIMEOUT_SECONDS}s)"
  elif kubectl exec -n "$NAMESPACE" "$backend_pod" -- sh -c 'command -v curl >/dev/null' 2>/dev/null; then
    probe_cmd="curl -fsS -o /dev/null -w '%{http_code}\n' --max-time 5 ${service_url}/readyz"
    echo "Polling ${service_url}/readyz from backend pod (curl; timeout: ${TIMEOUT_SECONDS}s)"
  else
    echo "Backend image has no curl/wget; provisioning an ephemeral probe pod"
    if ! probe_pod=$(start_probe_pod "$deadline"); then
      echo "ERROR: INFRA: no /readyz probe pod could be started within the ${TIMEOUT_SECONDS}s budget; the candidate was NOT probed (exit ${SMOKE_EXIT_INFRA})" >&2
      return "$SMOKE_EXIT_INFRA"
    fi
    probe_cmd="$wget_cmd"
    echo "Polling ${service_url}/readyz from ${probe_pod} (wget; timeout: ${TIMEOUT_SECONDS}s, $(( $(date +%s) - start ))s used by the probe pod)"
  fi

  while true; do
    if output=$(kubectl exec -n "$NAMESPACE" "$probe_pod" -- sh -c "$probe_cmd" 2>&1); then
      if echo "$output" | grep -qE '\b200\b'; then
        elapsed=$(( $(date +%s) - start ))
        echo "Backend /readyz returned 200 (took ${elapsed}s after rollout completed)"
        return 0
      fi
    fi

    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
      echo "ERROR: /readyz did not return 200 within ${TIMEOUT_SECONDS}s" >&2
      echo ""
      echo "Last probe output:"
      echo "$output" | tail -5 || true
      return 3
    fi

    printf "."
    sleep 5
  done
}

readyz_probe_loop || exit $?

echo ""
echo "=================================================================="
echo "Clean-install smoke test PASSED"
echo "  Backend tag ${BACKEND_TAG} reached Ready and served /readyz 200."
echo "  Web tag ${WEB_TAG} reached Ready."
echo "=================================================================="

# Cleanup happens via trap on EXIT
exit 0
