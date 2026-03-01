# artifact-keeper-test Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a release-gate test repository that deploys isolated Kubernetes environments and runs comprehensive E2E tests against all 38 format handlers, plus stress, resilience, mesh, security, and compatibility suites.

**Architecture:** Monolithic test repo with shell-based test scripts following a uniform contract. GitHub Actions workflows on self-hosted ARC runners orchestrate namespace lifecycle (Helm install into dynamic namespaces, test execution, teardown). The IAC Helm chart is referenced directly from the git repo.

**Tech Stack:** Bash (tests), Helm (deployment), GitHub Actions (orchestration), Playwright (web E2E), kubectl/curl (assertions)

---

## Phase 1: Repository Foundation

### Task 1.1: Create CLAUDE.md

**Files:**
- Create: `CLAUDE.md`

**Step 1: Write the file**

```markdown
# CLAUDE.md

## Project Overview

This is the release-gate test infrastructure for Artifact Keeper. It contains E2E test scripts, Helm value overlays, and GitHub Actions workflows that validate releases before tagging.

## Repository Structure

- `tests/` - Test scripts organized by suite (formats, stress, resilience, mesh, security, compatibility)
- `tests/lib/` - Shared shell helpers (auth, assertions, JUnit output)
- `helm/` - Thin Helm value overlays referencing the chart in artifact-keeper-iac
- `scripts/` - Namespace lifecycle (create, teardown, run-suite orchestrator)
- `.github/workflows/` - Release coordinator and reusable test workflows

## Running Tests Locally

Tests require a running Artifact Keeper instance. Set these env vars:

```bash
export BASE_URL="http://localhost:8080"
export ADMIN_USER="admin"
export ADMIN_PASS="admin123"
export RUN_ID="local-$(date +%s)"
```

Then run any test directly:

```bash
source tests/lib/common.sh
bash tests/formats/test-npm.sh
```

## Test Script Contract

Every script in `tests/` must:
1. Source `tests/lib/common.sh`
2. Use `RUN_ID` in all resource names to avoid collisions
3. Print PASS/FAIL per test section
4. Produce JUnit XML output to `$JUNIT_OUTPUT_DIR/`
5. Exit 0 on all-pass, non-zero on any failure

## Key Commands

```bash
# Deploy a test namespace (requires kubectl access)
./scripts/create-test-namespace.sh --run-id test-123 --backend-tag dev --web-tag dev

# Run a single format test
bash tests/formats/test-npm.sh

# Run a full suite
./scripts/run-suite.sh --suite formats --run-id test-123

# Tear down
./scripts/teardown-test-namespace.sh --run-id test-123
```

## Helm Chart Reference

Tests deploy using the Helm chart from `artifact-keeper-iac` (git source, not a registry). The chart is cloned at deploy time and overlaid with `helm/values-test.yaml`.

## Writing Style

Follow the same conventions as the main artifact-keeper repos: no em-dashes, no emoji in docs, no ChatGPT-isms. Be direct and technical.
```

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add CLAUDE.md with project conventions"
```

---

### Task 1.2: Create shared test library - common.sh

**Files:**
- Create: `tests/lib/common.sh`

**Step 1: Write the file**

This is the core shared library sourced by every test script. It provides auth, HTTP helpers, assertions, and JUnit output.

```bash
#!/usr/bin/env bash
# common.sh - Shared test helpers for artifact-keeper-test
# Source this at the top of every test script.

set -euo pipefail

# --- Configuration ---
export BASE_URL="${BASE_URL:-http://localhost:8080}"
export ADMIN_USER="${ADMIN_USER:-admin}"
export ADMIN_PASS="${ADMIN_PASS:-admin123}"
export RUN_ID="${RUN_ID:-local-$(date +%s)}"
export TEST_TIMEOUT="${TEST_TIMEOUT:-120}"
export JUNIT_OUTPUT_DIR="${JUNIT_OUTPUT_DIR:-/tmp/test-results}"

mkdir -p "$JUNIT_OUTPUT_DIR"

# --- State ---
_TEST_NAME=""
_TEST_SUITE=""
_TEST_START=0
_PASS_COUNT=0
_FAIL_COUNT=0
_JUNIT_CASES=""
_SECTION_START=0

# --- Auth ---
ADMIN_TOKEN=""

auth_admin() {
  local resp
  resp=$(curl -sf -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null) || {
    echo "FATAL: Failed to authenticate as admin"
    exit 1
  }
  ADMIN_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty')
  if [ -z "$ADMIN_TOKEN" ]; then
    echo "FATAL: No token in auth response"
    exit 1
  fi
  export ADMIN_TOKEN
}

auth_header() {
  echo "Authorization: Bearer ${ADMIN_TOKEN}"
}

# --- HTTP Helpers ---
api_get() {
  local path="$1"
  curl -sf -H "$(auth_header)" "${BASE_URL}${path}"
}

api_post() {
  local path="$1"
  local data="${2:-}"
  if [ -n "$data" ]; then
    curl -sf -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
      -d "$data" "${BASE_URL}${path}"
  else
    curl -sf -X POST -H "$(auth_header)" "${BASE_URL}${path}"
  fi
}

api_put() {
  local path="$1"
  local data="$2"
  curl -sf -X PUT -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$data" "${BASE_URL}${path}"
}

api_delete() {
  local path="$1"
  curl -sf -X DELETE -H "$(auth_header)" "${BASE_URL}${path}"
}

api_upload() {
  local path="$1"
  local file="$2"
  local content_type="${3:-application/octet-stream}"
  curl -sf -X PUT -H "$(auth_header)" -H "Content-Type: ${content_type}" \
    --data-binary "@${file}" "${BASE_URL}${path}"
}

# --- Repository Helpers ---
create_repo() {
  local key="$1"
  local format="$2"
  local repo_type="${3:-local}"
  local upstream_url="${4:-}"

  local data="{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"${format}\",\"repo_type\":\"${repo_type}\""
  if [ -n "$upstream_url" ]; then
    data="${data},\"upstream_url\":\"${upstream_url}\""
  fi
  data="${data}}"

  api_post "/api/v1/repositories" "$data" > /dev/null
}

create_local_repo() {
  create_repo "$1" "$2" "local"
}

create_remote_repo() {
  local key="$1"
  local format="$2"
  local upstream_url="$3"
  create_repo "$key" "$format" "remote" "$upstream_url"
}

create_virtual_repo() {
  local key="$1"
  local format="$2"
  create_repo "$key" "$format" "virtual"
}

# --- Test Framework ---
begin_suite() {
  _TEST_SUITE="$1"
  _TEST_START=$(date +%s)
  _PASS_COUNT=0
  _FAIL_COUNT=0
  _JUNIT_CASES=""
  echo "========================================"
  echo "  Suite: ${_TEST_SUITE}"
  echo "  Run ID: ${RUN_ID}"
  echo "  Target: ${BASE_URL}"
  echo "========================================"
}

begin_test() {
  _TEST_NAME="$1"
  _SECTION_START=$(date +%s)
  echo ""
  echo "--- ${_TEST_NAME} ---"
}

pass() {
  local duration=$(( $(date +%s) - _SECTION_START ))
  _PASS_COUNT=$(( _PASS_COUNT + 1 ))
  _JUNIT_CASES="${_JUNIT_CASES}<testcase name=\"${_TEST_NAME}\" classname=\"${_TEST_SUITE}\" time=\"${duration}\"/>\n"
  echo "  PASS (${duration}s)"
}

fail() {
  local msg="${1:-assertion failed}"
  local duration=$(( $(date +%s) - _SECTION_START ))
  _FAIL_COUNT=$(( _FAIL_COUNT + 1 ))
  _JUNIT_CASES="${_JUNIT_CASES}<testcase name=\"${_TEST_NAME}\" classname=\"${_TEST_SUITE}\" time=\"${duration}\"><failure message=\"${msg}\"/></testcase>\n"
  echo "  FAIL: ${msg} (${duration}s)"
}

end_suite() {
  local total_duration=$(( $(date +%s) - _TEST_START ))
  local total=$(( _PASS_COUNT + _FAIL_COUNT ))

  echo ""
  echo "========================================"
  echo "  Results: ${_PASS_COUNT}/${total} passed (${total_duration}s)"
  echo "========================================"

  # Write JUnit XML
  local xml_file="${JUNIT_OUTPUT_DIR}/${_TEST_SUITE}.xml"
  cat > "$xml_file" <<JUNITEOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="${_TEST_SUITE}" tests="${total}" failures="${_FAIL_COUNT}" time="${total_duration}">
$(echo -e "$_JUNIT_CASES")
</testsuite>
JUNITEOF

  if [ "$_FAIL_COUNT" -gt 0 ]; then
    exit 1
  fi
}

# --- Assertions ---
assert_eq() {
  local actual="$1"
  local expected="$2"
  local msg="${3:-expected '${expected}' but got '${actual}'}"
  if [ "$actual" != "$expected" ]; then
    fail "$msg"
    return 1
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="${3:-expected output to contain '${needle}'}"
  if [[ "$haystack" != *"$needle"* ]]; then
    fail "$msg"
    return 1
  fi
}

assert_http_ok() {
  local url="$1"
  local status
  status=$(curl -sf -o /dev/null -w '%{http_code}' -H "$(auth_header)" "$url" 2>/dev/null) || true
  if [ "$status" -lt 200 ] || [ "$status" -ge 300 ]; then
    fail "expected 2xx from ${url}, got ${status}"
    return 1
  fi
}

assert_http_status() {
  local url="$1"
  local expected="$2"
  local status
  status=$(curl -sf -o /dev/null -w '%{http_code}' -H "$(auth_header)" "$url" 2>/dev/null) || true
  assert_eq "$status" "$expected" "expected HTTP ${expected} from ${url}, got ${status}"
}

assert_count() {
  local json="$1"
  local expected="$2"
  local actual
  actual=$(echo "$json" | jq 'if type == "array" then length elif .items then .items | length elif .total then .total else 0 end')
  assert_eq "$actual" "$expected" "expected count ${expected}, got ${actual}"
}

# --- Prerequisite Check ---
require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" &>/dev/null; then
    echo "SKIP: ${cmd} not found, skipping ${_TEST_SUITE}"
    exit 0
  fi
}

# --- Temp Dir ---
WORK_DIR=""
setup_workdir() {
  WORK_DIR="$(mktemp -d)"
  trap 'rm -rf "$WORK_DIR"' EXIT
}
```

**Step 2: Commit**

```bash
git add tests/lib/common.sh
git commit -m "feat: add shared test library with auth, HTTP helpers, assertions, JUnit output"
```

---

### Task 1.3: Create wait-for-ready.sh

**Files:**
- Create: `tests/lib/wait-for-ready.sh`

**Step 1: Write the file**

```bash
#!/usr/bin/env bash
# wait-for-ready.sh - Poll health endpoints until the stack is up
# Usage: ./wait-for-ready.sh <base_url> [timeout_seconds]

set -euo pipefail

URL="${1:?Usage: wait-for-ready.sh <base_url> [timeout]}"
TIMEOUT="${2:-120}"
INTERVAL=5
ELAPSED=0

echo "Waiting for ${URL} to be ready (timeout: ${TIMEOUT}s)..."

while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
  # Check backend health
  backend_ok=false
  if curl -sf "${URL}/health" > /dev/null 2>&1; then
    backend_ok=true
  fi

  # Check web (if available on same host)
  web_ok=false
  if curl -sf "${URL}/" > /dev/null 2>&1 || curl -sf -o /dev/null -w '%{http_code}' "${URL}/" 2>/dev/null | grep -qE '^(200|301|302)'; then
    web_ok=true
  fi

  if $backend_ok; then
    echo "Backend ready after ${ELAPSED}s"
    if $web_ok; then
      echo "Web ready after ${ELAPSED}s"
    fi
    exit 0
  fi

  sleep "$INTERVAL"
  ELAPSED=$(( ELAPSED + INTERVAL ))
  echo "  ...waiting (${ELAPSED}s)"
done

echo "FATAL: Timed out after ${TIMEOUT}s waiting for ${URL}"
exit 1
```

**Step 2: Make executable and commit**

```bash
chmod +x tests/lib/wait-for-ready.sh
git add tests/lib/wait-for-ready.sh
git commit -m "feat: add wait-for-ready health check poller"
```

---

### Task 1.4: Create Helm value overlays

**Files:**
- Create: `helm/values-test.yaml`
- Create: `helm/values-test-mesh.yaml`

**Step 1: Write values-test.yaml**

This is a thin overlay for single-instance test deployments. The IAC chart from `artifact-keeper-iac` is the base.

```yaml
# values-test.yaml - Test environment overlay
# Used with: helm install -f values-test.yaml <chart-path>
# Candidate image tags are injected via --set at deploy time.

backend:
  image:
    repository: ghcr.io/artifact-keeper/artifact-keeper-backend
    tag: dev
    pullPolicy: Always
  replicaCount: 1
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 1
      memory: 1Gi
  env:
    ENVIRONMENT: "test"
    RUST_LOG: "info"
  autoscaling:
    enabled: false
  podDisruptionBudget:
    enabled: false
  scanWorkspace:
    enabled: false
  persistence:
    size: 2Gi

web:
  enabled: true
  image:
    repository: ghcr.io/artifact-keeper/artifact-keeper-web
    tag: dev
    pullPolicy: Always
  replicaCount: 1
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 250m
      memory: 256Mi

postgres:
  enabled: true
  auth:
    password: "test-db-password"
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 500m
      memory: 512Mi
  persistence:
    size: 2Gi

meilisearch:
  enabled: true
  masterKey: "artifact-keeper-test-key"
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 1
      memory: 2Gi
  persistence:
    size: 1Gi

# Disabled for basic tests (enabled selectively by resilience/security suites)
trivy:
  enabled: false
dependencyTrack:
  enabled: false
edge:
  enabled: false
ingress:
  enabled: false
networkPolicy:
  enabled: false
serviceMonitor:
  enabled: false
cosign:
  enabled: false

secrets:
  jwtSecret: "test-jwt-secret-not-for-production"
```

**Step 2: Write values-test-mesh.yaml**

```yaml
# values-test-mesh.yaml - Mesh topology test overlay
# Deployed per-instance. Instance-specific values (fullnameOverride,
# PEER_INSTANCE_NAME, PEER_PUBLIC_ENDPOINT, PEER_API_KEY, secrets.jwtSecret)
# are injected via --set at deploy time.

backend:
  image:
    repository: ghcr.io/artifact-keeper/artifact-keeper-backend
    tag: dev
    pullPolicy: Always
  replicaCount: 1
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi
  env:
    ENVIRONMENT: "mesh-test"
    RUST_LOG: "info"
  autoscaling:
    enabled: false
  podDisruptionBudget:
    enabled: false
  scanWorkspace:
    enabled: false
  persistence:
    size: 1Gi

# Web is enabled only for the main node; set web.enabled=false for peers via --set
web:
  enabled: true
  image:
    repository: ghcr.io/artifact-keeper/artifact-keeper-web
    tag: dev
    pullPolicy: Always
  replicaCount: 1
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 250m
      memory: 256Mi

postgres:
  enabled: true
  auth:
    password: "mesh-test-db-password"
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 250m
      memory: 256Mi
  persistence:
    size: 1Gi

meilisearch:
  enabled: true
  masterKey: "artifact-keeper-mesh-test-key"
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 1
      memory: 2Gi
  persistence:
    size: 1Gi

trivy:
  enabled: false
dependencyTrack:
  enabled: false
edge:
  enabled: false
ingress:
  enabled: false
networkPolicy:
  enabled: false
serviceMonitor:
  enabled: false
cosign:
  enabled: false
```

**Step 3: Commit**

```bash
git add helm/
git commit -m "feat: add Helm value overlays for test and mesh-test environments"
```

---

### Task 1.5: Create namespace lifecycle scripts

**Files:**
- Create: `scripts/create-test-namespace.sh`
- Create: `scripts/teardown-test-namespace.sh`
- Create: `scripts/run-suite.sh`

**Step 1: Write create-test-namespace.sh**

```bash
#!/usr/bin/env bash
# create-test-namespace.sh - Deploy a test environment into an isolated namespace
# Usage: ./create-test-namespace.sh --run-id <id> --backend-tag <tag> [--web-tag <tag>] [--iac-repo <path>]

set -euo pipefail

# --- Parse Args ---
RUN_ID=""
BACKEND_TAG="dev"
WEB_TAG="dev"
IAC_REPO=""
NAMESPACE_CPU="${TEST_NAMESPACE_CPU:-4000m}"
NAMESPACE_MEMORY="${TEST_NAMESPACE_MEMORY:-8Gi}"
GHCR_SECRET="${GHCR_DOCKER_CONFIG:-}"
HELM_VALUES_DIR="$(cd "$(dirname "$0")/../helm" && pwd)"

while [[ $# -gt 0 ]]; do
  case $1 in
    --run-id) RUN_ID="$2"; shift 2 ;;
    --backend-tag) BACKEND_TAG="$2"; shift 2 ;;
    --web-tag) WEB_TAG="$2"; shift 2 ;;
    --iac-repo) IAC_REPO="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [ -z "$RUN_ID" ]; then
  echo "Usage: create-test-namespace.sh --run-id <id> --backend-tag <tag>"
  exit 1
fi

NAMESPACE="test-${RUN_ID}"

echo "=== Creating test namespace: ${NAMESPACE} ==="
echo "  Backend: ${BACKEND_TAG}"
echo "  Web: ${WEB_TAG}"

# --- Clone IAC chart if not provided ---
if [ -z "$IAC_REPO" ]; then
  IAC_REPO="$(mktemp -d)/artifact-keeper-iac"
  echo "Cloning IAC chart..."
  git clone --depth 1 https://github.com/artifact-keeper/artifact-keeper-iac.git "$IAC_REPO"
fi

CHART_PATH="${IAC_REPO}/helm"

# --- Create Namespace ---
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# --- Apply ResourceQuota ---
cat <<EOF | kubectl apply -n "$NAMESPACE" -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: test-quota
spec:
  hard:
    requests.cpu: "${NAMESPACE_CPU}"
    requests.memory: "${NAMESPACE_MEMORY}"
EOF

# --- Create image pull secret ---
if [ -n "$GHCR_SECRET" ]; then
  kubectl create secret docker-registry ghcr-creds \
    --docker-server=ghcr.io \
    --docker-username=_ \
    --docker-password="$GHCR_SECRET" \
    -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
fi

# --- Helm Install ---
echo "Installing Artifact Keeper via Helm..."
helm upgrade --install "ak-test-${RUN_ID}" "$CHART_PATH" \
  -n "$NAMESPACE" \
  -f "${HELM_VALUES_DIR}/values-test.yaml" \
  --set "backend.image.tag=${BACKEND_TAG}" \
  --set "web.image.tag=${WEB_TAG}" \
  --wait \
  --timeout 5m

# --- Wait for ready ---
BACKEND_SVC="ak-test-${RUN_ID}-backend"
echo "Waiting for backend to be ready..."
"$(dirname "$0")/../tests/lib/wait-for-ready.sh" \
  "http://${BACKEND_SVC}.${NAMESPACE}.svc.cluster.local:8080" 120

echo "=== Namespace ${NAMESPACE} ready ==="
echo "BACKEND_URL=http://${BACKEND_SVC}.${NAMESPACE}.svc.cluster.local:8080"
```

**Step 2: Write teardown-test-namespace.sh**

```bash
#!/usr/bin/env bash
# teardown-test-namespace.sh - Collect logs and destroy a test namespace
# Usage: ./teardown-test-namespace.sh --run-id <id> [--logs-dir <path>]

set -euo pipefail

RUN_ID=""
LOGS_DIR="/tmp/test-logs"

while [[ $# -gt 0 ]]; do
  case $1 in
    --run-id) RUN_ID="$2"; shift 2 ;;
    --logs-dir) LOGS_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [ -z "$RUN_ID" ]; then
  echo "Usage: teardown-test-namespace.sh --run-id <id>"
  exit 1
fi

NAMESPACE="test-${RUN_ID}"
mkdir -p "$LOGS_DIR"

echo "=== Tearing down namespace: ${NAMESPACE} ==="

# --- Collect logs from all pods ---
echo "Collecting pod logs..."
for pod in $(kubectl get pods -n "$NAMESPACE" -o name 2>/dev/null || true); do
  pod_name="${pod#pod/}"
  echo "  Saving logs for ${pod_name}"
  kubectl logs -n "$NAMESPACE" "$pod_name" --all-containers > "${LOGS_DIR}/${pod_name}.log" 2>/dev/null || true
done

# --- Uninstall Helm release ---
echo "Uninstalling Helm release..."
helm uninstall "ak-test-${RUN_ID}" -n "$NAMESPACE" 2>/dev/null || true

# --- Delete namespace ---
echo "Deleting namespace..."
kubectl delete namespace "$NAMESPACE" --wait=false 2>/dev/null || true

# --- Also clean up mesh namespaces if they exist ---
for suffix in mesh-main mesh-peer1 mesh-peer2 mesh-peer3; do
  mesh_ns="test-${RUN_ID}-${suffix}"
  if kubectl get namespace "$mesh_ns" &>/dev/null; then
    echo "Cleaning up mesh namespace: ${mesh_ns}"
    for pod in $(kubectl get pods -n "$mesh_ns" -o name 2>/dev/null || true); do
      pod_name="${pod#pod/}"
      kubectl logs -n "$mesh_ns" "$pod_name" --all-containers > "${LOGS_DIR}/${mesh_ns}-${pod_name}.log" 2>/dev/null || true
    done
    helm uninstall "ak-${suffix}-${RUN_ID}" -n "$mesh_ns" 2>/dev/null || true
    kubectl delete namespace "$mesh_ns" --wait=false 2>/dev/null || true
  fi
done

echo "=== Teardown complete ==="
```

**Step 3: Write run-suite.sh**

```bash
#!/usr/bin/env bash
# run-suite.sh - Run a named test suite with result collection
# Usage: ./run-suite.sh --suite <name> [--filter <pattern>]
# Suites: formats, stress, resilience, mesh, security, compatibility

set -euo pipefail

SUITE=""
FILTER=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --suite) SUITE="$2"; shift 2 ;;
    --filter) FILTER="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [ -z "$SUITE" ]; then
  echo "Usage: run-suite.sh --suite <name> [--filter <pattern>]"
  echo "Suites: formats, stress, resilience, mesh, security, compatibility"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="${SCRIPT_DIR}/../tests"
RESULTS_DIR="${JUNIT_OUTPUT_DIR:-/tmp/test-results}"
mkdir -p "$RESULTS_DIR"
export JUNIT_OUTPUT_DIR="$RESULTS_DIR"

# --- Discover test scripts ---
SCRIPTS=()
if [ "$SUITE" = "resilience" ]; then
  # Resilience has subdirectories
  while IFS= read -r -d '' script; do
    SCRIPTS+=("$script")
  done < <(find "${TEST_DIR}/resilience" -name 'test-*.sh' -print0 | sort -z)
else
  while IFS= read -r -d '' script; do
    SCRIPTS+=("$script")
  done < <(find "${TEST_DIR}/${SUITE}" -maxdepth 1 -name 'test-*.sh' -print0 | sort -z)
fi

# --- Apply filter ---
if [ -n "$FILTER" ]; then
  FILTERED=()
  for s in "${SCRIPTS[@]}"; do
    if [[ "$(basename "$s")" == *"$FILTER"* ]]; then
      FILTERED+=("$s")
    fi
  done
  SCRIPTS=("${FILTERED[@]}")
fi

echo "=== Running suite: ${SUITE} (${#SCRIPTS[@]} tests) ==="

TOTAL=0
PASSED=0
FAILED=0
FAILED_NAMES=()

for script in "${SCRIPTS[@]}"; do
  name="$(basename "$script" .sh)"
  TOTAL=$(( TOTAL + 1 ))
  echo ""
  echo ">>> ${name}"

  if timeout "${TEST_TIMEOUT:-300}" bash "$script"; then
    PASSED=$(( PASSED + 1 ))
  else
    FAILED=$(( FAILED + 1 ))
    FAILED_NAMES+=("$name")
    echo "!!! FAILED: ${name}"
  fi
done

echo ""
echo "=== Suite ${SUITE}: ${PASSED}/${TOTAL} passed ==="

if [ "$FAILED" -gt 0 ]; then
  echo "Failed tests:"
  for name in "${FAILED_NAMES[@]}"; do
    echo "  - ${name}"
  done
  exit 1
fi
```

**Step 4: Make all scripts executable and commit**

```bash
chmod +x scripts/*.sh
git add scripts/
git commit -m "feat: add namespace lifecycle and test suite orchestrator scripts"
```

---

## Phase 2: Format Test Scripts (38 total)

Each format test follows the contract defined in common.sh. The 15 existing tests are ported from `artifact-keeper/scripts/native-tests/` and adapted to use the shared library. The remaining 23 are new.

### Format API Path Reference

| Format | API Path | Native Client |
|--------|----------|--------------|
| alpine | `/alpine/{key}/` | `apk` |
| ansible | `/ansible/{key}/` | `curl` (Galaxy API) |
| bazel | `/ext/bazel/{key}/` | `curl` (Bazel registry protocol) |
| cargo | `/cargo/{key}/` | `cargo` |
| chef | `/chef/{key}/` | `curl` (Chef Supermarket API) |
| cocoapods | `/cocoapods/{key}/` | `curl` (CocoaPods trunk API) |
| composer | `/composer/{key}/` | `curl` (Packagist API) |
| conan | `/conan/{key}/` | `curl` (Conan v2 API) |
| conda | `/conda/{key}/` | `conda` |
| cran | `/cran/{key}/` | `curl` (CRAN-like repo) |
| debian | `/debian/{key}/` | `dpkg`/`apt` |
| generic | `/generic/{key}/` | `curl` |
| gitlfs | `/lfs/{key}/` | `curl` (Git LFS batch API) |
| go | `/go/{key}/` | `go` |
| helm | `/helm/{key}/` | `helm` |
| hex | `/hex/{key}/` | `curl` (Hex.pm API) |
| huggingface | `/huggingface/{key}/` | `curl` (HF Hub API) |
| incus | `/incus/{key}/` | `curl` (Incus image API) |
| jetbrains | `/jetbrains/{key}/` | `curl` (JetBrains plugin repo XML) |
| maven | `/maven/{key}/` | `mvn` or `curl` |
| mlmodel | `/ext/mlmodel/{key}/` | `curl` |
| npm | `/npm/{key}/` | `npm` |
| nuget | `/nuget/{key}/` | `curl` (NuGet v3 API) |
| oci | `/v2/` (root-level) | `docker` or `curl` |
| opkg | `/ext/opkg/{key}/` | `curl` |
| p2 | `/ext/p2/{key}/` | `curl` (Eclipse P2 repo) |
| protobuf | `/proto/{key}/` | `curl` (BSR API) |
| pub | `/pub/{key}/` | `curl` (Dart pub API) |
| puppet | `/puppet/{key}/` | `curl` (Puppet Forge API) |
| pypi | `/pypi/{key}/` | `pip`/`twine` |
| rpm | `/rpm/{key}/` | `rpm`/`dnf` |
| rubygems | `/gems/{key}/` | `curl` (RubyGems API) |
| sbt | `/ivy/{key}/` | `curl` (Ivy-style paths) |
| swift | `/swift/{key}/` | `curl` (Swift Package Registry) |
| terraform | `/terraform/{key}/` | `curl` (Terraform registry protocol) |
| vagrant | `/ext/vagrant/{key}/` | `curl` (Vagrant Cloud API) |
| vscode | `/vscode/{key}/` | `curl` (VS Code Marketplace API) |
| wasm | `/ext/{format_key}/{key}/` | `curl` |

### Task 2.1: Port existing format tests (batch 1 - npm, pypi, cargo)

**Files:**
- Create: `tests/formats/test-npm.sh`
- Create: `tests/formats/test-pypi.sh`
- Create: `tests/formats/test-cargo.sh`

For each: read the existing script from `artifact-keeper/scripts/native-tests/test-<format>.sh`, adapt to use the common.sh library (replace inline auth with `auth_admin`, use `begin_suite`/`begin_test`/`pass`/`fail`/`end_suite`, use `create_local_repo` helper, prefix all repo keys with `RUN_ID`).

**Step 1: Write test-npm.sh**

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/../lib/common.sh"

begin_suite "npm"
auth_admin
setup_workdir
require_cmd npm

REPO_KEY="test-npm-${RUN_ID}"
NPM_REGISTRY="${BASE_URL}/api/v1/npm/${REPO_KEY}"

# --- Create repo ---
begin_test "Create NPM local repository"
create_local_repo "$REPO_KEY" "npm"
pass

# --- Publish ---
begin_test "Publish package via npm"
mkdir -p "${WORK_DIR}/my-test-pkg"
cat > "${WORK_DIR}/my-test-pkg/package.json" <<EOF
{
  "name": "@test/my-test-pkg",
  "version": "1.0.${RUN_ID##*-}",
  "description": "Test package for E2E"
}
EOF
echo "module.exports = {};" > "${WORK_DIR}/my-test-pkg/index.js"

cd "${WORK_DIR}/my-test-pkg"
npm config set "//${BASE_URL#http*://}/api/v1/npm/${REPO_KEY}/:_authToken" "${ADMIN_TOKEN}"
npm publish --registry "${NPM_REGISTRY}" 2>&1
pass

# --- Consume ---
begin_test "Install package via npm"
mkdir -p "${WORK_DIR}/consumer"
cd "${WORK_DIR}/consumer"
npm init -y > /dev/null 2>&1
npm install "@test/my-test-pkg@1.0.${RUN_ID##*-}" --registry "${NPM_REGISTRY}" 2>&1
test -d node_modules/@test/my-test-pkg
pass

# --- Verify API ---
begin_test "Verify package via REST API"
resp=$(api_get "/api/v1/repositories/${REPO_KEY}/packages")
assert_contains "$resp" "my-test-pkg"
pass

end_suite
```

**Step 2: Write test-pypi.sh**

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi"
auth_admin
setup_workdir
require_cmd pip
require_cmd python3

REPO_KEY="test-pypi-${RUN_ID}"
PYPI_URL="${BASE_URL}/api/v1/pypi/${REPO_KEY}"

# --- Create repo ---
begin_test "Create PyPI local repository"
create_local_repo "$REPO_KEY" "pypi"
pass

# --- Build package ---
begin_test "Build test package"
PKG_DIR="${WORK_DIR}/testpkg"
mkdir -p "${PKG_DIR}/testpkg_e2e"
cat > "${PKG_DIR}/testpkg_e2e/__init__.py" <<'EOF'
__version__ = "1.0.0"
EOF
cat > "${PKG_DIR}/setup.py" <<'EOF'
from setuptools import setup, find_packages
setup(
    name="testpkg-e2e",
    version="1.0.0",
    packages=find_packages(),
)
EOF
cd "${PKG_DIR}"
python3 setup.py sdist bdist_wheel > /dev/null 2>&1
pass

# --- Upload ---
begin_test "Upload package via API"
DIST_FILE=$(ls "${PKG_DIR}/dist/"*.tar.gz | head -1)
curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -F "content=@${DIST_FILE}" \
  "${PYPI_URL}/upload" > /dev/null
pass

# --- Install ---
begin_test "Install package via pip"
pip install --index-url "${PYPI_URL}/simple/" \
  --trusted-host "$(echo "${BASE_URL}" | sed 's|http[s]*://||' | cut -d: -f1)" \
  --no-deps testpkg-e2e 2>&1
pass

# --- Verify API ---
begin_test "Verify package via REST API"
resp=$(api_get "/api/v1/repositories/${REPO_KEY}/packages")
assert_contains "$resp" "testpkg-e2e"
pass

end_suite
```

**Step 3: Write test-cargo.sh**

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/../lib/common.sh"

begin_suite "cargo"
auth_admin
setup_workdir
require_cmd cargo

REPO_KEY="test-cargo-${RUN_ID}"
CARGO_REGISTRY="${BASE_URL}/api/v1/cargo/${REPO_KEY}"

# --- Create repo ---
begin_test "Create Cargo local repository"
create_local_repo "$REPO_KEY" "cargo"
pass

# --- Build crate ---
begin_test "Create and package test crate"
cd "$WORK_DIR"
cargo init --name "test-crate-e2e" test-crate-e2e > /dev/null 2>&1
cd test-crate-e2e

# Configure the registry
mkdir -p .cargo
cat > .cargo/config.toml <<EOF
[registries.test]
index = "sparse+${CARGO_REGISTRY}/index/"
token = "Bearer ${ADMIN_TOKEN}"
EOF

cargo package --allow-dirty > /dev/null 2>&1
pass

# --- Publish ---
begin_test "Publish crate via cargo"
cargo publish --registry test --allow-dirty 2>&1 || {
  # Some versions need the token via env
  CARGO_REGISTRIES_TEST_TOKEN="Bearer ${ADMIN_TOKEN}" \
    cargo publish --registry test --allow-dirty 2>&1
}
pass

# --- Verify API ---
begin_test "Verify crate via REST API"
resp=$(api_get "/api/v1/repositories/${REPO_KEY}/packages")
assert_contains "$resp" "test-crate-e2e"
pass

end_suite
```

**Step 4: Commit**

```bash
chmod +x tests/formats/test-npm.sh tests/formats/test-pypi.sh tests/formats/test-cargo.sh
git add tests/formats/
git commit -m "feat: add npm, pypi, cargo format test scripts"
```

---

### Task 2.2 through 2.13: Remaining format tests

Each task follows the same pattern. I'll list them as batches with the key details for each format. The implementer should read the existing test script in `artifact-keeper/scripts/native-tests/` where one exists, and adapt it to the common.sh library pattern shown above.

**Task 2.2: Port test-maven.sh, test-go.sh**
- Maven: `mvn deploy` to `/maven/{key}/`, verify with `mvn dependency:get`
- Go: Set `GOPROXY`, run `go mod download`, verify cached module

**Task 2.3: Port test-helm.sh, test-docker.sh**
- Helm: `helm push` chart, `helm pull` it back, verify index
- Docker/OCI: `docker push`/`pull` via `/v2/` root path, verify manifest

**Task 2.4: Port test-deb.sh, test-rpm.sh, test-conda.sh**
- Debian: Upload `.deb`, configure APT source, `apt install`
- RPM: Upload `.rpm`, configure YUM repo, `dnf install`
- Conda: Upload package, configure channel, `conda install`

**Task 2.5: Port test-protobuf.sh, test-incus.sh**
- Protobuf: Upload descriptor to `/proto/{key}/`, verify via API
- Incus: Upload image metadata to `/incus/{key}/`, verify listing

**Task 2.6: Port test-proxy-virtual.sh (cross-format)**
- Create local + remote + virtual repos
- Verify writes rejected on remote, cached on proxy, aggregated on virtual

**Task 2.7: Write test-alpine.sh, test-nuget.sh, test-rubygems.sh**
- Alpine: Upload `.apk`, verify APKINDEX via curl
- NuGet: Push `.nupkg` via NuGet v3 API, query service index
- RubyGems: Push `.gem` via `/gems/{key}/api/v1/gems`, query specs

**Task 2.8: Write test-composer.sh, test-hex.sh, test-pub.sh**
- Composer: Upload package via API, query packages.json
- Hex: Upload package via API, query hex registry
- Pub: Upload package via API, query pub API versions endpoint

**Task 2.9: Write test-terraform.sh, test-swift.sh, test-conan.sh**
- Terraform: Upload module via API, query module versions
- Swift: Upload package via API, query swift package registry
- Conan: Upload recipe via API, query search endpoint

**Task 2.10: Write test-ansible.sh, test-chef.sh, test-puppet.sh**
- Ansible: Upload collection via API, query Galaxy-compatible endpoint
- Chef: Upload cookbook via API, query universe endpoint
- Puppet: Upload module via API, query Forge-compatible endpoint

**Task 2.11: Write test-cocoapods.sh, test-cran.sh, test-vscode.sh, test-jetbrains.sh**
- CocoaPods: Upload podspec via API, query spec repo
- CRAN: Upload source package, query PACKAGES index
- VSCode: Upload VSIX extension, query marketplace API
- JetBrains: Upload plugin JAR, query plugin repository XML

**Task 2.12: Write test-gitlfs.sh, test-huggingface.sh, test-mlmodel.sh**
- Git LFS: Batch API upload/download via `/lfs/{key}/`
- HuggingFace: Upload model files via API, query model card
- MLModel: Upload model via `/ext/mlmodel/{key}/`, query listing

**Task 2.13: Write test-generic.sh, test-sbt.sh, test-bazel.sh, test-opkg.sh, test-p2.sh, test-vagrant.sh, test-wasm.sh**
- Generic: Upload/download binary blob via `/generic/{key}/`
- SBT: Upload Ivy-style artifact to `/ivy/{key}/`, resolve via path
- Bazel: Upload module via `/ext/bazel/{key}/`, query registry
- Opkg: Upload `.ipk` via `/ext/opkg/{key}/`
- P2: Upload feature/bundle via `/ext/p2/{key}/`
- Vagrant: Upload box via `/ext/vagrant/{key}/`
- WASM: Upload plugin, verify format registration, proxy request

For each task: write the script, `chmod +x`, commit with message `feat: add <format> format test script`.

---

## Phase 3: Security, Stress, and Compatibility Tests

### Task 3.1: Security test scripts

**Files:**
- Create: `tests/security/test-trivy-scan.sh`
- Create: `tests/security/test-quality-gate-enforcement.sh`

Trivy scan test: upload a known-vulnerable Docker image, verify scan results appear via API. Quality gate test: create a gate with `max_critical_issues: 0`, upload vulnerable artifact, verify gate blocks it.

Note: these tests need `trivy.enabled: true` in the Helm values. The workflow should deploy with a modified overlay for the security suite.

### Task 3.2: Stress test scripts

**Files:**
- Create: `tests/stress/test-concurrent-uploads.sh`
- Create: `tests/stress/test-throughput.sh`

Port from `artifact-keeper/scripts/stress/run-concurrent-uploads.sh`. Adapt to use common.sh. Run N concurrent uploads (configurable, default 100), assert >= 95% success rate.

### Task 3.3: Compatibility test scripts

**Files:**
- Create: `tests/compatibility/test-api-version-compat.sh`

Deploy new backend + old web, verify UI loads and basic operations work. Then old backend + new web. Uses API version headers to verify backward compatibility.

For each task: write scripts, commit.

---

## Phase 4: Resilience Tests

### Task 4.1: Crash recovery tests

**Files:**
- Create: `tests/resilience/crash/test-backend-kill.sh`
- Create: `tests/resilience/crash/test-backend-oom.sh`
- Create: `tests/resilience/crash/test-graceful-shutdown.sh`

Pattern: upload artifacts, record count, kill pod (`kubectl delete pod --force`), wait for reschedule, verify count matches, upload succeeds again.

### Task 4.2: Restart tests

**Files:**
- Create: `tests/resilience/restart/test-rolling-restart.sh`
- Create: `tests/resilience/restart/test-pod-reschedule.sh`
- Create: `tests/resilience/restart/test-full-reboot.sh`
- Create: `tests/resilience/restart/test-postgres-restart.sh`

Pattern: seed data, perform restart operation, verify all data survives, verify new operations work.

### Task 4.3: Network degradation tests

**Files:**
- Create: `tests/resilience/network/test-latency-injection.sh`
- Create: `tests/resilience/network/test-packet-loss.sh`
- Create: `tests/resilience/network/test-upstream-timeout.sh`
- Create: `tests/resilience/network/test-dns-failure.sh`
- Create: `tests/resilience/network/test-partition-heal.sh`

Pattern: Use `kubectl exec` to run `tc netem` on the backend pod (requires `NET_ADMIN` capability). Inject degradation, verify operations complete (possibly slower), remove degradation, verify recovery.

For upstream timeout: deploy an nginx pod that returns 504 after 30s delay, configure as proxy upstream, verify backend handles timeout gracefully.

### Task 4.4: Storage failure tests

**Files:**
- Create: `tests/resilience/storage/test-disk-full.sh`
- Create: `tests/resilience/storage/test-storage-readonly.sh`
- Create: `tests/resilience/storage/test-pvc-remount.sh`

Pattern: Use `kubectl exec` to fill disk or change mount permissions. Verify uploads fail with clean error (not crash), reads still work, recovery after fix.

### Task 4.5: Data integrity tests

**Files:**
- Create: `tests/resilience/data/test-concurrent-writes.sh`
- Create: `tests/resilience/data/test-large-artifact.sh`
- Create: `tests/resilience/data/test-corrupt-upload.sh`

Pattern: Race two uploads of same version, verify exactly one wins. Upload 2GB+ file, verify streaming completes. Upload truncated package, verify 400 error not 500.

For each task: write scripts, commit.

---

## Phase 5: Mesh Tests

### Task 5.1: Port mesh test scripts

**Files:**
- Create: `tests/mesh/test-peer-registration.sh`
- Create: `tests/mesh/test-sync-policy.sh`
- Create: `tests/mesh/test-artifact-sync.sh`
- Create: `tests/mesh/test-retroactive-sync.sh`
- Create: `tests/mesh/test-heartbeat.sh`

Port from `artifact-keeper/scripts/mesh-e2e/` and `artifact-keeper-iac/e2e/mesh/configmap-test-script.yaml`. Adapt to common.sh. The mesh tests need `MAIN_URL`, `PEER1_URL`, `PEER2_URL`, `PEER3_URL` env vars set by the workflow.

---

## Phase 6: GitHub Actions Workflows

### Task 6.1: Create release-gate.yml

**Files:**
- Create: `.github/workflows/release-gate.yml`

The main coordinator workflow. Accepts inputs for component versions and test suite selection. Runs on `ak-e2e-runners` (self-hosted ARC). Manages the full lifecycle: deploy, test, collect, teardown.

Key structure:
```yaml
name: Release Gate
on:
  workflow_dispatch:
    inputs:
      backend_tag: { required: true, type: string }
      web_tag: { required: false, type: string, default: 'latest' }
      test_suite: { required: false, type: string, default: 'all' }
      skip_teardown: { required: false, type: boolean, default: false }
  workflow_call:
    inputs:
      backend_tag: { required: true, type: string }
      web_tag: { required: false, type: string, default: 'latest' }
      test_suite: { required: false, type: string, default: 'all' }
      skip_teardown: { required: false, type: boolean, default: false }

jobs:
  deploy:
    runs-on: ak-e2e-runners
    outputs:
      run_id: ${{ steps.setup.outputs.run_id }}
      backend_url: ${{ steps.deploy.outputs.backend_url }}
    steps: [generate run ID, deploy namespace]

  format-tests:
    needs: deploy
    runs-on: ak-e2e-runners
    strategy:
      matrix:
        batch: [node, python, jvm, rust-go-swift, system-packages, containers, misc-native, generic-protocol]
    steps: [run format test batch]

  security-tests:
    needs: deploy
    runs-on: ak-e2e-runners
    steps: [run security suite]

  stress-tests:
    needs: [format-tests, security-tests]
    runs-on: ak-e2e-runners
    steps: [run stress suite]

  resilience-tests:
    needs: stress-tests
    runs-on: ak-e2e-runners
    strategy:
      matrix:
        category: [crash, restart, network, storage, data]
    steps: [run resilience category]

  mesh-tests:
    needs: resilience-tests
    runs-on: ak-e2e-runners
    steps: [deploy mesh topology, run mesh suite, teardown mesh]

  collect-results:
    needs: [format-tests, security-tests, stress-tests, resilience-tests, mesh-tests]
    if: always()
    runs-on: ak-e2e-runners
    steps: [aggregate JUnit XML, publish summary]

  teardown:
    needs: collect-results
    if: always() && inputs.skip_teardown != true
    runs-on: ak-e2e-runners
    steps: [run teardown script]
```

### Task 6.2: Create GitHub repo and configure

**Steps:**
1. `gh repo create artifact-keeper/artifact-keeper-test --public`
2. Push the repo
3. Set GitHub Actions variables:
   - `TEST_MAX_CPU`, `TEST_MAX_MEMORY`, `TEST_MAX_NAMESPACES`, `TEST_NAMESPACE_CPU`, `TEST_NAMESPACE_MEMORY`
4. Set GitHub Actions secrets:
   - `GHCR_TOKEN` (for image pulls)
5. Verify ARC runners can pick up jobs from this repo

### Task 6.3: Integration test - run the full pipeline

**Steps:**
1. Trigger `release-gate.yml` manually with `backend_tag: dev`
2. Watch namespace creation, format test execution, teardown
3. Debug any failures
4. Verify JUnit results are published as workflow artifacts

---

## Execution Order

The phases should be implemented in order. Within each phase, tasks can be parallelized where noted.

| Phase | Tasks | Can Parallelize? |
|-------|-------|-----------------|
| 1. Foundation | 1.1 - 1.5 | 1.2 + 1.3 in parallel, rest sequential |
| 2. Format tests | 2.1 - 2.13 | All batches in parallel |
| 3. Security/stress/compat | 3.1 - 3.3 | All in parallel |
| 4. Resilience | 4.1 - 4.5 | All in parallel |
| 5. Mesh | 5.1 | Sequential |
| 6. Workflows + integration | 6.1 - 6.3 | Sequential |
