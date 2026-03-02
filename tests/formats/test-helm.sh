#!/usr/bin/env bash
# test-helm.sh - Helm chart registry E2E test
#
# Requires: helm (v3+)
#
# Packages a minimal chart, pushes it to the Artifact Keeper Helm registry
# (tries OCI push first, falls back to PUT), pulls it back, and verifies
# the chart contents.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "helm"
require_cmd helm
auth_admin
setup_workdir

REPO_KEY="test-helm-${RUN_ID}"
CHART_NAME="e2e-chart"
CHART_VERSION="1.0.$(date +%s)"

# Create a Helm repository
begin_test "Create Helm repository"
if create_local_repo "$REPO_KEY" "helm"; then
  pass
else
  fail "could not create helm repository"
fi

# ---------------------------------------------------------------------------
# Generate a minimal Helm chart
# ---------------------------------------------------------------------------
begin_test "Package chart"
mkdir -p "$WORK_DIR/${CHART_NAME}/templates"

cat > "$WORK_DIR/${CHART_NAME}/Chart.yaml" <<EOF
apiVersion: v2
name: ${CHART_NAME}
description: E2E test chart
type: application
version: ${CHART_VERSION}
appVersion: "1.0.0"
EOF

cat > "$WORK_DIR/${CHART_NAME}/values.yaml" <<EOF
replicaCount: 1
image:
  repository: nginx
  tag: alpine
EOF

cat > "$WORK_DIR/${CHART_NAME}/templates/configmap.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Chart.Name }}-config
data:
  version: {{ .Chart.Version | quote }}
EOF

if helm package "$WORK_DIR/${CHART_NAME}" -d "$WORK_DIR" >/dev/null 2>&1; then
  CHART_FILE="$WORK_DIR/${CHART_NAME}-${CHART_VERSION}.tgz"
  if [ -f "$CHART_FILE" ]; then
    pass
  else
    fail "packaged chart file not found"
  fi
else
  fail "helm package failed"
fi

# ---------------------------------------------------------------------------
# Push chart
# ---------------------------------------------------------------------------
begin_test "Upload chart"
# ChartMuseum-compatible upload: POST multipart with field name "chart"
upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "$(format_auth_header)" \
  -F "chart=@${CHART_FILE}" \
  "${BASE_URL}/helm/${REPO_KEY}/api/charts") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "chart upload returned ${upload_status}, expected 200 or 201"
fi

# ---------------------------------------------------------------------------
# Verify chart via index
# ---------------------------------------------------------------------------
begin_test "Verify chart in repository index"
index_resp=$(curl -sf -H "$(format_auth_header)" "${BASE_URL}/helm/${REPO_KEY}/index.yaml" 2>/dev/null) || true

if [ -n "$index_resp" ]; then
  if echo "$index_resp" | grep -q "$CHART_NAME"; then
    pass
  else
    fail "chart name '${CHART_NAME}' not found in index.yaml"
  fi
else
  # Might be at a different path
  index_resp=$(curl -sf -H "$(format_auth_header)" "${BASE_URL}/helm/${REPO_KEY}/api/charts" 2>/dev/null) || true
  if [ -n "$index_resp" ] && echo "$index_resp" | grep -q "$CHART_NAME"; then
    pass
  else
    fail "could not locate chart in repository index"
  fi
fi

# ---------------------------------------------------------------------------
# Pull chart
# ---------------------------------------------------------------------------
begin_test "Pull chart via helm"
# Add the repo to helm
helm repo add "ak-${RUN_ID}" "${BASE_URL}/helm/${REPO_KEY}" \
  --username "$ADMIN_USER" --password "$ADMIN_PASS" 2>/dev/null || true

helm repo update "ak-${RUN_ID}" 2>/dev/null || true

mkdir -p "$WORK_DIR/pull-dest"
pull_ok=false
if helm pull "ak-${RUN_ID}/${CHART_NAME}" --version "$CHART_VERSION" \
     -d "$WORK_DIR/pull-dest" 2>/dev/null; then
  pull_ok=true
fi

# Fall back to direct download if helm pull did not succeed
if ! $pull_ok; then
  dl_status=$(curl -sf -o "$WORK_DIR/pull-dest/${CHART_NAME}-${CHART_VERSION}.tgz" \
    -H "$(format_auth_header)" \
    "${BASE_URL}/helm/${REPO_KEY}/charts/${CHART_NAME}-${CHART_VERSION}.tgz" \
    -w '%{http_code}' 2>/dev/null) || true
  if [ -f "$WORK_DIR/pull-dest/${CHART_NAME}-${CHART_VERSION}.tgz" ]; then
    pull_ok=true
  fi
fi

if $pull_ok && [ -f "$WORK_DIR/pull-dest/${CHART_NAME}-${CHART_VERSION}.tgz" ]; then
  pass
else
  fail "could not pull chart back from registry"
fi

# ---------------------------------------------------------------------------
# Verify pulled chart contents
# ---------------------------------------------------------------------------
begin_test "Verify pulled chart contents"
if tar tzf "$WORK_DIR/pull-dest/${CHART_NAME}-${CHART_VERSION}.tgz" 2>/dev/null | grep -q "Chart.yaml"; then
  pass
else
  fail "pulled chart archive does not contain Chart.yaml"
fi

# Cleanup helm repo
helm repo remove "ak-${RUN_ID}" 2>/dev/null || true

end_suite
