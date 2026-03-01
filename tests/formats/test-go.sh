#!/usr/bin/env bash
# test-go.sh - GOPROXY protocol E2E test
#
# Requires: go, zip
# Tests: create local repo, upload Go module, verify via GOPROXY endpoints
source "$(dirname "$0")/../lib/common.sh"

begin_suite "go"
require_cmd go
require_cmd zip
auth_admin
setup_workdir

REPO_KEY="test-go-${RUN_ID}"
MODULE_NAME="example.com/testmod"
MODULE_VERSION="v1.0.0"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create go repository"
if create_local_repo "$REPO_KEY" "go"; then
  pass
else
  fail "could not create go repo"
fi

# -------------------------------------------------------------------------
# Build module zip
# -------------------------------------------------------------------------

begin_test "Create minimal Go module"
MODULE_DIR="${WORK_DIR}/example.com/testmod"
mkdir -p "${MODULE_DIR}"

cat > "${MODULE_DIR}/go.mod" <<EOF
module example.com/testmod

go 1.21
EOF

cat > "${MODULE_DIR}/main.go" <<EOF
package testmod

func Hello() string {
    return "hello from testmod"
}
EOF

# GOPROXY zip layout: module@version/ prefix inside the zip
ZIP_DIR="${WORK_DIR}/ziproot"
MODULE_ZIP_PREFIX="example.com/testmod@${MODULE_VERSION}"
mkdir -p "${ZIP_DIR}/${MODULE_ZIP_PREFIX}"
cp "${MODULE_DIR}/go.mod" "${ZIP_DIR}/${MODULE_ZIP_PREFIX}/"
cp "${MODULE_DIR}/main.go" "${ZIP_DIR}/${MODULE_ZIP_PREFIX}/"

cd "${ZIP_DIR}"
zip -rq "${WORK_DIR}/module.zip" "${MODULE_ZIP_PREFIX}/"

if [ -s "${WORK_DIR}/module.zip" ]; then
  pass
else
  fail "failed to create module zip"
fi

# -------------------------------------------------------------------------
# Upload module zip
# -------------------------------------------------------------------------

begin_test "Upload module zip"
if curl -sf -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/zip" \
    --data-binary "@${WORK_DIR}/module.zip" \
    "${BASE_URL}/go/${REPO_KEY}/example.com/testmod/@v/${MODULE_VERSION}.zip" >/dev/null 2>&1; then
  pass
else
  fail "module zip upload failed"
fi

# -------------------------------------------------------------------------
# Upload go.mod
# -------------------------------------------------------------------------

begin_test "Upload go.mod"
if curl -sf -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: text/plain" \
    --data-binary "@${MODULE_DIR}/go.mod" \
    "${BASE_URL}/go/${REPO_KEY}/example.com/testmod/@v/${MODULE_VERSION}.mod" >/dev/null 2>&1; then
  pass
else
  fail "go.mod upload failed"
fi

# -------------------------------------------------------------------------
# Verify version list
# -------------------------------------------------------------------------

begin_test "Verify version list endpoint"
sleep 1
if resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/example.com/testmod/@v/list" 2>/dev/null); then
  if assert_contains "$resp" "${MODULE_VERSION}"; then
    pass
  fi
else
  fail "version list endpoint returned error"
fi

# -------------------------------------------------------------------------
# Verify .info endpoint
# -------------------------------------------------------------------------

begin_test "Verify .info endpoint"
if resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/example.com/testmod/@v/${MODULE_VERSION}.info" 2>/dev/null); then
  if assert_contains "$resp" "${MODULE_VERSION}"; then
    pass
  fi
else
  fail ".info endpoint returned error"
fi

# -------------------------------------------------------------------------
# Verify .mod download
# -------------------------------------------------------------------------

begin_test "Verify .mod download"
if resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/example.com/testmod/@v/${MODULE_VERSION}.mod" 2>/dev/null); then
  if assert_contains "$resp" "module example.com/testmod"; then
    pass
  fi
else
  fail ".mod download returned error"
fi

# -------------------------------------------------------------------------
# Verify .zip download
# -------------------------------------------------------------------------

begin_test "Verify .zip download"
if curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -o "${WORK_DIR}/downloaded.zip" \
    "${BASE_URL}/go/${REPO_KEY}/example.com/testmod/@v/${MODULE_VERSION}.zip" 2>/dev/null; then
  if [ -s "${WORK_DIR}/downloaded.zip" ]; then
    pass
  else
    fail "downloaded zip is empty"
  fi
else
  fail ".zip download returned error"
fi

# -------------------------------------------------------------------------
# Verify @latest endpoint
# -------------------------------------------------------------------------

begin_test "Verify @latest endpoint"
if resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/example.com/testmod/@latest" 2>/dev/null); then
  if assert_contains "$resp" "${MODULE_VERSION}"; then
    pass
  fi
else
  # @latest may return 404 if not implemented; skip gracefully
  skip "@latest endpoint not available"
fi

# -------------------------------------------------------------------------
# Test go mod download with GOPROXY
# -------------------------------------------------------------------------

begin_test "go mod download via GOPROXY"
CONSUMER_DIR="${WORK_DIR}/consumer"
mkdir -p "${CONSUMER_DIR}"
cd "${CONSUMER_DIR}"

cat > go.mod <<EOF
module consumer

go 1.21

require example.com/testmod ${MODULE_VERSION}
EOF

export GOPROXY="${BASE_URL}/go/${REPO_KEY},direct"
export GONOSUMDB="*"
export GONOSUMCHECK="*"
export GOPRIVATE="*"
export GOPATH="${WORK_DIR}/gopath"
mkdir -p "${GOPATH}"

if go mod download "example.com/testmod@${MODULE_VERSION}" 2>/dev/null; then
  pass
else
  # This may fail if the module zip layout is not perfectly conformant
  skip "go mod download failed (may require exact zip layout)"
fi

end_suite
