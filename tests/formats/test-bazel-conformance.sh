#!/usr/bin/env bash
# test-bazel-conformance.sh - Bazel remote cache/registry conformance tests
#
# Validates that the Bazel registry implementation at /ext/bazel/{repo_key}/
# conforms to the Bazel Central Registry protocol. Tests cover module upload
# and download, content integrity (SHA256), multiple file storage, 404 for
# missing paths, MODULE.bazel metadata, CAS (Content-Addressable Storage) by
# hash, and action cache GET/PUT.
#
# Endpoints: ${BASE_URL}/ext/bazel/{repo_key}/
#
# Requires: curl, shasum (or sha256sum)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "bazel-conformance"
auth_admin
setup_workdir

REPO_KEY="test-bzl-conf-${RUN_ID}"
BAZEL_URL="${BASE_URL}/ext/bazel/${REPO_KEY}"
MODULE_NAME="conftest_lib"
MODULE_VERSION="1.0.0"
MODULE_VERSION_2="2.0.0"
WASM_AVAILABLE=true

# -------------------------------------------------------------------------
# Setup: create repository and check plugin availability
# -------------------------------------------------------------------------

begin_test "Create bazel local repository"
if create_local_repo "$REPO_KEY" "bazel"; then
  pass
else
  fail "could not create bazel repository"
fi

begin_test "Check bazel WASM plugin availability"
PROBE_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BAZEL_URL}/") || true
if [ "$PROBE_CODE" = "404" ]; then
  WASM_AVAILABLE=false
  skip "bazel WASM plugin not loaded (HTTP 404), remaining tests will be skipped"
else
  pass
fi

# -------------------------------------------------------------------------
# Build test artifacts
# -------------------------------------------------------------------------

MODULE_BAZEL_FILE="${WORK_DIR}/MODULE.bazel"
cat > "$MODULE_BAZEL_FILE" <<'MODEOF'
module(
    name = "conftest_lib",
    version = "1.0.0",
    compatibility_level = 1,
)

bazel_dep(name = "rules_cc", version = "0.0.9")
MODEOF

# Create a source archive
mkdir -p "${WORK_DIR}/src/conftest_lib"
cat > "${WORK_DIR}/src/conftest_lib/BUILD" <<'EOF'
cc_library(
    name = "conftest_lib",
    srcs = ["lib.cc"],
    hdrs = ["lib.h"],
    visibility = ["//visibility:public"],
)
EOF
echo "// conftest_lib source" > "${WORK_DIR}/src/conftest_lib/lib.cc"
echo "// conftest_lib header" > "${WORK_DIR}/src/conftest_lib/lib.h"

SOURCE_ARCHIVE="${WORK_DIR}/source.tar.gz"
tar czf "$SOURCE_ARCHIVE" -C "${WORK_DIR}/src" conftest_lib

MODULE_SHA256=$(shasum -a 256 "$MODULE_BAZEL_FILE" | awk '{print $1}')
SOURCE_SHA256=$(shasum -a 256 "$SOURCE_ARCHIVE" | awk '{print $1}')

# =========================================================================
# Test 1: Upload a module (PUT MODULE.bazel)
# =========================================================================

begin_test "Upload MODULE.bazel descriptor"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${MODULE_BAZEL_FILE}" \
    "${BAZEL_URL}/modules/${MODULE_NAME}/${MODULE_VERSION}/MODULE.bazel") || true
  if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
    pass
  else
    fail "upload MODULE.bazel returned ${upload_status}, expected 200 or 201"
  fi
fi

# Upload the source archive alongside it
if [ "$WASM_AVAILABLE" = true ]; then
  curl -sf -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/gzip" \
    --data-binary "@${SOURCE_ARCHIVE}" \
    "${BAZEL_URL}/modules/${MODULE_NAME}/${MODULE_VERSION}/source.tar.gz" > /dev/null 2>&1 || true
fi

# =========================================================================
# Test 2: Download module by path
# =========================================================================

begin_test "Download MODULE.bazel by path"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  DL_MODULE="${WORK_DIR}/dl-MODULE.bazel"
  if curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      -o "$DL_MODULE" \
      "${BAZEL_URL}/modules/${MODULE_NAME}/${MODULE_VERSION}/MODULE.bazel"; then
    if [ -s "$DL_MODULE" ]; then
      pass
    else
      fail "downloaded MODULE.bazel is empty"
    fi
  else
    fail "GET MODULE.bazel failed"
  fi
fi

# =========================================================================
# Test 3: Content integrity verification (SHA256)
# =========================================================================

begin_test "Content integrity verification (SHA256 round-trip)"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  DL_SOURCE="${WORK_DIR}/dl-source.tar.gz"
  if curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      -o "$DL_SOURCE" \
      "${BAZEL_URL}/modules/${MODULE_NAME}/${MODULE_VERSION}/source.tar.gz"; then
    DL_SOURCE_SHA256=$(shasum -a 256 "$DL_SOURCE" | awk '{print $1}')
    if assert_eq "$DL_SOURCE_SHA256" "$SOURCE_SHA256" "source archive SHA256 mismatch after round-trip"; then
      pass
    fi
  else
    fail "GET source.tar.gz failed"
  fi
fi

# =========================================================================
# Test 4: Multiple files stored under one module
# =========================================================================

begin_test "Multiple files stored under one module version"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  # Upload a WORKSPACE file as a third artifact
  WORKSPACE_FILE="${WORK_DIR}/WORKSPACE"
  echo "workspace(name = \"conftest_lib\")" > "$WORKSPACE_FILE"

  ws_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORKSPACE_FILE}" \
    "${BAZEL_URL}/modules/${MODULE_NAME}/${MODULE_VERSION}/WORKSPACE") || true

  if [ "$ws_status" = "200" ] || [ "$ws_status" = "201" ]; then
    # Verify we can download both the MODULE.bazel and the WORKSPACE
    MOD_OK=false
    WS_OK=false
    if curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        "${BAZEL_URL}/modules/${MODULE_NAME}/${MODULE_VERSION}/MODULE.bazel" > /dev/null 2>&1; then
      MOD_OK=true
    fi
    if curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        "${BAZEL_URL}/modules/${MODULE_NAME}/${MODULE_VERSION}/WORKSPACE" > /dev/null 2>&1; then
      WS_OK=true
    fi

    if $MOD_OK && $WS_OK; then
      pass
    else
      fail "not all uploaded files are retrievable (MODULE.bazel=${MOD_OK}, WORKSPACE=${WS_OK})"
    fi
  else
    fail "WORKSPACE upload returned ${ws_status}"
  fi
fi

# =========================================================================
# Test 5: 404 for nonexistent module path
# =========================================================================

begin_test "GET nonexistent module returns 404"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BAZEL_URL}/modules/nonexistent_module/99.99.99/MODULE.bazel") || true
  if assert_eq "$HTTP_CODE" "404" "expected 404 for nonexistent module, got ${HTTP_CODE}"; then
    pass
  fi
fi

# =========================================================================
# Test 6: MODULE.bazel metadata content is correct
# =========================================================================

begin_test "MODULE.bazel metadata contains module name and version"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BAZEL_URL}/modules/${MODULE_NAME}/${MODULE_VERSION}/MODULE.bazel" 2>/dev/null); then
    if assert_contains "$resp" "conftest_lib" "MODULE.bazel should contain module name" && \
       assert_contains "$resp" "1.0.0" "MODULE.bazel should contain version"; then
      pass
    fi
  else
    fail "could not retrieve MODULE.bazel for metadata check"
  fi
fi

# =========================================================================
# Test 7: CAS (Content-Addressable Storage) by hash
# =========================================================================

begin_test "CAS blob upload and retrieval by hash"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  # Create a test blob and compute its SHA256
  CAS_BLOB="${WORK_DIR}/cas-blob.bin"
  echo "bazel-cas-test-content-${RUN_ID}" > "$CAS_BLOB"
  CAS_HASH=$(shasum -a 256 "$CAS_BLOB" | awk '{print $1}')
  CAS_SIZE=$(wc -c < "$CAS_BLOB" | tr -d ' ')

  # Upload to CAS endpoint
  cas_upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${CAS_BLOB}" \
    "${BAZEL_URL}/cas/blobs/${CAS_HASH}/${CAS_SIZE}") || true

  if [ "$cas_upload_status" = "200" ] || [ "$cas_upload_status" = "201" ]; then
    # Retrieve by hash
    DL_CAS="${WORK_DIR}/dl-cas-blob.bin"
    if curl -sf $CURL_TIMEOUT \
        -H "$(format_auth_header)" \
        -o "$DL_CAS" \
        "${BAZEL_URL}/cas/blobs/${CAS_HASH}/${CAS_SIZE}"; then
      DL_CAS_HASH=$(shasum -a 256 "$DL_CAS" | awk '{print $1}')
      if assert_eq "$DL_CAS_HASH" "$CAS_HASH" "CAS blob hash mismatch after retrieval"; then
        pass
      fi
    else
      fail "GET CAS blob by hash failed"
    fi
  elif [ "$cas_upload_status" = "404" ] || [ "$cas_upload_status" = "405" ]; then
    skip "CAS endpoint not implemented (HTTP ${cas_upload_status})"
  else
    fail "CAS blob upload returned ${cas_upload_status}"
  fi
fi

# =========================================================================
# Test 8: Action cache GET/PUT
# =========================================================================

begin_test "Action cache PUT and GET"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  # Create a minimal action result payload
  ACTION_HASH=$(echo "action-key-${RUN_ID}" | shasum -a 256 | awk '{print $1}')
  ACTION_RESULT="${WORK_DIR}/action-result.json"
  cat > "$ACTION_RESULT" <<EOJSON
{
  "output_files": [],
  "exit_code": 0,
  "stdout_raw": "",
  "stderr_raw": ""
}
EOJSON

  ac_upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${ACTION_RESULT}" \
    "${BAZEL_URL}/ac/actions/${ACTION_HASH}") || true

  if [ "$ac_upload_status" = "200" ] || [ "$ac_upload_status" = "201" ]; then
    # Retrieve the action result
    DL_ACTION="${WORK_DIR}/dl-action-result.json"
    if curl -sf $CURL_TIMEOUT \
        -H "$(format_auth_header)" \
        -o "$DL_ACTION" \
        "${BAZEL_URL}/ac/actions/${ACTION_HASH}"; then
      if [ -s "$DL_ACTION" ]; then
        pass
      else
        fail "downloaded action result is empty"
      fi
    else
      fail "GET action cache result failed"
    fi
  elif [ "$ac_upload_status" = "404" ] || [ "$ac_upload_status" = "405" ]; then
    skip "action cache endpoint not implemented (HTTP ${ac_upload_status})"
  else
    fail "action cache PUT returned ${ac_upload_status}"
  fi
fi

end_suite
