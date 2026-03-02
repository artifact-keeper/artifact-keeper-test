#!/usr/bin/env bash
# Bazel registry E2E test
# Tests upload and retrieval of Bazel modules via /ext/bazel/{repo_key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "bazel"
auth_admin
setup_workdir

REPO_KEY="test-bazel-${RUN_ID}"
WASM_AVAILABLE=true

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create bazel local repository"
if create_local_repo "$REPO_KEY" "bazel"; then
  pass
else
  fail "could not create bazel repo"
fi

# ---------------------------------------------------------------------------
# Check WASM plugin availability
# ---------------------------------------------------------------------------

begin_test "Check bazel WASM plugin availability"
PROBE_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/ext/bazel/${REPO_KEY}/") || true
if [ "$PROBE_CODE" = "404" ]; then
  WASM_AVAILABLE=false
  skip "bazel WASM plugin not loaded (HTTP 404)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Upload MODULE.bazel descriptor
# ---------------------------------------------------------------------------

begin_test "Upload MODULE.bazel descriptor"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  cat > "${WORK_DIR}/MODULE.bazel" <<'MODEOF'
module(
    name = "test_lib",
    version = "1.0.0",
    compatibility_level = 1,
)

bazel_dep(name = "rules_cc", version = "0.0.9")
MODEOF

  if resp=$(curl -sf -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/MODULE.bazel" \
    "${BASE_URL}/ext/bazel/${REPO_KEY}/modules/test_lib/1.0.0/MODULE.bazel" 2>&1); then
    pass
  else
    fail "upload MODULE.bazel failed: ${resp}"
  fi
fi

# ---------------------------------------------------------------------------
# Upload source archive
# ---------------------------------------------------------------------------

begin_test "Upload source archive"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  mkdir -p "${WORK_DIR}/src/test_lib"
  echo "// test_lib source" > "${WORK_DIR}/src/test_lib/lib.cc"
  tar czf "${WORK_DIR}/source.tar.gz" -C "${WORK_DIR}/src" test_lib

  if resp=$(curl -sf -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/gzip" \
    --data-binary "@${WORK_DIR}/source.tar.gz" \
    "${BASE_URL}/ext/bazel/${REPO_KEY}/modules/test_lib/1.0.0/source.tar.gz" 2>&1); then
    pass
  else
    fail "upload source archive failed: ${resp}"
  fi
fi

# ---------------------------------------------------------------------------
# Query registry endpoint
# ---------------------------------------------------------------------------

begin_test "Retrieve MODULE.bazel"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  if resp=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/ext/bazel/${REPO_KEY}/modules/test_lib/1.0.0/MODULE.bazel"); then
    if assert_contains "$resp" "test_lib" "MODULE.bazel should contain module name"; then
      pass
    fi
  else
    fail "download MODULE.bazel failed"
  fi
fi

# ---------------------------------------------------------------------------
# Query registry index
# ---------------------------------------------------------------------------

begin_test "Query registry index"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  RESP_STATUS=$(curl -s -o "${WORK_DIR}/bazel_registry.json" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/ext/bazel/${REPO_KEY}/bazel_registry.json") || true

  if [ "$RESP_STATUS" -ge 200 ] 2>/dev/null && [ "$RESP_STATUS" -lt 300 ] 2>/dev/null; then
    pass
  else
    if [ "$RESP_STATUS" = "404" ]; then
      skip "registry index endpoint not implemented"
    else
      fail "registry index returned HTTP ${RESP_STATUS}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Verify artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "bazel WASM plugin not loaded"
else
  if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
    if assert_contains "$resp" "test_lib" "artifact list should contain module name"; then
      pass
    fi
  else
    fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
  fi
fi

end_suite
