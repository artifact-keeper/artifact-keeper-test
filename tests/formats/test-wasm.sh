#!/usr/bin/env bash
# WASM binary format E2E test
# Tests .wasm file upload and listing via /ext/wasm/{repo_key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "wasm"
auth_admin
setup_workdir

REPO_KEY="test-wasm-${RUN_ID}"
MODULE_NAME="test-module"
MODULE_VERSION="1.0.$(date +%s)"
EXT_URL="${BASE_URL}/ext/wasm/${REPO_KEY}"
WASM_AVAILABLE=true

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create wasm local repository"
if create_local_repo "$REPO_KEY" "wasm_oci"; then
  pass
else
  fail "could not create wasm repo"
fi

# ---------------------------------------------------------------------------
# Check WASM plugin availability
# ---------------------------------------------------------------------------

begin_test "Check wasm WASM plugin availability"
PROBE_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${EXT_URL}/") || true
if [ "$PROBE_CODE" = "404" ]; then
  WASM_AVAILABLE=false
  skip "wasm WASM plugin not loaded (HTTP 404)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Create test .wasm binary
# ---------------------------------------------------------------------------

begin_test "Create test WASM binary"
cd "$WORK_DIR"

# Produce a minimal valid WASM binary.
# The WASM magic number is \0asm (00 61 73 6d) followed by version 1 (01 00 00 00).
# After the header, add an empty type section to make it a valid module.
printf '\x00\x61\x73\x6d' > test-module.wasm     # magic
printf '\x01\x00\x00\x00' >> test-module.wasm     # version 1
printf '\x01\x04\x01\x60\x00\x00' >> test-module.wasm  # type section: 1 func type () -> ()

pass

# ---------------------------------------------------------------------------
# Upload .wasm binary file
# ---------------------------------------------------------------------------

begin_test "Upload WASM binary"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "wasm WASM plugin not loaded"
else
  if resp=$(curl -sf -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/wasm" \
    --data-binary "@${WORK_DIR}/test-module.wasm" \
    "${EXT_URL}/${MODULE_NAME}/${MODULE_VERSION}/test-module.wasm" 2>&1); then
    pass
  else
    fail "upload test-module.wasm failed: ${resp}"
  fi
fi

# ---------------------------------------------------------------------------
# Query listing
# ---------------------------------------------------------------------------

begin_test "Query WASM module listing"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "wasm WASM plugin not loaded"
else
  sleep 1
  if resp=$(curl -sf "${EXT_URL}/" -H "$(format_auth_header)"); then
    if assert_contains "$resp" "$MODULE_NAME" "listing should contain module name"; then
      pass
    fi
  else
    # Try querying the specific module path
    if resp=$(curl -sf "${EXT_URL}/${MODULE_NAME}/" -H "$(format_auth_header)"); then
      if assert_contains "$resp" "$MODULE_NAME" "module path should contain module name"; then
        pass
      fi
    else
      fail "could not retrieve WASM module listing"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Download .wasm and verify content
# ---------------------------------------------------------------------------

begin_test "Download WASM binary"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "wasm WASM plugin not loaded"
else
  DL_FILE="${WORK_DIR}/downloaded.wasm"
  if curl -sf -H "$(format_auth_header)" -o "$DL_FILE" \
    "${EXT_URL}/${MODULE_NAME}/${MODULE_VERSION}/test-module.wasm"; then
    DL_SIZE=$(wc -c < "$DL_FILE" | tr -d ' ')
    ORIG_SIZE=$(wc -c < "${WORK_DIR}/test-module.wasm" | tr -d ' ')
    if assert_eq "$DL_SIZE" "$ORIG_SIZE" "downloaded WASM size should match original"; then
      pass
    fi
  else
    fail "download test-module.wasm failed"
  fi
fi

# ---------------------------------------------------------------------------
# Verify artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if [ "$WASM_AVAILABLE" = false ]; then
  skip "wasm WASM plugin not loaded"
else
  if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
    if assert_contains "$resp" "$MODULE_NAME" "artifact list should contain module name"; then
      pass
    fi
  else
    fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
  fi
fi

end_suite
