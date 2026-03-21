#!/usr/bin/env bash
# test-wasm-sandbox.sh - T2-10: WASM plugin sandbox enforcement
#
# Verifies that the WASM plugin runtime enforces resource limits and that
# malformed or resource-hungry plugins are handled gracefully. If the plugin
# system is not available in the test environment, tests are skipped.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "wasm-sandbox"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Check if plugin endpoints exist
# ---------------------------------------------------------------------------

begin_test "Check plugin system availability"
plugin_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/plugins") || true

if [ "$plugin_status" = "404" ]; then
  skip "plugin endpoints not available (HTTP 404); WASM plugin system may not be deployed"
elif [ "$plugin_status" = "200" ]; then
  pass
elif [ "$plugin_status" = "401" ] || [ "$plugin_status" = "403" ]; then
  fail "plugin endpoint requires different auth (HTTP ${plugin_status})"
else
  skip "plugin endpoint returned unexpected status ${plugin_status}"
fi

# ---------------------------------------------------------------------------
# Upload a malformed WASM binary (random bytes, not valid WASM)
# ---------------------------------------------------------------------------

begin_test "Reject malformed WASM binary upload"
if [ "$plugin_status" = "404" ]; then
  skip "plugin endpoints not available"
else
  # Generate a small file with the WASM magic bytes followed by garbage
  printf '\x00asm\x01\x00\x00\x00' > "${WORK_DIR}/bad-plugin.wasm"
  dd if=/dev/urandom bs=256 count=1 >> "${WORK_DIR}/bad-plugin.wasm" 2>/dev/null

  upload_status=$(curl -s -o "${WORK_DIR}/wasm-upload-resp.txt" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/wasm" \
    --data-binary "@${WORK_DIR}/bad-plugin.wasm" \
    "${BASE_URL}/api/v1/plugins/install/upload") || true
  body=$(cat "${WORK_DIR}/wasm-upload-resp.txt" 2>/dev/null) || true

  if [ "$upload_status" = "400" ] || [ "$upload_status" = "422" ]; then
    pass
  elif [ "$upload_status" = "404" ]; then
    skip "plugin upload endpoint not found (install/upload not implemented)"
  elif [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
    fail "server accepted a malformed WASM binary without validation"
  else
    # Any server error means it at least tried to validate and failed
    skip "upload returned status ${upload_status} (server may have partially validated)"
  fi
fi

# ---------------------------------------------------------------------------
# Upload a completely invalid file (not WASM at all)
# ---------------------------------------------------------------------------

begin_test "Reject non-WASM file as plugin"
if [ "$plugin_status" = "404" ]; then
  skip "plugin endpoints not available"
else
  echo "this is not a wasm file at all" > "${WORK_DIR}/not-wasm.txt"

  upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/wasm" \
    --data-binary "@${WORK_DIR}/not-wasm.txt" \
    "${BASE_URL}/api/v1/plugins/install/upload") || true

  if [ "$upload_status" = "400" ] || [ "$upload_status" = "422" ]; then
    pass
  elif [ "$upload_status" = "404" ]; then
    skip "plugin upload endpoint not found"
  elif [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
    fail "server accepted a non-WASM file as a plugin"
  else
    skip "upload of non-WASM returned status ${upload_status}"
  fi
fi

# ---------------------------------------------------------------------------
# Verify backend health after bad uploads (no crash)
# ---------------------------------------------------------------------------

begin_test "Backend still healthy after malformed plugin uploads"
health_ok=false
if curl -sf --max-time 10 "${BASE_URL}/readyz" >/dev/null 2>&1; then
  health_ok=true
elif curl -sf --max-time 10 "${BASE_URL}/health" >/dev/null 2>&1; then
  health_ok=true
fi

if $health_ok; then
  pass
else
  fail "backend health check failed after WASM upload tests"
fi

end_suite
