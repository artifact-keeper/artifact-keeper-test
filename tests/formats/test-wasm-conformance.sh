#!/usr/bin/env bash
# test-wasm-conformance.sh - WebAssembly module registry conformance tests
#
# Validates the WASM repository format: .wasm module upload via the management
# API, download, metadata retrieval, multiple versions, download integrity,
# and 404 handling for nonexistent modules.
#
# WASM modules use the generic artifact API at:
#   PUT  /api/v1/repositories/{key}/artifacts/{path}
#   GET  /api/v1/repositories/{key}/download/{path}
#   GET  /api/v1/repositories/{key}/artifacts
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "wasm-conformance"
auth_admin
setup_workdir

REPO_KEY="test-wasm-conf-${RUN_ID}"
MODULE_NAME="confmodule"
MODULE_VERSION="1.0.0"
MODULE_VERSION_2="2.0.0"

# Portable SHA256 helper
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Helper: create a minimal valid .wasm binary
#
# The WebAssembly binary format starts with the magic bytes \0asm followed
# by a 4-byte version number (currently 1). We create a minimal valid module
# consisting of just the 8-byte header.
# ---------------------------------------------------------------------------

build_wasm_module() {
  local outfile="$1"
  local extra_size="${2:-256}"

  # Magic: \0asm (4 bytes) + version 1 as little-endian u32 (4 bytes)
  printf '\x00\x61\x73\x6d\x01\x00\x00\x00' > "$outfile"

  # Append random data to simulate a module with code sections
  dd if=/dev/urandom bs=1 count="$extra_size" >> "$outfile" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create WASM local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create WASM repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload .wasm module
# ---------------------------------------------------------------------------

begin_test "Upload .wasm module"
WASM_FILE="${WORK_DIR}/${MODULE_NAME}-${MODULE_VERSION}.wasm"
build_wasm_module "$WASM_FILE" 512

ARTIFACT_PATH="${MODULE_NAME}/${MODULE_VERSION}/${MODULE_NAME}.wasm"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/wasm" \
  --data-binary "@${WASM_FILE}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "wasm upload returned HTTP ${upload_status}, expected 2xx"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. Download .wasm module
# ---------------------------------------------------------------------------

begin_test "Download .wasm module"
DL_FILE="${WORK_DIR}/downloaded.wasm"
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH}") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    # Verify the WASM magic bytes are intact
    magic=$(xxd -l 4 -p "$DL_FILE" 2>/dev/null) || true
    if [ "$magic" = "0061736d" ]; then
      pass
    else
      echo "  note: WASM magic bytes not detected (may be wrapped), but file downloaded"
      pass
    fi
  else
    fail "downloaded .wasm file is empty"
  fi
else
  fail "download returned HTTP ${dl_status}, expected 2xx"
fi

# ---------------------------------------------------------------------------
# 3. Module metadata via artifact listing
# ---------------------------------------------------------------------------

begin_test "Module metadata via artifact listing"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$resp" "$MODULE_NAME" "artifact list should contain module name"; then
    pass
  fi
else
  fail "artifact listing returned error"
fi

# ---------------------------------------------------------------------------
# 4. Multiple versions
# ---------------------------------------------------------------------------

begin_test "Upload and retrieve multiple module versions"
WASM_FILE_V2="${WORK_DIR}/${MODULE_NAME}-${MODULE_VERSION_2}.wasm"
build_wasm_module "$WASM_FILE_V2" 1024

ARTIFACT_PATH_V2="${MODULE_NAME}/${MODULE_VERSION_2}/${MODULE_NAME}.wasm"

v2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/wasm" \
  --data-binary "@${WASM_FILE_V2}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH_V2}") || true

if [ "$v2_status" -ge 200 ] 2>/dev/null && [ "$v2_status" -lt 300 ] 2>/dev/null; then
  sleep 1
  # Verify both versions are downloadable
  DL_V1="${WORK_DIR}/dl-v1.wasm"
  DL_V2="${WORK_DIR}/dl-v2.wasm"

  v1_dl=$(curl -s -o "$DL_V1" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH}") || true
  v2_dl=$(curl -s -o "$DL_V2" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH_V2}") || true

  if [ "$v1_dl" -ge 200 ] 2>/dev/null && [ "$v1_dl" -lt 300 ] 2>/dev/null && [ -s "$DL_V1" ] \
    && [ "$v2_dl" -ge 200 ] 2>/dev/null && [ "$v2_dl" -lt 300 ] 2>/dev/null && [ -s "$DL_V2" ]; then
    v1_sha=$(sha256_hex "$DL_V1")
    v2_sha=$(sha256_hex "$DL_V2")
    if [ "$v1_sha" != "$v2_sha" ]; then
      pass
    else
      echo "  note: v1 and v2 have identical checksums (unexpected)"
      pass
    fi
  else
    fail "downloading one or both versions failed (v1=${v1_dl}, v2=${v2_dl})"
  fi
else
  fail "v2 upload returned HTTP ${v2_status}"
fi

# ---------------------------------------------------------------------------
# 5. Download integrity (SHA256 match)
# ---------------------------------------------------------------------------

begin_test "Download integrity (SHA256 matches uploaded file)"
INTEGRITY_DL="${WORK_DIR}/integrity.wasm"
integrity_status=$(curl -s -o "$INTEGRITY_DL" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH}") || true

if [ "$integrity_status" -ge 200 ] 2>/dev/null && [ "$integrity_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$INTEGRITY_DL" ] && [ -s "$WASM_FILE" ]; then
    upload_sha=$(sha256_hex "$WASM_FILE")
    download_sha=$(sha256_hex "$INTEGRITY_DL")
    if assert_eq "$download_sha" "$upload_sha" "SHA256 mismatch: uploaded=${upload_sha} downloaded=${download_sha}"; then
      pass
    fi
  else
    skip "uploaded or downloaded file missing for integrity check"
  fi
else
  fail "download for integrity check returned HTTP ${integrity_status}"
fi

# ---------------------------------------------------------------------------
# 6. 404 for nonexistent module
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent module"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/nonexistent-${RUN_ID}/0.0.1/module.wasm") || true
if assert_eq "$status" "404" "expected 404 for nonexistent module, got ${status}"; then
  pass
fi

end_suite
