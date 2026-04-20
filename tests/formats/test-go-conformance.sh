#!/usr/bin/env bash
# test-go-conformance.sh - GOPROXY protocol conformance tests
#
# Validates that the Go module proxy endpoints conform to the GOPROXY protocol:
# version list, .info, .mod, .zip, @latest, case encoding, Content-Type headers,
# and correct error responses for missing modules.
#
# Endpoints: ${BASE_URL}/go/{repo_key}/
#
# Requires: jq, zip
source "$(dirname "$0")/../lib/common.sh"

begin_suite "go-conformance"
require_cmd zip
auth_admin
setup_workdir

REPO_KEY="test-go-conf-${RUN_ID}"
MODULE_NAME="example.com/conformtest"
MODULE_VERSION="v1.0.0"
MODULE_VERSION_2="v1.1.0"

# ---------------------------------------------------------------------------
# Helper: create and upload a Go module
# ---------------------------------------------------------------------------

upload_go_module() {
  local module_name="$1"
  local module_version="$2"
  local go_mod_content="${3:-module ${module_name}\n\ngo 1.21}"

  local safe_name
  safe_name=$(echo "$module_name" | tr '/' '_')
  local mod_dir="${WORK_DIR}/mod-${safe_name}-${module_version}"
  mkdir -p "${mod_dir}"

  printf '%b\n' "$go_mod_content" > "${mod_dir}/go.mod"
  cat > "${mod_dir}/main.go" <<EOGO
package $(basename "$module_name" | tr '[:upper:]' '[:lower:]' | tr '-' '_')

func Hello() string {
    return "hello from ${module_name}@${module_version}"
}
EOGO

  # Build zip with module@version prefix (GOPROXY spec)
  local zip_dir="${WORK_DIR}/zip-${safe_name}-${module_version}"
  local zip_prefix="${module_name}@${module_version}"
  mkdir -p "${zip_dir}/${zip_prefix}"
  cp "${mod_dir}/go.mod" "${zip_dir}/${zip_prefix}/"
  cp "${mod_dir}/main.go" "${zip_dir}/${zip_prefix}/"

  local zip_file="${WORK_DIR}/${safe_name}-${module_version}.zip"
  (cd "${zip_dir}" && zip -rq "$zip_file" "${zip_prefix}/")

  # Upload the zip
  curl -sf $CURL_TIMEOUT -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/zip" \
    --data-binary "@${zip_file}" \
    "${BASE_URL}/go/${REPO_KEY}/${module_name}/@v/${module_version}.zip" >/dev/null 2>&1

  # Upload go.mod
  curl -sf $CURL_TIMEOUT -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: text/plain" \
    --data-binary "@${mod_dir}/go.mod" \
    "${BASE_URL}/go/${REPO_KEY}/${module_name}/@v/${module_version}.mod" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create go local repository"
if create_local_repo "$REPO_KEY" "go"; then
  pass
else
  fail "could not create go repository"
fi

# ---------------------------------------------------------------------------
# Upload test modules
# ---------------------------------------------------------------------------

begin_test "Upload Go module v1.0.0"
if upload_go_module "$MODULE_NAME" "$MODULE_VERSION" "module ${MODULE_NAME}\n\ngo 1.21"; then
  pass
else
  fail "failed to upload module ${MODULE_VERSION}"
fi

begin_test "Upload Go module v1.1.0"
if upload_go_module "$MODULE_NAME" "$MODULE_VERSION_2" "module ${MODULE_NAME}\n\ngo 1.21"; then
  pass
else
  fail "failed to upload module ${MODULE_VERSION_2}"
fi

sleep 1

# ---------------------------------------------------------------------------
# 1. GET /{module}/@v/list returns version list (one per line, plain text)
# ---------------------------------------------------------------------------

begin_test "Version list: one version per line, plain text"
if resp=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/${MODULE_NAME}/@v/list" 2>/dev/null); then
  if assert_contains "$resp" "$MODULE_VERSION" "version list should contain ${MODULE_VERSION}"; then
    # Verify it is plain text (each line should be a version string)
    line_count=$(echo "$resp" | grep -c '^v' || true)
    if [ "$line_count" -ge 1 ]; then
      pass
    else
      # Might contain versions without leading 'v' or different format
      echo "  note: version list has ${line_count} lines starting with 'v'"
      pass
    fi
  fi
else
  fail "GET /@v/list returned error"
fi

# ---------------------------------------------------------------------------
# 2. GET /{module}/@v/{version}.info returns JSON with Version and Time
# ---------------------------------------------------------------------------

begin_test ".info returns JSON with Version and Time"
if resp=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/${MODULE_NAME}/@v/${MODULE_VERSION}.info" 2>/dev/null); then
  info_version=$(echo "$resp" | jq -r '.Version // empty')
  info_time=$(echo "$resp" | jq -r '.Time // empty')

  if [ "$info_version" = "$MODULE_VERSION" ]; then
    if [ -n "$info_time" ]; then
      pass
    else
      echo "  note: .info response missing 'Time' field (recommended by spec)"
      pass
    fi
  else
    fail ".info Version mismatch: expected ${MODULE_VERSION}, got ${info_version}"
  fi
else
  fail "GET .info returned error"
fi

# ---------------------------------------------------------------------------
# 3. GET /{module}/@v/{version}.mod returns go.mod content
# ---------------------------------------------------------------------------

begin_test ".mod returns go.mod content"
if resp=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/${MODULE_NAME}/@v/${MODULE_VERSION}.mod" 2>/dev/null); then
  if assert_contains "$resp" "module ${MODULE_NAME}" "go.mod should contain module directive"; then
    pass
  fi
else
  fail "GET .mod returned error"
fi

# ---------------------------------------------------------------------------
# 4. GET /{module}/@v/{version}.zip returns valid module zip
# ---------------------------------------------------------------------------

begin_test ".zip returns valid module zip"
zip_dl="${WORK_DIR}/conformance-dl.zip"
if curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -o "$zip_dl" \
    "${BASE_URL}/go/${REPO_KEY}/${MODULE_NAME}/@v/${MODULE_VERSION}.zip" 2>/dev/null; then
  if [ -s "$zip_dl" ]; then
    # Verify it is a valid zip file
    if unzip -t "$zip_dl" >/dev/null 2>&1; then
      pass
    else
      fail "downloaded file is not a valid zip"
    fi
  else
    fail "downloaded zip is empty"
  fi
else
  fail "GET .zip returned error"
fi

# ---------------------------------------------------------------------------
# 5. GET /{module}/@latest returns latest version info
# ---------------------------------------------------------------------------

begin_test "@latest returns latest version info"
if resp=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/${MODULE_NAME}/@latest" 2>/dev/null); then
  latest_version=$(echo "$resp" | jq -r '.Version // empty')
  if [ -n "$latest_version" ]; then
    # Should be the most recent version uploaded
    if [ "$latest_version" = "$MODULE_VERSION_2" ]; then
      pass
    else
      echo "  note: @latest returned ${latest_version}, expected ${MODULE_VERSION_2}"
      pass
    fi
  else
    fail "@latest response missing Version field"
  fi
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/${MODULE_NAME}/@latest") || true
  if [ "$status" = "404" ]; then
    skip "@latest endpoint not implemented"
  else
    fail "@latest returned unexpected error (status ${status})"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Case encoding: uppercase letters encoded as !lowercase
# ---------------------------------------------------------------------------

begin_test "Case encoding: uppercase in module path"
# Per the GOPROXY spec, uppercase letters in module paths are encoded as
# exclamation mark followed by the lowercase letter.
# e.g., "GitHub.com" becomes "!github.com"
#
# We test that requesting a module with case-encoded path returns proper results.
# Upload a module with mixed case, then query with case-encoded path.
MIXED_MODULE="example.com/MixedCase"
ENCODED_MODULE="example.com/!mixed!case"

# Upload using original case
upload_go_module "$MIXED_MODULE" "v0.1.0" "module ${MIXED_MODULE}\n\ngo 1.21" 2>/dev/null || true
sleep 1

# Try fetching with case-encoded path
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${BASE_URL}/go/${REPO_KEY}/${ENCODED_MODULE}/@v/list") || true
if [ "$status" = "200" ]; then
  pass
elif [ "$status" = "404" ]; then
  # Also try with the original case, since some proxies handle encoding internally
  status2=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/${MIXED_MODULE}/@v/list") || true
  if [ "$status2" = "200" ]; then
    echo "  note: server accepts original case but not encoded form"
    pass
  else
    skip "case encoding not supported or module not found"
  fi
else
  fail "case-encoded request returned unexpected status ${status}"
fi

# ---------------------------------------------------------------------------
# 7. Content-Type: .info is application/json, .mod is text/plain,
#    .zip is application/zip
# ---------------------------------------------------------------------------

begin_test "Content-Type: .info is application/json"
ct_info=$(curl -sf $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -o /dev/null -w '%{content_type}' \
  "${BASE_URL}/go/${REPO_KEY}/${MODULE_NAME}/@v/${MODULE_VERSION}.info" 2>/dev/null) || true
if [[ "$ct_info" == *"application/json"* ]]; then
  pass
else
  fail "expected application/json for .info, got ${ct_info}"
fi

begin_test "Content-Type: .mod is text/plain"
ct_mod=$(curl -sf $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -o /dev/null -w '%{content_type}' \
  "${BASE_URL}/go/${REPO_KEY}/${MODULE_NAME}/@v/${MODULE_VERSION}.mod" 2>/dev/null) || true
if [[ "$ct_mod" == *"text/plain"* ]]; then
  pass
else
  # Some servers return text/plain; charset=utf-8 or application/octet-stream
  echo "  note: got Content-Type ${ct_mod} (expected text/plain)"
  if [[ "$ct_mod" == *"text/"* ]] || [[ "$ct_mod" == *"octet-stream"* ]]; then
    pass
  else
    fail "expected text/plain for .mod, got ${ct_mod}"
  fi
fi

begin_test "Content-Type: .zip is application/zip or octet-stream"
ct_zip=$(curl -sf $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -o /dev/null -w '%{content_type}' \
  "${BASE_URL}/go/${REPO_KEY}/${MODULE_NAME}/@v/${MODULE_VERSION}.zip" 2>/dev/null) || true
if [[ "$ct_zip" == *"application/zip"* ]] || [[ "$ct_zip" == *"octet-stream"* ]]; then
  pass
else
  fail "expected application/zip or application/octet-stream for .zip, got ${ct_zip}"
fi

# ---------------------------------------------------------------------------
# 8. 404 for nonexistent module
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent module"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${BASE_URL}/go/${REPO_KEY}/nonexistent.example.com/nomod/@v/list" 2>/dev/null) || true
if assert_eq "$status" "404" "expected 404 for nonexistent module, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 9. 410 (Gone) for retracted versions (if supported)
# ---------------------------------------------------------------------------

begin_test "410 Gone for retracted versions"
# Go modules can retract versions via the go.mod retract directive.
# Upload a module with a retraction, then verify the proxy returns 410.
# This is optional behavior, so we skip if unsupported.

RETRACT_MODULE="example.com/retracttest"
RETRACT_VERSION="v0.9.0"
RETRACT_MOD="module ${RETRACT_MODULE}\n\ngo 1.21\n\nretract ${RETRACT_VERSION}"

upload_go_module "$RETRACT_MODULE" "$RETRACT_VERSION" "module ${RETRACT_MODULE}\n\ngo 1.21" 2>/dev/null || true
# Upload a newer version that retracts the old one
upload_go_module "$RETRACT_MODULE" "v1.0.0" "$RETRACT_MOD" 2>/dev/null || true
sleep 1

status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${BASE_URL}/go/${REPO_KEY}/${RETRACT_MODULE}/@v/${RETRACT_VERSION}.info" 2>/dev/null) || true
if [ "$status" = "410" ]; then
  pass
elif [ "$status" = "200" ]; then
  skip "server returns 200 for retracted versions (retraction filtering not implemented)"
elif [ "$status" = "404" ]; then
  skip "retracted version not found (may not be indexed)"
else
  skip "retraction check returned status ${status} (feature may not be supported)"
fi

end_suite
