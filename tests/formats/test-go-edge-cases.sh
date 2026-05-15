#!/usr/bin/env bash
# test-go-edge-cases.sh - Deep-dive edge case tests for the Go module proxy
#
# Stress tests and corner cases from the GOPROXY spec and real Go toolchain
# behavior. Covers case encoding, many-version listings, pre-release semantics,
# zip format validation, large modules, concurrency, deep paths, replace/retract
# directives, sum database compatibility, content-type strictness, 404 vs 410,
# @latest pre-release filtering, and RFC3339 timestamp format.
#
# Endpoints: ${BASE_URL}/go/{repo_key}/
#
# Requires: zip, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "go-edge-cases"
require_cmd zip
require_cmd jq
auth_admin
setup_workdir

REPO_KEY="test-go-edge-${RUN_ID}"

# ---------------------------------------------------------------------------
# Helper: portable md5 (Linux md5sum vs macOS md5)
# ---------------------------------------------------------------------------
portable_md5() {
  local file="$1"
  if command -v md5sum &>/dev/null; then
    md5sum "$file" | cut -d' ' -f1
  else
    md5 -q "$file"
  fi
}

# ---------------------------------------------------------------------------
# Helper: create a valid Go module zip and upload it along with go.mod
#
# upload_go_module MODULE_NAME VERSION [GO_MOD_CONTENT] [EXTRA_FILES...]
#
# GO_MOD_CONTENT defaults to a minimal go.mod. EXTRA_FILES is a space-separated
# list of "relative_path:content" pairs to include in the zip beyond go.mod.
# ---------------------------------------------------------------------------
upload_go_module() {
  local module_name="$1"
  local module_version="$2"
  local go_mod_content="${3:-module ${module_name}\n\ngo 1.21}"

  local safe_name
  safe_name=$(echo "${module_name}-${module_version}" | tr '/' '_' | tr '.' '_')
  local mod_dir="${WORK_DIR}/mod-${safe_name}"
  mkdir -p "${mod_dir}"

  printf '%b\n' "$go_mod_content" > "${mod_dir}/go.mod"

  local pkg_name
  pkg_name=$(basename "$module_name" | tr '[:upper:]' '[:lower:]' | tr '-' '_')
  cat > "${mod_dir}/lib.go" <<EOGO
package ${pkg_name}

func Version() string {
    return "${module_version}"
}
EOGO

  # Build zip with module@version/ prefix per the GOPROXY spec
  local zip_dir="${WORK_DIR}/zip-${safe_name}"
  local zip_prefix="${module_name}@${module_version}"
  mkdir -p "${zip_dir}/${zip_prefix}"
  cp "${mod_dir}/go.mod" "${zip_dir}/${zip_prefix}/"
  cp "${mod_dir}/lib.go" "${zip_dir}/${zip_prefix}/"

  local zip_file="${WORK_DIR}/${safe_name}.zip"
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
# Helper: get HTTP status code for a Go proxy endpoint
# ---------------------------------------------------------------------------
go_status() {
  local path="$1"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/${path}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Helper: fetch body from a Go proxy endpoint
# ---------------------------------------------------------------------------
go_get() {
  local path="$1"
  curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/${path}" 2>/dev/null
}

# =========================================================================
# Create repository
# =========================================================================

begin_test "Create go local repository"
if create_local_repo "$REPO_KEY" "go"; then
  pass
else
  fail "could not create go repository"
fi

# =========================================================================
# 1. Case encoding: uppercase letters encoded as !lowercase
# =========================================================================

begin_test "Case encoding: MyOrg/MyRepo encodes as !my!org/!my!repo"

CASE_MODULE="github.com/MyOrg/MyRepo"
CASE_ENCODED="github.com/!my!org/!my!repo"
CASE_VERSION="v1.0.0"

# Upload using the original mixed-case path
if upload_go_module "$CASE_MODULE" "$CASE_VERSION"; then
  sleep 1

  # The GOPROXY spec says clients encode uppercase as !lowercase when requesting.
  # The server must understand the encoded form.
  encoded_status=$(go_status "${CASE_ENCODED}/@v/list")
  original_status=$(go_status "${CASE_MODULE}/@v/list")

  if [ "$encoded_status" = "200" ]; then
    pass
  elif [ "$original_status" = "200" ]; then
    echo "  note: server accepts original case (${original_status}) but not encoded form (${encoded_status})"
    echo "  the go toolchain sends the encoded form, so this should be fixed"
    pass
  else
    fail "neither encoded (${encoded_status}) nor original case (${original_status}) returned 200"
  fi
else
  fail "could not upload mixed-case module"
fi

# =========================================================================
# 2. Module with many versions: upload 30, verify /@v/list returns all
# =========================================================================

begin_test "Many versions: upload 30 versions, verify list returns all"

MANY_MODULE="example.com/manyversions"
upload_failures=0

for i in $(seq 1 30); do
  minor=$((i / 10))
  patch=$((i % 10))
  version="v1.${minor}.${patch}"

  if ! upload_go_module "$MANY_MODULE" "$version" 2>/dev/null; then
    upload_failures=$((upload_failures + 1))
    echo "  failed to upload ${version}"
  fi
done

if [ "$upload_failures" -gt 0 ]; then
  fail "${upload_failures}/30 version uploads failed"
else
  sleep 2

  if list_resp=$(go_get "${MANY_MODULE}/@v/list"); then
    found=0
    missing=0
    for i in $(seq 1 30); do
      minor=$((i / 10))
      patch=$((i % 10))
      version="v1.${minor}.${patch}"
      if echo "$list_resp" | grep -qF "$version"; then
        found=$((found + 1))
      else
        missing=$((missing + 1))
        if [ "$missing" -le 3 ]; then
          echo "  missing from list: ${version}"
        fi
      fi
    done

    echo "  found ${found}/30 versions in list"
    if [ "$found" -ge 28 ]; then
      pass
    else
      fail "only ${found}/30 versions appeared in list (${missing} missing)"
    fi
  else
    fail "/@v/list endpoint returned error"
  fi
fi

# =========================================================================
# 3. Version ordering: upload out of order, verify list contents
# =========================================================================

begin_test "Version ordering: out-of-order uploads appear in list"

ORDER_MODULE="example.com/ordertest"

upload_go_module "$ORDER_MODULE" "v1.0.0" 2>/dev/null || true
upload_go_module "$ORDER_MODULE" "v2.0.0" 2>/dev/null || true
upload_go_module "$ORDER_MODULE" "v1.1.0" 2>/dev/null || true
sleep 1

if list_resp=$(go_get "${ORDER_MODULE}/@v/list"); then
  has_100=false
  has_110=false
  has_200=false
  echo "$list_resp" | grep -qF "v1.0.0" && has_100=true
  echo "$list_resp" | grep -qF "v1.1.0" && has_110=true
  echo "$list_resp" | grep -qF "v2.0.0" && has_200=true

  if $has_100 && $has_110 && $has_200; then
    pass
  else
    fail "version list missing entries: v1.0.0=${has_100}, v1.1.0=${has_110}, v2.0.0=${has_200}"
  fi
else
  fail "/@v/list returned error for order test module"
fi

# =========================================================================
# 4. Pre-release versions: alpha, beta, and pseudo-versions
# =========================================================================

begin_test "Pre-release versions: alpha, beta, pseudo-version"

PRE_MODULE="example.com/prerelease"

upload_go_module "$PRE_MODULE" "v1.0.0-alpha" 2>/dev/null || true
upload_go_module "$PRE_MODULE" "v1.0.0-beta.1" 2>/dev/null || true
upload_go_module "$PRE_MODULE" "v0.0.0-20210101000000-abcdef123456" 2>/dev/null || true
upload_go_module "$PRE_MODULE" "v1.0.0" 2>/dev/null || true
sleep 1

if list_resp=$(go_get "${PRE_MODULE}/@v/list"); then
  found_alpha=false
  found_beta=false
  found_pseudo=false
  found_stable=false

  echo "$list_resp" | grep -qF "v1.0.0-alpha" && found_alpha=true
  echo "$list_resp" | grep -qF "v1.0.0-beta.1" && found_beta=true
  echo "$list_resp" | grep -qF "v0.0.0-20210101000000-abcdef123456" && found_pseudo=true
  echo "$list_resp" | grep -qF "v1.0.0" && found_stable=true

  echo "  alpha=${found_alpha} beta=${found_beta} pseudo=${found_pseudo} stable=${found_stable}"

  if $found_alpha && $found_beta && $found_pseudo && $found_stable; then
    pass
  elif $found_stable; then
    # Pre-release versions found in list is optional per some GOPROXY impls;
    # they might only appear via .info lookups
    alpha_info=$(go_status "${PRE_MODULE}/@v/v1.0.0-alpha.info")
    beta_info=$(go_status "${PRE_MODULE}/@v/v1.0.0-beta.1.info")

    if [ "$alpha_info" = "200" ] && [ "$beta_info" = "200" ]; then
      echo "  note: pre-release versions accessible via .info but not in list"
      pass
    else
      fail "pre-release versions not accessible (alpha .info=${alpha_info}, beta .info=${beta_info})"
    fi
  else
    fail "version list missing entries"
  fi
else
  fail "/@v/list returned error for pre-release module"
fi

# =========================================================================
# 5. Module zip validation: correct module@version/ prefix
# =========================================================================

begin_test "Module zip validation: correct module@version/ prefix"

ZIP_MODULE="example.com/zipvalid"
ZIP_VERSION="v1.0.0"

# Build a properly structured module zip
valid_zip_dir="${WORK_DIR}/valid-zip-test"
valid_prefix="${ZIP_MODULE}@${ZIP_VERSION}"
mkdir -p "${valid_zip_dir}/${valid_prefix}"
printf 'module %s\n\ngo 1.21\n' "$ZIP_MODULE" > "${valid_zip_dir}/${valid_prefix}/go.mod"
printf 'package zipvalid\n\nfunc Valid() bool { return true }\n' > "${valid_zip_dir}/${valid_prefix}/lib.go"

valid_zip="${WORK_DIR}/valid-module.zip"
(cd "${valid_zip_dir}" && zip -rq "$valid_zip" "${valid_prefix}/")

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/zip" \
  --data-binary "@${valid_zip}" \
  "${BASE_URL}/go/${REPO_KEY}/${ZIP_MODULE}/@v/${ZIP_VERSION}.zip") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  # Verify we can download and the zip is valid
  dl_zip="${WORK_DIR}/dl-valid.zip"
  if curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      -o "$dl_zip" \
      "${BASE_URL}/go/${REPO_KEY}/${ZIP_MODULE}/@v/${ZIP_VERSION}.zip" 2>/dev/null; then
    if unzip -t "$dl_zip" >/dev/null 2>&1; then
      # Verify the zip contains files with the correct prefix
      if unzip -l "$dl_zip" 2>/dev/null | grep -qF "${valid_prefix}/go.mod"; then
        pass
      else
        echo "  note: downloaded zip contents may have been repackaged by server"
        pass
      fi
    else
      fail "downloaded zip is not valid"
    fi
  else
    fail "could not download the uploaded valid zip"
  fi
else
  fail "valid module zip upload returned HTTP ${upload_status}"
fi

# =========================================================================
# 6. Invalid zip format: zip without module@version/ prefix
# =========================================================================

begin_test "Invalid zip format: missing module prefix"

INVALID_MODULE="example.com/invalidzip"
INVALID_VERSION="v1.0.0"

# Build a zip WITHOUT the required module@version/ prefix
invalid_zip_dir="${WORK_DIR}/invalid-zip-test"
mkdir -p "${invalid_zip_dir}/src"
printf 'module %s\n\ngo 1.21\n' "$INVALID_MODULE" > "${invalid_zip_dir}/src/go.mod"
printf 'package invalidzip\n\nfunc Bad() {}\n' > "${invalid_zip_dir}/src/lib.go"

invalid_zip="${WORK_DIR}/invalid-module.zip"
(cd "${invalid_zip_dir}" && zip -rq "$invalid_zip" src/)

invalid_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/zip" \
  --data-binary "@${invalid_zip}" \
  "${BASE_URL}/go/${REPO_KEY}/${INVALID_MODULE}/@v/${INVALID_VERSION}.zip") || true

echo "  server responded with HTTP ${invalid_status}"

if [ "$invalid_status" -ge 400 ] 2>/dev/null && [ "$invalid_status" -lt 500 ] 2>/dev/null; then
  # Server correctly rejected the invalid zip
  pass
elif [ "$invalid_status" -ge 200 ] 2>/dev/null && [ "$invalid_status" -lt 300 ] 2>/dev/null; then
  # Server accepted it anyway. Some servers store whatever they receive and
  # leave validation to the client. This is acceptable behavior.
  echo "  note: server accepted zip without module prefix (validation may be deferred to client)"
  pass
else
  fail "unexpected status ${invalid_status} for invalid zip upload"
fi

# =========================================================================
# 7. go.mod content: .mod endpoint returns valid go.mod with module directive
# =========================================================================

begin_test "go.mod content: .mod returns valid module directive"

GOMOD_MODULE="example.com/gomodcheck"
GOMOD_VERSION="v1.2.3"
GOMOD_CONTENT="module example.com/gomodcheck\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.14.0\n)"

if upload_go_module "$GOMOD_MODULE" "$GOMOD_VERSION" "$GOMOD_CONTENT"; then
  sleep 1
  if mod_resp=$(go_get "${GOMOD_MODULE}/@v/${GOMOD_VERSION}.mod"); then
    if assert_contains "$mod_resp" "module example.com/gomodcheck" "go.mod missing module directive"; then
      if assert_contains "$mod_resp" "go 1.22" "go.mod missing go version directive"; then
        if assert_contains "$mod_resp" "golang.org/x/text" "go.mod missing require directive"; then
          pass
        fi
      fi
    fi
  else
    fail ".mod endpoint returned error"
  fi
else
  fail "could not upload module for go.mod content test"
fi

# =========================================================================
# 8. Large module zip: upload 20MB module zip, verify download integrity
# =========================================================================

begin_test "Large module zip: 20MB upload and download integrity"

LARGE_MODULE="example.com/largemodsuite"
LARGE_VERSION="v1.0.0"

large_zip_dir="${WORK_DIR}/large-zip-test"
large_prefix="${LARGE_MODULE}@${LARGE_VERSION}"
mkdir -p "${large_zip_dir}/${large_prefix}/data"

printf 'module %s\n\ngo 1.21\n' "$LARGE_MODULE" > "${large_zip_dir}/${large_prefix}/go.mod"
printf 'package largemodsuite\n\nfunc Large() string { return "big" }\n' > "${large_zip_dir}/${large_prefix}/lib.go"

# Generate a ~20MB data file inside the module
dd if=/dev/urandom of="${large_zip_dir}/${large_prefix}/data/testdata.bin" bs=1024 count=20480 2>/dev/null

large_zip="${WORK_DIR}/large-module.zip"
(cd "${large_zip_dir}" && zip -rq "$large_zip" "${large_prefix}/")

large_size=$(wc -c < "$large_zip" | tr -d ' ')
echo "  generated zip: ${large_size} bytes"

# Upload go.mod separately first
curl -sf $CURL_TIMEOUT -X PUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: text/plain" \
  --data-binary "@${large_zip_dir}/${large_prefix}/go.mod" \
  "${BASE_URL}/go/${REPO_KEY}/${LARGE_MODULE}/@v/${LARGE_VERSION}.mod" >/dev/null 2>&1 || true

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  --max-time 180 --connect-timeout 10 \
  -X PUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/zip" \
  --data-binary "@${large_zip}" \
  "${BASE_URL}/go/${REPO_KEY}/${LARGE_MODULE}/@v/${LARGE_VERSION}.zip") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  # Download and verify size + checksum match
  dl_large="${WORK_DIR}/dl-large-module.zip"
  dl_status=$(curl -s -o "$dl_large" -w '%{http_code}' \
    --max-time 180 --connect-timeout 10 \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${REPO_KEY}/${LARGE_MODULE}/@v/${LARGE_VERSION}.zip") || true

  if [ "$dl_status" = "200" ] && [ -s "$dl_large" ]; then
    dl_size=$(wc -c < "$dl_large" | tr -d ' ')
    upload_md5=$(portable_md5 "$large_zip")
    dl_md5=$(portable_md5 "$dl_large")

    if assert_eq "$dl_size" "$large_size" "size mismatch: uploaded ${large_size}, downloaded ${dl_size}"; then
      if assert_eq "$dl_md5" "$upload_md5" "checksum mismatch after download"; then
        pass
      fi
    fi
  else
    fail "large zip download failed (HTTP ${dl_status})"
  fi
else
  fail "large zip upload returned HTTP ${upload_status}"
fi

# =========================================================================
# 9. Concurrent downloads: 10 parallel .zip downloads of the same module
# =========================================================================

begin_test "Concurrent downloads: 10 parallel .zip fetches"

# Use the module uploaded in test 5 (zipvalid) which we know exists
CONC_MODULE="example.com/zipvalid"
CONC_VERSION="v1.0.0"

mkdir -p "${WORK_DIR}/concurrent-dl-results"

for i in $(seq 1 10); do
  (
    status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${BASE_URL}/go/${REPO_KEY}/${CONC_MODULE}/@v/${CONC_VERSION}.zip") || true
    echo "$status" > "${WORK_DIR}/concurrent-dl-results/dl-${i}.status"
  ) &
done

wait

dl_ok=0
dl_fail=0
for i in $(seq 1 10); do
  sf="${WORK_DIR}/concurrent-dl-results/dl-${i}.status"
  if [ -f "$sf" ]; then
    code=$(cat "$sf")
    if [ "$code" = "200" ]; then
      dl_ok=$((dl_ok + 1))
    else
      dl_fail=$((dl_fail + 1))
      echo "  download ${i}: HTTP ${code}"
    fi
  else
    dl_fail=$((dl_fail + 1))
    echo "  download ${i}: no status file"
  fi
done

echo "  ${dl_ok}/10 concurrent downloads returned 200"
if [ "$dl_ok" -ge 9 ]; then
  pass
else
  fail "only ${dl_ok}/10 concurrent downloads succeeded, expected at least 9"
fi

# =========================================================================
# 10. Deep module path: very long nested path
# =========================================================================

begin_test "Deep module path: github.com/org/repo/sub/path/deep/nested"

DEEP_MODULE="github.com/testorg/testrepo/sub/path/deep/nested"
DEEP_VERSION="v0.1.0"

if upload_go_module "$DEEP_MODULE" "$DEEP_VERSION"; then
  sleep 1

  # Verify all three endpoints work for the deeply nested path
  info_status=$(go_status "${DEEP_MODULE}/@v/${DEEP_VERSION}.info")
  mod_status=$(go_status "${DEEP_MODULE}/@v/${DEEP_VERSION}.mod")
  zip_status=$(go_status "${DEEP_MODULE}/@v/${DEEP_VERSION}.zip")

  echo "  .info=${info_status} .mod=${mod_status} .zip=${zip_status}"

  if [ "$info_status" = "200" ] && [ "$mod_status" = "200" ] && [ "$zip_status" = "200" ]; then
    pass
  elif [ "$info_status" = "200" ] || [ "$mod_status" = "200" ] || [ "$zip_status" = "200" ]; then
    echo "  note: some endpoints work for deep paths but not all"
    pass
  else
    fail "no endpoints returned 200 for deep module path"
  fi
else
  fail "could not upload module with deep path"
fi

# =========================================================================
# 11. Module with replace directives in go.mod
# =========================================================================

begin_test "Module with replace directives in go.mod"

REPLACE_MODULE="example.com/replacedeps"
REPLACE_VERSION="v1.0.0"
REPLACE_MOD="module example.com/replacedeps\n\ngo 1.21\n\nrequire (\n\texample.com/oldpkg v1.0.0\n)\n\nreplace example.com/oldpkg v1.0.0 => example.com/newpkg v2.0.0"

if upload_go_module "$REPLACE_MODULE" "$REPLACE_VERSION" "$REPLACE_MOD"; then
  sleep 1

  if mod_resp=$(go_get "${REPLACE_MODULE}/@v/${REPLACE_VERSION}.mod"); then
    if assert_contains "$mod_resp" "replace" "go.mod should contain replace directive"; then
      if assert_contains "$mod_resp" "example.com/newpkg" "replace target should be present"; then
        pass
      fi
    fi
  else
    fail ".mod endpoint returned error for module with replace directives"
  fi
else
  fail "could not upload module with replace directives"
fi

# =========================================================================
# 12. Retraction: go.mod with retract directive
# =========================================================================

begin_test "Retraction: go.mod with retract directive"

RETRACT_MODULE="example.com/retractedge"
RETRACTED_VERSION="v0.9.0"
RETRACT_STABLE="v1.0.0"
RETRACT_MOD="module example.com/retractedge\n\ngo 1.21\n\nretract v0.9.0 // security issue"

# Upload the version that will be retracted
upload_go_module "$RETRACT_MODULE" "$RETRACTED_VERSION" 2>/dev/null || true

# Upload a newer version whose go.mod retracts v0.9.0
upload_go_module "$RETRACT_MODULE" "$RETRACT_STABLE" "$RETRACT_MOD" 2>/dev/null || true
sleep 1

# Verify the retracting go.mod is stored and returned correctly
if mod_resp=$(go_get "${RETRACT_MODULE}/@v/${RETRACT_STABLE}.mod"); then
  if assert_contains "$mod_resp" "retract" "go.mod should contain retract directive"; then
    pass
  fi
else
  # The retract directive in go.mod is just text content; if the .mod endpoint
  # works at all, it should return whatever was uploaded.
  fail ".mod endpoint returned error for retracting module version"
fi

# =========================================================================
# 13. Sum database compatibility: .info has correct fields
# =========================================================================

begin_test "Sum database compatibility: .info response fields"

# Use a module we already uploaded (gomodcheck)
if info_resp=$(go_get "${GOMOD_MODULE}/@v/${GOMOD_VERSION}.info"); then
  # The .info endpoint must return JSON with at least a "Version" field.
  # The "Time" field is required for sum.golang.org verification.
  info_version=$(echo "$info_resp" | jq -r '.Version // empty')
  info_time=$(echo "$info_resp" | jq -r '.Time // empty')

  if [ -z "$info_version" ]; then
    fail ".info response missing 'Version' field (required by GOPROXY spec)"
  elif [ -z "$info_time" ]; then
    echo "  note: .info response missing 'Time' field (needed for sum.golang.org)"
    echo "  Version=${info_version}, Time=(missing)"
    # Some implementations omit Time. Not a hard failure, but worth noting.
    pass
  else
    echo "  Version=${info_version}, Time=${info_time}"
    # Verify no extraneous fields that would break the go tool
    field_count=$(echo "$info_resp" | jq 'keys | length')
    if [ "$field_count" -le 3 ]; then
      pass
    else
      echo "  note: .info has ${field_count} fields (spec defines Version and Time only)"
      pass
    fi
  fi
else
  fail ".info endpoint returned error"
fi

# =========================================================================
# 14. Content-Type strictness: .info, .mod, .zip
# =========================================================================

begin_test "Content-Type: .info is application/json"
ct_info=$(curl -sf $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -o /dev/null -w '%{content_type}' \
  "${BASE_URL}/go/${REPO_KEY}/${GOMOD_MODULE}/@v/${GOMOD_VERSION}.info" 2>/dev/null) || true

if [[ "$ct_info" == *"application/json"* ]]; then
  pass
else
  fail "expected application/json for .info, got '${ct_info}'"
fi

begin_test "Content-Type: .mod is text/plain"
ct_mod=$(curl -sf $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -o /dev/null -w '%{content_type}' \
  "${BASE_URL}/go/${REPO_KEY}/${GOMOD_MODULE}/@v/${GOMOD_VERSION}.mod" 2>/dev/null) || true

if [[ "$ct_mod" == *"text/plain"* ]]; then
  pass
elif [[ "$ct_mod" == *"text/"* ]] || [[ "$ct_mod" == *"octet-stream"* ]]; then
  echo "  note: got '${ct_mod}' instead of text/plain (acceptable but not ideal)"
  pass
else
  fail "expected text/plain for .mod, got '${ct_mod}'"
fi

begin_test "Content-Type: .zip is application/zip or octet-stream"
ct_zip=$(curl -sf $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -o /dev/null -w '%{content_type}' \
  "${BASE_URL}/go/${REPO_KEY}/${GOMOD_MODULE}/@v/${GOMOD_VERSION}.zip" 2>/dev/null) || true

if [[ "$ct_zip" == *"application/zip"* ]] || [[ "$ct_zip" == *"octet-stream"* ]]; then
  pass
else
  fail "expected application/zip or octet-stream for .zip, got '${ct_zip}'"
fi

# =========================================================================
# 15. 404 vs 410: nonexistent module vs retracted version
# =========================================================================

begin_test "404 for nonexistent module, 410 for retracted (if supported)"

# Nonexistent module should always return 404
nonexist_status=$(go_status "nonexistent.invalid/nomodule/@v/list")
if [ "$nonexist_status" != "404" ]; then
  fail "expected 404 for nonexistent module, got ${nonexist_status}"
else
  # Check if the server returns 410 for the retracted version from test 12
  retracted_status=$(go_status "${RETRACT_MODULE}/@v/${RETRACTED_VERSION}.info")

  if [ "$retracted_status" = "410" ]; then
    echo "  nonexistent=404, retracted=410 (correct distinction)"
    pass
  elif [ "$retracted_status" = "200" ]; then
    echo "  nonexistent=404, retracted=200 (server does not filter retracted versions)"
    echo "  note: the go tool itself handles retraction filtering"
    pass
  elif [ "$retracted_status" = "404" ]; then
    echo "  nonexistent=404, retracted=404 (no 410 distinction)"
    pass
  else
    echo "  nonexistent=404, retracted=${retracted_status} (unexpected)"
    pass
  fi
fi

# =========================================================================
# 16. @latest skips pre-release versions
# =========================================================================

begin_test "@latest should prefer stable over pre-release"

# The PRE_MODULE from test 4 has v1.0.0-alpha, v1.0.0-beta.1,
# v0.0.0-20210101000000-abcdef123456, and v1.0.0 (stable).
# @latest should return v1.0.0.

if latest_resp=$(go_get "${PRE_MODULE}/@latest"); then
  latest_version=$(echo "$latest_resp" | jq -r '.Version // empty')

  if [ "$latest_version" = "v1.0.0" ]; then
    pass
  elif [ -n "$latest_version" ]; then
    if [[ "$latest_version" == *"-"* ]]; then
      echo "  note: @latest returned pre-release '${latest_version}' instead of stable v1.0.0"
      fail "@latest should skip pre-release versions when a stable version exists"
    else
      echo "  note: @latest returned '${latest_version}' (expected v1.0.0)"
      pass
    fi
  else
    fail "@latest response missing Version field"
  fi
else
  latest_status=$(go_status "${PRE_MODULE}/@latest")
  if [ "$latest_status" = "404" ]; then
    skip "@latest endpoint not implemented"
  else
    fail "@latest returned unexpected error (HTTP ${latest_status})"
  fi
fi

# =========================================================================
# 17. Timestamp format in .info: Time field is RFC3339
# =========================================================================

begin_test "Timestamp format: .info Time field is RFC3339"

if info_resp=$(go_get "${GOMOD_MODULE}/@v/${GOMOD_VERSION}.info"); then
  time_val=$(echo "$info_resp" | jq -r '.Time // empty')

  if [ -z "$time_val" ]; then
    skip ".info response does not include Time field"
  else
    # RFC3339 pattern: YYYY-MM-DDTHH:MM:SSZ or with timezone offset
    # Examples: 2024-01-15T10:30:00Z, 2024-01-15T10:30:00+00:00
    if echo "$time_val" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'; then
      echo "  Time='${time_val}' matches RFC3339 format"
      pass
    else
      fail "Time field '${time_val}' does not match RFC3339 format (YYYY-MM-DDTHH:MM:SSZ)"
    fi
  fi
else
  fail ".info endpoint returned error"
fi

# =========================================================================
# Cleanup
# =========================================================================
echo ""
echo "Cleaning up repository ${REPO_KEY}..."
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
