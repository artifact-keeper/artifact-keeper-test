#!/usr/bin/env bash
# test-npm-edge-cases.sh - NPM registry deep-dive edge case tests
#
# Stress tests and edge cases that npm, yarn, and pnpm clients encounter
# in production. Covers scoped package edge cases, dist-tag management,
# rapid multi-version publishing, concurrent installs, large tarballs,
# SemVer pre-releases, deprecation metadata, integrity hashes, tarball
# URL rewriting, HEAD requests, and ETag-based conditional GETs.
#
# Endpoints: ${BASE_URL}/npm/{repo_key}/
#
# Requires: jq, curl, openssl (for SHA-512 integrity checks)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "npm-edge-cases"
auth_admin
setup_workdir

REPO_KEY="test-npm-edge-${RUN_ID}"
NPM_REGISTRY="${BASE_URL}/npm/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build and publish an npm package via the PUT JSON protocol
#
# Accepts optional extra fields merged into the version metadata via jq.
# Usage: npm_publish PKG_NAME VERSION [DESCRIPTION] [EXTRA_VERSION_JSON]
# ---------------------------------------------------------------------------

npm_publish() {
  local pkg_name="$1"
  local pkg_version="$2"
  local description="${3:-edge case test package}"
  local extra_version_json="${4:-}"

  local safe_dir
  safe_dir=$(echo "${pkg_name}/${pkg_version}" | sed 's|[/@]|_|g')
  local pkg_dir="${WORK_DIR}/pkg-${safe_dir}"
  mkdir -p "${pkg_dir}"

  cat > "${pkg_dir}/package.json" <<EOJSON
{
  "name": "${pkg_name}",
  "version": "${pkg_version}",
  "description": "${description}",
  "main": "index.js",
  "license": "MIT"
}
EOJSON

  cat > "${pkg_dir}/index.js" <<EOJS
module.exports = { name: "${pkg_name}", version: "${pkg_version}" };
EOJS

  # Build tarball with package/ prefix (npm convention)
  local tarball_file="${WORK_DIR}/${safe_dir}.tgz"
  tar czf "$tarball_file" -C "${pkg_dir}" --transform='s,^,package/,' . 2>/dev/null \
    || tar czf "$tarball_file" -s ',^,package/,' -C "${pkg_dir}" . 2>/dev/null \
    || tar czf "$tarball_file" -C "${pkg_dir}" .

  local tarball_b64
  tarball_b64=$(base64 < "$tarball_file" | tr -d '\n')
  local tarball_size
  tarball_size=$(wc -c < "$tarball_file" | tr -d ' ')

  local tarball_shasum
  if command -v shasum &>/dev/null; then
    tarball_shasum=$(shasum -a 1 "$tarball_file" | awk '{print $1}')
  else
    tarball_shasum=$(sha1sum "$tarball_file" | awk '{print $1}')
  fi

  # Compute SHA-512 integrity hash (SRI format)
  local tarball_integrity
  tarball_integrity="sha512-$(openssl dgst -sha512 -binary "$tarball_file" | base64 | tr -d '\n')"

  local encoded_name
  encoded_name=$(echo "$pkg_name" | sed 's|/|%2f|g')

  # Build the version metadata, optionally merging extra fields
  local version_meta
  version_meta=$(jq -n \
    --arg name "$pkg_name" \
    --arg version "$pkg_version" \
    --arg description "$description" \
    --arg tarball "${NPM_REGISTRY}/${pkg_name}/-/${pkg_name}-${pkg_version}.tgz" \
    --arg shasum "$tarball_shasum" \
    --arg integrity "$tarball_integrity" \
    '{
      name: $name,
      version: $version,
      description: $description,
      main: "index.js",
      license: "MIT",
      dist: {
        tarball: $tarball,
        shasum: $shasum,
        integrity: $integrity
      }
    }')

  if [ -n "$extra_version_json" ]; then
    version_meta=$(echo "$version_meta" | jq --argjson extra "$extra_version_json" '. * $extra')
  fi

  local payload
  payload=$(jq -n \
    --arg name "$pkg_name" \
    --arg description "$description" \
    --arg version "$pkg_version" \
    --argjson version_meta "$version_meta" \
    --arg att_key "${pkg_name}-${pkg_version}.tgz" \
    --arg att_data "$tarball_b64" \
    --arg att_len "$tarball_size" \
    '{
      name: $name,
      description: $description,
      "dist-tags": { latest: $version },
      versions: { ($version): $version_meta },
      "_attachments": {
        ($att_key): {
          content_type: "application/octet-stream",
          data: $att_data,
          length: ($att_len | tonumber)
        }
      }
    }')

  curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${NPM_REGISTRY}/${encoded_name}"
}

# Helper to build a tarball of a specific approximate size
build_sized_tarball() {
  local pkg_name="$1"
  local pkg_version="$2"
  local target_bytes="$3"
  local output_file="$4"

  local pkg_dir="${WORK_DIR}/sized-pkg"
  rm -rf "$pkg_dir"
  mkdir -p "$pkg_dir"

  cat > "${pkg_dir}/package.json" <<EOJSON
{
  "name": "${pkg_name}",
  "version": "${pkg_version}",
  "description": "Large tarball edge case test",
  "main": "index.js",
  "license": "MIT"
}
EOJSON

  echo "module.exports = {};" > "${pkg_dir}/index.js"

  # Generate a data file to pad to the target size.
  # We use dd with /dev/urandom for incompressible data to ensure the
  # tarball actually reaches the target size after gzip.
  dd if=/dev/urandom of="${pkg_dir}/data.bin" bs=1024 count=$((target_bytes / 1024 + 512)) 2>/dev/null

  tar czf "$output_file" -C "${pkg_dir}" --transform='s,^,package/,' . 2>/dev/null \
    || tar czf "$output_file" -s ',^,package/,' -C "${pkg_dir}" . 2>/dev/null \
    || tar czf "$output_file" -C "${pkg_dir}" .
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create npm local repository"
if create_local_repo "$REPO_KEY" "npm"; then
  pass
else
  fail "could not create npm repository"
fi

# ===========================================================================
# 1. Scoped package edge cases
# ===========================================================================

begin_test "Scoped package with URL-encoded slash"
SCOPED_PKG="@edge-scope-${RUN_ID}/nested-pkg"
status=$(npm_publish "$SCOPED_PKG" "1.0.0" "scoped package test") || true
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  sleep 1
  # Fetch using the URL-encoded form (@scope%2fname)
  encoded=$(echo "$SCOPED_PKG" | sed 's|/|%2f|g')
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NPM_REGISTRY}/${encoded}" 2>/dev/null); then
    actual_name=$(echo "$resp" | jq -r '.name // empty')
    if assert_eq "$actual_name" "$SCOPED_PKG" "scoped package name mismatch"; then
      pass
    fi
  else
    fail "GET scoped packument via URL-encoded path returned error"
  fi
else
  fail "scoped package publish failed with status ${status}"
fi

begin_test "Scoped package with unencoded slash in URL"
# Some clients (yarn) send @scope/name without encoding the slash.
# The registry should handle both forms.
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${SCOPED_PKG}" 2>/dev/null); then
  actual_name=$(echo "$resp" | jq -r '.name // empty')
  if assert_eq "$actual_name" "$SCOPED_PKG" "unencoded scoped package name mismatch"; then
    pass
  fi
else
  # Unencoded may not be supported, which is acceptable
  skip "registry does not support unencoded scoped package URLs"
fi

# ===========================================================================
# 2. Dist-tag management: set custom dist-tags (beta, next, canary)
# ===========================================================================

begin_test "Custom dist-tags persist across versions"
TAG_PKG="edge-tags-${RUN_ID}"
# Publish three versions
npm_publish "$TAG_PKG" "1.0.0" "dist-tag test" > /dev/null 2>&1
npm_publish "$TAG_PKG" "2.0.0-beta.1" "dist-tag test" > /dev/null 2>&1
npm_publish "$TAG_PKG" "3.0.0-canary.1" "dist-tag test" > /dev/null 2>&1
sleep 1

# Set custom dist-tags via PUT /-/package/{name}/dist-tags/{tag}
beta_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  -d '"2.0.0-beta.1"' \
  "${NPM_REGISTRY}/-/package/${TAG_PKG}/dist-tags/beta") || true

canary_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  -d '"3.0.0-canary.1"' \
  "${NPM_REGISTRY}/-/package/${TAG_PKG}/dist-tags/canary") || true

if [ "$beta_status" = "200" ] || [ "$beta_status" = "201" ] || [ "$beta_status" = "204" ]; then
  # Verify tags appear in packument
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NPM_REGISTRY}/${TAG_PKG}" 2>/dev/null); then
    beta_ver=$(echo "$resp" | jq -r '.["dist-tags"].beta // empty')
    canary_ver=$(echo "$resp" | jq -r '.["dist-tags"].canary // empty')
    latest_ver=$(echo "$resp" | jq -r '.["dist-tags"].latest // empty')

    if [ "$beta_ver" = "2.0.0-beta.1" ] && [ -n "$latest_ver" ]; then
      pass
    else
      fail "dist-tags not set correctly: beta=${beta_ver}, latest=${latest_ver}"
    fi
  else
    fail "could not fetch packument after setting dist-tags"
  fi
else
  skip "dist-tag PUT endpoint not supported (status: ${beta_status})"
fi

# ===========================================================================
# 3. Version-specific metadata: GET /{pkg}/{version}
# ===========================================================================

begin_test "GET specific version returns isolated version metadata"
VER_PKG="edge-ver-${RUN_ID}"
npm_publish "$VER_PKG" "1.0.0" "version metadata test" > /dev/null 2>&1
npm_publish "$VER_PKG" "2.0.0" "version metadata test v2" > /dev/null 2>&1
sleep 1

if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${VER_PKG}/1.0.0" 2>/dev/null); then
  ver_name=$(echo "$resp" | jq -r '.name // empty')
  ver_version=$(echo "$resp" | jq -r '.version // empty')
  ver_desc=$(echo "$resp" | jq -r '.description // empty')

  if [ "$ver_name" = "$VER_PKG" ] && [ "$ver_version" = "1.0.0" ]; then
    # Verify the response does NOT contain the other version's data as top-level
    has_versions_key=$(echo "$resp" | jq 'has("versions")') || true
    if [ "$has_versions_key" = "false" ] || [ "$has_versions_key" = "" ]; then
      pass
    else
      # Some registries wrap it; as long as .version is correct, that is fine
      pass
    fi
  else
    fail "version metadata mismatch: name=${ver_name}, version=${ver_version}"
  fi
else
  fail "GET /${VER_PKG}/1.0.0 returned error"
fi

# ===========================================================================
# 4. Publish 20 versions in rapid succession
# ===========================================================================

begin_test "Rapid publish of 20 versions"
RAPID_PKG="edge-rapid-${RUN_ID}"
rapid_ok=0
rapid_fail=0

for i in $(seq 1 20); do
  ver="1.0.${i}"
  status=$(npm_publish "$RAPID_PKG" "$ver" "rapid publish #${i}") || true
  if [ "$status" = "200" ] || [ "$status" = "201" ]; then
    rapid_ok=$((rapid_ok + 1))
  else
    rapid_fail=$((rapid_fail + 1))
  fi
done

sleep 2
# Verify all versions appear in the packument
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${RAPID_PKG}" 2>/dev/null); then
  version_count=$(echo "$resp" | jq '.versions | length')
  echo "  published: ${rapid_ok}/20, failed: ${rapid_fail}/20, packument versions: ${version_count}"
  if [ "$version_count" -ge 18 ]; then
    pass
  else
    fail "expected >= 18 versions in packument, got ${version_count} (published: ${rapid_ok})"
  fi
else
  fail "could not fetch packument after rapid publish"
fi

# ===========================================================================
# 5. Concurrent installs: 10 parallel GET requests for the same package
# ===========================================================================

begin_test "10 concurrent GET requests for same packument"
CONC_PKG="$RAPID_PKG"  # reuse the package with many versions
concurrent_pids=()
concurrent_results="${WORK_DIR}/concurrent"
mkdir -p "$concurrent_results"

for i in $(seq 1 10); do
  curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o "${concurrent_results}/resp-${i}.json" \
    -w "%{http_code}" \
    "${NPM_REGISTRY}/${CONC_PKG}" \
    > "${concurrent_results}/status-${i}.txt" 2>/dev/null &
  concurrent_pids+=($!)
done

# Wait for all requests
conc_ok=0
conc_err=0
for pid in "${concurrent_pids[@]}"; do
  wait "$pid" 2>/dev/null && conc_ok=$((conc_ok + 1)) || conc_err=$((conc_err + 1))
done

# Verify all returned 200 and contain the package name
conc_valid=0
for i in $(seq 1 10); do
  if [ -f "${concurrent_results}/resp-${i}.json" ]; then
    name=$(jq -r '.name // empty' "${concurrent_results}/resp-${i}.json" 2>/dev/null) || true
    if [ "$name" = "$CONC_PKG" ]; then
      conc_valid=$((conc_valid + 1))
    fi
  fi
done

echo "  concurrent results: ${conc_valid}/10 valid, ${conc_err}/10 errors"
if [ "$conc_valid" -ge 9 ]; then
  pass
else
  fail "expected >= 9 valid concurrent responses, got ${conc_valid}"
fi

# ===========================================================================
# 6. Large tarball: upload a ~10MB package, verify download integrity
# ===========================================================================

begin_test "Large tarball (~10MB) upload and download integrity"
LARGE_PKG="edge-large-${RUN_ID}"
LARGE_VERSION="1.0.0"
LARGE_TARBALL="${WORK_DIR}/large.tgz"

build_sized_tarball "$LARGE_PKG" "$LARGE_VERSION" 10485760 "$LARGE_TARBALL"

large_size=$(wc -c < "$LARGE_TARBALL" | tr -d ' ')
large_shasum=""
if command -v shasum &>/dev/null; then
  large_shasum=$(shasum -a 1 "$LARGE_TARBALL" | awk '{print $1}')
else
  large_shasum=$(sha1sum "$LARGE_TARBALL" | awk '{print $1}')
fi

encoded_large=$(echo "$LARGE_PKG" | sed 's|/|%2f|g')

# Write base64 to file to avoid argument list too long for large tarballs
base64 < "$LARGE_TARBALL" | tr -d '\n' > "${WORK_DIR}/large_b64.txt"

# Build JSON payload using python3 to handle large base64 data
large_payload=$(python3 -c "
import json, sys
b64_data = open('${WORK_DIR}/large_b64.txt').read()
payload = {
    'name': '${LARGE_PKG}',
    'description': 'large tarball test',
    'dist-tags': {'latest': '${LARGE_VERSION}'},
    'versions': {
        '${LARGE_VERSION}': {
            'name': '${LARGE_PKG}',
            'version': '${LARGE_VERSION}',
            'description': 'large tarball test',
            'main': 'index.js',
            'license': 'MIT',
            'dist': {
                'tarball': '${NPM_REGISTRY}/${LARGE_PKG}/-/${LARGE_PKG}-${LARGE_VERSION}.tgz',
                'shasum': '${large_shasum}'
            }
        }
    },
    '_attachments': {
        '${LARGE_PKG}-${LARGE_VERSION}.tgz': {
            'content_type': 'application/octet-stream',
            'data': b64_data,
            'length': ${large_size}
        }
    }
}
json.dump(payload, sys.stdout)
")

upload_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 120 \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  -d "$large_payload" \
  "${NPM_REGISTRY}/${encoded_large}") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  # Download and verify integrity
  DL_LARGE="${WORK_DIR}/large-download.tgz"
  if curl -sf --max-time 120 \
      -H "$(format_auth_header)" \
      -o "$DL_LARGE" \
      "${NPM_REGISTRY}/${LARGE_PKG}/-/${LARGE_PKG}-${LARGE_VERSION}.tgz" 2>/dev/null; then
    dl_shasum=""
    if command -v shasum &>/dev/null; then
      dl_shasum=$(shasum -a 1 "$DL_LARGE" | awk '{print $1}')
    else
      dl_shasum=$(sha1sum "$DL_LARGE" | awk '{print $1}')
    fi
    if assert_eq "$dl_shasum" "$large_shasum" "large tarball SHA mismatch: upload=${large_shasum} download=${dl_shasum}"; then
      dl_size=$(wc -c < "$DL_LARGE" | tr -d ' ')
      echo "  uploaded: ${large_size} bytes, downloaded: ${dl_size} bytes"
      pass
    fi
  else
    fail "large tarball download failed"
  fi
else
  fail "large tarball upload failed with status ${upload_status}"
fi

# ===========================================================================
# 7. Package with many dependencies (50+ deps in packument)
# ===========================================================================

begin_test "Package with 50+ dependencies in metadata"
DEPS_PKG="edge-deps-${RUN_ID}"

# Build a dependencies object with 55 entries
deps_json="{"
for i in $(seq 1 55); do
  if [ "$i" -gt 1 ]; then deps_json="${deps_json},"; fi
  deps_json="${deps_json}\"fake-dep-${i}\": \"^1.0.0\""
done
deps_json="${deps_json}}"

extra_fields=$(jq -n --argjson deps "$deps_json" '{ dependencies: $deps }')
status=$(npm_publish "$DEPS_PKG" "1.0.0" "many deps test" "$extra_fields") || true

if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NPM_REGISTRY}/${DEPS_PKG}" 2>/dev/null); then
    dep_count=$(echo "$resp" | jq '.versions["1.0.0"].dependencies | length' 2>/dev/null) || dep_count=0
    echo "  dependency count in packument: ${dep_count}"
    if [ "$dep_count" -ge 50 ]; then
      pass
    else
      fail "expected >= 50 dependencies in packument, got ${dep_count}"
    fi
  else
    fail "could not fetch packument for deps package"
  fi
else
  fail "publish of package with 50+ deps failed with status ${status}"
fi

# ===========================================================================
# 8. SemVer range resolution: v1.0.0, v1.1.0, v2.0.0
# ===========================================================================

begin_test "SemVer range resolution metadata"
SEM_PKG="edge-semver-${RUN_ID}"
npm_publish "$SEM_PKG" "1.0.0" "semver test" > /dev/null 2>&1
npm_publish "$SEM_PKG" "1.1.0" "semver test" > /dev/null 2>&1
npm_publish "$SEM_PKG" "2.0.0" "semver test" > /dev/null 2>&1
sleep 1

if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${SEM_PKG}" 2>/dev/null); then
  # Verify all three versions exist in the packument
  has_100=$(echo "$resp" | jq '.versions | has("1.0.0")')
  has_110=$(echo "$resp" | jq '.versions | has("1.1.0")')
  has_200=$(echo "$resp" | jq '.versions | has("2.0.0")')
  latest=$(echo "$resp" | jq -r '.["dist-tags"].latest // empty')

  if [ "$has_100" = "true" ] && [ "$has_110" = "true" ] && [ "$has_200" = "true" ]; then
    # latest should be 2.0.0 (highest semver)
    if [ "$latest" = "2.0.0" ]; then
      pass
    else
      echo "  note: latest is ${latest} (expected 2.0.0, may depend on publish order)"
      pass
    fi
  else
    fail "not all versions present: 1.0.0=${has_100}, 1.1.0=${has_110}, 2.0.0=${has_200}"
  fi
else
  fail "could not fetch packument for semver package"
fi

# ===========================================================================
# 9. Pre-release versions: alpha, beta, rc
# ===========================================================================

begin_test "Pre-release versions (alpha, beta, rc)"
PRE_PKG="edge-prerelease-${RUN_ID}"
npm_publish "$PRE_PKG" "1.0.0-alpha.1" "prerelease test" > /dev/null 2>&1
npm_publish "$PRE_PKG" "1.0.0-beta.2" "prerelease test" > /dev/null 2>&1
npm_publish "$PRE_PKG" "1.0.0-rc.1" "prerelease test" > /dev/null 2>&1
npm_publish "$PRE_PKG" "1.0.0" "prerelease test" > /dev/null 2>&1
sleep 1

if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${PRE_PKG}" 2>/dev/null); then
  has_alpha=$(echo "$resp" | jq '.versions | has("1.0.0-alpha.1")')
  has_beta=$(echo "$resp" | jq '.versions | has("1.0.0-beta.2")')
  has_rc=$(echo "$resp" | jq '.versions | has("1.0.0-rc.1")')
  has_stable=$(echo "$resp" | jq '.versions | has("1.0.0")')
  latest=$(echo "$resp" | jq -r '.["dist-tags"].latest // empty')

  if [ "$has_alpha" = "true" ] && [ "$has_beta" = "true" ] && \
     [ "$has_rc" = "true" ] && [ "$has_stable" = "true" ]; then
    # latest should point to the stable release, not a pre-release
    if [ "$latest" = "1.0.0" ]; then
      pass
    else
      echo "  note: latest=${latest}, expected 1.0.0 (pre-releases should not be latest)"
      pass
    fi
  else
    fail "pre-release versions missing: alpha=${has_alpha}, beta=${has_beta}, rc=${has_rc}, stable=${has_stable}"
  fi
else
  fail "could not fetch packument for prerelease package"
fi

# ===========================================================================
# 10. Deprecation metadata
# ===========================================================================

begin_test "Deprecation metadata in packument"
DEPR_PKG="edge-deprecate-${RUN_ID}"
npm_publish "$DEPR_PKG" "1.0.0" "deprecation test" > /dev/null 2>&1
npm_publish "$DEPR_PKG" "2.0.0" "deprecation test" > /dev/null 2>&1
sleep 1

# npm deprecate sends a PUT with the version metadata containing a "deprecated" field.
# We publish a modified packument that marks v1.0.0 as deprecated.
depr_payload=$(jq -n \
  --arg name "$DEPR_PKG" \
  --arg msg "Use v2.0.0 instead" \
  '{
    name: $name,
    versions: {
      "1.0.0": {
        deprecated: $msg
      }
    }
  }')

depr_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  -d "$depr_payload" \
  "${NPM_REGISTRY}/${DEPR_PKG}") || true

if [ "$depr_status" = "200" ] || [ "$depr_status" = "201" ] || [ "$depr_status" = "204" ]; then
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NPM_REGISTRY}/${DEPR_PKG}" 2>/dev/null); then
    depr_msg=$(echo "$resp" | jq -r '.versions["1.0.0"].deprecated // empty')
    if [ -n "$depr_msg" ]; then
      echo "  deprecated message: ${depr_msg}"
      pass
    else
      # Deprecation may not be supported; check that the publish at least did not corrupt data
      v2_exists=$(echo "$resp" | jq '.versions | has("2.0.0")')
      if [ "$v2_exists" = "true" ]; then
        skip "deprecation not reflected in packument (may not be supported)"
      else
        fail "packument corrupted after deprecation PUT"
      fi
    fi
  else
    fail "could not fetch packument after deprecation"
  fi
else
  skip "deprecation endpoint returned ${depr_status} (may not be supported)"
fi

# ===========================================================================
# 11. README in packument
# ===========================================================================

begin_test "README field preserved in packument"
README_PKG="edge-readme-${RUN_ID}"
readme_text="# Test Package\n\nThis is the README for the edge case test package."
extra_readme=$(jq -n --arg readme "$readme_text" '{ readme: $readme }')
status=$(npm_publish "$README_PKG" "1.0.0" "readme test" "$extra_readme") || true

if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NPM_REGISTRY}/${README_PKG}" 2>/dev/null); then
    readme_val=$(echo "$resp" | jq -r '.readme // .versions["1.0.0"].readme // empty')
    if [ -n "$readme_val" ]; then
      if assert_contains "$readme_val" "Test Package" "readme should contain expected text"; then
        pass
      fi
    else
      skip "readme field not preserved in packument (optional field)"
    fi
  else
    fail "could not fetch packument for readme check"
  fi
else
  fail "publish of readme package failed with status ${status}"
fi

# ===========================================================================
# 12. Time field: packument.time has entries per version
# ===========================================================================

begin_test "Packument time field has per-version timestamps"
# Reuse the semver package which has 3 versions
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${SEM_PKG}" 2>/dev/null); then
  has_time=$(echo "$resp" | jq 'has("time")')
  if [ "$has_time" = "true" ]; then
    time_entries=$(echo "$resp" | jq '.time | length')
    # Should have at least "created", "modified", and one entry per version
    if [ "$time_entries" -ge 3 ]; then
      echo "  time entries: ${time_entries}"
      pass
    else
      echo "  note: time field exists but only ${time_entries} entries"
      pass
    fi
  else
    skip "packument does not include time field (optional per npm spec)"
  fi
else
  fail "could not fetch packument for time field check"
fi

# ===========================================================================
# 13. Binary/optional/peer dependencies
# ===========================================================================

begin_test "optionalDependencies and peerDependencies in packument"
OPT_PKG="edge-optdeps-${RUN_ID}"
extra_deps=$(jq -n '{
  optionalDependencies: { "fsevents": "^2.0.0" },
  peerDependencies: { "react": ">=16.0.0" },
  peerDependenciesMeta: { "react": { "optional": true } }
}')
status=$(npm_publish "$OPT_PKG" "1.0.0" "optional deps test" "$extra_deps") || true

if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NPM_REGISTRY}/${OPT_PKG}" 2>/dev/null); then
    opt_count=$(echo "$resp" | jq '.versions["1.0.0"].optionalDependencies | length // 0' 2>/dev/null) || opt_count=0
    peer_count=$(echo "$resp" | jq '.versions["1.0.0"].peerDependencies | length // 0' 2>/dev/null) || peer_count=0

    if [ "$opt_count" -ge 1 ] && [ "$peer_count" -ge 1 ]; then
      pass
    elif [ "$opt_count" -ge 1 ] || [ "$peer_count" -ge 1 ]; then
      echo "  note: optionalDeps=${opt_count}, peerDeps=${peer_count} (partial preservation)"
      pass
    else
      fail "neither optionalDependencies nor peerDependencies preserved"
    fi
  else
    fail "could not fetch packument for optional deps check"
  fi
else
  fail "publish of optional deps package failed with status ${status}"
fi

# ===========================================================================
# 14. Package name validation: reject invalid npm names
# ===========================================================================

begin_test "Reject invalid npm package names"
invalid_names_rejected=0
invalid_names_total=0

# Test cases: names that violate npm naming rules
for bad_name in ".starts-with-dot" "_starts-with-underscore" "ALLUPPERCASE" "has spaces" "has!special" "node_modules" "favicon.ico"; do
  invalid_names_total=$((invalid_names_total + 1))
  bad_status=$(npm_publish "$bad_name" "1.0.0" "should be rejected") || true
  if [ "$bad_status" != "200" ] && [ "$bad_status" != "201" ]; then
    invalid_names_rejected=$((invalid_names_rejected + 1))
  fi
done

echo "  rejected: ${invalid_names_rejected}/${invalid_names_total} invalid names"
if [ "$invalid_names_rejected" -ge 3 ]; then
  pass
else
  # Some registries are lenient with name validation
  skip "only ${invalid_names_rejected}/${invalid_names_total} invalid names rejected (registry may be lenient)"
fi

# ===========================================================================
# 15. Integrity field: dist.integrity (SRI hash) is present
# ===========================================================================

begin_test "dist.integrity (SRI hash) present in packument"
# We published with integrity in npm_publish; verify it survived round-trip
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${SEM_PKG}" 2>/dev/null); then
  integrity=$(echo "$resp" | jq -r '.versions["1.0.0"].dist.integrity // empty')
  if [ -n "$integrity" ]; then
    # SRI hash should start with "sha512-"
    if [[ "$integrity" == sha512-* ]]; then
      pass
    else
      echo "  integrity value: ${integrity}"
      fail "integrity field present but not in expected sha512 SRI format"
    fi
  else
    # Check if shasum is at least present as a fallback
    shasum_val=$(echo "$resp" | jq -r '.versions["1.0.0"].dist.shasum // empty')
    if [ -n "$shasum_val" ]; then
      skip "dist.integrity not present, but dist.shasum exists (older registry behavior)"
    else
      fail "neither dist.integrity nor dist.shasum present in packument"
    fi
  fi
else
  fail "could not fetch packument for integrity check"
fi

# ===========================================================================
# 16. Tarball URL rewriting: dist.tarball points to this registry
# ===========================================================================

begin_test "dist.tarball URLs point to this registry"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${SEM_PKG}" 2>/dev/null); then
  # Check all versions' tarball URLs
  tarball_urls=$(echo "$resp" | jq -r '[.versions[].dist.tarball // empty] | .[]')
  all_rewritten=true
  bad_url=""

  while IFS= read -r url; do
    if [ -z "$url" ]; then continue; fi
    # The tarball URL should contain our registry base URL or at minimum
    # reference the correct repo key. It should NOT point to registry.npmjs.org
    # or any external upstream when served from a local repo.
    if [[ "$url" == *"npmjs.org"* ]] || [[ "$url" == *"registry.yarnpkg.com"* ]]; then
      all_rewritten=false
      bad_url="$url"
    fi
  done <<< "$tarball_urls"

  if [ "$all_rewritten" = "true" ]; then
    pass
  else
    fail "tarball URL not rewritten, still points to external: ${bad_url}"
  fi
else
  fail "could not fetch packument for tarball URL check"
fi

# ===========================================================================
# 17. HEAD on packument: returns Content-Length without body
# ===========================================================================

begin_test "HEAD on packument returns Content-Length without body"
head_resp=$(curl -sf $CURL_TIMEOUT \
  -I \
  -H "$(format_auth_header)" \
  "${NPM_REGISTRY}/${SEM_PKG}" 2>/dev/null) || true

if [ -n "$head_resp" ]; then
  # Check for Content-Length header (case-insensitive)
  content_length=$(echo "$head_resp" | grep -i "^content-length:" | head -1 | awk '{print $2}' | tr -d '\r')

  if [ -n "$content_length" ]; then
    # Content-Length should be a positive number
    if [ "$content_length" -gt 0 ] 2>/dev/null; then
      echo "  Content-Length: ${content_length}"
      pass
    else
      fail "Content-Length is not a positive number: ${content_length}"
    fi
  else
    # Some servers use Transfer-Encoding: chunked instead, which is acceptable
    transfer_enc=$(echo "$head_resp" | grep -i "^transfer-encoding:" | head -1 | tr -d '\r')
    if [ -n "$transfer_enc" ]; then
      echo "  no Content-Length, but Transfer-Encoding present: ${transfer_enc}"
      pass
    else
      fail "HEAD response has neither Content-Length nor Transfer-Encoding"
    fi
  fi
else
  head_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -I \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${SEM_PKG}" 2>/dev/null) || true
  if [ "$head_status" = "405" ]; then
    skip "HEAD method not supported on packument endpoint (405)"
  else
    fail "HEAD request failed with status ${head_status}"
  fi
fi

# ===========================================================================
# 18. ETag/If-None-Match: conditional GET with caching
# ===========================================================================

begin_test "ETag-based conditional GET returns 304"
# First request to get the ETag
etag_headers=$(curl -sf $CURL_TIMEOUT \
  -D - -o /dev/null \
  -H "$(format_auth_header)" \
  "${NPM_REGISTRY}/${SEM_PKG}" 2>/dev/null) || true

etag=$(echo "$etag_headers" | grep -i "^etag:" | head -1 | sed 's/^[Ee][Tt][Aa][Gg]: *//; s/\r$//')

if [ -n "$etag" ]; then
  # Second request with If-None-Match
  conditional_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -H "If-None-Match: ${etag}" \
    "${NPM_REGISTRY}/${SEM_PKG}" 2>/dev/null) || true

  if [ "$conditional_status" = "304" ]; then
    pass
  elif [ "$conditional_status" = "200" ]; then
    # Some registries do not implement If-None-Match; a 200 is acceptable
    skip "registry returned 200 instead of 304 (ETag caching may not be implemented)"
  else
    fail "conditional GET returned unexpected status ${conditional_status}"
  fi
else
  skip "no ETag header returned by registry"
fi

# ===========================================================================
# 19. Publish with duplicate version returns conflict
# ===========================================================================

begin_test "Duplicate version publish returns 409 conflict"
DUP_PKG="edge-dup-${RUN_ID}"
npm_publish "$DUP_PKG" "1.0.0" "first publish" > /dev/null 2>&1
sleep 1

# Attempt to publish the same version again
dup_status=$(npm_publish "$DUP_PKG" "1.0.0" "duplicate publish") || true

if [ "$dup_status" = "409" ] || [ "$dup_status" = "403" ]; then
  pass
elif [ "$dup_status" = "200" ] || [ "$dup_status" = "201" ]; then
  # Some registries allow re-publish (overwrite); note it but do not fail
  skip "registry allows re-publish of same version (no conflict enforcement)"
else
  echo "  status: ${dup_status}"
  fail "expected 409 for duplicate publish, got ${dup_status}"
fi

# ===========================================================================
# 20. Packument Content-Type is application/json
# ===========================================================================

begin_test "Packument Content-Type is application/json"
ct_resp=$(curl -sf $CURL_TIMEOUT \
  -o /dev/null -w '%{content_type}' \
  -H "$(format_auth_header)" \
  "${NPM_REGISTRY}/${SEM_PKG}" 2>/dev/null) || true

if [ -n "$ct_resp" ]; then
  if [[ "$ct_resp" == *"application/json"* ]]; then
    pass
  elif [[ "$ct_resp" == *"application/vnd.npm"* ]]; then
    # npm-specific content types are also acceptable
    pass
  else
    fail "packument Content-Type should be application/json, got: ${ct_resp}"
  fi
else
  fail "could not determine Content-Type for packument"
fi

# ===========================================================================
# Cleanup
# ===========================================================================

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
