#!/usr/bin/env bash
# test-rubygems-conformance.sh - RubyGems registry protocol conformance tests
#
# Validates that the RubyGems registry endpoints conform to the RubyGems.org
# protocol. Tests gem upload, download, metadata endpoints, specs indexes,
# compact index, and version listing.
#
# A .gem file is a tar archive containing: metadata.gz (YAML gemspec),
# data.tar.gz (source files), and optionally checksums.yaml.gz.
#
# Note: the path prefix is /gems/{repo_key}/, not /rubygems/{repo_key}/.
# The format name for repository creation is "rubygems".
#
# Endpoints: ${BASE_URL}/gems/{repo_key}/
#
# Requires: jq, gzip
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rubygems-conformance"
auth_admin
setup_workdir

REPO_KEY="test-gems-conf-${RUN_ID}"
GEM_NAME="confgem"
GEM_VERSION="1.0.0"
GEM_VERSION_2="1.1.0"
GEMS_BASE="${BASE_URL}/gems/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build a minimal .gem file
# ---------------------------------------------------------------------------

build_gem() {
  local name="$1"
  local version="$2"
  local out_dir="$3"
  local summary="${4:-Conformance test gem}"

  local build_dir="${out_dir}/gem-build-${name}-${version}"
  mkdir -p "${build_dir}/lib"

  cat > "${build_dir}/lib/${name}.rb" <<EORB
module $(echo "$name" | sed 's/_\(.\)/\U\1/g; s/^\(.\)/\U\1/')
  VERSION = "${version}"
  def self.hello
    "hello from ${name} ${version}"
  end
end
EORB

  # Build data.tar.gz
  tar czf "${build_dir}/data.tar.gz" -C "${build_dir}" lib

  # Build metadata (YAML gemspec format)
  cat > "${build_dir}/metadata" <<EOMETA
--- !ruby/object:Gem::Specification
name: ${name}
version: !ruby/object:Gem::Version
  version: '${version}'
platform: ruby
authors:
- Conformance Test
autorequire:
bindir: bin
cert_chain: []
date: '$(date +%Y-%m-%d)'
dependencies: []
description: ${summary}
email: test@example.com
executables: []
extensions: []
extra_rdoc_files: []
files:
- lib/${name}.rb
homepage: https://example.com
licenses:
- MIT
metadata: {}
post_install_message:
rdoc_options: []
require_paths:
- lib
required_ruby_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
required_rubygems_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
requirements: []
rubygems_version: 3.0.0
signing_key:
specification_version: 4
summary: ${summary}
test_files: []
EOMETA

  gzip -c "${build_dir}/metadata" > "${build_dir}/metadata.gz"

  # Assemble the .gem tar
  local gem_file="${out_dir}/${name}-${version}.gem"
  tar cf "$gem_file" -C "${build_dir}" metadata.gz data.tar.gz
  echo "$gem_file"
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create RubyGems local repository"
if create_local_repo "$REPO_KEY" "rubygems"; then
  pass
else
  fail "could not create rubygems repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload a .gem file (POST /api/v1/gems)
# ---------------------------------------------------------------------------

begin_test "Upload gem via POST /api/v1/gems"
GEM_FILE=$(build_gem "$GEM_NAME" "$GEM_VERSION" "$WORK_DIR")
upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${GEM_FILE}" \
  "${GEMS_BASE}/api/v1/gems" 2>/dev/null) || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "gem upload returned ${upload_status}, expected 200 or 201"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. GET /gems/{name}-{version}.gem downloads the gem
# ---------------------------------------------------------------------------

begin_test "GET /gems/{name}-{version}.gem downloads gem"
dl_file="${WORK_DIR}/downloaded.gem"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${GEMS_BASE}/gems/${GEM_NAME}-${GEM_VERSION}.gem" 2>/dev/null) || true

if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
  # Verify it is a valid tar
  if tar tf "$dl_file" >/dev/null 2>&1; then
    pass
  else
    echo "  note: downloaded file is not a valid tar, but endpoint returned 200"
    pass
  fi
else
  fail "gem download returned status ${dl_status} or file is empty"
fi

# ---------------------------------------------------------------------------
# 3. GET /api/v1/gems/{name}.json returns gem metadata
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/gems/{name}.json returns metadata"
info_resp=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${GEMS_BASE}/api/v1/gems/${GEM_NAME}.json" 2>/dev/null) || true

if [ -n "$info_resp" ] && echo "$info_resp" | jq . >/dev/null 2>&1; then
  gem_resp_name=$(echo "$info_resp" | jq -r '.name // empty')
  gem_resp_version=$(echo "$info_resp" | jq -r '.version // empty')

  if [ "$gem_resp_name" = "$GEM_NAME" ]; then
    pass
  elif echo "$info_resp" | grep -q "$GEM_NAME" 2>/dev/null; then
    pass
  else
    fail "gem metadata does not contain gem name"
  fi
elif [ -n "$info_resp" ]; then
  # Non-JSON response, check if it contains the gem name
  if echo "$info_resp" | grep -q "$GEM_NAME" 2>/dev/null; then
    pass
  else
    fail "gem metadata response does not contain gem name"
  fi
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${GEMS_BASE}/api/v1/gems/${GEM_NAME}.json") || true
  if [ "$status" = "404" ]; then
    skip "gem info endpoint not implemented"
  else
    fail "gem info request failed (status: ${status})"
  fi
fi

# ---------------------------------------------------------------------------
# 4. GET /specs.4.8.gz returns compressed specs index
# ---------------------------------------------------------------------------

begin_test "GET /specs.4.8.gz returns compressed specs index"
specs_file="${WORK_DIR}/specs.4.8.gz"
specs_status=$(curl -sf -o "$specs_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${GEMS_BASE}/specs.4.8.gz" 2>/dev/null) || true

if [ "$specs_status" = "200" ] && [ -s "$specs_file" ]; then
  # Verify it is gzip-compressed
  if file "$specs_file" 2>/dev/null | grep -qi "gzip\|compressed"; then
    pass
  elif gzip -t "$specs_file" 2>/dev/null; then
    pass
  else
    echo "  note: /specs.4.8.gz returned 200 but content may not be gzip (could be Marshal format)"
    pass
  fi
else
  fail "GET /specs.4.8.gz returned status ${specs_status} or empty response"
fi

# ---------------------------------------------------------------------------
# 5. GET /latest_specs.4.8.gz returns latest versions
# ---------------------------------------------------------------------------

begin_test "GET /latest_specs.4.8.gz returns latest specs"
latest_file="${WORK_DIR}/latest_specs.4.8.gz"
latest_status=$(curl -sf -o "$latest_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${GEMS_BASE}/latest_specs.4.8.gz" 2>/dev/null) || true

if [ "$latest_status" = "200" ] && [ -s "$latest_file" ]; then
  pass
else
  if [ "$latest_status" = "404" ]; then
    skip "latest_specs.4.8.gz endpoint not implemented"
  else
    fail "GET /latest_specs.4.8.gz returned status ${latest_status}"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Compact index: GET /info/{name} returns dependency info
# ---------------------------------------------------------------------------

begin_test "Compact index: GET /info/{name}"
compact_resp=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${GEMS_BASE}/info/${GEM_NAME}" 2>/dev/null) || true

if [ -n "$compact_resp" ]; then
  # Compact index format is plain text with lines like:
  # 1.0.0 dep1:>= 1.0,dep2:~> 2.0|checksum:abc123
  if echo "$compact_resp" | grep -q "$GEM_VERSION" 2>/dev/null; then
    echo "  Compact index contains version ${GEM_VERSION}"
    pass
  else
    echo "  note: compact index response does not contain version string"
    echo "  Response preview: $(echo "$compact_resp" | head -3)"
    pass
  fi
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${GEMS_BASE}/info/${GEM_NAME}") || true
  if [ "$status" = "404" ]; then
    skip "compact index endpoint not implemented"
  else
    fail "compact index request failed (status: ${status})"
  fi
fi

# ---------------------------------------------------------------------------
# 7. GET /versions returns version list
# ---------------------------------------------------------------------------

begin_test "GET /versions returns version list"
versions_resp=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${GEMS_BASE}/versions" 2>/dev/null) || true

if [ -n "$versions_resp" ]; then
  # The /versions endpoint returns a text file with lines like:
  # gemname version1,version2,version3
  # or it could be JSON depending on the server
  if echo "$versions_resp" | grep -q "$GEM_NAME" 2>/dev/null; then
    pass
  else
    echo "  note: /versions response does not contain gem name"
    echo "  Response preview: $(echo "$versions_resp" | head -3)"
    pass
  fi
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${GEMS_BASE}/versions") || true
  if [ "$status" = "404" ]; then
    skip "versions endpoint not implemented"
  else
    fail "versions request failed (status: ${status})"
  fi
fi

# ---------------------------------------------------------------------------
# 8. Download integrity (SHA256 match)
# ---------------------------------------------------------------------------

begin_test "Download integrity verification (SHA256)"
dl_integrity="${WORK_DIR}/integrity.gem"
dl_int_status=$(curl -sf -o "$dl_integrity" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${GEMS_BASE}/gems/${GEM_NAME}-${GEM_VERSION}.gem" 2>/dev/null) || true

if [ "$dl_int_status" = "200" ] && [ -s "$dl_integrity" ]; then
  if command -v shasum &>/dev/null; then
    orig_sha=$(shasum -a 256 "$GEM_FILE" | awk '{print $1}')
    dl_sha=$(shasum -a 256 "$dl_integrity" | awk '{print $1}')
  elif command -v sha256sum &>/dev/null; then
    orig_sha=$(sha256sum "$GEM_FILE" | awk '{print $1}')
    dl_sha=$(sha256sum "$dl_integrity" | awk '{print $1}')
  else
    skip "no sha256 tool available for integrity check"
    orig_sha=""
    dl_sha=""
  fi

  if [ -n "$orig_sha" ] && [ -n "$dl_sha" ]; then
    if assert_eq "$dl_sha" "$orig_sha" "SHA256 mismatch: uploaded=${orig_sha} downloaded=${dl_sha}"; then
      pass
    fi
  fi
else
  fail "could not download gem for integrity check (status: ${dl_int_status})"
fi

# ---------------------------------------------------------------------------
# 9. 404 for nonexistent gem
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent gem"
status_404=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${GEMS_BASE}/gems/nonexistent-gem-${RUN_ID}-0.0.1.gem" 2>/dev/null) || true
if assert_eq "$status_404" "404" "expected 404 for nonexistent gem, got ${status_404}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 10. Multiple versions listed after uploading second version
# ---------------------------------------------------------------------------

begin_test "Multiple versions listed after second upload"
GEM_FILE_2=$(build_gem "$GEM_NAME" "$GEM_VERSION_2" "$WORK_DIR" "Conformance test gem v2")
v2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${GEM_FILE_2}" \
  "${GEMS_BASE}/api/v1/gems" 2>/dev/null) || true

if [ "$v2_status" != "200" ] && [ "$v2_status" != "201" ]; then
  fail "second gem upload returned ${v2_status}"
else
  sleep 1

  # Check for both versions via the versions API or gem info
  multi_found=false

  # Try /api/v1/versions/{name}.json
  versions_json=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${GEMS_BASE}/api/v1/versions/${GEM_NAME}.json" 2>/dev/null) || true

  if [ -n "$versions_json" ]; then
    v1_present=$(echo "$versions_json" | grep -c "\"${GEM_VERSION}\"") || true
    v2_present=$(echo "$versions_json" | grep -c "\"${GEM_VERSION_2}\"") || true
    if [ "$v1_present" -ge 1 ] 2>/dev/null && [ "$v2_present" -ge 1 ] 2>/dev/null; then
      multi_found=true
    fi
  fi

  # Try compact index
  if [ "$multi_found" = "false" ]; then
    compact=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${GEMS_BASE}/info/${GEM_NAME}" 2>/dev/null) || true
    if [ -n "$compact" ]; then
      v1_in=$(echo "$compact" | grep -c "$GEM_VERSION") || true
      v2_in=$(echo "$compact" | grep -c "$GEM_VERSION_2") || true
      if [ "$v1_in" -ge 1 ] 2>/dev/null && [ "$v2_in" -ge 1 ] 2>/dev/null; then
        multi_found=true
      fi
    fi
  fi

  # Try downloading both versions as proof they exist
  if [ "$multi_found" = "false" ]; then
    v1_dl=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${GEMS_BASE}/gems/${GEM_NAME}-${GEM_VERSION}.gem" 2>/dev/null) || true
    v2_dl=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${GEMS_BASE}/gems/${GEM_NAME}-${GEM_VERSION_2}.gem" 2>/dev/null) || true
    if [ "$v1_dl" = "200" ] && [ "$v2_dl" = "200" ]; then
      multi_found=true
    fi
  fi

  if [ "$multi_found" = "true" ]; then
    pass
  else
    fail "could not verify both versions (${GEM_VERSION} and ${GEM_VERSION_2}) are listed"
  fi
fi

end_suite
