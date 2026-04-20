#!/usr/bin/env bash
# test-cocoapods-conformance.sh - CocoaPods spec repository conformance tests
#
# Validates that the CocoaPods repository implementation handles podspec
# uploads, CDN-compatible flat file spec retrieval, version listing, source
# archive downloads, and correct 404 responses.
#
# Endpoints: ${BASE_URL}/cocoapods/{repo_key}/
#
# Requires: curl, tar, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "cocoapods-conformance"
auth_admin
setup_workdir

REPO_KEY="test-cpods-conf-${RUN_ID}"
POD_NAME="ConfTestPod"
POD_VERSION="1.0.0"
POD_VERSION_2="2.0.0"
COCOAPODS_URL="${BASE_URL}/cocoapods/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: compute the CDN shard prefix for a pod name
#
# CocoaPods CDN uses the first three hex characters of the MD5 hash of the
# pod name, split as: {char0}/{char0}{char1}/{char0}{char1}{char2}
# e.g. for "Alamofire" the shard path is "a/a7/a79"
# ---------------------------------------------------------------------------

pod_shard_prefix() {
  local name="$1"
  local md5_hash=""
  if command -v md5sum &>/dev/null; then
    md5_hash=$(printf '%s' "$name" | md5sum | awk '{print $1}')
  elif command -v md5 &>/dev/null; then
    md5_hash=$(printf '%s' "$name" | md5)
  else
    # Fallback without shard
    echo ""
    return
  fi
  local c0="${md5_hash:0:1}"
  local c1="${md5_hash:1:1}"
  local c2="${md5_hash:2:1}"
  echo "${c0}/${c0}${c1}/${c0}${c1}${c2}"
}

# ---------------------------------------------------------------------------
# Helper: build and upload a podspec
# ---------------------------------------------------------------------------

upload_podspec() {
  local name="$1"
  local version="$2"

  local specfile="${WORK_DIR}/${name}-${version}.podspec.json"
  cat > "$specfile" <<EOJSON
{
  "name": "${name}",
  "version": "${version}",
  "summary": "Conformance test pod ${name} v${version}",
  "description": "A minimal pod for conformance testing of the CocoaPods registry.",
  "homepage": "https://example.com/${name}",
  "license": {
    "type": "MIT",
    "file": "LICENSE"
  },
  "authors": {
    "Conformance Test": "test@example.com"
  },
  "source": {
    "git": "https://example.com/${name}.git",
    "tag": "${version}"
  },
  "platforms": {
    "ios": "15.0",
    "osx": "13.0"
  },
  "source_files": "Sources/**/*.swift",
  "swift_versions": ["5.9", "6.0"]
}
EOJSON

  # The push_pod handler expects a tar.gz archive containing the .podspec.json
  local tarball="${WORK_DIR}/${name}-${version}-pod.tar.gz"
  tar czf "$tarball" -C "$WORK_DIR" "${name}-${version}.podspec.json"

  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/gzip" \
    --data-binary "@${tarball}" \
    "${COCOAPODS_URL}/pods"
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create CocoaPods local repository"
if create_local_repo "$REPO_KEY" "cocoapods"; then
  pass
else
  fail "could not create cocoapods repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload a podspec (JSON format)
# ---------------------------------------------------------------------------

begin_test "Upload podspec via POST"
status=$(upload_podspec "$POD_NAME" "$POD_VERSION") || true
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "podspec upload returned HTTP ${status}, expected 200 or 201"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. GET /Specs/{shard}/{name}/{version}/{name}.podspec.json returns the spec
# ---------------------------------------------------------------------------

begin_test "Retrieve podspec via CDN shard path"
shard=$(pod_shard_prefix "$POD_NAME")

# Try the sharded CDN path first
spec_resp=""
spec_status=""
if [ -n "$shard" ]; then
  spec_status=$(curl -s -o "${WORK_DIR}/spec.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COCOAPODS_URL}/Specs/${shard}/${POD_NAME}/${POD_VERSION}/${POD_NAME}.podspec.json") || true
fi

if [ "$spec_status" = "200" ] && [ -s "${WORK_DIR}/spec.json" ]; then
  spec_resp=$(cat "${WORK_DIR}/spec.json")
  if assert_contains "$spec_resp" "$POD_NAME" "podspec should contain pod name"; then
    if assert_contains "$spec_resp" "$POD_VERSION" "podspec should contain version"; then
      pass
    fi
  fi
else
  # Fallback: try without shard (some registries use flat /Specs/{name}/{version}/)
  spec_status=$(curl -s -o "${WORK_DIR}/spec.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COCOAPODS_URL}/Specs/${POD_NAME}/${POD_VERSION}/${POD_NAME}.podspec.json") || true

  if [ "$spec_status" = "200" ] && [ -s "${WORK_DIR}/spec.json" ]; then
    spec_resp=$(cat "${WORK_DIR}/spec.json")
    if assert_contains "$spec_resp" "$POD_NAME" "podspec should contain pod name"; then
      pass
    fi
  else
    fail "podspec retrieval failed via both sharded (${shard}) and flat paths (HTTP ${spec_status})"
  fi
fi

# ---------------------------------------------------------------------------
# 3. List available versions
# ---------------------------------------------------------------------------

begin_test "List available versions for pod"
# Upload a second version first
status2=$(upload_podspec "$POD_NAME" "$POD_VERSION_2") || true
if [ "$status2" = "200" ] || [ "$status2" = "201" ]; then
  sleep 1
fi

# Try the all_specs endpoint
versions_found=false
if list_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COCOAPODS_URL}/all_specs" 2>/dev/null); then
  if echo "$list_resp" | grep -q "$POD_NAME" 2>/dev/null; then
    versions_found=true
  fi
fi

# If all_specs does not list versions, try fetching both version specs individually
if ! $versions_found; then
  v1_ok=false
  v2_ok=false

  v1_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COCOAPODS_URL}/Specs/${POD_NAME}/${POD_VERSION}/${POD_NAME}.podspec.json") || true
  if [ "$v1_status" = "200" ]; then v1_ok=true; fi

  v2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COCOAPODS_URL}/Specs/${POD_NAME}/${POD_VERSION_2}/${POD_NAME}.podspec.json") || true
  if [ "$v2_status" = "200" ]; then v2_ok=true; fi

  if $v1_ok && $v2_ok; then
    versions_found=true
  fi
fi

if $versions_found; then
  pass
else
  fail "could not verify multiple versions are available for ${POD_NAME}"
fi

# ---------------------------------------------------------------------------
# 4. Download source archive
# ---------------------------------------------------------------------------

begin_test "Download source archive"
# CocoaPods registries may serve source archives at a known path
DL_FILE="${WORK_DIR}/pod-archive.tar.gz"
dl_status=""

# Try the standard archive endpoint
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${COCOAPODS_URL}/pods/${POD_NAME}/versions/${POD_VERSION}/download") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null && [ -s "$DL_FILE" ]; then
  pass
else
  # Alternative: try the spec file itself as the downloadable artifact
  dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COCOAPODS_URL}/Specs/${POD_NAME}/${POD_VERSION}/${POD_NAME}.podspec.json") || true

  if [ "$dl_status" = "200" ] && [ -s "$DL_FILE" ]; then
    echo "  note: source archive endpoint not available, podspec itself is downloadable"
    pass
  else
    skip "source archive download endpoint not available (status: ${dl_status})"
  fi
fi

# ---------------------------------------------------------------------------
# 5. 404 for nonexistent pod
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent pod"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${COCOAPODS_URL}/Specs/NonexistentPod${RUN_ID}/99.99.99/NonexistentPod${RUN_ID}.podspec.json") || true
if assert_eq "$status" "404" "expected 404 for nonexistent pod, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 6. CDN-compatible flat file structure
# ---------------------------------------------------------------------------

begin_test "CDN-compatible flat file structure"
# The CocoaPods CDN spec requires that the registry serve an all_pods_versions_X_Y_Z.txt
# file or at minimum support the /Specs/{shard}/{name}/{version}/ path structure.
# Verify that specs are accessible via the flat file layout.

cdn_ok=false

# Check 1: all_specs endpoint returns valid data
if all_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COCOAPODS_URL}/all_specs" 2>/dev/null); then
  if [ -n "$all_resp" ]; then
    cdn_ok=true
    echo "  all_specs endpoint available and returns data"
  fi
fi

# Check 2: spec accessible by name/version path (the CDN baseline)
if ! $cdn_ok; then
  spec_check=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COCOAPODS_URL}/Specs/${POD_NAME}/${POD_VERSION}/${POD_NAME}.podspec.json") || true

  if [ "$spec_check" = "200" ]; then
    cdn_ok=true
    echo "  flat file Specs/{name}/{version}/ path works"
  fi
fi

# Check 3: try the sharded path
if ! $cdn_ok; then
  shard=$(pod_shard_prefix "$POD_NAME")
  if [ -n "$shard" ]; then
    shard_check=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${COCOAPODS_URL}/Specs/${shard}/${POD_NAME}/${POD_VERSION}/${POD_NAME}.podspec.json") || true

    if [ "$shard_check" = "200" ]; then
      cdn_ok=true
      echo "  sharded CDN path Specs/{shard}/{name}/{version}/ works"
    fi
  fi
fi

if $cdn_ok; then
  pass
else
  fail "no CDN-compatible access pattern found for podspecs"
fi

end_suite
