#!/usr/bin/env bash
# test-cocoapods.sh - CocoaPods spec registry E2E test (curl-based)
#
# Uploads a podspec to the CocoaPods registry endpoint, verifies the spec
# listing, and downloads the podspec back.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cocoapods"
auth_admin
setup_workdir

REPO_KEY="test-cocoapods-${RUN_ID}"
POD_NAME="E2EHelloPod"
POD_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create CocoaPods repository"
if create_local_repo "$REPO_KEY" "cocoapods"; then
  pass
else
  fail "could not create cocoapods repository"
fi

# -----------------------------------------------------------------------
# Generate and upload a podspec (as tar.gz archive containing .podspec.json)
# -----------------------------------------------------------------------
begin_test "Upload podspec"
cat > "$WORK_DIR/${POD_NAME}.podspec.json" <<EOF
{
  "name": "${POD_NAME}",
  "version": "${POD_VERSION}",
  "summary": "E2E test pod for CocoaPods registry",
  "description": "A minimal pod used for end-to-end testing of the artifact registry CocoaPods support.",
  "homepage": "https://example.com/${POD_NAME}",
  "license": {
    "type": "MIT",
    "file": "LICENSE"
  },
  "authors": {
    "E2E Test": "test@example.com"
  },
  "source": {
    "git": "https://example.com/${POD_NAME}.git",
    "tag": "${POD_VERSION}"
  },
  "platforms": {
    "ios": "15.0"
  },
  "source_files": "Sources/**/*.swift",
  "swift_versions": ["5.9"]
}
EOF

# The backend push_pod handler expects a tar.gz archive containing a .podspec.json
POD_TARBALL="$WORK_DIR/${POD_NAME}-${POD_VERSION}.tar.gz"
tar czf "$POD_TARBALL" -C "$WORK_DIR" "${POD_NAME}.podspec.json"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${POD_TARBALL}" \
  "${BASE_URL}/cocoapods/${REPO_KEY}/pods") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "podspec upload returned ${upload_status}, expected 200 or 201"
fi

# -----------------------------------------------------------------------
# Verify spec listing (GET /:repo_key/all_specs)
# -----------------------------------------------------------------------
begin_test "Verify spec listing"
list_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/cocoapods/${REPO_KEY}/all_specs" 2>/dev/null) || true

if [ -n "$list_resp" ] && echo "$list_resp" | grep -q "$POD_NAME"; then
  pass
else
  fail "pod ${POD_NAME} not found in spec listing"
fi

# -----------------------------------------------------------------------
# Verify version info (GET /:repo_key/Specs/{name}/{version}/{name}.podspec.json)
# -----------------------------------------------------------------------
begin_test "Verify version info"
ver_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/cocoapods/${REPO_KEY}/Specs/${POD_NAME}/${POD_VERSION}/${POD_NAME}.podspec.json" 2>/dev/null) || true

if [ -n "$ver_resp" ] && echo "$ver_resp" | grep -q "$POD_VERSION"; then
  pass
else
  skip "version-specific endpoint not available"
fi

# -----------------------------------------------------------------------
# Download podspec (GET /:repo_key/Specs/{name}/{version}/{name}.podspec.json)
# -----------------------------------------------------------------------
begin_test "Download podspec"
dl_file="$WORK_DIR/downloaded.podspec.json"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/cocoapods/${REPO_KEY}/Specs/${POD_NAME}/${POD_VERSION}/${POD_NAME}.podspec.json" 2>/dev/null) || true

if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
  # Verify the content looks like our podspec
  if grep -q "$POD_NAME" "$dl_file" 2>/dev/null; then
    pass
  else
    fail "downloaded podspec does not contain expected pod name"
  fi
else
  fail "podspec download returned ${dl_status}, expected 200"
fi

end_suite
