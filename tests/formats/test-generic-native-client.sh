#!/usr/bin/env bash
# test-generic-native-client.sh - Generic format native HTTP smoke test
#
# The generic format has no native client binary, so "native client" here
# means hitting the format-native endpoint (`/generic/{repo_key}/{path}`)
# with curl and Basic auth, exactly as a third-party CI script would.
#
# Why this is separate from test-generic.sh and test-generic-conformance.sh:
# both of those only exercise the management API
# (`/api/v1/repositories/{key}/artifacts/...`). The management API is
# shared infrastructure; passing tests there prove the management surface
# works but say nothing about the format handler that real consumers hit.
#
# Real consumers hit `/generic/{key}/{path}` with Basic auth, e.g.:
#   curl -u user:pass -T file.bin https://ak/generic/myrepo/path/to/file.bin
#   curl -u user:pass -O https://ak/generic/myrepo/path/to/file.bin
#
# Requires: curl, shasum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "generic-native-client"
auth_admin
setup_workdir

REPO_KEY="test-generic-nc-${RUN_ID}"
GENERIC_URL="${BASE_URL}/generic/${REPO_KEY}"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repository"
fi

# -------------------------------------------------------------------------
# PUT a binary blob via the format-native endpoint
# -------------------------------------------------------------------------

begin_test "PUT binary blob to /generic/{key}/{path}"
dd if=/dev/urandom of="${WORK_DIR}/blob.bin" bs=1024 count=8 2>/dev/null
ORIG_SHA256=$(shasum -a 256 "${WORK_DIR}/blob.bin" | awk '{print $1}')

put_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/blob.bin" \
  "${GENERIC_URL}/releases/v1/blob.bin") || put_status="000"

if [ "$put_status" -ge 200 ] 2>/dev/null && [ "$put_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "PUT returned HTTP ${put_status}, expected 2xx"
fi

# -------------------------------------------------------------------------
# GET the same path back and verify SHA256
# -------------------------------------------------------------------------

begin_test "GET binary blob and verify SHA256 round-trip"
if curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o "${WORK_DIR}/downloaded.bin" \
    "${GENERIC_URL}/releases/v1/blob.bin"; then
  DL_SHA256=$(shasum -a 256 "${WORK_DIR}/downloaded.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$ORIG_SHA256" "SHA256 mismatch after generic format-native round-trip"; then
    pass
  fi
else
  fail "GET via /generic/{key}/{path} returned non-2xx"
fi

# -------------------------------------------------------------------------
# Deeply nested path
#
# Real consumers commonly publish under multi-segment paths like
# tools/${VERSION}/linux/amd64/binary. Verify the path segments are
# preserved through the format-native handler.
# -------------------------------------------------------------------------

begin_test "PUT and GET deeply nested path"
echo "nested path content for ${RUN_ID}" > "${WORK_DIR}/nested.txt"
NESTED_SHA=$(shasum -a 256 "${WORK_DIR}/nested.txt" | awk '{print $1}')

put_nested=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: text/plain" \
  --data-binary "@${WORK_DIR}/nested.txt" \
  "${GENERIC_URL}/tools/2026/04/25/linux/amd64/cli.txt") || put_nested="000"

if [ "$put_nested" -ge 200 ] 2>/dev/null && [ "$put_nested" -lt 300 ] 2>/dev/null; then
  if curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      -o "${WORK_DIR}/nested-dl.txt" \
      "${GENERIC_URL}/tools/2026/04/25/linux/amd64/cli.txt"; then
    DL_NESTED_SHA=$(shasum -a 256 "${WORK_DIR}/nested-dl.txt" | awk '{print $1}')
    if assert_eq "$DL_NESTED_SHA" "$NESTED_SHA" "SHA256 mismatch on nested path"; then
      pass
    fi
  else
    fail "GET on deeply nested path returned non-2xx"
  fi
else
  fail "PUT on deeply nested path returned HTTP ${put_nested}"
fi

# -------------------------------------------------------------------------
# 404 on a path that was never written
# -------------------------------------------------------------------------

begin_test "GET unknown path returns 404"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${GENERIC_URL}/no/such/path-${RUN_ID}.bin") || status="000"
if assert_eq "$status" "404" "expected 404 for unknown path, got ${status}"; then
  pass
fi

# -------------------------------------------------------------------------
# Unauthenticated PUT is rejected
#
# This guards against a regression where the format-native endpoint
# accidentally allows anonymous writes. A 401 (preferred) or 403 are
# both acceptable; anything in 2xx is a security regression.
# -------------------------------------------------------------------------

begin_test "Unauthenticated PUT is rejected"
echo "should not be accepted" > "${WORK_DIR}/anon.txt"
anon_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "Content-Type: text/plain" \
  --data-binary "@${WORK_DIR}/anon.txt" \
  "${GENERIC_URL}/anon/leak.txt") || anon_status="000"
if [ "$anon_status" = "401" ] || [ "$anon_status" = "403" ]; then
  pass
else
  fail "anonymous PUT to /generic/{key}/{path} returned ${anon_status}, expected 401 or 403"
fi

end_suite
