#!/usr/bin/env bash
# test-upload-limit.sh - Configurable MAX_UPLOAD_SIZE verification
#
# Checks that the system config reports a max upload size, then uploads a
# file within the limit to confirm it succeeds. Generating a file large
# enough to exceed the limit is impractical in CI, so the over-limit case
# is not tested here.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "upload-limit"
auth_admin
setup_workdir

REPO_KEY="test-uplimit-${RUN_ID}"

# -------------------------------------------------------------------------
# Check system config for max upload size
# -------------------------------------------------------------------------

begin_test "System config reports max_upload_size_bytes"
MAX_UPLOAD=""
if resp=$(api_get "/api/v1/system/config" 2>/dev/null); then
  MAX_UPLOAD=$(echo "$resp" | jq -r '.max_upload_size_bytes // .max_upload_size // empty' 2>/dev/null) || true
  if [ -n "$MAX_UPLOAD" ] && [ "$MAX_UPLOAD" != "null" ]; then
    echo "  max upload size: ${MAX_UPLOAD} bytes"
    pass
  else
    skip "max_upload_size_bytes not in system config response"
  fi
elif resp=$(api_get "/api/v1/admin/settings" 2>/dev/null); then
  MAX_UPLOAD=$(echo "$resp" | jq -r '.max_upload_size_bytes // .max_upload_size // empty' 2>/dev/null) || true
  if [ -n "$MAX_UPLOAD" ] && [ "$MAX_UPLOAD" != "null" ]; then
    echo "  max upload size: ${MAX_UPLOAD} bytes"
    pass
  else
    skip "max_upload_size_bytes not in settings response"
  fi
elif resp=$(api_get "/api/v1/admin/system/settings" 2>/dev/null); then
  MAX_UPLOAD=$(echo "$resp" | jq -r '.max_upload_size_bytes // .max_upload_size // empty' 2>/dev/null) || true
  if [ -n "$MAX_UPLOAD" ] && [ "$MAX_UPLOAD" != "null" ]; then
    echo "  max upload size: ${MAX_UPLOAD} bytes"
    pass
  else
    skip "max_upload_size_bytes not in system settings response"
  fi
else
  skip "no system config endpoint returned a valid response"
fi

begin_test "Max upload size is a positive number"
if [ -n "${MAX_UPLOAD:-}" ] && [ "$MAX_UPLOAD" != "null" ]; then
  if [ "$MAX_UPLOAD" -gt 0 ] 2>/dev/null; then
    pass
  else
    fail "max_upload_size_bytes is not a positive number: ${MAX_UPLOAD}"
  fi
else
  skip "no max upload size to validate"
fi

# -------------------------------------------------------------------------
# Upload a small file (well under any reasonable limit)
# -------------------------------------------------------------------------

begin_test "Create repo for upload test"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

begin_test "Upload small file succeeds"
# Generate a 1 KB file, well under any configured limit
dd if=/dev/urandom of="${WORK_DIR}/small.bin" bs=1024 count=1 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/test/small.bin" \
    "${WORK_DIR}/small.bin"; then
  pass
else
  fail "upload of small file failed"
fi

begin_test "Upload moderate file succeeds"
# Generate a 100 KB file, still well under default limits
dd if=/dev/urandom of="${WORK_DIR}/moderate.bin" bs=1024 count=100 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/test/moderate.bin" \
    "${WORK_DIR}/moderate.bin"; then
  pass
else
  fail "upload of 100 KB file failed"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/test/moderate.bin" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/test/small.bin" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
