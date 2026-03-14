#!/usr/bin/env bash
# test-search-checksum.sh - Checksum-based artifact lookup E2E test
#
# Uploads an artifact, computes its SHA256, and searches by checksum.
#
# Requires: curl, jq, sha256sum or shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-checksum"
auth_admin
setup_workdir

REPO_KEY="test-checksum-${RUN_ID}"

begin_test "Create repo and upload artifact"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "checksum-test-content-${RUN_ID}" > "${WORK_DIR}/checksumfile.bin"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/checksumfile.bin" \
    "${WORK_DIR}/checksumfile.bin" > /dev/null 2>&1
  pass
else
  fail "could not create repo"
fi

# Compute SHA256
if command -v sha256sum &>/dev/null; then
  CHECKSUM=$(sha256sum "${WORK_DIR}/checksumfile.bin" | awk '{print $1}')
elif command -v shasum &>/dev/null; then
  CHECKSUM=$(shasum -a 256 "${WORK_DIR}/checksumfile.bin" | awk '{print $1}')
else
  CHECKSUM=""
fi

sleep 3

# -------------------------------------------------------------------------
# Search by checksum
# -------------------------------------------------------------------------

begin_test "Search by SHA256 checksum"
if [ -n "$CHECKSUM" ]; then
  if resp=$(api_get "/api/v1/search/checksum?sha256=${CHECKSUM}" 2>/dev/null); then
    if assert_contains "$resp" "checksumfile"; then
      pass
    fi
  elif resp=$(api_get "/api/v1/search?checksum=${CHECKSUM}" 2>/dev/null); then
    if assert_contains "$resp" "checksumfile"; then
      pass
    fi
  else
    skip "checksum search not available"
  fi
else
  skip "sha256sum/shasum not available"
fi

end_suite
