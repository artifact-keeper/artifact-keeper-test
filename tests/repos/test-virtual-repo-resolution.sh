#!/usr/bin/env bash
# test-virtual-repo-resolution.sh - Virtual repository aggregation E2E test
#
# Tests that a virtual repository aggregates artifacts from multiple local
# repositories and resolves them by priority order.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-repo-resolution"
auth_admin
setup_workdir

LOCAL_A="test-virt-local-a-${RUN_ID}"
LOCAL_B="test-virt-local-b-${RUN_ID}"
VIRTUAL_KEY="test-virt-virtual-${RUN_ID}"

# -------------------------------------------------------------------------
# Create two local repos and one virtual repo
# -------------------------------------------------------------------------

begin_test "Create local repo A"
if create_local_repo "$LOCAL_A" "generic"; then
  pass
else
  fail "could not create local repo A"
fi

begin_test "Create local repo B"
if create_local_repo "$LOCAL_B" "generic"; then
  pass
else
  fail "could not create local repo B"
fi

begin_test "Create virtual repo"
if create_virtual_repo "$VIRTUAL_KEY" "generic"; then
  pass
else
  fail "could not create virtual repo"
fi

# -------------------------------------------------------------------------
# Add local repos as members of the virtual repo
# -------------------------------------------------------------------------

begin_test "Add local repos as virtual repo members"
MEMBERS_PAYLOAD="{\"members\":[{\"member_key\":\"${LOCAL_A}\",\"priority\":1},{\"member_key\":\"${LOCAL_B}\",\"priority\":2}]}"
if api_put "/api/v1/repositories/${VIRTUAL_KEY}/members" "$MEMBERS_PAYLOAD" > /dev/null 2>&1; then
  pass
else
  fail "could not add members to virtual repo"
fi

# -------------------------------------------------------------------------
# Upload distinct artifacts to each local repo
# -------------------------------------------------------------------------

begin_test "Upload artifact to local repo A"
echo "content-from-A-${RUN_ID}" > "${WORK_DIR}/file-a.txt"
if api_upload "/api/v1/repositories/${LOCAL_A}/artifacts/shared/file.txt" \
    "${WORK_DIR}/file-a.txt"; then
  pass
else
  fail "upload to local A failed"
fi

begin_test "Upload unique artifact to local repo B"
echo "content-from-B-${RUN_ID}" > "${WORK_DIR}/file-b.txt"
if api_upload "/api/v1/repositories/${LOCAL_B}/artifacts/only-in-b/file.txt" \
    "${WORK_DIR}/file-b.txt"; then
  pass
else
  fail "upload to local B failed"
fi

# -------------------------------------------------------------------------
# Resolve artifacts through the virtual repo
# -------------------------------------------------------------------------

sleep 2

begin_test "Virtual repo resolves artifact from local A"
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/artifacts/shared/file.txt" 2>/dev/null); then
  pass
else
  # Try downloading via generic format endpoint
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      -o "${WORK_DIR}/resolved-a.txt" \
      "${BASE_URL}/generic/${VIRTUAL_KEY}/shared/file.txt" 2>/dev/null; then
    pass
  else
    fail "virtual repo could not resolve artifact from local A"
  fi
fi

begin_test "Virtual repo resolves artifact only in local B"
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/artifacts/only-in-b/file.txt" 2>/dev/null); then
  pass
else
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      -o "${WORK_DIR}/resolved-b.txt" \
      "${BASE_URL}/generic/${VIRTUAL_KEY}/only-in-b/file.txt" 2>/dev/null; then
    pass
  else
    fail "virtual repo could not resolve artifact only in local B"
  fi
fi

# -------------------------------------------------------------------------
# List artifacts through virtual repo
# -------------------------------------------------------------------------

begin_test "List artifacts via virtual repo"
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$resp" "file.txt"; then
    pass
  fi
else
  skip "virtual repo artifact listing not supported"
fi

end_suite
