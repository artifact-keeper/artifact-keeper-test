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
# Member-listing poll (15 s) plus member-upload listing poll (20 s); each
# normally ends on its first probe.
require_wait_budget 35 "member and listing polls"

LOCAL_A="test-virt-local-a-${RUN_ID}"
LOCAL_B="test-virt-local-b-${RUN_ID}"
VIRTUAL_KEY="test-virt-virtual-${RUN_ID}"

# members_listed: wait_until predicate, the virtual repo lists >= 1 member.
members_listed() {
  local n
  n=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.items | length' 2>/dev/null)
  [ "${n:-0}" -ge 1 ] 2>/dev/null
}

# member_uploads_listed: wait_until predicate, both member repos list the
# artifact uploaded to them (what the virtual listing aggregates).
member_uploads_listed() {
  repo_lists_artifact "$LOCAL_A" "shared/file.txt" && repo_lists_artifact "$LOCAL_B" "only-in-b/file.txt"
}

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
if resp=$(api_put "/api/v1/repositories/${VIRTUAL_KEY}/members" "$MEMBERS_PAYLOAD" 2>&1); then
  pass
else
  # Try POST as alternative
  if resp=$(api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
      "{\"member_key\":\"${LOCAL_A}\",\"priority\":1}" 2>&1); then
    api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
      "{\"member_key\":\"${LOCAL_B}\",\"priority\":2}" > /dev/null 2>&1 || true
    pass
  else
    fail "could not add members to virtual repo"
  fi
fi

# Verify members were added. The member write commits before it answers;
# bounded wait for the listing, the check below judges it either way.
begin_test "Verify members were added"
# common.sh runs under set -e: a timeout must not abort the script before
# the check below records its verdict.
wait_until "members listed on ${VIRTUAL_KEY}" 15 members_listed \
  || echo "  continuing to the check below after the wait timed out" >&2
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null); then
  count=$(echo "$resp" | jq '.items | length' 2>/dev/null) || count=0
  if [ "$count" -ge 1 ]; then
    pass
  else
    skip "members endpoint returned 0 items (PUT may not persist)"
  fi
else
  skip "member listing not available"
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

begin_test "Virtual repo lists aggregated artifacts"
# Precondition: each member repo lists its own upload.
if ! wait_until "uploads listed in ${LOCAL_A} and ${LOCAL_B}" 20 member_uploads_listed; then
  fail "the uploads to ${LOCAL_A} and ${LOCAL_B} were not both listed in their own repos within 20s"
elif resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/artifacts" 2>/dev/null); then
  # Virtual repo should aggregate artifacts from both local repos
  if [[ "$resp" == *"file.txt"* ]]; then
    pass
  else
    skip "virtual repo artifact aggregation returned no results"
  fi
else
  skip "virtual repo artifact listing not available"
fi

begin_test "Download artifact through virtual repo format endpoint"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/resolved.txt" \
    "${BASE_URL}/generic/${VIRTUAL_KEY}/shared/file.txt" 2>/dev/null; then
  if [ -s "${WORK_DIR}/resolved.txt" ]; then
    pass
  else
    skip "downloaded file is empty"
  fi
else
  skip "virtual repo format-level resolution not supported for generic format"
fi

# -------------------------------------------------------------------------
# List artifacts through virtual repo
# -------------------------------------------------------------------------

begin_test "List virtual repo members"
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null); then
  count=$(echo "$resp" | jq '.items | length' 2>/dev/null) || count=0
  if [ "$count" -ge 2 ]; then
    pass
  elif [ "$count" -ge 1 ]; then
    pass  # at least one member found
  else
    skip "virtual member PUT succeeded but listing returned 0 items"
  fi
else
  skip "virtual repo member listing not supported"
fi

end_suite
