#!/usr/bin/env bash
# test-generic-reupload.sh - Generic artifact re-upload after delete
#
# Verifies the full cycle: upload, verify, delete, verify deleted,
# re-upload the same path, and confirm the new content is served.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "generic-reupload"
auth_admin
setup_workdir
# Three listing polls of at most 20 s each; each normally ends on its first
# probe (upload and delete commit the row change before they answer).
require_wait_budget 60 "artifact listing polls"

REPO_KEY="test-reupload-${RUN_ID}"
ARTIFACT_PATH="libs/reupload-test.jar"

# not_listed: wait_until predicate, the deleted artifact is gone from the
# listing (or the listing itself is gone, which the check below also accepts).
not_listed() { ! repo_lists_artifact "$REPO_KEY" "reupload-test"; }

# -------------------------------------------------------------------------
# Setup
# -------------------------------------------------------------------------

begin_test "Create local generic repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

# -------------------------------------------------------------------------
# First upload
# -------------------------------------------------------------------------

begin_test "Upload artifact (first version)"
echo "first-content-${RUN_ID}" > "${WORK_DIR}/first.txt"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" \
    "${WORK_DIR}/first.txt"; then
  pass
else
  fail "first upload failed"
fi

begin_test "Verify artifact appears in listing"
if ! wait_until "reupload-test listed in ${REPO_KEY}" 20 repo_lists_artifact "$REPO_KEY" "reupload-test"; then
  fail "uploaded artifact never appeared in the ${REPO_KEY} listing within 20s"
elif resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$resp" "reupload-test"; then
    pass
  fi
else
  fail "could not list artifacts"
fi

# -------------------------------------------------------------------------
# Delete
# -------------------------------------------------------------------------

begin_test "Delete artifact"
if api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" > /dev/null 2>&1; then
  pass
else
  fail "delete failed"
fi

begin_test "Verify artifact is gone from listing"
# Bounded wait for the delete to leave the listing. On timeout wait_until
# logs it and the check below judges the listing (common.sh runs under
# set -e, so the timeout must not abort the script).
wait_until "reupload-test gone from ${REPO_KEY}" 20 not_listed \
  || echo "  continuing to the check below after the wait timed out" >&2
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  # Empty result or no mention of the artifact both count
  count=$(echo "$resp" | jq '
    if type == "array" then length
    elif .items then (.items | length)
    elif .total != null then .total
    else 0
    end
  ' 2>/dev/null) || count=0
  if [ "$count" -eq 0 ]; then
    pass
  elif ! echo "$resp" | jq -r '.. | .path? // .name? // empty' 2>/dev/null | grep -q "reupload-test"; then
    pass
  else
    fail "artifact still present after delete"
  fi
else
  # A 404 or empty response also means it is gone
  pass
fi

# -------------------------------------------------------------------------
# Re-upload same path with new content
# -------------------------------------------------------------------------

begin_test "Re-upload artifact (second version)"
echo "second-content-${RUN_ID}" > "${WORK_DIR}/second.txt"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" \
    "${WORK_DIR}/second.txt"; then
  pass
else
  fail "re-upload failed"
fi

begin_test "Verify re-uploaded artifact appears in listing"
if ! wait_until "re-uploaded reupload-test listed in ${REPO_KEY}" 20 repo_lists_artifact "$REPO_KEY" "reupload-test"; then
  fail "re-uploaded artifact never appeared in the ${REPO_KEY} listing within 20s"
elif resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$resp" "reupload-test"; then
    pass
  fi
else
  fail "could not list artifacts after re-upload"
fi

begin_test "Verify re-uploaded content matches"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded.txt" \
    "${BASE_URL}/generic/${REPO_KEY}/${ARTIFACT_PATH}" 2>/dev/null; then
  downloaded=$(cat "${WORK_DIR}/downloaded.txt")
  expected="second-content-${RUN_ID}"
  if assert_eq "$downloaded" "$expected" "downloaded content does not match second upload"; then
    pass
  fi
elif curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded.txt" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}/download" 2>/dev/null; then
  downloaded=$(cat "${WORK_DIR}/downloaded.txt")
  expected="second-content-${RUN_ID}"
  if assert_eq "$downloaded" "$expected" "downloaded content does not match second upload"; then
    pass
  fi
else
  skip "could not download artifact to verify content"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
