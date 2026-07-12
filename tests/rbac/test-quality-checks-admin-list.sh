#!/usr/bin/env bash
# test-quality-checks-admin-list.sh - Admin quality-checks list-all E2E (#2419)
#
# Verifies the admin quality-checks list-all endpoint contract:
#   * admin  GET /api/v1/admin/quality-checks                 -> 200 + paginated
#                                                                {items,total,page,per_page} envelope
#   * admin  GET /api/v1/admin/quality-checks?repository_id=  -> 200 filtered (scoped envelope)
#   * non-admin GET /api/v1/admin/quality-checks              -> 403 (admin-gated)
#   * GET /api/v1/quality/checks (no artifact_id)             -> 400 (unchanged #2334 contract)
#
# The list-all endpoint (#2419) is what the web admin quality-checks page
# depends on; the artifact-scoped /quality/checks route intentionally still
# requires artifact_id and is NOT changed. Assertions target the endpoint
# contract (status + envelope shape), so the test is robust whether or not the
# backend already has quality-check rows.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "quality-checks-admin-list"
auth_admin
setup_workdir

begin_test "Backend supports admin quality-checks list-all (#2419)"
require_feature "quality_checks_admin_list" || { end_suite; exit 0; }
pass

TEST_USER="e2e-qcadmin-${RUN_ID}"
TEST_PASS="QcAdmin123!"
REPO_KEY="e2e-qc-repo-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup: a repository (for the repository_id filter) and a non-admin user.
# -------------------------------------------------------------------------

begin_test "Create repository for scoped filter"
REPO_ID=""
if create_repo "$REPO_KEY" "rpm" "local"; then
  REPO_ID=$(api_get "/api/v1/repositories/${REPO_KEY}" 2>/dev/null | jq -r '.id // empty') || true
  if [ -n "$REPO_ID" ] && [ "$REPO_ID" != "null" ]; then
    pass
  else
    fail "repo created but could not resolve id"
  fi
else
  fail "could not create repository"
fi

begin_test "Create non-admin user and login"
USER_ID=""
USER_TOKEN=""
USER_ID=$(create_test_user_with_retry "$TEST_USER" "$TEST_PASS" "${TEST_USER}@test.local") || true
if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  USER_TOKEN=$(login_as "$TEST_USER" "$TEST_PASS") || true
  if [ -n "$USER_TOKEN" ]; then
    pass
  else
    fail "could not login as non-admin user"
  fi
else
  fail "could not create non-admin user"
fi

# -------------------------------------------------------------------------
# 1) Admin list-all -> 200 with the paginated envelope.
# -------------------------------------------------------------------------

begin_test "Admin GET /admin/quality-checks -> 200 paginated envelope"
BODY_FILE=$(mktemp)
STATUS=$(curl -s -o "$BODY_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/admin/quality-checks" 2>/dev/null) || STATUS="000"
BODY=$(cat "$BODY_FILE" 2>/dev/null || true); rm -f "$BODY_FILE"
if [ "$STATUS" = "200" ]; then
  # Envelope must carry items (array), total (number), page, per_page.
  SHAPE=$(echo "$BODY" | jq -r '
    if (.items | type) == "array"
       and (.total | type) == "number"
       and (.page  | type) == "number"
       and (.per_page | type) == "number"
    then "ok" else "bad" end' 2>/dev/null) || SHAPE="bad"
  assert_eq "$SHAPE" "ok" "expected {items,total,page,per_page} envelope, got: ${BODY:0:200}" && pass
else
  fail "expected 200, got ${STATUS}: ${BODY:0:200}"
fi

# -------------------------------------------------------------------------
# 2) Admin filtered by repository_id -> 200 scoped envelope.
# -------------------------------------------------------------------------

begin_test "Admin GET /admin/quality-checks?repository_id -> 200 scoped"
if [ -n "$REPO_ID" ]; then
  BODY_FILE=$(mktemp)
  STATUS=$(curl -s -o "$BODY_FILE" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/quality-checks?repository_id=${REPO_ID}" 2>/dev/null) || STATUS="000"
  BODY=$(cat "$BODY_FILE" 2>/dev/null || true); rm -f "$BODY_FILE"
  if [ "$STATUS" = "200" ]; then
    HAS_ITEMS=$(echo "$BODY" | jq -r 'if (.items | type) == "array" then "ok" else "bad" end' 2>/dev/null) || HAS_ITEMS="bad"
    # Every returned row (if any) must belong to the requested repository.
    OFF_SCOPE=$(echo "$BODY" | jq -r --arg r "$REPO_ID" '[.items[]? | select(.repository_id != $r)] | length' 2>/dev/null) || OFF_SCOPE="1"
    assert_eq "$HAS_ITEMS" "ok" "scoped response missing items array" \
      && assert_eq "$OFF_SCOPE" "0" "scoped response leaked other repositories' rows" \
      && pass
  else
    fail "expected 200 for scoped list, got ${STATUS}: ${BODY:0:200}"
  fi
else
  skip "no repository id available"
fi

# -------------------------------------------------------------------------
# 3) Non-admin -> 403 (admin-gated list-all).
# -------------------------------------------------------------------------

begin_test "Non-admin GET /admin/quality-checks -> 403"
if [ -n "$USER_TOKEN" ]; then
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/admin/quality-checks" 2>/dev/null) || STATUS="000"
  assert_eq "$STATUS" "403" "expected 403 for non-admin, got ${STATUS}" && pass
else
  skip "no non-admin token"
fi

# -------------------------------------------------------------------------
# 4) Regression: artifact-scoped /quality/checks still 400s without
#    artifact_id (the #2334 contract must NOT change).
# -------------------------------------------------------------------------

begin_test "GET /quality/checks without artifact_id -> 400 (#2334 unchanged)"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/quality/checks" 2>/dev/null) || STATUS="000"
assert_eq "$STATUS" "400" "expected 400 (artifact_id required), got ${STATUS}" && pass

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

auth_admin
[ -n "$USER_ID" ] && api_delete "/api/v1/users/${USER_ID}" >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true

end_suite
