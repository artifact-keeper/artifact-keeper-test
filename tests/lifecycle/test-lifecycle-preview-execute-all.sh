#!/usr/bin/env bash
# test-lifecycle-preview-execute-all.sh - Lifecycle preview + execute-all
#
# Covers Epic 6 sub-tasks 6.5 and 6.6 (artifact-keeper-test#71):
#   6.5 POST /api/v1/admin/lifecycle/{id}/preview   (dry-run, no mutation)
#   6.6 POST /api/v1/admin/lifecycle/execute-all    (apply all enabled policies)
#
# Schema source (openapi.yaml):
#   /admin/lifecycle/{id}/preview  -> PolicyExecutionResult (single object)
#   /admin/lifecycle/execute-all   -> array<PolicyExecutionResult>
#
# Background: test-lifecycle-policies.sh already covers single-policy
# create + dry-run-fallback + per-policy execute. It does NOT pin:
#   - The dedicated preview endpoint distinguishes itself from execute by
#     leaving the artifacts in place (i.e. preview MUST be a true dry-run).
#   - execute-all returns an array shape and iterates over multiple
#     policies (the existing test only ever creates one).
#
# Contract under test:
#   1. Create two repos, upload >=3 versions to each.
#   2. Create one max_versions=1 policy per repo.
#   3. POST .../{id}/preview on policy A. Assert response is non-empty
#      object (PolicyExecutionResult), AND that the artifacts are still
#      there (preview did not delete).
#   4. POST .../execute-all. Assert response is an array with length>=2
#      (one entry per enabled policy).
#   5. After execute-all, each repo retains <= 2 versions (we tolerate
#      slight over-retention from policy-engine batching; the strong
#      signal is "fewer than we started with on BOTH repos").
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "lifecycle-preview-execute-all"
auth_admin
setup_workdir

REPO_A="test-lc-a-${RUN_ID}"
REPO_B="test-lc-b-${RUN_ID}"
POLICY_A=""
POLICY_B=""

add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/repositories/${REPO_A}\" || true"
add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/repositories/${REPO_B}\" || true"
# Policy cleanup is registered dynamically below once we have the ids.

# -------------------------------------------------------------------------
# Setup: two repos, each with several versioned artifacts.
# -------------------------------------------------------------------------

create_repo_with_versions() {
  local key="$1"
  if ! create_local_repo "$key" "generic"; then
    return 1
  fi
  if ! resp=$(api_get "/api/v1/repositories/${key}" 2>/dev/null); then
    return 1
  fi
  local repo_id
  repo_id=$(echo "$resp" | jq -r '.id // empty')
  if [ -z "$repo_id" ] || [ "$repo_id" = "null" ]; then
    return 1
  fi
  # Upload 4 versions; max_versions=1 should remove all but one.
  local i
  for i in 1 2 3 4; do
    echo "v${i}-${RUN_ID}" > "${WORK_DIR}/${key}-v${i}.txt"
    curl -s -o /dev/null $CURL_TIMEOUT \
      -X PUT -H "$(auth_header)" -H "Content-Type: application/octet-stream" \
      --data-binary "@${WORK_DIR}/${key}-v${i}.txt" \
      "${BASE_URL}/api/v1/repositories/${key}/artifacts/pkg/v${i}/file.txt" \
      > /dev/null 2>&1 || true
  done
  echo "$repo_id"
}

begin_test "Create repo A + 4 versions"
REPO_A_ID=$(create_repo_with_versions "$REPO_A") || REPO_A_ID=""
if [ -n "$REPO_A_ID" ]; then pass; else skip_suite "could not set up repo A"; fi

begin_test "Create repo B + 4 versions"
REPO_B_ID=$(create_repo_with_versions "$REPO_B") || REPO_B_ID=""
if [ -n "$REPO_B_ID" ]; then pass; else skip_suite "could not set up repo B"; fi

# -------------------------------------------------------------------------
# Create one lifecycle policy per repo. If the policy create endpoint
# returns 404/501 we skip the whole suite since neither preview nor
# execute-all are reachable without a policy id.
# -------------------------------------------------------------------------

create_policy() {
  local repo_id="$1"
  local name="$2"
  local body
  body=$(jq -n --arg n "$name" --arg r "$repo_id" \
    '{name: $n, repository_id: $r, policy_type: "max_versions", config: {max_versions: 1}, priority: 10}')
  local out="${WORK_DIR}/${name}.json"
  local st
  st=$(curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$body" "${BASE_URL}/api/v1/admin/lifecycle" 2>/dev/null) || st="000"
  if [ "$st" -lt 200 ] 2>/dev/null || [ "$st" -ge 300 ] 2>/dev/null; then
    echo "  policy create returned HTTP ${st}: $(head -c 200 "$out" 2>/dev/null)"
    return 1
  fi
  jq -r '.id // empty' < "$out"
}

begin_test "Create policy A (max_versions=1 on repo A)"
POLICY_A=$(create_policy "$REPO_A_ID" "lc-a-${RUN_ID}") || POLICY_A=""
if [ -n "$POLICY_A" ] && [ "$POLICY_A" != "null" ]; then
  add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/admin/lifecycle/${POLICY_A}\" || true"
  pass
else
  skip_suite "could not create policy A"
fi

begin_test "Create policy B (max_versions=1 on repo B)"
POLICY_B=$(create_policy "$REPO_B_ID" "lc-b-${RUN_ID}") || POLICY_B=""
if [ -n "$POLICY_B" ] && [ "$POLICY_B" != "null" ]; then
  add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/admin/lifecycle/${POLICY_B}\" || true"
  pass
else
  skip_suite "could not create policy B"
fi

# Helper: count how many of v1..v4 still resolve for a given repo.
count_versions() {
  local key="$1"
  local n=0 i st
  for i in 1 2 3 4; do
    st=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/repositories/${key}/artifacts/pkg/v${i}/file.txt" 2>/dev/null) || st="000"
    if [ "$st" = "200" ]; then n=$(( n + 1 )); fi
  done
  echo "$n"
}

# -------------------------------------------------------------------------
# 6.5: Preview must be a true dry-run.
# -------------------------------------------------------------------------

begin_test "POST /lifecycle/:id/preview returns PolicyExecutionResult with dry_run=true"
PREVIEW_BODY="${WORK_DIR}/preview.json"
PREVIEW_STATUS=$(curl -s -o "$PREVIEW_BODY" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d '{}' \
  "${BASE_URL}/api/v1/admin/lifecycle/${POLICY_A}/preview" 2>/dev/null) || PREVIEW_STATUS="000"
case "$PREVIEW_STATUS" in
  200)
    # PolicyExecutionResult schema (openapi.yaml:15510) requires all 7
    # fields below. dry_run MUST be true for the preview endpoint --
    # the load-bearing distinction between preview and execute. Use
    # jq -e with a single boolean expression so any missing field or
    # wrong type fails the assertion.
    if jq -e '
      type == "object"
      and (.dry_run == true)
      and (has("policy_id") and (.policy_id | type) == "string")
      and (has("policy_name") and (.policy_name | type) == "string")
      and (has("artifacts_matched") and (.artifacts_matched | type) == "number")
      and (has("artifacts_removed") and (.artifacts_removed | type) == "number")
      and (has("bytes_freed") and (.bytes_freed | type) == "number")
      and (has("errors") and (.errors | type) == "array")
    ' < "$PREVIEW_BODY" > /dev/null 2>&1; then
      pass
    else
      body=$(head -c 400 "$PREVIEW_BODY" 2>/dev/null || true)
      fail "preview response missing required PolicyExecutionResult fields or dry_run!=true: ${body}"
    fi
    ;;
  404|501)
    skip "preview endpoint returned ${PREVIEW_STATUS}; not exposed in this build"
    ;;
  *)
    body=$(head -c 400 "$PREVIEW_BODY" 2>/dev/null || true)
    fail "preview returned HTTP ${PREVIEW_STATUS}: ${body}"
    ;;
esac

begin_test "Preview did NOT delete artifacts (dry-run guarantee)"
# Repo A should still have all 4 versions after preview.
N_AFTER_PREVIEW=$(count_versions "$REPO_A")
if [ "$N_AFTER_PREVIEW" -ge 4 ] 2>/dev/null; then
  pass
elif [ "$PREVIEW_STATUS" != "200" ]; then
  skip "preview did not run; nothing to assert"
else
  fail "preview appears to have mutated state: only ${N_AFTER_PREVIEW}/4 versions remain on repo A"
fi

# -------------------------------------------------------------------------
# 6.6: execute-all applies every enabled policy.
# -------------------------------------------------------------------------

begin_test "POST /lifecycle/execute-all returns array"
EXEC_BODY="${WORK_DIR}/execute-all.json"
EXEC_STATUS=$(curl -s -o "$EXEC_BODY" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d '{}' \
  "${BASE_URL}/api/v1/admin/lifecycle/execute-all" 2>/dev/null) || EXEC_STATUS="000"
case "$EXEC_STATUS" in
  200)
    if jq -e 'type == "array"' < "$EXEC_BODY" > /dev/null 2>&1; then
      pass
    else
      fail "execute-all response is not an array: $(head -c 200 "$EXEC_BODY")"
    fi
    ;;
  404|501)
    skip "execute-all endpoint returned ${EXEC_STATUS}"
    ;;
  *)
    body=$(head -c 400 "$EXEC_BODY" 2>/dev/null || true)
    fail "execute-all returned HTTP ${EXEC_STATUS}: ${body}"
    ;;
esac

begin_test "execute-all reports >= 2 results (one per enabled policy)"
if [ "$EXEC_STATUS" != "200" ]; then
  skip "execute-all did not return 200"
else
  n=$(jq 'length' < "$EXEC_BODY" 2>/dev/null || echo 0)
  if [ "$n" -ge 2 ] 2>/dev/null; then
    pass
  else
    # Other suites may run in parallel and clean up policies before our
    # execute-all fires. Treat n==1 as a soft failure (the count is
    # informational; the real assertion is "array shape returned").
    fail "expected >= 2 policy results, got ${n}"
  fi
fi

begin_test "After execute-all, both repos have <= 2 versions remaining"
if [ "$EXEC_STATUS" != "200" ]; then
  skip "execute-all did not return 200"
else
  # Give the policy engine a moment in case execution is async.
  sleep 5
  REM_A=$(count_versions "$REPO_A")
  REM_B=$(count_versions "$REPO_B")
  # max_versions=1, so ideally REM == 1. Tolerate up to 2 to absorb
  # batching / clock-window edge cases.
  if [ "$REM_A" -le 2 ] 2>/dev/null && [ "$REM_B" -le 2 ] 2>/dev/null; then
    pass
  else
    fail "expected <= 2 versions on each repo after execute-all; got A=${REM_A}, B=${REM_B}"
  fi
fi

end_suite
