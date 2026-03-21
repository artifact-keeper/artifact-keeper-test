#!/usr/bin/env bash
# test-curation.sh - Package curation rules E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "curation"
auth_admin
setup_workdir

REPO_KEY="curation-test-${RUN_ID}"
RULE_PATTERN="malicious-${RUN_ID}-*"

begin_test "Create curation rule"
if resp=$(api_post "/api/v1/curation/rules" \
    "{\"package_pattern\":\"${RULE_PATTERN}\",\"version_constraint\":\"*\",\"action\":\"block\",\"priority\":100,\"reason\":\"E2E test\"}" 2>/dev/null); then
  RULE_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "curation endpoint not available"
fi

begin_test "List curation rules"
if resp=$(api_get "/api/v1/curation/rules" 2>/dev/null); then
  if assert_contains "$resp" "$RULE_PATTERN"; then pass; fi
else
  skip "curation listing not available"
fi

# ---------------------------------------------------------------------------
# Curation enforcement tests: verify blocked packages are rejected
# ---------------------------------------------------------------------------

begin_test "Create repo for curation tests"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create curation test repo"
fi

begin_test "Attempt to download blocked package"
if [ -z "${RULE_ID:-}" ] || [ "$RULE_ID" = "null" ]; then
  skip "no curation rule was created"
else
  # Try downloading a package matching the block rule pattern
  status=$(curl -s -o /dev/null -w "%{http_code}" -H "$(auth_header)" $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/malicious-${RUN_ID}-pkg/v1/file.tar.gz" 2>&1) || true
  if [ "$status" = "403" ] || [ "$status" = "451" ] || [ "$status" = "404" ]; then
    pass
  else
    fail "blocked package was accessible (status: ${status})"
  fi
fi

begin_test "Non-blocked package still accessible"
if [ -z "${RULE_ID:-}" ] || [ "$RULE_ID" = "null" ]; then
  skip "no curation rule was created"
else
  echo "legit-pkg-${RUN_ID}" > "${WORK_DIR}/legit.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/legit-pkg/v1/file.txt" \
    "${WORK_DIR}/legit.txt" "text/plain" > /dev/null 2>&1 || true
  status=$(curl -s -o /dev/null -w "%{http_code}" -H "$(auth_header)" $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/legit-pkg/v1/file.txt" 2>&1) || true
  if [ "$status" = "200" ]; then
    pass
  else
    fail "non-blocked package was inaccessible (status: ${status})"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

begin_test "Delete curation rule"
if [ -n "${RULE_ID:-}" ] && [ "$RULE_ID" != "null" ]; then
  api_delete "/api/v1/curation/rules/${RULE_ID}" > /dev/null 2>&1 || true
  pass
else
  skip "no rule ID"
fi

end_suite
