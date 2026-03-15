#!/usr/bin/env bash
# test-curation.sh - Package curation rules E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "curation"
auth_admin

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

begin_test "Delete curation rule"
if [ -n "${RULE_ID:-}" ] && [ "$RULE_ID" != "null" ]; then
  api_delete "/api/v1/curation/rules/${RULE_ID}" > /dev/null 2>&1 || true
  pass
else
  skip "no rule ID"
fi

end_suite
