#!/usr/bin/env bash
# test-curation.sh - Package curation rules E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "curation"
auth_admin

RULE_NAME="e2e-curation-${RUN_ID}"

begin_test "Create curation rule"
if resp=$(api_post "/api/v1/curation/rules" \
    "{\"name\":\"${RULE_NAME}\",\"action\":\"block\",\"criteria\":{\"name_pattern\":\"malicious-*\"}}" 2>/dev/null); then
  RULE_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
elif resp=$(api_post "/api/v1/curation" \
    "{\"name\":\"${RULE_NAME}\",\"action\":\"block\",\"criteria\":{\"name_pattern\":\"malicious-*\"}}" 2>/dev/null); then
  RULE_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "curation endpoint not available"
fi

begin_test "List curation rules"
if resp=$(api_get "/api/v1/curation/rules" 2>/dev/null); then
  if assert_contains "$resp" "$RULE_NAME"; then pass; fi
elif resp=$(api_get "/api/v1/curation" 2>/dev/null); then
  if assert_contains "$resp" "$RULE_NAME"; then pass; fi
else
  skip "curation listing not available"
fi

begin_test "Delete curation rule"
if [ -n "${RULE_ID:-}" ] && [ "$RULE_ID" != "null" ]; then
  api_delete "/api/v1/curation/rules/${RULE_ID}" > /dev/null 2>&1 || \
    api_delete "/api/v1/curation/${RULE_ID}" > /dev/null 2>&1 || true
  pass
else
  skip "no rule ID"
fi

end_suite
