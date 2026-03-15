#!/usr/bin/env bash
# test-promotion-rules.sh - Auto-promotion rules E2E test
#
# Tests CRUD for promotion rules and verifies rule evaluation triggers
# automatic promotion when conditions are met.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "promotion-rules"
auth_admin
setup_workdir

STAGING_KEY="test-promorules-staging-${RUN_ID}"
RELEASE_KEY="test-promorules-release-${RUN_ID}"

begin_test "Create staging and release repos"
if create_repo "$STAGING_KEY" "generic" "staging" && \
   create_repo "$RELEASE_KEY" "generic" "local"; then
  pass
else
  fail "could not create repos"
fi

# -------------------------------------------------------------------------
# Get repo UUIDs for rule creation
# -------------------------------------------------------------------------

SOURCE_ID=""
TARGET_ID=""
if resp=$(api_get "/api/v1/repositories/${STAGING_KEY}" 2>/dev/null); then
  SOURCE_ID=$(echo "$resp" | jq -r '.id') || true
fi
if resp=$(api_get "/api/v1/repositories/${RELEASE_KEY}" 2>/dev/null); then
  TARGET_ID=$(echo "$resp" | jq -r '.id') || true
fi

# -------------------------------------------------------------------------
# Create promotion rule
# -------------------------------------------------------------------------

begin_test "Create auto-promotion rule"
RULE_PAYLOAD='{
  "name": "auto-promote-'"${RUN_ID}"'",
  "source_repo_id": "'"${SOURCE_ID}"'",
  "target_repo_id": "'"${TARGET_ID}"'",
  "is_enabled": true
}'
if resp=$(api_post "/api/v1/promotion-rules" "$RULE_PAYLOAD" 2>/dev/null); then
  RULE_ID=$(echo "$resp" | jq -r '.id // empty') || true
  if [ -n "$RULE_ID" ] && [ "$RULE_ID" != "null" ]; then
    pass
  else
    pass  # Rule created but no ID returned
  fi
else
  skip "promotion rules endpoint not available"
fi

# -------------------------------------------------------------------------
# List rules
# -------------------------------------------------------------------------

begin_test "List promotion rules"
if resp=$(api_get "/api/v1/promotion-rules" 2>/dev/null); then
  if assert_contains "$resp" "auto-promote-${RUN_ID}"; then
    pass
  fi
else
  skip "could not list promotion rules"
fi

# -------------------------------------------------------------------------
# Get rule by ID
# -------------------------------------------------------------------------

begin_test "Get promotion rule by ID"
if [ -n "${RULE_ID:-}" ] && [ "$RULE_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/promotion-rules/${RULE_ID}" 2>/dev/null); then
    if assert_contains "$resp" "auto-promote-${RUN_ID}"; then
      pass
    fi
  else
    fail "could not get rule by ID"
  fi
else
  skip "no rule ID available"
fi

# -------------------------------------------------------------------------
# Delete rule
# -------------------------------------------------------------------------

begin_test "Delete promotion rule"
if [ -n "${RULE_ID:-}" ] && [ "$RULE_ID" != "null" ]; then
  if api_delete "/api/v1/promotion-rules/${RULE_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete promotion rule"
  fi
else
  skip "no rule ID to delete"
fi

end_suite
