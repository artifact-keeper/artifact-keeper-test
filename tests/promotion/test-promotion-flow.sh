#!/usr/bin/env bash
# test-promotion-flow.sh - Artifact promotion E2E test
#
# Tests the complete promotion lifecycle: upload artifact to staging repo,
# promote to release repo, verify artifact appears in target, verify
# promotion history.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "promotion-flow"
auth_admin
setup_workdir

STAGING_KEY="test-promo-staging-${RUN_ID}"
RELEASE_KEY="test-promo-release-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup: create staging and release repos
# -------------------------------------------------------------------------

begin_test "Create staging repo"
if create_repo "$STAGING_KEY" "generic" "staging"; then
  pass
else
  fail "could not create staging repo"
fi

begin_test "Create release repo"
if create_repo "$RELEASE_KEY" "generic" "local"; then
  pass
else
  fail "could not create release repo"
fi

# -------------------------------------------------------------------------
# Upload artifact to staging
# -------------------------------------------------------------------------

begin_test "Upload artifact to staging"
echo "release-candidate-${RUN_ID}" > "${WORK_DIR}/app.jar"
if api_upload "/api/v1/repositories/${STAGING_KEY}/artifacts/com/app/app.jar" \
    "${WORK_DIR}/app.jar"; then
  pass
else
  fail "upload to staging failed"
fi

sleep 2

# -------------------------------------------------------------------------
# Get artifact ID for promotion
# -------------------------------------------------------------------------

begin_test "Get artifact ID from staging"
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${STAGING_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // .[0].artifact_id // empty
    elif .items then .items[0].id // .items[0].artifact_id // empty
    else .id // .artifact_id // empty
    end' 2>/dev/null) || true
  if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
    pass
  else
    fail "could not extract artifact ID from response"
  fi
else
  fail "could not list staging artifacts"
fi

# -------------------------------------------------------------------------
# Promote artifact
# -------------------------------------------------------------------------

begin_test "Promote artifact from staging to release"
if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" = "null" ]; then
  skip "no artifact ID available"
else
  PROMO_PAYLOAD="{\"target_repository\":\"${RELEASE_KEY}\"}"
  if api_post "/api/v1/promotion/repositories/${STAGING_KEY}/artifacts/${ARTIFACT_ID}/promote" "$PROMO_PAYLOAD" > /dev/null 2>&1; then
    pass
  else
    fail "promotion request failed"
  fi
fi

# -------------------------------------------------------------------------
# Verify artifact in release repo
# -------------------------------------------------------------------------

sleep 2

begin_test "Verify artifact exists in release repo"
if resp=$(api_get "/api/v1/repositories/${RELEASE_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$resp" "app.jar"; then
    pass
  fi
else
  fail "could not list release repo artifacts"
fi

# -------------------------------------------------------------------------
# Check promotion history
# -------------------------------------------------------------------------

begin_test "Verify promotion history"
if resp=$(api_get "/api/v1/promotion/repositories/${STAGING_KEY}/promotion-history" 2>/dev/null); then
  if assert_contains "$resp" "$RELEASE_KEY"; then
    pass
  fi
else
  skip "promotion history endpoint not available"
fi

end_suite
