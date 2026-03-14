#!/usr/bin/env bash
# test-promotion-bulk.sh - Bulk artifact promotion E2E test
#
# Tests promoting multiple artifacts in a single request.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "promotion-bulk"
auth_admin
setup_workdir

STAGING_KEY="test-bulk-staging-${RUN_ID}"
RELEASE_KEY="test-bulk-release-${RUN_ID}"

begin_test "Create repos"
if create_local_repo "$STAGING_KEY" "generic" && \
   create_local_repo "$RELEASE_KEY" "generic"; then
  pass
else
  fail "could not create repos"
fi

# -------------------------------------------------------------------------
# Upload 5 artifacts to staging
# -------------------------------------------------------------------------

begin_test "Upload 5 artifacts to staging"
uploaded=0
for i in 1 2 3 4 5; do
  echo "bulk-artifact-${i}-${RUN_ID}" > "${WORK_DIR}/bulk-${i}.bin"
  if api_upload "/api/v1/repositories/${STAGING_KEY}/artifacts/pkg/bulk-${i}.bin" \
      "${WORK_DIR}/bulk-${i}.bin" > /dev/null 2>&1; then
    uploaded=$(( uploaded + 1 ))
  fi
done
if [ "$uploaded" -ge 3 ]; then
  pass
else
  fail "only uploaded ${uploaded}/5 artifacts"
fi

sleep 2

# -------------------------------------------------------------------------
# Collect artifact IDs
# -------------------------------------------------------------------------

begin_test "Collect artifact IDs for bulk promote"
ARTIFACT_IDS="[]"
if resp=$(api_get "/api/v1/repositories/${STAGING_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_IDS=$(echo "$resp" | jq '
    if type == "array" then [.[].id // .[].artifact_id] | map(select(. != null))
    elif .items then [.items[].id // .items[].artifact_id] | map(select(. != null))
    else []
    end' 2>/dev/null) || ARTIFACT_IDS="[]"
  count=$(echo "$ARTIFACT_IDS" | jq 'length') || count=0
  if [ "$count" -ge 3 ]; then
    pass
  else
    fail "only found ${count} artifact IDs"
  fi
else
  fail "could not list staging artifacts"
fi

# -------------------------------------------------------------------------
# Bulk promote
# -------------------------------------------------------------------------

begin_test "Bulk promote all artifacts"
if [ "$(echo "$ARTIFACT_IDS" | jq 'length')" -gt 0 ] 2>/dev/null; then
  BULK_PAYLOAD="{\"source_repo\":\"${STAGING_KEY}\",\"target_repo\":\"${RELEASE_KEY}\",\"artifact_ids\":${ARTIFACT_IDS}}"
  if api_post "/api/v1/promotion/promote" "$BULK_PAYLOAD" > /dev/null 2>&1; then
    pass
  elif api_post "/api/v1/promotion" "$BULK_PAYLOAD" > /dev/null 2>&1; then
    pass
  else
    fail "bulk promotion failed"
  fi
else
  skip "no artifact IDs for bulk promotion"
fi

# -------------------------------------------------------------------------
# Verify all artifacts in release repo
# -------------------------------------------------------------------------

sleep 2

begin_test "Verify artifacts promoted to release"
if resp=$(api_get "/api/v1/repositories/${RELEASE_KEY}/artifacts" 2>/dev/null); then
  count=$(echo "$resp" | jq '
    if type == "array" then length
    elif .items then (.items | length)
    elif .total != null then .total
    else 0
    end' 2>/dev/null) || count=0
  if [ "$count" -ge 3 ]; then
    pass
  else
    fail "expected >= 3 artifacts in release, got ${count}"
  fi
else
  fail "could not list release artifacts"
fi

end_suite
