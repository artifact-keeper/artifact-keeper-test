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
# Two listing polls of at most 20 s each (uploads listed in staging, bulk
# promotion landed in release); each normally ends on its first probe.
require_wait_budget 40 "artifact listing polls"

STAGING_KEY="test-bulk-staging-${RUN_ID}"
RELEASE_KEY="test-bulk-release-${RUN_ID}"

# listed_count KEY: how many artifacts the KEY listing returns (same shape
# handling as the assertions below).
listed_count() {
  local resp
  resp=$(api_get "/api/v1/repositories/${1}/artifacts" 2>/dev/null) || { echo 0; return; }
  echo "$resp" | jq '
    if type == "array" then length
    elif .items then (.items | length)
    elif .total != null then .total
    else 0
    end' 2>/dev/null || echo 0
}

# listed_at_least KEY N: wait_until predicate, the KEY listing holds >= N rows.
listed_at_least() {
  local n
  n=$(listed_count "$1")
  [ "${n:-0}" -ge "$2" ] 2>/dev/null
}

begin_test "Create repos"
if create_repo "$STAGING_KEY" "generic" "staging" && \
   create_repo "$RELEASE_KEY" "generic" "local"; then
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

# -------------------------------------------------------------------------
# Collect artifact IDs
# -------------------------------------------------------------------------

begin_test "Collect artifact IDs for bulk promote"
ARTIFACT_IDS="[]"
# Wait until every accepted upload is listed before collecting ids.
if ! wait_until "${uploaded} uploads listed in ${STAGING_KEY}" 20 listed_at_least "$STAGING_KEY" "$uploaded"; then
  fail "only $(listed_count "$STAGING_KEY") of ${uploaded} accepted uploads appeared in the ${STAGING_KEY} listing within 20s"
elif resp=$(api_get "/api/v1/repositories/${STAGING_KEY}/artifacts" 2>/dev/null); then
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
  BULK_PAYLOAD="{\"target_repository\":\"${RELEASE_KEY}\",\"artifact_ids\":${ARTIFACT_IDS}}"
  if api_post "/api/v1/promotion/repositories/${STAGING_KEY}/promote" "$BULK_PAYLOAD" > /dev/null 2>&1; then
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

begin_test "Verify artifacts promoted to release"
# Wait for the bulk promotion to land (one copied row per promoted id listed
# in the target), then assert on the listing as before.
PROMOTED_N=$(echo "$ARTIFACT_IDS" | jq 'length' 2>/dev/null) || PROMOTED_N=0
if ! wait_until "${PROMOTED_N} promoted artifacts listed in ${RELEASE_KEY}" 20 listed_at_least "$RELEASE_KEY" "${PROMOTED_N:-0}"; then
  fail "only $(listed_count "$RELEASE_KEY") of ${PROMOTED_N} promoted artifacts appeared in the ${RELEASE_KEY} listing within 20s"
elif resp=$(api_get "/api/v1/repositories/${RELEASE_KEY}/artifacts" 2>/dev/null); then
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
