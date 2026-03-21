#!/usr/bin/env bash
# test-meilisearch-restart.sh - Meilisearch restart resilience test
#
# Uploads an artifact, kills the Meilisearch pod, verifies that uploads
# continue working, waits for recovery, and confirms search recovers.
#
# Requires: curl, jq, kubectl
source "$(dirname "$0")/../../lib/common.sh"

begin_suite "resilience-meilisearch-restart"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="meili-test-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup: create repo and upload searchable artifact
# -------------------------------------------------------------------------

begin_test "Create repo and upload"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "searchable-${RUN_ID}" > "${WORK_DIR}/test.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/search-test.txt" \
    "${WORK_DIR}/test.txt" "text/plain" > /dev/null
  pass
else
  fail "could not create repo"
fi

sleep 3  # Allow indexing

# -------------------------------------------------------------------------
# Verify search works before restart
# -------------------------------------------------------------------------

begin_test "Search works before restart"
resp=$(api_get "/api/v1/search/quick?q=searchable-${RUN_ID}" 2>/dev/null) || true
if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  pass
else
  skip "search not available (Meilisearch may not be deployed)"
fi

# -------------------------------------------------------------------------
# Kill Meilisearch pod
# -------------------------------------------------------------------------

begin_test "Kill Meilisearch"
kubectl delete pod -l app.kubernetes.io/name=meilisearch -n "${NAMESPACE}" --force 2>&1 || true
pass

# -------------------------------------------------------------------------
# Verify uploads still work without Meilisearch
# -------------------------------------------------------------------------

begin_test "Uploads still work without Meilisearch"
echo "during-outage-${RUN_ID}" > "${WORK_DIR}/outage.txt"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/outage-test.txt" \
    "${WORK_DIR}/outage.txt" "text/plain" > /dev/null 2>&1; then
  pass
else
  fail "uploads failed when Meilisearch is down"
fi

# -------------------------------------------------------------------------
# Wait for Meilisearch recovery
# -------------------------------------------------------------------------

begin_test "Wait for Meilisearch recovery"
elapsed=0
ready="false"
while [ "$elapsed" -lt 90 ]; do
  ready=$(kubectl get pods -l app.kubernetes.io/name=meilisearch \
    -n "${NAMESPACE}" -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null || true)
  if [ "$ready" = "true" ]; then break; fi
  sleep 5
  elapsed=$((elapsed + 5))
done
if [ "$ready" = "true" ]; then
  pass
else
  fail "Meilisearch did not recover in 90s"
fi

# -------------------------------------------------------------------------
# Verify search recovers
# -------------------------------------------------------------------------

begin_test "Search recovers"
sleep 10  # Allow reindexing after restart
resp=$(api_get "/api/v1/search/quick?q=searchable-${RUN_ID}" 2>/dev/null) || true
if [ -n "$resp" ] && assert_contains "$resp" "search-test"; then
  pass
else
  fail "search did not recover after Meilisearch restart"
fi

end_suite
