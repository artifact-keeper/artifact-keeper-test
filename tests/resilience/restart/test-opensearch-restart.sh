#!/usr/bin/env bash
# test-opensearch-restart.sh - search engine restart resilience test
#
# Uploads an artifact, confirms search finds it, kills the OpenSearch pod,
# verifies that uploads continue working, waits for OpenSearch to come back,
# and confirms search finds the artifact again.
#
# This used to be test-meilisearch-restart.sh. The chart replaced Meilisearch
# with OpenSearch in v1.2.x, so `app.kubernetes.io/name=meilisearch` matched
# nothing: the kill deleted nothing ("No resources found", then PASS) and the
# recovery wait could never see a ready pod ("Meilisearch did not recover in
# 90s"). The search checks also queried the file CONTENT, which search does not
# index, so "search recovers" could not pass either way, and the baseline check
# accepted any JSON. artifact-keeper-test#354.
#
# Requires: curl, jq, kubectl
source "$(dirname "$0")/../../lib/common.sh"
source "$(dirname "$0")/../../lib/k8s.sh"

begin_suite "resilience-opensearch-restart"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="search-restart-${RUN_ID}"
# Search tokenizes on punctuation; keep the term one alphanumeric token, the
# same way tests/search/test-search-basic.sh does.
UNIQUE_TERM="srchrestart${RUN_ID//[^a-z0-9]/}"

# search_finds TERM NEEDLE TIMEOUT: poll quick search until the response
# contains NEEDLE. Indexing is asynchronous, so a single fixed sleep is a race.
search_finds() {
  local term="$1" needle="$2" timeout="$3" waited=0 resp
  while :; do
    resp=$(api_get "/api/v1/search/quick?q=${term}" 2>/dev/null) || resp=""
    case "$resp" in *"$needle"*) return 0 ;; esac
    [ "$waited" -ge "$timeout" ] && break
    sleep 3
    waited=$(( waited + 3 ))
  done
  SEARCH_LAST_RESPONSE="$resp"
  return 1
}

# -------------------------------------------------------------------------
# Setup: create repo and upload searchable artifact
# -------------------------------------------------------------------------

begin_test "Create repo and upload"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "searchable-${RUN_ID}" > "${WORK_DIR}/test.txt"
  if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/search-test.txt" \
      "${WORK_DIR}/test.txt" "text/plain" > /dev/null; then
    pass
  else
    fail_fatal "upload of the searchable artifact failed"
  fi
else
  fail_fatal "could not create repo"
fi

# -------------------------------------------------------------------------
# Verify search works before restart
# -------------------------------------------------------------------------

begin_test "Search finds the artifact before restart"
# Without a baseline hit the "search recovers" check below would be grading a
# search that never worked, so this is a precondition.
if search_finds "$UNIQUE_TERM" "search-test" 60; then
  pass
else
  fail_fatal "quick search did not return the uploaded artifact within 60s, before any restart" \
    "q=${UNIQUE_TERM}; last response: ${SEARCH_LAST_RESPONSE:-<empty>}"
fi

# -------------------------------------------------------------------------
# Kill OpenSearch pod
# -------------------------------------------------------------------------

begin_test "Kill OpenSearch"
k8s_require_pod SEARCH_POD "$AK_OPENSEARCH_SELECTOR" OpenSearch
echo "  Force-killing pod: ${SEARCH_POD}"
if del_out=$(kubectl delete pod "$SEARCH_POD" -n "${NAMESPACE}" --force --grace-period=0 2>&1); then
  echo "$del_out"
  pass
else
  infra_fail "kubectl delete pod ${SEARCH_POD} failed; the restart this suite exists to test never happened" "$del_out"
  end_suite
fi

# -------------------------------------------------------------------------
# Verify uploads still work without OpenSearch
# -------------------------------------------------------------------------

begin_test "Uploads still work without OpenSearch"
echo "during-outage-${RUN_ID}" > "${WORK_DIR}/outage.txt"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/outage-test.txt" \
    "${WORK_DIR}/outage.txt" "text/plain" > /dev/null 2>&1; then
  pass
else
  fail "uploads failed when OpenSearch is down"
fi

# -------------------------------------------------------------------------
# Wait for OpenSearch recovery
# -------------------------------------------------------------------------

begin_test "Wait for OpenSearch recovery"
# OpenSearch is a JVM with a readiness probe on cluster health; its cold start
# is slower than Meilisearch's, hence 180s rather than the old 90s.
if k8s_wait_ready "$AK_OPENSEARCH_SELECTOR" OpenSearch 180 "$SEARCH_POD_UID"; then
  echo "  OpenSearch pod ${K8S_READY_POD} ready after ${K8S_READY_ELAPSED}s"
  pass
fi

# -------------------------------------------------------------------------
# Verify search recovers
# -------------------------------------------------------------------------

begin_test "Search recovers"
if search_finds "$UNIQUE_TERM" "search-test" 90; then
  pass
else
  fail "search did not return the pre-restart artifact within 90s of OpenSearch recovery" \
    "q=${UNIQUE_TERM}; last response: ${SEARCH_LAST_RESPONSE:-<empty>}"
fi

end_suite
