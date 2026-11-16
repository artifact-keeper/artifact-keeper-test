#!/usr/bin/env bash
# test-reindex.sh - Reindex trigger contract (Epic 10.10, #77)
#
# Pins the contract on POST /api/v1/admin/reindex. The handler runs a full
# OpenSearch reindex of every artifact and repository and answers 200 with
# ReindexResponse { message, artifacts_indexed, repositories_indexed } once it
# has finished (backend/src/api/handlers/admin.rs trigger_reindex). It is
# synchronous, so there is no job to wait for: the response IS the outcome.
# The suite used to describe it as "202 with a job id, not waited for" and
# passed on any 2xx body, including an empty one.
#
# Sibling impact (artifact-keeper-test#365): a full reindex is instance-wide.
# While it runs, the artifacts index has refresh disabled, so a document a
# concurrent suite indexes becomes searchable only when the reindex refreshes
# at its end. On the gate's small instance that is seconds. The search suites
# poll for visibility with bounded waits (#364), which absorb the window; a
# search suite that guesses a fixed sleep does not.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-reindex"
auth_admin

begin_test "POST /admin/reindex completes and reports what it indexed"
RESP_FILE=$(mktemp)
curl_rc=0
status=$(curl -s -o "$RESP_FILE" -w '%{http_code}' --max-time 60 \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${BASE_URL}/api/v1/admin/reindex" 2>/dev/null) || curl_rc=$?
[ "$curl_rc" -eq 0 ] || status=000
resp=$(cat "$RESP_FILE"); rm -f "$RESP_FILE"
if [ "$status" = "200" ]; then
  if echo "$resp" | jq -e '(.artifacts_indexed | type) == "number" and (.repositories_indexed | type) == "number"' > /dev/null 2>&1; then
    echo "  indexed $(echo "$resp" | jq -r '.artifacts_indexed') artifacts, $(echo "$resp" | jq -r '.repositories_indexed') repositories"
    pass
  else
    fail "reindex answered 200 without numeric artifacts_indexed/repositories_indexed" "${resp:0:300}"
  fi
elif [ "$status" = "404" ]; then
  # Under RELEASE_GATE=1 the admin-tests job pre-waits for OpenSearch
  # ready, so a 404 here means the route is genuinely missing on the
  # build under test, not a not-yet-ready race. That is a real
  # regression (the release gate must pin the reindex contract), so
  # promote the skip to a hard fail in release-gate context. Local-dev
  # runs (no RELEASE_GATE) keep the graceful skip so this test still
  # works against builds that don't ship the endpoint.
  if [ "${RELEASE_GATE:-0}" = "1" ]; then
    fail "POST /api/v1/admin/reindex returned 404 under RELEASE_GATE=1 (endpoint must be mounted on release-gate builds)"
  else
    skip "endpoint not mounted in this build"
  fi
elif [ "$curl_rc" -eq 28 ]; then
  # The request reached the backend and the reindex did not finish: that is
  # the product, not the harness.
  fail "POST /api/v1/admin/reindex did not finish within 60s"
elif [ "$status" = "000" ]; then
  infra_fail "POST /api/v1/admin/reindex got no HTTP answer (curl exit ${curl_rc}: connection refused or reset)"
else
  fail "expected 200 from a completed reindex, got ${status}" "${resp:0:300}"
fi

begin_test "POST /admin/reindex without auth returns 401/403"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${BASE_URL}/api/v1/admin/reindex" 2>/dev/null) || status=000
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
  pass
elif [ "$status" = "404" ]; then
  # Same reasoning as above: in release-gate the route must exist.
  if [ "${RELEASE_GATE:-0}" = "1" ]; then
    fail "POST /api/v1/admin/reindex returned 404 (unauth) under RELEASE_GATE=1"
  else
    skip "endpoint not mounted"
  fi
else
  fail "expected 401/403 for unauthenticated, got ${status}"
fi

end_suite
