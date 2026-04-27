#!/usr/bin/env bash
# test-cache-ttl-config.sh - Per-repository proxy cache TTL get/set
#
# Covers Epic 6 sub-task 6.3 (artifact-keeper-test#70):
#   PUT /api/v1/repositories/:key/cache-ttl  body: {"cache_ttl_seconds": N}
#   GET /api/v1/repositories/:key/cache-ttl
#
# Response shape (from backend repositories.rs CacheTtlResponse):
#   { "repository_key": "<key>", "cache_ttl_seconds": <i64> }
#
# Validation rules from the backend:
#   validate_cache_ttl(): 1 <= secs <= 2_592_000 (30 days). Out-of-range
#   values yield AppError::Validation -> HTTP 400.
#   Default when no row exists in repository_config: 3600 (1 hour).
#
# -------------------------------------------------------------------------
# COVERAGE GAP (documented per Epic 6 acceptance):
#
# As of v1.1.x, the cache_ttl_secs config row written by PUT /cache-ttl is
# NOT consumed anywhere else in the backend. A grep over backend/src/ for
# `cache_ttl_secs` returns only the two handler functions (set_cache_ttl
# and get_cache_ttl). The proxy cache layer does not currently honor this
# value to invalidate or re-fetch artifacts.
#
# As a result this test cannot externally observe the TTL's effect on
# proxy behavior (e.g. "wait > ttl, expect re-fetch") without faking
# observability. We assert only the contract that IS observable:
#
#   1. PUT a valid TTL -> 200 with the value echoed back.
#   2. GET right after -> same value persisted.
#   3. Default value when nothing was set (3600).
#   4. Boundary validation (lower/upper limits and out-of-range -> 400).
#
# When the proxy actually wires cache_ttl_secs into the eviction path,
# extend this script with an end-to-end "stale cache" assertion. For now
# the get-after-set roundtrip is the contract.
# -------------------------------------------------------------------------
#
# EXPECT_FAILURE=1 inverts the suite exit code.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "cache-ttl-config"
auth_admin
setup_workdir

REMOTE_KEY="test-ttl-remote-${RUN_ID}"
LOCAL_KEY="test-ttl-local-${RUN_ID}"
DEFAULT_KEY="test-ttl-default-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup: remote (proxy) repo to receive TTL config, plus a "default" remote
# we never touch so we can read the unset default. A local repo is included
# to confirm the endpoint is permitted on non-remote repos as well (the
# backend doesn't restrict cache_ttl by repo_type today; if that changes,
# the test will surface it).
# -------------------------------------------------------------------------

begin_test "Create remote repo R"
if create_remote_repo "$REMOTE_KEY" "generic" "https://example.invalid/upstream"; then
  pass
else
  fail "could not create remote repo"
fi

begin_test "Create remote repo for default-TTL probe"
if create_remote_repo "$DEFAULT_KEY" "generic" "https://example.invalid/upstream"; then
  pass
else
  fail "could not create default-probe repo"
fi

begin_test "Create local repo L"
if create_local_repo "$LOCAL_KEY" "generic"; then
  pass
else
  fail "could not create local repo"
fi

# -------------------------------------------------------------------------
# 6.3.a: GET on a never-set repo returns the documented default (3600).
# -------------------------------------------------------------------------

begin_test "GET default cache-ttl is 3600"
if RESP=$(api_get "/api/v1/repositories/${DEFAULT_KEY}/cache-ttl" 2>/dev/null); then
  ttl=$(echo "$RESP" | jq -r '.cache_ttl_seconds // empty')
  rkey=$(echo "$RESP" | jq -r '.repository_key // empty')
  if [ "$ttl" = "3600" ] && [ "$rkey" = "$DEFAULT_KEY" ]; then
    pass
  else
    fail "expected default ttl=3600 key=${DEFAULT_KEY}; got ttl='${ttl}' key='${rkey}'"
  fi
else
  fail "GET cache-ttl failed for default-probe repo"
fi

# -------------------------------------------------------------------------
# 6.3.b: PUT a valid TTL, GET it back.
# -------------------------------------------------------------------------

begin_test "PUT cache-ttl=300 on R returns 200 with value echoed"
PUT_PAYLOAD='{"cache_ttl_seconds": 300}'
if RESP=$(api_put "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" "$PUT_PAYLOAD" 2>/dev/null); then
  ttl=$(echo "$RESP" | jq -r '.cache_ttl_seconds // empty')
  rkey=$(echo "$RESP" | jq -r '.repository_key // empty')
  if [ "$ttl" = "300" ] && [ "$rkey" = "$REMOTE_KEY" ]; then
    pass
  else
    fail "expected echo ttl=300 key=${REMOTE_KEY}; got ttl='${ttl}' key='${rkey}'"
  fi
else
  fail "PUT cache-ttl failed"
fi

begin_test "GET cache-ttl on R returns the persisted value"
if RESP=$(api_get "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" 2>/dev/null); then
  ttl=$(echo "$RESP" | jq -r '.cache_ttl_seconds // empty')
  if [ "$ttl" = "300" ]; then
    pass
  else
    fail "expected persisted ttl=300, got '${ttl}'"
  fi
else
  fail "GET cache-ttl after PUT failed"
fi

# -------------------------------------------------------------------------
# 6.3.c: Update is a true upsert. PUT a different value, GET reflects it.
# This guards against a buggy INSERT-without-ON-CONFLICT regression.
# -------------------------------------------------------------------------

begin_test "PUT cache-ttl=86400 (upsert)"
if RESP=$(api_put "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" \
    '{"cache_ttl_seconds": 86400}' 2>/dev/null); then
  ttl=$(echo "$RESP" | jq -r '.cache_ttl_seconds // empty')
  if [ "$ttl" = "86400" ]; then
    pass
  else
    fail "expected upsert echo ttl=86400, got '${ttl}'"
  fi
else
  fail "PUT upsert failed"
fi

begin_test "GET reflects upserted cache-ttl=86400"
if RESP=$(api_get "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" 2>/dev/null); then
  ttl=$(echo "$RESP" | jq -r '.cache_ttl_seconds // empty')
  if [ "$ttl" = "86400" ]; then
    pass
  else
    fail "expected upserted ttl=86400, got '${ttl}'"
  fi
else
  fail "GET after upsert failed"
fi

# -------------------------------------------------------------------------
# 6.3.d: Boundary validation per validate_cache_ttl(): 1..=2_592_000.
# -------------------------------------------------------------------------

begin_test "PUT cache-ttl=1 (lower bound, valid)"
LB_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"cache_ttl_seconds": 1}' \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/cache-ttl") || LB_STATUS="000"
if assert_http_2xx "$LB_STATUS" "expected 2xx for ttl=1"; then
  pass
fi

begin_test "PUT cache-ttl=2592000 (upper bound, valid)"
UB_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"cache_ttl_seconds": 2592000}' \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/cache-ttl") || UB_STATUS="000"
if assert_http_2xx "$UB_STATUS" "expected 2xx for ttl=2592000"; then
  pass
fi

begin_test "PUT cache-ttl=0 returns 400 (below lower bound)"
ZERO_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"cache_ttl_seconds": 0}' \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/cache-ttl") || ZERO_STATUS="000"
assert_eq "$ZERO_STATUS" "400" "expected 400 for ttl=0, got ${ZERO_STATUS}" && pass

begin_test "PUT cache-ttl=2592001 returns 400 (above upper bound)"
OVER_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"cache_ttl_seconds": 2592001}' \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/cache-ttl") || OVER_STATUS="000"
assert_eq "$OVER_STATUS" "400" "expected 400 for ttl=2592001, got ${OVER_STATUS}" && pass

begin_test "PUT cache-ttl=-1 returns 400 (negative)"
NEG_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"cache_ttl_seconds": -1}' \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/cache-ttl") || NEG_STATUS="000"
assert_eq "$NEG_STATUS" "400" "expected 400 for ttl=-1, got ${NEG_STATUS}" && pass

# -------------------------------------------------------------------------
# 6.3.e: Endpoint works on a local (non-remote) repo. Today the backend
# does not gate the endpoint by repo_type, so we just confirm the
# get-after-set contract holds. If a future release restricts this to
# proxy/remote repos, this assertion will surface the change.
# -------------------------------------------------------------------------

begin_test "PUT/GET cache-ttl on local repo (current contract permits)"
PUT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"cache_ttl_seconds": 60}' \
  "${BASE_URL}/api/v1/repositories/${LOCAL_KEY}/cache-ttl") || PUT_STATUS="000"
case "$PUT_STATUS" in
  2[0-9][0-9])
    if RESP=$(api_get "/api/v1/repositories/${LOCAL_KEY}/cache-ttl" 2>/dev/null); then
      ttl=$(echo "$RESP" | jq -r '.cache_ttl_seconds // empty')
      if [ "$ttl" = "60" ]; then
        pass
      else
        fail "local repo PUT succeeded but GET returned '${ttl}'"
      fi
    else
      fail "local repo GET cache-ttl failed after PUT 2xx"
    fi
    ;;
  400|422)
    skip "backend now restricts cache-ttl to proxy repos (got ${PUT_STATUS})"
    ;;
  *)
    fail "unexpected status ${PUT_STATUS} for cache-ttl on local repo"
    ;;
esac

# -------------------------------------------------------------------------
# 6.3.f: Unknown repo -> 404.
# -------------------------------------------------------------------------

begin_test "GET cache-ttl on unknown repo returns 404"
NF_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/test-ttl-noexist-${RUN_ID}/cache-ttl") || NF_STATUS="000"
assert_eq "$NF_STATUS" "404" "expected 404 for unknown repo, got ${NF_STATUS}" && pass

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${DEFAULT_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  if ( end_suite ); then
    echo "EXPECT_FAILURE=1 but suite passed; inverting to fail"
    exit 1
  else
    echo "EXPECT_FAILURE=1 and suite failed as expected; inverting to pass"
    exit 0
  fi
fi

end_suite
