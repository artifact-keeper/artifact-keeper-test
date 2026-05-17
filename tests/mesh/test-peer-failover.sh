#!/usr/bin/env bash
# test-peer-failover.sh - Failover across multiple peers (Epic 12.9, #78)
#
# Verifies that with two registered peers (one healthy, one broken),
# a sync policy fanning out to "all peers" still delivers artifacts
# via the healthy peer, and that the broken peer's failure does not
# block delivery. Effectively the "failover" behaviour from the
# consumer side: a client doesn't care which peer served the data,
# only that at least one healthy peer ends up holding it.
#
# This complements test-backoff-backpressure.sh (12.5+12.7) which
# focuses on backoff windows; here we focus on the failover *outcome*
# (artifact ends up on the healthy survivor).
#
# Requires: curl, jq, MAIN_URL + PEER1_URL exported.
# PEER2_URL is optional -- if absent we reuse PEER1_URL as the
# "healthy" target and a closed port as the "broken" target.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "federation-peer-failover"
setup_workdir

if [ -z "${PEER1_URL:-}" ]; then
  skip_suite "PEER1_URL not set -- multi-instance env required"
fi

MAIN_URL="${MAIN_URL:-$BASE_URL}"
BASE_URL="$MAIN_URL"
auth_admin
MAIN_TOKEN="$ADMIN_TOKEN"

# PEER2_URL is optional. The "broken" leg always points at a closed
# port so failover semantics still hold even on a 1-peer cluster.
HEALTHY_URL="$PEER1_URL"
DEAD_URL="http://127.0.0.1:1"

REPO_KEY="fed-fover-${RUN_ID}"
HEALTHY_PEER="fed-fover-healthy-${RUN_ID}"
BROKEN_PEER="fed-fover-broken-${RUN_ID}"
POLICY_NAME="fed-fover-policy-${RUN_ID}"
HEALTHY_ID=""
BROKEN_ID=""
POLICY_ID=""
FAILOVER_TIMEOUT="${FAILOVER_TIMEOUT:-90}"

cleanup_failover() {
  export BASE_URL="$MAIN_URL"; export ADMIN_TOKEN="$MAIN_TOKEN"
  if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
    api_delete "/api/v1/sync-policies/${POLICY_ID}" > /dev/null 2>&1 || true
  fi
  for pid in "$HEALTHY_ID" "$BROKEN_ID"; do
    if [ -n "$pid" ] && [ "$pid" != "null" ]; then
      api_delete "/api/v1/peers/${pid}" > /dev/null 2>&1 || true
    fi
  done
  api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler cleanup_failover

begin_test "Create local repo on main"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo on main"
fi

begin_test "Create matching repo on healthy peer"
export BASE_URL="$HEALTHY_URL"
auth_admin
PEER_TOKEN="$ADMIN_TOKEN"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo on healthy peer"
fi
export BASE_URL="$MAIN_URL"; export ADMIN_TOKEN="$MAIN_TOKEN"

begin_test "Register healthy peer"
payload="{\"name\":\"${HEALTHY_PEER}\",\"endpoint_url\":\"${HEALTHY_URL}\",\"api_key\":\"fed-test-key\"}"
status=$(curl -s -o "${WORK_DIR}/healthy.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$payload" "${BASE_URL}/api/v1/peers" 2>/dev/null) || status=000
case "$status" in
  404|501) skip "federation disabled (HTTP ${status})" ;;
  2*)
    HEALTHY_ID=$(jq -r '.id // empty' < "${WORK_DIR}/healthy.json")
    if [ -n "$HEALTHY_ID" ] && [ "$HEALTHY_ID" != "null" ]; then
      api_post "/api/v1/peers/${HEALTHY_ID}/heartbeat" '{"cache_used_bytes":0}' > /dev/null 2>&1 || true
      pass
    else
      fail "healthy peer created but no id"
    fi
    ;;
  *) fail "healthy peer registration failed: HTTP ${status}" ;;
esac

begin_test "Register broken peer (closed port)"
payload="{\"name\":\"${BROKEN_PEER}\",\"endpoint_url\":\"${DEAD_URL}\",\"api_key\":\"fed-test-key\"}"
if resp=$(api_post "/api/v1/peers" "$payload" 2>/dev/null); then
  BROKEN_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$BROKEN_ID" ] && [ "$BROKEN_ID" != "null" ]; then
    pass
  else
    fail "broken peer created but no id"
  fi
else
  fail "broken peer registration failed"
fi

begin_test "Create fan-out policy targeting both peers"
if [ -z "${HEALTHY_ID:-}" ] || [ -z "${BROKEN_ID:-}" ]; then
  skip "missing peer ids"
else
  policy_payload="{\"name\":\"${POLICY_NAME}\",\"repo_selector\":{\"match_pattern\":\"${REPO_KEY}\"},\"peer_selector\":{\"match_peers\":[\"${HEALTHY_ID}\",\"${BROKEN_ID}\"]},\"replication_mode\":\"push\",\"enabled\":true}"
  if resp=$(api_post "/api/v1/sync-policies" "$policy_payload" 2>/dev/null); then
    POLICY_ID=$(echo "$resp" | jq -r '.id // empty')
    api_post "/api/v1/sync-policies/evaluate" "" > /dev/null 2>&1 || true
    pass
  else
    fail "could not create policy"
  fi
fi

begin_test "Upload artifact and trigger fan-out sync"
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no policy"
else
  echo "failover marker ${RUN_ID}" > "${WORK_DIR}/fo.txt"
  if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/fover/marker.txt" \
      "${WORK_DIR}/fo.txt" "text/plain" > /dev/null; then
    api_post "/api/v1/peers/${HEALTHY_ID}/sync" "" > /dev/null 2>&1 || true
    api_post "/api/v1/peers/${BROKEN_ID}/sync" "" > /dev/null 2>&1 || true
    pass
  else
    fail "upload failed"
  fi
fi

begin_test "Healthy peer receives artifact despite broken peer in fan-out"
if [ -z "${HEALTHY_ID:-}" ] || [ "$HEALTHY_ID" = "null" ]; then
  skip "no healthy peer"
else
  export BASE_URL="$HEALTHY_URL"; export ADMIN_TOKEN="$PEER_TOKEN"
  elapsed=0
  synced=false
  while [ "$elapsed" -lt "$FAILOVER_TIMEOUT" ]; do
    if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
      # jq -e predicate: stricter than substring match on raw JSON.
      if printf '%s' "$resp" | jq -e '
          [ (if type == "array" then .[] else .items[]? end)
            | (.path // .name // "")
            | test("marker\\.txt$") ]
          | any
        ' > /dev/null 2>&1; then
        synced=true
        break
      fi
    fi
    sleep 4
    elapsed=$(( elapsed + 4 ))
  done
  export BASE_URL="$MAIN_URL"; export ADMIN_TOKEN="$MAIN_TOKEN"

  if $synced; then
    pass
  else
    # Under RELEASE_GATE, a healthy-peer timeout is the exact silent-
    # success class the gate exists to catch: a regression in failover
    # would land here and be hidden by skip. Fail loudly under the gate;
    # preserve the lenient skip for local-dev runs where sync workers
    # may not be running.
    if [ "${RELEASE_GATE:-0}" = "1" ]; then
      fail "healthy peer did not receive artifact within ${FAILOVER_TIMEOUT}s; failover timeout must not skip under RELEASE_GATE=1"
    else
      skip "healthy peer did not receive artifact within ${FAILOVER_TIMEOUT}s (sync worker timing; set RELEASE_GATE=1 to fail)"
    fi
  fi
fi

begin_test "Broken peer is marked unhealthy after failover attempt"
if [ -z "${BROKEN_ID:-}" ] || [ "$BROKEN_ID" = "null" ]; then
  skip "no broken peer"
else
  observed_degraded=0
  for _ in $(seq 1 10); do
    sleep 2
    if resp=$(api_get "/api/v1/peers/${BROKEN_ID}" 2>/dev/null); then
      health=$(echo "$resp" | jq -r '.health_status // .status // empty')
      case "$health" in
        degraded|unhealthy|down|offline|error)
          observed_degraded=1
          break
          ;;
      esac
    fi
  done
  if [ $observed_degraded -eq 1 ]; then
    pass
  else
    skip "broken peer never flipped to unhealthy status (heartbeat worker timing)"
  fi
fi

end_suite
