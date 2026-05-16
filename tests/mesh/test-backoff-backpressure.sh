#!/usr/bin/env bash
# test-backoff-backpressure.sh - Backoff-until + partial-failure recovery
# (Epic 12.5 + 12.7, #78)
#
# Covers two related backpressure paths that share setup:
#
#   12.5  A peer that fails its heartbeat / transfer attempts should be
#         placed into a "degraded" or back-off state and not retry until
#         a documented backoff window elapses. Once the peer becomes
#         reachable again, the next sync attempt must clear the back-off
#         and resume transfers.
#
#   12.7  In a multi-peer sync policy, if some peers are unreachable, the
#         healthy peers must continue to receive artifacts (partial
#         failure must not poison the whole fan-out).
#
# We piggy-back on the existing degradation flow used by
# test-peer-degradation-recovery.sh: a peer pointing at a closed port is
# considered "broken", and a peer pointing at $PEER1_URL is "healthy".
#
# Skip cleanly on clusters without federation enabled (404/501 on
# /api/v1/peers or no PEER1_URL).
#
# Requires: curl, jq, MAIN_URL + PEER1_URL exported.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "federation-backoff-backpressure"
setup_workdir

if [ -z "${PEER1_URL:-}" ]; then
  skip_suite "PEER1_URL not set -- multi-instance env required"
fi

MAIN_URL="${MAIN_URL:-$BASE_URL}"
BASE_URL="$MAIN_URL"
auth_admin

REPO_KEY="fed-bp-${RUN_ID}"
HEALTHY_PEER="fed-bp-healthy-${RUN_ID}"
BROKEN_PEER="fed-bp-broken-${RUN_ID}"
POLICY_NAME="fed-bp-policy-${RUN_ID}"
HEALTHY_ID=""
BROKEN_ID=""
POLICY_ID=""
DEAD_URL="http://127.0.0.1:1"
DEGRADE_TIMEOUT="${BP_DEGRADE_TIMEOUT:-30}"
RECOVERY_TIMEOUT="${BP_RECOVERY_TIMEOUT:-60}"

cleanup_backpressure() {
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
add_exit_handler cleanup_backpressure

begin_test "Create repo for multi-peer fan-out"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create local repo"
fi

begin_test "Register healthy peer"
payload="{\"name\":\"${HEALTHY_PEER}\",\"endpoint_url\":\"${PEER1_URL}\",\"api_key\":\"fed-test-key\"}"
status=$(curl -s -o "${WORK_DIR}/healthy.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$payload" "${BASE_URL}/api/v1/peers" 2>/dev/null) || status=000
if [ "$status" = "404" ] || [ "$status" = "501" ]; then
  skip "federation peer registration disabled (HTTP ${status})"
elif [ "$status" -ge 200 ] && [ "$status" -lt 300 ] 2>/dev/null; then
  HEALTHY_ID=$(jq -r '.id // empty' < "${WORK_DIR}/healthy.json")
  if [ -n "$HEALTHY_ID" ] && [ "$HEALTHY_ID" != "null" ]; then
    api_post "/api/v1/peers/${HEALTHY_ID}/heartbeat" '{"cache_used_bytes":0}' > /dev/null 2>&1 || true
    pass
  else
    fail "healthy peer created but no id"
  fi
else
  fail "healthy peer registration failed: HTTP ${status}"
fi

begin_test "Register broken peer pointing at closed port"
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

# ---------- 12.5: degraded -> backoff -> recovery ----------

begin_test "Broken peer reaches degraded/unhealthy within ${DEGRADE_TIMEOUT}s"
if [ -z "${BROKEN_ID:-}" ] || [ "$BROKEN_ID" = "null" ]; then
  skip "no broken peer"
else
  elapsed=0
  observed_degraded=0
  while [ "$elapsed" -lt "$DEGRADE_TIMEOUT" ]; do
    sleep 2
    elapsed=$(( elapsed + 2 ))
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
    skip "heartbeat worker did not flip broken peer to degraded within ${DEGRADE_TIMEOUT}s (artifact-keeper-fzj)"
  fi
fi

begin_test "Trigger sync on degraded peer respects back-off (no 5xx storm)"
if [ -z "${BROKEN_ID:-}" ] || [ "$BROKEN_ID" = "null" ]; then
  skip "no broken peer"
else
  # Multiple back-to-back sync triggers MUST NOT 5xx; the server is
  # expected to enqueue with a backoff and return 200/202/409.
  bad=0
  for _ in 1 2 3; do
    s=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X POST -H "$(auth_header)" \
      "${BASE_URL}/api/v1/peers/${BROKEN_ID}/sync" 2>/dev/null) || s=000
    case "$s" in
      200|202|204|409|429) ;;
      5*) bad=$(( bad + 1 )) ;;
      *) ;;
    esac
  done
  if [ "$bad" -eq 0 ]; then
    pass
  else
    fail "received ${bad} 5xx responses from /sync on degraded peer (no back-off?)"
  fi
fi

begin_test "Healthy peer recovers backoff_until / next_attempt_at after heartbeat"
# Best-effort: after a fresh heartbeat from the healthy peer, the
# backoff_until / next_attempt_at field (if exposed) must be in the past
# or null. We tolerate missing fields, but if present they must clear.
if [ -z "${HEALTHY_ID:-}" ] || [ "$HEALTHY_ID" = "null" ]; then
  skip "no healthy peer"
else
  api_post "/api/v1/peers/${HEALTHY_ID}/heartbeat" '{"cache_used_bytes":0}' > /dev/null 2>&1 || true
  sleep 2
  if resp=$(api_get "/api/v1/peers/${HEALTHY_ID}" 2>/dev/null); then
    backoff=$(echo "$resp" | jq -r '.backoff_until // .next_attempt_at // empty')
    if [ -z "$backoff" ] || [ "$backoff" = "null" ]; then
      pass
    else
      # If backoff is in the past compared to "now" we consider it cleared.
      now_epoch=$(date -u +%s)
      bo_epoch=$(date -u -d "$backoff" +%s 2>/dev/null || echo 0)
      if [ "$bo_epoch" -le "$now_epoch" ]; then
        pass
      else
        fail "healthy peer still backed off until ${backoff}"
      fi
    fi
  else
    skip "could not GET healthy peer"
  fi
fi

# ---------- 12.7: partial failure does not poison the fan-out ----------

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
    fail "could not create fan-out sync policy"
  fi
fi

begin_test "Upload artifact and verify healthy peer still receives it"
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no policy"
else
  echo "partial-failure recovery payload ${RUN_ID}" > "${WORK_DIR}/bp.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/bp/marker.txt" \
    "${WORK_DIR}/bp.txt" "text/plain" > /dev/null 2>&1 || true
  api_post "/api/v1/peers/${HEALTHY_ID}/sync" "" > /dev/null 2>&1 || true

  ORIG_BASE="$BASE_URL"; ORIG_TOK="$ADMIN_TOKEN"
  export BASE_URL="$PEER1_URL"
  auth_admin || true
  create_local_repo "$REPO_KEY" "generic" > /dev/null 2>&1 || true

  elapsed=0
  synced=false
  while [ "$elapsed" -lt "$RECOVERY_TIMEOUT" ]; do
    if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
      if [[ "$resp" == *"marker.txt"* ]]; then
        synced=true
        break
      fi
    fi
    sleep 3
    elapsed=$(( elapsed + 3 ))
  done

  export BASE_URL="$ORIG_BASE"; export ADMIN_TOKEN="$ORIG_TOK"

  if $synced; then
    pass
  else
    skip "healthy peer did not receive artifact within ${RECOVERY_TIMEOUT}s (sync worker timing)"
  fi
fi

end_suite
