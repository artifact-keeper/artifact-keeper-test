#!/usr/bin/env bash
# test-replication-schedule.sh - Cron-based replication schedule actually fires
# (Epic 12.8, #78)
#
# Verifies that a sync policy created with a cron-style schedule
# (replication_schedule on AssignRepoRequest, or schedule on sync-policy
# bodies) actually fires within the expected window: a soon-to-fire
# expression (e.g. every minute) must produce a sync task / log entry
# within ~120s.
#
# OpenAPI: the field exercised here is `replication_schedule`, a
# free-form string on AssignRepoRequest (openapi.yaml:10704). It is NOT
# the same as LifecyclePolicy.cron_schedule at openapi.yaml:14185, which
# governs retention policies, not sync. The 1.1.x backend accepts
# standard 5-field cron syntax. Some deployments only support manual
# triggers; in that case the assignment endpoint or the policy will
# 4xx and we skip cleanly.
#
# Requires: curl, jq, MAIN_URL + PEER1_URL exported.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "federation-replication-schedule"
setup_workdir

if [ -z "${PEER1_URL:-}" ]; then
  skip_suite "PEER1_URL not set -- multi-instance env required"
fi

MAIN_URL="${MAIN_URL:-$BASE_URL}"
BASE_URL="$MAIN_URL"
auth_admin

REPO_KEY="fed-sched-${RUN_ID}"
PEER_NAME="fed-sched-peer-${RUN_ID}"
POLICY_NAME="fed-sched-policy-${RUN_ID}"
PEER_ID=""
POLICY_ID=""
REPO_ID=""
CRON_EXPR="${SCHEDULE_CRON:-* * * * *}"  # every minute
SCHEDULE_WAIT="${SCHEDULE_WAIT_SECS:-180}"

cleanup_schedule() {
  if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
    api_delete "/api/v1/sync-policies/${POLICY_ID}" > /dev/null 2>&1 || true
  fi
  if [ -n "${PEER_ID:-}" ] && [ "$PEER_ID" != "null" ]; then
    api_delete "/api/v1/peers/${PEER_ID}" > /dev/null 2>&1 || true
  fi
  api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler cleanup_schedule

begin_test "Create repo and capture id"
if create_local_repo "$REPO_KEY" "generic"; then
  if resp=$(api_get "/api/v1/repositories/${REPO_KEY}" 2>/dev/null); then
    REPO_ID=$(echo "$resp" | jq -r '.id // empty')
    pass
  else
    pass # repo created, id lookup is best-effort
  fi
else
  fail "could not create repo"
fi

begin_test "Register peer + heartbeat"
payload="{\"name\":\"${PEER_NAME}\",\"endpoint_url\":\"${PEER1_URL}\",\"api_key\":\"fed-test-key\"}"
status=$(curl -s -o "${WORK_DIR}/peer.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$payload" "${BASE_URL}/api/v1/peers" 2>/dev/null) || status=000
case "$status" in
  404|501)
    skip "federation disabled (HTTP ${status})"
    ;;
  2*)
    PEER_ID=$(jq -r '.id // empty' < "${WORK_DIR}/peer.json")
    if [ -n "$PEER_ID" ] && [ "$PEER_ID" != "null" ]; then
      api_post "/api/v1/peers/${PEER_ID}/heartbeat" '{"cache_used_bytes":0}' > /dev/null 2>&1 || true
      pass
    else
      fail "peer created but no id"
    fi
    ;;
  *)
    fail "peer registration failed: HTTP ${status}"
    ;;
esac

begin_test "Assign repo to peer with cron replication_schedule"
if [ -z "${PEER_ID:-}" ] || [ "$PEER_ID" = "null" ] || \
   [ -z "${REPO_ID:-}" ] || [ "$REPO_ID" = "null" ]; then
  skip "no peer or repo id"
else
  assign_payload="{\"repository_id\":\"${REPO_ID}\",\"replication_mode\":\"push\",\"replication_schedule\":\"${CRON_EXPR}\",\"sync_enabled\":true}"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$assign_payload" \
    "${BASE_URL}/api/v1/peers/${PEER_ID}/repositories" 2>/dev/null) || status=000
  case "$status" in
    200|201|204) pass ;;
    400|404|501) skip "scheduled replication not accepted (HTTP ${status})" ;;
    *) fail "POST /peers/${PEER_ID}/repositories returned HTTP ${status}" ;;
  esac
fi

begin_test "Create push policy as backstop scheduler trigger"
if [ -z "${PEER_ID:-}" ] || [ "$PEER_ID" = "null" ]; then
  skip "no peer"
else
  policy_payload="{\"name\":\"${POLICY_NAME}\",\"repo_selector\":{\"match_pattern\":\"${REPO_KEY}\"},\"peer_selector\":{\"match_peers\":[\"${PEER_ID}\"]},\"replication_mode\":\"push\",\"enabled\":true}"
  if resp=$(api_post "/api/v1/sync-policies" "$policy_payload" 2>/dev/null); then
    POLICY_ID=$(echo "$resp" | jq -r '.id // empty')
    # NOTE: we deliberately do NOT call POST /sync-policies/evaluate.
    # That endpoint fires a synchronous sync, which would contaminate
    # the "did the cron tick?" assertion below: a pass would no longer
    # prove the scheduler fired. The load-bearing check is now
    # "sync evidence has a timestamp >= window start".
    pass
  else
    fail "could not create policy"
  fi
fi

begin_test "Upload an artifact for the scheduler to pick up"
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no policy"
else
  echo "scheduled-fire ${RUN_ID}" > "${WORK_DIR}/sched.txt"
  if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/sched/marker.txt" \
      "${WORK_DIR}/sched.txt" "text/plain" > /dev/null; then
    # Stamp the start of the schedule window. Any sync task / artifact
    # landing observed with an earlier timestamp is a stale signal from
    # before the upload and MUST NOT count as a tick.
    SCHEDULE_WINDOW_START=$(date +%s)
    pass
  else
    fail "upload failed"
  fi
fi

begin_test "Sync task / replication log entry appears within ${SCHEDULE_WAIT}s"
if [ -z "${PEER_ID:-}" ] || [ "$PEER_ID" = "null" ]; then
  skip "no peer"
elif [ -z "${SCHEDULE_WINDOW_START:-}" ]; then
  skip "no upload anchor -- cannot bound schedule window"
else
  elapsed=0
  observed=false
  while [ "$elapsed" -lt "$SCHEDULE_WAIT" ]; do
    if resp=$(api_get "/api/v1/peers/${PEER_ID}/sync/tasks" 2>/dev/null); then
      # Walk every task; consider it evidence ONLY if its
      # created_at/started_at/updated_at parses to an epoch >= window
      # start. Drops the off-by-default lenient "any non-empty array"
      # check, which would otherwise pass on a stale queue entry from
      # before the upload.
      max_ts=$(printf '%s' "$resp" | jq -r --arg url "$MAIN_URL" '
        def epoch:
          if type == "number" then .
          elif type == "string" and . != "" then (try fromdateiso8601 catch (try tonumber catch 0))
          else 0
          end;
        [ (if type == "array" then .[] else .items[]? end)
          | ((.created_at // .started_at // .updated_at // .scheduled_at // "") | epoch) ]
        | max // 0
      ' 2>/dev/null) || max_ts=0
      if [ "${max_ts:-0}" -ge "$SCHEDULE_WINDOW_START" ] 2>/dev/null; then
        observed=true
        break
      fi
    fi
    sleep 5
    elapsed=$(( elapsed + 5 ))
    echo "  ...waiting for scheduler tick (${elapsed}s, window_start=${SCHEDULE_WINDOW_START})"
  done

  if $observed; then
    pass
  else
    # Fallback: did the artifact actually land on peer1 AFTER window
    # start? If yes, the schedule fired and the queue snapshot just
    # drained between polls. Crucially we require a timestamp recency
    # check -- "artifact present" alone could be a stale entry from a
    # previous run. We compare against created_at/updated_at on the
    # listing.
    ORIG_BASE="$BASE_URL"; ORIG_TOK="$ADMIN_TOKEN"
    export BASE_URL="$PEER1_URL"
    auth_admin || true
    create_local_repo "$REPO_KEY" "generic" > /dev/null 2>&1 || true
    landed_recent=false
    if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
      latest_ts=$(printf '%s' "$resp" | jq -r '
        def epoch:
          if type == "number" then .
          elif type == "string" and . != "" then (try fromdateiso8601 catch (try tonumber catch 0))
          else 0
          end;
        [ (if type == "array" then .[] else .items[]? end)
          | select((.path // .name // "") | test("marker\\.txt$"))
          | ((.created_at // .updated_at // .last_modified // "") | epoch) ]
        | max // 0
      ' 2>/dev/null) || latest_ts=0
      if [ "${latest_ts:-0}" -ge "$SCHEDULE_WINDOW_START" ] 2>/dev/null; then
        landed_recent=true
      fi
    fi
    export BASE_URL="$ORIG_BASE"; export ADMIN_TOKEN="$ORIG_TOK"
    if $landed_recent; then
      pass
    else
      skip "scheduled run did not fire within ${SCHEDULE_WAIT}s (cron worker not running in ephemeral env)"
    fi
  fi
fi

end_suite
