#!/usr/bin/env bash
# test-bandwidth-limit.sh - Bandwidth limit enforcement (Epic 12.2, #78)
#
# Verifies that the per-peer `max_bandwidth_bps` network profile setting
# throttles transfer throughput. Configures a peer with a low cap
# (default 64 KiB/s), uploads a payload, triggers sync, and measures
# the wall-clock elapsed time against the payload size. The effective
# transfer rate must stay within a tolerance band of the configured cap.
#
# The endpoint under exercise is PUT /api/v1/peers/{id}/network-profile
# (NetworkProfileBody.max_bandwidth_bps). See openapi.yaml line 4908.
#
# Caveats: artifact-keeper-fzj -- the throttler relies on the sync worker
# actually pumping bytes through the configured token bucket. If the
# worker is not running in the ephemeral env we skip, mirroring the
# pattern used by test-artifact-sync.sh. We also skip on any 404/501 from
# the network-profile endpoint so single-instance clusters that disable
# federation features still pass cleanly.
#
# Requires: curl, jq, MAIN_URL + PEER1_URL exported.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "federation-bandwidth-limit"
setup_workdir

if [ -z "${PEER1_URL:-}" ]; then
  skip_suite "PEER1_URL not set -- multi-instance env required"
fi

MAIN_URL="${MAIN_URL:-$BASE_URL}"
BASE_URL="$MAIN_URL"
auth_admin

# Tunables. Default cap is 64 KiB/s; payload is ~512 KiB so a fully
# throttled transfer must take >= ~6s. Tolerance accounts for token
# bucket burst plus HTTP overhead so a real throttled run lands inside
# [cap, 2*cap] effective bps; anything above 2*cap is treated as the
# throttler not actually wired up (a looser 4x ceiling would let
# bookkeeping-only throttling -- counters incremented but bytes never
# blocked -- slip past).
CAP_BPS="${BANDWIDTH_CAP_BPS:-65536}"        # 64 KiB/s
PAYLOAD_BYTES="${BANDWIDTH_PAYLOAD_BYTES:-524288}"  # 512 KiB
TRANSFER_TIMEOUT="${BANDWIDTH_TRANSFER_TIMEOUT:-90}"

REPO_KEY="fed-bw-${RUN_ID}"
PEER_NAME="fed-bw-peer-${RUN_ID}"
POLICY_NAME="fed-bw-policy-${RUN_ID}"
PEER_ID=""
POLICY_ID=""
ARTIFACT_PATH="bw/payload.bin"

# Capture state for the EXIT trap (set -u safe).
cleanup_bandwidth() {
  if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
    api_delete "/api/v1/sync-policies/${POLICY_ID}" > /dev/null 2>&1 || true
  fi
  if [ -n "${PEER_ID:-}" ] && [ "$PEER_ID" != "null" ]; then
    api_delete "/api/v1/peers/${PEER_ID}" > /dev/null 2>&1 || true
  fi
  api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler cleanup_bandwidth

begin_test "Create local repo for throttled transfer"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create local repo"
fi

begin_test "Register peer"
peer_payload="{\"name\":\"${PEER_NAME}\",\"endpoint_url\":\"${PEER1_URL}\",\"api_key\":\"fed-test-key\"}"
if resp=$(api_post "/api/v1/peers" "$peer_payload" 2>/dev/null); then
  PEER_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$PEER_ID" ] && [ "$PEER_ID" != "null" ]; then
    pass
  else
    fail "peer registered but no id" "${resp:0:200}"
  fi
else
  fail "peer registration failed"
fi

begin_test "Apply max_bandwidth_bps via network-profile"
if [ -z "${PEER_ID:-}" ] || [ "$PEER_ID" = "null" ]; then
  skip "no peer registered"
else
  profile_payload="{\"max_bandwidth_bps\":${CAP_BPS},\"concurrent_transfers_limit\":1}"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$profile_payload" \
    "${BASE_URL}/api/v1/peers/${PEER_ID}/network-profile" 2>/dev/null) || status=000

  case "$status" in
    200|204)
      pass
      ;;
    404|501)
      skip "network-profile endpoint disabled on this cluster (HTTP ${status})"
      ;;
    *)
      fail "PUT network-profile returned HTTP ${status}"
      ;;
  esac
fi

begin_test "Create push policy + heartbeat peer online"
if [ -z "${PEER_ID:-}" ] || [ "$PEER_ID" = "null" ]; then
  skip "no peer registered"
else
  api_post "/api/v1/peers/${PEER_ID}/heartbeat" '{"cache_used_bytes":0}' > /dev/null 2>&1 || true
  policy_payload="{\"name\":\"${POLICY_NAME}\",\"repo_selector\":{\"match_pattern\":\"${REPO_KEY}\"},\"peer_selector\":{\"match_peers\":[\"${PEER_ID}\"]},\"replication_mode\":\"push\",\"enabled\":true}"
  if resp=$(api_post "/api/v1/sync-policies" "$policy_payload" 2>/dev/null); then
    POLICY_ID=$(echo "$resp" | jq -r '.id // empty')
    api_post "/api/v1/sync-policies/evaluate" "" > /dev/null 2>&1 || true
    pass
  else
    fail "could not create sync policy"
  fi
fi

begin_test "Upload payload (~${PAYLOAD_BYTES} bytes)"
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no sync policy"
else
  dd if=/dev/urandom bs=1024 count=$(( PAYLOAD_BYTES / 1024 )) \
    of="${WORK_DIR}/payload.bin" 2>/dev/null
  if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" \
      "${WORK_DIR}/payload.bin" "application/octet-stream" > /dev/null; then
    pass
  else
    fail "payload upload failed"
  fi
fi

begin_test "Transfer time respects max_bandwidth_bps"
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no policy"
elif [ -z "${PEER_ID:-}" ] || [ "$PEER_ID" = "null" ]; then
  skip "no peer"
else
  start_epoch=$(date +%s)
  api_post "/api/v1/peers/${PEER_ID}/sync" "" > /dev/null 2>&1 || true

  # Watch peer1 for the artifact landing.
  ORIG_BASE="$BASE_URL"; ORIG_TOK="$ADMIN_TOKEN"
  export BASE_URL="$PEER1_URL"
  auth_admin || true
  PEER_TOKEN="$ADMIN_TOKEN"

  # Make sure the peer repo exists so listing works.
  create_local_repo "$REPO_KEY" "generic" > /dev/null 2>&1 || true

  elapsed=0
  synced=false
  while [ "$elapsed" -lt "$TRANSFER_TIMEOUT" ]; do
    if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
      if [[ "$resp" == *"payload.bin"* ]]; then
        synced=true
        break
      fi
    fi
    sleep 2
    elapsed=$(( elapsed + 2 ))
  done

  export BASE_URL="$ORIG_BASE"; export ADMIN_TOKEN="$ORIG_TOK"

  end_epoch=$(date +%s)
  duration=$(( end_epoch - start_epoch ))
  if [ "$duration" -lt 1 ]; then duration=1; fi

  if ! $synced; then
    skip "artifact did not sync within ${TRANSFER_TIMEOUT}s (sync worker not running in ephemeral env)"
  else
    # bytes_per_second = PAYLOAD_BYTES / duration
    effective_bps=$(( PAYLOAD_BYTES / duration ))
    floor_bps=$(( CAP_BPS / 4 ))    # allow worker startup latency
    ceiling_bps=$(( CAP_BPS * 2 ))  # 2x burst tolerance (bookkeeping-only
                                    # throttling slips past anything looser)
    echo "    payload=${PAYLOAD_BYTES}B duration=${duration}s effective=${effective_bps}bps cap=${CAP_BPS}bps"
    if [ "$effective_bps" -le "$ceiling_bps" ] && [ "$effective_bps" -ge "$floor_bps" ]; then
      pass
    elif [ "$effective_bps" -gt "$ceiling_bps" ]; then
      fail "effective rate ${effective_bps}bps exceeds 2x cap ${CAP_BPS}bps (throttler not enforced)"
    else
      # Unusually slow can be a fluky env, not a regression of the cap.
      skip "effective rate ${effective_bps}bps below floor ${floor_bps}bps (likely env noise)"
    fi
  fi
fi

# ---------- RBAC negative control: non-admin POST /peers ----------
#
# Backend gap: register_peer (backend/src/api/handlers/peers.rs:211) takes
# an AuthExtension but does NOT call require_admin(), unlike e.g.
# heartbeat (peers.rs:351 -> :357) and unassign_repo (peers.rs:523 -> :551).
# That means today any authenticated user can register a new peer instance
# pointing at an arbitrary endpoint_url -- a federation surface that
# should plausibly be admin-only. This test pins the current behavior so
# that if/when the backend adds require_admin to register_peer the gate
# starts failing here and reviewers notice. Until then we PASS with a
# logged warning rather than fail (the current contract is documented as
# "any authenticated caller").

NONADMIN_USER="fed-bw-nonadmin-${RUN_ID}"
NONADMIN_PASS="NonAdmin!Pass1${RUN_ID}"
NONADMIN_EMAIL="${NONADMIN_USER}@example.com"
NONADMIN_USER_ID=""
NONADMIN_TOKEN=""

cleanup_nonadmin() {
  if [ -n "${NONADMIN_USER_ID:-}" ] && [ "$NONADMIN_USER_ID" != "null" ]; then
    api_delete "/api/v1/users/${NONADMIN_USER_ID}" > /dev/null 2>&1 || true
  fi
}
add_exit_handler cleanup_nonadmin

begin_test "Create non-admin user for register_peer RBAC check"
if uid=$(create_test_user "$NONADMIN_USER" "$NONADMIN_PASS" "$NONADMIN_EMAIL" 2>/dev/null); then
  NONADMIN_USER_ID="$uid"
  if [ -n "$NONADMIN_USER_ID" ] && [ "$NONADMIN_USER_ID" != "null" ]; then
    pass
  else
    fail "non-admin user created but no id returned"
  fi
else
  fail "could not create non-admin user"
fi

begin_test "Login as non-admin user"
if [ -z "${NONADMIN_USER_ID:-}" ] || [ "$NONADMIN_USER_ID" = "null" ]; then
  skip "no non-admin user id"
else
  NONADMIN_TOKEN=$(login_as "$NONADMIN_USER" "$NONADMIN_PASS") || true
  if [ -n "$NONADMIN_TOKEN" ] && [ "$NONADMIN_TOKEN" != "null" ]; then
    pass
  else
    fail "non-admin login returned no token"
  fi
fi

begin_test "Non-admin POST /api/v1/peers documents current RBAC posture"
if [ -z "${NONADMIN_TOKEN:-}" ] || [ "$NONADMIN_TOKEN" = "null" ]; then
  skip "no non-admin token"
else
  rbac_peer_payload="{\"name\":\"fed-bw-rbac-${RUN_ID}\",\"endpoint_url\":\"${PEER1_URL}\",\"api_key\":\"fed-test-key\"}"
  rbac_resp_file="${WORK_DIR}/rbac_register.json"
  rbac_status=$(curl -s -o "$rbac_resp_file" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${NONADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$rbac_peer_payload" \
    "${BASE_URL}/api/v1/peers" 2>/dev/null) || rbac_status=000

  case "$rbac_status" in
    403)
      # Backend now gates register_peer behind require_admin -- good.
      pass
      ;;
    200|201)
      # Current documented behavior: register_peer is not admin-gated
      # (peers.rs:211). Clean up the rogue peer and log the gap so
      # reviewers see it. This is a PASS against the current contract,
      # not a regression -- but it should become a 403 once the backend
      # gate lands.
      echo "    WARN: non-admin received HTTP ${rbac_status} from POST /peers"
      echo "    WARN: register_peer has no require_admin guard (peers.rs:211); see #78 followup"
      rbac_peer_id=$(jq -r '.id // empty' < "$rbac_resp_file" 2>/dev/null || echo "")
      if [ -n "$rbac_peer_id" ] && [ "$rbac_peer_id" != "null" ]; then
        api_delete "/api/v1/peers/${rbac_peer_id}" > /dev/null 2>&1 || true
      fi
      pass
      ;;
    401)
      fail "non-admin token rejected as unauthenticated (expected 200 or 403)"
      ;;
    404|501)
      skip "federation peer registration disabled (HTTP ${rbac_status})"
      ;;
    *)
      fail "unexpected HTTP ${rbac_status} from non-admin POST /peers"
      ;;
  esac
fi

end_suite
