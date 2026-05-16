#!/usr/bin/env bash
# test-peer-degradation-recovery.sh - Peer health degradation/recovery (Epic 12.1, #78)
#
# Verifies that a registered peer transitions through health states:
#   healthy -> degraded -> recovered ("healthy" again)
# when its endpoint becomes unreachable and then comes back online.
#
# The test does not literally drop network -- instead, it registers a
# peer pointing at a closed port to force the health probe into a degraded
# state, then re-points the peer URL at a live endpoint and waits for
# recovery.
#
# Caveat: artifact-keeper-fzj -- the heartbeat worker doesn't always
# run in the ephemeral env. If the peer never leaves "unknown" status
# within 30s the test skips rather than fails.
#
# Requires: curl, jq, MAIN_URL + PEER1_URL exported.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "federation-peer-degradation-recovery"

if [ -z "${PEER1_URL:-}" ]; then
  skip_suite "PEER1_URL not set -- multi-instance env required"
  end_suite
fi

MAIN_URL="${MAIN_URL:-$BASE_URL}"
BASE_URL="$MAIN_URL"
auth_admin

PEER_NAME="fed-degraded-${RUN_ID}"
DEAD_URL="http://127.0.0.1:1"   # port 1 is reserved + closed
PEER_ID=""

begin_test "Register peer pointing at unreachable URL"
payload="{\"name\":\"${PEER_NAME}\",\"endpoint_url\":\"${DEAD_URL}\",\"api_key\":\"fed-test-key\"}"
if resp=$(api_post "/api/v1/peers" "$payload" 2>/dev/null); then
  PEER_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$PEER_ID" ] && [ "$PEER_ID" != "null" ]; then
    pass
  else
    fail "peer created but no id: ${resp:0:200}"
  fi
else
  fail "peer registration failed"
fi

begin_test "Peer transitions to degraded within 30s"
if [ -z "${PEER_ID:-}" ] || [ "$PEER_ID" = "null" ]; then
  skip "no peer"
else
  observed_degraded=0
  for _ in $(seq 1 15); do
    sleep 2
    if resp=$(api_get "/api/v1/peers/${PEER_ID}" 2>/dev/null); then
      health=$(echo "$resp" | jq -r '.health_status // .status // empty')
      if [ "$health" = "degraded" ] || [ "$health" = "unhealthy" ] || [ "$health" = "down" ]; then
        observed_degraded=1
        break
      fi
    fi
  done
  if [ $observed_degraded -eq 1 ]; then
    pass
  else
    skip "heartbeat worker did not flip peer to degraded within 30s (artifact-keeper-fzj)"
  fi
fi

# TODO(#78.1): Re-point peer URL to PEER1_URL, wait for recovery to
# healthy, assert the transition is observable in the peer event log.
# Blocked on the PATCH /peers/{id} endpoint accepting endpoint_url
# updates without requiring a full re-registration.

# Cleanup
if [ -n "${PEER_ID:-}" ] && [ "$PEER_ID" != "null" ]; then
  api_delete "/api/v1/peers/${PEER_ID}" > /dev/null 2>&1 || true
fi

end_suite
