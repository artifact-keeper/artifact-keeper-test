#!/usr/bin/env bash
# test-peer-registration.sh - Mesh peer registration E2E test
#
# Verifies that mesh instances can register peers and that
# registration is reflected in the peer list.
#
# Requires: MAIN_URL, PEER1_URL, PEER2_URL, PEER3_URL

source "$(dirname "$0")/../lib/common.sh"

begin_suite "mesh-peer-registration"
setup_workdir

MAIN_URL="${MAIN_URL:?MAIN_URL must be set}"
PEER1_URL="${PEER1_URL:?PEER1_URL must be set}"
PEER2_URL="${PEER2_URL:?PEER2_URL must be set}"
PEER3_URL="${PEER3_URL:?PEER3_URL must be set}"

# Auth against the main instance
auth_admin

# ---------------------------------------------------------------------------
# Register peers on the main instance
# ---------------------------------------------------------------------------

begin_test "Register peer1 on main instance"
PEER1_PAYLOAD="{\"name\":\"peer1-${RUN_ID}\",\"endpoint_url\":\"${PEER1_URL}\",\"api_key\":\"mesh-test-key\"}"
if resp=$(api_post "/api/v1/peers" "$PEER1_PAYLOAD"); then
  if assert_contains "$resp" "peer1" "response should contain peer name"; then
    pass
  fi
else
  fail "POST /api/v1/peers failed for peer1"
fi

begin_test "Register peer2 on main instance"
PEER2_PAYLOAD="{\"name\":\"peer2-${RUN_ID}\",\"endpoint_url\":\"${PEER2_URL}\",\"api_key\":\"mesh-test-key\"}"
if resp=$(api_post "/api/v1/peers" "$PEER2_PAYLOAD"); then
  if assert_contains "$resp" "peer2" "response should contain peer name"; then
    pass
  fi
else
  fail "POST /api/v1/peers failed for peer2"
fi

begin_test "Register peer3 on main instance"
PEER3_PAYLOAD="{\"name\":\"peer3-${RUN_ID}\",\"endpoint_url\":\"${PEER3_URL}\",\"api_key\":\"mesh-test-key\"}"
if resp=$(api_post "/api/v1/peers" "$PEER3_PAYLOAD"); then
  if assert_contains "$resp" "peer3" "response should contain peer name"; then
    pass
  fi
else
  fail "POST /api/v1/peers failed for peer3"
fi

# ---------------------------------------------------------------------------
# Verify peer list
# ---------------------------------------------------------------------------

begin_test "List peers on main instance"
if resp=$(api_get "/api/v1/peers"); then
  if assert_contains "$resp" "peer1" "peer list should contain peer1" && \
     assert_contains "$resp" "peer2" "peer list should contain peer2" && \
     assert_contains "$resp" "peer3" "peer list should contain peer3"; then
    pass
  fi
else
  fail "GET /api/v1/peers failed"
fi

# ---------------------------------------------------------------------------
# Verify peer details
# ---------------------------------------------------------------------------

begin_test "Get peer1 details"
# Extract peer1 ID from list
PEER1_ID=$(echo "$resp" | jq -r '.[] | select(.name | contains("peer1")) | .id // empty' 2>/dev/null || true)
if [ -z "$PEER1_ID" ]; then
  PEER1_ID=$(echo "$resp" | jq -r '.items[]? | select(.name | contains("peer1")) | .id // empty' 2>/dev/null || true)
fi

if [ -n "$PEER1_ID" ]; then
  if detail=$(api_get "/api/v1/peers/${PEER1_ID}"); then
    if assert_contains "$detail" "$PEER1_URL" "peer detail should contain URL"; then
      pass
    fi
  else
    fail "GET /api/v1/peers/${PEER1_ID} failed"
  fi
else
  skip "could not extract peer1 ID from response"
fi

# ---------------------------------------------------------------------------
# Verify bidirectional registration
# ---------------------------------------------------------------------------

begin_test "Register main as peer on peer1"
# Auth against peer1
ORIG_BASE_URL="$BASE_URL"
ORIG_TOKEN="$ADMIN_TOKEN"
export BASE_URL="$PEER1_URL"
auth_admin

MAIN_PAYLOAD="{\"name\":\"main-${RUN_ID}\",\"endpoint_url\":\"${ORIG_BASE_URL}\",\"api_key\":\"mesh-test-key\"}"
if resp=$(api_post "/api/v1/peers" "$MAIN_PAYLOAD"); then
  if assert_contains "$resp" "main" "response should contain main peer name"; then
    pass
  fi
else
  fail "failed to register main instance as peer on peer1"
fi

# Restore main context
export BASE_URL="$ORIG_BASE_URL"
export ADMIN_TOKEN="$ORIG_TOKEN"

end_suite
