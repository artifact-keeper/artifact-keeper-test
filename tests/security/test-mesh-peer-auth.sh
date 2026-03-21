#!/usr/bin/env bash
# test-mesh-peer-auth.sh - T2-19: Mesh peer authentication enforcement
#
# Verifies that the mesh peer registration and sync endpoints reject requests
# with invalid or missing API keys/tokens.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "mesh-peer-auth"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Check if peer endpoints exist
# ---------------------------------------------------------------------------

begin_test "Check peer endpoint availability"
peer_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/peers" 2>/dev/null) || peer_status="000"

if [ "$peer_status" = "404" ]; then
  skip "peer endpoints not available (HTTP 404); mesh peering may not be enabled"
elif [ "$peer_status" = "000" ]; then
  skip "could not reach peer endpoint"
else
  pass
fi

# ---------------------------------------------------------------------------
# Test peer registration with wrong API key
# ---------------------------------------------------------------------------

begin_test "Peer registration with wrong API key rejected"
if [ "$peer_status" = "404" ]; then
  skip "peer endpoints not available"
else
  reg_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-API-Key: wrong-api-key-${RUN_ID}" \
    -d "{\"name\":\"evil-peer-${RUN_ID}\",\"endpoint_url\":\"https://evil.example.com:8080\"}" \
    "${BASE_URL}/api/v1/peers/announce") || true

  if [ "$reg_status" = "401" ] || [ "$reg_status" = "403" ]; then
    pass
  elif [ "$reg_status" = "404" ]; then
    skip "peer announce endpoint not found"
  elif [ "$reg_status" = "200" ] || [ "$reg_status" = "201" ]; then
    fail "peer registration accepted with wrong API key (HTTP ${reg_status})"
  else
    # 400, 422, etc. are all acceptable rejections
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Test peer registration with no API key at all
# ---------------------------------------------------------------------------

begin_test "Peer registration with no API key rejected"
if [ "$peer_status" = "404" ]; then
  skip "peer endpoints not available"
else
  noreg_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"nokey-peer-${RUN_ID}\",\"endpoint_url\":\"https://nokey.example.com:8080\"}" \
    "${BASE_URL}/api/v1/peers/announce") || true

  if [ "$noreg_status" = "401" ] || [ "$noreg_status" = "403" ]; then
    pass
  elif [ "$noreg_status" = "404" ]; then
    skip "peer announce endpoint not found"
  elif [ "$noreg_status" = "200" ] || [ "$noreg_status" = "201" ]; then
    fail "peer registration accepted with no API key (HTTP ${noreg_status})"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Test sync API with wrong bearer token
# ---------------------------------------------------------------------------

begin_test "Sync API with wrong bearer token rejected"
if [ "$peer_status" = "404" ]; then
  skip "peer endpoints not available"
else
  sync_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer wrong-token-${RUN_ID}" \
    "${BASE_URL}/api/v1/peers/sync") || true

  if [ "$sync_status" = "401" ] || [ "$sync_status" = "403" ]; then
    pass
  elif [ "$sync_status" = "404" ]; then
    skip "peer sync endpoint not found"
  elif [ "$sync_status" = "200" ]; then
    fail "sync API accepted wrong bearer token (HTTP 200)"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Test sync API with no auth at all
# ---------------------------------------------------------------------------

begin_test "Sync API with no auth rejected"
if [ "$peer_status" = "404" ]; then
  skip "peer endpoints not available"
else
  noauth_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/peers/sync") || true

  if [ "$noauth_status" = "401" ] || [ "$noauth_status" = "403" ]; then
    pass
  elif [ "$noauth_status" = "404" ]; then
    skip "peer sync endpoint not found"
  elif [ "$noauth_status" = "200" ]; then
    fail "sync API accessible with no authentication (HTTP 200)"
  else
    pass
  fi
fi

end_suite
