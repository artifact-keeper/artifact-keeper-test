#!/usr/bin/env bash
# test-secret-field-exposure.sh - authenticated API projections do not return
# the secrets they store
#
# Ported from tests/security/redteam/test-14-api-key-exposure.sh, which could
# not fail: it sourced tests/security/redteam/lib.sh (fail() only incremented
# an unread counter) and ended in `exit 0`. See
# tests/security/README-redteam-port.md.
#
# The two assertions are regression guards for real leaks found by dynamic
# scanning: GET /api/v1/peers returned the inter-node api_key in plaintext,
# and the user projection is the natural place for a password hash or TOTP
# secret to reappear. Neither invariant is asserted anywhere else in this repo
# (`grep -rl 'password_hash\|totp_secret' tests/` returns only this file and a
# comment in tests/admin/test-user-password-ops.sh).
#
# Change from the original beyond the framework wiring
# ----------------------------------------------------
# The peer check ran against whatever peers happened to be registered. The
# bootstrap peer (`artifact-keeper-local`) carries no api_key, so on a fresh
# instance the jq filter matched nothing and the assertion passed without a
# secret ever having been stored. This version registers its own peer with a
# known api_key and then greps the listing for that exact string, so the
# assertion is about a secret the instance is definitely holding.
#
# This is an AUTHENTICATED read: an admin is allowed to know that a peer has a
# key. What is not acceptable is the key material itself crossing the API
# boundary, because the peers listing is readable by every admin-scoped token
# and lands in browser caches, HAR files and support bundles.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "secret-field-exposure"
auth_admin
setup_workdir

PEER_NAME="sec-secretleak-peer-${RUN_ID}"
PEER_KEY="secretleak-apikey-${RUN_ID}"
PEER_ID=""

cleanup_peer() {
  if [ -n "$PEER_ID" ]; then
    curl -s -o /dev/null "${CURL_TIMEOUT_ARGS[@]}" -X DELETE \
      -H "$(auth_header)" "${BASE_URL}/api/v1/peers/${PEER_ID}" >/dev/null 2>&1 || true
  fi
}
add_exit_handler "cleanup_peer"

# ---------------------------------------------------------------------------
# Peer api_key
# ---------------------------------------------------------------------------

begin_test "Register a peer holding a known api_key"
status=$(curl -s -o "${WORK_DIR}/peer-create.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "{\"name\":\"${PEER_NAME}\",\"endpoint_url\":\"https://peer-${RUN_ID}.example.com\",\"api_key\":\"${PEER_KEY}\"}" \
  "${BASE_URL}/api/v1/peers" 2>/dev/null) || status="000"
PEER_ID=$(jq -r '.id // empty' "${WORK_DIR}/peer-create.json" 2>/dev/null) || PEER_ID=""

if [ "$status" = "404" ]; then
  skip "peer mesh endpoints are not mounted on this deployment (HTTP 404)"
elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null && [ -n "$PEER_ID" ]; then
  pass
else
  fail "could not register a peer for the api_key leak check (HTTP ${status})" \
    "Without a stored secret the leak assertion below is vacuous. Response: $(head -c 400 "${WORK_DIR}/peer-create.json" 2>/dev/null)"
fi

begin_test "GET /api/v1/peers does not return the peer api_key"
if [ -z "$PEER_ID" ]; then
  skip "no peer was registered; nothing to inspect"
else
  status=$(curl -s -o "${WORK_DIR}/peers.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -H "$(auth_header)" "${BASE_URL}/api/v1/peers" 2>/dev/null) || status="000"
  if [ "$status" != "200" ]; then
    fail "GET /api/v1/peers returned ${status}, expected 200" \
      "Response: $(head -c 400 "${WORK_DIR}/peers.json" 2>/dev/null)"
  elif ! grep -q "$PEER_NAME" "${WORK_DIR}/peers.json" 2>/dev/null; then
    fail "the peer just registered is absent from GET /api/v1/peers" \
      "Without the fixture in the response the leak check proves nothing. Listing (truncated): $(head -c 500 "${WORK_DIR}/peers.json" 2>/dev/null)"
  elif grep -q "$PEER_KEY" "${WORK_DIR}/peers.json" 2>/dev/null; then
    fail "GET /api/v1/peers returns the peer api_key in plaintext" \
      "Any admin-scoped token can read the inter-node authentication material and impersonate a peer in the mesh. Peer: ${PEER_NAME}."
  else
    key_fields=$(jq -r '..|objects|keys[]?' "${WORK_DIR}/peers.json" 2>/dev/null \
      | grep -iE '^(api_key|api_secret|secret|password|private_key|token|credentials?)$' \
      | sort -u | tr '\n' ' ') || key_fields=""
    if [ -n "$key_fields" ]; then
      fail "the peer projection carries secret-shaped fields: ${key_fields}" \
        "The value did not match this test's fixture, but the field is present in the DTO and will carry real key material on a populated mesh."
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# User projection
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/users does not return password hashes or TOTP secrets"
status=$(curl -s -o "${WORK_DIR}/users.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -H "$(auth_header)" "${BASE_URL}/api/v1/users" 2>/dev/null) || status="000"

if [ "$status" != "200" ]; then
  fail "GET /api/v1/users returned ${status}, expected 200 for an admin token" \
    "Response: $(head -c 400 "${WORK_DIR}/users.json" 2>/dev/null)"
else
  user_count=$(jq -r 'if type=="array" then length elif .items then (.items|length) else 0 end' \
    "${WORK_DIR}/users.json" 2>/dev/null) || user_count=0
  leaked=$(jq -r '..|objects|keys[]?' "${WORK_DIR}/users.json" 2>/dev/null \
    | grep -iE '^(password|password_hash|totp_secret|totp_secret_encrypted|recovery_codes|backup_codes)$' \
    | sort -u | tr '\n' ' ') || leaked=""

  if [ "${user_count:-0}" -lt 1 ] 2>/dev/null; then
    fail "GET /api/v1/users returned no users; the projection could not be inspected" \
      "The admin account this suite authenticated as must appear. An empty list makes the field check vacuous. Response: $(head -c 400 "${WORK_DIR}/users.json" 2>/dev/null)"
  elif [ -n "$leaked" ]; then
    fail "the user projection exposes credential fields: ${leaked}" \
      "A password hash is offline-crackable and a TOTP secret defeats the second factor outright. ${user_count} user record(s) inspected."
  else
    pass
  fi
fi

end_suite
