#!/usr/bin/env bash
# test-cors-policy.sh - the API never grants a cross-origin read to an
# attacker-chosen origin
#
# Ported from tests/security/redteam/test-03-cors.sh, which could not fail: it
# sourced tests/security/redteam/lib.sh (fail() only incremented an unread
# counter) and ended in `exit 0`. See tests/security/README-redteam-port.md.
#
# This is the only place in the repo that asserts anything about CORS
# (`grep -rl 'Access-Control-Allow-Origin' tests/` returns this file alone).
#
# What is asserted, and what deliberately is not
# ----------------------------------------------
# The security property is about what the server MAY NOT say, so every
# assertion is a prohibition:
#
#   - Access-Control-Allow-Origin must never be `*` on a credentialed API.
#   - It must never echo an attacker-supplied Origin.
#   - It must never be the literal `null`, which is reachable from a sandboxed
#     iframe or a data: URL.
#   - Access-Control-Allow-Credentials: true must never appear next to any of
#     the above.
#
# The gate deploy configures no CORS allowlist, so today the backend emits no
# Access-Control-Allow-Origin at all and every assertion holds trivially. That
# is the correct posture and NOT a reason to soften the test: the failure this
# guards is a middleware change to CorsLayer::permissive() or an
# AllowOrigin::mirror_request(), either of which turns all four green
# assertions red on the next run. A "CORS layer is mounted" diagnostic is
# printed (the backend sets `Vary: origin`) but is not asserted, because
# removing the layer entirely is more restrictive, not less.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cors-policy"
auth_admin
setup_workdir

EVIL_ORIGIN="https://evil-${RUN_ID}.example.com"

# probe_cors METHOD PATH ORIGIN [extra curl args...]
# Writes the response header block to $WORK_DIR/cors-headers.txt (CR-stripped).
probe_cors() {
  local method="$1" path="$2" origin="$3"
  shift 3
  curl -s -D "${WORK_DIR}/cors-headers.raw" -o /dev/null "${CURL_TIMEOUT_ARGS[@]}" \
    -X "$method" -H "Origin: ${origin}" "$@" \
    "${BASE_URL}${path}" >/dev/null 2>&1 || true
  tr -d '\r' < "${WORK_DIR}/cors-headers.raw" > "${WORK_DIR}/cors-headers.txt" 2>/dev/null || true
}

cors_header() {
  grep -i "^${1}:" "${WORK_DIR}/cors-headers.txt" 2>/dev/null | head -1 | sed 's/^[^:]*: *//' || true
}

# assert_acao_safe LABEL  -- reads the captured header block.
assert_acao_safe() {
  local label="$1"
  local acao creds
  acao=$(cors_header "access-control-allow-origin")
  creds=$(cors_header "access-control-allow-credentials")

  if [ "$acao" = "*" ]; then
    fail "${label}: Access-Control-Allow-Origin is the wildcard" \
      "Any website can read responses from this API cross-origin. Credentials header: ${creds:-<absent>}."
    return
  fi
  if [ "$acao" = "$EVIL_ORIGIN" ]; then
    fail "${label}: Access-Control-Allow-Origin echoes the request Origin" \
      "The server reflected the attacker-supplied Origin '${EVIL_ORIGIN}'. Combined with Access-Control-Allow-Credentials this is a full cross-origin read of any logged-in user's data. Credentials header: ${creds:-<absent>}."
    return
  fi
  if [ "$acao" = "null" ]; then
    fail "${label}: Access-Control-Allow-Origin is the literal 'null'" \
      "The null origin is produced by sandboxed iframes, data: URLs and redirects, so it is attacker-reachable. Credentials header: ${creds:-<absent>}."
    return
  fi
  if [ -n "$acao" ] && [ "$creds" = "true" ]; then
    fail "${label}: credentials are allowed for origin '${acao}'" \
      "Access-Control-Allow-Credentials: true was returned for a request carrying Origin: ${EVIL_ORIGIN}. Verify '${acao}' is a configured allowlist entry and not a reflection."
    return
  fi
  pass
}

# ---------------------------------------------------------------------------
# Diagnostic: is a CORS layer mounted at all?
# ---------------------------------------------------------------------------

probe_cors GET "/health" "$EVIL_ORIGIN"
if grep -qi '^vary:.*origin' "${WORK_DIR}/cors-headers.txt" 2>/dev/null; then
  echo "  note: a CORS layer is mounted (Vary: origin present on GET /health)"
else
  echo "  note: no Vary: origin on GET /health; either no CORS layer is mounted or it does not vary on Origin"
fi

# ---------------------------------------------------------------------------
# Simple request
# ---------------------------------------------------------------------------

begin_test "Simple GET with an attacker Origin is not granted cross-origin read"
probe_cors GET "/health" "$EVIL_ORIGIN"
assert_acao_safe "GET /health"

begin_test "Authenticated API GET with an attacker Origin is not granted cross-origin read"
probe_cors GET "/api/v1/repositories" "$EVIL_ORIGIN" -H "$(auth_header)"
assert_acao_safe "GET /api/v1/repositories"

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

begin_test "Preflight for a write with an attacker Origin is not granted"
probe_cors OPTIONS "/api/v1/repositories" "$EVIL_ORIGIN" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type, Authorization"
assert_acao_safe "OPTIONS /api/v1/repositories"

# ---------------------------------------------------------------------------
# null origin
# ---------------------------------------------------------------------------

begin_test "Origin: null is not granted cross-origin read"
probe_cors GET "/health" "null"
acao=$(cors_header "access-control-allow-origin")
creds=$(cors_header "access-control-allow-credentials")
if [ "$acao" = "null" ] || [ "$acao" = "*" ]; then
  fail "Origin: null was granted (Access-Control-Allow-Origin: ${acao})" \
    "A sandboxed iframe or data: URL sends Origin: null, so an allowlist entry of 'null' (or a wildcard) is attacker-reachable. Credentials header: ${creds:-<absent>}."
else
  pass
fi

end_suite
