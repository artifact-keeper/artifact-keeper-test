#!/usr/bin/env bash
# test-download-ticket-lifecycle.sh - Download ticket creation & shape (Epic 11.9, #76)
#
# In v1.1.x the backend exposes POST /api/v1/auth/ticket which mints a
# short-lived (30s), single-use token meant to be passed as ?ticket= on
# endpoints that cannot use Authorization headers (e.g. <a> downloads,
# EventSource SSE).
#
# auth_config_service::validate_download_ticket implements single-use via
# DELETE ... RETURNING (the second call gets nothing back), and expiry via
# `expires_at > NOW()`.
#
# Verifies (against what is observable from the public API in v1.1.x):
#   1. Authenticated POST /auth/ticket returns 200 with a non-empty `ticket`
#      and an `expires_in` numeric (matches TicketResponse in auth.rs:483)
#   2. Unauthenticated POST is rejected with 401
#   3. The ticket value differs across calls (uniqueness)
#   4. Two tickets created back-to-back have the documented short TTL
#      (expires_in <= 60)
#
# Single-use consumption and expiry-rejection scenarios are guarded behind
# `require_feature` because v1.1.x does not yet ship a public consumer
# endpoint for `?ticket=` (see backend grep: only the create handler and
# service-layer validate_download_ticket exist; no Query<Ticket> consumer
# is wired up). When a consumer ships, lift the require_feature gate and
# enable the consumption tests below.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-download-ticket"
auth_admin
setup_workdir

TICKET=""
TICKET_2=""

# -------------------------------------------------------------------------
# Create a ticket (authenticated)
# -------------------------------------------------------------------------

begin_test "POST /auth/ticket returns ticket + expires_in"
resp=$(curl -sf $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"purpose":"download","resource_path":"/api/v1/repositories"}' \
  "${BASE_URL}/api/v1/auth/ticket" 2>/dev/null) || true

if [ -z "$resp" ]; then
  fail "ticket endpoint returned empty body"
else
  TICKET=$(echo "$resp" | jq -r '.ticket // empty')
  EXPIRES_IN=$(echo "$resp" | jq -r '.expires_in // empty')
  if [ -z "$TICKET" ] || [ "$TICKET" = "null" ]; then
    fail "response missing ticket field: ${resp:0:200}"
  elif ! [[ "$EXPIRES_IN" =~ ^[0-9]+$ ]]; then
    fail "response missing or non-numeric expires_in: '${EXPIRES_IN}'"
  elif [ "$EXPIRES_IN" -gt 60 ]; then
    # Documented in auth.rs:519 as 30s; allow up to 60 to absorb future bumps.
    fail "expires_in (${EXPIRES_IN}s) is unexpectedly large; download tickets are short-lived"
  else
    pass
  fi
fi

# -------------------------------------------------------------------------
# Ticket length sanity (auth_config_service builds it from two hex UUIDs)
# -------------------------------------------------------------------------

begin_test "Ticket value has expected entropy"
if [ -z "${TICKET:-}" ]; then
  skip "no ticket from previous step"
else
  ticket_len=${#TICKET}
  # Two stripped UUID hex strings concatenated -> 64 chars in v1.1.x. We
  # only assert >=32 to allow future format changes without breaking.
  if [ "$ticket_len" -ge 32 ]; then
    pass
  else
    fail "ticket too short (${ticket_len} chars); expected >= 32"
  fi
fi

# -------------------------------------------------------------------------
# Unauthenticated request must be rejected
# -------------------------------------------------------------------------

begin_test "POST /auth/ticket without auth returns 401"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"purpose":"download"}' \
  "${BASE_URL}/api/v1/auth/ticket" 2>/dev/null) || true
status="${status:-000}"
if [ "$status" = "401" ]; then
  pass
else
  fail "expected 401 for unauthenticated ticket request, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# Two tickets are distinct (no replay of the same value)
# -------------------------------------------------------------------------

begin_test "Two tickets are distinct values"
resp2=$(curl -sf $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"purpose":"download"}' \
  "${BASE_URL}/api/v1/auth/ticket" 2>/dev/null) || true
TICKET_2=$(echo "$resp2" | jq -r '.ticket // empty')
if [ -z "${TICKET:-}" ] || [ -z "${TICKET_2:-}" ]; then
  skip "missing one or both tickets"
elif [ "$TICKET" = "$TICKET_2" ]; then
  fail "two consecutive tickets returned the same value (no entropy)"
else
  pass
fi

# -------------------------------------------------------------------------
# Consumer-side tests (single-use + expiry).
#
# v1.1.x has no public endpoint that accepts ?ticket= as auth, so we cannot
# observe single-use enforcement from the outside. The service-layer
# validate_download_ticket (auth_config_service.rs:1367) uses
# `DELETE ... RETURNING` which is single-use by construction. Document the
# gap and skip in a way that release-gate (RELEASE_GATE=1) treats as
# expected-skip, not a silent pass.
# -------------------------------------------------------------------------

begin_test "Single-use ticket consumption"
require_feature "download_ticket_consumer" || true
# When the consumer endpoint lands (Epic 11.x, target 1.2.0), this test
# should issue a ticket, consume it once successfully, then assert the
# second consumption returns 401/403/404. Until then, require_feature
# auto-skips on 1.1.x and auto-fails on >=1.2.0 if not implemented.

begin_test "Expired ticket rejection"
require_feature "download_ticket_consumer" || true
# Same auto-skip-then-fail behaviour. When consumer endpoint exists, this
# test should set ticket TTL to 1s, sleep 2s, then assert consumption
# returns 401 (expires_at <= NOW() in validate_download_ticket).

# EXPECT_FAILURE=1 inverts the suite's exit code so this script can be used
# as a fixture to validate the gate (a "broken" gate is a passing self-test).
enable_expect_failure_trap

end_suite
