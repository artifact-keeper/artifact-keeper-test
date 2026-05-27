#!/usr/bin/env bash
# test-oidc-callback-empty-state-1369.sh
#
# Reproducer for artifact-keeper#1369: the OIDC callback handler used to feed
# an empty `state` query parameter straight into the SSO session lookup, which
# bubbled up as AppError::Authentication and returned HTTP 401. That was wrong
# on two counts:
#   1. An empty `state` is a malformed callback, not a CSRF failure. The
#      correct status for a missing required parameter is 400 with a
#      VALIDATION_ERROR code so frontends can distinguish "you forgot a
#      parameter" from "your session expired / replay detected".
#   2. The 401 path leaked timing/branch info about session lookup. Failing
#      validation first means we never touch the session store for malformed
#      requests.
#
# Fix landed in artifact-keeper PR #1383 (validate_oidc_callback_params runs
# BEFORE the session lookup in both oidc_callback and oidc_callback_generic).
#
# Pre-fix backend (1.1.0-rc.2): empty state -> 401
# Post-fix backend (main):      empty state -> 400 with code = VALIDATION_ERROR
#
# Backend reference:
#   - backend/src/api/handlers/sso.rs:183-190 validate_oidc_callback_params
#   - backend/src/api/handlers/sso.rs:217, 257 (called before session lookup)
#   - backend/src/error.rs:119 Validation -> 400 VALIDATION_ERROR
#
# This test also verifies the CSRF defense (non-empty but invalid state still
# returns 401) was preserved by the fix — that is the load-bearing security
# behavior we must not regress.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-oidc-callback-empty-state-1369"
auth_admin

# Use a UUID-shaped path id for the per-provider route so its parameter parser
# accepts the request and we reach validate_oidc_callback_params. A bogus id is
# fine: we never get past param validation in the cases we care about.
PROVIDER_ID="00000000-0000-0000-0000-000000000000"
GENERIC_PATH="/api/v1/auth/sso/oidc/callback"
PROVIDER_PATH="/api/v1/auth/sso/oidc/${PROVIDER_ID}/callback"

# ---------------------------------------------------------------------------
# Helper: hit the callback and capture both status and the error code from
# the JSON envelope. Echoes "<status>|<code>" on stdout.
#
# We deliberately split the curl into status (-o /dev/null -w '%{http_code}')
# and a separate body fetch so a malformed/empty body cannot break the
# status check. Two calls add no real cost and keep the assertion crisp.
# ---------------------------------------------------------------------------
oidc_call() {
  local url="$1"
  local status body code
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT "$url" 2>/dev/null) || status="000"
  body=$(curl -s $CURL_TIMEOUT "$url" 2>/dev/null) || body=""
  code=$(echo "$body" | jq -r '.code // .error.code // empty' 2>/dev/null) || code=""
  echo "${status}|${code}|${body:0:200}"
}

# ---------------------------------------------------------------------------
# 1) Empty state on the generic callback returns 400, not 401.
#    code=X, state=   (empty)
# ---------------------------------------------------------------------------

begin_test "Generic callback: empty state returns 400 with VALIDATION_ERROR"
result=$(oidc_call "${BASE_URL}${GENERIC_PATH}?code=X&state=")
status="${result%%|*}"
rest="${result#*|}"
code="${rest%%|*}"
body="${rest#*|}"
if [ "$status" = "400" ] && [ "$code" = "VALIDATION_ERROR" ]; then
  pass
elif [ "$status" = "401" ]; then
  fail "pre-fix bug: empty state returned 401 (CSRF path) instead of 400 (validation). #1369 regression" "$body"
elif [ "$status" = "400" ]; then
  # Backend accepted as bad request but didn't tag the structured code we want.
  # Treat as failure so we catch any envelope-format regression. The fix in
  # #1383 specifically wires AppError::Validation -> VALIDATION_ERROR.
  fail "got HTTP 400 but error code was '${code}', expected VALIDATION_ERROR" "$body"
else
  fail "unexpected HTTP ${status} for empty state (want 400)" "$body"
fi

# ---------------------------------------------------------------------------
# 2) Empty code (state present) also returns 400.
# ---------------------------------------------------------------------------

begin_test "Generic callback: empty code returns 400 with VALIDATION_ERROR"
result=$(oidc_call "${BASE_URL}${GENERIC_PATH}?code=&state=somestate")
status="${result%%|*}"
rest="${result#*|}"
code="${rest%%|*}"
body="${rest#*|}"
if [ "$status" = "400" ] && [ "$code" = "VALIDATION_ERROR" ]; then
  pass
elif [ "$status" = "400" ]; then
  fail "got HTTP 400 but error code was '${code}', expected VALIDATION_ERROR" "$body"
else
  fail "expected 400 VALIDATION_ERROR for empty code, got HTTP ${status} code='${code}'" "$body"
fi

# ---------------------------------------------------------------------------
# 3) Both code and state empty: still 400 (not 401, not 500).
# ---------------------------------------------------------------------------

begin_test "Generic callback: both empty returns 400 with VALIDATION_ERROR"
result=$(oidc_call "${BASE_URL}${GENERIC_PATH}?code=&state=")
status="${result%%|*}"
rest="${result#*|}"
code="${rest%%|*}"
body="${rest#*|}"
if [ "$status" = "400" ] && [ "$code" = "VALIDATION_ERROR" ]; then
  pass
else
  fail "expected 400 VALIDATION_ERROR for both empty, got HTTP ${status} code='${code}'" "$body"
fi

# ---------------------------------------------------------------------------
# 4) Per-provider callback (UUID path) also validates state shape before
#    session lookup. Same fix lives in oidc_callback as well as the generic
#    variant — both must behave identically.
# ---------------------------------------------------------------------------

begin_test "Per-provider callback: empty state returns 400 with VALIDATION_ERROR"
result=$(oidc_call "${BASE_URL}${PROVIDER_PATH}?code=X&state=")
status="${result%%|*}"
rest="${result#*|}"
code="${rest%%|*}"
body="${rest#*|}"
if [ "$status" = "400" ] && [ "$code" = "VALIDATION_ERROR" ]; then
  pass
elif [ "$status" = "401" ]; then
  fail "pre-fix bug: per-provider callback with empty state returned 401 instead of 400" "$body"
else
  fail "expected 400 VALIDATION_ERROR on per-provider path, got HTTP ${status} code='${code}'" "$body"
fi

# ---------------------------------------------------------------------------
# 5) CSRF defense preserved: a NON-empty state that has no matching SSO
#    session must still return 401. Empty != invalid; the fix only changes
#    the empty-string branch, never the replay-defense branch.
#
#    This is the load-bearing security assertion. If a refactor accidentally
#    collapses "no session" into VALIDATION_ERROR, we lose the CSRF signal
#    and an attacker can probe state values without 401 telemetry.
# ---------------------------------------------------------------------------

begin_test "Non-empty but invalid state still returns 401 (CSRF defense preserved)"
# Use a RUN_ID-scoped state value so parallel suites can't collide.
INVALID_STATE="not-a-real-session-${RUN_ID}"
result=$(oidc_call "${BASE_URL}${GENERIC_PATH}?code=X&state=${INVALID_STATE}")
status="${result%%|*}"
body="${result##*|}"
if [ "$status" = "401" ]; then
  pass
elif [ "$status" = "400" ]; then
  fail "regression: non-empty invalid state returned 400 — CSRF defense was over-broadened" "$body"
else
  # Any 5xx here means the validation/session pipeline crashed, which is also a fail.
  fail "expected 401 for non-empty invalid state, got HTTP ${status}" "$body"
fi

# EXPECT_FAILURE=1 inverts the suite's exit code so this script can be used
# as a fixture to validate the gate (a "broken" gate is a passing self-test).
enable_expect_failure_trap

end_suite
