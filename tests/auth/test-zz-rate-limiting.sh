#!/usr/bin/env bash
# test-rate-limiting.sh - Rate limiting enforcement E2E test
#
# Sends rapid requests to the auth endpoint to trigger rate limiting.
#
# Why this suite declares-then-verifies (artifact-keeper-test#343)
# ---------------------------------------------------------------
# This suite used to flood /api/v1/auth/login 50 times and, if no 429 came
# back, skip with "rate limiting not triggered after 50 requests (may not be
# enabled in test mode)". That reason is a GUESS, and it is the ambiguity the
# coverage floor (#339) exists to eliminate: the harness could not distinguish
#
#   (a) the limiter is deliberately disabled in this deployment   -> fine
#   (b) the limiter is enabled but broken                         -> a real bug
#
# and it reported both as a skip, so the suite certified nothing while
# auth-tests reported green.
#
# The gate's own chart values answer the question outright: both
# helm/values-test.yaml and helm/values-test-full.yaml set
# RATE_LIMIT_ENABLED: "false", because release-gate runs 20+ suites against one
# shared backend and the per-user/IP and global windows trip 429 across a full
# run. The deployment's intent is therefore mirrored into AK_RATE_LIMIT_ENABLED
# by the auth-tests job, and this suite VERIFIES the declaration instead of
# trusting it:
#
#   declared off -> prove the limiter really is inert, then exempt
#   declared on  -> require a 429; NOT tripping is a FAILURE, never a skip
#
# Both drift directions are caught: a chart that quietly re-enables the limiter
# fails the "declared off" verification, and a chart that quietly disables it
# fails the "declared on" assertion.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "rate-limiting"

# flood_login N -- issue N login attempts for a non-existent user, echo "429"
# as soon as one is rate-limited, otherwise echo the last status seen.
flood_login() {
  local n="$1" i status
  for i in $(seq 1 "$n"); do
    status=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
      "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d '{"username":"nonexistent","password":"wrong"}' 2>/dev/null) || true
    if [ "$status" = "429" ]; then
      echo "429"
      return 0
    fi
  done
  echo "${status:-000}"
}

# ---------------------------------------------------------------------------
# Resolve the deployment's declared posture.
# ---------------------------------------------------------------------------

RATE_LIMIT_DECLARED="${AK_RATE_LIMIT_ENABLED:-}"

if [ -z "$RATE_LIMIT_DECLARED" ] && [ "${RELEASE_GATE:-0}" = "1" ]; then
  # Under RELEASE_GATE=1 the job MUST declare the posture; otherwise we are
  # back to guessing from a failed flood, which is the bug this suite fixes.
  begin_test "Deployment declares its rate-limit posture"
  infra_fail "AK_RATE_LIMIT_ENABLED is unset under RELEASE_GATE=1; the auth-tests job must mirror RATE_LIMIT_ENABLED from the chart values so this suite can tell 'deliberately disabled' from 'enabled but broken'"
  end_suite
fi

if [ "$RATE_LIMIT_DECLARED" = "false" ]; then
  # -------------------------------------------------------------------------
  # Declared OFF. Verify the declaration holds before exempting the suite: if
  # the backend actually IS rate-limiting, the chart and the job env have
  # drifted apart and the exemption would be hiding a live config.
  # -------------------------------------------------------------------------
  observed=$(flood_login 50)
  if [ "$observed" = "429" ]; then
    begin_test "Declared-disabled limiter is actually inert"
    fail "AK_RATE_LIMIT_ENABLED=false but the backend returned HTTP 429; the deployment's declared rate-limit posture does not match its behavior (chart values and job env have drifted)"
    end_suite
  fi

  # Declaration verified: the limiter really is not provisioned in this deploy.
  # This exits 0 via the capability-exemption allowlist in common.sh.
  skip_suite "rate limiting is disabled in this deployment (RATE_LIMIT_ENABLED=false in the gate chart values); verified inert: 50 login attempts produced no 429"
fi

# ---------------------------------------------------------------------------
# Declared ON (or a local dev run with the limiter expected up). The limiter
# MUST trip -- a flood that never yields 429 is now a failure, not a skip.
# ---------------------------------------------------------------------------

begin_test "Rapid auth requests trigger rate limit"
observed=$(flood_login 50)
if [ "$observed" = "429" ]; then
  pass
else
  fail "rate limiting is declared enabled (AK_RATE_LIMIT_ENABLED=${RATE_LIMIT_DECLARED:-<unset>}) but 50 rapid login attempts never returned 429 (last status ${observed})"
fi

# ---------------------------------------------------------------------------
# Verify rate limit response carries retry information
# ---------------------------------------------------------------------------

begin_test "Rate limit response includes retry info"
if [ "$observed" != "429" ]; then
  # The limiter never tripped, so there is no 429 response to inspect. The
  # failure is already recorded above; recording a second failure here would
  # double-count one defect.
  skip "no 429 response to inspect (see the failure above)"
else
  headers=$(curl -s -D- -o /dev/null -X POST \
    "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"nonexistent","password":"wrong"}' 2>/dev/null) || true
  if echo "$headers" | grep -qi "retry-after\|x-ratelimit"; then
    pass
  else
    fail "429 response carried neither Retry-After nor X-RateLimit-* headers"
  fi
fi

end_suite
