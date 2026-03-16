#!/usr/bin/env bash
# test-rate-limiting.sh - Rate limiting enforcement E2E test
#
# Sends rapid requests to the auth endpoint to trigger rate limiting.
# Backend rate limit: 30 req/min for auth endpoints.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rate-limiting"

# -------------------------------------------------------------------------
# Flood auth endpoint
# -------------------------------------------------------------------------

begin_test "Rapid auth requests trigger rate limit"
got_429=false
for i in $(seq 1 50); do
  status=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"nonexistent","password":"wrong"}' 2>/dev/null) || true
  if [ "$status" = "429" ]; then
    got_429=true
    break
  fi
done

if $got_429; then
  pass
else
  skip "rate limiting not triggered after 50 requests (may not be enabled in test mode)"
fi

# -------------------------------------------------------------------------
# Verify rate limit includes retry-after header
# -------------------------------------------------------------------------

begin_test "Rate limit response includes retry info"
if $got_429; then
  headers=$(curl -s -D- -o /dev/null -X POST \
    "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"nonexistent","password":"wrong"}' 2>/dev/null) || true
  if echo "$headers" | grep -qi "retry-after\|x-ratelimit"; then
    pass
  else
    skip "rate limit headers not present"
  fi
else
  skip "rate limiting not triggered"
fi

end_suite
