#!/usr/bin/env bash
# test-default-credentials.sh - T2-13: Common default credential pairs rejected
#
# Verifies that well-known default credential combinations are rejected by the
# login endpoint. The test environment uses a non-default admin password, so all
# common pairs should return 401.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "default-credentials"
# NOTE: We do NOT call auth_admin here because these tests deliberately use
# wrong credentials. We still need the backend to be reachable though.
setup_workdir

# Wait for backend readiness
_ready=false
for _i in $(seq 1 15); do
  if curl -sf --max-time 5 "${BASE_URL}/readyz" >/dev/null 2>&1 || \
     curl -sf --max-time 5 "${BASE_URL}/health" >/dev/null 2>&1; then
    _ready=true
    break
  fi
  sleep 2
done
if ! $_ready; then
  echo "FATAL: backend not ready at ${BASE_URL} after 30s"
  exit 1
fi

# ---------------------------------------------------------------------------
# Helper: attempt login with given credentials
# ---------------------------------------------------------------------------

try_login() {
  local username="$1"
  local password="$2"

  curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${username}\",\"password\":\"${password}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>/dev/null || echo "000"
}

# ---------------------------------------------------------------------------
# Test common default credential pairs
# ---------------------------------------------------------------------------

begin_test "Reject admin:admin"
status=$(try_login "admin" "admin")
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
  pass
elif [ "$status" = "200" ]; then
  fail "default credentials admin:admin were accepted (HTTP 200)"
else
  # 429 (rate limited), 500, etc. still mean the creds were not accepted
  pass
fi

begin_test "Reject admin:password"
status=$(try_login "admin" "password")
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
  pass
elif [ "$status" = "200" ]; then
  fail "default credentials admin:password were accepted (HTTP 200)"
else
  pass
fi

begin_test "Reject root:root"
status=$(try_login "root" "root")
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
  pass
elif [ "$status" = "200" ]; then
  fail "default credentials root:root were accepted (HTTP 200)"
else
  pass
fi

begin_test "Reject admin:changeme"
status=$(try_login "admin" "changeme")
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
  pass
elif [ "$status" = "200" ]; then
  fail "default credentials admin:changeme were accepted (HTTP 200)"
else
  pass
fi

begin_test "Reject admin:12345"
status=$(try_login "admin" "12345")
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
  pass
elif [ "$status" = "200" ]; then
  fail "default credentials admin:12345 were accepted (HTTP 200)"
else
  pass
fi

begin_test "Reject root:admin"
status=$(try_login "root" "admin")
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
  pass
elif [ "$status" = "200" ]; then
  fail "default credentials root:admin were accepted (HTTP 200)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Verify that the actual test credentials still work
#
# Six wrong-credential attempts above can trip the per-IP auth rate limiter
# (429). admin is in RATE_LIMIT_EXEMPT_USERNAMES for username-bucket checks,
# but the IP bucket counts every failed login regardless of username. So the
# positive assertion below has to tolerate a transient 429 by waiting for
# the bucket to refill. Same retry budget pattern as auth_admin / login_as
# (PR #118): 5 attempts with 3s base delay, doubled on 429.
# ---------------------------------------------------------------------------

begin_test "Actual admin credentials are accepted"
_max_attempts="${ADMIN_LOGIN_MAX_ATTEMPTS:-5}"
_base_delay="${ADMIN_LOGIN_RETRY_DELAY:-3}"
status="000"
for _attempt in $(seq 1 "$_max_attempts"); do
  status=$(try_login "$ADMIN_USER" "$ADMIN_PASS")
  if [ "$status" = "200" ]; then
    break
  fi
  # Only retry on transient throttling / readiness signals. 401 / 403 mean
  # the creds genuinely don't work and retrying would just mask a real bug.
  case "$status" in
    429|503|000)
      if [ "$_attempt" -lt "$_max_attempts" ]; then
        if [ "$status" = "429" ]; then
          sleep "$(( _base_delay * 2 ))"
        else
          sleep "$_base_delay"
        fi
        continue
      fi
      ;;
    *)
      break
      ;;
  esac
done
if [ "$status" = "200" ]; then
  pass
else
  fail "expected admin credentials to be accepted, got HTTP ${status} after ${_max_attempts} attempts"
fi

end_suite
