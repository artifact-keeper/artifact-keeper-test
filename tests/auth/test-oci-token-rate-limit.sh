#!/usr/bin/env bash
# test-oci-token-rate-limit.sh - /v2/token credential-exchange rate limiting (#4020)
#
# The OCI token endpoint is unauthenticated by design and, before #4020, sat
# outside every rate-limit layer, so password guessing against it was bounded
# only by account lockout. The fix applies the login limiter (per username+IP
# budget, global backstop) to the Basic / OAuth2 password-grant exits while
# leaving the refresh-grant, bearer-swap, and anonymous-mint exits unlimited.
#
# Declare-then-verify (same pattern as test-zz-rate-limiting.sh): the swarm
# deployment for this cluster sets RATE_LIMIT_ENABLED=true and mirrors it
# into AK_RATE_LIMIT_ENABLED, so this suite VERIFIES the posture instead of
# guessing:
#
#   declared off -> prove the endpoint really is inert, then exempt
#   declared on  -> require 429 + Retry-After; no 429 is a FAILURE, not a skip
#
# On an UNFIXED backend the "declared on" cases all fail: no 429 ever comes
# back from /v2/token no matter how many wrong passwords are presented.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-token-rate-limit"

# Wrong-password Basic credential for a probe user that does not exist.
basic_probe_header() {
  local user="$1"
  printf 'Basic %s' "$(printf '%s:wrong-password' "$user" | base64 -w0 2>/dev/null || printf '%s:wrong-password' "$user" | base64)"
}

# token_status <method> <auth-header-or-empty> <extra-curl-args...>
# Single /v2/token exchange, echoes the HTTP status.
token_status() {
  local method="$1" authz="$2"; shift 2
  local args=(-s -o /dev/null -w '%{http_code}' --max-time 10 -X "$method")
  if [ -n "$authz" ]; then
    args+=(-H "Authorization: ${authz}")
  fi
  curl "${args[@]}" "$@" "${BASE_URL}/v2/token?service=artifact-keeper" 2>/dev/null || echo "000"
}

RATE_LIMIT_DECLARED="${AK_RATE_LIMIT_ENABLED:-}"

begin_test "Deployment rate-limit posture is declared"
if [ -z "$RATE_LIMIT_DECLARED" ]; then
  if [ "${RELEASE_GATE:-0}" = "1" ]; then
    fail "AK_RATE_LIMIT_ENABLED is unset: the deployment must declare its posture (see test-zz-rate-limiting.sh)"
  else
    # Local dev convenience: assume the default (limiter enabled).
    RATE_LIMIT_DECLARED="true"
    pass "posture undeclared; assuming limiter enabled for local run"
  fi
elif [ "$RATE_LIMIT_DECLARED" = "true" ] || [ "$RATE_LIMIT_DECLARED" = "false" ]; then
  pass "posture declared: RATE_LIMIT_ENABLED=${RATE_LIMIT_DECLARED}"
else
  fail "AK_RATE_LIMIT_ENABLED must be 'true' or 'false', got '${RATE_LIMIT_DECLARED}'"
fi

if [ "$RATE_LIMIT_DECLARED" = "false" ]; then
  # Declared OFF: prove the endpoint is really inert, then exempt the rest.
  begin_test "Declared-off posture is honest (no 429 from /v2/token flood)"
  local_seen=""
  for i in $(seq 1 15); do
    st=$(token_status GET "$(basic_probe_header "zz-4020-inert")")
    local_seen="$st"
    if [ "$st" = "429" ]; then
      break
    fi
  done
  if [ "$local_seen" = "429" ]; then
    fail "deployment declares RATE_LIMIT_ENABLED=false but /v2/token returned 429 after $i attempts"
  else
    pass "limiter is inert as declared (last status ${local_seen})"
  fi
  end_suite
  exit $?
fi

# ---------------------------------------------------------------------------
# Declared ON. The password-grant exits MUST trip 429 with Retry-After after
# the per-(username, IP) budget (default 10 / 15 min) is spent.
# ---------------------------------------------------------------------------

begin_test "N+1 wrong passwords from one IP yield 429 with Retry-After"
probe_user="zz-4020-basic-${RUN_ID}"
saw_429=""
retry_after=""
last=""
for i in $(seq 1 20); do
  headers_file=$(mktemp)
  last=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -D "$headers_file" \
    -H "Authorization: $(basic_probe_header "$probe_user")" \
    "${BASE_URL}/v2/token?service=artifact-keeper" 2>/dev/null) || last="000"
  if [ "$last" = "429" ]; then
    saw_429="yes"
    retry_after=$(grep -i '^Retry-After:' "$headers_file" | tr -d '\r' | awk '{print $2}')
    rm -f "$headers_file"
    break
  fi
  rm -f "$headers_file"
done
if [ -n "$saw_429" ]; then
  if [ -n "$retry_after" ]; then
    pass "429 after ${i} wrong-password exchanges, with Retry-After: ${retry_after}"
  else
    fail "429 after ${i} exchanges but the response carried NO Retry-After header (#4020 acceptance)"
  fi
else
  fail "no 429 after 20 wrong-password /v2/token exchanges (last status ${last}): /v2/token is not rate limited (#4020)"
fi

begin_test "A different username keeps its own budget (per-username keying)"
st=$(token_status GET "$(basic_probe_header "zz-4020-other-${RUN_ID}")")
if [ "$st" != "429" ]; then
  pass "a fresh username still reaches the exchange (status ${st}) — the probe user's budget did not lock it out"
else
  fail "a different username was 429'd by the probe user's flood: the key is not per-(username, IP)"
fi

begin_test "The refresh grant is NOT rate limited (docker pull refresh flow)"
# grant_type=refresh_token presents an already-issued credential; limiting it
# would break every long-running docker pull. It must answer 401 (invalid
# token), never 429, even right after the password budget was spent.
saw_429=""
last=""
for i in $(seq 1 6); do
  last=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "grant_type=refresh_token&refresh_token=not-a-real-token" \
    "${BASE_URL}/v2/token?service=artifact-keeper" 2>/dev/null) || last="000"
  if [ "$last" = "429" ]; then
    saw_429="yes"
    break
  fi
done
if [ -z "$saw_429" ]; then
  pass "refresh grant answers ${last}, never 429 — the refresh flow stays unlimited"
else
  fail "refresh grant was 429'd: #4020 must leave the refresh-grant exit unlimited"
fi

begin_test "The bearer swap is NOT rate limited"
saw_429=""
last=""
for i in $(seq 1 6); do
  last=$(token_status GET "Bearer not.a.validjwt")
  if [ "$last" = "429" ]; then
    saw_429="yes"
    break
  fi
done
if [ -z "$saw_429" ]; then
  pass "bearer swap answers ${last}, never 429 — the validated-credential exit stays unlimited"
else
  fail "bearer swap was 429'd: #4020 must leave the bearer-swap exit unlimited"
fi

begin_test "The anonymous mint is NOT rate limited"
saw_429=""
last=""
for i in $(seq 1 6); do
  last=$(token_status GET "")
  if [ "$last" = "429" ]; then
    saw_429="yes"
    break
  fi
done
if [ -z "$saw_429" ]; then
  pass "anonymous mint answers ${last}, never 429"
else
  fail "anonymous mint was 429'd: there is no password to guess on this exit"
fi

end_suite
