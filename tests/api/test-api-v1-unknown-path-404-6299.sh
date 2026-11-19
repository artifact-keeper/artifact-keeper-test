#!/usr/bin/env bash
# test-api-v1-unknown-path-404-6299.sh -- Unknown /api/v1 paths answer the
# API's own JSON 404 "Not found"
#
# Regression test for artifact-keeper#6299 (backend change: artifact-keeper/
# artifact-keeper PR 6301, 1.12.3).
#
# Background
#   The /api/v1 nest had no fallback, so a path no API route matched fell
#   through to the format routes. Their repository lookup answered
#   404 {"code":"NOT_FOUND","message":"Repository not found"}, which sent
#   operators and SDK users looking for a missing repository when the real
#   problem was a typo in the endpoint. The fix gives the nest a fallback that
#   answers 404 {"code":"NOT_FOUND","message":"Not found"}.
#
# What this script asserts
#   - GET (signed in and anonymous) and POST /api/v1/does-not-exist answer
#     404 with a JSON body whose message is exactly "Not found" and that does
#     not mention a repository.
#   - Controls: a real route (GET /api/v1/repositories) is still 200, and a
#     known path with the wrong method (PUT /api/v1/repositories, GET
#     /api/v1/auth/login) is still 405, so the fallback does not swallow
#     method checks.
#
# The release gate runs the same assertions as FIX #6299 in the DTF tier
# deploy-test/harness/tiers/api-contracts-1120-fixes.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "api-v1-unknown-path-404-6299"
auth_admin

# call <METHOD> <PATH> <auth|anon> [JSON body] -> "<status>\t<content-type>\t<body>"
call() {
  local method="$1" path="$2" who="$3" body="${4:-}"
  local out hdrs code ctype resp
  out=$(mktemp); hdrs=$(mktemp)
  local args=(-s -o "$out" -D "$hdrs" -w '%{http_code}' --max-time 30 --connect-timeout 10 -X "$method")
  [ "$who" = "auth" ] && args+=(-H "$(auth_header)")
  [ -n "$body" ] && args+=(-H "Content-Type: application/json" --data-binary "$body")
  code=$(curl "${args[@]}" "${BASE_URL}${path}") || code="000"
  ctype=$(tr -d '\r' <"$hdrs" | grep -i '^content-type:' | tail -1 | cut -d: -f2- | sed 's/^ *//' || true)
  resp=$(cat "$out" 2>/dev/null || echo "")
  rm -f "$out" "$hdrs"
  printf '%s\t%s\t%s\n' "$code" "$ctype" "$resp"
}

# assert_api_not_found <result> <label>
assert_api_not_found() {
  local result="$1" label="$2"
  local status ctype body msg
  status="${result%%$'\t'*}"
  ctype="$(printf '%s' "$result" | cut -f2)"
  body="$(printf '%s' "$result" | cut -f3-)"
  if [ "$status" != "404" ]; then
    fail "${label}: expected 404, got ${status}" "body: ${body:0:300}"
    return 1
  fi
  case "$ctype" in
    application/json*) ;;
    *) fail "${label}: expected application/json, got '${ctype}'" "body: ${body:0:300}"; return 1 ;;
  esac
  msg=$(printf '%s' "$body" | jq -r '.message // empty' 2>/dev/null || echo "")
  if [ "$msg" != "Not found" ]; then
    fail "${label}: message is '${msg}', expected 'Not found'" \
"body: ${body:0:300}
note: 'Repository not found' is the pre-#6299 shape (the path fell through to the format routes)."
    return 1
  fi
  case "$body" in
    *[Rr]epository*) fail "${label}: body names a repository" "body: ${body:0:300}"; return 1 ;;
  esac
  return 0
}

begin_test "GET /api/v1/does-not-exist (signed in) returns JSON 404 'Not found'"
assert_api_not_found "$(call GET /api/v1/does-not-exist auth)" "GET signed in" && pass

begin_test "GET /api/v1/does-not-exist (anonymous) returns JSON 404 'Not found'"
assert_api_not_found "$(call GET /api/v1/does-not-exist anon)" "GET anonymous" && pass

begin_test "POST /api/v1/does-not-exist returns JSON 404 'Not found'"
assert_api_not_found "$(call POST /api/v1/does-not-exist auth '{"name":"x"}')" "POST signed in" && pass

begin_test "Control: GET /api/v1/repositories still returns 200"
result=$(call GET /api/v1/repositories auth)
status="${result%%$'\t'*}"
if [ "$status" = "200" ]; then
  pass
else
  fail "GET /api/v1/repositories returned ${status}" "$(printf '%s' "$result" | cut -f3- | head -c 300)"
fi

begin_test "Control: a known path with the wrong method still returns 405"
r1=$(call PUT /api/v1/repositories auth '{}')
r2=$(call GET /api/v1/auth/login anon)
s1="${r1%%$'\t'*}"; s2="${r2%%$'\t'*}"
if [ "$s1" = "405" ] && [ "$s2" = "405" ]; then
  pass
else
  fail "wrong-method requests: PUT /api/v1/repositories=${s1}, GET /api/v1/auth/login=${s2} (expected 405 each)"
fi

end_suite
