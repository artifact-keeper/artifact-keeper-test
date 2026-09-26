#!/usr/bin/env bash
# test-public-repo-guest-disabled.sh - explicit 400 instead of silent coercion (#3855)
#
# With AK_GUEST_ACCESS_ENABLED=false, a create/update asking for a public
# repository used to be silently rewritten to private (201/200 for a repo
# the caller never asked for — perpetual Terraform drift, late "why can
# nobody pull anonymously" surprises). The fix rejects the contradiction
# with 400 naming the switch.
#
# Declare-then-verify (same pattern as test-zz-rate-limiting.sh): the cluster
# deployment mirrors AK_GUEST_ACCESS_ENABLED into the environment, so this
# suite verifies the posture instead of guessing:
#
#   declared disabled -> require 400 on public create/update (FAIL on 201)
#   declared enabled  -> prove public create really works (posture honesty)
#
# On an UNFIXED backend with guest access disabled, the public create
# answers 201 and the first case FAILS.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "public-repo-guest-disabled"

auth_admin

GUEST_DECLARED="${AK_GUEST_ACCESS_ENABLED:-}"
REPO_KEY="zz-3855-pub-${RUN_ID}"
REPO_KEY_PRIV="zz-3855-priv-${RUN_ID}"

create_repo_status() {
  local key="$1" is_public="$2"
  curl -s -o /tmp/zz-3855-body.json -w '%{http_code}' --max-time 10 \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":${is_public}}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo "000"
}

begin_test "Deployment guest-access posture is declared"
if [ -z "$GUEST_DECLARED" ]; then
  if [ "${RELEASE_GATE:-0}" = "1" ]; then
    fail "AK_GUEST_ACCESS_ENABLED is unset: the deployment must declare its posture"
  else
    GUEST_DECLARED="true"
    pass "posture undeclared; assuming guest access enabled for local run"
  fi
elif [ "$GUEST_DECLARED" = "true" ] || [ "$GUEST_DECLARED" = "false" ]; then
  pass "posture declared: AK_GUEST_ACCESS_ENABLED=${GUEST_DECLARED}"
else
  fail "AK_GUEST_ACCESS_ENABLED must be 'true' or 'false', got '${GUEST_DECLARED}'"
fi

if [ "$GUEST_DECLARED" = "true" ]; then
  # Guest access enabled: the 400 does not apply here; certify posture
  # honesty instead (public create must really work).
  begin_test "Declared-enabled posture is honest (public create succeeds)"
  st=$(create_repo_status "$REPO_KEY" true)
  if [ "$st" = "201" ] || [ "$st" = "200" ]; then
    pass "public create succeeded as declared (status ${st})"
    api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
  else
    fail "deployment declares guest access enabled but public create returned ${st}"
  fi
  end_suite
  exit $?
fi

# ---------------------------------------------------------------------------
# Declared DISABLED. Public create/update must be rejected 400, never
# silently coerced (#3855).
# ---------------------------------------------------------------------------

begin_test "Public create is rejected 400 naming the guest-access switch"
st=$(create_repo_status "$REPO_KEY" true)
body=$(cat /tmp/zz-3855-body.json 2>/dev/null || true)
if [ "$st" != "400" ]; then
  fail "public create under AK_GUEST_ACCESS_ENABLED=false returned ${st}, expected 400 (#3855); body: ${body}"
elif echo "$body" | grep -q "AK_GUEST_ACCESS_ENABLED=false"; then
  pass "public create rejected 400 and the message names the switch"
else
  fail "public create rejected 400 but the message does not name AK_GUEST_ACCESS_ENABLED=false: ${body}"
fi

begin_test "A rejected public create leaves no repository row behind"
st=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}" 2>/dev/null || echo "000")
if [ "$st" = "404" ]; then
  pass "no repository exists at ${REPO_KEY} after the rejected create"
else
  fail "GET /repositories/${REPO_KEY} returned ${st} after a rejected create — the repo was persisted anyway"
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
fi

begin_test "Private create succeeds under the disabled policy (control)"
st=$(create_repo_status "$REPO_KEY_PRIV" false)
if [ "$st" = "201" ] || [ "$st" = "200" ]; then
  pass "private create succeeded (status ${st})"
else
  fail "private create under the disabled policy returned ${st}, expected 201"
fi

begin_test "Flipping a repository to public on update is rejected 400"
st=$(curl -s -o /tmp/zz-3855-body.json -w '%{http_code}' --max-time 10 \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"is_public":true}' \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY_PRIV}" 2>/dev/null || echo "000")
body=$(cat /tmp/zz-3855-body.json 2>/dev/null || true)
if [ "$st" != "400" ]; then
  fail "is_public=true update under the disabled policy returned ${st}, expected 400 (#3855); body: ${body}"
elif echo "$body" | grep -q "AK_GUEST_ACCESS_ENABLED=false"; then
  pass "public flip rejected 400 and the message names the switch"
else
  fail "public flip rejected 400 but the message does not name AK_GUEST_ACCESS_ENABLED=false: ${body}"
fi

begin_test "The rejected flip left the stored visibility private"
vis=$(curl -sf --max-time 10 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY_PRIV}" 2>/dev/null | jq -r '.is_public' 2>/dev/null)
if [ "$vis" = "false" ]; then
  pass "stored visibility stayed private after the rejected flip"
else
  fail "stored is_public is '${vis}' after a flip that was rejected 400"
fi

api_delete "/api/v1/repositories/${REPO_KEY_PRIV}" >/dev/null 2>&1 || true
rm -f /tmp/zz-3855-body.json

end_suite
