#!/usr/bin/env bash
# =============================================================================
# tiers/auth-logout-revokes-access-token/oracle.sh
#   #4883  logout (and refresh replay) ends the session's access token
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh enables `set -e`; every probe below judges its own result.
set +e

BASE="$BASE_URL"
setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# The bound the fix promises across replicas; on this single replica the
# token is refused at once, so 5 s also absorbs scheduler jitter.
BOUND_SECS=5

# A dedicated user per run.
USER_NAME="la${DTF_SLOT}u$(printf '%s' "$RUN_ID" | tr -dc 'a-z0-9' | tail -c 8)"
USER_PASS="La!$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')x9"
NEW_PASS="Lb!$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')x8"

ADMIN_TOKEN="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u admin --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" | jqr '.access_token // empty')"
[ -n "$ADMIN_TOKEN" ] || { infra_fail "admin login failed"; end_suite; }
c="$(curl -s -o "${W}/user.json" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$USER_NAME" --arg p "$USER_PASS" --arg e "${USER_NAME}@dtf.local" \
        '{username:$u,password:$p,email:$e,is_admin:false}')")"
case "$c" in 200|201) ;; *) infra_fail "could not create the tier user (${c}): $(head -c 200 "${W}/user.json")"; end_suite ;; esac
USER_ID="$(jqr '.id // .user.id // empty' < "${W}/user.json")"
# A user created by an admin may be asked to change the password first; that
# does not block GET /auth/me, which is all this tier calls with its tokens.

# login [<password>] [<cookie-jar>] -> login body
login(){
  local pass="${1:-$USER_PASS}" jar=()
  [ -n "${2:-}" ] && jar=(-c "$2")
  curl -s --max-time 15 "${jar[@]}" -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$USER_NAME" --arg p "$pass" '{username:$u,password:$p}')" 2>/dev/null || true
}
# refresh <refresh-token> <out-file> -> HTTP code
refresh(){
  curl -s -o "$2" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/auth/refresh" \
    -H 'Content-Type: application/json' -d "$(jq -nc --arg r "$1" '{refresh_token:$r}')" 2>/dev/null || true
}
# me <bearer> -> HTTP code of GET /api/v1/auth/me
me(){
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Authorization: Bearer $1" \
    "${BASE}/api/v1/auth/me" 2>/dev/null || true
}
# logout_code <out-file> <curl args...> -> HTTP code
logout_code(){
  local out="$1"; shift
  curl -s -o "$out" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/auth/logout" "$@" 2>/dev/null || true
}
# refused_within <label> <bearer>: GET /auth/me with the Bearer is 401 within
# BOUND_SECS (polled every 0.5 s). Sets LAST_CODE and LAST_AFTER.
refused_within(){
  local label="$1" tok="$2" start now code=""
  start="$(date +%s%N)"
  while :; do
    code="$(me "$tok")"
    now="$(date +%s%N)"
    [ "$code" = "401" ] && break
    [ $(( (now - start) / 1000000 )) -ge $(( BOUND_SECS * 1000 )) ] && break
    sleep 0.5
  done
  LAST_CODE="$code"; LAST_AFTER="$(( (now - start) / 1000000 ))ms"
  note "${label}: Bearer replay -> ${code} after ${LAST_AFTER}"
  [ "$code" = "401" ] || fail_g "${label}: the access token still answers ${code} ${BOUND_SECS}s later (expected 401)"
}

begin_suite "auth-logout-revokes-access-token"

# -----------------------------------------------------------------------------
begin_test "FIX #4883 API shape: after a bearer logout ({} body) a Bearer replay of the access token is 401 within ${BOUND_SECS}s"
reset_case
L="$(login)"; AT="$(jqr '.access_token // empty' <<<"$L")"
if [ -z "$AT" ]; then
  fail_g "login returned no access token: $(head -c 200 <<<"$L")"
else
  c="$(me "$AT")"; note "before logout: ${c}"
  [ "$c" = "200" ] || fail_g "precondition: the fresh access token answered ${c}"
  c="$(logout_code "${W}/lo.json" -H "Authorization: Bearer ${AT}" -H 'Content-Type: application/json' -d '{}')"
  [ "$c" = "200" ] || fail_g "logout answered ${c}"
  refused_within "API shape" "$AT"
fi
finish_case "#4883: the access token keeps working after a bearer logout"

# -----------------------------------------------------------------------------
begin_test "FIX #4883 browser shape: after a cookie logout the cookie's access token replayed as Bearer is 401 within ${BOUND_SECS}s"
reset_case
JAR="${W}/jar.txt"
L="$(login "$USER_PASS" "$JAR")"
CAT="$(awk '!/^#/ && $6=="ak_access_token" {print $7}' "$JAR" | tail -n1)"
[ -n "$CAT" ] || CAT="$(awk '$6=="ak_access_token" {print $7}' "$JAR" | tail -n1)"
if [ -z "$CAT" ]; then
  fail_g "login set no ak_access_token cookie: $(head -c 200 <<<"$L")"
else
  c="$(me "$CAT")"; note "before logout: ${c}"
  [ "$c" = "200" ] || fail_g "precondition: the cookie's access token answered ${c}"
  c="$(logout_code "${W}/lo.json" -b "$JAR")"
  [ "$c" = "200" ] || fail_g "logout answered ${c}"
  refused_within "browser shape" "$CAT"
fi
finish_case "#4883: the cookie session's access token keeps working as a Bearer after logout"

# -----------------------------------------------------------------------------
begin_test "FIX #4883: refresh-token replay detection ends the access tokens of that session within ${BOUND_SECS}s"
reset_case
L="$(login)"; RT1="$(jqr '.refresh_token // empty' <<<"$L")"; AT1="$(jqr '.access_token // empty' <<<"$L")"
c2="$(refresh "$RT1" "${W}/r2.json")"; RT2="$(jqr '.refresh_token // empty' < "${W}/r2.json")"
c3="$(refresh "$RT2" "${W}/r3.json")"; AT3="$(jqr '.access_token // empty' < "${W}/r3.json")"
note "rotations: ${c2}, ${c3}"
if [ "$c2" != "200" ] || [ "$c3" != "200" ] || [ -z "$AT3" ]; then
  fail_g "precondition: two rotations did not succeed (${c2}, ${c3})"
else
  c="$(me "$AT3")"; note "current access token before the replay: ${c}"
  [ "$c" = "200" ] || fail_g "precondition: the current access token answered ${c}"
  c="$(refresh "$RT1" "${W}/replay.json")"
  note "replay of the first refresh token: ${c}"
  [ "$c" = "401" ] || fail_g "the replayed refresh token answered ${c}, expected 401"
  refused_within "rotated access token after replay" "$AT3"
  refused_within "original access token after replay" "$AT1"
fi
finish_case "#4883: access tokens of a replayed session keep working"

# -----------------------------------------------------------------------------
begin_test "CONTROL: logging out one session leaves another session's access token working"
reset_case
L1="$(login)"; AT1="$(jqr '.access_token // empty' <<<"$L1")"
L2="$(login)"; AT2="$(jqr '.access_token // empty' <<<"$L2")"
c="$(logout_code "${W}/lo.json" -H "Authorization: Bearer ${AT1}" -H 'Content-Type: application/json' -d '{}')"
[ "$c" = "200" ] || fail_g "logout answered ${c}"
sleep 1
ok=0
for _ in 1 2 3; do [ "$(me "$AT2")" = "200" ] && ok=$((ok+1)); sleep 0.5; done
note "other session after logout: ${ok}/3 probes 200"
[ "$ok" -ge 2 ] || fail_g "the other session's access token stopped working (${ok}/3 probes 200)"
finish_case "logout of one session ended another session's access token"

# -----------------------------------------------------------------------------
begin_test "CONTROL: an API token of the user is not affected by logout"
reset_case
L="$(login)"; AT="$(jqr '.access_token // empty' <<<"$L")"
c="$(curl -s -o "${W}/tok.json" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/auth/tokens" \
  -H "Authorization: Bearer ${AT}" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "dtf-${RUN_ID}" '{name:$n,scopes:["read:artifacts"],expires_in_days:1}')")"
API_TOKEN="$(jqr '.token // empty' < "${W}/tok.json")"
if [ -z "$API_TOKEN" ]; then
  note "could not mint an API token (${c}: $(head -c 160 "${W}/tok.json")); skipping"
else
  c="$(logout_code "${W}/lo.json" -H "Authorization: Bearer ${AT}" -H 'Content-Type: application/json' -d '{}')"
  [ "$c" = "200" ] || fail_g "logout answered ${c}"
  sleep 1
  c="$(me "$API_TOKEN")"; note "API token after logout: ${c}"
  [ "$c" = "200" ] || fail_g "the API token answered ${c} after the session logged out (expected 200)"
fi
finish_case "logout ended an API token"

# -----------------------------------------------------------------------------
begin_test "CONTROL: a password change ends the old access token within ${BOUND_SECS}s"
reset_case
L="$(login)"; AT="$(jqr '.access_token // empty' <<<"$L")"
c="$(me "$AT")"; note "before the password change: ${c}"
[ "$c" = "200" ] || fail_g "precondition: the access token answered ${c}"
c="$(curl -s -o "${W}/pw.json" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/users/${USER_ID}/password" \
  -H "Authorization: Bearer ${AT}" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg o "$USER_PASS" --arg n "$NEW_PASS" '{current_password:$o,new_password:$n}')")"
note "password change: ${c} $(head -c 120 "${W}/pw.json")"
case "$c" in
  200|204) refused_within "after password change" "$AT"; USER_PASS="$NEW_PASS" ;;
  *) fail_g "the password change answered ${c}" ;;
esac
finish_case "a password change left the old access token working"

if [ -n "$USER_ID" ]; then
  curl -s -o /dev/null --max-time 15 -X DELETE -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE}/api/v1/users/${USER_ID}" || true
fi
end_suite
