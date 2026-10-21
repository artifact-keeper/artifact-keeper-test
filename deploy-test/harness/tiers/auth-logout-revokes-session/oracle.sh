#!/usr/bin/env bash
# =============================================================================
# tiers/auth-logout-revokes-session/oracle.sh
#   #4831  logout revokes the presenting session's refresh-token family
# See the manifest for the shapes and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
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

# A dedicated user per run, so the DB assertions see only this tier's rows.
USER_NAME="lo${DTF_SLOT}u$(printf '%s' "$RUN_ID" | tr -dc 'a-z0-9' | tail -c 8)"
USER_PASS="Lo!$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')x9"

ADMIN_TOKEN="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u admin --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" | jqr '.access_token // empty')"
[ -n "$ADMIN_TOKEN" ] || { infra_fail "admin login failed"; end_suite; }
c="$(curl -s -o "${W}/user.json" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$USER_NAME" --arg p "$USER_PASS" --arg e "${USER_NAME}@dtf.local" \
        '{username:$u,password:$p,email:$e,is_admin:false}')")"
case "$c" in 200|201) ;; *) infra_fail "could not create the tier user (${c}): $(head -c 200 "${W}/user.json")"; end_suite ;; esac
USER_ID="$(jqr '.id // .user.id // empty' < "${W}/user.json")"

# login [<cookie-jar>] -> login body (access_token, refresh_token)
login(){
  local jar=()
  [ -n "${1:-}" ] && jar=(-c "$1")
  curl -s --max-time 15 "${jar[@]}" -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$USER_NAME" --arg p "$USER_PASS" '{username:$u,password:$p}')" 2>/dev/null || true
}
# refresh <refresh-token> <out-file> -> HTTP code; body in <out-file>
refresh(){
  curl -s -o "$2" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/auth/refresh" \
    -H 'Content-Type: application/json' -d "$(jq -nc --arg r "$1" '{refresh_token:$r}')" 2>/dev/null || true
}
# family_of <jwt> -> the family_id claim (empty when absent)
family_of(){ python3 -I -c '
import base64, json, sys
p = sys.argv[1].split(".")[1]; p += "=" * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p)).get("family_id", ""))
' "$1" 2>/dev/null || true; }
# unrevoked <family-id> -> count of live jti rows in that family
unrevoked(){
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT COUNT(*) FROM refresh_token_jti WHERE family_id = '$1' AND revoked_at IS NULL" 2>/dev/null | tr -d '[:space:]'
}

# expect_revoked <label> <refresh-token>: the refresh token is dead and its
# family has no live jti rows.
expect_revoked(){
  local label="$1" rt="$2" fid code
  fid="$(family_of "$rt")"
  code="$(refresh "$rt" "${W}/refresh.json")"
  note "${label}: refresh after logout -> ${code} $(head -c 120 "${W}/refresh.json")"
  [ "$code" = "401" ] || fail_g "${label}: the session's refresh token still refreshes after logout (HTTP ${code}, expected 401)"
  [ -z "$(jqr '.access_token // empty' < "${W}/refresh.json")" ] || fail_g "${label}: the refresh after logout minted an access token"
  if [ -z "$fid" ]; then
    fail_g "${label}: the refresh token carries no family_id"
  else
    local n; n="$(unrevoked "$fid")"
    note "${label}: unrevoked jti rows in family ${fid}: ${n}"
    [ "$n" = "0" ] || fail_g "${label}: ${n:-?} refresh_token_jti row(s) of the session's family are still unrevoked"
  fi
}

# logout_code <out-file> <curl args...> -> HTTP code
logout_code(){
  local out="$1"; shift
  curl -s -o "$out" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/auth/logout" "$@" 2>/dev/null || true
}

begin_suite "auth-logout-revokes-session"

# -----------------------------------------------------------------------------
begin_test "FIX #4831 shape A: a bearer logout with an empty JSON body revokes the session's refresh-token family"
reset_case
L="$(login)"; AT="$(jqr '.access_token // empty' <<<"$L")"; RT="$(jqr '.refresh_token // empty' <<<"$L")"
if [ -z "$AT" ] || [ -z "$RT" ]; then
  fail_g "login did not return a token pair: $(head -c 200 <<<"$L")"
else
  c="$(refresh "$RT" "${W}/pre.json")"
  # A refresh rotates the pair; continue with the rotated tokens so the
  # logout presents a live session.
  [ "$c" = "200" ] || fail_g "precondition: the fresh refresh token did not refresh (${c})"
  AT="$(jqr '.access_token // empty' < "${W}/pre.json")"; RT="$(jqr '.refresh_token // empty' < "${W}/pre.json")"
  c="$(logout_code "${W}/lo.json" -H "Authorization: Bearer ${AT}" -H 'Content-Type: application/json' -d '{}')"
  [ "$c" = "200" ] || fail_g "logout answered ${c}"
  expect_revoked "shape A" "$RT"
fi
finish_case "#4831: a bearer logout with an empty body leaves the session's refresh token working"

# -----------------------------------------------------------------------------
begin_test "FIX #4831 shape D: a browser logout (the login's cookie jar, no body) revokes the session's refresh-token family"
reset_case
JAR="${W}/jar-d.txt"
L="$(login "$JAR")"; RT="$(jqr '.refresh_token // empty' <<<"$L")"
if [ -z "$RT" ] || ! grep -q 'ak_access_token' "$JAR"; then
  fail_g "login did not set the session cookies: $(head -c 200 <<<"$L")"
else
  note "cookie jar: $(awk '!/^#/ && NF {print $6" path="$3}' "$JAR" | tr '\n' ' ')"
  c="$(logout_code "${W}/lo.json" -b "$JAR")"
  [ "$c" = "200" ] || fail_g "logout answered ${c}"
  expect_revoked "shape D" "$RT"
fi
finish_case "#4831: a browser logout leaves the session's refresh token working"

# -----------------------------------------------------------------------------
begin_test "CONTROL shape B: a bearer logout carrying the refresh token in the body revokes the family (GHSA-965p shape)"
reset_case
L="$(login)"; AT="$(jqr '.access_token // empty' <<<"$L")"; RT="$(jqr '.refresh_token // empty' <<<"$L")"
c="$(logout_code "${W}/lo.json" -H "Authorization: Bearer ${AT}" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg r "$RT" '{refresh_token:$r}')")"
[ "$c" = "200" ] || fail_g "logout answered ${c}"
expect_revoked "shape B" "$RT"
finish_case "a logout carrying the refresh token does not revoke it"

# -----------------------------------------------------------------------------
begin_test "CONTROL shape C: a bearer logout with the refresh token in the ak_refresh_token cookie revokes the family"
reset_case
L="$(login)"; AT="$(jqr '.access_token // empty' <<<"$L")"; RT="$(jqr '.refresh_token // empty' <<<"$L")"
c="$(logout_code "${W}/lo.json" -H "Authorization: Bearer ${AT}" -H "Cookie: ak_refresh_token=${RT}")"
[ "$c" = "200" ] || fail_g "logout answered ${c}"
expect_revoked "shape C" "$RT"
finish_case "a logout with the refresh cookie does not revoke it"

# -----------------------------------------------------------------------------
begin_test "CONTROL: replaying a rotated refresh token is refused"
reset_case
L="$(login)"; RT="$(jqr '.refresh_token // empty' <<<"$L")"
c1="$(refresh "$RT" "${W}/r1.json")"
c2="$(refresh "$RT" "${W}/r2.json")"
note "first refresh ${c1}, replay ${c2}"
[ "$c1" = "200" ] || fail_g "the first refresh answered ${c1}"
[ "$c2" = "401" ] || fail_g "the replayed refresh token answered ${c2}, expected 401"
finish_case "a rotated refresh token can be replayed"

# -----------------------------------------------------------------------------
begin_test "CONTROL: logging out one session (bearer, empty body) leaves another session of the same user refreshing"
reset_case
L1="$(login)"; AT1="$(jqr '.access_token // empty' <<<"$L1")"; RT1="$(jqr '.refresh_token // empty' <<<"$L1")"
L2="$(login)"; RT2="$(jqr '.refresh_token // empty' <<<"$L2")"
F1="$(family_of "$RT1")"; F2="$(family_of "$RT2")"
[ -n "$F1" ] && [ "$F1" != "$F2" ] || fail_g "the two logins did not get distinct refresh-token families (${F1} / ${F2})"
c="$(logout_code "${W}/lo.json" -H "Authorization: Bearer ${AT1}" -H 'Content-Type: application/json' -d '{}')"
[ "$c" = "200" ] || fail_g "logout answered ${c}"
c="$(refresh "$RT2" "${W}/s2.json")"
note "session 2 refresh after session 1 logout: ${c}; unrevoked rows in its family: $(unrevoked "$F2")"
[ "$c" = "200" ] || fail_g "the other session's refresh token answered ${c}, expected 200 (logout must be per session)"
[ -n "$(jqr '.access_token // empty' < "${W}/s2.json")" ] || fail_g "the other session's refresh minted no access token"
finish_case "logout of one session revoked another session"

if [ -n "$USER_ID" ]; then
  curl -s -o /dev/null --max-time 15 -X DELETE -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE}/api/v1/users/${USER_ID}" || true
fi
end_suite
