#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/auth-strictness-1120/oracle.sh
#   Auth strictness fixes of 1.12.0: a Basic password with a multibyte
#   character across byte 8 (#5525), CI assertions without aud/iss and a
#   disabled SSO provider (#5482), a route's stricter Referrer-Policy (#5259).
#   See the manifest.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock CI issuer's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${DTF_SLOT}-${RUN_ID##*-}-$$"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# req <METHOD> <PATH> <TOKEN or -> [JSON body]: sets CODE and BODY.
req(){
  local m="$1" p="$2" t="$3" d="${4:-}"
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$m")
  [ "$t" != "-" ] && ca+=(-H "Authorization: Bearer ${t}")
  [ -n "$d" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$d")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}${p}")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
login(){ curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" | jqr '.access_token // empty'; }
# hdr <file> <name>: every value of a response header, comma-joined.
hdr(){ grep -i "^$2:" "$1" | cut -d: -f2- | sed 's/^ *//' | tr -d '\r' | paste -sd, -; }

begin_suite "auth-strictness-1120"

begin_test "setup: admin session"
TOK="$(login admin "$ADMIN_PASS")"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
pass

# =============================================================================
# #5525 a Basic password with a multibyte character across byte 8
# =============================================================================
R_PY="as12-pypi-${SFX}"
begin_test "CONTROL: a wrong ASCII Basic password on a private PyPI repository's simple index is 401 and the backend stays up"
reset_case
req POST /api/v1/repositories "$TOK" "$(jq -nc --arg k "$R_PY" '{key:$k,name:$k,format:"pypi",repo_type:"local",is_public:false}')"
note "create ${R_PY}: ${CODE}"
is_2xx "$CODE" || fail_g "creating ${R_PY} answered ${CODE}: ${BODY:0:160}"
c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -u 'x:12345678' "${BASE}/pypi/${R_PY}/simple/")"
note "Basic x:12345678 -> ${c}"
[ "$c" = "401" ] || fail_g "a wrong ASCII Basic password answered ${c}, expected 401"
c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -u "admin:${ADMIN_PASS}" "${BASE}/pypi/${R_PY}/simple/")"
note "Basic admin -> ${c}"
[ "$c" = "200" ] || fail_g "the admin's Basic login on the simple index answered ${c}, expected 200"
finish_case "Basic auth on a format route broken"

begin_test "FIX #5525: Basic 'x:1234567é' (é across byte 8) on /pypi/{repo}/simple/ answers 401 instead of dropping the connection"
reset_case
# eDoxMjM0NTY3w6k= is base64("x:1234567é"), the credential from the issue.
for path in "/pypi/${R_PY}/simple/" "/api/v1/repositories/${R_PY}"; do
  c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H 'Authorization: Basic eDoxMjM0NTY3w6k=' "${BASE}${path}")"; rc=$?
  note "${path}: HTTP ${c} (curl exit ${rc})"
  [ "$c" = "401" ] || fail_g "${path} answered HTTP ${c} (curl exit ${rc}; 52 = the server dropped the connection), expected 401"
done
c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "${BASE}/health")"
note "health after: ${c}"
finish_case "a multibyte Basic password panics the token lookup"

# =============================================================================
# #5482 (1) CI assertions without aud / iss
# =============================================================================
MOCK="http://127.0.0.1:${TRIVY_PORT}"
ISS="https://mock-ci-oidc/as12-${SFX}"
AUD="ak-as12-${SFX}"
PROJ="dtf/as12-${SFX}"
SUB="repo:${PROJ}:ref:refs/heads/main"
claims(){ # [jq filter applied to the full claim set]
  local n; n="$(date +%s)"
  jq -cn --arg iss "$ISS" --arg sub "$SUB" --arg repo "$PROJ" --arg aud "$AUD" --argjson n "$n" \
    '{iss:$iss, aud:$aud, sub:$sub, repository:$repo, ref:"refs/heads/main", iat:$n, nbf:$n, exp:($n + 300)}' | jq -c "${1:-.}"
}
jwt(){ curl -s --max-time 15 -X POST "${MOCK}/mint" -H 'Content-Type: application/json' -d "{\"claims\":$1}" 2>/dev/null || true; }
# xchg <assertion> [json body]: sets CODE and BODY
xchg(){
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 30 -X POST -H "Authorization: Bearer $1")
  [ -n "${2:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$2")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}/api/v1/auth/ci/token")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}

begin_test "setup: mock CI issuer, a github-type CI OIDC provider and a mapping"
reset_case
[ "$(curl -s --max-time 10 "${MOCK}/__readyz" 2>/dev/null)" = "ok" ] || { infra_fail "mock CI issuer not ready"; end_suite; }
req POST /api/v1/admin/ci-oidc "$TOK" "$(jq -nc --arg n "as12-gh-${SFX}" --arg i "$ISS" --arg a "$AUD" '{name:$n,provider_type:"github",issuer_url:$i,audience:$a}')"
CI_PID="$(jqr '.id // empty' <<<"$BODY")"
is_2xx "$CODE" && [ -n "$CI_PID" ] || { infra_fail "creating the CI provider answered ${CODE}: ${BODY:0:200}"; end_suite; }
req POST "/api/v1/admin/ci-oidc/${CI_PID}/mappings" "$TOK" "$(jq -nc --arg n "as12-m-${SFX}" --arg p "$PROJ" '{name:$n,claim_filters:{repository:$p}}')"
is_2xx "$CODE" || { infra_fail "creating the mapping answered ${CODE}: ${BODY:0:200}"; end_suite; }
echo "-- provider ${CI_PID} issuer ${ISS} audience ${AUD}"
pass

begin_test "CONTROL: a signed assertion carrying iss and aud is exchanged (with and without provider_id); a wrong aud is refused"
reset_case
xchg "$(jwt "$(claims)")"
note "iss+aud: ${CODE} token=$( [ -n "$(jqr '.access_token // empty' <<<"$BODY")" ] && echo yes || echo no)"
[ "$CODE" = "200" ] && [ -n "$(jqr '.access_token // empty' <<<"$BODY")" ] || fail_g "a well-formed assertion answered ${CODE}: ${BODY:0:160}"
xchg "$(jwt "$(claims)")" "$(jq -nc --arg p "$CI_PID" '{provider_id:$p}')"
note "iss+aud with provider_id: ${CODE}"
[ "$CODE" = "200" ] || fail_g "a well-formed assertion with provider_id answered ${CODE}: ${BODY:0:160}"
xchg "$(jwt "$(claims '.aud = "someone-else"')")"
note "aud someone-else: ${CODE}"
[ "$CODE" = "401" ] || fail_g "a wrong aud answered ${CODE}, expected 401"
finish_case "the CI OIDC exchange baseline is broken"

begin_test "FIX #5482: a signed CI assertion with no aud, aud null or aud 42 is refused with 401"
reset_case
for f in 'del(.aud)' '.aud = null' '.aud = 42'; do
  xchg "$(jwt "$(claims "$f")")"
  note "${f}: ${CODE} token=$( [ -n "$(jqr '.access_token // empty' <<<"$BODY")" ] && echo yes || echo no) ${BODY:0:100}"
  [ "$CODE" = "401" ] || fail_g "an assertion with ${f} answered ${CODE}, expected 401"
  [ -z "$(jqr '.access_token // empty' <<<"$BODY")" ] || fail_g "an assertion with ${f} was exchanged for an access token"
done
finish_case "a CI assertion without an audience is exchanged"

begin_test "FIX #5482: a signed CI assertion with no iss, sent with {provider_id}, is refused with 401"
reset_case
xchg "$(jwt "$(claims 'del(.iss)')")" "$(jq -nc --arg p "$CI_PID" '{provider_id:$p}')"
note "no iss + provider_id: ${CODE} token=$( [ -n "$(jqr '.access_token // empty' <<<"$BODY")" ] && echo yes || echo no) ${BODY:0:100}"
[ "$CODE" = "401" ] || fail_g "an assertion with no iss answered ${CODE}, expected 401"
[ -z "$(jqr '.access_token // empty' <<<"$BODY")" ] || fail_g "an assertion with no iss was exchanged for an access token"
finish_case "a CI assertion without an issuer is exchanged through provider_id"

# =============================================================================
# #5482 (2) a disabled SSO provider (LDAP)
# =============================================================================
LDAP_CONTAINER="ak-dtf${DTF_SLOT}-ldap"
LDAP_BIND_DN="cn=admin,dc=dtf,dc=local"
# The overlay's throwaway bind password, assembled so no literal is committed.
LDAP_BIND_PW="$(printf '%s%s' admin pass)"
LDAP_UID="as12-${SFX}"
LDAP_UPW="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)Aa1"
begin_test "setup: an LDAP user and an LDAP provider"
cat > "${W}/seed.ldif" <<LDIF
dn: ou=people,dc=dtf,dc=local
objectClass: organizationalUnit
ou: people

dn: uid=${LDAP_UID},ou=people,dc=dtf,dc=local
objectClass: inetOrgPerson
uid: ${LDAP_UID}
cn: AS12 User
sn: User
mail: ${LDAP_UID}@dtf.local
userPassword: ${LDAP_UPW}
LDIF
seed="$(docker exec -i "$LDAP_CONTAINER" ldapadd -c -x -H ldap://localhost:389 -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PW" < "${W}/seed.ldif" 2>&1)"
echo "$seed" | grep -q "adding new entry \"uid=${LDAP_UID}" || { infra_fail "could not seed the LDAP user: ${seed:0:300}"; end_suite; }
req POST /api/v1/admin/sso/ldap "$TOK" "$(jq -nc --arg n "as12-ldap-${SFX}" --arg b "$LDAP_BIND_DN" --arg bp "$LDAP_BIND_PW" \
  '{name:$n,server_url:"ldaps://ldap.dtf.local:636",bind_dn:$b,bind_password:$bp,user_base_dn:"dc=dtf,dc=local",user_filter:"(uid={0})",insecure_skip_verify:true}')"
LDAP_PID="$(jqr '.id // empty' <<<"$BODY")"
is_2xx "$CODE" && [ -n "$LDAP_PID" ] || { infra_fail "creating the LDAP provider answered ${CODE}: ${BODY:0:200}"; end_suite; }
echo "-- LDAP provider ${LDAP_PID} user ${LDAP_UID}"
pass
ldap_login(){ curl -s -o "${W}/ll" -w '%{http_code}' --max-time 30 -X POST -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$LDAP_UID" --arg p "$LDAP_UPW" '{username:$u,password:$p}')" "${BASE}/api/v1/auth/sso/ldap/${LDAP_PID}/login"; }

begin_test "CONTROL: the LDAP user logs in through the enabled provider; once disabled the provider leaves GET /auth/sso/providers"
reset_case
c="$(ldap_login)"
note "login (enabled): ${c} token=$( [ -n "$(jqr '.access_token // empty' "${W}/ll")" ] && echo yes || echo no)"
[ "$c" = "200" ] || fail_g "LDAP login on the enabled provider answered ${c}: $(head -c 160 "${W}/ll")"
req GET /api/v1/auth/sso/providers -
note "providers (enabled): $(jqr -c --arg i "$LDAP_PID" '[.. | objects | select(.id? == $i)] | length' <<<"$BODY")"
req PUT "/api/v1/admin/sso/ldap/${LDAP_PID}" "$TOK" '{"is_enabled":false}'
note "disable: ${CODE} is_enabled=$(jqr '.is_enabled' <<<"$BODY")"
is_2xx "$CODE" || fail_g "disabling the provider answered ${CODE}: ${BODY:0:160}"
req GET /api/v1/auth/sso/providers -
n="$(jqr -c --arg i "$LDAP_PID" '[.. | objects | select(.id? == $i)] | length' <<<"$BODY")"
note "providers (disabled): ${n}"
[ "${n:-1}" = "0" ] || fail_g "the disabled provider is still listed"
finish_case "LDAP login or provider listing broken"

begin_test "FIX #5482: LDAP login through a disabled provider is refused (404) and issues no token"
reset_case
c="$(ldap_login)"
note "login (disabled): ${c} token=$( [ -n "$(jqr '.access_token // empty' "${W}/ll")" ] && echo yes || echo no) $(head -c 120 "${W}/ll")"
[ "$c" = "404" ] || fail_g "LDAP login on the disabled provider answered ${c}, expected 404"
[ -z "$(jqr '.access_token // empty' "${W}/ll")" ] || fail_g "the disabled provider issued an access token"
finish_case "a disabled SSO provider still signs users in"

# =============================================================================
# #5259 a route's stricter Referrer-Policy survives the global layer
# =============================================================================
R_AP="as12-ap-${SFX}"
begin_test "setup: an Agent Plugins repository and an API token for its token-in-path URL"
req POST /api/v1/repositories "$TOK" "$(jq -nc --arg k "$R_AP" '{key:$k,name:$k,format:"agentplugins",repo_type:"local",is_public:false}')"
c1="$CODE"
req POST /api/v1/auth/tokens "$TOK" "$(jq -nc --arg n "as12-ap-${SFX}" '{name:$n,scopes:["read:artifacts"],expires_in_days:1}')"
AP_TOK="$(jqr '.token // .access_token // empty' <<<"$BODY")"
if ! is_2xx "$c1" || [ -z "$AP_TOK" ]; then infra_fail "agent plugins setup: repo ${c1}, token ${CODE} ${BODY:0:160}"; end_suite; fi
pass

begin_test "CONTROL: an ordinary API route carries the default Referrer-Policy; the token route answers 200 with Cache-Control private, no-store"
reset_case
curl -s -o /dev/null -D "${W}/h1" --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/repositories/${R_AP}"
note "/api/v1/repositories/{key}: referrer-policy=$(hdr "${W}/h1" referrer-policy)"
[ "$(hdr "${W}/h1" referrer-policy)" = "strict-origin-when-cross-origin" ] || fail_g "the default Referrer-Policy is $(hdr "${W}/h1" referrer-policy)"
c="$(curl -s -o "${W}/m" -D "${W}/h2" -w '%{http_code}' --max-time 30 "${BASE}/agentplugins/t/${AP_TOK}/${R_AP}/claude-marketplace.json")"
note "token route: ${c} cache-control=$(hdr "${W}/h2" cache-control) x-frame-options=$(hdr "${W}/h2" x-frame-options)"
[ "$c" = "200" ] || fail_g "the token-in-path marketplace answered ${c}: $(head -c 160 "${W}/m")"
[ "$(hdr "${W}/h2" cache-control)" = "private, no-store" ] || fail_g "the token route's Cache-Control is $(hdr "${W}/h2" cache-control)"
finish_case "security headers baseline broken"

begin_test "FIX #5259: the Agent Plugins token-in-path route keeps its Referrer-Policy: no-referrer through the global security headers"
reset_case
note "token route referrer-policy=$(hdr "${W}/h2" referrer-policy)"
[ "$(hdr "${W}/h2" referrer-policy)" = "no-referrer" ] || fail_g "the token route answered Referrer-Policy '$(hdr "${W}/h2" referrer-policy)', expected exactly no-referrer"
finish_case "the global layer overwrites the token route's Referrer-Policy"

end_suite
