#!/usr/bin/env bash
# =============================================================================
# tiers/oidc-exchange-and-login/oracle.sh -- 1.11.2 SSO/login fixes, end to end
# =============================================================================
# run.sh has stood up filesystem + sso=oidc-entra-shape and exported BASE_URL,
# DB_CONTAINER, ADMIN_USER/ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, COMMON_SH,
# TRIVY_PORT (the mock IdP's published port) and RELEASE_GATE=1.
#
# Gates (see the manifest for the bug behind each):
#   #4699  the token request carries the configured `scope`; an Entra-shaped
#          IdP then returns an id_token and the login completes; an IdP that
#          still returns none gets 502 OIDC_NO_ID_TOKEN, not 500.
#   #4143  X-Forwarded-Proto/-Host shape the OIDC redirect_uri only when the
#          TCP peer is in RATE_LIMIT_TRUSTED_PROXY_CIDRS; a plain-http
#          redirect_uri logs an operator hint.
#   #4648  the SSO exchange (and the callback's access cookie) report the
#          configured token lifetime; local login already did (control).
#   #4638  a refused private target names AK_SSRF_ALLOW_PRIVATE_CIDRS on the
#          LDAP, upstream and webhook surfaces; a metadata address never does.
#
# The headless OIDC flow is the one oidc-group-sync drives: GET AK login ->
# 307 to the mock /authorize (state, nonce, redirect_uri) -> the mock 302s back
# to AK's callback with an opaque code carrying this login's claims and its
# id_token_mode -> AK exchanges the code at the mock /token server-side.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns errexit back on. This oracle asserts on every outcome
# explicitly (a failed grep or a refused curl IS the observation), so errexit
# would end the suite at the first empty match instead of recording a FAIL.
set +e

ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"
SUF="${RUN_ID##*-}-$$"
ISSUER="http://mock-oidc"
MOCK_HOST_URL="http://127.0.0.1:${TRIVY_PORT:-}"
BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"
MOCK_NET="ak-dtf${DTF_SLOT}-mockoidcentra"
TRUSTED_PEER_IP="172.16.${DTF_SLOT}.70"    # inside 172.16.<slot>.64/28
UNTRUSTED_PEER_IP="172.16.${DTF_SLOT}.90"  # outside it
CURL_IMAGE="curlimages/curl:8.11.1"
# JWT_ACCESS_TOKEN_EXPIRY_MINUTES=37 in profiles/sso.oidc-entra-shape.yml.
TTL_SECS=2220
CONFIGURED_SCOPES='["openid","profile","email","offline_access"]'
CONFIGURED_SCOPE_STR="openid profile email offline_access"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers -----------------------------------------------------------------

# http_req METHOD URL [JSON_BODY] -> writes body to $WORK/body, headers to
# $WORK/hdr, prints the status code.
http_req() {
  local method="$1" url="$2" body="${3:-}"
  local args=(-s -X "$method" -D "$WORK/hdr" -o "$WORK/body" -w '%{http_code}')
  [ -n "${TOK:-}" ] && args+=(-H "Authorization: Bearer ${TOK}")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  curl "${args[@]}" "$url"
}

# create_oidc_provider NAME CLIENT_ID [ISSUER] -> prints status; body in $WORK/body
create_oidc_provider() {
  local body
  body=$(jq -n --arg name "$1" --arg cid "$2" --arg iss "${3:-$ISSUER}" \
    --argjson scopes "$CONFIGURED_SCOPES" \
    '{name:$name, issuer_url:$iss, client_id:$cid, client_secret:"dtf-oidc-secret",
      scopes:$scopes, is_enabled:true, auto_create_users:true, pkce_enabled:false,
      map_groups_to_groups:false}')
  http_req POST "${BASE_URL}/api/v1/admin/sso/oidc" "$body"
}

# url_query_param URL NAME -> the decoded value of NAME in URL's query string
url_query_param() {
  python3 -c 'import sys,urllib.parse as u; q=u.parse_qs(u.urlparse(sys.argv[1]).query); print(q.get(sys.argv[2],[""])[0])' "$1" "$2"
}

# drive_oidc_callback PROVIDER_ID SUB MODE -> prints the callback status; the
# callback's headers/body land in $WORK/cb_hdr / $WORK/cb_body.
drive_oidc_callback() {
  local pid="$1" sub="$2" mode="$3" authz cb
  : >"$WORK/cb_hdr"; : >"$WORK/cb_body"
  authz=$(curl -s -o "$WORK/login_body" -w '%{redirect_url}' \
    "${BASE_URL}/api/v1/auth/sso/oidc/${pid}/login")
  [ -z "$authz" ] && { echo "000-no-login-redirect"; return; }
  cb=$(curl -s -o "$WORK/authz_body" -w '%{redirect_url}' \
    "${authz}&sub=${sub}&email=${sub}%40dtf.test&groups=&id_token_mode=${mode}")
  [ -z "$cb" ] && { echo "000-no-authorize-redirect"; return; }
  curl -s -D "$WORK/cb_hdr" -o "$WORK/cb_body" -w '%{http_code}' "$cb"
}

# token_request_for CLIENT_ID -> the LAST recorded /token form for that client
token_request_for() {
  curl -s "${MOCK_HOST_URL}/__requests" \
    | jq -c --arg cid "$1" '[.[] | select(.client_id == $cid)] | last // empty'
}

# peer_login_redirect PEER_IP PROVIDER_ID -> the authorize Location AK returns
# to a request made from PEER_IP (a throwaway curl container on the mock net)
# carrying spoofable forwarding headers.
peer_login_redirect() {
  docker run --rm --network "$MOCK_NET" --ip "$1" "$CURL_IMAGE" \
    -s -o /dev/null -w '%{redirect_url}' \
    -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Host: sso.example.test' \
    "http://backend:8080/api/v1/auth/sso/oidc/$2/login" 2>/dev/null
}

# setup_fail MSG [BODY] -> record a setup failure as INFRA (exit 11) and stop.
setup_fail() {
  begin_test "setup"
  infra_fail "$@"
  end_suite
}

begin_suite "oidc-exchange-and-login"

# ---- bootstrap ---------------------------------------------------------------
TOK=""
ADMIN_LOGIN_STATUS=$(http_req POST "${BASE_URL}/api/v1/auth/login" \
  "$(jq -n --arg u "${ADMIN_USER:-admin}" --arg p "$ADMPASS" '{username:$u, password:$p}')")
cp "$WORK/body" "$WORK/admin_login.json"
TOK=$(jq -r '.access_token // empty' "$WORK/admin_login.json")
if [ "$ADMIN_LOGIN_STATUS" != "200" ] || [ -z "$TOK" ]; then
  setup_fail "admin login to ${BASE_URL} failed (status ${ADMIN_LOGIN_STATUS})" \
    "$(head -c 300 "$WORK/admin_login.json")"
fi
if [ -z "${TRIVY_PORT:-}" ] \
   || ! curl -s "${MOCK_HOST_URL}/.well-known/openid-configuration" | jq -e '.token_endpoint' >/dev/null 2>&1 \
   || ! curl -s "${MOCK_HOST_URL}/__requests" | jq -e 'type == "array"' >/dev/null 2>&1; then
  setup_fail "Entra-shaped mock IdP not serving discovery + /__requests on ${MOCK_HOST_URL}"
fi
if ! docker image inspect "$CURL_IMAGE" >/dev/null 2>&1 && ! docker pull -q "$CURL_IMAGE" >/dev/null 2>&1; then
  setup_fail "cannot obtain ${CURL_IMAGE} for the in-network peer probes"
fi

P1_CID="dtf-entra-${SUF}"
P1_NAME="dtf-entra-${SUF}"
ST=$(create_oidc_provider "$P1_NAME" "$P1_CID")
P1=$(jq -r '.id // empty' "$WORK/body")
[ "$ST" = "200" ] || [ "$ST" = "201" ] || P1=""
[ -n "$P1" ] || setup_fail "could not create the Entra-shaped OIDC provider (status ${ST})" "$(head -c 300 "$WORK/body")"

P2_CID="dtf-noidt-${SUF}"
P2_NAME="dtf-noidt-${SUF}"
ST=$(create_oidc_provider "$P2_NAME" "$P2_CID")
P2=$(jq -r '.id // empty' "$WORK/body")
[ "$ST" = "200" ] || [ "$ST" = "201" ] || P2=""
[ -n "$P2" ] || setup_fail "could not create the no-id_token OIDC provider (status ${ST})" "$(head -c 300 "$WORK/body")"

# =============================================================================
# #4648 control: local login already reported the lifetime before the fix.
# =============================================================================
begin_test "CONTROL #4648: POST /auth/login reports expires_in=${TTL_SECS} (JWT_ACCESS_TOKEN_EXPIRY_MINUTES=37) and token_type Bearer"
LL_EXP=$(jq -r '.expires_in // "absent"' "$WORK/admin_login.json")
LL_TT=$(jq -r '.token_type // "absent"' "$WORK/admin_login.json")
if [ "$LL_EXP" = "$TTL_SECS" ] && [ "$LL_TT" = "Bearer" ]; then
  pass
else
  fail "local login lifetime not reported as configured (expires_in=${LL_EXP} token_type=${LL_TT})" \
       "expected expires_in=${TTL_SECS}; the profile sets JWT_ACCESS_TOKEN_EXPIRY_MINUTES=37"
fi

# =============================================================================
# #4699 control: an IdP that always returns an id_token logs in on any image.
# =============================================================================
begin_test "CONTROL #4699: OIDC login against an IdP that always returns an id_token completes (307 to /callback?code=)"
ST=$(drive_oidc_callback "$P1" "ctl-${SUF}" always)
LOC=$(grep -i '^location:' "$WORK/cb_hdr" | tr -d '\r' | sed 's/^[Ll]ocation: *//')
CTL_CODE=$(url_query_param "http://x${LOC}" code)
if [ "$ST" = "307" ] && [ -n "$CTL_CODE" ]; then
  pass
else
  fail "control OIDC login failed (callback status ${ST}, location '${LOC}')" "$(head -c 400 "$WORK/cb_body")"
fi

# cookie_max_age HEADER_FILE -> Max-Age of the ak_access_token Set-Cookie
cookie_max_age() {
  grep -i '^set-cookie: *ak_access_token=' "$1" | tr -d '\r' | sed -n 's/.*Max-Age=\([0-9]*\).*/\1/p' | head -1
}

begin_test "CONTROL #4648: the OIDC callback's ak_access_token cookie Max-Age equals the configured lifetime (${TTL_SECS})"
COOKIE_AGE=$(cookie_max_age "$WORK/cb_hdr")
if [ -n "$COOKIE_AGE" ] && [ "$COOKIE_AGE" -le "$TTL_SECS" ] && [ "$COOKIE_AGE" -ge $((TTL_SECS - 30)) ]; then
  pass
else
  fail "callback access cookie Max-Age='${COOKIE_AGE}', expected within 30 s of ${TTL_SECS}" \
       "$(grep -i '^set-cookie' "$WORK/cb_hdr" | sed 's/=[^;]*;/=<redacted>;/' | head -2)"
fi

# =============================================================================
# #4699: the token request carries the configured scopes; the Entra-shaped IdP
# then returns an id_token and the login completes.
# =============================================================================
begin_test "#4699: OIDC login against an Entra-shaped IdP (id_token only when the token request asks for openid) completes"
ST=$(drive_oidc_callback "$P1" "entra-${SUF}" entra)
LOC=$(grep -i '^location:' "$WORK/cb_hdr" | tr -d '\r' | sed 's/^[Ll]ocation: *//')
EX_CODE=$(url_query_param "http://x${LOC}" code)
if [ "$ST" = "307" ] && [ -n "$EX_CODE" ]; then
  pass
else
  fail "Entra-shaped login did not complete (callback status ${ST})" \
       "body: $(head -c 400 "$WORK/cb_body"). Before #4699 the token request had no scope, the IdP sent no id_token and the callback answered 500."
fi

begin_test "#4699: the recorded /token request carries scope='${CONFIGURED_SCOPE_STR}' (the provider's configured scopes)"
TREQ=$(token_request_for "$P1_CID")
T_SCOPE=$(printf '%s' "$TREQ" | jq -r 'if has("scope") then .scope else "<absent>" end' 2>/dev/null)
T_GRANT=$(printf '%s' "$TREQ" | jq -r '.grant_type // empty' 2>/dev/null)
if [ -z "$TREQ" ]; then
  fail "the mock recorded no /token request for client_id ${P1_CID}"
elif [ "$T_GRANT" = "authorization_code" ] && [ "$T_SCOPE" = "$CONFIGURED_SCOPE_STR" ]; then
  pass
else
  fail "token request scope='${T_SCOPE}' grant_type='${T_GRANT}', expected scope='${CONFIGURED_SCOPE_STR}'" \
       "recorded form keys: $(printf '%s' "$TREQ" | jq -c 'keys')"
fi

# =============================================================================
# #4648: the SSO exchange reports the token lifetime.
# =============================================================================
begin_test "#4648: POST /auth/sso/exchange reports expires_in (~${TTL_SECS} s) and a usable access token"
if [ -z "$EX_CODE" ]; then
  # The Entra-shaped login failed (see above); fall back to the control
  # login's code so this gate still judges the exchange on its own.
  EX_CODE="$CTL_CODE"
fi
if [ -z "$EX_CODE" ]; then
  : >"$WORK/hdr"
  fail "no exchange code: neither OIDC login reached /callback?code="
else
  SAVED_TOK="$TOK"; TOK=""
  ST=$(http_req POST "${BASE_URL}/api/v1/auth/sso/exchange" "$(jq -n --arg c "$EX_CODE" '{code:$c}')")
  TOK="$SAVED_TOK"
  EXP=$(jq -r 'if has("expires_in") then .expires_in else "absent" end' "$WORK/body" 2>/dev/null)
  SSO_AT=$(jq -r '.access_token // empty' "$WORK/body" 2>/dev/null)
  ME_ST="n/a"
  [ -n "$SSO_AT" ] && ME_ST=$(curl -s -o "$WORK/me" -w '%{http_code}' -H "Authorization: Bearer ${SSO_AT}" "${BASE_URL}/api/v1/auth/me")
  if [ "$ST" = "200" ] && [ "$ME_ST" = "200" ] && [[ "$EXP" =~ ^[0-9]+$ ]] \
     && [ "$EXP" -le "$TTL_SECS" ] && [ "$EXP" -ge $((TTL_SECS - 30)) ]; then
    pass
  else
    fail "exchange status=${ST} expires_in=${EXP} /auth/me with the SSO token=${ME_ST}" \
         "expected 200, expires_in within 30 s of ${TTL_SECS}, and a working token; body keys: $(jq -c 'keys' "$WORK/body" 2>/dev/null)"
  fi
fi

begin_test "#4648: the exchange's ak_access_token cookie Max-Age matches the token lifetime (~${TTL_SECS} s), not a hardcoded 3600"
EX_COOKIE_AGE=$(cookie_max_age "$WORK/hdr")
if [ -n "$EX_COOKIE_AGE" ] && [ "$EX_COOKIE_AGE" -le "$TTL_SECS" ] && [ "$EX_COOKIE_AGE" -ge $((TTL_SECS - 30)) ]; then
  pass
else
  fail "exchange access cookie Max-Age='${EX_COOKIE_AGE}', expected within 30 s of ${TTL_SECS}" \
       "a cookie that outlives the JWT keeps a dead session in the browser"
fi

# =============================================================================
# #4699: an IdP that never returns an id_token gets a 502 naming the provider.
# =============================================================================
begin_test "#4699: a token response without id_token answers 502 OIDC_NO_ID_TOKEN naming the provider (not 500 INTERNAL_ERROR)"
ST=$(drive_oidc_callback "$P2" "noidt-${SUF}" never)
E_CODE=$(jq -r '.code // empty' "$WORK/cb_body" 2>/dev/null)
E_MSG=$(jq -r '.message // empty' "$WORK/cb_body" 2>/dev/null)
if [ "$ST" = "502" ] && [ "$E_CODE" = "OIDC_NO_ID_TOKEN" ] \
   && [[ "$E_MSG" == *"$P2_NAME"* ]] && [[ "$E_MSG" == *"id_token"* ]]; then
  pass
else
  fail "callback without id_token answered ${ST} code='${E_CODE}'" "message: ${E_MSG:0:300}"
fi

# =============================================================================
# #4143: forwarding headers only from a trusted peer.
# =============================================================================
begin_test "CONTROL #4143: a TRUSTED peer (${TRUSTED_PEER_IP}, in RATE_LIMIT_TRUSTED_PROXY_CIDRS) with X-Forwarded-Proto/Host gets redirect_uri https://sso.example.test/..."
LOC_T=$(peer_login_redirect "$TRUSTED_PEER_IP" "$P1")
RU_T=$(url_query_param "$LOC_T" redirect_uri)
if [ -z "$LOC_T" ]; then
  infra_fail "the trusted-peer probe container got no redirect from http://backend:8080 on ${MOCK_NET}"
elif [ "$RU_T" = "https://sso.example.test/api/v1/auth/sso/oidc/callback" ]; then
  pass
else
  fail "trusted peer redirect_uri='${RU_T}'" "expected https://sso.example.test/api/v1/auth/sso/oidc/callback"
fi

begin_test "#4143: an UNTRUSTED peer (${UNTRUSTED_PEER_IP}) sending the same headers gets redirect_uri http://backend:8080/... (headers ignored)"
LOC_U=$(peer_login_redirect "$UNTRUSTED_PEER_IP" "$P1")
RU_U=$(url_query_param "$LOC_U" redirect_uri)
if [ -z "$LOC_U" ]; then
  infra_fail "the untrusted-peer probe container got no redirect from http://backend:8080 on ${MOCK_NET}"
elif [ "$RU_U" = "http://backend:8080/api/v1/auth/sso/oidc/callback" ]; then
  pass
else
  fail "untrusted peer redirect_uri='${RU_U}'" \
       "expected http://backend:8080/api/v1/auth/sso/oidc/callback: X-Forwarded-* from a peer outside RATE_LIMIT_TRUSTED_PROXY_CIDRS must not steer the redirect_uri"
fi

begin_test "#4143: a request-derived plain-http redirect_uri logs the operator hint naming the provider, AK_EXTERNAL_URL and X-Forwarded-Proto"
HINT=$(docker logs "$BACKEND_CONTAINER" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' \
  | grep -F "was derived from the request and is plain http" | grep -F "$P1_NAME" | tail -1)
if [ -n "$HINT" ] && [[ "$HINT" == *AK_EXTERNAL_URL* ]] && [[ "$HINT" == *X-Forwarded-Proto* ]]; then
  pass
else
  fail "no plain-http redirect_uri hint for provider ${P1_NAME} in docker logs ${BACKEND_CONTAINER}"
fi

# =============================================================================
# #4638: refusals of a private target name AK_SSRF_ALLOW_PRIVATE_CIDRS.
# =============================================================================
# refusal_case LABEL METHOD PATH JSON -> asserts 400 whose message names the
# allowlist setting with the refused address as the example.
refusal_case() {
  local label="$1" path="$2" body="$3" st msg
  begin_test "#4638: ${label} at 10.10.10.10 is refused with a 400 that names AK_SSRF_ALLOW_PRIVATE_CIDRS"
  st=$(http_req POST "${BASE_URL}${path}" "$body")
  msg=$(jq -r '.message // .error // empty' "$WORK/body" 2>/dev/null)
  if [ "$st" = "400" ] && [[ "$msg" == *"AK_SSRF_ALLOW_PRIVATE_CIDRS=10.10.10.10"* ]]; then
    pass
  else
    fail "${label}: status=${st}" "message: ${msg:0:400}"
  fi
}

refusal_case "LDAP server_url ldap://10.10.10.10:389" "/api/v1/admin/sso/ldap" \
  "$(jq -n --arg n "dtf-ldap-${SUF}" '{name:$n, server_url:"ldap://10.10.10.10:389", user_base_dn:"dc=dtf,dc=test", is_enabled:false}')"
refusal_case "remote repository upstream_url http://10.10.10.10/simple/" "/api/v1/repositories" \
  "$(jq -n --arg k "dtf-rem-${SUF}" '{key:$k, name:$k, format:"pypi", repo_type:"remote", upstream_url:"http://10.10.10.10/simple/", is_public:false}')"
refusal_case "webhook url http://10.10.10.10/hook" "/api/v1/webhooks" \
  "$(jq -n --arg n "dtf-hook-${SUF}" '{name:$n, url:"http://10.10.10.10/hook", events:["artifact_uploaded"]}')"

begin_test "CONTROL #4638: an OIDC issuer at 10.10.10.10 is refused (400) naming AK_SSRF_ALLOW_PRIVATE_CIDRS (the SSO surface already did)"
ST=$(create_oidc_provider "dtf-priv-${SUF}" "dtf-priv-${SUF}" "http://10.10.10.10/")
MSG=$(jq -r '.message // empty' "$WORK/body" 2>/dev/null)
if [ "$ST" = "400" ] && [[ "$MSG" == *AK_SSRF_ALLOW_PRIVATE_CIDRS* ]]; then
  pass
else
  fail "private OIDC issuer: status=${ST}" "message: ${MSG:0:400}"
fi

begin_test "#4638: an OIDC issuer at the metadata address 169.254.169.254 is refused WITHOUT advertising AK_SSRF_ALLOW_PRIVATE_CIDRS (it can never be admitted)"
ST=$(create_oidc_provider "dtf-meta-${SUF}" "dtf-meta-${SUF}" "http://169.254.169.254/")
MSG=$(jq -r '.message // empty' "$WORK/body" 2>/dev/null)
if [ "$ST" = "400" ] && [[ "$MSG" != *AK_SSRF_ALLOW_PRIVATE_CIDRS* ]] && [[ "$MSG" != *SSO_ALLOW_PRIVATE_IPS* ]]; then
  pass
else
  fail "metadata OIDC issuer: status=${ST}" "message: ${MSG:0:400}"
fi

begin_test "CONTROL #4638: an OIDC provider with a public https issuer saves"
ST=$(create_oidc_provider "dtf-pub-${SUF}" "dtf-pub-${SUF}" "https://login.microsoftonline.com/common/v2.0")
PUB_ID=$(jq -r '.id // empty' "$WORK/body" 2>/dev/null)
if { [ "$ST" = "200" ] || [ "$ST" = "201" ]; } && [ -n "$PUB_ID" ]; then
  pass
else
  fail "public issuer refused: status=${ST}" "$(head -c 400 "$WORK/body")"
fi

end_suite
