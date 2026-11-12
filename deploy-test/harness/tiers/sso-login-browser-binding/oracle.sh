#!/usr/bin/env bash
# =============================================================================
# tiers/sso-login-browser-binding/oracle.sh -- artifact-keeper#5486
#   An OIDC or SAML sign-in, and the exchange code it produces, completes only
#   in the browser that started it.
# See the manifest for the topology and the gates.
#
# run.sh has stood up filesystem + sso=oidc and exported BASE_URL, ADMIN_PASS,
# RUN_ID, DTF_SLOT, DTF_DIR, COMMON_SH, TRIVY_PORT (the mock IdP's published
# port) and RELEASE_GATE=1.
#
# Every browser is a curl cookie jar. The OIDC flow is the headless one
# oidc-group-sync drives: GET AK login -> 307 to the mock /authorize -> the
# mock 302s to AK's callback with an opaque code -> AK redeems it at the mock
# /token server-side. The IdP step never carries a jar.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${RUN_ID:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns errexit back on. Every outcome is asserted explicitly (an
# empty grep IS the observation), so errexit would end the suite early.
set +e

setup_workdir
W="$WORK_DIR"
ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"
SUF="${RUN_ID##*-}-$$"
ISSUER="http://mock-oidc"
MOCK_URL="http://127.0.0.1:${TRIVY_PORT:-}"
SAML_PROBE="${DTF_SAML_XSW_PROBE:-${DTF_DIR:-}/harness/tiers/sso/probe/target/release/dtf-saml-xsw-probe}"
SSO="${BASE_URL}/api/v1/auth/sso"
REFUSAL_PREFIX="This sign-in was not started in this browser"

# --- helpers -----------------------------------------------------------------
snip() { head -c 300 "$1" 2>/dev/null | tr -d '\n'; }
new_jar() { : > "$W/jar-$1"; echo "$W/jar-$1"; }
# hdr_location HDR -> the Location header value
hdr_location() { grep -i '^location:' "$1" 2>/dev/null | tr -d '\r' | sed 's/^[Ll]ocation: *//' | tail -1; }
# set_cookies HDR -> every Set-Cookie line, values redacted
set_cookies() { grep -i '^set-cookie:' "$1" 2>/dev/null | tr -d '\r' | sed -E 's/=([^;]{6})[^;]*;/=\1...;/'; }
has_session_cookie() { grep -qi '^set-cookie: *ak_access_token=[^;]' "$1" 2>/dev/null; }
has_any_cookie() { grep -qi '^set-cookie:' "$1" 2>/dev/null; }
# query_param URL NAME -> decoded value
query_param() {
  python3 -c 'import sys,urllib.parse as u; q=u.parse_qs(u.urlparse(sys.argv[1]).query); print(q.get(sys.argv[2],[""])[0])' "$1" "$2"
}

# get JAR URL TAG -> status; headers $W/TAG.hdr, body $W/TAG.body. JAR "-" = none.
get() {
  local jar="$1" url="$2" tag="$3"
  local -a args=(-s --max-time 60 -D "$W/$tag.hdr" -o "$W/$tag.body" -w '%{http_code}')
  [ "$jar" != "-" ] && args+=(-b "$jar" -c "$jar")
  : > "$W/$tag.hdr"; : > "$W/$tag.body"
  curl "${args[@]}" "$url" 2>/dev/null || echo 000
}
# exchange JAR CODE TAG -> status; as get()
exchange() {
  local jar="$1" code="$2" tag="$3"
  local -a args=(-s --max-time 60 -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg c "$code" '{code:$c}')" -D "$W/$tag.hdr" -o "$W/$tag.body" -w '%{http_code}')
  [ "$jar" != "-" ] && args+=(-b "$jar" -c "$jar")
  : > "$W/$tag.hdr"; : > "$W/$tag.body"
  curl "${args[@]}" "${SSO}/exchange" 2>/dev/null || echo 000
}
# me_of TAG -> the username /auth/me reports for the access_token in $W/TAG.body
me_of() {
  local at
  at="$(jq -r '.access_token // empty' "$W/$1.body" 2>/dev/null)"
  [ -n "$at" ] || { echo ""; return; }
  curl -s --max-time 30 -H "Authorization: Bearer ${at}" "${BASE_URL}/api/v1/auth/me" \
    | jq -r '.username // empty' 2>/dev/null
}
# oidc_start JAR PID TAG [QUERY] -> the authorize URL (login headers in $W/TAG.hdr)
oidc_start() {
  local st
  st="$(get "$1" "${SSO}/oidc/$2/login${4:+?$4}" "$3")"
  [ "$st" = "307" ] || [ "$st" = "302" ] || { echo ""; return; }
  hdr_location "$W/$3.hdr"
}
# idp_login AUTHZ SUB -> AK callback URL the mock IdP sends the browser to
idp_login() {
  [ -n "$1" ] || { echo ""; return; }
  curl -s --max-time 30 -o /dev/null -w '%{redirect_url}' \
    "$1&sub=$2&email=$2%40dtf.test&groups=" 2>/dev/null
}
# exch_code TAG -> the exchange code a callback/ACS/complete response carries:
# Location ...?code= (browser) or the 64-hex line of a text/plain page (cli)
exch_code() {
  local loc
  loc="$(hdr_location "$W/$1.hdr")"
  if [ -n "$loc" ]; then query_param "http://x${loc}" code; return; fi
  grep -oE '^[0-9a-f]{64}$' "$W/$1.body" 2>/dev/null | head -1
}
# refused TAG -> 0 when the response is the browser-binding refusal
refused() {
  local code msg
  code="$(jq -r '.code // empty' "$W/$1.body" 2>/dev/null)"
  msg="$(jq -r '.message // empty' "$W/$1.body" 2>/dev/null)"
  [ "$code" = "AUTH_ERROR" ] && [[ "$msg" == "$REFUSAL_PREFIX"* ]]
}
# saml_start JAR PID TAG [QUERY] -> the AuthnRequest ID of the login
saml_start() {
  local st loc
  st="$(get "$1" "${SSO}/saml/$2/login${4:+?$4}" "$3")"
  [ "$st" = "307" ] || [ "$st" = "302" ] || { echo ""; return; }
  loc="$(hdr_location "$W/$3.hdr")"
  python3 - "$loc" <<'PY'
import sys, urllib.parse, base64, re, zlib
q = urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)
try:
    raw = base64.b64decode(q['SAMLRequest'][0])
    if not raw.lstrip().startswith(b'<'):
        raw = zlib.decompress(raw, -15)
    m = re.search(r'ID="([^"]+)"', raw.decode('utf-8', 'replace'))
    print(m.group(1) if m else "")
except Exception:
    print("")
PY
}
# saml_response RID NAMEID -> base64 signed Response answering RID
saml_response() {
  "$SAML_PROBE" craft --key "$W/idp_key.pem" --case positive --issuer "$SAML_ISS" \
    --audience artifact-keeper --request-id "$1" --name-id "$2" --groups Developers 2>/dev/null
}
# acs JAR PID B64 TAG -> status; as get()
acs() {
  local jar="$1" pid="$2" b64="$3" tag="$4"
  local -a args=(-s --max-time 60 -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "SAMLResponse=${b64}" -D "$W/$tag.hdr" -o "$W/$tag.body" -w '%{http_code}')
  [ "$jar" != "-" ] && args+=(-b "$jar" -c "$jar")
  : > "$W/$tag.hdr"; : > "$W/$tag.body"
  curl "${args[@]}" "${SSO}/saml/${pid}/acs" 2>/dev/null || echo 000
}
diag() { # TAG -> one-line status context for a fail() body
  echo "location='$(hdr_location "$W/$1.hdr" | cut -c1-120)' set-cookie=[$(set_cookies "$W/$1.hdr" | cut -c1-90 | tr '\n' ' ')] body=$(snip "$W/$1.body")"
}

begin_suite "sso-login-browser-binding"

# ---- bootstrap ---------------------------------------------------------------
begin_test "setup: admin login, mock IdP discovery, OIDC provider"
TOK="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "${ADMIN_USER:-admin}" --arg p "$ADMPASS" '{username:$u,password:$p}')" \
  | jq -r '.access_token // empty' 2>/dev/null)"
[ -n "$TOK" ] || { infra_fail "admin login to ${BASE_URL} failed"; end_suite; }
curl -s --max-time 10 "${MOCK_URL}/.well-known/openid-configuration" | jq -e '.token_endpoint' >/dev/null 2>&1 \
  || { infra_fail "mock IdP not serving discovery on ${MOCK_URL}"; end_suite; }
P_OIDC="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/admin/sso/oidc" -H "Authorization: Bearer ${TOK}" \
  -H 'Content-Type: application/json' -d "$(jq -nc --arg n "dtf-bind-${SUF}" --arg i "$ISSUER" \
  '{name:$n, issuer_url:$i, client_id:$n, client_secret:"dtf-oidc-secret", is_enabled:true,
    auto_create_users:true, pkce_enabled:true, map_groups_to_groups:false}')" | jq -r '.id // empty' 2>/dev/null)"
[ -n "$P_OIDC" ] || { infra_fail "could not create the OIDC provider"; end_suite; }
pass

# =============================================================================
# CONTROL: one browser, start to finish.
# =============================================================================
begin_test "CONTROL: an OIDC login started, called back and exchanged in one browser completes, and the token is the IdP's user"
U_CTL="dtf-bind-ctl-${SUF}"
J="$(new_jar ctl)"
CB="$(idp_login "$(oidc_start "$J" "$P_OIDC" ctl-login)" "$U_CTL")"
ST="$(get "$J" "$CB" ctl-cb)"
CODE="$(exch_code ctl-cb)"
XS="$(exchange "$J" "$CODE" ctl-x)"
ME="$(me_of ctl-x)"
if [ "$ST" = "307" ] && [ -n "$CODE" ] && has_session_cookie "$W/ctl-cb.hdr" && [ "$XS" = "200" ] && [ "$ME" = "$U_CTL" ]; then
  pass
else
  fail "callback ${ST}, exchange ${XS}, /auth/me user '${ME}' (want 307 + session cookie, 200, ${U_CTL})" "$(diag ctl-cb) | exchange: $(snip "$W/ctl-x.body")"
fi

# =============================================================================
# The binding cookie.
# =============================================================================
begin_test "FIX #5486: the OIDC login response sets ak_sso_bind_<16hex>=<64hex>; HttpOnly; SameSite=Lax; Path=/api/v1/auth/sso; Max-Age=600"
BIND="$(grep -i '^set-cookie: *ak_sso_bind_' "$W/ctl-login.hdr" | tr -d '\r' | head -1)"
if [[ "$BIND" =~ ak_sso_bind_([0-9a-f]{16})=([0-9a-f]{64}) ]] && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]:0:16}" ] \
   && grep -qi 'HttpOnly' <<<"$BIND" && grep -qi 'SameSite=Lax' <<<"$BIND" \
   && grep -qi 'Path=/api/v1/auth/sso\(;\|$\)' <<<"$BIND" && grep -qi 'Max-Age=600\b' <<<"$BIND"; then
  pass
else
  fail "no binding cookie of the documented shape on the login response" "set-cookie=[$(set_cookies "$W/ctl-login.hdr" | tr '\n' ' ')]"
fi

begin_test "FIX #5486: an unknown client value on the login URL is refused with 400"
ST="$(get - "${SSO}/oidc/${P_OIDC}/login?client=dtf-bogus" badclient)"
if [ "$ST" = "400" ]; then pass
else fail "login?client=dtf-bogus answered ${ST}, want 400 (only client=cli is accepted)" "$(diag badclient)"; fi

# =============================================================================
# OIDC callback delivered in another browser.
# =============================================================================
U_A="dtf-bind-a-${SUF}"
JA="$(new_jar a1)"; JB="$(new_jar b1)"
# Jar B has started a sign-in of its own, so it holds a binding cookie, just
# not the one for jar A's state.
oidc_start "$JB" "$P_OIDC" b1-login >/dev/null
CB_A="$(idp_login "$(oidc_start "$JA" "$P_OIDC" a1-login)" "$U_A")"

begin_test "FIX #5486: an OIDC callback for a login started in browser A, delivered in browser B, is refused 401 AUTH_ERROR and sets no cookie"
ST="$(get "$JB" "$CB_A" b1-cb)"
if [ -z "$CB_A" ]; then
  infra_fail "the mock IdP returned no callback URL for browser A's login"
elif [ "$ST" = "401" ] && refused b1-cb && ! has_any_cookie "$W/b1-cb.hdr"; then
  pass
else
  fail "callback in browser B answered ${ST}$(has_session_cookie "$W/b1-cb.hdr" && echo ' WITH a session cookie')" "$(diag b1-cb)"
fi

begin_test "FIX #5486: browser B's refusal did not consume the state: the same callback then completes in browser A"
ST="$(get "$JA" "$CB_A" a1-cb)"
if [ "$ST" = "307" ] && [ -n "$(exch_code a1-cb)" ] && has_session_cookie "$W/a1-cb.hdr"; then pass
else fail "callback in browser A answered ${ST}, want 307 /callback?code= with the session cookies" "$(diag a1-cb)"; fi

begin_test "FIX #5486: the same refusal on the per-provider path /oidc/{id}/callback (browser B holds no cookie), then browser A completes it"
JA2="$(new_jar a2)"; JB2="$(new_jar b2)"
CB_A2="$(idp_login "$(oidc_start "$JA2" "$P_OIDC" a2-login)" "$U_A")"
CB_A2="${CB_A2/\/oidc\/callback\?//oidc/${P_OIDC}/callback?}"
STB="$(get "$JB2" "$CB_A2" b2-cb)"
STA="$(get "$JA2" "$CB_A2" a2-cb)"
if [[ "$CB_A2" != *"/oidc/${P_OIDC}/callback?"* ]]; then
  infra_fail "could not build the per-provider callback URL from '${CB_A2}'"
elif [ "$STB" = "401" ] && refused b2-cb && ! has_any_cookie "$W/b2-cb.hdr" \
     && [ "$STA" = "307" ] && has_session_cookie "$W/a2-cb.hdr"; then
  pass
else
  fail "browser B ${STB} (want 401 refusal, no cookie), browser A ${STA} (want 307 + session)" "B: $(diag b2-cb) | A: $(diag a2-cb)"
fi

# =============================================================================
# Exchange code redeemed from another browser.
# =============================================================================
# A fresh login completed in browser A, so this case does not depend on the
# callback cases above.
JA3="$(new_jar a3)"; JB3="$(new_jar b3)"
CB_A3="$(idp_login "$(oidc_start "$JA3" "$P_OIDC" a3-login)" "$U_A")"
ST_A3="$(get "$JA3" "$CB_A3" a3-cb)"
CODE_A="$(exch_code a3-cb)"

begin_test "FIX #5486: an exchange code from browser A's callback POSTed from browser B is refused 401"
ST="$(exchange "$JB3" "$CODE_A" b3-x)"
if [ -z "$CODE_A" ]; then
  infra_fail "browser A's own callback (HTTP ${ST_A3}) produced no exchange code to test with" "$(diag a3-cb)"
elif [ "$ST" = "401" ] && refused b3-x && ! has_session_cookie "$W/b3-x.hdr"; then
  pass
else
  fail "exchange from browser B answered ${ST}$( [ -n "$(me_of b3-x)" ] && echo " and handed out a session for '$(me_of b3-x)'")" "$(diag b3-x)"
fi

begin_test "FIX #5486: browser B's refusal did not consume the code: browser A redeems it (200, token is A's user) and the binding cookie is expired"
ST="$(exchange "$JA3" "$CODE_A" a1-x)"
ME="$(me_of a1-x)"
if [ -n "$CODE_A" ] && [ "$ST" = "200" ] && [ "$ME" = "$U_A" ] \
   && grep -qiE '^set-cookie: *ak_sso_bind_[0-9a-f]{16}=;.*Max-Age=0' "$W/a1-x.hdr"; then
  pass
else
  fail "exchange from browser A answered ${ST}, user '${ME}' (want 200, ${U_A}, and ak_sso_bind_*=; Max-Age=0)" "$(diag a1-x)"
fi

# =============================================================================
# OIDC ?client=cli
# =============================================================================
U_C="dtf-bind-cli-${SUF}"
JC="$(new_jar cli)"; JD="$(new_jar cli-browser)"
AUTHZ_C="$(oidc_start "$JC" "$P_OIDC" cli-login "client=cli")"
CB_C="$(idp_login "$AUTHZ_C" "$U_C")"

begin_test "FIX #5486: an OIDC login with client=cli carries a state that starts with cli- and sets the binding cookie"
STATE_C="$(query_param "$AUTHZ_C" state)"
if [[ "$STATE_C" == cli-* ]] && grep -qiE '^set-cookie: *ak_sso_bind_[0-9a-f]{16}=[0-9a-f]{64}' "$W/cli-login.hdr"; then pass
else fail "state='${STATE_C:0:24}...', want a cli- prefix and an ak_sso_bind_* cookie" "$(diag cli-login)"; fi

begin_test "FIX #5486: the client=cli callback in a browser without the cookie answers 200 text/plain (no-store) with a 64-hex code and sets no cookie"
ST="$(get "$JD" "$CB_C" cli-cb)"
CODE_C="$(exch_code cli-cb)"
CT="$(grep -i '^content-type:' "$W/cli-cb.hdr" | tr -d '\r' | head -1)"
if [ "$ST" = "200" ] && [[ "$CT" == *text/plain* ]] && grep -qi '^cache-control:.*no-store' "$W/cli-cb.hdr" \
   && grep -qE '^[0-9a-f]{64}$' "$W/cli-cb.body" && ! has_any_cookie "$W/cli-cb.hdr"; then
  pass
else
  fail "client=cli callback answered ${ST} (${CT})" "$(diag cli-cb)"
fi

begin_test "FIX #5486: the client=cli exchange code is refused 401 without the login response's cookie"
ST="$(exchange - "$CODE_C" cli-x-nocookie)"
if [ -z "$CODE_C" ]; then fail "no exchange code from the client=cli callback" "$(diag cli-cb)"
elif [ "$ST" = "401" ] && refused cli-x-nocookie; then pass
else fail "cookieless exchange answered ${ST}" "$(diag cli-x-nocookie)"; fi

begin_test "FIX #5486: the client=cli exchange code redeems with the login response's cookie (200, token is the IdP's user)"
ST="$(exchange "$JC" "$CODE_C" cli-x)"
ME="$(me_of cli-x)"
if [ "$ST" = "200" ] && [ "$ME" = "$U_C" ]; then pass
else fail "exchange with the client's cookie answered ${ST}, user '${ME}' (want 200, ${U_C})" "$(diag cli-x)"; fi

# =============================================================================
# SAML
# =============================================================================
SAML_OK=1
begin_test "setup: SAML provider with a run-time IdP key (dtf-saml-xsw-probe)"
if [ ! -x "$SAML_PROBE" ]; then
  infra_fail "no SAML signer at ${SAML_PROBE} (the sso tier's dtf-saml-xsw-probe; the release gate's build-dtf-probes job provides it, or set DTF_SAML_XSW_PROBE)"
  SAML_OK=0
elif ! "$SAML_PROBE" keygen "$W" >/dev/null 2>&1; then
  infra_fail "probe keygen failed"; SAML_OK=0
else
  SAML_ISS="https://idp.dtf-bind.test/${SUF}"
  P_SAML="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/admin/sso/saml" -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' -d "$(jq -nc --arg n "dtf-bind-saml-${SUF}" --arg e "$SAML_ISS" \
    --arg c "$(cat "$W/idp_cert.pem")" \
    '{name:$n, entity_id:$e, sso_url:"https://idp.dtf-bind.test/sso", certificate:$c, sp_entity_id:"artifact-keeper",
      sign_requests:false, require_signed_assertions:true, admin_group:"dtf-never", is_enabled:true}')" \
    | jq -r '.id // empty' 2>/dev/null)"
  if [ -n "$P_SAML" ]; then pass; else infra_fail "could not create the SAML provider"; SAML_OK=0; fi
fi

if [ "$SAML_OK" = "1" ]; then
  # --- CONTROL: one browser, either shape ------------------------------------
  begin_test "CONTROL: a signed SAML response for a login started in one browser completes in it (ACS 307 + session, or ACS 303 -> /auth/sso/complete -> 307 + session)"
  U_SV="dtf-bind-saml-ctl-${SUF}"
  JS="$(new_jar saml-ctl)"
  RID="$(saml_start "$JS" "$P_SAML" s-ctl-login)"
  ST="$(acs "$JS" "$P_SAML" "$(saml_response "$RID" "$U_SV")" s-ctl-acs)"
  LOC="$(hdr_location "$W/s-ctl-acs.hdr")"
  SHAPE="?"
  if [ "$ST" = "307" ] && [[ "$LOC" == /callback\?code=* ]] && has_session_cookie "$W/s-ctl-acs.hdr"; then
    SHAPE="acs-307"; FINAL=s-ctl-acs
  elif [ "$ST" = "303" ] && [[ "$LOC" == /api/v1/auth/sso/complete\?code=* ]]; then
    STC="$(get "$JS" "${BASE_URL}${LOC}" s-ctl-complete)"
    LOC2="$(hdr_location "$W/s-ctl-complete.hdr")"
    if [ "$STC" = "307" ] && [[ "$LOC2" == /callback\?code=* ]] && has_session_cookie "$W/s-ctl-complete.hdr"; then
      SHAPE="acs-303-complete-307"; FINAL=s-ctl-complete
    fi
  fi
  if [ "$SHAPE" != "?" ]; then
    XS="$(exchange "$JS" "$(exch_code "$FINAL")" s-ctl-x)"
    ME="$(me_of s-ctl-x)"
  fi
  if [ "$SHAPE" != "?" ] && [ "$XS" = "200" ] && [ -n "$ME" ]; then
    echo "    SAML completion shape: ${SHAPE}; signed in as ${ME}"
    pass
  else
    fail "ACS ${ST} (shape ${SHAPE}), exchange ${XS:-n/a}" "acs: $(diag s-ctl-acs) | complete: $(diag s-ctl-complete 2>/dev/null)"
  fi

  # --- ACS POST delivered from another browser --------------------------------
  U_SA="dtf-bind-saml-a-${SUF}"
  JSA="$(new_jar saml-a)"; JSB="$(new_jar saml-b)"
  RID_A="$(saml_start "$JSA" "$P_SAML" s-a-login)"
  B64_A="$(saml_response "$RID_A" "$U_SA")"

  begin_test "FIX #5486: a signed SAML response for browser A's login POSTed to the ACS from browser B answers 303 to /auth/sso/complete and sets no cookie"
  ST="$(acs "$JSB" "$P_SAML" "$B64_A" s-b-acs)"
  LOC="$(hdr_location "$W/s-b-acs.hdr")"
  if [ -z "$RID_A" ] || [ -z "$B64_A" ]; then
    infra_fail "could not obtain an AuthnRequest ID or craft the signed response"
  elif [ "$ST" = "303" ] && [[ "$LOC" == /api/v1/auth/sso/complete\?code=* ]] && ! has_any_cookie "$W/s-b-acs.hdr"; then
    pass
  else
    fail "ACS from browser B answered ${ST}$(has_session_cookie "$W/s-b-acs.hdr" && echo ' WITH a session cookie')" "$(diag s-b-acs)"
  fi

  begin_test "FIX #5486: /auth/sso/complete for that code in browser B is refused 401 AUTH_ERROR and sets no cookie"
  if [[ "$LOC" == /api/v1/auth/sso/complete\?code=* ]]; then
    ST="$(get "$JSB" "${BASE_URL}${LOC}" s-b-complete)"
    if [ "$ST" = "401" ] && refused s-b-complete && ! has_any_cookie "$W/s-b-complete.hdr"; then pass
    else fail "/complete in browser B answered ${ST}" "$(diag s-b-complete)"; fi
  else
    fail "the ACS did not hand over a /auth/sso/complete URL (status above), so no completion step exists to refuse it" "$(diag s-b-acs)"
  fi

  begin_test "FIX #5486: /auth/sso/complete for that code in browser A answers 307 /callback?code= with the session cookies, and the code redeems in A"
  if [[ "$LOC" == /api/v1/auth/sso/complete\?code=* ]]; then
    ST="$(get "$JSA" "${BASE_URL}${LOC}" s-a-complete)"
    LOC2="$(hdr_location "$W/s-a-complete.hdr")"
    XS="$(exchange "$JSA" "$(exch_code s-a-complete)" s-a-x)"
    ME="$(me_of s-a-x)"
    if [ "$ST" = "307" ] && [[ "$LOC2" == /callback\?code=* ]] && has_session_cookie "$W/s-a-complete.hdr" \
       && [ "$XS" = "200" ] && [ -n "$ME" ]; then pass
    else fail "/complete in browser A ${ST}, exchange ${XS}, user '${ME}'" "$(diag s-a-complete) | $(diag s-a-x)"; fi
  else
    fail "no /auth/sso/complete URL to complete in browser A" "$(diag s-b-acs)"
  fi

  # --- SAML ?client=cli ----------------------------------------------------------
  begin_test "FIX #5486: a SAML login with client=cli has an AuthnRequest ID starting _cli-; its ACS answers 200 text/plain with the code, sets no cookie, and the code redeems only with the login's cookie"
  U_SC="dtf-bind-saml-cli-${SUF}"
  JSC="$(new_jar saml-cli)"
  RID_C="$(saml_start "$JSC" "$P_SAML" s-cli-login "client=cli")"
  ST="$(acs - "$P_SAML" "$(saml_response "$RID_C" "$U_SC")" s-cli-acs)"
  CODE_SC="$(exch_code s-cli-acs)"
  CT="$(grep -i '^content-type:' "$W/s-cli-acs.hdr" | tr -d '\r' | head -1)"
  XN="$(exchange - "$CODE_SC" s-cli-x-nocookie)"
  XS="$(exchange "$JSC" "$CODE_SC" s-cli-x)"
  ME="$(me_of s-cli-x)"
  if [[ "$RID_C" == _cli-* ]] && [ "$ST" = "200" ] && [[ "$CT" == *text/plain* ]] \
     && grep -qE '^[0-9a-f]{64}$' "$W/s-cli-acs.body" && ! has_any_cookie "$W/s-cli-acs.hdr" \
     && [ "$XN" = "401" ] && [ "$XS" = "200" ] && [ -n "$ME" ]; then
    pass
  else
    fail "request id '${RID_C:0:12}...', ACS ${ST} (${CT}), cookieless exchange ${XN} (want 401), exchange with cookie ${XS} (want 200)" "$(diag s-cli-acs)"
  fi
fi

end_suite
