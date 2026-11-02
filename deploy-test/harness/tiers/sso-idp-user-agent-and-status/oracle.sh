#!/usr/bin/env bash
# =============================================================================
# tiers/sso-idp-user-agent-and-status/oracle.sh
#   artifact-keeper#5036 (PR #5114): the SSO client sends a User-Agent to identity
#   providers and reports their HTTP errors by status.
# See the manifest for the topology and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the OIDC
# mock), NEXUS_API_PORT (the CI OIDC mock's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"; : "${DTF_SLOT:?}"
: "${TRIVY_PORT:?}"; : "${NEXUS_API_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

setup_workdir
W="$WORK_DIR"
SUF="${RUN_ID##*-}-$$"
OIDC_CTL="http://127.0.0.1:${TRIVY_PORT}"
CI_CTL="http://127.0.0.1:${NEXUS_API_PORT}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
ISSUER="http://mock-oidc"
AUD="ak-dtf-${SUF}"
PROJ="dtf/waf-${SUF}"
SCOPES='["openid","profile","email"]'

api() { # <method> <path> [json] -> HTTP code, body in $W/api.json
  local -a args=(-s -o "$W/api.json" -w '%{http_code}' --max-time 60 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "${BASE_URL}$2" 2>/dev/null || echo 000
}
mk_oidc() { # <name> <issuer> -> provider id, empty on failure
  local st
  st="$(api POST /api/v1/admin/sso/oidc "$(jq -nc --arg n "$1" --arg i "$2" --argjson s "$SCOPES" \
    '{name:$n,issuer_url:$i,client_id:$n,client_secret:"dtf-oidc-secret",scopes:$s,is_enabled:true,
      auto_create_users:true,pkce_enabled:false,map_groups_to_groups:false}')")"
  case "$st" in 2??) jq -r '.id // empty' "$W/api.json" 2>/dev/null || true ;; *) echo "" ;; esac
}
# login_redirect <provider id> -> HTTP code; the Location in $W/location, body in $W/login.body
login_redirect() {
  : > "$W/login.body"
  curl -s -o "$W/login.body" -w '%{http_code} %{redirect_url}' --max-time 60 \
    "${BASE_URL}/api/v1/auth/sso/oidc/$1/login" > "$W/login.out" 2>/dev/null || echo "000 " > "$W/login.out"
  cut -d' ' -f2- "$W/login.out" > "$W/location"
  cut -d' ' -f1 "$W/login.out"
}
# callback <provider id> <iss> -> callback HTTP code; body in $W/cb.body, headers in $W/cb.hdr
callback() {
  local st authz cb
  : > "$W/cb.body"; : > "$W/cb.hdr"
  st="$(login_redirect "$1")"
  authz="$(cat "$W/location")"
  [ -n "$authz" ] || { echo "login-${st}"; return; }
  cb="$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 30 \
    "${authz}&sub=dtf-waf-${SUF}&email=dtf-waf-${SUF}%40dtf.test&groups=&iss=$(jq -rn --arg i "$2" '$i|@uri')" 2>/dev/null || true)"
  [ -n "$cb" ] || { echo "no-authorize-redirect"; return; }
  curl -s -D "$W/cb.hdr" -o "$W/cb.body" -w '%{http_code}' --max-time 60 "$cb" 2>/dev/null || echo 000
}
backend_log() { docker logs "$BACKEND_CTR" 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' || true; }
snip() { head -c 300 "$1" 2>/dev/null | tr -d '\n' || true; }
# The backend log after line <mark>, for the cases that assert what it reports.
log_since() { backend_log | tail -n "+$(( $1 + 1 ))"; }
log_mark() { backend_log | wc -l | tr -d ' '; }
expect_reported() { # <test label> <endpoint words> <mark> <response body file>
  local lines
  lines="$(log_since "$3")"
  begin_test "$1"
  if printf '%s\n' "$lines" | grep -q "$2 returned a non-success status" \
     && printf '%s\n' "$lines" | grep -qE '\b403\b' \
     && ! printf '%s\n' "$lines" | grep -qiE 'invalid JSON|Failed to parse OIDC discovery|expected value at line 1'; then pass
  else fail "the log does not name '$2' with the 403, or reports a parse error" \
    "$(printf '%s\n' "$lines" | grep -E 'non-success status|Request error' | sed -E 's/^.*(Request error|WARN[^:]*:)/\1/' | tail -4 | cut -c1-300)"; fi
  begin_test "CONTROL: the response to that failure does not carry the IdP's block page ($2)"
  if ! grep -aq 'WAF-BLOCK-PAGE' "$4" 2>/dev/null; then pass
  else fail "the block page reached the client" "$(snip "$4")"; fi
}

begin_suite "sso-idp-user-agent-and-status"

begin_test "setup: admin login, version, both mocks refuse a request with no User-Agent"
TOK="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jq -r '.access_token // empty' 2>/dev/null || true)"
VERSION="$(curl -s --max-time 30 "${BASE_URL}/health" | jq -r '.version // empty' 2>/dev/null || true)"
no_ua="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'User-Agent:' "${OIDC_CTL}/.well-known/openid-configuration" 2>/dev/null || true)"
with_ua="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'User-Agent: dtf-probe' "${OIDC_CTL}/.well-known/openid-configuration" 2>/dev/null || true)"
if [ -z "$TOK" ] || [ -z "$VERSION" ]; then infra_fail "admin login or /health version failed"; end_suite; fi
if [ "$no_ua" = "403" ] && [ "$with_ua" = "200" ]; then pass
else infra_fail "the mock WAF is not sound: no User-Agent ${no_ua} (want 403), with ${with_ua} (want 200)"; end_suite; fi
WANT_UA="artifact-keeper/${VERSION}"

# ===========================================================================
# OIDC login behind the WAF
# ===========================================================================
P_OK="$(mk_oidc "dtf-waf-ok-${SUF}" "$ISSUER")"
P_DISC="$(mk_oidc "dtf-waf-disc-${SUF}" "${ISSUER}/block")"
P_JWKS="$(mk_oidc "dtf-waf-jwks-${SUF}" "${ISSUER}/bad-jwks")"
P_TOKEN="$(mk_oidc "dtf-waf-token-${SUF}" "${ISSUER}/bad-token")"
P_JSON="$(mk_oidc "dtf-waf-json-${SUF}" "${ISSUER}/json-token")"
begin_test "setup: OIDC providers created"
if [ -n "$P_OK" ] && [ -n "$P_DISC" ] && [ -n "$P_JWKS" ] && [ -n "$P_TOKEN" ] && [ -n "$P_JSON" ]; then pass
else infra_fail "provider create failed: '${P_OK}' '${P_DISC}' '${P_JWKS}' '${P_TOKEN}' '${P_JSON}': $(snip "$W/api.json")"; end_suite; fi

begin_test "FIX #5036: OIDC login behind the WAF redirects to the IdP"
st="$(login_redirect "$P_OK")"; loc="$(cat "$W/location")"
case "$loc" in
  "${OIDC_CTL}/authorize"*) pass ;;
  *) fail "HTTP ${st} Location '${loc}', want a redirect to ${OIDC_CTL}/authorize" "$(snip "$W/login.body")" ;;
esac

begin_test "FIX #5036: the OIDC callback behind the WAF completes the login"
st="$(callback "$P_OK" "$ISSUER")"
if { [ "$st" = "200" ] || [ "$st" = "302" ] || [ "$st" = "303" ] || [ "$st" = "307" ]; } \
   && ! grep -aqiE '"code" *: *"|error=' "$W/cb.body" \
   && ! grep -aqi '^location:.*error' "$W/cb.hdr"; then pass
else fail "callback '${st}', want a completed login" "$(snip "$W/cb.body") $(tr -d '\r' < "$W/cb.hdr" | grep -i '^location' | cut -c1-200)"; fi

begin_test "FIX #5036: discovery, token and JWKS requests to the IdP all carried ${WANT_UA}"
curl -s --max-time 10 -o "$W/seen.json" "${OIDC_CTL}/__seen" 2>/dev/null || true
# The setup's two probes are the only other requests so far: one with no
# User-Agent, one with dtf-probe. Everything else came from the backend.
sent="$(jq -c --arg ua "$WANT_UA" '{
    paths: ([.[] | select(.ua == $ua) | .path] | unique),
    no_ua: ([.[] | select(.ua == null)] | length),
    other: [.[] | select(.ua != null and .ua != $ua and .ua != "dtf-probe")]}' "$W/seen.json" 2>/dev/null || echo '{}')"
want='{"paths":["/.well-known/openid-configuration","/jwks","/token"],"no_ua":1,"other":[]}'
if [ "$sent" = "$want" ]; then pass
else fail "saw ${sent:0:400}, want ${want}" "$(head -c 800 "$W/seen.json")"; fi

mark="$(log_mark)"
st="$(login_redirect "$P_DISC")"
begin_test "CONTROL: an IdP answering 403 HTML at discovery fails the login"
case "$st" in 5??) pass ;; *) fail "HTTP ${st}, want 5xx" "$(snip "$W/login.body")" ;; esac
sleep 1
expect_reported "FIX #5036: a 403 HTML page at OIDC discovery is reported by status" "OIDC discovery" "$mark" "$W/login.body"

mark="$(log_mark)"
st="$(callback "$P_JWKS" "${ISSUER}/bad-jwks")"
sleep 1
expect_reported "FIX #5036: a 403 HTML page at the OIDC JWKS endpoint is reported by status" "OIDC JWKS endpoint" "$mark" "$W/cb.body"

mark="$(log_mark)"
st="$(callback "$P_TOKEN" "${ISSUER}/bad-token")"
sleep 1
expect_reported "FIX #5036: a 403 HTML page at the OIDC token endpoint is reported by status" "OIDC token endpoint" "$mark" "$W/cb.body"

begin_test "CONTROL: an OAuth JSON 400 from the token endpoint still names the IdP's error code"
st="$(callback "$P_JSON" "${ISSUER}/json-token")"
if grep -aq 'invalid_grant' "$W/cb.body" 2>/dev/null; then pass
else fail "callback '${st}', want a body naming invalid_grant" "$(snip "$W/cb.body")"; fi

# ===========================================================================
# CI OIDC exchange behind the WAF
# ===========================================================================
claims() { # <iss>
  local n; n="$(date +%s)"
  jq -cn --arg iss "$1" --arg sub "repo:${PROJ}:ref:refs/heads/main" --arg repo "$PROJ" --arg aud "$AUD" \
    --argjson iat "$n" --argjson exp "$((n + 300))" \
    '{iss:$iss,aud:$aud,sub:$sub,repository:$repo,ref:"refs/heads/main",iat:$iat,nbf:$iat,exp:$exp}'
}
mint() { curl -s --max-time 20 -X POST "${CI_CTL}/mint" -H 'Content-Type: application/json' -d "{\"claims\":$1}" 2>/dev/null || true; }
exchange() { # <issuer> -> HTTP code, body in $W/x.json
  curl -s -o "$W/x.json" -w '%{http_code}' --max-time 60 -X POST -H "Authorization: Bearer $(mint "$(claims "$1")")" \
    "${BASE_URL}/api/v1/auth/ci/token" 2>/dev/null || echo 000
}
mk_ci() { # <name> <issuer>
  local st id
  st="$(api POST /api/v1/admin/ci-oidc "$(jq -nc --arg n "$1" --arg i "$2" --arg a "$AUD" \
    '{name:$n,provider_type:"github",issuer_url:$i,audience:$a}')")"
  id="$(jq -r '.id // empty' "$W/api.json" 2>/dev/null || true)"
  case "$st" in 2??) ;; *) echo "provider ${1}: HTTP ${st} $(snip "$W/api.json");"; return ;; esac
  st="$(api POST "/api/v1/admin/ci-oidc/${id}/mappings" "$(jq -nc --arg n "${1}-m" --arg p "$PROJ" '{name:$n,claim_filters:{repository:$p}}')")"
  case "$st" in 2??) ;; *) echo "mapping ${1}: HTTP ${st} $(snip "$W/api.json");" ;; esac
}
ISS_OK="https://mock-ci-oidc/gh-${SUF}"
ISS_DISC="https://mock-ci-oidc/block-disc-${SUF}"
ISS_JWKS="https://mock-ci-oidc/block-jwks-${SUF}"

begin_test "setup: CI OIDC providers created"
ERR="$(mk_ci "dtf-waf-ci-ok-${SUF}" "$ISS_OK"; mk_ci "dtf-waf-ci-disc-${SUF}" "$ISS_DISC"; mk_ci "dtf-waf-ci-jwks-${SUF}" "$ISS_JWKS")"
if [ -z "$ERR" ]; then pass; else infra_fail "$ERR"; end_suite; fi

begin_test "FIX #5036: a CI OIDC exchange behind the WAF mints a token"
st="$(exchange "$ISS_OK")"
if [ "$st" = "200" ] && [ -n "$(jq -r '.access_token // empty' "$W/x.json" 2>/dev/null)" ]; then pass
else fail "HTTP ${st}, want 200 with an access_token" "$(snip "$W/x.json")"; fi

begin_test "FIX #5036: CI OIDC discovery and JWKS requests carried ${WANT_UA}"
curl -s --max-time 10 -o "$W/ci-seen.json" "${CI_CTL}/__seen" 2>/dev/null || true
got="$(jq -r --arg i "/gh-${SUF}/" --arg ua "$WANT_UA" \
  '[.[] | select(.path | startswith($i))] as $r | [($r | length > 0), ($r | map(.path | test("openid-configuration")) | any), ($r | map(.path | endswith("/jwks")) | any), ($r | all(.ua == $ua))] | all' \
  "$W/ci-seen.json" 2>/dev/null || echo false)"
if [ "$got" = "true" ]; then pass
else fail "want discovery and JWKS requests for ${ISS_OK}, all with ${WANT_UA}" "$(head -c 800 "$W/ci-seen.json")"; fi

mark="$(log_mark)"
st="$(exchange "$ISS_DISC")"
sleep 1
expect_reported "FIX #5036: a 403 HTML page at CI OIDC discovery is reported by status" "CI OIDC discovery" "$mark" "$W/x.json"

mark="$(log_mark)"
st="$(exchange "$ISS_JWKS")"
sleep 1
expect_reported "FIX #5036: a 403 HTML page at the CI OIDC JWKS endpoint is reported by status" "CI OIDC JWKS endpoint" "$mark" "$W/x.json"

end_suite
