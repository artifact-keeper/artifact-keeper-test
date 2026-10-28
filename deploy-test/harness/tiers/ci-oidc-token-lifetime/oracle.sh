#!/usr/bin/env bash
# =============================================================================
# tiers/ci-oidc-token-lifetime/oracle.sh
#   #5054  a CI OIDC exchange mints a token that lives AK's configured TTL, not
#          the CI assertion's remaining lifetime; kubernetes keeps the cap; an
#          expired assertion is still refused.
# See the manifest for the bug and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, TRIVY_PORT (the mock issuer's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${RUN_ID:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
ISS_G="https://mock-ci-oidc/gh-${SUF}"    # a github-type provider
ISS_K="https://mock-ci-oidc/k8s-${SUF}"   # a kubernetes-type provider
AUD="ak-dtf-${SUF}"
PROJ="dtf/lifetime-${SUF}"
SUB="repo:${PROJ}:ref:refs/heads/main"

WORK="$(mktemp -d -t dtf-ciol-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# req METHOD PATH TOKEN [JSON] -> HTTP code on stdout, body in $WORK/body.
req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
body() { cat "$WORK/body" 2>/dev/null || true; }
snip() { body | head -c 200 || true; }
jr() { body | jq -r "$1" 2>/dev/null || true; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
now() { date +%s; }
# claims ISS EXP_OFFSET -> a GitHub-shaped claim set, iat = now
claims() {
  local n; n="$(now)"
  jq -cn --arg iss "$1" --arg sub "$SUB" --arg repo "$PROJ" --arg aud "$AUD" \
    --argjson iat "$n" --argjson exp "$((n + $2))" \
    '{iss:$iss, aud:$aud, sub:$sub, repository:$repo, ref:"refs/heads/main", iat:$iat, nbf:$iat, exp:$exp}'
}
jwt() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -X POST "${MOCK}/mint" -H 'Content-Type: application/json' \
    -d "{\"claims\":$1}" 2>/dev/null || true
}
xchg() {
  : > "$WORK/body"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $1" "${BASE_URL}/api/v1/auth/ci/token" 2>/dev/null || echo 000
}
# jwt_exp TOKEN -> the exp claim of an AK access token (payload decoded locally)
jwt_exp() {
  local p; p="$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')"
  while [ $(( ${#p} % 4 )) -ne 0 ]; do p="${p}="; done
  printf '%s' "$p" | base64 -d 2>/dev/null | jq -r '.exp // empty' 2>/dev/null || true
}
mk_provider() { # NAME ISSUER TYPE -> HTTP code; id via jr
  req POST /api/v1/admin/ci-oidc "$ADMIN_TOKEN" \
    "{\"name\":\"$1\",\"provider_type\":\"$3\",\"issuer_url\":\"$2\",\"audience\":\"${AUD}\"}"
}
mk_mapping() { # PROVIDER_ID NAME -> HTTP code
  req POST "/api/v1/admin/ci-oidc/$1/mappings" "$ADMIN_TOKEN" \
    "{\"name\":\"$2\",\"claim_filters\":{\"repository\":\"${PROJ}\"}}"
}

FAILS=0
DETAIL=""
gate(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# =============================================================================
begin_suite "ci-oidc-token-lifetime"

begin_test "setup: mock issuer up, a github-type and a kubernetes-type provider with one mapping each"
auth_admin
SETUP_ERR=""
[ "$(curl -s "${CURL_TIMEOUT_ARGS[@]}" "${MOCK}/__readyz" 2>/dev/null)" = "ok" ] || SETUP_ERR="${SETUP_ERR} mock-issuer"
code="$(mk_provider "ciol-gh-${SUF}" "$ISS_G" github)"; PG="$(jr '.id // empty')"
is_2xx "$code" && [ -n "$PG" ] || SETUP_ERR="${SETUP_ERR} provider-gh(${code}:$(snip))"
code="$(mk_provider "ciol-k8s-${SUF}" "$ISS_K" kubernetes)"; PK="$(jr '.id // empty')"
is_2xx "$code" && [ -n "$PK" ] || SETUP_ERR="${SETUP_ERR} provider-k8s(${code}:$(snip))"
is_2xx "$(mk_mapping "$PG" "ciol-mg-${SUF}")" || SETUP_ERR="${SETUP_ERR} mapping-gh($(snip))"
is_2xx "$(mk_mapping "$PK" "ciol-mk-${SUF}")" || SETUP_ERR="${SETUP_ERR} mapping-k8s($(snip))"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- issuers ${ISS_G} ${ISS_K}; aud ${AUD}; PG=${PG} PK=${PK}"
pass

# =============================================================================
# CONTROLS (every image)
# =============================================================================
begin_test "CONTROL: an expired assertion (300 s past exp, and 30 s past exp inside the verifier's leeway) is refused with 401 and no token"
reset_case
for off in -300 -30; do
  code="$(xchg "$(jwt "$(claims "$ISS_G" "$off")")")"
  note "exp now${off}: ${code} $(jr '.message // empty' | head -c 120)"
  [ "$code" = "401" ] || gate "an assertion with exp now${off} answered ${code}, expected 401"
  [ -z "$(jr '.access_token // empty')" ] || gate "an assertion with exp now${off} returned an access_token"
done
finish_case "an expired CI assertion still exchanges"

begin_test "CONTROL: a kubernetes provider's token still expires no later than the assertion it was exchanged for"
reset_case
a_exp=$(( $(now) + 120 ))
code="$(xchg "$(jwt "$(claims "$ISS_K" 120)")")"
KT="$(jr '.access_token // empty')"; k_in="$(jr '.expires_in // empty')"; k_exp="$(jwt_exp "$KT")"
note "kubernetes exchange: ${code} expires_in=${k_in} token exp=${k_exp} assertion exp=${a_exp}"
[ "$code" = "200" ] && [ -n "$KT" ] || gate "the kubernetes exchange answered ${code}: $(snip)"
{ [ -n "$k_in" ] && [ "$k_in" -ge 1 ] && [ "$k_in" -le 120 ]; } || gate "kubernetes expires_in=${k_in}, expected 1..120"
{ [ -n "$k_exp" ] && [ "$k_exp" -le $(( a_exp + 1 )) ]; } || gate "kubernetes token exp ${k_exp} is after the assertion's ${a_exp}"
finish_case "a kubernetes CI credential outlives the ServiceAccount token it was exchanged for"

begin_test "CONTROL: the exchange returns no refresh_token"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_G" 300)")")"
note "exchange: ${code} refresh_token=$(jr '.refresh_token // "absent"' | head -c 20)"
[ "$code" = "200" ] || gate "exchange answered ${code}: $(snip)"
[ -z "$(jr '.refresh_token // empty')" ] || gate "the CI exchange returned a refresh_token"
finish_case "a CI exchange hands out a renewable session"

# =============================================================================
# FIX #5054 (RED on 1.11.8)
# =============================================================================
begin_test "FIX #5054: a GitHub-shaped assertion (exp in 300 s) mints a token that lives the configured TTL, at most 3600 s"
reset_case
now0="$(now)"
code="$(xchg "$(jwt "$(claims "$ISS_G" 300)")")"
GT="$(jr '.access_token // empty')"; g_in="$(jr '.expires_in // empty')"; g_exp="$(jwt_exp "$GT")"
note "github exchange: ${code} expires_in=${g_in} token exp-now=$(( ${g_exp:-0} - now0 ))"
[ "$code" = "200" ] && [ -n "$GT" ] || gate "the github exchange answered ${code}: $(snip)"
{ [ -n "$g_in" ] && [ "$g_in" -gt 300 ] && [ "$g_in" -le 3600 ]; } \
  || gate "expires_in=${g_in}, expected more than the assertion's 300 s and at most 3600 (1.11.8: capped at the assertion's exp)"
{ [ -n "$g_exp" ] && [ $(( g_exp - now0 )) -gt 305 ] && [ $(( g_exp - now0 )) -le 3601 ]; } \
  || gate "token exp is $(( ${g_exp:-0} - now0 )) s away, expected more than 305 and at most 3601"
finish_case "a CI token dies with the CI platform's short-lived ID token"

begin_test "FIX #5054: a token exchanged from an assertion expiring in 6 s still works 10 s later"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_G" 6)")")"
ST="$(jr '.access_token // empty')"
note "exchange with exp now+6: ${code} expires_in=$(jr '.expires_in // empty')"
[ "$code" = "200" ] && [ -n "$ST" ] || gate "the exchange answered ${code}: $(snip)"
code="$(req GET /api/v1/auth/me "$ST")"
[ "$code" = "200" ] || gate "the fresh token answered ${code} on /auth/me"
sleep 10
code="$(req GET /api/v1/auth/me "$ST")"
note "/auth/me 4 s after the assertion's exp: ${code}"
[ "$code" = "200" ] || gate "the token answered ${code} once its assertion had expired, expected 200 (1.11.8: 401)"
finish_case "a CI token stops working when its assertion expires"

end_suite
