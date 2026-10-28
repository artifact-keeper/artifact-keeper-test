#!/usr/bin/env bash
# =============================================================================
# tiers/ci-oidc-provider-token-ttl/oracle.sh
#   #5054  the per-provider token_ttl_secs: default 900, 60..3600, enforced on
#          create and update, and it is the lifetime the exchange mints.
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, TRIVY_PORT (the mock issuer's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${RUN_ID:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
AUD="ak-dtf-${SUF}"
PROJ="dtf/ttl-${SUF}"

WORK="$(mktemp -d -t dtf-ciot-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

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
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || echo "?"; }
now() { date +%s; }
claims() { # ISS -> GitHub-shaped claims, exp now+300
  local n; n="$(now)"
  jq -cn --arg iss "$1" --arg sub "repo:${PROJ}:ref:refs/heads/main" --arg repo "$PROJ" --arg aud "$AUD" \
    --argjson iat "$n" --argjson exp "$((n + 300))" \
    '{iss:$iss, aud:$aud, sub:$sub, repository:$repo, iat:$iat, nbf:$iat, exp:$exp}'
}
jwt() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -X POST "${MOCK}/mint" -H 'Content-Type: application/json' \
    -d "{\"claims\":$1}" 2>/dev/null || true
}
# expires_in_for ISS -> expires_in of a fresh exchange ("" on failure)
expires_in_for() {
  local code
  code="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $(jwt "$(claims "$1")")" "${BASE_URL}/api/v1/auth/ci/token" 2>/dev/null || echo 000)"
  [ "$code" = "200" ] && jr '.expires_in // empty'
}
# mk_provider NAME ISSUER [TTL_JSON_FRAGMENT] -> HTTP code; id via jr
mk_provider() {
  req POST /api/v1/admin/ci-oidc "$ADMIN_TOKEN" \
    "{\"name\":\"$1\",\"provider_type\":\"github\",\"issuer_url\":\"$2\",\"audience\":\"${AUD}\"${3:+,$3}}"
}
mk_mapping() {
  req POST "/api/v1/admin/ci-oidc/$1/mappings" "$ADMIN_TOKEN" \
    "{\"name\":\"$2\",\"claim_filters\":{\"repository\":\"${PROJ}\"}}"
}
near() { [ -n "$1" ] && [ "$1" -ge $(( $2 - 5 )) ] && [ "$1" -le "$2" ]; }

FAILS=0
DETAIL=""
gate(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# =============================================================================
begin_suite "ci-oidc-provider-token-ttl"

begin_test "setup: mock issuer up"
auth_admin
[ "$(curl -s "${CURL_TIMEOUT_ARGS[@]}" "${MOCK}/__readyz" 2>/dev/null)" = "ok" ] || { infra_fail "mock issuer not ready"; end_suite; }
pass

begin_test "FIX #5054: a provider without token_ttl_secs reports 900 and mints a 900 s token from a 300 s assertion"
reset_case
ISS_D="https://mock-ci-oidc/ttl-d-${SUF}"
code="$(mk_provider "ciot-d-${SUF}" "$ISS_D")"; PD="$(jr '.id // empty')"; ttl="$(jr '.token_ttl_secs // "absent"')"
note "create: ${code} token_ttl_secs=${ttl}"
is_2xx "$code" && [ -n "$PD" ] || gate "create answered ${code}: $(snip)"
[ "$ttl" = "900" ] || gate "token_ttl_secs is '${ttl}', expected 900"
is_2xx "$(mk_mapping "$PD" "ciot-md-${SUF}")" || gate "mapping: $(snip)"
got="$(expires_in_for "$ISS_D")"; note "exchange expires_in=${got}"
near "$got" 900 || gate "expires_in=${got}, expected 895..900"
finish_case "the default provider TTL is not 900 s"

begin_test "FIX #5054: token_ttl_secs 1800 on create is stored and is the minted lifetime"
reset_case
ISS_L="https://mock-ci-oidc/ttl-l-${SUF}"
code="$(mk_provider "ciot-l-${SUF}" "$ISS_L" '"token_ttl_secs":1800')"; PL="$(jr '.id // empty')"
note "create 1800: ${code} token_ttl_secs=$(jr '.token_ttl_secs // "absent"')"
is_2xx "$code" && [ -n "$PL" ] && [ "$(jr '.token_ttl_secs')" = "1800" ] || gate "create with 1800 answered ${code}: $(snip)"
is_2xx "$(mk_mapping "$PL" "ciot-ml-${SUF}")" || gate "mapping: $(snip)"
got="$(expires_in_for "$ISS_L")"; note "exchange expires_in=${got}"
near "$got" 1800 || gate "expires_in=${got}, expected 1795..1800"
finish_case "a provider's token_ttl_secs is not the minted lifetime"

begin_test "FIX #5054: token_ttl_secs outside 60..3600 is refused with 400 on create (no row) and update (value kept)"
reset_case
for bad in 59 3601 86400; do
  name="ciot-bad${bad}-${SUF}"
  code="$(mk_provider "$name" "https://mock-ci-oidc/ttl-bad-${SUF}" "\"token_ttl_secs\":${bad}")"
  note "create ${bad}: ${code} $(jr '.message // empty' | head -c 100)"
  [ "$code" = "400" ] || gate "create with token_ttl_secs ${bad} answered ${code}, expected 400"
  [ "$(db "SELECT count(*) FROM ci_oidc_providers WHERE name = '${name}'")" = "0" ] || gate "a provider was written for ${bad}"
  code="$(req PUT "/api/v1/admin/ci-oidc/${PL}" "$ADMIN_TOKEN" "{\"token_ttl_secs\":${bad}}")"
  note "update to ${bad}: ${code}"
  [ "$code" = "400" ] || gate "update to token_ttl_secs ${bad} answered ${code}, expected 400"
done
req GET "/api/v1/admin/ci-oidc/${PL}" "$ADMIN_TOKEN" >/dev/null
[ "$(jr '.token_ttl_secs')" = "1800" ] || gate "after refused updates token_ttl_secs is '$(jr '.token_ttl_secs')', expected 1800"
finish_case "a TTL outside 60..3600 is accepted"

begin_test "FIX #5054: PUT token_ttl_secs 120 takes effect on the next exchange"
reset_case
code="$(req PUT "/api/v1/admin/ci-oidc/${PL}" "$ADMIN_TOKEN" '{"token_ttl_secs":120}')"
note "update to 120: ${code} token_ttl_secs=$(jr '.token_ttl_secs // "absent"')"
is_2xx "$code" && [ "$(jr '.token_ttl_secs')" = "120" ] || gate "update answered ${code}: $(snip)"
got="$(expires_in_for "$ISS_L")"; note "exchange expires_in=${got}"
near "$got" 120 || gate "expires_in=${got}, expected 115..120"
finish_case "an updated token_ttl_secs does not take effect"

end_suite
