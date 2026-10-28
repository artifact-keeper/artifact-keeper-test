#!/usr/bin/env bash
# =============================================================================
# tiers/ci-oidc-exchange/oracle.sh
#   POST /api/v1/auth/ci/token end to end against a real (mock) CI OIDC issuer:
#   a matching assertion exchanges, every mismatched claim and a bad signature
#   is refused, and the minted token carries the mapping's repository scope.
#   #4031  one mapping = one service account for every ref; principals are not
#          merged across issuers; deactivation sticks.
#   #4511  a future nbf is refused.
#   #4314  a CI credential cannot mint an API token.
#   #4663  an assertion inside the exp leeway buys no session; AK's own tokens
#          expire at exp, with no leeway.
#   #4133  a provider audience equal to the Kubernetes API server's is refused.
#   #4117  a mapping's group_binding_ids grants (and revokes) access.
# See the manifest for the bugs, the fixture and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, TRIVY_PORT (the mock issuer's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
ISS_A="https://mock-ci-oidc/a-${SUF}"     # provider PA
ISS_B="https://mock-ci-oidc/b-${SUF}"     # provider PB: same claims, other issuer
ISS_K="https://mock-ci-oidc/k-${SUF}"     # provider PK (kubernetes): the short-lived mapping
AUD="ak-dtf-${SUF}"
PROJ="dtf/app-${SUF}"                      # the repository claim M_A and M_B require
SUB_MAIN="repo:${PROJ}:ref:refs/heads/main"
SUB_TAG="repo:${PROJ}:ref:refs/tags/v1.0.0"
RA="cio-a-${SLOT}-${SUF}"; RB="cio-b-${SLOT}-${SUF}"; RG="cio-g-${SLOT}-${SUF}"
BYTES_A="cio-bytes-A-${SUF}"; BYTES_G="cio-bytes-G-${SUF}"
K8S_AUD_1="https://kubernetes.default.svc"
K8S_AUD_2="https://kubernetes.default.svc.cluster.local"

WORK="$(mktemp -d -t dtf-cio-XXXXXX)"
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
snip() { body | head -c 300 || true; }
jr() { body | jq -r "$1" 2>/dev/null || true; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
is_denied() { case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || echo "?"; }
now() { date +%s; }

# claims ISS SUB REPOSITORY EXP_OFFSET [EXTRA_JSON] -> claim set (aud = $AUD
# unless AUD_OVERRIDE is set), iat = now.
claims() {
  local n; n="$(now)"
  jq -cn --arg iss "$1" --arg sub "$2" --arg repo "$3" --arg aud "${AUD_OVERRIDE:-$AUD}" \
    --argjson iat "$n" --argjson exp "$((n + $4))" --argjson extra "${5:-{\}}" \
    '{iss:$iss, aud:$aud, sub:$sub, repository:$repo, iat:$iat, exp:$exp} + $extra'
}
# jwt CLAIMS [good|wrong] -> compact JWS signed by the mock issuer
jwt() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -X POST "${MOCK}/mint" -H 'Content-Type: application/json' \
    -d "{\"claims\":$1,\"key\":\"${2:-good}\"}" 2>/dev/null || true
}
# xchg JWT -> HTTP code of POST /auth/ci/token, body in $WORK/body
xchg() {
  : > "$WORK/body"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $1" "${BASE_URL}/api/v1/auth/ci/token" 2>/dev/null || echo 000
}
put_obj() { # REPO PATH BYTES
  printf '%s' "$3" > "$WORK/up"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" --data-binary "@$WORK/up" \
    "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" 2>/dev/null || echo 000
}
dl() { req GET "/api/v1/repositories/$1/download/obj.txt" "$2"; }
mk_repo() {
  req POST /api/v1/repositories "$ADMIN_TOKEN" \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null
  jr '.id // empty'
}
mk_provider() { # NAME ISSUER AUDIENCE [TYPE] -> HTTP code; id via jr
  req POST /api/v1/admin/ci-oidc "$ADMIN_TOKEN" \
    "{\"name\":\"$1\",\"provider_type\":\"${4:-generic}\",\"issuer_url\":\"$2\",\"audience\":\"$3\"}"
}
mk_mapping() { # PROVIDER_ID JSON -> HTTP code
  req POST "/api/v1/admin/ci-oidc/$1/mappings" "$ADMIN_TOKEN" "$2"
}
user_id_of() { db "SELECT id FROM users WHERE username = '$1'"; }
# refused CODE WHAT [WANT_CODE]: WANT_CODE (default 401) and no token in the body
refused() {
  [ "$1" = "${3:-401}" ] || gate "$2 answered $1, expected ${3:-401}: $(snip | head -c 160)"
  [ -z "$(jr '.access_token // empty')" ] || gate "$2 returned an access_token"
  return 0
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
begin_suite "ci-oidc-exchange"

begin_test "setup: mock issuer up, private repos, two providers on two issuers with identical mappings, a ceiling mapping, a short-lived mapping"
auth_admin
SETUP_ERR=""
[ "$(curl -s "${CURL_TIMEOUT_ARGS[@]}" "${MOCK}/__readyz" 2>/dev/null)" = "ok" ] || SETUP_ERR="${SETUP_ERR} mock-issuer"
RA_ID="$(mk_repo "$RA")"; RB_ID="$(mk_repo "$RB")"; RG_ID="$(mk_repo "$RG")"
[ -n "$RA_ID" ] && [ -n "$RB_ID" ] && [ -n "$RG_ID" ] || SETUP_ERR="${SETUP_ERR} repos"
for pair in "$RA|$BYTES_A" "$RB|cio-bytes-B-${SUF}" "$RG|$BYTES_G"; do
  is_2xx "$(put_obj "${pair%%|*}" obj.txt "${pair##*|}")" || SETUP_ERR="${SETUP_ERR} upload(${pair%%|*})"
done
code="$(mk_provider "cio-pa-${SUF}" "$ISS_A" "$AUD")"; PA="$(jr '.id // empty')"
is_2xx "$code" && [ -n "$PA" ] || SETUP_ERR="${SETUP_ERR} provider-A(${code}:$(snip | head -c 120))"
code="$(mk_provider "cio-pb-${SUF}" "$ISS_B" "$AUD")"; PB="$(jr '.id // empty')"
is_2xx "$code" && [ -n "$PB" ] || SETUP_ERR="${SETUP_ERR} provider-B(${code})"
FILTERS="{\"repository\":\"${PROJ}\",\"sub\":[\"${SUB_MAIN}\",\"${SUB_TAG}\"]}"
code="$(mk_mapping "$PA" "{\"name\":\"cio-ma-${SUF}\",\"claim_filters\":${FILTERS},\"allowed_repo_ids\":[\"${RA_ID}\"]}")"
MA="$(jr '.id // empty')"; MA_SA_ID="$(jr '.service_account_id // empty')"; MA_SA_NAME="$(jr '.service_account_username // empty')"
is_2xx "$code" && [ -n "$MA" ] || SETUP_ERR="${SETUP_ERR} mapping-A(${code}:$(snip | head -c 120))"
# Before any exchange: does the mapping already own an account? (#4031)
MA_ACCOUNT_AT_CREATE="$(db "SELECT count(*) FROM users WHERE external_id = 'ci:${PA}:${MA}'")"
code="$(mk_mapping "$PB" "{\"name\":\"cio-mb-${SUF}\",\"claim_filters\":${FILTERS}}")"; MB="$(jr '.id // empty')"
is_2xx "$code" && [ -n "$MB" ] || SETUP_ERR="${SETUP_ERR} mapping-B(${code})"
# The short-lived mapping lives on a kubernetes provider: since #5054 only that
# type caps the minted token at the assertion's exp, which the #4663 own-token
# case needs (every image caps a kubernetes, or pre-1.11 free-text, provider).
code="$(mk_provider "cio-pk-${SUF}" "$ISS_K" "$AUD" kubernetes)"; PK="$(jr '.id // empty')"
is_2xx "$code" && [ -n "$PK" ] || SETUP_ERR="${SETUP_ERR} provider-K(${code})"
code="$(mk_mapping "$PK" "{\"name\":\"cio-ms-${SUF}\",\"claim_filters\":{\"repository\":\"dtf/short-${SUF}\"}}")"
is_2xx "$code" || SETUP_ERR="${SETUP_ERR} mapping-short(${code})"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- issuers ${ISS_A} ${ISS_B}; aud ${AUD}; PA=${PA} MA=${MA} PB=${PB} MB=${MB}; repos ${RA} ${RB} ${RG}"
pass

# =============================================================================
# CONTROLS (every image)
# =============================================================================
begin_test "CONTROL: a matching assertion (issuer, audience, subject, repository claim, unexpired) exchanges for a working token"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_A" "$SUB_MAIN" "$PROJ" 300)")")"
CT_MAIN="$(jr '.access_token // empty')"; U_MAIN="$(jr '.username // empty')"; EXP_IN="$(jr '.expires_in // empty')"
note "exchange main: ${code} username=${U_MAIN} token_type=$(jr '.token_type') expires_in=${EXP_IN}"
[ "$code" = "200" ] && [ -n "$CT_MAIN" ] || gate "matching assertion answered ${code}: $(snip)"
[ "$(jr '.token_type')" = "Bearer" ] || gate "token_type is '$(jr '.token_type')'"
case "$U_MAIN" in ci-*) ;; *) gate "username '${U_MAIN}' is not a ci- service account";; esac
# 1..300 up to 1.11.8 (capped at the assertion's exp), the configured TTL from
# 1.11.9 (#5054, gated by ci-oidc-token-lifetime); never above 3600 on either.
{ [ -n "$EXP_IN" ] && [ "$EXP_IN" -ge 1 ] && [ "$EXP_IN" -le 3600 ]; } || gate "expires_in=${EXP_IN}, expected 1..3600"
code="$(req GET /api/v1/auth/me "$CT_MAIN")"
U_MAIN_ID="$(jr '.id // empty')"
[ "$code" = "200" ] && [ "$(jr '.username')" = "$U_MAIN" ] && [ "$(jr '.is_admin')" = "false" ] \
  || gate "/auth/me with the CI token answered ${code}: $(snip)"
[ "$(db "SELECT auth_provider FROM users WHERE id = '${U_MAIN_ID}'")" = "ci" ] || gate "the account's auth_provider is not ci"
finish_case "a valid CI assertion does not exchange"

begin_test "CONTROL: each mismatched claim, a bad signature and a long-expired assertion are refused"
reset_case
code="$(AUD_OVERRIDE="other-${SUF}" xchg "$(jwt "$(AUD_OVERRIDE="other-${SUF}" claims "$ISS_A" "$SUB_MAIN" "$PROJ" 300)")")"
note "wrong audience: ${code} $(jr '.message')"; refused "$code" "wrong audience"
code="$(xchg "$(jwt "$(claims "https://mock-ci-oidc/nobody-${SUF}" "$SUB_MAIN" "$PROJ" 300)")")"
note "unknown issuer: ${code} $(jr '.message')"; refused "$code" "unknown issuer" 404
body | grep -q "nobody-${SUF}" || gate "the unknown-issuer refusal does not name the issuer"
code="$(xchg "$(jwt "$(claims "$ISS_A" "repo:${PROJ}:ref:refs/heads/dev" "$PROJ" 300)")")"
note "subject outside the mapping: ${code} $(jr '.message')"; refused "$code" "subject outside the mapping"
code="$(xchg "$(jwt "$(claims "$ISS_A" "$SUB_MAIN" "dtf/other-${SUF}" 300)")")"
note "repository claim outside the mapping: ${code} $(jr '.message')"; refused "$code" "repository claim outside the mapping"
code="$(xchg "$(jwt "$(claims "$ISS_A" "$SUB_MAIN" "$PROJ" 300)" wrong)")"
note "signed by a key the JWKS does not publish: ${code} $(jr '.message')"; refused "$code" "wrong signing key"
code="$(xchg "$(jwt "$(claims "$ISS_A" "$SUB_MAIN" "$PROJ" -300)")")"
note "exp 300 s ago: ${code} $(jr '.message')"; refused "$code" "assertion expired 300 s ago"
code="$(req POST /api/v1/auth/ci/token "")"
note "no Authorization: ${code}"; refused "$code" "no Authorization header"
finish_case "a mismatched or forged assertion exchanges"

begin_test "CONTROL: an nbf inside the clock-skew window (20 s ahead) still exchanges"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_A" "$SUB_MAIN" "$PROJ" 300 "{\"nbf\":$(( $(now) + 20 ))}")")")"
note "nbf now+20: ${code}"
[ "$code" = "200" ] && [ -n "$(jr '.access_token // empty')" ] || gate "nbf within skew answered ${code}: $(snip)"
finish_case "ordinary clock skew is no longer tolerated"

begin_test "CONTROL: the issued token's repository scope is the mapping's allowed_repo_ids ceiling"
reset_case
for r in "$RA_ID" "$RB_ID"; do
  code="$(req POST /api/v1/permissions "$ADMIN_TOKEN" \
    "{\"principal_type\":\"user\",\"principal_id\":\"${U_MAIN_ID}\",\"target_type\":\"repository\",\"target_id\":\"${r}\",\"actions\":[\"read\"]}")"
  is_2xx "$code" || gate "granting the CI account read on ${r} answered ${code}: $(snip)"
done
code="$(xchg "$(jwt "$(claims "$ISS_A" "$SUB_MAIN" "$PROJ" 300)")")"; CT="$(jr '.access_token // empty')"
[ "$code" = "200" ] || gate "re-exchange answered ${code}"
code="$(dl "$RA" "$CT")"; note "CI token reads A (in allowed_repo_ids): ${code}"
[ "$code" = "200" ] && [ "$(body)" = "$BYTES_A" ] || gate "CI token download A answered ${code} '$(snip | head -c 80)'"
code="$(dl "$RB" "$CT")"; note "CI token reads B (granted, outside allowed_repo_ids): ${code}"
is_denied "$code" || gate "CI token download B answered ${code}, expected 403/404 (the mapping ceiling)"
finish_case "the exchanged token's scope does not match its mapping"

# =============================================================================
# FIX #4031 (RED on 1.10.0)
# =============================================================================
begin_test "FIX #4031: the mapping's service account exists at mapping create, and the create response names it"
reset_case
note "create response: service_account_id=${MA_SA_ID:-absent} service_account_username=${MA_SA_NAME:-absent}; rows keyed ci:PA:MA at create: ${MA_ACCOUNT_AT_CREATE}"
[ -n "$MA_SA_ID" ] && [ "$MA_SA_ID" = "$U_MAIN_ID" ] || gate "service_account_id '${MA_SA_ID}' is not the account the exchange authenticated (${U_MAIN_ID})"
[ -n "$MA_SA_NAME" ] && [ "$MA_SA_NAME" = "$U_MAIN" ] || gate "service_account_username '${MA_SA_NAME}' is not '${U_MAIN}'"
[[ "$MA_SA_NAME" =~ ^ci-[0-9a-f]{12}$ ]] || gate "service_account_username '${MA_SA_NAME}' is not ci-<12 hex>"
[ "$MA_ACCOUNT_AT_CREATE" = "1" ] || gate "no account keyed on the mapping existed before the first exchange (${MA_ACCOUNT_AT_CREATE})"
finish_case "the mapping's account is created only by a pipeline run"

begin_test "FIX #4031: a second ref (tag) of the same mapping authenticates as the same service account"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_A" "$SUB_TAG" "$PROJ" 300)")")"
note "exchange tag: ${code} username=$(jr '.username') $(jr '.message')"
[ "$code" = "200" ] || gate "tag ref answered ${code} (1.10.0: 409 Username already exists): $(snip | head -c 160)"
[ "$(jr '.username')" = "$U_MAIN" ] || gate "tag ref authenticated as '$(jr '.username')', expected ${U_MAIN}"
CT_TAG="$(jr '.access_token // empty')"
if [ -n "$CT_TAG" ]; then
  req GET /api/v1/auth/me "$CT_TAG" >/dev/null
  [ "$(jr '.id')" = "$U_MAIN_ID" ] || gate "tag token's /auth/me id $(jr '.id') != ${U_MAIN_ID}"
fi
finish_case "a mapping authenticates only the first ref that ever ran"

begin_test "FIX #4031: the same subject through a second issuer is a second principal; the first account is untouched"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_B" "$SUB_MAIN" "$PROJ" 300)")")"
U_B="$(jr '.username // empty')"
note "exchange via issuer B: ${code} username=${U_B}"
[ "$code" = "200" ] || gate "issuer B exchange answered ${code}: $(snip)"
[ -n "$U_B" ] && [ "$U_B" != "$U_MAIN" ] || gate "issuer B authenticated as '${U_B}', the same principal as issuer A"
rows="$(db "SELECT count(DISTINCT id) FROM users WHERE auth_provider = 'ci' AND (external_id = 'ci:${PA}:${MA}' OR external_id = 'ci:${PB}:${MB}')")"
note "distinct accounts keyed on the two mappings: ${rows}; A's account is now '$(db "SELECT username FROM users WHERE id = '${U_MAIN_ID}'")'"
[ "$rows" = "2" ] || gate "${rows} account row(s) for the two mappings, expected 2"
[ "$(db "SELECT username FROM users WHERE id = '${U_MAIN_ID}'")" = "$U_MAIN" ] || gate "issuer B's exchange rewrote issuer A's account"
finish_case "principals are merged across issuers"

begin_test "FIX #4031: an administrator's deactivation of the CI account sticks across the next exchange"
reset_case
code="$(req PATCH "/api/v1/users/${U_MAIN_ID}" "$ADMIN_TOKEN" '{"is_active":false}')"
is_2xx "$code" || gate "deactivating the CI account answered ${code}"
code="$(xchg "$(jwt "$(claims "$ISS_A" "$SUB_MAIN" "$PROJ" 300)")")"
active="$(db "SELECT is_active FROM users WHERE id = '${U_MAIN_ID}'")"
note "exchange for the deactivated account: ${code} $(jr '.message'); is_active=${active}"
refused "$code" "exchange for a deactivated CI account"
[ "$active" = "f" ] || gate "the exchange reactivated the account (is_active=${active})"
finish_case "the exchange reactivates a deactivated CI account"

begin_test "FIX #4031: deleting a mapping deactivates its service account"
reset_case
code="$(mk_mapping "$PB" "{\"name\":\"cio-md-${SUF}\",\"claim_filters\":{\"repository\":\"dtf/delete-${SUF}\"}}")"; MD="$(jr '.id // empty')"
code="$(xchg "$(jwt "$(claims "$ISS_B" "x" "dtf/delete-${SUF}" 300)")")"; U_D="$(jr '.username // empty')"
[ "$code" = "200" ] && [ -n "$U_D" ] || gate "exchange through the to-be-deleted mapping answered ${code}"
code="$(req DELETE "/api/v1/admin/ci-oidc/${PB}/mappings/${MD}" "$ADMIN_TOKEN")"
is_2xx "$code" || gate "deleting the mapping answered ${code}"
active="$(db "SELECT is_active FROM users WHERE username = '${U_D}'")"
note "account ${U_D} after its mapping is deleted: is_active=${active}"
[ "$active" = "f" ] || gate "the deleted mapping's account is still active (${active})"
finish_case "a deleted mapping leaves its account active"

# =============================================================================
# FIX #4511 (RED on 1.10.0)
# =============================================================================
begin_test "FIX #4511: an assertion whose nbf is 300 s in the future is refused"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_B" "$SUB_MAIN" "$PROJ" 600 "{\"nbf\":$(( $(now) + 300 ))}")")")"
note "nbf now+300: ${code} $(jr '.message')"
refused "$code" "a not-yet-valid assertion"
finish_case "a token that is not valid yet exchanges"

# =============================================================================
# FIX #4314 (RED on 1.10.0)
# =============================================================================
begin_test "FIX #4314: a CI-exchanged credential cannot mint an API token for its account"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_B" "$SUB_MAIN" "$PROJ" 300)")")"; CT_B="$(jr '.access_token // empty')"
[ -n "$CT_B" ] || gate "exchange via issuer B answered ${code}"
for ep in /api/v1/profile/access-tokens /api/v1/auth/tokens; do
  nm="cio-mint-${ep##*/}-${SUF}"
  code="$(req POST "$ep" "$CT_B" "{\"name\":\"${nm}\",\"scopes\":[\"read:artifacts\"]}")"
  note "CI credential mints via ${ep}: ${code} $(jr '.message')"
  [ "$code" = "403" ] || gate "CI credential minting via ${ep} answered ${code}, expected 403"
  [ "$(db "SELECT count(*) FROM api_tokens WHERE name = '${nm}'")" = "0" ] || gate "an API token was stored for the CI account via ${ep}"
done
finish_case "a short-lived CI credential turns itself into a permanent API token"

# =============================================================================
# FIX #4663 (RED on 1.10.0 and 1.11.0)
# =============================================================================
begin_test "FIX #4663: an assertion 30 s past exp (inside the verifier's leeway) buys no session, never expires_in 0"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_B" "$SUB_MAIN" "$PROJ" -30)")")"
note "exp now-30: ${code} expires_in=$(jr '.expires_in // "absent"') $(jr '.message // empty')"
refused "$code" "an assertion 30 s past exp"
[ "$(jr '.expires_in // empty')" = "0" ] && gate "the exchange answered expires_in: 0"
finish_case "an expired assertion buys an expires_in: 0 session"

begin_test "FIX #4663: AK's own session token is refused once its exp has passed (no 60 s leeway)"
reset_case
code="$(xchg "$(jwt "$(claims "$ISS_K" "x" "dtf/short-${SUF}" 8)")")"
ST="$(jr '.access_token // empty')"; st_exp="$(jr '.expires_in // empty')"
note "assertion exp now+8: ${code} expires_in=${st_exp}"
{ [ "$code" = "200" ] && [ -n "$st_exp" ] && [ "$st_exp" -ge 1 ] && [ "$st_exp" -le 8 ]; } || gate "short exchange answered ${code} expires_in=${st_exp}, expected 200 and 1..8"
code="$(req GET /api/v1/auth/me "$ST")"
[ "$code" = "200" ] || gate "the fresh short token answered ${code} on /auth/me"
sleep 13
code="$(req GET /api/v1/auth/me "$ST")"
note "/auth/me 5 s after the token's exp: ${code}"
[ "$code" = "401" ] || gate "a session token 5 s past its exp answered ${code}, expected 401"
finish_case "a session token outlives its exp by the validation leeway"

# =============================================================================
# FIX #4133 (RED on 1.10.0 and 1.11.0)
# =============================================================================
begin_test "FIX #4133: a provider audience equal to the Kubernetes API server's is refused on create and update, nothing written"
reset_case
before="$(db "SELECT count(*) FROM ci_oidc_providers")"
for aud in "$K8S_AUD_1" "$K8S_AUD_2"; do
  for ptype in generic github; do
    code="$(mk_provider "cio-k8s-${ptype}-${SUF}" "https://mock-ci-oidc/k8s-${SUF}" "$aud" "$ptype")"
    note "create ${ptype} with ${aud}: ${code} $(jr '.message' | head -c 120)"
    [ "$code" = "400" ] || gate "create ${ptype} provider with audience ${aud} answered ${code}, expected 400"
    body | grep -qF "$aud" || gate "the refusal for ${aud} does not name it"
  done
done
after="$(db "SELECT count(*) FROM ci_oidc_providers")"
[ "$after" = "$before" ] || gate "provider count went ${before} -> ${after}"
code="$(req PUT "/api/v1/admin/ci-oidc/${PB}" "$ADMIN_TOKEN" "{\"audience\":\"${K8S_AUD_2}\"}")"
stored="$(db "SELECT audience FROM ci_oidc_providers WHERE id = '${PB}'")"
note "update PB to ${K8S_AUD_2}: ${code}; stored audience ${stored}"
[ "$code" = "400" ] || gate "update to ${K8S_AUD_2} answered ${code}, expected 400"
[ "$stored" = "$AUD" ] || gate "PB's audience is now '${stored}'"
finish_case "a Kubernetes API server audience is accepted"

# =============================================================================
# FIX #4117 (RED on 1.10.0)
# =============================================================================
begin_test "FIX #4117: group_binding_ids naming an unknown group is refused and writes no mapping"
reset_case
nm="cio-mbad-${SUF}"
code="$(mk_mapping "$PA" "{\"name\":\"${nm}\",\"claim_filters\":{\"repository\":\"dtf/bad-${SUF}\"},\"group_binding_ids\":[\"00000000-0000-4000-8000-000000000000\"]}")"
note "unknown group id: ${code} $(jr '.message' | head -c 140)"
[ "$code" = "400" ] || gate "a binding to an unknown group answered ${code}, expected 400"
[ "$(db "SELECT count(*) FROM ci_oidc_identity_mappings WHERE name = '${nm}'")" = "0" ] || gate "the refused mapping was written"
finish_case "a binding to a nonexistent group is accepted"

begin_test "FIX #4117: a mapping bound to a group grants that group's access to the exchanged token, audited; [] revokes it"
reset_case
req POST /api/v1/groups "$ADMIN_TOKEN" "{\"name\":\"cio-g-${SUF}\",\"description\":\"ci-oidc-exchange\"}" >/dev/null
G="$(jr '.id // empty')"
code="$(req POST /api/v1/permissions "$ADMIN_TOKEN" \
  "{\"principal_type\":\"group\",\"principal_id\":\"${G}\",\"target_type\":\"repository\",\"target_id\":\"${RG_ID}\",\"actions\":[\"read\"]}")"
{ [ -n "$G" ] && is_2xx "$code"; } || gate "group setup answered ${code}"
code="$(mk_mapping "$PA" "{\"name\":\"cio-mg-${SUF}\",\"claim_filters\":{\"repository\":\"dtf/bound-${SUF}\"},\"group_binding_ids\":[\"${G}\"]}")"
MG="$(jr '.id // empty')"
note "bound mapping create: ${code} group_binding_ids=$(jr '.group_binding_ids | tostring')"
is_2xx "$code" && [ -n "$MG" ] || gate "creating the bound mapping answered ${code}"
code="$(xchg "$(jwt "$(claims "$ISS_A" "x" "dtf/bound-${SUF}" 300)")")"; GT="$(jr '.access_token // empty')"; U_G="$(jr '.username // empty')"
[ "$code" = "200" ] || gate "exchange through the bound mapping answered ${code}"
member="$(db "SELECT count(*) FROM user_group_members m JOIN users u ON u.id = m.user_id WHERE m.group_id = '${G}' AND u.username = '${U_G}'")"
code="$(dl "$RG" "$GT")"
note "bound account ${U_G}: member of G=${member}; download G's repo: ${code}"
[ "$member" = "1" ] || gate "the bound account is not a member of the group (${member})"
[ "$code" = "200" ] && [ "$(body)" = "$BYTES_G" ] || gate "the bound token's download answered ${code}, expected 200 with the group's repository bytes"
audit="$(db "SELECT count(*) FROM audit_log WHERE action = 'CI_OIDC_GROUP_BINDING_RECONCILED' AND details->>'mapping_id' = '${MG}' AND details->'added' ? '${G}'")"
note "CI_OIDC_GROUP_BINDING_RECONCILED rows adding G for the mapping: ${audit}"
[ "$audit" = "1" ] || gate "no CI_OIDC_GROUP_BINDING_RECONCILED audit row adds the group (${audit})"
code="$(req PUT "/api/v1/admin/ci-oidc/${PA}/mappings/${MG}" "$ADMIN_TOKEN" '{"group_binding_ids":[]}')"
is_2xx "$code" || gate "narrowing the binding to [] answered ${code}"
code="$(xchg "$(jwt "$(claims "$ISS_A" "x" "dtf/bound-${SUF}" 300)")")"; GT="$(jr '.access_token // empty')"
code="$(dl "$RG" "$GT")"
member="$(db "SELECT count(*) FROM user_group_members m JOIN users u ON u.id = m.user_id WHERE m.group_id = '${G}' AND u.username = '${U_G}'")"
note "after binding []: member=${member}; download: ${code}"
[ "$member" = "0" ] || gate "binding [] left the membership in place"
is_denied "$code" || gate "after binding [] the token still reads the group's repository (${code})"
finish_case "a mapping's group binding does not grant, or does not revoke"

end_suite
