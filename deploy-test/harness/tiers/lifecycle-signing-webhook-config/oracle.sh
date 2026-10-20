#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/lifecycle-signing-webhook-config/oracle.sh
#   #4428  WEBHOOK_ALLOW_PRIVATE_IPS admits a private webhook receiver even
#          when AK_SSRF_ALLOW_PRIVATE_CIDRS is set and does not list it
#   #4474  SSO_ALLOW_PRIVATE_IPS does the same for an OIDC issuer
#   #4529  PUT /repositories/{key}/upstream-auth writes a REPOSITORY_UPDATED
#          audit row with the auth-type change and credentials_changed, and
#          never the secret
# See the manifest for the gates and which image each case goes red on.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock receiver's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${RUN_ID:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${DTF_SLOT}-${RUN_ID##*-}-$$"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
RECV="http://172.16.${DTF_SLOT}.78"     # outside AK_SSRF_ALLOW_PRIVATE_CIDRS
LISTED="http://172.16.${DTF_SLOT}.79"   # the one listed address (nothing there)

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$@" 2>/dev/null || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }

req(){
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}$2")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
msg(){ jqr '.message // .error // empty' <<<"$BODY" | head -c 220; }

begin_suite "lifecycle-signing-webhook-config"

begin_test "setup: admin session, mock receiver up, backend environment as the profile set it"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
[ "$(curl -s --max-time 5 "${MOCK}/__readyz")" = "ok" ] || { infra_fail "mock receiver not reachable on ${MOCK}"; end_suite; }
envs="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "ak-dtf${DTF_SLOT}-backend" 2>/dev/null | grep -E '^(AK_SSRF_ALLOW_PRIVATE_CIDRS|WEBHOOK_ALLOW_PRIVATE_IPS|SSO_ALLOW_PRIVATE_IPS|UPSTREAM_ALLOW_PRIVATE_IPS)=' | sort | paste -sd' ' -)"
echo "-- backend env: ${envs}"
{ grep -q "AK_SSRF_ALLOW_PRIVATE_CIDRS=172.16.${DTF_SLOT}.79/32" <<<"$envs" && grep -q 'WEBHOOK_ALLOW_PRIVATE_IPS=true' <<<"$envs"; } \
  || { infra_fail "the backend does not carry the ssrf.private-toggles environment"; end_suite; }
pass

# =============================================================================
begin_test "CONTROL: the CIDR list stays authoritative for upstreams and metadata stays blocked for webhooks"
reset_case
req POST /api/v1/repositories "$(jq -nc --arg k "lw-up-${SFX}" --arg u "${RECV}/up/" '{key:$k,name:$k,format:"generic",repo_type:"remote",upstream_url:$u}')"
note "Remote upstream at the unlisted ${RECV}: ${CODE} $(msg)"
[ "$CODE" = "400" ] || fail_g "a Remote at an unlisted private address answered ${CODE}, expected 400"
req POST /api/v1/repositories "$(jq -nc --arg k "lw-ok-${SFX}" --arg u "${LISTED}/up/" '{key:$k,name:$k,format:"generic",repo_type:"remote",upstream_url:$u}')"
note "Remote upstream at the listed ${LISTED}: ${CODE}"
is_2xx "$CODE" || fail_g "a Remote at the listed address answered ${CODE}: $(msg)"
req POST /api/v1/webhooks "$(jq -nc '{name:"lw-meta",url:"http://169.254.169.254/latest/meta-data",events:["artifact_uploaded"]}')"
note "webhook to 169.254.169.254: ${CODE} $(msg)"
[ "$CODE" = "400" ] || fail_g "a metadata-address webhook answered ${CODE}, expected 400"
finish_case "the SSRF guard's upstream rule or metadata block changed"

begin_test "#4428: with WEBHOOK_ALLOW_PRIVATE_IPS=true a webhook to a private receiver outside the CIDR list is accepted and delivered"
reset_case
req POST /api/v1/webhooks "$(jq -nc --arg u "${RECV}/hook/lw-${SFX}" '{name:"lw-private",url:$u,events:["artifact_uploaded"]}')"
WH="$(jqr '.id // empty' <<<"$BODY")"
note "webhook to ${RECV}: ${CODE} $(msg)"
is_2xx "$CODE" && [ -n "$WH" ] || fail_g "the private webhook was refused (${CODE})"
if [ -n "$WH" ]; then
  req POST "/api/v1/webhooks/${WH}/test"
  note "test delivery: ${CODE} $(jqr -c '{success,status_code,error}' <<<"$BODY")"
  got="$(curl -s --max-time 10 "${MOCK}/__log" | jq --arg p "/hook/lw-${SFX}" '[.[] | select(.path == $p and .method == "POST")] | length' 2>/dev/null)"
  note "receiver POSTs at /hook/lw-${SFX}: ${got:-0}"
  [ "$(jqr '.success' <<<"$BODY")" = "true" ] && [ "${got:-0}" -ge 1 ] 2>/dev/null || fail_g "the test delivery did not reach the receiver"
fi
finish_case "WEBHOOK_ALLOW_PRIVATE_IPS is ignored when AK_SSRF_ALLOW_PRIVATE_CIDRS is set"

begin_test "#4474: with SSO_ALLOW_PRIVATE_IPS=true an OIDC issuer at a private address outside the CIDR list is accepted"
reset_case
req POST /api/v1/admin/sso/oidc "$(jq -nc --arg n "lw-oidc-${SFX}" --arg i "${RECV}/oidc" '{name:$n,issuer_url:$i,client_id:"dtf",client_secret:"dtf-secret"}')"
OID="$(jqr '.id // empty' <<<"$BODY")"
note "OIDC provider with issuer ${RECV}/oidc: ${CODE} $(msg)"
is_2xx "$CODE" && [ -n "$OID" ] || fail_g "the private OIDC issuer was refused (${CODE})"
req POST /api/v1/admin/sso/oidc "$(jq -nc --arg n "lw-oidcm-${SFX}" '{name:$n,issuer_url:"http://169.254.169.254/oidc",client_id:"dtf",client_secret:"dtf-secret"}')"
note "OIDC provider with a metadata issuer: ${CODE} $(msg)"
[ "$CODE" = "400" ] || fail_g "a metadata-address issuer answered ${CODE}, expected 400"
finish_case "SSO_ALLOW_PRIVATE_IPS is ignored when AK_SSRF_ALLOW_PRIVATE_CIDRS is set"

begin_test "#4529: PUT upstream-auth writes a REPOSITORY_UPDATED audit row with the auth-type change and credentials_changed, never the secret"
reset_case
R="lw-ok-${SFX}"
RID="$(psql_q "SELECT id FROM repositories WHERE key = '${R}'" | tr -d '[:space:]')"
SECRET="DtfSecret-${SFX}-x9"
audit_rows(){ psql_q "SELECT count(*) FROM audit_log WHERE resource_id = '${RID}' AND action = 'REPOSITORY_UPDATED' AND details ? 'upstream_auth_change'" | tr -d '[:space:]'; }
last_change(){ psql_q "SELECT (details->'upstream_auth_change')::text FROM audit_log WHERE resource_id = '${RID}' AND action = 'REPOSITORY_UPDATED' AND details ? 'upstream_auth_change' ORDER BY created_at DESC LIMIT 1" | sed 's/^ *//'; }
wait_rows(){ local want="$1" n=""; for _i in $(seq 1 20); do n="$(audit_rows)"; [ "$n" = "$want" ] && break; sleep 0.5; done; echo "${n:-0}"; }
if [ -z "$RID" ]; then
  fail_g "the Remote ${R} was not created (see the control)"
else
  req PUT "/api/v1/repositories/${R}/upstream-auth" "$(jq -nc --arg p "$SECRET" '{auth_type:"basic",username:"dtf-user",password:$p}')"
  note "PUT upstream-auth basic: ${CODE} $(msg)"
  is_2xx "$CODE" || fail_g "setting basic upstream auth answered ${CODE}"
  n1="$(wait_rows 1)"; c1="$(last_change)"
  note "audit rows: ${n1}; upstream_auth_change: ${c1:-none}"
  [ "$n1" = "1" ] || fail_g "${n1} REPOSITORY_UPDATED rows carry upstream_auth_change, expected 1"
  [ "$(jqr '.credentials_changed' <<<"$c1")" = "true" ] || fail_g "credentials_changed is $(jqr '.credentials_changed' <<<"$c1"), expected true"
  grep -q '"basic"' <<<"$c1" || fail_g "the change does not record the new auth type basic"
  req PUT "/api/v1/repositories/${R}/upstream-auth" "$(jq -nc --arg p "$SECRET" '{auth_type:"basic",username:"dtf-user",password:$p}')"
  n2="$(wait_rows 2)"; c2="$(last_change)"
  note "same credentials again: ${CODE}; audit rows: ${n2}; upstream_auth_change: ${c2:-none}"
  [ "$n2" = "2" ] || fail_g "${n2} rows after a second write, expected 2"
  [ "$(jqr '.credentials_changed' <<<"$c2")" = "false" ] || fail_g "re-saving the same credentials recorded credentials_changed=$(jqr '.credentials_changed' <<<"$c2")"
  req PUT "/api/v1/repositories/${R}/upstream-auth" '{"auth_type":"none"}'
  n3="$(wait_rows 3)"; c3="$(last_change)"
  note "auth_type none: ${CODE}; audit rows: ${n3}; upstream_auth_change: ${c3:-none}"
  [ "$n3" = "3" ] || fail_g "${n3} rows after clearing the auth, expected 3"
  leak="$(psql_q "SELECT count(*) FROM audit_log WHERE details::text LIKE '%${SECRET}%'" | tr -d '[:space:]')"
  note "audit rows containing the password: ${leak}"
  [ "$leak" = "0" ] || fail_g "the upstream password appears in ${leak} audit row(s)"
fi
finish_case "upstream-auth changes are not audited, or the audit row is wrong"

end_suite
