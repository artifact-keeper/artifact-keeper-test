#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/api-contracts-1120/oracle.sh
#   Pure-API contracts added in 1.12.0: #4839 the admin downloads listing's
#   downloader=all|anonymous|authenticated filter, #2024 the lifecycle
#   match.format scope. See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

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

begin_suite "api-contracts-1120"

# =============================================================================
begin_test "setup: admin session, a public generic repo with one artifact downloaded once anonymously and once as admin"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
req GET /api/v1/auth/me "$TOK"
ADMIN_ID="$(jqr '.id // empty' <<<"$BODY")"
[ -n "$ADMIN_ID" ] || { infra_fail "GET /auth/me answered ${CODE}: ${BODY:0:200}"; end_suite; }
R_GEN="ac12-gen-${SFX}"
req POST /api/v1/repositories "$TOK" "$(jq -nc --arg k "$R_GEN" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:true}')"
is_2xx "$CODE" || { infra_fail "creating ${R_GEN} answered ${CODE}: ${BODY:0:200}"; end_suite; }
R_GEN_ID="$(jqr '.id // empty' <<<"$BODY")"
printf 'api-contracts-1120 %s\n' "$SFX" > "${W}/a.txt"
CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${W}/a.txt" \
  "${BASE}/api/v1/repositories/${R_GEN}/artifacts/dl/a.txt")"
BODY="$(cat "${W}/body")"
is_2xx "$CODE" || { infra_fail "upload answered ${CODE}: ${BODY:0:200}"; end_suite; }
ART_ID="$(jqr '.id // empty' <<<"$BODY")"
A1="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "${BASE}/api/v1/repositories/${R_GEN}/download/dl/a.txt")"
A2="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/repositories/${R_GEN}/download/dl/a.txt")"
[ "$A1" = "200" ] && [ "$A2" = "200" ] || { infra_fail "downloads answered anon=${A1} admin=${A2}"; end_suite; }
# Download rows are written off the request path: wait for both.
for _ in $(seq 1 50); do
  req GET "/api/v1/admin/downloads?artifact_id=${ART_ID}" "$TOK"
  [ "$(jqr '.total' <<<"$BODY")" = "2" ] && break
  sleep 0.2
done
[ "$(jqr '.total' <<<"$BODY")" = "2" ] || { infra_fail "the two downloads were never listed: ${BODY:0:300}"; end_suite; }
DL_IP="$(jqr '[.downloads[].ip_address | select(. != null)][0] // empty' <<<"$BODY")"
echo "-- repo ${R_GEN} (${R_GEN_ID}), artifact ${ART_ID}, admin ${ADMIN_ID}, client ip ${DL_IP:-unknown}"
pass

# =============================================================================
begin_test "CONTROL: the listing returns the anonymous and the admin download of the artifact"
reset_case
req GET "/api/v1/admin/downloads?artifact_id=${ART_ID}" "$TOK"
note "all: ${CODE} total=$(jqr .total <<<"$BODY") users=$(jqr -c '[.downloads[].user_id]' <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr .total <<<"$BODY")" = "2" ] || fail_g "listing answered ${CODE} total $(jqr .total <<<"$BODY")"
[ "$(jqr '[.downloads[] | select(.user_id == null)] | length' <<<"$BODY")" = "1" ] || fail_g "no single anonymous row"
[ "$(jqr --arg u "$ADMIN_ID" '[.downloads[] | select(.user_id == $u)] | length' <<<"$BODY")" = "1" ] || fail_g "no single admin row"
finish_case "download attribution listing broken"

begin_test "FIX #4839: downloader=anonymous lists only the null-user row, downloader=authenticated only the admin's"
reset_case
req GET "/api/v1/admin/downloads?artifact_id=${ART_ID}&downloader=anonymous" "$TOK"
note "anonymous: ${CODE} total=$(jqr .total <<<"$BODY") users=$(jqr -c '[.downloads[].user_id]' <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr .total <<<"$BODY")" = "1" ] && [ "$(jqr '.downloads[0].user_id' <<<"$BODY")" = "null" ] \
  || fail_g "downloader=anonymous is not exactly the null-user row"
req GET "/api/v1/admin/downloads?artifact_id=${ART_ID}&downloader=authenticated" "$TOK"
note "authenticated: ${CODE} total=$(jqr .total <<<"$BODY") users=$(jqr -c '[.downloads[].user_id]' <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr .total <<<"$BODY")" = "1" ] && [ "$(jqr '.downloads[0].user_id' <<<"$BODY")" = "$ADMIN_ID" ] \
  || fail_g "downloader=authenticated is not exactly the admin's row"
req GET "/api/v1/admin/downloads?artifact_id=${ART_ID}&downloader=all" "$TOK"
note "all (explicit): ${CODE} total=$(jqr .total <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr .total <<<"$BODY")" = "2" ] || fail_g "downloader=all is not both rows"
if [ -n "$DL_IP" ]; then
  req GET "/api/v1/admin/downloads/by-ip/${DL_IP}?artifact_id=${ART_ID}&downloader=anonymous" "$TOK"
  note "by-ip anonymous: ${CODE} total=$(jqr .total <<<"$BODY")"
  [ "$CODE" = "200" ] && [ "$(jqr '[.downloads[] | select(.user_id != null)] | length' <<<"$BODY")" = "0" ] \
    && [ "$(jqr .total <<<"$BODY")" -ge 1 ] 2>/dev/null || fail_g "by-ip downloader=anonymous carries an attributed row"
fi
finish_case "the admin downloads listing cannot select anonymous or authenticated downloads"

begin_test "FIX #4839: downloader=anonymous with a user_id, and an unknown downloader value, are 400"
reset_case
req GET "/api/v1/admin/downloads?downloader=anonymous&user_id=${ADMIN_ID}" "$TOK"
note "anonymous + user_id: ${CODE} ${BODY:0:160}"
[ "$CODE" = "400" ] || fail_g "downloader=anonymous with user_id answered ${CODE}, not 400"
req GET "/api/v1/admin/downloads/by-user/${ADMIN_ID}?downloader=anonymous" "$TOK"
note "by-user + anonymous: ${CODE}"
[ "$CODE" = "400" ] || fail_g "by-user with downloader=anonymous answered ${CODE}, not 400"
req GET "/api/v1/admin/downloads?downloader=robots" "$TOK"
note "downloader=robots: ${CODE}"
[ "$CODE" = "400" ] || fail_g "an unknown downloader value answered ${CODE}, not 400"
finish_case "contradictory or unknown downloader filters are not refused"

# =============================================================================
# #2024 match.format
# =============================================================================
# mk_policy <name> <match json> -> sets CODE, BODY, LP_ID
mk_policy(){
  req POST /api/v1/admin/lifecycle "$TOK" "$(jq -nc --arg n "$1" --arg r "$R_GEN_ID" --argjson m "$2" \
    '{name:$n,policy_type:"tag_pattern_delete",config:({pattern:".*"} + (if $m == null then {} else {match:$m} end)),repository_ids:[$r],enabled:false}')"
  LP_ID="$(jqr '.id // empty' <<<"$BODY")"
}
# preview <id> -> sets CODE, BODY, MATCHED
preview(){ req POST "/api/v1/admin/lifecycle/$1/preview" "$TOK"; MATCHED="$(jqr '.artifacts_matched // empty' <<<"$BODY")"; }

begin_test "CONTROL: a policy without match.format previews the repository's artifact; an unknown format or match key is 400"
reset_case
mk_policy "ac12-plain-${SFX}" null
note "create (no match): ${CODE} id=${LP_ID}"
is_2xx "$CODE" && [ -n "$LP_ID" ] || fail_g "create answered ${CODE}: ${BODY:0:200}"
preview "$LP_ID"
note "preview: ${CODE} matched=${MATCHED}"
[ "$CODE" = "200" ] && [ "$MATCHED" = "1" ] || fail_g "preview answered ${CODE} matched=${MATCHED}, not 1"
mk_policy "ac12-badfmt-${SFX}" '{"format":"definitely-not-a-format"}'
note "create (format nope): ${CODE}"
[ "$CODE" = "400" ] || fail_g "an unknown format answered ${CODE}, not 400"
mk_policy "ac12-badkey-${SFX}" '{"formats":"generic"}'
note "create (match.formats): ${CODE}"
[ "$CODE" = "400" ] || fail_g "a misspelt match key answered ${CODE}, not 400"
finish_case "lifecycle policy validation or preview broken"

begin_test "FIX #2024: match.format scopes a policy to repositories of that format"
reset_case
mk_policy "ac12-generic-${SFX}" '{"format":"generic"}'
note "create (format generic): ${CODE} ${BODY:0:160}"
if is_2xx "$CODE" && [ -n "$LP_ID" ]; then
  [ "$(jqr '.config.match.format' <<<"$BODY")" = "generic" ] || fail_g "the stored config lost match.format: $(jqr -c .config <<<"$BODY")"
  preview "$LP_ID"
  note "preview (generic): ${CODE} matched=${MATCHED}"
  [ "$CODE" = "200" ] && [ "$MATCHED" = "1" ] || fail_g "a generic-scoped policy previews ${MATCHED} in a generic repository, not 1"
else
  fail_g "a policy with match.format \"generic\" was refused: ${CODE}"
fi
for fmt in '"npm"' '["npm","helm"]'; do
  mk_policy "ac12-other-${SFX}-$RANDOM" "{\"format\":${fmt}}"
  note "create (format ${fmt}): ${CODE}"
  if is_2xx "$CODE" && [ -n "$LP_ID" ]; then
    preview "$LP_ID"
    note "preview (${fmt}): ${CODE} matched=${MATCHED}"
    [ "$CODE" = "200" ] && [ "$MATCHED" = "0" ] || fail_g "a ${fmt}-scoped policy previews ${MATCHED} in a generic repository, not 0"
  else
    fail_g "a policy with match.format ${fmt} was refused: ${CODE}"
  fi
done
finish_case "lifecycle policies cannot be scoped by repository format"

end_suite
