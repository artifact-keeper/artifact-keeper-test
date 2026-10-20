#!/usr/bin/env bash
# =============================================================================
# tiers/token-virtual-catalog/oracle.sh
#   #4808 (fixed by #4213) a service-account token scoped ONLY to a virtual
#         repository reads the contextual Packages catalog of that virtual:
#         list, detail and versions with repository_key=<virtual>; a context
#         that does not hold the package is a 404.
#   #4215 (fixed by #4217) admin diagnostics: per-token scope analysis names
#         the virtual and each member the token cannot reach (no_grant /
#         out_of_token_scope); the token list carries the count; the selector
#         preview refuses a misspelled selector and analyses on behalf of a
#         service account; a stored invalid selector is reported.
# See the manifest for THE BUGS, the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
M1="tvc-m1-${SLOT}-${SUF}"        # private hosted member, account granted read
M2="tvc-m2-${SLOT}-${SUF}"        # private hosted member, account NOT granted (until the end)
OTHER="tvc-other-${SLOT}-${SUF}"  # private hosted, not in the virtual
VIRT="tvc-virt-${SLOT}-${SUF}"    # private virtual over M1, M2
GROUP_ID="com.dtf"
A_ID="tvc-a-${SLOT}-${SUF}"; B_ID="tvc-b-${SLOT}-${SUF}"; C_ID="tvc-c-${SLOT}-${SUF}"
PA_NAME="${GROUP_ID}:${A_ID}"; PB_NAME="${GROUP_ID}:${B_ID}"; PC_NAME="${GROUP_ID}:${C_ID}"
USER_NAME="tvc-user-${SLOT}-${SUF}"
USER_PASS="Tvc_${SUF}_Aa1!"
SA_PATH="/api/v1/service-accounts"
PREVIEW="${SA_PATH}/repo-selector/preview"

WORK="$(mktemp -d -t dtf-tvc-XXXXXX)"
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
snip() { body | head -c 400 || true; }
jb() { body | jq -c "$1" 2>/dev/null || true; }
# jr FILTER: a filter that needs a shell value reads it as env.K (set K=... on
# the call), so no shell expansion happens inside the jq program.
jr() { body | jq -r "$1" 2>/dev/null || true; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || echo "?"; }
# names -> sorted, comma-joined package names of the last listing body.
names() { jr '[.items[]?.name] | sort | join(",")'; }

FAILS=0
DETAIL=""
gate(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mk_repo() { # KEY TYPE -> repo id
  req POST /api/v1/repositories "$ADMIN_TOKEN" \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"maven\",\"repo_type\":\"$2\",\"is_public\":false}" >/dev/null
  jr '.id // empty'
}
upload_jar() { # REPO ARTIFACT_ID VERSION
  local f="$WORK/$2-$3.jar" code
  printf 'tvc-%s-%s-%s' "$2" "$3" "$SUF" > "$f"
  code="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/java-archive' \
    --data-binary "@$f" \
    "${BASE_URL}/api/v1/repositories/$1/artifacts/com/dtf/$2/$3/$2-$3.jar" 2>/dev/null || echo 000)"
  is_2xx "$code"
}
grant_read() { # SA_ID REPO_ID -> http code
  req POST /api/v1/permissions "$ADMIN_TOKEN" \
    "{\"principal_type\":\"service_account\",\"principal_id\":\"$1\",\"target_type\":\"repository\",\"target_id\":\"$2\",\"actions\":[\"read\"]}"
}
# package_id REPO NAME (as admin, member context) -> id
package_id() {
  req GET "/api/v1/packages?repository_key=$1&per_page=100" "$ADMIN_TOKEN" >/dev/null
  K="$2" jr '.items[]? | select(.name == env.K) | .id' | head -n1 || true
}

# =============================================================================
begin_suite "token-virtual-catalog"

begin_test "setup: private maven members M1, M2, an unrelated repo, a private virtual over M1+M2, packages, a service account granted V+M1, a token scoped to V only"
auth_admin
SETUP_ERR=""
M1_ID="$(mk_repo "$M1" local)"; M2_ID="$(mk_repo "$M2" local)"; OTHER_ID="$(mk_repo "$OTHER" local)"
V_ID="$(mk_repo "$VIRT" virtual)"
[ -n "$M1_ID" ] && [ -n "$M2_ID" ] && [ -n "$OTHER_ID" ] && [ -n "$V_ID" ] || SETUP_ERR="${SETUP_ERR} repos(m1=${M1_ID} m2=${M2_ID} other=${OTHER_ID} v=${V_ID})"
for m in "$M1" "$M2"; do
  code="$(req POST "/api/v1/repositories/${VIRT}/members" "$ADMIN_TOKEN" "{\"member_key\":\"${m}\"}")"
  is_2xx "$code" || SETUP_ERR="${SETUP_ERR} member(${m}:${code})"
done
upload_jar "$M1" "$A_ID" 1.0.0 && upload_jar "$M1" "$A_ID" 1.1.0 \
  && upload_jar "$M2" "$B_ID" 1.0.0 && upload_jar "$OTHER" "$C_ID" 1.0.0 || SETUP_ERR="${SETUP_ERR} uploads"
PA=""; PB=""; PC=""
for _i in $(seq 1 20); do
  PA="$(package_id "$M1" "$PA_NAME")"; PB="$(package_id "$M2" "$PB_NAME")"; PC="$(package_id "$OTHER" "$PC_NAME")"
  [ -n "$PA" ] && [ -n "$PB" ] && [ -n "$PC" ] && break
  sleep 0.5
done
[ -n "$PA" ] && [ -n "$PB" ] && [ -n "$PC" ] || SETUP_ERR="${SETUP_ERR} catalog(pa=${PA} pb=${PB} pc=${PC})"

req POST "$SA_PATH" "$ADMIN_TOKEN" "{\"name\":\"tvc-sa-${SLOT}-${SUF}\",\"description\":\"token-virtual-catalog\",\"scopes\":[\"read:artifacts\"]}" >/dev/null
SA="$(jr '.id // empty')"
req POST "$SA_PATH" "$ADMIN_TOKEN" "{\"name\":\"tvc-sa2-${SLOT}-${SUF}\",\"description\":\"token-virtual-catalog other account\",\"scopes\":[\"read:artifacts\"]}" >/dev/null
SA2="$(jr '.id // empty')"
[ -n "$SA" ] && [ -n "$SA2" ] || SETUP_ERR="${SETUP_ERR} service-accounts(sa=${SA} sa2=${SA2})"
for r in "$V_ID" "$M1_ID"; do
  code="$(grant_read "$SA" "$r")"
  is_2xx "$code" || SETUP_ERR="${SETUP_ERR} grant(${r}:${code}:$(snip))"
done
req POST "${SA_PATH}/${SA}/tokens" "$ADMIN_TOKEN" \
  "{\"name\":\"tvc-virt-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repository_ids\":[\"${V_ID}\"]}" >/dev/null
TV="$(jr '.token // empty')"; TV_ID="$(jr '.id // empty')"
req POST "${SA_PATH}/${SA}/tokens" "$ADMIN_TOKEN" \
  "{\"name\":\"tvc-sel-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repo_selector\":{\"match_repos\":[\"${M1_ID}\"]}}" >/dev/null
TSEL_ID="$(jr '.id // empty')"
[ -n "$TV" ] && [ -n "$TV_ID" ] && [ -n "$TSEL_ID" ] || SETUP_ERR="${SETUP_ERR} tokens(tv=${TV_ID} tsel=${TSEL_ID}:$(snip))"
USER_ID="$(create_test_user_with_retry "$USER_NAME" "$USER_PASS" "${USER_NAME}@dtf.test" 2>/dev/null || true)"
USER_TOKEN=""
[ -n "$USER_ID" ] && USER_TOKEN="$(login_as "$USER_NAME" "$USER_PASS" 2>/dev/null || true)"
[ -n "$USER_TOKEN" ] || SETUP_ERR="${SETUP_ERR} user(${USER_ID})"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- V=${VIRT} (${V_ID}) M1=${M1} M2=${M2} OTHER=${OTHER}; PA=${PA} PB=${PB} PC=${PC}; SA=${SA} token=${TV_ID}"
pass

# =============================================================================
# CONTROLS (both images)
# =============================================================================
begin_test "CONTROL: an unscoped admin sees every member's packages through the virtual and each package directly"
reset_case
code="$(req GET "/api/v1/packages?repository_key=${VIRT}&per_page=100" "$ADMIN_TOKEN")"
note "admin list V: ${code} names=$(names) keys=$(jr '[.items[]?.repository_key] | unique | join(",")')"
[ "$code" = "200" ] && [ "$(names)" = "${PA_NAME},${PB_NAME}" ] || gate "admin list V answered ${code} names=$(names), expected ${PA_NAME},${PB_NAME}"
[ "$(jr '[.items[]?.repository_key] | unique | join(",")')" = "$VIRT" ] || gate "admin list V rows not reported under ${VIRT}"
code="$(req GET "/api/v1/packages/${PA}" "$ADMIN_TOKEN")"
[ "$code" = "200" ] && [ "$(jr '.repository_key')" = "$M1" ] || gate "admin detail PA answered ${code} key=$(jr '.repository_key'), expected 200 ${M1}"
code="$(req GET "/api/v1/packages/${PA}?repository_key=${VIRT}" "$ADMIN_TOKEN")"
[ "$code" = "200" ] && [ "$(jr '.repository_key')" = "$VIRT" ] || gate "admin detail PA in V answered ${code} key=$(jr '.repository_key'), expected 200 ${VIRT}"
code="$(req GET "/api/v1/packages/${PA}/versions" "$ADMIN_TOKEN")"
[ "$code" = "200" ] && [ "$(jr '[.versions[]?.version] | sort | join(",")')" = "1.0.0,1.1.0" ] \
  || gate "admin versions PA answered ${code}: $(snip)"
finish_case "the admin view of the catalog changed"

begin_test "CONTROL: the virtual-scoped token cannot read a member outside the virtual context"
reset_case
code="$(req GET "/api/v1/packages?repository_key=${M1}&per_page=100" "$TV")"
note "TV list M1 directly: ${code} names=$(names)"
[ "$code" = "200" ] && [ -z "$(names)" ] || gate "TV list of ${M1} directly answered ${code} names=$(names), expected 200 and empty"
code="$(req GET "/api/v1/packages?per_page=100" "$TV")"
printf '%s' "$(names)" | grep -q "$A_ID\|$B_ID\|$C_ID" && gate "TV unfiltered list shows fixture packages: $(names)"
code="$(req GET "/api/v1/packages/${PA}" "$TV")"
[ "$code" = "404" ] || gate "TV detail PA without context answered ${code}, expected 404: $(snip)"
code="$(req GET "/api/v1/packages/${PA}/versions" "$TV")"
[ "$code" = "404" ] || gate "TV versions PA without context answered ${code}, expected 404: $(snip)"
code="$(req GET "/api/v1/repositories/${M1}" "$TV")"
case "$code" in 403|404) ;; *) gate "TV GET /repositories/${M1} answered ${code}, expected 403/404";; esac
code="$(req GET "/api/v1/packages?repository_key=${OTHER}&per_page=100" "$TV")"
[ -z "$(names)" ] || gate "TV list of the unrelated repo shows $(names)"
finish_case "the virtual-scoped token reaches a member directly"

begin_test "CONTROL: the selector preview still matches a valid selector; the token list shows the token's pin"
reset_case
code="$(req POST "$PREVIEW" "$ADMIN_TOKEN" "{\"repo_selector\":{\"match_repos\":[\"${V_ID}\"]}}")"
note "preview match_repos=[V]: ${code} $(snip)"
[ "$code" = "200" ] && [ "$(jr '.total')" = "1" ] && [ "$(jr '.matched_repositories[0].key')" = "$VIRT" ] \
  || gate "preview of a valid selector answered ${code} $(snip)"
code="$(req GET "${SA_PATH}/${SA}/tokens" "$ADMIN_TOKEN")"
[ "$code" = "200" ] && [ "$(K="$TV_ID" jr '.items[]? | select(.id == env.K) | .repository_ids | join(",")')" = "$V_ID" ] \
  || gate "token list answered ${code}; the virtual token's repository_ids are not [${V_ID}]: $(snip)"
code="$(req POST "$PREVIEW" "$USER_TOKEN" "{\"repo_selector\":{\"match_repos\":[\"${V_ID}\"]}}")"
case "$code" in 403|404) ;; *) gate "non-admin preview answered ${code}, expected 403/404";; esac
finish_case "the pre-existing selector preview / token list changed"

# =============================================================================
# FIX #4808 / #4213 (RED on 1.11.3: empty page, 404 on detail and versions)
# =============================================================================
begin_test "FIX #4213: the virtual-scoped token lists the granted member's packages with repository_key=<virtual>"
reset_case
code="$(req GET "/api/v1/packages?repository_key=${VIRT}&per_page=100" "$TV")"
note "TV list V: ${code} total=$(jr '.pagination.total // .total') names=$(names) $(snip | head -c 200)"
[ "$code" = "200" ] || gate "TV list V answered ${code}"
[ "$(names)" = "$PA_NAME" ] || gate "TV list V names=$(names), expected exactly ${PA_NAME} (the ungranted member's ${PB_NAME} must stay out)"
[ "$(jr '[.items[]?.repository_key] | unique | join(",")')" = "$VIRT" ] || gate "TV list V rows not reported under ${VIRT}"
finish_case "a virtual-scoped token sees an empty catalog through its virtual"

begin_test "FIX #4213: detail and versions with repository_key=<virtual> answer 200 for the virtual-scoped token"
reset_case
code="$(req GET "/api/v1/packages/${PA}?repository_key=${VIRT}" "$TV")"
note "TV detail PA in V: ${code} $(snip | head -c 200)"
[ "$code" = "200" ] && [ "$(jr '.name')" = "$PA_NAME" ] && [ "$(jr '.repository_key')" = "$VIRT" ] \
  || gate "TV detail PA in V answered ${code} name=$(jr '.name') key=$(jr '.repository_key'), expected 200 ${PA_NAME} ${VIRT}"
code="$(req GET "/api/v1/packages/${PA}/versions?repository_key=${VIRT}" "$TV")"
note "TV versions PA in V: ${code} $(snip | head -c 200)"
[ "$code" = "200" ] && [ "$(jr '[.versions[]?.version] | sort | join(",")')" = "1.0.0,1.1.0" ] \
  || gate "TV versions PA in V answered ${code} versions=$(jr '[.versions[]?.version] | sort | join(",")'), expected 1.0.0,1.1.0"
code="$(req GET "/api/v1/packages/${PB}?repository_key=${VIRT}" "$TV")"
[ "$code" = "404" ] || gate "TV detail of the ungranted member's PB in V answered ${code}, expected 404"
finish_case "detail / versions through the virtual are refused for a virtual-scoped token"

begin_test "FIX #4213: a repository_key that does not hold the package is a 404 (admin and token)"
reset_case
for pair in "${PA}|${OTHER}" "${PC}|${VIRT}" "${PB}|${M1}"; do
  pid="${pair%%|*}"; ctx="${pair##*|}"
  code="$(req GET "/api/v1/packages/${pid}?repository_key=${ctx}" "$ADMIN_TOKEN")"
  code2="$(req GET "/api/v1/packages/${pid}/versions?repository_key=${ctx}" "$ADMIN_TOKEN")"
  note "admin package ${pid:0:8} in ${ctx}: detail ${code}, versions ${code2}"
  [ "$code" = "404" ] || gate "admin detail ${pid} with repository_key=${ctx} answered ${code}, expected 404"
  [ "$code2" = "404" ] || gate "admin versions ${pid} with repository_key=${ctx} answered ${code2}, expected 404"
done
code="$(req GET "/api/v1/packages/${PC}?repository_key=${VIRT}" "$TV")"
[ "$code" = "404" ] || gate "TV detail of PC (not in V) with repository_key=V answered ${code}"
finish_case "the repository_key context does not constrain the package lookup"

# =============================================================================
# FIX #4215 / #4217 (RED on 1.11.3: route absent, preview lenient)
# =============================================================================
begin_test "FIX #4217: scope-analysis names the virtual and the ungranted member (no_grant), not the granted one; the token list counts it"
reset_case
code="$(req GET "${SA_PATH}/${SA}/tokens/${TV_ID}/scope-analysis" "$ADMIN_TOKEN")"
note "analysis: ${code} $(snip)"
want="[{\"virtual_repo_key\":\"${VIRT}\",\"members\":[{\"repo_key\":\"${M2}\",\"reason\":\"no_grant\"}]}]"
[ "$code" = "200" ] || gate "scope-analysis answered ${code}, expected 200"
[ "$(jb '.unreachable')" = "$want" ] || gate "unreachable=$(jb '.unreachable'), expected ${want}"
[ "$(jr '.unreachable_member_count')" = "1" ] || gate "unreachable_member_count=$(jr '.unreachable_member_count'), expected 1"
[ "$(jr '.scope_error // "none"')" = "none" ] || gate "scope_error=$(jr '.scope_error') on a valid pin"
code="$(req GET "${SA_PATH}/${SA}/tokens" "$ADMIN_TOKEN")"
[ "$(K="$TV_ID" jr '.items[]? | select(.id == env.K) | .unreachable_member_count')" = "1" ] \
  || gate "token list unreachable_member_count for the virtual token is '$(K="$TV_ID" jr '.items[]? | select(.id == env.K) | .unreachable_member_count')', expected 1"
finish_case "the per-token scope analysis is missing or wrong"

begin_test "FIX #4217: scope-analysis is admin-only and bound to the owning service account"
reset_case
code="$(req GET "${SA_PATH}/${SA}/tokens/${TV_ID}/scope-analysis" "$ADMIN_TOKEN")"
[ "$code" = "200" ] || gate "admin analysis answered ${code} (the denials below would be hollow)"
code="$(req GET "${SA_PATH}/${SA}/tokens/${TV_ID}/scope-analysis" "$USER_TOKEN")"
case "$code" in 403|404) ;; *) gate "non-admin analysis answered ${code}, expected 403/404";; esac
code="$(req GET "${SA_PATH}/${SA}/tokens/${TV_ID}/scope-analysis" "$TV")"
case "$code" in 403|404) ;; *) gate "the token itself reading its analysis answered ${code}, expected 403/404";; esac
for pair in "${SA2}|${TV_ID}|other service account" "${USER_ID}|${TV_ID}|non-service-account user" \
            "${SA}|00000000-0000-4000-8000-000000000000|unknown token"; do
  acct="${pair%%|*}"; rest="${pair#*|}"; tok="${rest%%|*}"; what="${rest#*|}"
  code="$(req GET "${SA_PATH}/${acct}/tokens/${tok}/scope-analysis" "$ADMIN_TOKEN")"
  note "admin analysis via ${what}: ${code}"
  [ "$code" = "404" ] || gate "analysis via ${what} answered ${code}, expected 404: $(snip)"
  printf '%s' "$(body)" | grep -q "$M2" && gate "analysis via ${what} leaked the member key"
done
finish_case "the scope analysis answers outside its owner"

begin_test "FIX #4217: the selector preview refuses a misspelled selector and analyses on behalf of a service account"
reset_case
code="$(req POST "$PREVIEW" "$ADMIN_TOKEN" '{"repo_selector":{"match_formatz":["maven"]}}')"
note "preview misspelled: ${code} $(snip | head -c 200)"
[ "$code" = "400" ] || gate "misspelled selector answered ${code}, expected 400 (1.11.3 silently drops the unknown key and answers 200)"
printf '%s' "$(body)" | grep -q 'unknown field' || gate "400 body does not name the unknown field"
code="$(req POST "$PREVIEW" "$ADMIN_TOKEN" '{"repo_selector":["not","an","object"]}')"
[ "$code" = "400" ] || gate "non-object selector answered ${code}, expected 400"
code="$(req POST "$PREVIEW" "$ADMIN_TOKEN" "{\"repo_selector\":{\"match_repos\":[\"${V_ID}\"]},\"service_account_id\":\"${SA}\"}")"
note "preview for SA: ${code} $(snip)"
want="[{\"virtual_repo_key\":\"${VIRT}\",\"members\":[{\"repo_key\":\"${M2}\",\"reason\":\"no_grant\"}]}]"
[ "$code" = "200" ] && [ "$(jb '.unreachable')" = "$want" ] || gate "preview for the account answered ${code} unreachable=$(jb '.unreachable'), expected ${want}"
code="$(req POST "$PREVIEW" "$ADMIN_TOKEN" "{\"repo_selector\":{\"match_repos\":[\"${V_ID}\"]},\"service_account_id\":\"${USER_ID}\"}")"
[ "$code" = "404" ] || gate "preview on behalf of a non-service-account user answered ${code}, expected 404"
finish_case "the selector preview does not diagnose"

begin_test "FIX #4217: a stored invalid selector is reported as scope_error=invalid_selector (token list and analysis)"
reset_case
db "UPDATE api_tokens SET repo_selector = '{\"match_repoz\": [\"${M1_ID}\"]}'::jsonb WHERE id = '${TSEL_ID}'" >/dev/null
code="$(req GET "${SA_PATH}/${SA}/tokens" "$ADMIN_TOKEN")"
got="$(K="$TSEL_ID" jr '.items[]? | select(.id == env.K) | .scope_error // "none"')"
note "token list scope_error for the tampered token: ${code} ${got}"
[ "$got" = "invalid_selector" ] || gate "token list scope_error='${got}', expected invalid_selector"
code="$(req GET "${SA_PATH}/${SA}/tokens/${TSEL_ID}/scope-analysis" "$ADMIN_TOKEN")"
[ "$code" = "200" ] && [ "$(jr '.scope_error')" = "invalid_selector" ] || gate "analysis of the tampered token answered ${code} scope_error=$(jr '.scope_error')"
finish_case "an invalid stored selector is not reported"

begin_test "FIX #4213+#4217: once the account is granted M2 the analysis is empty and the virtual lists both members"
reset_case
code="$(grant_read "$SA" "$M2_ID")"
is_2xx "$code" || gate "granting M2 answered ${code}"
code="$(req GET "${SA_PATH}/${SA}/tokens/${TV_ID}/scope-analysis" "$ADMIN_TOKEN")"
note "analysis after grant: ${code} $(snip)"
[ "$code" = "200" ] && [ "$(jb '.unreachable')" = "[]" ] && [ "$(jr '.unreachable_member_count')" = "0" ] \
  || gate "analysis after granting M2 answered ${code} $(snip)"
code="$(req GET "/api/v1/packages?repository_key=${VIRT}&per_page=100" "$TV")"
note "TV list V after grant: ${code} names=$(names)"
[ "$code" = "200" ] && [ "$(names)" = "${PA_NAME},${PB_NAME}" ] || gate "TV list V after granting M2 names=$(names), expected ${PA_NAME},${PB_NAME}"
code="$(req GET "/api/v1/packages?repository_key=${M2}&per_page=100" "$TV")"
[ -z "$(names)" ] || gate "TV list of ${M2} directly shows $(names) after the grant (scope, not grant, must still refuse it)"
finish_case "granting the member does not open it through the virtual"

end_suite
