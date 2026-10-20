#!/usr/bin/env bash
# =============================================================================
# tiers/repo-read-hiding/oracle.sh - private repositories stay invisible to a
#   caller without read: promotion history (#4418), release-target read
#   (#4473), and a NOT_FOUND body identical to a missing repository (#4498)
# =============================================================================
# run.sh has stood up `storage.filesystem` with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Fixture:
#   QS   private generic staging   (R holds `reader`; N holds nothing)
#   QL   private generic local     (release target of QS; R holds `reader`)
#   SP   public generic staging, linked to QL; one artifact promoted SP -> QL
#   Q    private generic local     (not staging; for the type-probe case)
# Callers: N (signed in, no grant), anonymous, R (reader), admin.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
QS="rrh-qstg-${SLOT}-${SUF}"
QL="rrh-qrel-${SLOT}-${SUF}"
SP="rrh-pstg-${SLOT}-${SUF}"
Q="rrh-qloc-${SLOT}-${SUF}"
MISSING="rrh-missing-${SLOT}-${SUF}"
PW="Rrh_${SUF}_Aa1!"
N_USER="rrh-n-${SLOT}-${SUF}"
R_USER="rrh-r-${SLOT}-${SUF}"
# The single body #4498 ships for both "missing" and "unreadable".
NOT_FOUND_BODY='{"code":"NOT_FOUND","message":"Repository not found"}'

WORK="$(mktemp -d -t dtf-rrh-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# req METHOD PATH TOKEN [JSON] -> HTTP code; body in $WORK/body. TOKEN may be
# empty (anonymous).
req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
upload() { # KEY PATH CONTENT TOKEN
  : > "$WORK/body"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -X PUT -o "$WORK/body" -w '%{http_code}' \
    -H "Authorization: Bearer ${4}" -H 'Content-Type: application/octet-stream' \
    --data-binary "$3" "${BASE_URL}/api/v1/repositories/${1}/artifacts/${2}" 2>/dev/null || echo 000
}
body() { head -c 300 "$WORK/body" 2>/dev/null || true; }
raw() { cat "$WORK/body" 2>/dev/null || true; }
jb() { jq -r "$1" "$WORK/body" 2>/dev/null || true; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null | tr -d '[:space:]' || echo "?"; }
setup_ok() {
  if [ "${2:0:1}" != "2" ]; then
    begin_test "setup: ${1}"; infra_fail "${1}: HTTP ${2}" "$(body)"; end_suite
  fi
}

# probe_pair PATH_UNREADABLE PATH_MISSING TOKEN -> sets U_CODE U_BODY M_CODE M_BODY
probe_pair() {
  U_CODE="$(req GET "$1" "$3")"; U_BODY="$(raw)"
  M_CODE="$(req GET "$2" "$3")"; M_BODY="$(raw)"
}

begin_suite "repo-read-hiding"

# =============================================================================
# SETUP
# =============================================================================
auth_admin
AT="$ADMIN_TOKEN"
for u in "$N_USER" "$R_USER"; do
  if ! create_test_user_with_retry "$u" "$PW" "${u}@t.test" >/dev/null; then
    begin_test "setup: create user ${u}"; infra_fail "could not create user ${u}"; end_suite
  fi
done
NT="$(login_as "$N_USER" "$PW")" || true
RT="$(login_as "$R_USER" "$PW")" || true
if [ -z "$NT" ] || [ -z "$RT" ]; then
  begin_test "setup: log in the test users"; infra_fail "a login returned no token"; end_suite
fi

mkrepo() { # KEY TYPE PUBLIC
  req POST /api/v1/repositories "$AT" \
    "$(jq -nc --arg k "$1" --arg t "$2" --argjson p "$3" '{key:$k,name:$k,format:"generic",repo_type:$t,is_public:$p}')"
}
c="$(mkrepo "$QS" staging false)"; setup_ok "create private staging ${QS}" "$c"
c="$(mkrepo "$QL" local false)";   setup_ok "create private local ${QL}" "$c"
c="$(mkrepo "$SP" staging true)";  setup_ok "create public staging ${SP}" "$c"
c="$(mkrepo "$Q" local false)";    setup_ok "create private local ${Q}" "$c"
for k in "$QS" "$QL"; do
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
    INSERT INTO role_assignments (user_id, role_id, repository_id)
    SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
    WHERE u.username='${R_USER}' AND r.name='reader' AND repo.key='${k}'
    ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true
done

# QS -> QL link and one promotion QS -> QL (history on the private staging).
c="$(req PUT "/api/v1/promotion/repositories/${QS}/release-target" "$AT" "$(jq -nc --arg k "$QL" '{release_repository_key:$k}')")"
setup_ok "link ${QS} -> ${QL}" "$c"
c="$(upload "$QS" "rrh/q-1.0.bin" "rrh-q-${SUF}" "$AT")"; setup_ok "upload to ${QS}" "$c"
QA="$(db "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${QS}' AND a.path='rrh/q-1.0.bin';")"
c="$(req POST "/api/v1/promotion/repositories/${QS}/artifacts/${QA}/promote" "$AT" \
  "$(jq -nc --arg k "$QL" '{target_repository:$k,skip_policy_check:true,notes:"rrh-private"}')")"
setup_ok "promote ${QS} -> ${QL}" "$c"

# SP (public) -> QL (private) link and one promotion SP -> QL.
c="$(req PUT "/api/v1/promotion/repositories/${SP}/release-target" "$AT" "$(jq -nc --arg k "$QL" '{release_repository_key:$k}')")"
setup_ok "link ${SP} -> ${QL}" "$c"
c="$(upload "$SP" "rrh/p-1.0.bin" "rrh-p-${SUF}" "$AT")"; setup_ok "upload to ${SP}" "$c"
PA="$(db "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${SP}' AND a.path='rrh/p-1.0.bin';")"
c="$(req POST "/api/v1/promotion/repositories/${SP}/artifacts/${PA}/promote" "$AT" \
  "$(jq -nc --arg k "$QL" '{target_repository:$k,skip_policy_check:true,notes:"rrh-public"}')")"
setup_ok "promote ${SP} -> ${QL}" "$c"
HIST="$(db "SELECT count(*) FROM promotion_history ph JOIN repositories r ON r.id=ph.source_repo_id WHERE r.key IN ('${QS}','${SP}');")"
if [ "$HIST" != "2" ]; then
  begin_test "setup: promotion history rows"; infra_fail "expected 2 promotion_history rows, found ${HIST}"; end_suite
fi

# =============================================================================
# #4498 - unreadable answers byte-identically to missing
# =============================================================================
begin_test "#4498 control: the missing-repository 404 (signed-in, no grant)"
c="$(req GET "/api/v1/repositories/${MISSING}" "$NT")"
if [ "$c" = "404" ]; then pass; else fail "missing repo: HTTP ${c}" "$(body)"; fi

begin_test "#4498 control: a reader of the private repository gets 200 with its key"
c="$(req GET "/api/v1/repositories/${QS}" "$RT")"
if [ "$c" = "200" ] && [ "$(jb '.key')" = "$QS" ]; then pass; else fail "reader GET: HTTP ${c}" "$(body)"; fi

for who in N anon; do
  if [ "$who" = "N" ]; then tok="$NT"; else tok=""; fi
  for sub in "" "/artifacts" "/storage"; do
    begin_test "#4498 fix: ${who} GET /repositories/{private}${sub} is byte-identical to the missing-repository 404"
    probe_pair "/api/v1/repositories/${QS}${sub}" "/api/v1/repositories/${MISSING}${sub}" "$tok"
    if [ "$U_CODE" = "$M_CODE" ] && [ "$U_BODY" = "$M_BODY" ] && [ "$U_BODY" = "$NOT_FOUND_BODY" ]; then pass
    else fail "existence oracle: unreadable ${U_CODE} '${U_BODY:0:160}' vs missing ${M_CODE} '${M_BODY:0:160}'" \
              "expected both ${NOT_FOUND_BODY}"; fi
  done
done

# =============================================================================
# #4418 - promotion history needs read on the repository
# =============================================================================
H="/api/v1/promotion/repositories"

begin_test "#4418 control: admin reads the private staging repository's history (1 row, counterpart key)"
c="$(req GET "${H}/${QS}/promotion-history" "$AT")"
if [ "$c" = "200" ] && [ "$(jb '.items | length')" = "1" ] && [ "$(jb '.items[0].target_repo_key')" = "$QL" ]; then pass
else fail "admin history: HTTP ${c}" "$(body)"; fi

begin_test "#4418 control: a reader of the private staging repository reads its history"
c="$(req GET "${H}/${QS}/promotion-history" "$RT")"
if [ "$c" = "200" ] && [ "$(jb '.items | length')" = "1" ] && [ "$(jb '.items[0].artifact_path')" = "rrh/q-1.0.bin" ]; then pass
else fail "reader history: HTTP ${c}" "$(body)"; fi

begin_test "#4418 fix: non-reader GET .../{private}/promotion-history -> 404 identical to a missing repository, no history"
probe_pair "${H}/${QS}/promotion-history" "${H}/${MISSING}/promotion-history" "$NT"
if [ "$U_CODE" = "404" ] && [ "$U_BODY" = "$M_BODY" ] && ! printf '%s' "$U_BODY" | grep -q 'rrh/q-1.0.bin'; then pass
else fail "non-reader history: unreadable ${U_CODE} '${U_BODY:0:200}' vs missing ${M_CODE} '${M_BODY:0:120}'"; fi

begin_test "#4418 fix: history of a public staging repo blanks the key of the private counterpart for a non-reader"
c="$(req GET "${H}/${SP}/promotion-history" "$NT")"
if [ "$c" = "200" ] && [ "$(jb '.items | length')" = "1" ] && [ "$(jb '.items[0].target_repo_key')" = "" ] \
   && [ "$(jb '.items[0].source_repo_key')" = "$SP" ] && ! grep -qF "$QL" "$WORK/body"; then pass
else fail "counterpart redaction: HTTP ${c}, target_repo_key='$(jb '.items[0].target_repo_key')'" "$(body)"; fi

begin_test "#4418 control: admin sees the counterpart key on the same public history"
c="$(req GET "${H}/${SP}/promotion-history" "$AT")"
if [ "$c" = "200" ] && [ "$(jb '.items[0].target_repo_key')" = "$QL" ]; then pass
else fail "admin public history: HTTP ${c}" "$(body)"; fi

# =============================================================================
# #4473 - release-target read needs read on the repository
# =============================================================================
begin_test "#4473 control: admin reads the private staging repository's release target"
c="$(req GET "${H}/${QS}/release-target" "$AT")"
if [ "$c" = "200" ] && [ "$(jb '.linked')" = "true" ] && [ "$(jb '.release_repository_key')" = "$QL" ]; then pass
else fail "admin release-target: HTTP ${c}" "$(body)"; fi

begin_test "#4473 fix: non-reader GET .../{private staging}/release-target -> 404 identical to a missing repository"
probe_pair "${H}/${QS}/release-target" "${H}/${MISSING}/release-target" "$NT"
if [ "$U_CODE" = "404" ] && [ "$U_BODY" = "$M_BODY" ] && ! printf '%s' "$U_BODY" | grep -qF "$QL"; then pass
else fail "non-reader release-target: unreadable ${U_CODE} '${U_BODY:0:200}' vs missing ${M_CODE} '${M_BODY:0:120}'"; fi

begin_test "#4473 fix: non-reader GET .../{private non-staging}/release-target -> 404 before the type check (no 400)"
probe_pair "${H}/${Q}/release-target" "${H}/${MISSING}/release-target" "$NT"
if [ "$U_CODE" = "404" ] && [ "$U_BODY" = "$M_BODY" ]; then pass
else fail "type oracle: unreadable non-staging ${U_CODE} '${U_BODY:0:200}' vs missing ${M_CODE} '${M_BODY:0:120}'"; fi

begin_test "#4473 control: admin on a non-staging repository still gets the 400 type error"
c="$(req GET "${H}/${Q}/release-target" "$AT")"
if [ "$c" = "400" ]; then pass; else fail "admin non-staging release-target: HTTP ${c}" "$(body)"; fi

begin_test "#4473 fix: public staging linked to a private release repo -> linked:true, key and id null for a non-reader"
c="$(req GET "${H}/${SP}/release-target" "$NT")"
if [ "$c" = "200" ] && [ "$(jb '.linked')" = "true" ] && [ "$(jb '.release_repository_key')" = "null" ] \
   && [ "$(jb '.release_repository_id')" = "null" ] && ! grep -qF "$QL" "$WORK/body"; then pass
else fail "linked-target redaction: HTTP ${c}" "$(body)"; fi

begin_test "#4473 control: a reader of the release repo sees its key on the same public staging repo"
c="$(req GET "${H}/${SP}/release-target" "$RT")"
if [ "$c" = "200" ] && [ "$(jb '.release_repository_key')" = "$QL" ]; then pass
else fail "reader linked-target: HTTP ${c}" "$(body)"; fi

# =============================================================================
# Listing control (pre-existing hiding, both images)
# =============================================================================
begin_test "control: the repository listing for a non-reader omits every private repository"
c="$(req GET "/api/v1/repositories?per_page=200" "$NT")"
if [ "$c" = "200" ] && jb '.items[].key' | grep -qx "$SP" \
   && ! jb '.items[].key' | grep -qE "^(${QS}|${QL}|${Q})$"; then pass
else fail "listing: HTTP ${c}" "$(body)"; fi

end_suite
