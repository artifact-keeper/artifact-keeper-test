#!/usr/bin/env bash
# =============================================================================
# tiers/promotion-and-curation-validation/oracle.sh
#   #4204 a quality gate that cannot be evaluated (database error) fails the
#         promotion closed: single -> 503, bulk -> that item fails
#   #4245 a curation rule with an unknown top-level action is a 400, not 500
#   #4246 a publisher_trust config the evaluator would reject is a 400
#   #4251 publisher-trust rules judge conda_native packages
#   #4506 origin predicates gate a Remote's proxied content (cache included)
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

DBC="$DB_CONTAINER"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# call METHOD PATH BODY OUTFILE -> http code (admin bearer)
call(){
  local method="$1" path="$2" body="$3" out="$4" code
  rm -f "$out"
  if [ -n "$body" ]; then
    code="$(curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
      -d "$body" "${BASE_URL}${path}" 2>/dev/null)"
  else
    code="$(curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}${path}" 2>/dev/null)"
  fi
  [ -f "$out" ] || : > "$out"
  echo "${code:-000}"
}

P="pc${DTF_SLOT}-$(echo "$RUN_ID" | tr 'A-Z_' 'a-z-' | tr -cd 'a-z0-9-' | tail -c 12)"
S_G="${P}-stg-gated"     # generic staging with an (always passing) block gate
S_N="${P}-stg-none"      # generic staging, no gate
R="${P}-rel"             # generic release
CUR="${P}-cur"           # conda_native staging that carries curation rows
UP="${P}-up"             # generic hosted repository the Remotes proxy
RM_OK="${P}-rm-ok"       # Remote, no policy / an admitting policy
RM_K="${P}-rm-kind"      # Remote, origin.allowed_kinds=[hosted]
RM_U="${P}-rm-ups"       # Remote, origin.denied_upstreams=[its upstream]
VR="${P}-virt"           # virtual over RM_K
HS_OFF="artifact_health_scores_dtf_off"

repo_id(){ psql_q "SELECT id FROM repositories WHERE key='$1'" | tr -d '[:space:]'; }
mkrepo(){ # key format type [upstream] -> id
  local extra=""
  [ -n "${4:-}" ] && extra=",\"upstream_url\":\"$4\""
  call POST /api/v1/repositories \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"$3\",\"is_public\":true${extra}}" "$W/mk.json" >/dev/null
  repo_id "$1"
}
upload(){ # repo path file -> artifact id
  curl -s --max-time 60 -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    --data-binary "@$3" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" | jqr '.id // empty'
}
art_in(){ psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$1' AND a.path='$2' AND NOT a.is_deleted" | head -1 | tr -d '[:space:]'; }
promote(){ call POST "/api/v1/promotion/repositories/$1/artifacts/$2/promote" "{\"target_repository\":\"$3\"}" "$4"; }
policy(){ # name repo_id predicates_json -> http code; id in $W/pol.json
  call POST /api/v1/security/policies \
    "{\"name\":\"$1\",\"repository_id\":\"$2\",\"max_severity\":\"critical\",\"block_unscanned\":false,\"block_on_fail\":false,\"predicates\":$3}" "$W/pol.json"
}
remote_get(){ # repo path out -> http code
  rm -f "$3"
  curl -s --max-time 30 -o "$3" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/$1/download/$2" 2>/dev/null || echo 000
}

# Restore the health-score table whatever happens to the run.
restore_hs(){
  if [ "$(psql_q "SELECT to_regclass('public.${HS_OFF}') IS NOT NULL")" = "t" ]; then
    psql_q "ALTER TABLE ${HS_OFF} RENAME TO artifact_health_scores" >/dev/null
  fi
}
add_exit_handler restore_hs

begin_suite "promotion-and-curation-validation"
auth_admin

# =============================================================================
begin_test "setup: repositories, gate, uploads, Remotes"
reset_case
ID_G="$(mkrepo "$S_G" generic staging)"
# shellcheck disable=SC2034  # checked through ${!v} below
ID_N="$(mkrepo "$S_N" generic staging)"
# shellcheck disable=SC2034  # checked through ${!v} below
ID_R="$(mkrepo "$R" generic local)"
ID_CUR="$(mkrepo "$CUR" conda_native staging)"
# shellcheck disable=SC2034  # checked through ${!v} below
ID_UP="$(mkrepo "$UP" generic local)"
for v in ID_G ID_N ID_R ID_CUR ID_UP; do
  [ -n "${!v}" ] || fail_g "repository for ${v} was not created ($(head -c 200 "$W/mk.json"))"
done
for f in g1 g2 g3 n1 u1 u2 u3; do printf '%s-%s\n' "$P" "$f" > "$W/$f.txt"; done
A_G1="$(upload "$S_G" "g/g1.txt" "$W/g1.txt")"
A_G2="$(upload "$S_G" "g/g2.txt" "$W/g2.txt")"
A_G3="$(upload "$S_G" "g/g3.txt" "$W/g3.txt")"
A_N1="$(upload "$S_N" "n/n1.txt" "$W/n1.txt")"
for f in u1 u2 u3; do [ -n "$(upload "$UP" "f/${f}.txt" "$W/${f}.txt")" ] || fail_g "upstream upload ${f} failed"; done
for v in A_G1 A_G2 A_G3 A_N1; do [ -n "${!v}" ] || fail_g "upload for ${v} returned no artifact id"; done
# min_health_score 0 always passes: the gate EXISTS, so evaluation has to
# read the artifact's health score, which is what the fault below breaks.
st="$(call POST /api/v1/quality/gates "{\"name\":\"${P}-gate\",\"repository_id\":\"${ID_G}\",\"min_health_score\":0,\"enforce_on_promotion\":true,\"action\":\"block\"}" "$W/gate.json")"
[ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "quality gate -> HTTP ${st} $(head -c 200 "$W/gate.json")"
hs_ready(){ [ "$(psql_q "SELECT count(*) FROM artifact_health_scores WHERE artifact_id IN ('${A_G1}','${A_G2}','${A_G3}')" | tr -d '[:space:]')" = "3" ]; }
wait_until "health scores" 30 hs_ready || fail_g "health scores never appeared"

# The Remotes proxy the hosted repository through the backend's own address
# on the compose network (loopback and service names are refused as
# upstreams; UPSTREAM_ALLOW_PRIVATE_IPS admits the private address).
BIP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$BACKEND_CTR" 2>/dev/null | awk '{print $1}')"
[ -n "$BIP" ] || fail_g "could not read the backend container address"
UPURL="http://${BIP}:8080/api/v1/repositories/${UP}/download"
ID_RM_OK="$(mkrepo "$RM_OK" generic remote "$UPURL")"
ID_RM_K="$(mkrepo "$RM_K" generic remote "$UPURL")"
ID_RM_U="$(mkrepo "$RM_U" generic remote "$UPURL")"
for v in ID_RM_OK ID_RM_K ID_RM_U; do
  [ -n "${!v}" ] || fail_g "Remote for ${v} was not created ($(head -c 200 "$W/mk.json"))"
done
create_virtual_repo "$VR" generic "$RM_K" >/dev/null 2>&1 || true
[ -n "$(repo_id "$VR")" ] || fail_g "virtual ${VR} was not created"
finish_case "setup failed"

# =============================================================================
begin_test "CONTROL: Remotes serve the upstream bytes (and warm their caches) before any policy"
reset_case
for rk in "$RM_OK" "$RM_K" "$RM_U"; do
  st="$(remote_get "$rk" "f/u1.txt" "$W/rg.out")"
  [ "$st" = "200" ] && [ "$(cat "$W/rg.out")" = "$(cat "$W/u1.txt")" ] \
    || fail_g "${rk} f/u1.txt -> HTTP ${st} '$(head -c 80 "$W/rg.out")'"
done
st="$(remote_get "$VR" "f/u3.txt" "$W/rg.out")"
[ "$st" = "200" ] && [ "$(cat "$W/rg.out")" = "$(cat "$W/u3.txt")" ] \
  || fail_g "virtual ${VR} f/u3.txt -> HTTP ${st} '$(head -c 80 "$W/rg.out")'"
finish_case "the Remote / virtual proxy path is broken"

# Attach the policies now: RM_K admits only hosted content, RM_U denies its
# own upstream, RM_OK gets a policy whose predicates ADMIT a Remote.
st="$(policy "${P}-pol-kind" "$ID_RM_K" '{"origin":{"allowed_kinds":["hosted"]}}')"; POL_K="$(jqr '.id // empty' < "$W/pol.json")"
[ "$st" = "200" ] || [ "$st" = "201" ] || echo "   policy kind -> HTTP ${st}"
st="$(policy "${P}-pol-ups" "$ID_RM_U" "{\"origin\":{\"denied_upstreams\":[\"${UPURL}\"]}}")"; POL_U="$(jqr '.id // empty' < "$W/pol.json")"
[ "$st" = "200" ] || [ "$st" = "201" ] || echo "   policy ups -> HTTP ${st}"
st="$(policy "${P}-pol-ok" "$ID_RM_OK" '{"origin":{"allowed_kinds":["proxy"]}}')"
[ "$st" = "200" ] || [ "$st" = "201" ] || echo "   policy ok -> HTTP ${st}"

begin_test "CONTROL: a policy whose origin predicates admit a Remote does not block it"
reset_case
for pth in f/u1.txt f/u2.txt; do
  st="$(remote_get "$RM_OK" "$pth" "$W/rg.out")"
  b="$(basename "$pth" .txt)"
  [ "$st" = "200" ] && [ "$(cat "$W/rg.out")" = "$(cat "$W/${b}.txt")" ] \
    || fail_g "${RM_OK} ${pth} -> HTTP ${st} '$(head -c 80 "$W/rg.out")'"
done
finish_case "an admitting origin policy blocks a Remote"

begin_test "FIX #4506: origin predicates refuse a Remote's proxied content, cached entries included"
reset_case
for rk in "$RM_K" "$RM_U"; do
  for pth in f/u1.txt f/u2.txt; do   # u1 is cached, u2 never fetched
    st="$(remote_get "$rk" "$pth" "$W/rg.out")"
    [ "$st" = "403" ] || fail_g "${rk} ${pth} -> HTTP ${st} (want 403) '$(head -c 80 "$W/rg.out")'"
    grep -q "blocked by the repository's scan policy" "$W/rg.out" \
      || fail_g "${rk} ${pth}: body does not name the scan policy: '$(head -c 120 "$W/rg.out")'"
    grep -q "$(cat "$W/$(basename "$pth" .txt).txt")" "$W/rg.out" && fail_g "${rk} ${pth}: refused response carries the content"
  done
done
st="$(remote_get "$VR" "f/u3.txt" "$W/rg.out")"
[ "$st" != "200" ] || fail_g "virtual over a refused Remote still serves its cached content (HTTP 200)"
grep -q "$(cat "$W/u3.txt")" "$W/rg.out" && fail_g "virtual response carries the refused member's content"
finish_case "#4506 origin policies do not gate Remote content"

begin_test "CONTROL: removing the policies restores the Remotes"
reset_case
[ -n "$POL_K" ] && call DELETE "/api/v1/security/policies/${POL_K}" "" "$W/del.json" >/dev/null
[ -n "$POL_U" ] && call DELETE "/api/v1/security/policies/${POL_U}" "" "$W/del.json" >/dev/null
for rk in "$RM_K" "$RM_U"; do
  st="$(remote_get "$rk" "f/u2.txt" "$W/rg.out")"
  [ "$st" = "200" ] && [ "$(cat "$W/rg.out")" = "$(cat "$W/u2.txt")" ] \
    || fail_g "${rk} f/u2.txt after policy removal -> HTTP ${st} '$(head -c 80 "$W/rg.out")'"
done
finish_case "a Remote stays blocked after its policy is removed"

# =============================================================================
# #4204 fault: the quality gate's health-score read fails with a database
# error (table renamed away). The gate row itself is still readable.
psql_q "ALTER TABLE artifact_health_scores RENAME TO ${HS_OFF}" >/dev/null

begin_test "CONTROL: with no gate configured, promotion proceeds while health scores are unreadable"
reset_case
st="$(promote "$S_N" "$A_N1" "$R" "$W/n1.json")"
[ "$st" = "200" ] && [ "$(jqr '.promoted' < "$W/n1.json")" = "true" ] \
  || fail_g "ungated promote -> HTTP ${st} $(head -c 300 "$W/n1.json")"
[ -n "$(art_in "$R" "n/n1.txt")" ] || fail_g "ungated artifact did not land in the target"
finish_case "an ungated promotion depends on the gate tables"

begin_test "FIX #4204: a gate evaluation error refuses a single promotion with a retryable 503"
reset_case
st="$(promote "$S_G" "$A_G1" "$R" "$W/g1.json")"
[ "$st" = "503" ] || fail_g "gated promote under a gate DB error -> HTTP ${st} (want 503): $(head -c 300 "$W/g1.json")"
grep -q "could not be evaluated" "$W/g1.json" || fail_g "503 body does not say the gate could not be evaluated"
grep -qi "artifact_health_scores\|relation" "$W/g1.json" && fail_g "503 body leaks the database error"
[ -z "$(art_in "$R" "g/g1.txt")" ] || fail_g "the artifact was promoted without its gate"
[ "$(psql_q "SELECT count(*) FROM promotion_history WHERE artifact_id='${A_G1}'" | tr -d '[:space:]')" = "0" ] \
  || fail_g "a promotion_history row was written"
finish_case "#4204 gate evaluation error fails open (single)"

begin_test "FIX #4204: a gate evaluation error fails that bulk item"
reset_case
st="$(call POST "/api/v1/promotion/repositories/${S_G}/promote" "{\"target_repository\":\"${R}\",\"artifact_ids\":[\"${A_G2}\"]}" "$W/g2.json")"
[ "$st" = "200" ] || fail_g "bulk -> HTTP ${st}"
[ "$(jqr '.results[0].promoted' < "$W/g2.json")" = "false" ] && [ "$(jqr '.failed' < "$W/g2.json")" = "1" ] \
  || fail_g "bulk item under a gate DB error: $(head -c 300 "$W/g2.json")"
jqr '.results[0].message' < "$W/g2.json" | grep -qi "quality gate" || fail_g "bulk item message does not name the gate failure"
[ -z "$(art_in "$R" "g/g2.txt")" ] || fail_g "the bulk item was promoted without its gate"
finish_case "#4204 gate evaluation error fails open (bulk)"

restore_hs

begin_test "CONTROL: once the gate can be evaluated again, the gated promotion succeeds"
reset_case
st="$(promote "$S_G" "$A_G3" "$R" "$W/g3.json")"
[ "$st" = "200" ] && [ "$(jqr '.promoted' < "$W/g3.json")" = "true" ] \
  || fail_g "gated promote after restore -> HTTP ${st} $(head -c 300 "$W/g3.json")"
finish_case "a passing gate refuses a promotion"

# =============================================================================
RULES=()
rule_body(){ # action rule_type config_json -> JSON
  printf '{"action":"%s","reason":"%s","rule_type":"%s","scope":"repository","staging_repo_id":"%s","priority":40,"package_pattern":"*","config":%s}' \
    "$1" "${P}-rule" "$2" "$ID_CUR" "$3"
}
PT_OK='{"trusted_publishers":["NumFOCUS"],"match":"metadata","action":"block"}'

begin_test "CONTROL: valid pattern and publisher_trust rules are created (201)"
reset_case
st="$(call POST /api/v1/curation/rules "$(rule_body block pattern '{}')" "$W/r1.json")"
R_PAT="$(jqr '.id // empty' < "$W/r1.json")"
[ "$st" = "201" ] && [ -n "$R_PAT" ] || fail_g "pattern rule -> HTTP ${st} $(head -c 200 "$W/r1.json")"
st="$(call POST /api/v1/curation/rules "$(rule_body block publisher_trust "$PT_OK")" "$W/r2.json")"
R_PT="$(jqr '.id // empty' < "$W/r2.json")"
[ "$st" = "201" ] && [ -n "$R_PT" ] || fail_g "publisher_trust rule -> HTTP ${st} $(head -c 200 "$W/r2.json")"
RULES+=("$R_PAT" "$R_PT")
# The pattern rule would block everything in the staging repo; disable it so
# only the publisher_trust rule judges the seeded packages below.
psql_q "UPDATE curation_rules SET enabled=false WHERE id='${R_PAT}'" >/dev/null
finish_case "valid curation rules are refused"

begin_test "FIX #4245: an unknown top-level action is a 400 naming the allowed actions (create and update)"
reset_case
st="$(call POST /api/v1/curation/rules "$(rule_body flag pattern '{}')" "$W/a1.json")"
[ "$st" = "400" ] || fail_g "create action=flag -> HTTP ${st} (want 400) $(head -c 200 "$W/a1.json")"
{ grep -q "allow" "$W/a1.json" && grep -q "block" "$W/a1.json"; } || fail_g "create 400 does not list allow/block: $(head -c 200 "$W/a1.json")"
id="$(jqr '.id // empty' < "$W/a1.json")"
[ -n "$id" ] && call DELETE "/api/v1/curation/rules/${id}" "" "$W/del.json" >/dev/null
st="$(call PUT "/api/v1/curation/rules/${R_PAT}" "{\"package_pattern\":\"*\",\"action\":\"flag\",\"reason\":\"x\"}" "$W/a2.json")"
[ "$st" = "400" ] || fail_g "update action=flag -> HTTP ${st} (want 400) $(head -c 200 "$W/a2.json")"
[ "$(psql_q "SELECT action FROM curation_rules WHERE id='${R_PAT}'" | tr -d '[:space:]')" = "block" ] || fail_g "the rule's action changed"
finish_case "#4245 unknown curation action is not a 400"

begin_test "FIX #4246: a publisher_trust config the evaluator would reject is a 400 naming the field"
reset_case
check_bad(){ # label config want_substring
  local st id
  st="$(call POST /api/v1/curation/rules "$(rule_body block publisher_trust "$2")" "$W/pt.json")"
  # A misconfigured rule that WAS accepted (pre-fix) is deleted at once so it
  # cannot judge the seeded packages below.
  id="$(jqr '.id // empty' < "$W/pt.json")"
  [ -n "$id" ] && call DELETE "/api/v1/curation/rules/${id}" "" "$W/del.json" >/dev/null
  [ "$st" = "400" ] || fail_g "$1 -> HTTP ${st} (want 400) $(head -c 200 "$W/pt.json")"
  grep -q "$3" "$W/pt.json" || fail_g "$1: 400 does not name '$3': $(head -c 200 "$W/pt.json")"
}
check_bad "empty trusted_publishers" '{"trusted_publishers":[],"match":"metadata","action":"block"}' "trusted_publishers"
check_bad "missing trusted_publishers" '{"match":"metadata","action":"block"}' "trusted_publishers"
check_bad "bad match" '{"trusted_publishers":["a"],"match":"fuzzy","action":"block"}' "match"
check_bad "bad config action" '{"trusted_publishers":["a"],"match":"metadata","action":"explode"}' "action"
st="$(call PUT "/api/v1/curation/rules/${R_PT}" "{\"package_pattern\":\"*\",\"action\":\"block\",\"reason\":\"x\",\"rule_type\":\"publisher_trust\",\"config\":{\"trusted_publishers\":[]}}" "$W/pt.json")"
[ "$st" = "400" ] || fail_g "update to an empty trusted_publishers -> HTTP ${st} (want 400)"
[ "$(psql_q "SELECT config->'trusted_publishers'->>0 FROM curation_rules WHERE id='${R_PT}'" | tr -d '[:space:]')" = "NumFOCUS" ] \
  || fail_g "the rule's config changed"
# Put the valid config back (a pre-fix image accepted the update above).
call PUT "/api/v1/curation/rules/${R_PT}" "{\"package_pattern\":\"*\",\"action\":\"block\",\"reason\":\"${P}-rule\",\"rule_type\":\"publisher_trust\",\"config\":${PT_OK}}" "$W/pt.json" >/dev/null
finish_case "#4246 invalid publisher_trust config is accepted"

# Seed curation rows (the publisher signal reads only the metadata blob).
seed_pkg(){ # name format metadata_json
  psql_q "INSERT INTO curation_packages (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path, status, metadata) VALUES ('${ID_CUR}','${ID_CUR}','$2','$1','1.0.0','/$1','pending','$3'::jsonb)" >/dev/null
}
pkg(){ psql_q "SELECT status || '|' || COALESCE(rule_id::text,'NULL') FROM curation_packages WHERE staging_repo_id='${ID_CUR}' AND package_name='$1'" | tr -d '[:space:]'; }
seed_pkg "${P}-pypi-evil" pypi '{"info":{"name":"x","author":"evil-corp"}}'
seed_pkg "${P}-raw" raw '{}'
seed_pkg "${P}-cn-evil" conda_native '{"about":{"maintainer":"evil-corp"}}'
seed_pkg "${P}-cn-good" conda_native '{"about":{"maintainer":"NumFOCUS"}}'
st="$(call POST /api/v1/curation/packages/re-evaluate "{\"staging_repo_id\":\"${ID_CUR}\",\"default_action\":\"allow\"}" "$W/re.json")"
[ "$st" = "200" ] || echo "   re-evaluate -> HTTP ${st} $(head -c 200 "$W/re.json")"

begin_test "CONTROL: publisher_trust blocks an untrusted pypi publisher and passes a raw package through"
reset_case
[ "$(pkg "${P}-pypi-evil")" = "blocked|${R_PT}" ] || fail_g "pypi untrusted: '$(pkg "${P}-pypi-evil")' (want blocked|${R_PT})"
[ "$(pkg "${P}-raw")" = "approved|NULL" ] || fail_g "raw: '$(pkg "${P}-raw")' (want approved|NULL)"
finish_case "publisher_trust baseline is broken"

begin_test "FIX #4251: publisher_trust judges conda_native packages (untrusted blocked, trusted approved by the rule)"
reset_case
[ "$(pkg "${P}-cn-evil")" = "blocked|${R_PT}" ] || fail_g "conda_native untrusted: '$(pkg "${P}-cn-evil")' (want blocked|${R_PT}; pre-fix NotApplicable -> approved|NULL)"
reason="$(psql_q "SELECT evaluation_reason FROM curation_packages WHERE staging_repo_id='${ID_CUR}' AND package_name='${P}-cn-evil'")"
echo "$reason" | grep -q "evil-corp" || fail_g "block reason does not name the publisher: '${reason}'"
[ "$(pkg "${P}-cn-good")" = "approved|${R_PT}" ] \
  || fail_g "conda_native trusted publisher: '$(pkg "${P}-cn-good")' (want approved|${R_PT}: allowed BY the rule, not by the default)"
finish_case "#4251 publisher trust does not apply to conda_native"

# --- cleanup -----------------------------------------------------------------
for id in "${RULES[@]}"; do [ -n "$id" ] && call DELETE "/api/v1/curation/rules/${id}" "" "$W/del.json" >/dev/null; done
psql_q "DELETE FROM curation_packages WHERE staging_repo_id='${ID_CUR}'" >/dev/null

end_suite
