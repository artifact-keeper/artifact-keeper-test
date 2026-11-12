#!/usr/bin/env bash
# =============================================================================
# tiers/scan-results-durability/oracle.sh
#   #5534 a finding with a version or source string over 100 characters is
#         stored; it no longer fails the whole findings batch
#   #5564 an over-long scanner_version is stored; what the schema still
#         refuses (a cve_id over 30) is 400 VALIDATION_ERROR, not a 500
#   #5153 an acknowledgement survives a rescan and a promotion
#   #5006 concurrent scan completions in one repository all recalculate the
#         repository score
#   #5715 a scan row whose status the build does not know is unscanned for
#         block_unscanned, not "not applicable"
# See the manifest for the fixes and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock-scan-formats control port, used only to fetch the
# log4j-core fixture), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test.

MOCK="http://127.0.0.1:${TRIVY_PORT}"
LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"
SCAN_WAIT=180
RACE_ROUNDS=5      # #5006: fresh repository per round
RACE_WIDTH=4       # #5006: artifacts whose ingests complete at once per round
BURST_WIDTH=8      # KNOWN-RED pin: a burst past the fix's retry bound

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '\r' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

api(){ # <METHOD> <path> [json] [outfile] -> HTTP code; body in outfile (default $W/api.body)
  local out="${4:-$W/api.body}" code
  code="$(curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$1" "${BASE_URL}$2" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' ${3:+-d "$3"})" || true
  [ -f "$out" ] || : > "$out"
  echo "${code:-000}"
}
abody(){ head -c "${1:-300}" "$W/api.body" 2>/dev/null || true; }
mkrepo(){ # key repo_type -> HTTP code
  api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg t "$2" '{key:$k,name:$k,format:"generic",repo_type:$t,is_public:true}')"
}
repo_id(){ psqlq "SELECT id FROM repositories WHERE key='$1'"; }
upload(){ # repo path file -> artifact id
  curl -s --max-time 60 -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    --data-binary "@$3" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" | jqr '.id // empty'
}
dl(){ # repo path -> HTTP code of an anonymous download
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    "${BASE_URL}/api/v1/repositories/$1/download/$2" 2>/dev/null || echo 000
}
policy(){ # name repo_id -> HTTP code (max_severity high, block_unscanned)
  api POST /api/v1/security/policies "$(jq -nc --arg n "$1" --arg r "$2" \
    '{name:$n,repository_id:$r,max_severity:"high",block_unscanned:true,block_on_fail:false,require_signature:false}')"
}
ingest(){ # json [outfile] -> HTTP code
  api POST /api/v1/security/findings/external "$1" "${2:-$W/api.body}"
}
# open_scans <artifact_id> / grype_rows <artifact_id>
open_scans(){ psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND status IN ('pending','running')"; }
grype_done(){ # artifact_id min_completed_grype_rows
  [ "$(open_scans "$1")" = "0" ] && \
  [ "$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='grype' AND status='completed'")" -ge "$2" ] 2>/dev/null
}

SFX="$(printf '%s' "${RUN_ID##*-}" | tr -cd '0-9' | tail -c 8)"
P="srd${DTF_SLOT}-${SFX}"
ING="${P}-ingest"      # generic local: external submissions (#5534, #5564)
HOS="${P}-hosted"      # generic local: grype rescan after acknowledgement (#5153)
STG="${P}-stg"         # generic staging: promotion source (#5153)
REL="${P}-rel"         # generic local: promotion target with a policy (#5153)
UNK="${P}-state"       # generic local: block_unscanned and seeded scan rows (#5715)
JAR_PATH="lib/log4j-core-2.14.1.jar"

begin_suite "scan-results-durability"
auth_admin

# =============================================================================
begin_test "setup: repositories, the log4j-core fixture and the uploads"
reset_case
curl -s --max-time 15 -o "$W/log4j.jar" "${MOCK}/__golden/maven2/${LOG4J}" || true
[ -s "$W/log4j.jar" ] || fail_g "log4j-core fixture not served by ${MOCK} (profiles/upstreams.mock-scan-formats.yml)"
for r in "$ING:local" "$HOS:local" "$STG:staging" "$REL:local" "$UNK:local"; do
  c="$(mkrepo "${r%%:*}" "${r#*:}")"
  [[ "$c" =~ ^20[01]$ ]] || fail_g "create ${r} -> ${c} $(abody)"
done
for r in "$HOS" "$STG"; do
  c="$(api PUT "/api/v1/repositories/${r}/security" '{"scan_enabled":true,"scan_on_upload":true}')"
  [ "$c" = "200" ] || fail_g "scan config on ${r} -> ${c} $(abody)"
done
printf 'dtf scan-results-durability ingest target %s\n' "$P" > "$W/ing.txt"
A_ING="$(upload "$ING" "ing/target.txt" "$W/ing.txt")"
A_HOS="$(upload "$HOS" "$JAR_PATH" "$W/log4j.jar")"
A_STG="$(upload "$STG" "$JAR_PATH" "$W/log4j.jar")"
for v in A_ING A_HOS A_STG; do [ -n "${!v}" ] || fail_g "upload for ${v} returned no artifact id"; done
finish_case "setup failed"
[ "$FAILS" -eq 0 ] || end_suite

# =============================================================================
# #5534 / #5564: the external findings ingest stores what the scanner said.
# =============================================================================
LONG_FIX="$(printf '1.0.%s, ' $(seq 1 30) | sed 's/, $//')"   # ~180 chars: an advisory listing many fixed versions
LONG_SRC="dtf-scanner/$(printf 'x%.0s' $(seq 1 140))"           # 152 chars
LONG_VER="dtf-scanner-$(printf 'v%.0s' $(seq 1 120))+db-2026-11-01"  # ~145 chars (column was VARCHAR(50))

begin_test "CONTROL: a submission with short strings is stored as one completed scan with every finding"
reset_case
n0="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_ING}'")"
c="$(ingest "$(jq -nc --arg a "$A_ING" '{artifact_id:$a,scanner:"dtf-ext",scanner_version:"1.0",
  findings:[{severity:"high",title:"short one",cve_id:"CVE-2099-55340",affected_component:"libdtf",affected_version:"1.0.0",fixed_version:"1.0.1"},
            {severity:"low",title:"short two",cve_id:"CVE-2099-55341",affected_component:"libdtf",affected_version:"1.0.0"}]}')")"
sid="$(jqr '.scan_id // empty' < "$W/api.body")"
n1="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_ING}'")"
f="$(psqlq "SELECT count(*) FROM scan_findings WHERE scan_result_id='${sid:-00000000-0000-0000-0000-000000000000}'")"
note "POST -> ${c}; scan rows ${n0} -> ${n1}; findings under ${sid:-none}: ${f}"
[ "$c" = "200" ] || fail_g "clean submission -> ${c}: $(abody)"
[ "$((n1 - n0))" = "1" ] || fail_g "expected one new scan row, got $((n1 - n0))"
[ "$f" = "2" ] || fail_g "expected 2 stored findings, got ${f}"
finish_case "external ingest baseline"

begin_test "FIX #5534: findings whose fixed_version, affected_version and source exceed 100 characters are stored with the rest of the batch"
reset_case
n0="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_ING}'")"
c="$(ingest "$(jq -nc --arg a "$A_ING" --arg fx "$LONG_FIX" --arg src "$LONG_SRC" '{artifact_id:$a,scanner:"dtf-ext",scanner_version:"1.0",
  findings:[{severity:"high",title:"ordinary finding",cve_id:"CVE-2099-55342",affected_component:"libdtf",affected_version:"1.0.0",fixed_version:"1.0.1"},
            {severity:"high",title:"many fixed versions",cve_id:"CVE-2099-55343",affected_component:"libdtf",affected_version:("1.0.0-" + ("r" * 110)),fixed_version:$fx},
            {severity:"medium",title:"long source",cve_id:"CVE-2099-55344",affected_component:"libdtf",affected_version:"1.0.0",source:$src}]}')")"
sid="$(jqr '.scan_id // empty' < "$W/api.body")"
n1="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_ING}'")"
got="$(psqlq "SELECT count(*) FROM scan_findings WHERE scan_result_id='${sid:-00000000-0000-0000-0000-000000000000}'")"
fx="$(psqlq "SELECT length(fixed_version) FROM scan_findings WHERE scan_result_id='${sid:-00000000-0000-0000-0000-000000000000}' AND cve_id='CVE-2099-55343'")"
srcl="$(psqlq "SELECT length(source) FROM scan_findings WHERE scan_result_id='${sid:-00000000-0000-0000-0000-000000000000}' AND cve_id='CVE-2099-55344'")"
note "POST -> ${c} $(abody 200); scan rows ${n0} -> ${n1}; findings stored ${got:-0} of 3; fixed_version ${fx:-none} chars (sent ${#LONG_FIX}); source ${srcl:-none} chars (sent ${#LONG_SRC})"
[ "$c" = "200" ] || fail_g "submission with long strings -> ${c}, expected 200 (pre-fix: value too long for type character varying(100))"
[ "${got:-0}" = "3" ] || fail_g "${got:-0} of 3 findings stored"
[ "${fx:-0}" = "${#LONG_FIX}" ] || fail_g "fixed_version stored with ${fx:-no} characters, sent ${#LONG_FIX}"
[ "${srcl:-0}" = "${#LONG_SRC}" ] || fail_g "source stored with ${srcl:-no} characters, sent ${#LONG_SRC}"
finish_case "long finding strings fail the scan"

begin_test "FIX #5564: a scanner_version over 50 characters is stored on a completed scan"
reset_case
c="$(ingest "$(jq -nc --arg a "$A_ING" --arg v "$LONG_VER" '{artifact_id:$a,scanner:"dtf-ext",scanner_version:$v,
  findings:[{severity:"high",title:"provenance",cve_id:"CVE-2099-55640",affected_component:"libdtf",affected_version:"1.0.0"}]}')")"
sid="$(jqr '.scan_id // empty' < "$W/api.body")"
row="$(psqlq "SELECT status||'|'||length(scanner_version) FROM scan_results WHERE id='${sid:-00000000-0000-0000-0000-000000000000}'")"
note "POST -> ${c} $(abody 200); stored status|scanner_version length: ${row:-none} (sent ${#LONG_VER})"
[ "$c" = "200" ] || fail_g "long scanner_version -> ${c}, expected 200 (pre-fix: value too long for type character varying(50))"
[ "$row" = "completed|${#LONG_VER}" ] || fail_g "stored row '${row}', expected completed|${#LONG_VER}"
finish_case "long scanner_version fails the scan"

begin_test "FIX #5564: a cve_id the schema still refuses (over 30 characters) is 400 VALIDATION_ERROR and writes no scan row"
reset_case
n0="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_ING}'")"
c="$(ingest "$(jq -nc --arg a "$A_ING" '{artifact_id:$a,scanner:"dtf-ext",
  findings:[{severity:"high",title:"vendor advisory",cve_id:("VENDOR-ADVISORY-" + ("1" * 30)),affected_component:"libdtf"}]}')")"
code="$(jqr '.code // empty' < "$W/api.body")"
n1="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_ING}'")"
note "POST -> ${c} code=${code:-none} $(abody 200); scan rows ${n0} -> ${n1}"
[ "$c" = "400" ] || fail_g "over-long cve_id -> ${c}, expected 400"
[ "$code" = "VALIDATION_ERROR" ] || fail_g "error code '${code}', expected VALIDATION_ERROR"
[ "$n1" = "$n0" ] || fail_g "the refused submission left $((n1 - n0)) scan row(s)"
finish_case "over-long cve_id not refused cleanly"

# =============================================================================
# #5153: an acknowledgement is a durable decision.
# =============================================================================
begin_test "CONTROL: grype scans log4j-core on upload, a severity policy then blocks it, and acknowledging every finding opens it"
reset_case
t=0; while [ "$t" -lt "$SCAN_WAIT" ]; do grype_done "$A_HOS" 1 && grype_done "$A_STG" 1 && break; sleep 2; t=$((t+2)); done
nf="$(psqlq "SELECT count(*) FROM scan_findings WHERE artifact_id='${A_HOS}' AND severity IN ('critical','high')")"
c="$(policy "${P}-pol-hosted" "$(repo_id "$HOS")")"
d0="$(dl "$HOS" "$JAR_PATH")"
acks=""
for f in $(psqlq "SELECT id FROM scan_findings WHERE artifact_id='${A_HOS}'"); do
  acks="${acks}$(api POST "/api/v1/security/findings/${f}/acknowledge" '{"reason":"dtf: accepted risk"}') "
done
d1="$(dl "$HOS" "$JAR_PATH")"
note "critical/high findings ${nf:-0}; policy -> ${c}; download before ack ${d0}; acks: ${acks}; download after ack ${d1}"
[ "${nf:-0}" -ge 1 ] 2>/dev/null || fail_g "grype reported no critical/high finding for log4j-core 2.14.1"
[ "$c" = "200" ] || [ "$c" = "201" ] || fail_g "policy -> ${c}"
[ "$d0" = "403" ] || fail_g "download before acknowledging -> ${d0}, expected 403"
[[ "$acks" =~ ^(200\ )+$ ]] || fail_g "acknowledge answers: ${acks}"
[ "$d1" = "200" ] || fail_g "download after acknowledging every finding -> ${d1}, expected 200"
finish_case "acknowledgement baseline"

begin_test "FIX #5153: after a rescan (bypass_dedup) reports the same CVEs, the acknowledged artifact still downloads"
reset_case
before="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_HOS}' AND scan_type='grype' AND status='completed'")"
c="$(api POST /api/v1/security/scan "$(jq -nc --arg a "$A_HOS" '{artifact_id:$a,bypass_dedup:true}')")"
t=0; while [ "$t" -lt "$SCAN_WAIT" ]; do grype_done "$A_HOS" "$((before + 1))" && break; sleep 2; t=$((t+2)); done
sleep 2
nf2="$(psqlq "SELECT count(*) FROM scan_findings f JOIN scan_results s ON s.id=f.scan_result_id WHERE s.artifact_id='${A_HOS}' AND s.scan_type='grype' AND s.id=(SELECT id FROM scan_results WHERE artifact_id='${A_HOS}' AND scan_type='grype' ORDER BY created_at DESC LIMIT 1)")"
d2="$(dl "$HOS" "$JAR_PATH")"
q="$(psqlq "SELECT quarantine_status FROM artifacts WHERE id='${A_HOS}'")"
note "rescan -> ${c}; grype rows completed ${before} -> $(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_HOS}' AND scan_type='grype' AND status='completed'"); findings in the new scan ${nf2:-0}; download ${d2}; quarantine_status ${q}"
[ "$c" = "200" ] || fail_g "rescan trigger -> ${c} $(abody)"
[ "${nf2:-0}" -ge 1 ] 2>/dev/null || fail_g "the rescan reported no findings (nothing to carry the decision to)"
[ "$d2" = "200" ] || fail_g "download after the rescan -> ${d2}, expected 200 (pre-fix: the rescan's rows start unacknowledged and the policy blocks again)"
finish_case "acknowledgement lost on rescan"

begin_test "FIX #5153: an acknowledged artifact promoted into a repository with a block_unscanned severity policy downloads there"
reset_case
c0="$(policy "${P}-pol-rel" "$(repo_id "$REL")")"
acks=""
for f in $(psqlq "SELECT id FROM scan_findings WHERE artifact_id='${A_STG}'"); do
  acks="${acks}$(api POST "/api/v1/security/findings/${f}/acknowledge" '{"reason":"dtf: accepted risk"}') "
done
ds="$(dl "$STG" "$JAR_PATH")"
c="$(api POST "/api/v1/promotion/repositories/${STG}/artifacts/${A_STG}/promote" "$(jq -nc --arg t "$REL" '{target_repository:$t}')" "$W/promo.json")"
dr="$(dl "$REL" "$JAR_PATH")"
note "policy on ${REL} -> ${c0}; acks: ${acks}; staging download ${ds}; promote -> ${c} $(head -c 300 "$W/promo.json"); target download ${dr}"
[[ "$acks" =~ ^(200\ )+$ ]] || fail_g "acknowledge answers: ${acks}"
[ "$c" = "200" ] && [ "$(jqr '.promoted' < "$W/promo.json")" = "true" ] || \
  fail_g "promotion -> ${c} promoted=$(jqr '.promoted' < "$W/promo.json") violations $(jq -c '.policy_violations // []' < "$W/promo.json" 2>/dev/null | head -c 200) (pre-fix: the promotion gate counts acknowledged findings)"
[ "$dr" = "200" ] || fail_g "download of the promoted copy -> ${dr}, expected 200 (pre-fix: the promotion is refused, or the copy carries no scan rows and block_unscanned refuses it)"
finish_case "acknowledgement lost on promotion"

# =============================================================================
# #5006: concurrent completions in one repository.
# =============================================================================
# race_round <repo key> <width> <round tag>: <width> external ingests into fresh
# artifacts of a fresh repository, all at once. Leaves RACE_BAD (non-200
# answers) and RACE_SCORE ("scanned|high_count" of the stored score).
RACE_BAD=0; RACE_SCORE=""
race_round(){
  local rr="$1" width="$2" tag="$3" c i a cc codes=""
  RACE_BAD=0; RACE_SCORE=""
  c="$(mkrepo "$rr" local)"
  [[ "$c" =~ ^20[01]$ ]] || { fail_g "create ${rr} -> ${c}"; RACE_BAD=-1; return; }
  local ids=()
  for i in $(seq 1 "$width"); do
    printf 'dtf race %s %s %s\n' "$P" "$tag" "$i" > "$W/race-${tag}-${i}.txt"
    ids+=("$(upload "$rr" "race/f${i}.txt" "$W/race-${tag}-${i}.txt")")
  done
  for i in $(seq 1 "$width"); do
    a="${ids[$((i - 1))]}"
    ingest "$(jq -nc --arg a "$a" --arg cve "CVE-2099-5006${tag}$(printf '%02d' "$i")" '{artifact_id:$a,scanner:"dtf-race",scanner_version:"1.0",
      findings:[{severity:"high",title:"race",cve_id:$cve,affected_component:"librace",affected_version:"1.0.0"}]}')" \
      "$W/race-${tag}-${i}.out" > "$W/race-${tag}-${i}.code" &
  done
  wait
  for i in $(seq 1 "$width"); do
    cc="$(cat "$W/race-${tag}-${i}.code")"; codes="${codes}${cc} "
    if [ "$cc" != "200" ]; then RACE_BAD=$((RACE_BAD + 1)); note "round ${tag} ingest ${i} -> ${cc}: $(head -c 200 "$W/race-${tag}-${i}.out")"; fi
  done
  sleep 1
  api GET "/api/v1/repositories/${rr}/security" "" "$W/race-${tag}.sec" >/dev/null
  RACE_SCORE="$(jqr '"\(.score.coverage.scanned // "none")|\(.score.high_count // "none")"' < "$W/race-${tag}.sec")"
  note "round ${tag}: answers ${codes}; stored score scanned|high = ${RACE_SCORE} (want ${width}|${width})"
}

begin_test "FIX #5006: ${RACE_ROUNDS} rounds of ${RACE_WIDTH} scan completions at once in one repository all succeed and the score counts every one"
reset_case
for r in $(seq 1 "$RACE_ROUNDS"); do
  race_round "${P}-race${r}" "$RACE_WIDTH" "$r"
  [ "$RACE_BAD" = "0" ] || fail_g "round ${r}: ${RACE_BAD} of ${RACE_WIDTH} concurrent completions failed (pre-fix: could not serialize access due to concurrent update, no retry)"
  [ "$RACE_SCORE" = "${RACE_WIDTH}|${RACE_WIDTH}" ] || fail_g "round ${r}: stored score scanned|high ${RACE_SCORE}, want ${RACE_WIDTH}|${RACE_WIDTH} (a recalculation was lost)"
done
finish_case "concurrent completions lose a score recalculation"

# KNOWN-RED pin (reported, never failed). With #5007 a recalculation that finds
# the repository lock busy waits for the holder and starts over, and the last of
# its 8 attempts waits for the lock inside its REPEATABLE READ transaction. That
# wait happens after the snapshot is taken, so a burst wide enough to use up the
# attempts still answers 500 "could not serialize access" on main (measured on
# 2bdf092: width 6, 3 of 10 rounds; width 8, 10 of 10; width 4, 0 of 30).
begin_test "KNOWN-RED #5006 follow-up: ${BURST_WIDTH} scan completions at once in one repository (reported, not gated)"
reset_case
race_round "${P}-burst" "$BURST_WIDTH" "b"
if [ "$RACE_BAD" = "0" ] && [ "$RACE_SCORE" = "${BURST_WIDTH}|${BURST_WIDTH}" ]; then
  echo "   KNOWN-RED pin now passes (${BURST_WIDTH} of ${BURST_WIDTH}, score ${RACE_SCORE}): flip it to a FIX assertion"
else
  echo "   KNOWN-RED (not gated): ${RACE_BAD} of ${BURST_WIDTH} completions failed; stored score ${RACE_SCORE}"
fi
pass

# =============================================================================
# #5715: classify_scan_state and a status this build does not know.
# The tier's database stands in for a newer release that wrote a new status:
# the status CHECK constraint is dropped and rows are seeded directly.
# =============================================================================
seed_scan(){ # artifact_id scan_type status [error_message]
  psqlq "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, error_message, started_at, completed_at)
         SELECT a.id, a.repository_id, '$2', '$3', $( [ -n "${4:-}" ] && echo "'$4'" || echo NULL ), now(), now()
           FROM artifacts a WHERE a.id='$1' RETURNING id" | head -1
}
begin_test "CONTROL: block_unscanned refuses an unscanned artifact and passes one whose only row is not_applicable"
reset_case
printf 'dtf state never %s\n' "$P" > "$W/never.txt"; printf 'dtf state na %s\n' "$P" > "$W/na.txt"; printf 'dtf state unknown %s\n' "$P" > "$W/unk.txt"
A_NEVER="$(upload "$UNK" "state/never.txt" "$W/never.txt")"
A_NA="$(upload "$UNK" "state/na.txt" "$W/na.txt")"
A_UNK="$(upload "$UNK" "state/unknown.txt" "$W/unk.txt")"
c="$(policy "${P}-pol-state" "$(repo_id "$UNK")")"
s_na="$(seed_scan "$A_NA" license not_applicable "Scanner license does not apply to this artifact format")"
d_never="$(dl "$UNK" state/never.txt)"; d_na="$(dl "$UNK" state/na.txt)"
note "policy -> ${c}; seeded not_applicable row ${s_na:-none}; never scanned -> ${d_never}; not_applicable -> ${d_na}"
[ -n "$A_NEVER" ] && [ -n "$A_NA" ] && [ -n "$A_UNK" ] || fail_g "uploads returned no artifact id"
[ "$c" = "200" ] || [ "$c" = "201" ] || fail_g "policy -> ${c}"
[ -n "$s_na" ] || fail_g "could not seed the not_applicable row"
[ "$d_never" = "403" ] || fail_g "never-scanned download -> ${d_never}, expected 403"
[ "$d_na" = "200" ] || fail_g "not_applicable download -> ${d_na}, expected 200"
finish_case "block_unscanned baseline"

begin_test "FIX #5715: an artifact whose only scan row has a status the build does not know is refused by block_unscanned"
reset_case
psqlq "ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_status_check" >/dev/null
s_unk="$(seed_scan "$A_UNK" grype superseded)"
d_unk="$(dl "$UNK" state/unknown.txt)"
note "seeded status 'superseded' row ${s_unk:-none}; download -> ${d_unk}"
[ -n "$s_unk" ] || fail_g "could not seed the unknown-status row"
[ "$d_unk" = "403" ] || fail_g "unknown-status download -> ${d_unk}, expected 403 (pre-fix: classified not_applicable and served)"
finish_case "unknown scan status fails open"

end_suite
