#!/usr/bin/env bash
# =============================================================================
# tiers/osv-positional-findings/oracle.sh
#   #4079 OSV querybatch answers mapped positionally (no cross-dependency
#         contamination through the advisory cache)
#   #4081 a finding names the dependency it is about, not deps.first()
#   #4150 OSV findings carry CVE id, fixed version and title; the same CVE in
#         two packages is reported for each
#   #4080 an advisory-feed outage grades the dependency scan `partial`, and an
#         unanswered query is not cached as clean
# See the manifest for the fixes and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock OSV's published control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
SCAN_WAIT=120

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- mock OSV control ----------------------------------------------------------
mock_mode(){ curl -s --max-time 5 -X PUT --data "$1" "${MOCK}/__mode" | jqr '.mode // empty'; }
mock_reset(){ curl -s --max-time 5 -X POST "${MOCK}/__reset" >/dev/null || true; }
# mock_queried <name>: how many querybatch requests named this package
mock_queried(){
  curl -s --max-time 5 "${MOCK}/__requests" \
    | jq --arg n "$1" '[.[] | select(.path == "/v1/querybatch")
        | select([.body.queries[]?.package.name] | index($n))] | length' 2>/dev/null || echo 0
}
# mock_record_gets <id>: GET /v1/vulns/<id> count
mock_record_gets(){
  curl -s --max-time 5 "${MOCK}/__requests" \
    | jq --arg p "/v1/vulns/$1" '[.[] | select(.path == $p)] | length' 2>/dev/null || echo 0
}

# --- API -------------------------------------------------------------------------
api(){ # <METHOD> <path> [json] -> HTTP code; body in $W/api.body
  local code
  code="$(curl -s --max-time 30 -o "$W/api.body" -w '%{http_code}' -X "$1" "$BASE$2" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"})" || true
  echo "${code:-000}"
}
abody(){ cat "$W/api.body" 2>/dev/null || true; }

# upload <dir> <requirements text> -> artifact id (generic repo, path
# <dir>/requirements.txt: the dependency scanner parses it as a pip manifest
# on every image)
upload(){
  printf '%s' "$2" > "$W/req.txt"
  curl -s --max-time 30 -X PUT -H "Authorization: Bearer $TOK" --data-binary "@$W/req.txt" \
    "$BASE/api/v1/repositories/${REPO}/artifacts/$1/requirements.txt" | jqr '.id // empty'
}

# scan <artifact_id>: POST /security/scan, then wait until no scan row of the
# artifact is pending/running and a dependency row exists. 0 when settled.
scan(){
  local code t=0 open dep
  code="$(api POST /api/v1/security/scan "{\"artifact_id\":\"$1\"}")"
  case "$code" in 2??) ;; *) note "POST /security/scan -> ${code}: $(abody | head -c 300)"; return 1;; esac
  while [ "$t" -lt "$SCAN_WAIT" ]; do
    open="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND status IN ('pending','running')")"
    dep="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='dependency' AND status IN ('completed','failed')")"
    if [ "${open:-1}" = "0" ] && [ "${dep:-0}" -ge "${2:-1}" ]; then return 0; fi
    sleep 2; t=$((t+2))
  done
  note "scan of $1 did not settle within ${SCAN_WAIT}s"
  return 1
}
# Latest dependency scan row of an artifact: id|status|completeness|findings_count
dep_row(){
  psqlq "SELECT id||'|'||status||'|'||COALESCE(scan_completeness,'')||'|'||findings_count
         FROM scan_results WHERE artifact_id='$1' AND scan_type='dependency'
         ORDER BY created_at DESC LIMIT 1"
}
# Findings of a dependency scan row, one per line: component|cve|fixed|title|severity
dep_findings(){
  psqlq "SELECT COALESCE(affected_component,'')||'|'||COALESCE(cve_id,'')||'|'||COALESCE(fixed_version,'')
                ||'|'||title||'|'||severity
         FROM scan_findings WHERE scan_result_id='$1' ORDER BY affected_component, title"
}

# =============================================================================
begin_suite "osv-positional-findings"

begin_test "setup: admin login, mock OSV reachable, advisories registered, generic repo"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock OSV not reachable on ${MOCK} (profiles/upstreams.mock-osv.yml)"; end_suite
fi
# Package names carry the run suffix: the backend's advisory cache (1 h, keyed
# by ecosystem:name:version) must start empty for every name this run uses.
SFX="$(printf '%s' "${RUN_ID##*-}$$" | tr -cd '0-9')"
P_CLEAN="dtf-clean-${SFX}"       # no advisory
P_VULN="dtf-vuln-${SFX}"         # GHSA-dtfv-${SFX}-0001 / CVE-2099-1001, fixed 1.0.1
P_SHX="dtf-shared-x-${SFX}"      # both GHSA-dtfs-${SFX}-0002 / CVE-2099-1002
P_SHY="dtf-shared-y-${SFX}"
P_OUT="dtf-outage-${SFX}"        # GHSA-dtfo-${SFX}-0003 / CVE-2099-1003, asked during an outage
P_CTL="dtf-control-${SFX}"       # no advisory (control)
ID_V="GHSA-dtfv-${SFX}-0001"; ID_S="GHSA-dtfs-${SFX}-0002"; ID_O="GHSA-dtfo-${SFX}-0003"
rec(){ # <id> <cve> <summary> <severity> <fixed> <pkg>...
  local id="$1" cve="$2" sum="$3" sev="$4" fixed="$5"; shift 5
  jq -nc --arg id "$id" --arg cve "$cve" --arg sum "$sum" --arg sev "$sev" --arg fx "$fixed" \
    --args '{id:$id, modified:"2026-01-01T00:00:00Z", summary:$sum, details:("Details for "+$id),
      aliases:[$cve], database_specific:{severity:$sev},
      affected:[$ARGS.positional[] | {package:{ecosystem:"PyPI",name:.},
        ranges:[{type:"ECOSYSTEM",events:[{introduced:"0"},{fixed:$fx}]}]}]}' "$@"
}
ADV="$(jq -nc \
  --arg pv "$P_VULN" --arg px "$P_SHX" --arg py "$P_SHY" --arg po "$P_OUT" \
  --arg iv "$ID_V" --arg is "$ID_S" --arg io "$ID_O" \
  --argjson rv "$(rec "$ID_V" CVE-2099-1001 "DTF vuln package remote code execution" HIGH 1.0.1 "$P_VULN")" \
  --argjson rs "$(rec "$ID_S" CVE-2099-1002 "DTF shared library heap overflow" CRITICAL 1.0.2 "$P_SHX" "$P_SHY")" \
  --argjson ro "$(rec "$ID_O" CVE-2099-1003 "DTF outage package path traversal" MODERATE 1.0.3 "$P_OUT")" \
  '{rules:[{ecosystem:"PyPI",name:$pv,version:"1.0.0",ids:[$iv]},
           {ecosystem:"PyPI",name:$px,version:"1.0.0",ids:[$is]},
           {ecosystem:"PyPI",name:$py,version:"1.0.0",ids:[$is]},
           {ecosystem:"PyPI",name:$po,version:"1.0.0",ids:[$io]}],
    records:{($iv):$rv, ($is):$rs, ($io):$ro}}')"
reg="$(curl -s --max-time 5 -X PUT --data "$ADV" "${MOCK}/__advisories" | jqr '.records // empty')"
mock_mode ok >/dev/null; mock_reset
REPO="osvpos-${SFX}"
code="$(api POST /api/v1/repositories "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')")"
if [ "$reg" = "3" ] && { [ "$code" = "200" ] || [ "$code" = "201" ]; }; then
  pass
else
  infra_fail "setup: advisories registered='${reg}', repo create -> ${code}: $(abody | head -c 300)"; end_suite
fi

# -----------------------------------------------------------------------------
begin_test "CONTROL: a manifest with no advisories asks the feed once per dependency and grades complete, 0 findings"
reset_case
A_CTL="$(upload ctl "${P_CTL}==1.0.0
")"
if [ -z "$A_CTL" ]; then fail_g "upload of ctl/requirements.txt failed"
elif scan "$A_CTL"; then
  IFS='|' read -r _ st comp cnt <<<"$(dep_row "$A_CTL")"
  note "dependency row: status=${st} completeness=${comp} findings=${cnt}"
  [ "$st" = "completed" ] || fail_g "dependency scan status '${st}', expected completed"
  [ "$comp" = "complete" ] || fail_g "scan_completeness '${comp}', expected complete"
  [ "$cnt" = "0" ] || fail_g "findings_count ${cnt}, expected 0"
  q="$(mock_queried "$P_CTL")"
  [ "$q" -ge 1 ] || fail_g "the mock OSV never received a querybatch naming ${P_CTL} (is api.osv.dev pinned to the mock?)"
else fail_g "scan did not settle"; fi
finish_case "control scan against the mock OSV did not behave"

# -----------------------------------------------------------------------------
# A1: clean dependency FIRST, vulnerable dependency second (one batch).
begin_test "FIX #4081: the finding names the vulnerable dependency, not the first one in the manifest"
reset_case
A1="$(upload app1 "${P_CLEAN}==1.0.0
${P_VULN}==1.0.0
")"
A1_SCAN=""
if [ -z "$A1" ]; then fail_g "upload of app1/requirements.txt failed"
elif scan "$A1"; then
  IFS='|' read -r A1_SCAN st comp cnt <<<"$(dep_row "$A1")"
  note "dependency row: status=${st} completeness=${comp} findings=${cnt}"
  dep_findings "$A1_SCAN" > "$W/a1.findings"
  note "findings: $(tr '\n' ';' < "$W/a1.findings")"
  comps="$(cut -d'|' -f1 "$W/a1.findings" | sort -u | tr '\n' ' ')"
  [ "$(wc -l < "$W/a1.findings")" -ge 1 ] || fail_g "no finding at all for ${P_VULN}"
  [ "$comps" = "${P_VULN} " ] || fail_g "affected_component set is '${comps}', expected only '${P_VULN}' (the first dependency is ${P_CLEAN})"
else fail_g "scan did not settle"; fi
finish_case "finding attributed to the wrong dependency"

begin_test "FIX #4150: the OSV finding carries its CVE alias, fixed version and summary title (record fetched from /v1/vulns)"
reset_case
if [ -n "$A1_SCAN" ]; then
  line="$(grep "^${P_VULN}|" "$W/a1.findings" | head -1 || true)"
  [ -n "$line" ] || line="$(head -1 "$W/a1.findings")"
  IFS='|' read -r comp cve fixed title sev <<<"$line"
  note "finding: component=${comp} cve=${cve} fixed=${fixed} title='${title}' severity=${sev}"
  [ "$cve" = "CVE-2099-1001" ] || fail_g "cve_id '${cve}', expected CVE-2099-1001 (the record's alias)"
  [ "$fixed" = "1.0.1" ] || fail_g "fixed_version '${fixed}', expected 1.0.1"
  [ "$title" = "DTF vuln package remote code execution" ] || fail_g "title '${title}', expected the record's summary (not 'Vulnerability ${ID_V}')"
  g="$(mock_record_gets "$ID_V")"
  note "GET /v1/vulns/${ID_V} x${g}"
  [ "$g" -ge 1 ] || fail_g "the scanner never fetched the full record /v1/vulns/${ID_V}"
else fail_g "no A1 dependency scan to inspect"; fi
finish_case "OSV finding not hydrated"

# A2: only the clean dependency, scanned after A1 (its advisory answer is now
# in the backend's 1 h cache, written from A1's batch).
begin_test "FIX #4079: a dependency batched with a vulnerable one does not inherit its finding through the advisory cache"
reset_case
A2="$(upload app2 "${P_CLEAN}==1.0.0
")"
if [ -z "$A2" ]; then fail_g "upload of app2/requirements.txt failed"
elif scan "$A2"; then
  IFS='|' read -r sid st comp cnt <<<"$(dep_row "$A2")"
  note "dependency row: status=${st} completeness=${comp} findings=${cnt}"
  note "findings: $(dep_findings "$sid" | tr '\n' ';')"
  [ "$st" = "completed" ] || fail_g "dependency scan status '${st}', expected completed"
  [ "$cnt" = "0" ] || fail_g "${P_CLEAN} alone has ${cnt} finding(s); the mock has no advisory for it (contaminated from ${P_VULN}'s batch)"
else fail_g "scan did not settle"; fi
finish_case "cross-dependency contamination"

# A3: two packages hit by the same advisory/CVE.
begin_test "FIX #4150: the same CVE in two packages is reported once for each package"
reset_case
A3="$(upload app3 "${P_SHX}==1.0.0
${P_SHY}==1.0.0
")"
if [ -z "$A3" ]; then fail_g "upload of app3/requirements.txt failed"
elif scan "$A3"; then
  IFS='|' read -r sid st comp cnt <<<"$(dep_row "$A3")"
  dep_findings "$sid" > "$W/a3.findings"
  note "dependency row: status=${st} findings=${cnt}; findings: $(tr '\n' ';' < "$W/a3.findings")"
  comps="$(cut -d'|' -f1 "$W/a3.findings" | sort | tr '\n' ' ')"
  [ "$comps" = "${P_SHX} ${P_SHY} " ] || fail_g "components '${comps}', expected exactly one finding for each of ${P_SHX} and ${P_SHY}"
  [ "$(cut -d'|' -f2 "$W/a3.findings" | sort -u | tr '\n' ' ')" = "CVE-2099-1002 " ] \
    || fail_g "cve_ids '$(cut -d'|' -f2 "$W/a3.findings" | tr '\n' ' ')', expected CVE-2099-1002 on both"
else fail_g "scan did not settle"; fi
finish_case "shared CVE collapsed across packages"

# A4: the feed is down while a fresh package is scanned.
begin_test "FIX #4080: a scan during an OSV outage is graded partial, not a clean complete"
reset_case
mock_mode down >/dev/null
A4="$(upload app4 "${P_OUT}==1.0.0
")"
if [ -z "$A4" ]; then fail_g "upload of app4/requirements.txt failed"
elif scan "$A4"; then
  IFS='|' read -r sid st comp cnt <<<"$(dep_row "$A4")"
  note "dependency row during outage: status=${st} completeness=${comp} findings=${cnt}"
  q="$(mock_queried "$P_OUT")"
  note "querybatch naming ${P_OUT} during the outage: ${q} (answered 503)"
  [ "$q" -ge 1 ] || fail_g "the outage was never exercised: no querybatch reached the mock"
  [ "$comp" = "partial" ] || fail_g "scan_completeness '${comp}' during a 503 feed outage, expected partial"
else fail_g "scan did not settle"; fi
mock_mode ok >/dev/null
finish_case "feed outage graded as a clean scan"

begin_test "CONTROL: after the outage the same package is asked again and its advisory reported"
reset_case
# A second artifact naming the same package: the scan dedup reuses a scan of
# identical bytes, and the question here is the advisory cache, keyed by
# package, not by artifact.
before="$(mock_queried "$P_OUT")"
A5="$(upload app5 "${P_OUT}==1.0.0
# after the outage
")"
if [ -z "$A5" ]; then fail_g "upload of app5/requirements.txt failed"
elif scan "$A5"; then
  IFS='|' read -r sid st comp cnt <<<"$(dep_row "$A5")"
  after="$(mock_queried "$P_OUT")"
  note "after recovery: status=${st} completeness=${comp} findings=${cnt}; querybatch naming ${P_OUT}: ${before} -> ${after}"
  [ "$after" -gt "$before" ] || fail_g "the feed was never asked about ${P_OUT} again (the outage answer was cached for the advisory TTL)"
  [ "$comp" = "complete" ] || fail_g "scan_completeness '${comp}' once the feed answers, expected complete"
  [ "${cnt:-0}" -ge 1 ] || fail_g "findings_count ${cnt}, expected the ${ID_O} finding"
else fail_g "scan did not settle"; fi
finish_case "outage cached as an all-clear"

# -----------------------------------------------------------------------------
begin_test "CONTROL: the backend reached the mock over TLS as api.osv.dev (no feed errors on the control batch)"
reset_case
total="$(curl -s --max-time 5 "${MOCK}/__requests" | jq '[.[] | select(.path == "/v1/querybatch")] | length' 2>/dev/null || echo 0)"
note "querybatch requests received: ${total}"
[ "${total:-0}" -ge 4 ] || fail_g "expected at least 4 querybatch requests (control, app1, app3, outage), got ${total}"
finish_case "mock feed plumbing"

end_suite
