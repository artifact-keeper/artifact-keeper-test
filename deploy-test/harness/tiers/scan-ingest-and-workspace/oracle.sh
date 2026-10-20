#!/usr/bin/env bash
# =============================================================================
# tiers/scan-ingest-and-workspace/oracle.sh
#   #4669 the dependency scanner asks OSV about the scanned package itself
#   #4667 POST /security/findings/external refuses a NUL byte with 400 and
#         leaves no orphaned `completed` scan row
#   #4668 concurrent scans of one artifact get separate workspaces
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
ROUNDS=3          # concurrent-scan rounds (#4668)
PER_ROUND=3       # scans fired at once per round

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

# mock_queried <name>: querybatch requests naming this package
mock_queried(){
  curl -s --max-time 5 "${MOCK}/__requests" \
    | jq --arg n "$1" '[.[] | select(.path == "/v1/querybatch")
        | select([.body.queries[]?.package.name] | index($n))] | length' 2>/dev/null || echo 0
}

api(){ # <METHOD> <path> [json] -> HTTP code; body in $W/api.body
  local code
  code="$(curl -s --max-time 30 -o "$W/api.body" -w '%{http_code}' -X "$1" "$BASE$2" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"})" || true
  echo "${code:-000}"
}
abody(){ cat "$W/api.body" 2>/dev/null || true; }

# trigger <artifact_id> [bypass_dedup] -> HTTP code
trigger(){
  local body="{\"artifact_id\":\"$1\"}"
  [ "${2:-}" = "bypass" ] && body="{\"artifact_id\":\"$1\",\"bypass_dedup\":true}"
  curl -s --max-time 30 -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/security/scan" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$body" || echo 000
}
# settle <artifact_id> <min grype rows>: wait until no row is pending/running
# and at least that many grype rows exist.
settle(){
  local t=0 open n
  while [ "$t" -lt "$SCAN_WAIT" ]; do
    open="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND status IN ('pending','running')")"
    n="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='grype'")"
    if [ "${open:-1}" = "0" ] && [ "${n:-0}" -ge "$2" ]; then return 0; fi
    sleep 2; t=$((t+2))
  done
  note "scans of $1 did not settle within ${SCAN_WAIT}s (open=${open} grype rows=${n})"
  return 1
}

# publish_npm <name> <version> -> HTTP code (npm PUT with the tarball attached)
publish_npm(){
  local d="$W/npm-$1" tgz="$W/$1-$2.tgz" b64 sz
  mkdir -p "$d/package"
  jq -nc --arg n "$1" --arg v "$2" '{name:$n,version:$v,main:"index.js",license:"MIT"}' > "$d/package/package.json"
  echo 'module.exports = 1;' > "$d/package/index.js"
  tar czf "$tgz" -C "$d" package
  b64="$(base64 -w0 < "$tgz")"; sz="$(wc -c < "$tgz" | tr -d ' ')"
  jq -nc --arg n "$1" --arg v "$2" --arg b "$b64" --argjson s "$sz" --arg reg "$BASE/npm/${NPM_REPO}/" \
    '{name:$n, "dist-tags":{latest:$v},
      versions:{($v):{name:$n,version:$v,main:"index.js",license:"MIT",
        dist:{tarball:($reg+$n+"/-/"+$n+"-"+$v+".tgz")}}},
      _attachments:{($n+"-"+$v+".tgz"):{content_type:"application/octet-stream",data:$b,length:$s}}}' > "$W/pub.json"
  curl -s --max-time 30 -o "$W/pub.body" -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' --data-binary "@$W/pub.json" "$BASE/npm/${NPM_REPO}/$1" || echo 000
}

# =============================================================================
begin_suite "scan-ingest-and-workspace"

begin_test "setup: admin login, mock OSV advisories, npm and generic repos, a leaf npm package"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock OSV not reachable on ${MOCK} (profiles/upstreams.mock-osv.yml)"; end_suite
fi
SFX="$(printf '%s' "${RUN_ID##*-}$$" | tr -cd '0-9')"
LEAF="dtf-leaf-${SFX}"              # npm, no dependencies; GHSA-leaf-${SFX}-0001 / CVE-2099-2001
DEP="dtf-dep-${SFX}"                # PyPI, declared dependency; GHSA-ddep-${SFX}-0002 / CVE-2099-2002
ID_L="GHSA-leaf-${SFX}-0001"; ID_D="GHSA-ddep-${SFX}-0002"
ADV="$(jq -nc --arg l "$LEAF" --arg d "$DEP" --arg il "$ID_L" --arg id "$ID_D" '
  {rules:[{ecosystem:"npm",name:$l,version:"1.0.0",ids:[$il]},
          {ecosystem:"PyPI",name:$d,version:"1.0.0",ids:[$id]}],
   records:{
     ($il):{id:$il,modified:"2026-01-01T00:00:00Z",summary:"DTF leaf prototype pollution",
            aliases:["CVE-2099-2001"],database_specific:{severity:"HIGH"},
            affected:[{package:{ecosystem:"npm",name:$l},
              ranges:[{type:"SEMVER",events:[{introduced:"0"},{fixed:"1.0.1"}]}]}]},
     ($id):{id:$id,modified:"2026-01-01T00:00:00Z",summary:"DTF declared dependency overflow",
            aliases:["CVE-2099-2002"],database_specific:{severity:"HIGH"},
            affected:[{package:{ecosystem:"PyPI",name:$d},
              ranges:[{type:"ECOSYSTEM",events:[{introduced:"0"},{fixed:"1.0.1"}]}]}]}}}')"
reg="$(curl -s --max-time 5 -X PUT --data "$ADV" "${MOCK}/__advisories" | jqr '.records // empty')"
curl -s --max-time 5 -X PUT --data ok "${MOCK}/__mode" >/dev/null || true
curl -s --max-time 5 -X POST "${MOCK}/__reset" >/dev/null || true
NPM_REPO="sinpm-${SFX}"; GEN_REPO="sigen-${SFX}"
c1="$(api POST /api/v1/repositories "$(jq -nc --arg k "$NPM_REPO" '{key:$k,name:$k,format:"npm",repo_type:"local",is_public:false}')")"
c2="$(api POST /api/v1/repositories "$(jq -nc --arg k "$GEN_REPO" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')")"
pc="$(publish_npm "$LEAF" 1.0.0)"
A_LEAF="$(psqlq "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id
                WHERE r.key='${NPM_REPO}' AND a.path LIKE '%.tgz' ORDER BY a.created_at DESC LIMIT 1")"
printf '%s==1.0.0\n' "$DEP" > "$W/req.txt"
A_GEN="$(curl -s --max-time 30 -X PUT -H "Authorization: Bearer $TOK" --data-binary "@$W/req.txt" \
  "$BASE/api/v1/repositories/${GEN_REPO}/artifacts/app/requirements.txt" | jqr '.id // empty')"
if [ "$reg" = "2" ] && [[ "$c1$c2" =~ ^(20[01]){2}$ ]] && [[ "$pc" =~ ^20[01]$ ]] && [ -n "$A_LEAF" ] && [ -n "$A_GEN" ]; then
  pass
else
  infra_fail "setup: advisories='${reg}' npm repo ${c1} generic repo ${c2} publish ${pc} ($(head -c 200 "$W/pub.body" 2>/dev/null)) leaf='${A_LEAF}' generic='${A_GEN}'"
  end_suite
fi

# -----------------------------------------------------------------------------
begin_test "CONTROL: a declared dependency is queried and reported (the mock feed answers on this image)"
reset_case
code="$(trigger "$A_GEN")"
if [[ "$code" =~ ^2 ]] && settle "$A_GEN" 1; then
  row="$(psqlq "SELECT id||'|'||status||'|'||findings_count FROM scan_results
               WHERE artifact_id='${A_GEN}' AND scan_type='dependency' ORDER BY created_at DESC LIMIT 1")"
  IFS='|' read -r sid st cnt <<<"$row"
  comp="$(psqlq "SELECT string_agg(COALESCE(affected_component,'')||'/'||COALESCE(cve_id,''),',') FROM scan_findings WHERE scan_result_id='${sid}'")"
  note "dependency row: status=${st} findings=${cnt} [${comp}]"
  [ "$st" = "completed" ] || fail_g "dependency scan status '${st}'"
  [ "$comp" = "${DEP}/CVE-2099-2002" ] || fail_g "expected one finding ${DEP}/CVE-2099-2002, got '${comp}'"
else fail_g "scan trigger ${code} or did not settle"; fi
finish_case "the mock OSV feed does not answer the dependency scanner"

begin_test "FIX #4669: a leaf npm package with no dependencies is asked about itself and reported"
reset_case
before="$(mock_queried "$LEAF")"
code="$(trigger "$A_LEAF")"
if [[ "$code" =~ ^2 ]] && settle "$A_LEAF" 1; then
  row="$(psqlq "SELECT id||'|'||status||'|'||COALESCE(scan_completeness,'')||'|'||findings_count FROM scan_results
               WHERE artifact_id='${A_LEAF}' AND scan_type='dependency' ORDER BY created_at DESC LIMIT 1")"
  IFS='|' read -r sid st comp cnt <<<"$row"
  after="$(mock_queried "$LEAF")"
  fnd="$(psqlq "SELECT string_agg(COALESCE(affected_component,'')||'/'||COALESCE(cve_id,''),',') FROM scan_findings WHERE scan_result_id='${sid}'")"
  inv="$(psqlq "SELECT count(*) FROM scan_packages WHERE scan_result_id='${sid}' AND name='${LEAF}'")"
  note "dependency row: status=${st} completeness=${comp} findings=${cnt} [${fnd}]; querybatch naming ${LEAF}: $((after - before)); own name in its dependency inventory: ${inv}"
  [ "$((after - before))" = "1" ] || fail_g "the feed was asked about ${LEAF} $((after - before)) time(s), expected exactly once"
  [ "$fnd" = "${LEAF}/CVE-2099-2001" ] || fail_g "expected one finding ${LEAF}/CVE-2099-2001 (the package's own advisory), got '${fnd}'"
  [ "${inv:-0}" = "0" ] || fail_g "the package was added to its own dependency inventory (${inv} scan_packages rows)"
else fail_g "scan trigger ${code} or did not settle"; fi
finish_case "leaf package never asked about itself"

# -----------------------------------------------------------------------------
begin_test "CONTROL: a clean external findings submission is ingested as one completed scan with its finding"
reset_case
n0="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_GEN}'")"
code="$(api POST /api/v1/security/findings/external "$(jq -nc --arg a "$A_GEN" '{artifact_id:$a,scanner:"dtf-external",scanner_version:"1.0",
  findings:[{severity:"high",title:"DTF external finding",cve_id:"CVE-2099-2101",affected_component:"dtf-ext-comp"}]}')")"
sid="$(abody | jqr '.scan_id // empty')"
n1="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_GEN}'")"
f="$(psqlq "SELECT count(*) FROM scan_findings WHERE scan_result_id='${sid:-00000000-0000-0000-0000-000000000000}' AND cve_id='CVE-2099-2101'")"
note "POST -> ${code} findings_ingested=$(abody | jqr '.findings_ingested // empty'); scan rows ${n0} -> ${n1}; finding rows under ${sid}: ${f}"
[ "$code" = "200" ] || fail_g "clean submission -> ${code}: $(abody | head -c 300)"
[ "$((n1 - n0))" = "1" ] || fail_g "expected exactly one new scan row, got $((n1 - n0))"
[ "$f" = "1" ] || fail_g "the ingested finding is not stored under the returned scan_id"
finish_case "external findings ingestion"

begin_test "FIX #4667: a NUL byte in a submitted finding is 400 VALIDATION_ERROR and leaves no orphaned scan row"
reset_case
n0="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_GEN}'")"
# jq renders "\u0000" in a string as the JSON escape, which is what a client sends.
code="$(api POST /api/v1/security/findings/external "$(jq -nc --arg a "$A_GEN" '{artifact_id:$a,scanner:"dtf-external-nul",
  findings:[{severity:"high",title:("DTF NUL" + "\u0000" + "finding"),cve_id:"CVE-2099-2102"}]}')")"
n1="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_GEN}'")"
orph="$(psqlq "SELECT count(*) FROM scan_results sr WHERE sr.artifact_id='${A_GEN}' AND sr.status='completed'
              AND sr.scanner_version IS NULL AND sr.scan_type NOT IN ('dependency','grype')
              AND NOT EXISTS (SELECT 1 FROM scan_findings f WHERE f.scan_result_id=sr.id)")"
note "POST -> ${code} $(abody | head -c 200); scan rows ${n0} -> ${n1}; completed rows with no findings: ${orph}"
[ "$code" = "400" ] || fail_g "NUL submission -> ${code}, expected 400"
[ "$(abody | jqr '.code // empty')" = "VALIDATION_ERROR" ] || fail_g "error code '$(abody | jqr '.code // empty')', expected VALIDATION_ERROR"
[ "$n1" = "$n0" ] || fail_g "the refused submission left $((n1 - n0)) scan row(s) behind"
finish_case "NUL submission not refused cleanly"

# -----------------------------------------------------------------------------
# The leaf tarball's grype scan above ran alone: it catalogs the package.
begin_test "CONTROL: a lone scan of the npm tarball catalogs its package (grype scan_packages >= 1)"
reset_case
lone="$(psqlq "SELECT (SELECT count(*) FROM scan_packages p WHERE p.scan_result_id=sr.id)
              FROM scan_results sr WHERE sr.artifact_id='${A_LEAF}' AND sr.scan_type='grype'
              ORDER BY sr.created_at LIMIT 1")"
note "lone grype scan: ${lone} package row(s)"
[ "${lone:-0}" -ge 1 ] || fail_g "the lone grype scan cataloged nothing"
finish_case "baseline grype inventory"

begin_test "FIX #4668: ${ROUNDS} rounds of ${PER_ROUND} concurrent scans of one artifact all complete with the full inventory"
reset_case
base_n="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_LEAF}' AND scan_type='grype'")"
t0="$(psqlq "SELECT now()")"
codes=""
for _r in $(seq 1 "$ROUNDS"); do
  for _i in $(seq 1 "$PER_ROUND"); do trigger "$A_LEAF" bypass > "$W/trig.${_r}.${_i}" & done
  wait
  for _f in "$W"/trig."${_r}".*; do codes="${codes}$(cat "$_f") "; done
  settle "$A_LEAF" "$(( base_n + _r * PER_ROUND ))" || true
done
psqlq "SELECT sr.status||'|'||(SELECT count(*) FROM scan_packages p WHERE p.scan_result_id=sr.id)
       ||'|'||COALESCE(left(sr.error_message,160),'')
       FROM scan_results sr WHERE sr.artifact_id='${A_LEAF}' AND sr.scan_type='grype'
       AND sr.created_at >= '${t0}' ORDER BY sr.started_at" > "$W/conc.rows"
total="$(grep -c . "$W/conc.rows" || true)"
notdone="$(grep -vc '^completed|' "$W/conc.rows" || true)"
empty="$(grep -c '^completed|0|' "$W/conc.rows" || true)"
note "trigger codes: ${codes}"
note "grype rows: ${total} (expected $((ROUNDS * PER_ROUND))); not completed: ${notdone}; completed with 0 packages: ${empty}"
note "rows (status|packages|error): $(tr '\n' ';' < "$W/conc.rows")"
[ "${total:-0}" -ge "$((ROUNDS * PER_ROUND))" ] || fail_g "only ${total} grype scans ran"
[ "${notdone:-0}" = "0" ] || fail_g "${notdone} concurrent scan(s) did not complete"
[ "${empty:-0}" = "0" ] || fail_g "${empty} concurrent scan(s) completed with an empty inventory (a sibling scan deleted the shared workspace)"
finish_case "concurrent scans share one workspace"

end_suite
