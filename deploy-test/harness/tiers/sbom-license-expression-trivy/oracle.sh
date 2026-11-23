#!/usr/bin/env bash
# =============================================================================
# tiers/sbom-license-expression-trivy/oracle.sh
#   #5629 SBOM license expressions survive when the Trivy filesystem scanner
#         also catalogued the package
# See the manifest for the bug and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
BACKEND="ak-dtf${DTF_SLOT}-backend"
ADAPTER="ak-dtf${DTF_SLOT}-trivy"
SCAN_WAIT=300

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

api(){ # <METHOD> <path> [json] -> HTTP code; body in $W/api.body
  local code
  code="$(curl -s --max-time 60 -o "$W/api.body" -w '%{http_code}' -X "$1" "$BASE$2" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"})" || true
  echo "${code:-000}"
}
abody(){ cat "$W/api.body" 2>/dev/null || true; }
# lic <component> -> that component's licenses[] in the SBOM as compact JSON
lic(){ jq -c --arg n "$1" '[.components[]? | select(.name == $n) | .licenses][0]' "$W/sbom.cdx.json" 2>/dev/null || echo null; }
# stored <scan_type> <component> [artifact] -> the license that scan stored for it
stored(){
  psqlq "SELECT sp.license FROM scan_packages sp JOIN scan_results sr ON sr.id = sp.scan_result_id
         WHERE sr.artifact_id='${3:-$A_GEN}' AND sr.scan_type='$1' AND sp.name='$2' LIMIT 1"
}
# clic <component> -> that component's licenses[] in the composer.lock SBOM
clic(){ jq -c --arg n "$1" '[.components[]? | select(.name == $n or (.group // "") + "/" + .name == $n) | .licenses][0]' "$W/sbom-composer.cdx.json" 2>/dev/null || echo null; }
# scan_both <artifact> -> waits for a completed grype and filesystem scan; echoes "<grype> <filesystem> <secs>"
scan_both(){
  local t=0 g=0 f=0
  api POST /api/v1/security/scan "{\"artifact_id\":\"$1\"}" >/dev/null
  while [ "$t" -lt "$SCAN_WAIT" ]; do
    g="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='grype' AND status='completed'")"
    f="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='filesystem' AND status='completed'")"
    [ "${g:-0}" -ge 1 ] 2>/dev/null && [ "${f:-0}" -ge 1 ] 2>/dev/null && break
    sleep 3; t=$((t+3))
  done
  echo "${g:-0} ${f:-0} ${t}"
}

# =============================================================================
begin_suite "sbom-license-expression-trivy"

begin_test "setup: Trivy filesystem scanner registered on the adapter, Trivy DB warm, a package-lock in a generic repo"
err=""
docker logs "$BACKEND" >"$W/backend-start.log" 2>&1 || true
grep -q "Trivy filesystem scanner enabled (scanner-adapter" "$W/backend-start.log" \
  || err="${err} the backend did not register the Trivy filesystem scanner on the adapter;"
warmed=0
for attempt in 1 2 3 4 5; do
  if docker exec "$ADAPTER" sh -c 'trivy image --cache-dir "${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}" --download-db-only' >/dev/null 2>&1; then
    warmed=1; break
  fi
  echo "   DB warm attempt ${attempt}/5 failed; retrying in 5s"; sleep 5
done
[ "$warmed" = 1 ] || err="${err} could not download the Trivy DB in ${ADAPTER};"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
[ -n "$TOK" ] || err="${err} admin login failed at $BASE;"
SFX="$(printf '%s' "${RUN_ID##*-}$$" | tr -cd '0-9')"
GEN="sltgen-${SFX}"
# The license shapes, one lockfile entry each (as sbom-license-expression).
jq -nc '{name:"app",version:"1.0.0",lockfileVersion:3,requires:true,packages:{
  "":{name:"app",version:"1.0.0"},
  "node_modules/dtf-compound":{version:"1.0.0",license:"MIT AND PSF-2.0"},
  "node_modules/dtf-with":{version:"1.0.0",license:"Apache-2.0 WITH LLVM-exception"},
  "node_modules/dtf-single":{version:"1.0.0",license:"MIT"},
  "node_modules/dtf-free":{version:"1.0.0",license:"Public Domain"}}}' > "$W/lock.json"
A_GEN=""
if [ -z "$err" ]; then
  c1="$(api POST /api/v1/repositories "$(jq -nc --arg k "$GEN" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:true}')")"
  A_GEN="$(curl -s --max-time 30 -X PUT -H "Authorization: Bearer $TOK" --data-binary "@$W/lock.json" \
    "$BASE/api/v1/repositories/${GEN}/artifacts/app/package-lock.json" | jqr '.id // empty')"
  [[ "$c1" =~ ^20[01]$ ]] && [ -n "$A_GEN" ] || err="${err} generic repo ${c1}, artifact '${A_GEN}': $(abody | head -c 200);"
fi
if [ -z "$err" ]; then pass; else infra_fail "${err}"; end_suite; fi

# -----------------------------------------------------------------------------
begin_test "CONTROL: Grype and the Trivy filesystem scan both catalog the lockfile; Trivy stores the compound license wrapped as a LicenseRef"
reset_case
api POST /api/v1/security/scan "{\"artifact_id\":\"${A_GEN}\"}" >/dev/null
t=0; g=0; f=0
while [ "$t" -lt "$SCAN_WAIT" ]; do
  g="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_GEN}' AND scan_type='grype' AND status='completed'")"
  f="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_GEN}' AND scan_type='filesystem' AND status='completed'")"
  [ "${g:-0}" -ge 1 ] 2>/dev/null && [ "${f:-0}" -ge 1 ] 2>/dev/null && break
  sleep 3; t=$((t+3))
done
sg="$(stored grype dtf-compound)"; sf="$(stored filesystem dtf-compound)"
note "completed scans: grype ${g}, filesystem ${f} (after ${t}s); dtf-compound stored as grype '${sg}', filesystem '${sf}'"
note "scan rows: $(psqlq "SELECT string_agg(scan_type||'='||status, ',') FROM scan_results WHERE artifact_id='${A_GEN}'")"
[ "${g:-0}" -ge 1 ] 2>/dev/null || fail_g "no completed grype scan"
[ "${f:-0}" -ge 1 ] 2>/dev/null || fail_g "no completed Trivy filesystem scan"
[ "$sg" = "MIT AND PSF-2.0" ] || fail_g "grype stored dtf-compound as '${sg}', expected 'MIT AND PSF-2.0'"
# Up to #6379 Trivy wraps the compound as one LicenseRef, which is what the
# #5629 FIX case discriminates on; since #6379 it keeps the conjunction as
# expression with the unlisted PSF-2.0 wrapped alone, and the #5629 swap
# keeps Grype's text for the SBOM either way.
[ "$sf" = "LicenseRef-MIT-AND-PSF-2.0" ] || [ "$sf" = "MIT AND LicenseRef-PSF-2.0" ] \
  || fail_g "the Trivy filesystem scan stored dtf-compound as '${sf}', expected 'LicenseRef-MIT-AND-PSF-2.0' (before #6379) or 'MIT AND LicenseRef-PSF-2.0' (since)"
finish_case "both scanners' inventories"

begin_test "setup: generate the package-lock's CycloneDX SBOM"
reset_case
code="$(api POST /api/v1/sbom "{\"artifact_id\":\"${A_GEN}\",\"format\":\"cyclonedx\",\"force_regenerate\":true}")"
SBOM_ID="$(abody | jqr '.id // empty')"
code2="$(api GET "/api/v1/sbom/${SBOM_ID}")"
abody | jq '.content // .' > "$W/sbom.cdx.json" 2>/dev/null || true
note "generate -> ${code}, GET -> ${code2}, dtf-* components: $(jq '[.components[]? | select(.name | startswith("dtf-"))] | length' "$W/sbom.cdx.json" 2>/dev/null)"
[ "$code" = "200" ] && [ "$code2" = "200" ] || fail_g "SBOM generate/GET failed: $(abody | head -c 300)"
[ "$(jq '[.components[]? | select(.name | startswith("dtf-"))] | length' "$W/sbom.cdx.json" 2>/dev/null)" = "4" ] \
  || fail_g "the SBOM does not carry the four dtf-* lockfile components once each"
finish_case "SBOM not generated"

begin_test "CONTROL: a single SPDX id stays license.id and a WITH expression stays an expression"
reset_case
s="$(lic dtf-single)"; w="$(lic dtf-with)"
note "dtf-single: ${s}; dtf-with: ${w}"
[ "$s" = '[{"license":{"id":"MIT"}}]' ] || fail_g "dtf-single licenses ${s}, expected [{\"license\":{\"id\":\"MIT\"}}]"
[ "$w" = '[{"expression":"Apache-2.0 WITH LLVM-exception"}]' ] || fail_g "dtf-with licenses ${w}"
finish_case "license rendering"

begin_test "FIX #5629: the compound license is an expression and free text keeps its name with the Trivy filesystem scanner enabled"
reset_case
c="$(lic dtf-compound)"; f="$(lic dtf-free)"
note "dtf-compound: ${c}; dtf-free: ${f}"
[ "$c" = '[{"expression":"MIT AND PSF-2.0"}]' ] || fail_g "dtf-compound licenses ${c}, expected [{\"expression\":\"MIT AND PSF-2.0\"}]"
[ "$f" = '[{"license":{"name":"Public Domain"}}]' ] || fail_g "dtf-free licenses ${f}, expected [{\"license\":{\"name\":\"Public Domain\"}}]"
finish_case "the Trivy LicenseRef row replaced the license text"

# =============================================================================
# #6379: a Trivy license list that joins a compound expression with another
# license. composer.lock lists licenses as an array, which Trivy reports
# element by element: ["MIT AND PSF-2.0", "ISC"].
# =============================================================================
begin_test "setup: a composer.lock whose packages list a compound license beside another one"
reset_case
jq -nc '{packages:[
  {name:"dtf/joined",version:"1.0.0",type:"library",license:["MIT AND PSF-2.0","ISC"]},
  {name:"dtf/choice",version:"1.0.0",type:"library",license:["MIT OR Apache-2.0","ISC"]}],
  "packages-dev":[]}' > "$W/composer.lock"
A_COMP="$(curl -s --max-time 30 -X PUT -H "Authorization: Bearer $TOK" --data-binary "@$W/composer.lock" \
  "$BASE/api/v1/repositories/${GEN}/artifacts/php/composer.lock" | jqr '.id // empty')"
[ -n "$A_COMP" ] || fail_g "composer.lock upload failed"
read -r cg cf ct <<<"$(scan_both "${A_COMP:-x}")"
TJ="$(stored filesystem dtf/joined "$A_COMP")"; GJ="$(stored grype dtf/joined "$A_COMP")"
TC="$(stored filesystem dtf/choice "$A_COMP")"
note "completed scans: grype ${cg}, filesystem ${cf} (after ${ct}s); dtf/joined stored as filesystem '${TJ}', grype '${GJ}'; dtf/choice filesystem '${TC}'"
[ "${cf:-0}" -ge 1 ] 2>/dev/null || fail_g "no completed Trivy filesystem scan of composer.lock"
[ -n "$TJ" ] || fail_g "the Trivy filesystem scan did not catalog dtf/joined with a license"
code="$(api POST /api/v1/sbom "{\"artifact_id\":\"${A_COMP}\",\"format\":\"cyclonedx\",\"force_regenerate\":true}")"
SBOM_C="$(abody | jqr '.id // empty')"
code2="$(api GET "/api/v1/sbom/${SBOM_C}")"
abody | jq '.content // .' > "$W/sbom-composer.cdx.json" 2>/dev/null || true
[ "$code" = "200" ] && [ "$code2" = "200" ] || fail_g "composer.lock SBOM generate/GET failed: $(abody | head -c 300)"
finish_case "composer.lock not catalogued by the Trivy filesystem scan"

begin_test "CONTROL: an element offering a choice (OR) is still wrapped as a LicenseRef (#1152)"
reset_case
note "dtf/choice: filesystem '${TC}'"
[ "$TC" = "LicenseRef-MIT-OR-Apache-2.0 AND ISC" ] || fail_g "dtf/choice stored as '${TC}', expected 'LicenseRef-MIT-OR-Apache-2.0 AND ISC'"
finish_case "OR element handling"

begin_test "FIX #6379: the joined compound license is stored and exported as an expression of real licenses"
reset_case
j="$(clic dtf/joined)"
note "dtf/joined: stored '${TJ}', SBOM ${j}"
[ "$TJ" = "MIT AND LicenseRef-PSF-2.0 AND ISC" ] || fail_g "the Trivy filesystem scan stored dtf/joined as '${TJ}', expected 'MIT AND LicenseRef-PSF-2.0 AND ISC' (the conjunction kept; PSF-2.0, an id outside the recognised list, wrapped alone)"
# Which scanner's row the SBOM keeps is the merge's choice (Grype stores
# this composer.lock entry as `ISC` alone, a separate gap); the gate here is
# that the compound is not one opaque LicenseRef in the SBOM.
case "$j" in
  *LicenseRef-MIT-AND*) fail_g "the SBOM licenses of dtf/joined carry the compound as one opaque LicenseRef: ${j}" ;;
  null|'') fail_g "dtf/joined has no licenses in the SBOM" ;;
esac
finish_case "the Trivy license list lost the compound expression"

end_suite
