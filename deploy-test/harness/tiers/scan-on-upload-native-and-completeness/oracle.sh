#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-upload-native-and-completeness/oracle.sh - scan_on_upload on
# format-native publishes, not_cataloged completeness, one-hop scan reuse
# =============================================================================
# artifact-keeper 1.11.0:
#   #4166  scan_on_upload fires for every format-native publish handler, not
#          only the generic upload route (1.11.2 #4124 / #4125 pinned the mvn
#          deploy and docker push halves with unit tests).
#   #4159  a native conda PUT /conda/{repo}/{subdir}/{file} is scanned too.
#   #4036 / #4094 / #4154  a scan that cataloged nothing for an artifact that
#          should have a catalog is recorded `not_cataloged` with a reason,
#          sets the repository's has_uncataloged_scan, floors the grade to F
#          for package artifacts only (typed repos, and .whl/.jar/... in a
#          generic one; a plain generic .zip is flagged, grade unchanged), and
#          is never reused for identical bytes.
#   #4425  hash-based scan reuse copies only from an ORIGINAL scan, so a
#          reused copy cannot restart the reuse window.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port, used here only to fetch the Maven jar and NuGet package
# fixtures), DB_CONTAINER, COMMON_SH. The other packages are built by
# fixtures/make_fixtures.py. Scans run the backend image's bundled Grype and
# the dependency scanner; nothing in the assertions depends on the network.
#
# Green: ak-backend:1.11.0 and newer. Red: ak-backend:1.10.0.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test, so
# a failed grep or curl must never end the run before end_suite.

begin_suite "scan-on-upload-native-and-completeness"
auth_admin
setup_workdir
require_cmd python3

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
FX="${WORK_DIR}/fx"

R_MVN="sou-mvn-${SUF}"
R_NPM="sou-npm-${SUF}"
R_OCI="sou-oci-${SUF}"
R_CARGO="sou-cargo-${SUF}"
R_NUGET="sou-nuget-${SUF}"
R_CONDA="sou-conda-${SUF}"
R_ZIP="sou-zip-${SUF}"
R_WHL="sou-whl-${SUF}"
R_REUSE="sou-reuse-${SUF}"
ALL_REPOS="$R_MVN $R_NPM $R_OCI $R_CARGO $R_NUGET $R_CONDA $R_ZIP $R_WHL $R_REUSE"

cleanup() {
  local k
  for k in $ALL_REPOS; do api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true; done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
# put FILE URL [content-type] -> HTTP status
put() {
  curl -s -o "${WORK_DIR}/put.out" -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" \
    -H "Content-Type: ${3:-application/octet-stream}" --data-binary "@$1" "$2" 2>/dev/null || echo 000
}
# completed_scans REPO_KEY [PATH_SUFFIX] -> count of completed scan_results rows
completed_scans() {
  psql_q "SELECT count(*) FROM scan_results s JOIN artifacts a ON a.id = s.artifact_id
          JOIN repositories r ON r.id = a.repository_id
          WHERE r.key = '$1' AND s.status = 'completed' AND a.path LIKE '%${2:-}'"
}
has_scan() { [ "$(completed_scans "$@")" -ge 1 ] 2>/dev/null; }
all_native_scanned() {
  local k
  for k in "$R_MVN" "$R_NPM" "$R_OCI" "$R_CARGO" "$R_CONDA"; do has_scan "$k" || return 1; done
}
art_id() { api_get "/api/v1/repositories/$1/artifacts/$2" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true; }
# grype_row REPO_KEY PATH_SUFFIX [SCAN_TYPE] -> "completeness|reason" of the
# newest completed row of that scanner (default grype)
grype_row() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT coalesce(s.scan_completeness,'') || '|' || coalesce(s.scan_completeness_reason,'')
     FROM scan_results s JOIN artifacts a ON a.id = s.artifact_id JOIN repositories r ON r.id = a.repository_id
     WHERE r.key = '$1' AND a.path LIKE '%$2' AND s.scan_type = '${3:-grype}' AND s.status = 'completed'
     ORDER BY s.completed_at DESC LIMIT 1" 2>/dev/null | head -1 || true
}
score_of() { # REPO_KEY -> "grade has_uncataloged_scan"
  api_get "/api/v1/repositories/$1/security" 2>/dev/null \
    | jq -r '(.score // {}) | "\(.grade // "none") \(.has_uncataloged_scan // "none")"' 2>/dev/null || true
}
score_is() { [ "$(score_of "$1")" = "$2" ]; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: build fixtures, create hosted repos with scan_enabled + scan_on_upload"
mkdir -p "$FX"
python3 -I "${HERE}/fixtures/make_fixtures.py" "$FX" "$SUF" > "${WORK_DIR}/names.json" 2>"${WORK_DIR}/mk.err" || true
NAME=$(jq -r '.npm // empty' "${WORK_DIR}/names.json" 2>/dev/null || true)
curl -s --max-time 10 -o "${FX}/clean.jar" "${MOCK}/__golden/maven2/com/example/dtfscan/dtf-clean/1.0.0/dtf-clean-1.0.0.jar" || true
curl -s --max-time 10 -o "${FX}/clean.nupkg" "${MOCK}/__golden/nuget/v3-flatcontainer/dtf.scanclean/1.0.0/dtf.scanclean.1.0.0.nupkg" || true
curl -s --max-time 10 -o "${FX}/log4j.jar" "${MOCK}/__golden/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar" || true
ok=1
for pair in "$R_MVN:maven" "$R_NPM:npm" "$R_OCI:docker" "$R_CARGO:cargo" "$R_NUGET:nuget" "$R_CONDA:conda" \
            "$R_ZIP:generic" "$R_WHL:generic" "$R_REUSE:generic"; do
  k="${pair%%:*}"
  create_repo "$k" "${pair#*:}" local || ok=0
  [ "$(api_put "/api/v1/repositories/${k}/security" '{"scan_enabled":true,"scan_on_upload":true}' 2>/dev/null \
      | jq -r '.scan_on_upload' 2>/dev/null || true)" = "true" ] || ok=0
done
if [ "$ok" = 1 ] && [ -n "$NAME" ] && [ -s "${FX}/clean.jar" ] && [ -s "${FX}/clean.nupkg" ] && [ -s "${FX}/log4j.jar" ]; then
  pass
else
  fail "setup ok=${ok} name=${NAME:-none} $(head -c 200 "${WORK_DIR}/mk.err" 2>/dev/null)"
fi

# ---------------------------------------------------------------------------
# Native publishes (control: every one is accepted on every image)
# ---------------------------------------------------------------------------
begin_test "control: native publishes are accepted (mvn deploy PUT, npm publish, OCI push, cargo publish, NuGet push, conda PUT)"
s_mvn=$(put "${FX}/clean.jar" "${BASE_URL}/maven/${R_MVN}/com/example/dtfscan/dtf-clean/1.0.0/dtf-clean-1.0.0.jar")
s_npm=$(put "${FX}/npm-publish.json" "${BASE_URL}/npm/${R_NPM}/${NAME}" application/json)
s_blob=""
for b in oci-config.json oci-layer.tar.gz; do
  d="sha256:$(sha256sum "${FX}/${b}" | cut -d' ' -f1)"
  s_blob+=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X POST -H "$(auth_header)" \
    -H 'Content-Type: application/octet-stream' --data-binary "@${FX}/${b}" \
    "${BASE_URL}/v2/${R_OCI}/img/blobs/uploads/?digest=${d}" 2>/dev/null || echo 000)
done
s_man=$(put "${FX}/oci-manifest.json" "${BASE_URL}/v2/${R_OCI}/img/manifests/v1" application/vnd.oci.image.manifest.v1+json)
s_cargo=$(put "${FX}/cargo-publish.bin" "${BASE_URL}/cargo/${R_CARGO}/api/v1/crates/new")
s_nuget=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" \
  -F "package=@${FX}/clean.nupkg" "${BASE_URL}/nuget/${R_NUGET}/api/v2/package/" 2>/dev/null || echo 000)
s_conda=$(put "${FX}/conda.tar.bz2" "${BASE_URL}/conda/${R_CONDA}/noarch/${NAME}-1.0.0-py_0.tar.bz2")
got="mvn=${s_mvn} npm=${s_npm} blobs=${s_blob} manifest=${s_man} cargo=${s_cargo} nuget=${s_nuget} conda=${s_conda}"
if [[ "$s_mvn" =~ ^20[01]$ && "$s_npm" =~ ^20[01]$ && "$s_blob" = "201201" && "$s_man" = "201" \
      && "$s_cargo" = "200" && "$s_nuget" =~ ^20[01]$ && "$s_conda" =~ ^20[01]$ ]]; then
  pass
else
  fail "$got"
fi

begin_test "control: generic uploads are accepted (docs .zip, package-shaped .whl, log4j jar A)"
s1=$(put "${FX}/docs.zip" "${BASE_URL}/api/v1/repositories/${R_ZIP}/artifacts/bundles/docs-${SUF}.zip")
s2=$(put "${FX}/fake.whl" "${BASE_URL}/api/v1/repositories/${R_WHL}/artifacts/wheels/dtfsou-1.0-py3-none-any.whl")
s3=$(put "${FX}/log4j.jar" "${BASE_URL}/api/v1/repositories/${R_REUSE}/artifacts/a/log4j-core-2.14.1.jar")
if [[ "$s1" =~ ^20[01]$ && "$s2" =~ ^20[01]$ && "$s3" =~ ^20[01]$ ]]; then pass; else fail "zip=${s1} whl=${s2} jarA=${s3}"; fi

begin_test "control: the generic upload route and NuGet push already scan on upload (completed rows, no trigger)"
wait_until "generic + nuget scan rows" 90 has_scan "$R_ZIP" || true
wait_until "nuget scan row" 30 has_scan "$R_NUGET" || true
wait_until "jar A scan row" 60 has_scan "$R_REUSE" "a/log4j-core-2.14.1.jar" || true
if has_scan "$R_ZIP" && has_scan "$R_NUGET" && has_scan "$R_REUSE" "a/log4j-core-2.14.1.jar"; then
  pass
else
  fail "completed rows: zip=$(completed_scans "$R_ZIP") nuget=$(completed_scans "$R_NUGET") jarA=$(completed_scans "$R_REUSE" a/log4j-core-2.14.1.jar)"
fi

# ---------------------------------------------------------------------------
# #4166 / #4124 / #4125 / #4159: native handlers scan on upload
# ---------------------------------------------------------------------------
wait_until "scan rows on every native publish" 60 all_native_scanned || true
for pair in "$R_MVN:#4166/#4124 mvn deploy (Maven PUT of a .jar)" "$R_NPM:#4166 npm publish" \
            "$R_OCI:#4166/#4125 docker push (OCI manifest PUT)" "$R_CARGO:#4166 cargo publish" \
            "$R_CONDA:#4159 native conda PUT"; do
  k="${pair%%:*}"
  begin_test "FIX ${pair#*:} into a scan_on_upload repo produces a completed scan with no manual trigger"
  n=$(completed_scans "$k")
  if [ "${n:-0}" -ge 1 ] 2>/dev/null; then
    pass
  else
    fail "completed scan_results rows for ${k}: ${n:-0} (pre-1.11.0 only the generic route scanned on upload)"
  fi
done

# ---------------------------------------------------------------------------
# #4036 / #4094 / #4154: not_cataloged
# ---------------------------------------------------------------------------
begin_test "FIX #4036/#4094: the conda package Grype cannot catalog is recorded not_cataloged with a reason; repo flagged, grade F"
row=$(grype_row "$R_CONDA" ".tar.bz2")
wait_until "conda repo score" 30 score_is "$R_CONDA" "F true" || true
sc=$(score_of "$R_CONDA")
if [ "${row%%|*}" = "not_cataloged" ] && [ -n "${row#*|}" ] && [ "$sc" = "F true" ]; then
  pass
else
  fail "grype row '${row}', score '${sc}' (pre-fix: complete / grade A)"
fi

begin_test "FIX #4154: a plain generic .zip nothing catalogs is not_cataloged (Grype and, set-level, the dependency scanner) and flags the repo without flooring the grade"
row=$(grype_row "$R_ZIP" "docs-${SUF}.zip")
dep=$(grype_row "$R_ZIP" "docs-${SUF}.zip" dependency)
wait_until "zip repo score" 30 score_is "$R_ZIP" "A true" || true
sc=$(score_of "$R_ZIP")
if [ "${row%%|*}" = "not_cataloged" ] && [ -n "${row#*|}" ] && [ "${dep%%|*}" = "not_cataloged" ] \
   && [[ "${dep#*|}" == "no scanner cataloged any component"* ]] && [ "$sc" = "A true" ]; then
  pass
else
  fail "grype row '${row}', dependency row '${dep}', score '${sc}'"
fi

begin_test "FIX #4154: a package-shaped generic .whl nothing catalogs floors the grade to F"
wait_until "whl scan row" 30 has_scan "$R_WHL" || true
row=$(grype_row "$R_WHL" ".whl")
wait_until "whl repo score" 30 score_is "$R_WHL" "F true" || true
sc=$(score_of "$R_WHL")
if [ "${row%%|*}" = "not_cataloged" ] && [ "$sc" = "F true" ]; then
  pass
else
  fail "grype row '${row}', score '${sc}' (pre-fix: complete / grade A)"
fi

begin_test "FIX #4154: a not_cataloged scan is never reused for identical bytes (second .zip gets its own scan)"
s=$(put "${FX}/docs.zip" "${BASE_URL}/api/v1/repositories/${R_ZIP}/artifacts/bundles/copy-${SUF}.zip")
wait_until "copy zip scan row" 60 has_scan "$R_ZIP" "copy-${SUF}.zip" || true
reused=$(psql_q "SELECT count(*) FROM scan_results s JOIN artifacts a ON a.id = s.artifact_id
                 WHERE a.path LIKE '%copy-${SUF}.zip' AND s.status = 'completed' AND s.is_reused")
total=$(completed_scans "$R_ZIP" "copy-${SUF}.zip")
if [[ "$s" =~ ^20[01]$ ]] && [ "${total:-0}" -ge 1 ] 2>/dev/null && [ "$reused" = "0" ]; then
  pass
else
  fail "upload ${s}; completed rows ${total:-0}, of which reused ${reused:-?}"
fi

# ---------------------------------------------------------------------------
# #4425: reuse copies only from an original scan
# ---------------------------------------------------------------------------
CK=$(sha256sum "${FX}/log4j.jar" | cut -d' ' -f1)
begin_test "control: identical jar B reuses jar A's Grype scan (is_reused, source = A's original)"
s=$(put "${FX}/log4j.jar" "${BASE_URL}/api/v1/repositories/${R_REUSE}/artifacts/b/log4j-core-2.14.1.jar")
B_ID=$(art_id "$R_REUSE" "b/log4j-core-2.14.1.jar")
b_reused() { [ "$(psql_q "SELECT count(*) FROM scan_results WHERE artifact_id='${B_ID}' AND scan_type='grype' AND status='completed' AND is_reused")" -ge 1 ] 2>/dev/null; }
wait_until "B's reused grype row" 60 b_reused || true
A_ORIG=$(psql_q "SELECT s.id FROM scan_results s JOIN artifacts a ON a.id = s.artifact_id
                 WHERE a.path = 'a/log4j-core-2.14.1.jar' AND a.repository_id = (SELECT id FROM repositories WHERE key='${R_REUSE}')
                   AND s.scan_type='grype' AND s.status='completed' AND s.source_scan_id IS NULL
                 ORDER BY s.completed_at DESC LIMIT 1")
b_src=$(psql_q "SELECT source_scan_id FROM scan_results WHERE artifact_id='${B_ID}' AND scan_type='grype' AND status='completed' AND is_reused LIMIT 1")
if [[ "$s" =~ ^20[01]$ ]] && [ -n "$A_ORIG" ] && [ "$b_src" = "$A_ORIG" ]; then
  pass
else
  fail "upload ${s}; A original '${A_ORIG}', B source '${b_src}'"
fi

begin_test "FIX #4425: once A's original scan is past the 30-day reuse window, C is scanned afresh (a copy does not restart the window)"
# Age every ORIGINAL grype scan of these bytes past DEDUP_TTL_DAYS (30). B's
# reused copy keeps its fresh completed_at; pre-fix it is the newest match and
# C copies from it.
psql_q "UPDATE scan_results SET completed_at = NOW() - interval '40 days', created_at = NOW() - interval '40 days'
        WHERE checksum_sha256 = '${CK}' AND scan_type = 'grype' AND source_scan_id IS NULL" >/dev/null
s=$(put "${FX}/log4j.jar" "${BASE_URL}/api/v1/repositories/${R_REUSE}/artifacts/c/log4j-core-2.14.1.jar")
C_ID=$(art_id "$R_REUSE" "c/log4j-core-2.14.1.jar")
c_done() { [ "$(psql_q "SELECT count(*) FROM scan_results WHERE artifact_id='${C_ID}' AND scan_type='grype' AND status='completed'")" -ge 1 ] 2>/dev/null; }
wait_until "C's grype row" 90 c_done || true
c_row=$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT is_reused || '|' || coalesce(source_scan_id::text,'') || '|' || findings_count
   FROM scan_results WHERE artifact_id='${C_ID}' AND scan_type='grype' AND status='completed'
   ORDER BY completed_at DESC LIMIT 1" 2>/dev/null | head -1 || true)
if [[ "$s" =~ ^20[01]$ ]] && [ "${c_row%%|*}" = "false" ] && [ "$(cut -d'|' -f3 <<<"$c_row")" -gt 0 ] 2>/dev/null; then
  pass
else
  fail "C grype row (is_reused|source|findings): '${c_row}' (pre-fix: reused from B's copy)"
fi

end_suite
