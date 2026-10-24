#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-proxy-maven-nuget/oracle.sh - the scan-on-proxy gate on
# proxied Maven archives and NuGet packages, and the formats capability
# =============================================================================
# artifact-keeper 1.11.0: #4100 (Maven/Gradle/sbt, issue #4097), #4102 (NuGet,
# Chocolatey, PowerShell), #3603 (a real .nuspec with an <?xml ?> declaration
# pins the scan identity), #4099 (`GET /api/v1/formats` reports
# `scan_on_proxy`). Before 1.11.0 only PyPI, npm, OCI and VS Code proxied
# downloads went through the inline scan gate; a Maven or NuGet Remote with
# `scan_on_proxy=true` streamed every package unscanned, with no `X-AK-Scan`
# header, whatever the repository's `proxy_scan_action` said.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH. The verdicts come from the backend
# image's bundled Grype and its pre-seeded DB; nothing leaves the host.
#
# Fixture identities (mock_scan_upstream.py): log4j-core 2.14.1 (Log4Shell,
# critical), Newtonsoft.Json 12.0.1 (GHSA-5crp-9r3c-p9vr, high) are graded
# vulnerable; com.example.dtfscan:dtf-clean 1.0.0 and Dtf.ScanClean 1.0.0 are
# clean; dtf-liar / Dtf.ScanLiar declare a different version than the one
# requested; dtf-badsha has a lying .sha1 sidecar.
#
# Green: ak-backend:1.11.0 and newer. Red: ak-backend:1.10.0 (every FIX case;
# every control passes on both).
# =============================================================================
set -uo pipefail
# common.sh turns on errexit; every probe below is an assignment or a test, so
# a failed grep or curl must never end the run before end_suite.
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "scan-on-proxy-maven-nuget"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

MVN="sop-mvn-${SUF}"        # Remote, scan_on_proxy, fail_closed
MVN_OFF="sop-mvnoff-${SUF}" # Remote, no scanning (control)
MVN_M="sop-mvnm-${SUF}"     # Remote member of the virtual, fail_closed
MVN_V="sop-mvnv-${SUF}"     # Virtual over MVN_M
NUG="sop-nug-${SUF}"        # Remote, scan_on_proxy, fail_closed
NUG_OFF="sop-nugoff-${SUF}" # Remote, no scanning (control)

LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1"
CLEAN="com/example/dtfscan/dtf-clean/1.0.0/dtf-clean-1.0.0"
LIAR="com/example/dtfscan/dtf-liar/2.0.0/dtf-liar-2.0.0"
BADSHA="com/example/dtfscan/dtf-badsha/1.0.0/dtf-badsha-1.0.0"
NJ_DIR="newtonsoft.json/12.0.1"
NJ_NUPKG="${NJ_DIR}/newtonsoft.json.12.0.1.nupkg"
NJ_NUSPEC="${NJ_DIR}/newtonsoft.json.nuspec"
NC_NUPKG="dtf.scanclean/1.0.0/dtf.scanclean.1.0.0.nupkg"
NL_NUPKG="dtf.scanliar/2.0.0/dtf.scanliar.2.0.0.nupkg"

cleanup() {
  local k
  for k in "$MVN_V" "$MVN_M" "$MVN" "$MVN_OFF" "$NUG" "$NUG_OFF"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
hits() { curl -s --max-time 10 "${MOCK}/__hits?prefix=$1" | jq -r '.count // empty' 2>/dev/null; }

# pull URL -> sets ST (status), SCAN (X-AK-Scan or ""), BODY (file), BSHA.
BODY="${WORK_DIR}/body"
pull() {
  local hdr="${WORK_DIR}/hdr"
  ST=$(curl -s -D "$hdr" -o "$BODY" -w '%{http_code}' --max-time 120 "$1" 2>/dev/null) || ST="000"
  SCAN=$(grep -i '^x-ak-scan:' "$hdr" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1) || true
  BSHA=$(sha256sum "$BODY" 2>/dev/null | cut -d' ' -f1)
}
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null; }
snippet() { head -c 200 "$BODY" | tr -c '[:print:]' '.'; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }

remote() { # key format upstream
  create_repo "$1" "$2" "remote" "$3"
}
scan_cfg() { # key action -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: mock upstream reachable and fixtures present"
if [ -n "$(golden_sha "maven2/${LOG4J}.jar")" ] && [ -n "$(golden_sha "nuget/v3-flatcontainer/${NJ_NUPKG}")" ]; then
  pass
else
  fail "mock control endpoint ${MOCK} did not answer"
fi

begin_test "Setup: Maven + NuGet Remotes (fail_closed scan-on-proxy), unscanned controls, Maven virtual"
ok=1
remote "$MVN" maven "${UP}/maven2" || ok=0
remote "$MVN_OFF" maven "${UP}/maven2" || ok=0
remote "$MVN_M" maven "${UP}/maven2" || ok=0
create_repo "$MVN_V" maven virtual || ok=0
api_post "/api/v1/repositories/${MVN_V}/members" "{\"member_key\":\"${MVN_M}\"}" >/dev/null 2>&1 || ok=0
remote "$NUG" nuget "${UP}/nuget/v3/index.json" || ok=0
remote "$NUG_OFF" nuget "${UP}/nuget/v3/index.json" || ok=0
a1=$(scan_cfg "$MVN" fail_closed); a2=$(scan_cfg "$MVN_M" fail_closed); a3=$(scan_cfg "$NUG" fail_closed)
if [ "$ok" = 1 ] && [ "$a1$a2$a3" = "fail_closedfail_closedfail_closed" ]; then
  pass
else
  fail "repo setup failed (ok=${ok}) or proxy_scan_action not persisted: '${a1}' '${a2}' '${a3}'"
fi

M="${BASE_URL}/maven"
N="${BASE_URL}/nuget"

# ---------------------------------------------------------------------------
# Controls (pass on every image)
# ---------------------------------------------------------------------------
begin_test "control: a Remote WITHOUT scan_on_proxy streams log4j-core-2.14.1.jar unchanged, no X-AK-Scan"
pull "${M}/${MVN_OFF}/${LOG4J}.jar"
if [ "$ST" = "200" ] && [ "$BSHA" = "$(golden_sha "maven2/${LOG4J}.jar")" ] && [ -z "$SCAN" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' sha=${BSHA}"
fi

begin_test "control: a POM through the fail_closed Remote is served as metadata (200, upstream bytes, no X-AK-Scan)"
pull "${M}/${MVN}/${LOG4J}.pom"
if [ "$ST" = "200" ] && [ "$BSHA" = "$(golden_sha "maven2/${LOG4J}.pom")" ] && [ -z "$SCAN" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "control: the .jar.sha1 sidecar through the fail_closed Remote is served (200, upstream bytes)"
pull "${M}/${MVN}/${LOG4J}.jar.sha1"
if [ "$ST" = "200" ] && [ "$BSHA" = "$(golden_sha "maven2/${LOG4J}.jar.sha1")" ] && [ -z "$SCAN" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "control: a NuGet Remote WITHOUT scan_on_proxy streams Newtonsoft.Json 12.0.1 unchanged, no X-AK-Scan"
pull "${N}/${NUG_OFF}/v3/flatcontainer/${NJ_NUPKG}"
if [ "$ST" = "200" ] && [ "$BSHA" = "$(golden_sha "nuget/v3-flatcontainer/${NJ_NUPKG}")" ] && [ -z "$SCAN" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "control: the .nuspec through the fail_closed NuGet Remote is metadata (200, upstream bytes, no X-AK-Scan)"
pull "${N}/${NUG}/v3/flatcontainer/${NJ_NUSPEC}"
if [ "$ST" = "200" ] && [ "$BSHA" = "$(golden_sha "nuget/v3-flatcontainer/${NJ_NUSPEC}")" ] && [ -z "$SCAN" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "control: GET /api/v1/formats lists the maven and nuget handlers"
FMT="${WORK_DIR}/formats.json"
api_get "/api/v1/formats" > "$FMT" 2>/dev/null || true
fmt_field() { jq -r --arg k "$1" --arg f "$2" '[(if type == "array" then . else .items end)[] | select(.format_key==$k)][0][$f] // empty' "$FMT" 2>/dev/null || true; }
if [ "$(fmt_field maven format_key)" = "maven" ] && [ "$(fmt_field nuget format_key)" = "nuget" ]; then
  pass
else
  fail "formats listing: $(head -c 200 "$FMT")"
fi

# ---------------------------------------------------------------------------
# #4099: the formats API reports the scan-on-proxy capability
# ---------------------------------------------------------------------------
# alpine is "accepted" on the 1.11 line and "enforced" from 1.12.0 (#4113);
# either value proves the capability field is reported.
begin_test "FIX #4099: /api/v1/formats reports scan_on_proxy=enforced for maven, nuget, cargo, npm, pypi and a capability value for alpine"
got="$(fmt_field maven scan_on_proxy) $(fmt_field nuget scan_on_proxy) $(fmt_field cargo scan_on_proxy) $(fmt_field npm scan_on_proxy) $(fmt_field pypi scan_on_proxy)"
alpine_cap="$(fmt_field alpine scan_on_proxy)"
if [ "$got" = "enforced enforced enforced enforced enforced" ] && { [ "$alpine_cap" = "accepted" ] || [ "$alpine_cap" = "enforced" ]; }; then
  pass
else
  fail "maven nuget cargo npm pypi = '${got}', alpine = '${alpine_cap}' (pre-1.11.0: field absent)"
fi

# ---------------------------------------------------------------------------
# #4100: Maven archives through the gate
# ---------------------------------------------------------------------------
begin_test "FIX #4100: fail_closed pull of log4j-core-2.14.1.jar is 403 scan_blocked (was 200 unscanned)"
pull "${M}/${MVN}/${LOG4J}.jar"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(jq -r '.file' "$BODY" 2>/dev/null)" = "log4j-core-2.14.1.jar" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4100: a 'vulnerable' proxy_scan_results verdict (max critical) is recorded for the jar's digest"
d=$(golden_sha "maven2/${LOG4J}.jar")
sev=$(psql_q "SELECT max_severity FROM proxy_scan_results WHERE checksum_sha256='${d}' ORDER BY scanned_at DESC LIMIT 1")
if [ "$(verdict_of "$d")" = "vulnerable" ] && [ "$sev" = "critical" ]; then
  pass
else
  fail "digest ${d}: verdict='$(verdict_of "$d")' max_severity='${sev}'"
fi

begin_test "FIX #4100: a jar no advisory names is served 200 with X-AK-Scan: clean and the upstream bytes"
pull "${M}/${MVN}/${CLEAN}.jar"
if [ "$ST" = "200" ] && [ "$SCAN" = "clean" ] && [ "$BSHA" = "$(golden_sha "maven2/${CLEAN}.jar")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4100: a jar whose pom.properties declares another version is withheld under fail_closed (423, no verdict row)"
pull "${M}/${MVN}/${LIAR}.jar"
d=$(golden_sha "maven2/${LIAR}.jar")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4100: a jar that disagrees with its .sha1 sidecar is refused 502 and not kept in the proxy cache"
pull "${M}/${MVN}/${BADSHA}.jar"
st1="$ST"; b1=$(snippet)
h1=$(hits "/maven2/${BADSHA}.jar")
pull "${M}/${MVN}/${BADSHA}.jar"
h2=$(hits "/maven2/${BADSHA}.jar")
if [ "$st1" = "502" ] && grep -q "sha1" <<<"$b1" && [ "$ST" = "502" ] && [ -n "$h1" ] && [ "${h2:-0}" -gt "${h1:-0}" ] 2>/dev/null; then
  pass
else
  fail "first=${st1} ${b1} second=${ST} upstream jar GETs ${h1:-?} -> ${h2:-?} (a cached body would not refetch)"
fi

begin_test "FIX #4100: a ';' path parameter is refused 400 before any upstream fetch"
before=$(hits "/maven2/${CLEAN%/*}/")
pull "${M}/${MVN}/${CLEAN}.jar;jsessionid=x"
after=$(hits "/maven2/${CLEAN%/*}/")
if [ "$ST" = "400" ] && [ "$(body_err)" = "VALIDATION_ERROR" ] && [ -n "$before" ] && [ "$after" = "$before" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) upstream hits ${before:-?} -> ${after:-?}"
fi

begin_test "FIX #4100: a metadata name nested under an archive (.jar/x.pom) is refused 400 before any upstream fetch"
before=$(hits "/maven2/${CLEAN%/*}/")
pull "${M}/${MVN}/${CLEAN}.jar/x.pom"
after=$(hits "/maven2/${CLEAN%/*}/")
if [ "$ST" = "400" ] && [ "$(body_err)" = "VALIDATION_ERROR" ] && [ -n "$before" ] && [ "$after" = "$before" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) upstream hits ${before:-?} -> ${after:-?}"
fi

begin_test "FIX #4100: through a Virtual whose Remote member scans, log4j-core-2.14.1.jar is 403 scan_blocked"
pull "${M}/${MVN_V}/${LOG4J}.jar"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4100: through the same Virtual the clean jar is 200 with X-AK-Scan: clean"
pull "${M}/${MVN_V}/${CLEAN}.jar"
if [ "$ST" = "200" ] && [ "$SCAN" = "clean" ] && [ "$BSHA" = "$(golden_sha "maven2/${CLEAN}.jar")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

# ---------------------------------------------------------------------------
# #4102 / #3603: NuGet packages through the gate
# ---------------------------------------------------------------------------
begin_test "FIX #4102: fail_closed V3 flat-container pull of Newtonsoft.Json 12.0.1 is 403 scan_blocked"
pull "${N}/${NUG}/v3/flatcontainer/${NJ_NUPKG}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(jq -r '.file' "$BODY" 2>/dev/null)" = "newtonsoft.json.12.0.1.nupkg" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4102: a 'vulnerable' verdict (max high) is recorded for the .nupkg digest"
d=$(golden_sha "nuget/v3-flatcontainer/${NJ_NUPKG}")
sev=$(psql_q "SELECT max_severity FROM proxy_scan_results WHERE checksum_sha256='${d}' ORDER BY scanned_at DESC LIMIT 1")
if [ "$(verdict_of "$d")" = "vulnerable" ] && [ "$sev" = "high" ]; then
  pass
else
  fail "digest ${d}: verdict='$(verdict_of "$d")' max_severity='${sev}'"
fi

begin_test "FIX #4102: the V2 package route serves the same package under the same verdict (403 scan_blocked)"
pull "${N}/${NUG}/v2/package/Newtonsoft.Json/12.0.1"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #3603/#4102: a package whose .nuspec carries an <?xml ?> declaration is graded and served (200, X-AK-Scan: clean)"
pull "${N}/${NUG}/v3/flatcontainer/${NC_NUPKG}"
if [ "$ST" = "200" ] && [ "$SCAN" = "clean" ] && [ "$BSHA" = "$(golden_sha "nuget/v3-flatcontainer/${NC_NUPKG}")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) (423 here means the nuspec identity did not parse)"
fi

begin_test "FIX #4102: a package whose .nuspec declares another version is withheld under fail_closed (423)"
pull "${N}/${NUG}/v3/flatcontainer/${NL_NUPKG}"
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4102: a package id with a ';' is refused 400 before any upstream fetch"
before=$(hits "/nuget/v3-flatcontainer/dtf.scanclean")
pull "${N}/${NUG}/v3/flatcontainer/dtf.scanclean;x/1.0.0/dtf.scanclean.1.0.0.nupkg"
after=$(hits "/nuget/v3-flatcontainer/dtf.scanclean")
if [ "$ST" = "400" ] && [ "$(body_err)" = "VALIDATION_ERROR" ] && [ -n "$before" ] && [ "$after" = "$before" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) upstream hits ${before:-?} -> ${after:-?}"
fi

end_suite
