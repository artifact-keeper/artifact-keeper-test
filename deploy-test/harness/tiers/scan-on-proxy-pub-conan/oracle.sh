#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-proxy-pub-conan/oracle.sh - the scan-on-proxy gate on proxied
# Pub package archives and Conan recipe/package archives, Remote and Virtual
# =============================================================================
# artifact-keeper 1.12.0: #4107 (Pub), #4108 (Conan), epic #4097. Before them
# both download handlers streamed a Remote's archive straight through even
# with scan_on_proxy=true, and `GET /api/v1/formats` reported them
# `accepted`. They now go through proxy_helpers::serve_scanned_proxy_file:
#   * Pub: the archive's root pubspec.yaml must declare the requested name
#     and version; the engine catalogs that pubspec as the package itself.
#   * Conan: the .tgz archives (conan_export / conan_sources / conan_package)
#     must be readable gzipped tars and are graded on their contents;
#     conanfile.py and the manifests stream unscanned.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH. Verdicts come from the backend
# image's bundled Grype and its pre-seeded DB; nothing leaves the host.
#
# Fixtures (scan-on-proxy-maven-nuget/fixtures/mock_scan_upstream.py):
#   Pub    http 0.12.0, dtf_scanclean 1.0.0, dtf_scanliar 2.0.0 (pubspec says
#          1.0.0)
#   Conan  dtfvuln 1.0.0 (conan_sources.tgz requires openssl/1.1.1k),
#          dtfclean 1.0.0, dtfliar 1.0.0 (conan_sources.tgz is not a tar.gz)
#
# Green: an image carrying #4107-#4108. Red: ak-backend:1.11.5 (every FIX
# case; every control passes on both).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test, so
# a failed grep or curl must never end the run before end_suite.

begin_suite "scan-on-proxy-pub-conan"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

PUB="sopb-pub-${SUF}"        # Pub Remote, fail_closed
PUB_FO="sopb-pubfo-${SUF}"   # Pub Remote, fail_open
PUB_OFF="sopb-puboff-${SUF}" # Pub Remote, no scanning (control)
PUB_M="sopb-pubm-${SUF}"     # Pub Remote member of PUB_V, fail_closed
PUB_V="sopb-pubv-${SUF}"     # Pub Virtual over PUB_M
CON="sopb-con-${SUF}"        # Conan Remote, fail_closed
CON_OFF="sopb-conoff-${SUF}" # Conan Remote, no scanning (control)
CON_M="sopb-conm-${SUF}"     # Conan Remote member of CON_V, fail_closed
CON_V="sopb-conv-${SUF}"     # Conan Virtual over CON_M

PUB_VULN="packages/http/versions/0.12.0.tar.gz"
PUB_CLEAN="packages/dtf_scanclean/versions/1.0.0.tar.gz"
PUB_LIAR="packages/dtf_scanliar/versions/2.0.0.tar.gz"
RREV="0123456789abcdef0123456789abcdef"
con_file() { echo "v2/conans/$1/1.0.0/_/_/revisions/${RREV}/files/$2"; }
CON_VULN="$(con_file dtfvuln conan_sources.tgz)"
CON_CLEAN="$(con_file dtfclean conan_sources.tgz)"
CON_LIAR="$(con_file dtfliar conan_sources.tgz)"
CON_PY="$(con_file dtfvuln conanfile.py)"

cleanup() {
  local k
  for k in "$PUB_V" "$CON_V" "$PUB_M" "$CON_M" "$PUB" "$PUB_FO" "$PUB_OFF" "$CON" "$CON_OFF"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
hits() { curl -s --max-time 10 "${MOCK}/__hits?prefix=$1" | jq -r '.count // empty' 2>/dev/null; }

BODY="${WORK_DIR}/body"
HDR="${WORK_DIR}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 120 "$1" 2>/dev/null) || ST="000"
  SCAN=$(hdr x-ak-scan)
  BSHA=$(sha256sum "$BODY" 2>/dev/null | cut -d' ' -f1)
}
hdr() { grep -i "^$1:" "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
body_file() { jq -r '.file // empty' "$BODY" 2>/dev/null || true; }
snippet() { head -c 200 "$BODY" | tr -c '[:print:]' '.'; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
verdict_rows() { psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256='$1'"; }
scan_cfg() { # key action -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: mock upstream reachable and the Pub and Conan fixtures present"
if [ -n "$(golden_sha "pub/${PUB_VULN}")" ] && [ -n "$(golden_sha "conan/${CON_VULN}")" ]; then
  pass
else
  fail "mock control endpoint ${MOCK} did not answer (or this mock predates the Pub/Conan fixtures)"
fi

begin_test "Setup: Remotes (fail_closed, fail_open, unscanned) and a Virtual per format"
ok=1
for k in "$PUB" "$PUB_FO" "$PUB_OFF" "$PUB_M"; do create_repo "$k" pub remote "${UP}/pub" || ok=0; done
for k in "$CON" "$CON_OFF" "$CON_M"; do create_repo "$k" conan remote "${UP}/conan" || ok=0; done
create_repo "$PUB_V" pub virtual || ok=0
create_repo "$CON_V" conan virtual || ok=0
api_post "/api/v1/repositories/${PUB_V}/members" "{\"member_key\":\"${PUB_M}\"}" >/dev/null 2>&1 || ok=0
api_post "/api/v1/repositories/${CON_V}/members" "{\"member_key\":\"${CON_M}\"}" >/dev/null 2>&1 || ok=0
a="$(scan_cfg "$PUB" fail_closed) $(scan_cfg "$PUB_FO" fail_open) $(scan_cfg "$PUB_M" fail_closed)"
a="$a $(scan_cfg "$CON" fail_closed) $(scan_cfg "$CON_M" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closed fail_open fail_closed fail_closed fail_closed" ]; then
  pass
else
  fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
fi

D="${BASE_URL}/pub"
C="${BASE_URL}/conan"

# ---------------------------------------------------------------------------
# Controls (pass on every image)
# ---------------------------------------------------------------------------
begin_test "control: Remotes WITHOUT scan_on_proxy stream the vulnerable Pub and Conan archives unchanged, no X-AK-Scan"
pull "${D}/${PUB_OFF}/${PUB_VULN}"; s1="$ST/$SCAN"; ok1=$([ "$BSHA" = "$(golden_sha "pub/${PUB_VULN}")" ] && echo y)
pull "${C}/${CON_OFF}/${CON_VULN}"; s2="$ST/$SCAN"; ok2=$([ "$BSHA" = "$(golden_sha "conan/${CON_VULN}")" ] && echo y)
if [ "$s1 $s2" = "200/ 200/" ] && [ "$ok1$ok2" = "yy" ]; then
  pass
else
  fail "pub=${s1} conan=${s2} bytes-match='${ok1}${ok2}'"
fi

begin_test "control: conanfile.py through the fail_closed Conan Remote is not gated (200, upstream bytes, no X-AK-Scan)"
pull "${C}/${CON}/${CON_PY}"
if [ "$ST/$SCAN" = "200/" ] && [ "$BSHA" = "$(golden_sha "conan/${CON_PY}")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "control: GET /api/v1/formats lists the pub and conan handlers"
FMT="${WORK_DIR}/formats.json"
api_get "/api/v1/formats" > "$FMT" 2>/dev/null || true
fmt_field() { jq -r --arg k "$1" --arg f "$2" '[(if type == "array" then . else .items end)[] | select(.format_key==$k)][0][$f] // empty' "$FMT" 2>/dev/null || true; }
if [ "$(fmt_field pub format_key) $(fmt_field conan format_key)" = "pub conan" ]; then
  pass
else
  fail "formats: $(head -c 200 "$FMT")"
fi

# ---------------------------------------------------------------------------
# The formats capability
# ---------------------------------------------------------------------------
begin_test "FIX #4107/#4108: /api/v1/formats reports pub and conan scan_on_proxy=enforced (hex stays accepted)"
got="$(fmt_field pub scan_on_proxy) $(fmt_field conan scan_on_proxy) $(fmt_field hex scan_on_proxy)"
if [ "$got" = "enforced enforced accepted" ]; then
  pass
else
  fail "pub conan hex = '${got}' (1.11.x: accepted accepted accepted)"
fi

# ---------------------------------------------------------------------------
# #4107 Pub
# ---------------------------------------------------------------------------
begin_test "FIX #4107: fail_closed pull of http 0.12.0 is 403 scan_blocked with a 'vulnerable' verdict"
pull "${D}/${PUB}/${PUB_VULN}"
d=$(golden_sha "pub/${PUB_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(body_file)" = "http-0.12.0.tar.gz" ] \
   && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4107: a package no advisory names is graded as itself (cataloged) and served 200 clean; the second pull reuses verdict and cache"
pull "${D}/${PUB}/${PUB_CLEAN}"
s1="$ST/$SCAN"; b1="$BSHA"
d=$(golden_sha "pub/${PUB_CLEAN}")
h1=$(hits "/pub/${PUB_CLEAN}")
pull "${D}/${PUB}/${PUB_CLEAN}"
h2=$(hits "/pub/${PUB_CLEAN}")
cataloged=$(psql_q "SELECT components_cataloged FROM proxy_scan_results WHERE checksum_sha256='${d}' ORDER BY scanned_at DESC LIMIT 1")
if [ "$s1" = "200/clean" ] && [ "$b1" = "$d" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "$(verdict_rows "$d")" = "1" ] \
   && [ "$h1" = "$h2" ] && [ "${cataloged:-0}" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "first=${s1} second=${ST}/${SCAN} rows=$(verdict_rows "$d") cataloged='${cataloged}' upstream GETs ${h1:-?} -> ${h2:-?}"
fi

begin_test "FIX #4107: an archive whose pubspec.yaml declares another version is withheld under fail_closed (423, no verdict row)"
pull "${D}/${PUB}/${PUB_LIAR}"
d=$(golden_sha "pub/${PUB_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4107: fail_open first pull of http 0.12.0 is 200 X-AK-Scan: pending, then 403 once the async verdict lands"
psql_q "DELETE FROM proxy_scan_results WHERE checksum_sha256='$(golden_sha "pub/${PUB_VULN}")'" >/dev/null
pull "${D}/${PUB_FO}/${PUB_VULN}"
s1="$ST/$SCAN"; cc=$(hdr cache-control)
d=$(golden_sha "pub/${PUB_VULN}")
pub_vulnerable() { [ "$(verdict_of "$d")" = "vulnerable" ]; }
wait_until "vulnerable verdict for the fail_open pub archive" 60 pub_vulnerable || true
pull "${D}/${PUB_FO}/${PUB_VULN}"
if [ "$s1" = "200/pending" ] && [ "$cc" = "no-store" ] && [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "first=${s1} cache-control='${cc}' second=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4107: through a Virtual whose Remote member scans, http 0.12.0 is 403 and the clean package 200 clean"
pull "${D}/${PUB_V}/${PUB_VULN}"; s1="$ST/$(body_err)"
pull "${D}/${PUB_V}/${PUB_CLEAN}"
if [ "$s1" = "403/scan_blocked" ] && [ "$ST/$SCAN" = "200/clean" ]; then
  pass
else
  fail "vulnerable=${s1} clean=${ST}/${SCAN}"
fi

# ---------------------------------------------------------------------------
# #4108 Conan
# ---------------------------------------------------------------------------
begin_test "FIX #4108: fail_closed pull of conan_sources.tgz requiring openssl/1.1.1k is 403 scan_blocked"
pull "${C}/${CON}/${CON_VULN}"
d=$(golden_sha "conan/${CON_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(body_file)" = "conan_sources.tgz" ] \
   && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4108: an archive with no vulnerable content is 200 X-AK-Scan: clean"
pull "${C}/${CON}/${CON_CLEAN}"
d=$(golden_sha "conan/${CON_CLEAN}")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' verdict='$(verdict_of "$d")' body=$(snippet)"
fi

begin_test "FIX #4108: a .tgz that is not a gzipped tar is withheld under fail_closed (423, no verdict row)"
pull "${C}/${CON}/${CON_LIAR}"
d=$(golden_sha "conan/${CON_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4108: through a Virtual whose Remote member scans, the vulnerable archive is 403 scan_blocked"
pull "${C}/${CON_V}/${CON_VULN}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

end_suite
