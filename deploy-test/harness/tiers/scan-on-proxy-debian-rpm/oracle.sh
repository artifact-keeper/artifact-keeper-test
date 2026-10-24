#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-proxy-debian-rpm/oracle.sh - the scan-on-proxy gate on proxied
# Debian and RPM packages, Remote and Virtual
# =============================================================================
# artifact-keeper 1.12.0: #4111 (Debian), #4112 (RPM), epic #4097.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH.
#
# Fixtures (scan-on-proxy-maven-nuget/fixtures/mock_scan_upstream.py):
#   Debian  dists/bookworm/Release (Origin Debian, Version 12.7);
#           openssl 3.0.11-1~deb12u2 (vulnerable on Debian 12),
#           dtf-scanclean 1.0-1, dtf-scanliar 2.0-1 (control says 1.0-1);
#           debian-norel: dtf-norelease 1.0-1 under an upstream with no Release
#   RPM     openssl-libs 1:3.0.7-17.el9_2 (vulnerable on RHEL 9),
#           dtf-scanclean 1.0-1.el9, dtf-scanliar 2.0-1.el9 (header says 1.0),
#           dtf-notag 1.0-1 (no dist tag), repodata/repomd.xml
#
# Green: an image carrying #4111/#4112. Red: ak-backend:1.11.5 (every FIX
# case; every control passes on both).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "scan-on-proxy-debian-rpm"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

DEB="sopo-deb-${SUF}"         # Debian Remote, fail_closed
DEB_FO="sopo-debfo-${SUF}"    # Debian Remote, fail_open
DEB_RO="sopo-debro-${SUF}"    # Debian Remote, record_only
DEB_OFF="sopo-deboff-${SUF}"  # Debian Remote, no scanning (control)
DEB_NR="sopo-debnr-${SUF}"    # Debian Remote over an upstream with no Release, fail_closed
DEB_M="sopo-debm-${SUF}"      # Debian Remote member of DEB_V, fail_closed
DEB_V="sopo-debv-${SUF}"      # Debian Virtual over DEB_M
RPM="sopo-rpm-${SUF}"         # RPM Remote, fail_closed
RPM_FO="sopo-rpmfo-${SUF}"    # RPM Remote, fail_open
RPM_OFF="sopo-rpmoff-${SUF}"  # RPM Remote, no scanning (control)
RPM_M="sopo-rpmm-${SUF}"      # RPM Remote member of RPM_V, fail_closed
RPM_V="sopo-rpmv-${SUF}"      # RPM Virtual over RPM_M

DEB_VULN="pool/main/o/openssl/openssl_3.0.11-1~deb12u2_amd64.deb"
DEB_CLEAN="pool/main/d/dtf-scanclean/dtf-scanclean_1.0-1_amd64.deb"
DEB_LIAR="pool/main/d/dtf-scanliar/dtf-scanliar_2.0-1_amd64.deb"
DEB_NOREL="pool/main/d/dtf-norelease/dtf-norelease_1.0-1_amd64.deb"
TREE="9/BaseOS/x86_64/os"
RPM_VULN="${TREE}/Packages/o/openssl-libs-3.0.7-17.el9_2.x86_64.rpm"
RPM_CLEAN="${TREE}/Packages/d/dtf-scanclean-1.0-1.el9.noarch.rpm"
RPM_LIAR="${TREE}/Packages/d/dtf-scanliar-2.0-1.el9.noarch.rpm"
RPM_NOTAG="${TREE}/Packages/d/dtf-notag-1.0-1.noarch.rpm"
RPM_REPOMD="${TREE}/repodata/repomd.xml"

cleanup() {
  local k
  for k in "$DEB_V" "$RPM_V" "$DEB_M" "$RPM_M" "$DEB" "$DEB_FO" "$DEB_RO" "$DEB_OFF" "$DEB_NR" \
           "$RPM" "$RPM_FO" "$RPM_OFF"; do
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
cataloged_of() { psql_q "SELECT components_cataloged FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
scan_cfg() {
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: mock upstream reachable and the Debian and RPM fixtures present"
if [ -n "$(golden_sha "debian/${DEB_VULN}")" ] && [ -n "$(golden_sha "rpm/${RPM_VULN}")" ] \
   && [ -n "$(golden_sha "debian-norel/${DEB_NOREL}")" ]; then
  pass
else
  fail "mock control endpoint ${MOCK} did not answer (or this mock predates the Debian/RPM fixtures)"
fi

begin_test "Setup: Remotes (fail_closed, fail_open, record_only, unscanned) and a Virtual per format"
ok=1
for k in "$DEB" "$DEB_FO" "$DEB_RO" "$DEB_OFF" "$DEB_M"; do create_repo "$k" debian remote "${UP}/debian" || ok=0; done
create_repo "$DEB_NR" debian remote "${UP}/debian-norel" || ok=0
for k in "$RPM" "$RPM_FO" "$RPM_OFF" "$RPM_M"; do create_repo "$k" rpm remote "${UP}/rpm" || ok=0; done
create_repo "$DEB_V" debian virtual || ok=0
create_repo "$RPM_V" rpm virtual || ok=0
api_post "/api/v1/repositories/${DEB_V}/members" "{\"member_key\":\"${DEB_M}\"}" >/dev/null 2>&1 || ok=0
api_post "/api/v1/repositories/${RPM_V}/members" "{\"member_key\":\"${RPM_M}\"}" >/dev/null 2>&1 || ok=0
a="$(scan_cfg "$DEB" fail_closed) $(scan_cfg "$DEB_FO" fail_open) $(scan_cfg "$DEB_RO" record_only)"
a="$a $(scan_cfg "$DEB_NR" fail_closed) $(scan_cfg "$DEB_M" fail_closed)"
a="$a $(scan_cfg "$RPM" fail_closed) $(scan_cfg "$RPM_FO" fail_open) $(scan_cfg "$RPM_M" fail_closed)"
want="fail_closed fail_open record_only fail_closed fail_closed fail_closed fail_open fail_closed"
if [ "$ok" = 1 ] && [ "$a" = "$want" ]; then
  pass
else
  fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
fi

D="${BASE_URL}/debian"
R="${BASE_URL}/rpm"

# apt reads the suite's Release before any package; that is what caches the
# release the Debian gate grades against. The no-Release upstream answers 404.
begin_test "Setup: apt-style Release fetch through every scanning Debian Remote"
rs=""
for k in "$DEB" "$DEB_FO" "$DEB_RO" "$DEB_M" "$DEB_OFF"; do
  pull "${D}/${k}/dists/bookworm/Release"; rs="${rs} ${ST}"
done
if [ "$rs" = " 200 200 200 200 200" ]; then
  pass
else
  fail "Release statuses:${rs}"
fi

# ---------------------------------------------------------------------------
# Controls (pass on every image)
# ---------------------------------------------------------------------------
begin_test "control: Remotes WITHOUT scan_on_proxy stream the vulnerable .deb and .rpm unchanged, no X-AK-Scan"
pull "${D}/${DEB_OFF}/${DEB_VULN}"; s1="$ST/$SCAN"; ok1=$([ "$BSHA" = "$(golden_sha "debian/${DEB_VULN}")" ] && echo y)
pull "${R}/${RPM_OFF}/${RPM_VULN}"; s2="$ST/$SCAN"; ok2=$([ "$BSHA" = "$(golden_sha "rpm/${RPM_VULN}")" ] && echo y)
if [ "$s1 $s2" = "200/ 200/" ] && [ "$ok1$ok2" = "yy" ]; then
  pass
else
  fail "deb=${s1} rpm=${s2} bytes-match='${ok1}${ok2}'"
fi

begin_test "control: repository metadata through the fail_closed RPM Remote is not gated (repomd.xml 200, no X-AK-Scan)"
pull "${R}/${RPM}/${RPM_REPOMD}"
if [ "$ST/$SCAN" = "200/" ] && [ "$BSHA" = "$(golden_sha "rpm/${RPM_REPOMD}")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "control: GET /api/v1/formats lists the debian and rpm handlers"
FMT="${WORK_DIR}/formats.json"
api_get "/api/v1/formats" > "$FMT" 2>/dev/null || true
fmt_field() { jq -r --arg k "$1" --arg f "$2" '[(if type == "array" then . else .items end)[] | select(.format_key==$k)][0][$f] // empty' "$FMT" 2>/dev/null || true; }
if [ "$(fmt_field debian format_key) $(fmt_field rpm format_key)" = "debian rpm" ]; then
  pass
else
  fail "formats: $(head -c 200 "$FMT")"
fi

begin_test "FIX #4111/#4112: /api/v1/formats reports debian and rpm scan_on_proxy=enforced (helm stays accepted)"
got="$(fmt_field debian scan_on_proxy) $(fmt_field rpm scan_on_proxy) $(fmt_field helm scan_on_proxy)"
if [ "$got" = "enforced enforced accepted" ]; then
  pass
else
  fail "debian rpm helm = '${got}' (1.11.x: accepted accepted accepted)"
fi

# ---------------------------------------------------------------------------
# #4111 Debian
# ---------------------------------------------------------------------------
begin_test "FIX #4111: fail_closed pull of openssl 3.0.11-1~deb12u2 is 403 scan_blocked (graded on Debian 12)"
pull "${D}/${DEB}/${DEB_VULN}"
d=$(golden_sha "debian/${DEB_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] \
   && [ "$(body_file)" = "openssl_3.0.11-1~deb12u2_amd64.deb" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4111: a package no advisory names is graded as itself, 200 clean, and the second pull reuses the verdict and cache"
pull "${D}/${DEB}/${DEB_CLEAN}"
s1="$ST/$SCAN"; b1="$BSHA"
d=$(golden_sha "debian/${DEB_CLEAN}")
c=$(cataloged_of "$d")
h1=$(hits "/debian/${DEB_CLEAN}")
pull "${D}/${DEB}/${DEB_CLEAN}"
h2=$(hits "/debian/${DEB_CLEAN}")
if [ "$s1" = "200/clean" ] && [ "$b1" = "$d" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "${c:-0}" -ge 1 ] 2>/dev/null \
   && [ "$(verdict_rows "$d")" = "1" ] && [ "$h1" = "$h2" ]; then
  pass
else
  fail "first=${s1} second=${ST}/${SCAN} cataloged='${c}' rows=$(verdict_rows "$d") upstream GETs ${h1:-?} -> ${h2:-?}"
fi

begin_test "FIX #4111: a .deb whose control declares another version is withheld under fail_closed (423, no verdict row)"
pull "${D}/${DEB}/${DEB_LIAR}"
d=$(golden_sha "debian/${DEB_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4111: a .deb whose release cannot be determined is withheld under fail_closed (423, no verdict row)"
pull "${D}/${DEB_NR}/${DEB_NOREL}"
d=$(golden_sha "debian-norel/${DEB_NOREL}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4111: fail_open first pull of the vulnerable .deb is 200 X-AK-Scan: pending (no-store), then 403 once the verdict lands"
psql_q "DELETE FROM proxy_scan_results WHERE checksum_sha256='$(golden_sha "debian/${DEB_VULN}")'" >/dev/null
pull "${D}/${DEB_FO}/${DEB_VULN}"
s1="$ST/$SCAN"; cc=$(hdr cache-control)
d=$(golden_sha "debian/${DEB_VULN}")
deb_vulnerable() { [ "$(verdict_of "$d")" = "vulnerable" ]; }
wait_until "vulnerable verdict for the fail_open .deb" 60 deb_vulnerable || true
pull "${D}/${DEB_FO}/${DEB_VULN}"
if [ "$s1" = "200/pending" ] && [ "$cc" = "no-store" ] && [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "first=${s1} cache-control='${cc}' second=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4111: record_only serves the vulnerable .deb with X-AK-Scan: recorded"
pull "${D}/${DEB_RO}/${DEB_VULN}"
if [ "$ST" = "200" ] && [ "$SCAN" = "recorded" ] && [ "$BSHA" = "$(golden_sha "debian/${DEB_VULN}")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4111: through a Virtual whose Remote member scans, the vulnerable .deb is 403 and the clean one 200 clean"
pull "${D}/${DEB_V}/${DEB_VULN}"; s1="$ST/$(body_err)"
pull "${D}/${DEB_V}/${DEB_CLEAN}"
if [ "$s1" = "403/scan_blocked" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$(golden_sha "debian/${DEB_CLEAN}")" ]; then
  pass
else
  fail "vulnerable=${s1} clean=${ST}/${SCAN}"
fi

begin_test "FIX #4111: an ambiguous pool path on a Debian Remote is 400 before any upstream request"
h1=$(hits "/debian/pool/main/o/openssl/")
pull "${D}/${DEB}/pool/main/o/openssl/openssl_3.0.11-1~deb12u2_amd64.deb%3F.dsc"
h2=$(hits "/debian/pool/main/o/openssl/")
if [ "$ST" = "400" ] && [ "$h1" = "$h2" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) upstream GETs ${h1:-?} -> ${h2:-?}"
fi

# ---------------------------------------------------------------------------
# #4112 RPM
# ---------------------------------------------------------------------------
begin_test "FIX #4112: fail_closed pull of openssl-libs 1:3.0.7-17.el9_2 is 403 scan_blocked (graded on RHEL 9)"
pull "${R}/${RPM}/${RPM_VULN}"
d=$(golden_sha "rpm/${RPM_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] \
   && [ "$(body_file)" = "openssl-libs-3.0.7-17.el9_2.x86_64.rpm" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4112: an RPM no advisory names is graded as itself and served 200 X-AK-Scan: clean"
pull "${R}/${RPM}/${RPM_CLEAN}"
d=$(golden_sha "rpm/${RPM_CLEAN}")
c=$(cataloged_of "$d")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "${c:-0}" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "status=${ST} scan='${SCAN}' verdict='$(verdict_of "$d")' cataloged='${c}'"
fi

begin_test "FIX #4112: RPMs whose header disagrees or that carry no dist tag are withheld under fail_closed (423, no verdict row)"
pull "${R}/${RPM}/${RPM_LIAR}"; s1="$ST/$(body_err)"; v1=$(verdict_of "$(golden_sha "rpm/${RPM_LIAR}")")
pull "${R}/${RPM}/${RPM_NOTAG}"; s2="$ST/$(body_err)"; v2=$(verdict_of "$(golden_sha "rpm/${RPM_NOTAG}")")
if [ "$s1 $s2" = "423/scan_pending 423/scan_pending" ] && [ -z "$v1$v2" ]; then
  pass
else
  fail "liar=${s1} notag=${s2} verdicts='${v1}' '${v2}'"
fi

begin_test "FIX #4112: fail_open first pull of the vulnerable RPM is 200 X-AK-Scan: pending (no-store), then 403 once the verdict lands"
psql_q "DELETE FROM proxy_scan_results WHERE checksum_sha256='$(golden_sha "rpm/${RPM_VULN}")'" >/dev/null
pull "${R}/${RPM_FO}/${RPM_VULN}"
s1="$ST/$SCAN"; cc=$(hdr cache-control)
d=$(golden_sha "rpm/${RPM_VULN}")
rpm_vulnerable() { [ "$(verdict_of "$d")" = "vulnerable" ]; }
wait_until "vulnerable verdict for the fail_open RPM" 60 rpm_vulnerable || true
pull "${R}/${RPM_FO}/${RPM_VULN}"
if [ "$s1" = "200/pending" ] && [ "$cc" = "no-store" ] && [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "first=${s1} cache-control='${cc}' second=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4112: through a Virtual whose Remote member scans, the vulnerable RPM is 403 and the clean one 200 clean"
pull "${R}/${RPM_V}/${RPM_VULN}"; s1="$ST/$(body_err)"
pull "${R}/${RPM_V}/${RPM_CLEAN}"
if [ "$s1" = "403/scan_blocked" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$(golden_sha "rpm/${RPM_CLEAN}")" ]; then
  pass
else
  fail "vulnerable=${s1} clean=${ST}/${SCAN}"
fi

begin_test "FIX #4112: an ambiguous path on an RPM Remote is 400 before any upstream request"
h1=$(hits "/rpm/${TREE}/Packages/o/")
pull "${R}/${RPM}/${RPM_VULN}%3F.xml"
h2=$(hits "/rpm/${TREE}/Packages/o/")
if [ "$ST" = "400" ] && [ "$h1" = "$h2" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) upstream GETs ${h1:-?} -> ${h2:-?}"
fi

end_suite
