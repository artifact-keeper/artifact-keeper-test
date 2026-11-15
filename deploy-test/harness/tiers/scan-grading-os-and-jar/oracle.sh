#!/usr/bin/env bash
# =============================================================================
# tiers/scan-grading-os-and-jar/oracle.sh
#   #5236 an Alpine subpackage (libcurl) is graded with its origin's (curl)
#         CPE matches, not passed clean
#   #5262 a JAR is not graded on the dependencies its build POM declares
#         (provided / test scope)
#   #5170 a Debian package is graded on its own suite's release: a version
#         marker that names another release, or a pool file no index lists,
#         is inconclusive (423 under fail_closed), not graded on a borrowed
#         release
#   #5628 a proxy rescan of a release-pinned vulnerable .deb / .rpm does not
#         overwrite the verdict with an unpinned clean one
# See the manifest for the bugs and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the
# mock's published control port), DB_CONTAINER, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test
# that swallows its own failure.

begin_suite "scan-grading-os-and-jar"
auth_admin
setup_workdir
W="$WORK_DIR"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-files.yml).
UP="http://172.16.${DTF_SLOT}.76"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

APK="sgo-apk-${SUF}"       # alpine Remote, fail_closed
DEB="sgo-deb-${SUF}"       # debian Remote, fail_closed
RPM="sgo-rpm-${SUF}"       # rpm Remote, fail_closed
MVN="sgo-mvn-${SUF}"       # maven Remote, fail_closed
DEB_OFF="sgo-deboff-${SUF}" # debian Remote, no scanning (control)
ALL_REPOS="$APK $DEB $RPM $MVN $DEB_OFF"

cleanup() {
  local k
  for k in $ALL_REPOS; do api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true; done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true; }
uri() { jq -rn --arg v "$1" '$v|@uri'; }

BODY="${W}/body"
HDR="${W}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 150 "$1" 2>/dev/null) || ST="000"
  SCAN=$(hdr x-ak-scan)
  BSHA=$(sha_of "$BODY")
}
hdr() { grep -i "^$1:" "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
snippet() { # a JSON body verbatim (truncated); package bytes as their size
  if [ "$(head -c 1 "$1" 2>/dev/null)" = "{" ]; then head -c 200 "$1" | tr -c '[:print:]' '.'; else echo "($(stat -c %s "$1" 2>/dev/null || echo 0) bytes)"; fi
}
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
findings_of() { psql_q "SELECT findings_count FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
scan_cfg() { # key action -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null || true
}
fx() { awk -F'\t' -v p="$1" '$1==p {print $2; exit}' "${W}/fx/files.tsv"; }
fx_sha() { sha_of "$(fx "$1")"; }
RBODY="${W}/rescan"
rescan() { # key path -> sets RST and RBODY
  RST=$(curl -s -o "$RBODY" -w '%{http_code}' --max-time 150 -X POST \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg p "$2" '{path:$p}')" \
    "${BASE_URL}/api/v1/repositories/$1/security/proxy-scans/rescan" 2>/dev/null) || RST="000"
}
rjson() { jq -r "$1 // empty" "$RBODY" 2>/dev/null || true; }
cached_path() { # repo-key suffix -> the proxy cache path ending in suffix
  psql_q "SELECT p.path FROM proxy_cache_artifacts p JOIN repositories r ON r.id = p.repository_id WHERE r.key='$1' AND p.path LIKE '%$2' ORDER BY length(p.path) LIMIT 1"
}

A="${BASE_URL}/alpine"
D="${BASE_URL}/debian"
R="${BASE_URL}/rpm"
M="${BASE_URL}/maven"
APK_CURL="v3.22/main/x86_64/curl-8.14.1-r4.apk"
APK_LIBCURL="v3.22/main/x86_64/libcurl-8.14.1-r4.apk"
DEB_VULN="pool/main/o/openssl/openssl_3.0.11-1~deb12u2_amd64.deb"
DEB_CLEAN="pool/main/d/dtf-gradeclean/dtf-gradeclean_1.0-1_amd64.deb"
DEB_OLDMARK="pool/main/d/dtf-oldmark/dtf-oldmark_1.0-1+deb11u1_amd64.deb"
DEB_UNLISTED="pool/main/d/dtf-unlisted/dtf-unlisted_1.0-1_amd64.deb"
RPM_VULN="9/BaseOS/x86_64/os/Packages/o/openssl-libs-3.0.7-17.el9_2.x86_64.rpm"
JAR_PLUGIN="com/example/dtfgrade/dtf-grade-plugin/1.0.0/dtf-grade-plugin-1.0.0.jar"
JAR_LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"

# =============================================================================
# Setup
# =============================================================================
begin_test "Setup: fixtures built and stored in the mock upstream"
err=""
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"
  end_suite
fi
mkdir -p "${W}/fx"
n=$(python3 -I "${HERE}/fixtures/build_fixtures.py" "${W}/fx" 2>"${W}/fx.err") || n=""
if [ -z "$n" ]; then
  infra_fail "fixture build failed: $(head -c 300 "${W}/fx.err")"
  end_suite
fi
while IFS=$'\t' read -r p f ct; do
  b=$(curl -s --max-time 20 -X PUT --data-binary @"$f" "${MOCK}/__file?path=$(uri "$p")&ctype=$(uri "$ct")" \
        | jq -r '.bytes // empty' 2>/dev/null) || b=""
  [ "$b" = "$(stat -c %s "$f")" ] || err="${err} ${p}"
done < "${W}/fx/files.tsv"
if [ -z "$err" ]; then
  pass
else
  infra_fail "mock PUT failed for:${err}"
  end_suite
fi

begin_test "Setup: fail_closed alpine, debian, rpm and maven Remotes on the mock, plus an unscanned debian Remote"
ok=1
create_repo "$APK" alpine remote "${UP}/alpine" || ok=0
create_repo "$DEB" debian remote "${UP}/debian" || ok=0
create_repo "$DEB_OFF" debian remote "${UP}/debian" || ok=0
create_repo "$RPM" rpm remote "${UP}/rpm" || ok=0
create_repo "$MVN" maven remote "${UP}/maven2" || ok=0
a="$(scan_cfg "$APK" fail_closed) $(scan_cfg "$DEB" fail_closed) $(scan_cfg "$RPM" fail_closed) $(scan_cfg "$MVN" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closed fail_closed fail_closed fail_closed" ]; then
  pass
else
  infra_fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
  end_suite
fi

# apt reads the suite's Release before any package; that is what caches the
# release the Debian gate grades against. No client fetches the Packages
# index here (a client with current lists would not).
begin_test "Setup: apt-style Release fetch through the debian Remotes"
pull "${D}/${DEB}/dists/bookworm/Release"; s1="$ST"
pull "${D}/${DEB_OFF}/dists/bookworm/Release"
if [ "$s1 $ST" = "200 200" ]; then
  pass
else
  infra_fail "Release statuses: ${s1} ${ST}"
  end_suite
fi

# =============================================================================
# Controls (pass on every image)
# =============================================================================
begin_test "CONTROL: the unscanned debian Remote streams every .deb unchanged, no X-AK-Scan"
bad=""
for p in "$DEB_VULN" "$DEB_CLEAN" "$DEB_OLDMARK" "$DEB_UNLISTED"; do
  pull "${D}/${DEB_OFF}/${p}"
  [ "$ST/$SCAN" = "200/" ] && [ "$BSHA" = "$(fx_sha "/debian/${p}")" ] || bad="${bad} ${p##*/}=${ST}/${SCAN}"
done
if [ -z "$bad" ]; then pass; else fail "not streamed:${bad}"; fi

begin_test "CONTROL: Alpine curl 8.14.1-r4 (its own origin) is 403 scan_blocked on v3.22"
pull "${A}/${APK}/${APK_CURL}"
d=$(fx_sha "/alpine/${APK_CURL}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet "$BODY") verdict='$(verdict_of "$d")' findings='$(findings_of "$d")'"
fi

begin_test "CONTROL: log4j-core 2.14.1 is still graded on the components the JAR carries: 403 scan_blocked"
pull "${M}/${MVN}/${JAR_LOG4J}"
d=$(fx_sha "/maven2/${JAR_LOG4J}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet "$BODY") verdict='$(verdict_of "$d")'"
fi

begin_test "CONTROL: an unmarked .deb the bookworm index lists is graded on Debian 12: 200 X-AK-Scan: clean"
pull "${D}/${DEB}/${DEB_CLEAN}"
d=$(fx_sha "/debian/${DEB_CLEAN}")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet "$BODY") verdict='$(verdict_of "$d")'"
fi

begin_test "CONTROL: openssl 3.0.11-1~deb12u2 (listed) is 403 scan_blocked, graded on Debian 12"
pull "${D}/${DEB}/${DEB_VULN}"
DEB_VULN_D=$(fx_sha "/debian/${DEB_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$DEB_VULN_D")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} body=$(snippet "$BODY") verdict='$(verdict_of "$DEB_VULN_D")'"
fi

begin_test "CONTROL: openssl-libs 3.0.7-17.el9_2 is 403 scan_blocked, graded on RHEL 9"
pull "${R}/${RPM}/${RPM_VULN}"
RPM_VULN_D=$(fx_sha "/rpm/${RPM_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$RPM_VULN_D")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} body=$(snippet "$BODY") verdict='$(verdict_of "$RPM_VULN_D")'"
fi

# =============================================================================
# #5236 Alpine subpackage graded with its origin's CPE matches
# =============================================================================
begin_test "FIX #5236: Alpine libcurl 8.14.1-r4 (origin curl) is graded with curl's CPE matches: 403 scan_blocked (was 200 clean, 0 findings)"
pull "${A}/${APK}/${APK_LIBCURL}"
d=$(fx_sha "/alpine/${APK_LIBCURL}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ] \
   && [ "$(findings_of "$d")" -ge 10 ] 2>/dev/null; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet "$BODY") verdict='$(verdict_of "$d")' findings='$(findings_of "$d")'"
fi

# =============================================================================
# #5262 build-POM declarations are not installed dependencies
# =============================================================================
begin_test "FIX #5262: a plugin JAR whose build POM declares maven-core 3.2.5 (provided) and maven-compat 3.2.5 (test) is 200 clean (was 403)"
pull "${M}/${MVN}/${JAR_PLUGIN}"
d=$(fx_sha "/maven2/${JAR_PLUGIN}")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet "$BODY") verdict='$(verdict_of "$d")' findings='$(findings_of "$d")'"
fi

# =============================================================================
# #5170 Debian release identity
# =============================================================================
begin_test "FIX #5170: a .deb in the bookworm index whose version marker (+deb11u1) names Debian 11 is withheld 423 scan_identity_unestablished, not graded"
pull "${D}/${DEB}/${DEB_OLDMARK}"
d=$(fx_sha "/debian/${DEB_OLDMARK}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_identity_unestablished" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' error='$(body_err)' body=$(snippet "$BODY") verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #5170: an unmarked .deb that no index lists is withheld 423 scan_identity_unestablished, not graded on a release borrowed from the cached suite"
pull "${D}/${DEB}/${DEB_UNLISTED}"
d=$(fx_sha "/debian/${DEB_UNLISTED}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_identity_unestablished" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' error='$(body_err)' body=$(snippet "$BODY") verdict='$(verdict_of "$d")'"
fi

# =============================================================================
# #5628 rescan of a release-pinned vulnerable .deb / .rpm
# =============================================================================
# A rescan has no request, so it cannot pin the release: it catalogs the one
# package and matches nothing. Since #5711 it is refused (503
# RESCAN_REQUEST_PINNED, no Retry-After) and the stored verdict and pin stay.
for fmt in deb rpm; do
  if [ "$fmt" = deb ]; then key="$DEB"; dg="$DEB_VULN_D"; suffix="${DEB_VULN##*/}"; else key="$RPM"; dg="$RPM_VULN_D"; suffix="${RPM_VULN##*/}"; fi
  begin_test "FIX #5628: a proxy rescan of the release-pinned vulnerable ${suffix} is refused and keeps the vulnerable verdict (was 200 clean, verdict overwritten)"
  path=$(cached_path "$key" "$suffix")
  pin0=$(psql_q "SELECT coalesce(pin_identity,'') FROM proxy_scan_results WHERE checksum_sha256='${dg}' ORDER BY scanned_at DESC LIMIT 1")
  rescan "$key" "${path:-$suffix}"
  v1=$(verdict_of "$dg")
  pin1=$(psql_q "SELECT coalesce(pin_identity,'') FROM proxy_scan_results WHERE checksum_sha256='${dg}' ORDER BY scanned_at DESC LIMIT 1")
  if [ "$fmt" = deb ]; then pull "${D}/${DEB}/${DEB_VULN}"; else pull "${R}/${RPM}/${RPM_VULN}"; fi
  if [ "$RST" = "503" ] && [ "$(rjson .code)" = "RESCAN_REQUEST_PINNED" ] && [ "$v1" = "vulnerable" ] \
     && [ -n "$pin0" ] && [ "$pin1" = "$pin0" ] && [ "$ST" = "403" ]; then
    pass
  else
    fail "rescan ${path:-?}: HTTP ${RST} code='$(rjson .code)' state='$(rjson .state)' findings='$(rjson .findings_count)'; verdict now '${v1}', pin '${pin0}' -> '${pin1}'; next pull ${ST}"
  fi
done

end_suite
