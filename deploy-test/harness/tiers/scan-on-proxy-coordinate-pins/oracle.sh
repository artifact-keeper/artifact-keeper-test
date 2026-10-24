#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-proxy-coordinate-pins/oracle.sh - a proxied Go module,
# Composer package or Conan reference is graded as the coordinate requested
# =============================================================================
# artifact-keeper 1.12.0: #4952, epic #4097. The Go, Composer and Conan scan
# gates check the archive against the request, then scan it. The bundled
# engine does not catalog a module zip, a dist or a Conan archive as itself,
# so until #4952 only what the archive bundled was graded. Now the scan
# workspace also carries a pin for the request coordinate.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH.
#
# Fixtures (scan-on-proxy-maven-nuget/fixtures/mock_scan_upstream.py), each
# the vulnerable coordinate as its own archive with nothing vulnerable inside:
#   Go        golang.org/x/text v0.3.0 (go.mod requires nothing)
#   Composer  guzzlehttp/guzzle 6.5.0 (no composer.lock)
#   Conan     openssl/1.1.1k conan_sources.tgz (conanfile.txt requires nothing)
# and the clean controls example.com/dtfscan/cleanmod, dtf/cleanpkg, dtfclean.
#
# Green: an image carrying #4952. Red: ak-backend:1.11.5.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "scan-on-proxy-coordinate-pins"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

GO="sopp-go-${SUF}"
GO_OFF="sopp-gooff-${SUF}"
CMP="sopp-cmp-${SUF}"
CON="sopp-con-${SUF}"

GO_TEXT="golang.org/x/text/@v/v0.3.0.zip"
GO_CLEAN="example.com/dtfscan/cleanmod/@v/v1.0.0.zip"
REF="0123456789abcdef0123456789abcdef01234567"
CMP_GUZZLE="dist/guzzlehttp/guzzle/6.5.0/${REF}.zip"
CMP_CLEAN="dist/dtf/cleanpkg/1.0.0/${REF}.zip"
RREV="0123456789abcdef0123456789abcdef"
CON_OPENSSL="v2/conans/openssl/1.1.1k/_/_/revisions/${RREV}/files/conan_sources.tgz"
CON_CLEAN="v2/conans/dtfclean/1.0.0/_/_/revisions/${RREV}/files/conan_sources.tgz"

cleanup() {
  local k
  for k in "$GO" "$GO_OFF" "$CMP" "$CON"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }

BODY="${WORK_DIR}/body"
HDR="${WORK_DIR}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 120 "$1" 2>/dev/null) || ST="000"
  SCAN=$(hdr x-ak-scan)
  BSHA=$(sha256sum "$BODY" 2>/dev/null | cut -d' ' -f1)
}
hdr() { grep -i "^$1:" "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
snippet() { head -c 200 "$BODY" | tr -c '[:print:]' '.'; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
cataloged_of() { psql_q "SELECT components_cataloged FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
scan_cfg() {
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}

begin_test "Setup: mock upstream reachable and the coordinate fixtures present"
if [ -n "$(golden_sha "goproxy/${GO_TEXT}")" ] && [ -n "$(golden_sha "composer/zipball/guzzle.zip")" ] \
   && [ -n "$(golden_sha "conan/${CON_OPENSSL}")" ]; then
  pass
else
  fail "mock control endpoint ${MOCK} did not answer (or this mock predates the #4952 fixtures)"
fi

begin_test "Setup: fail_closed Go, Composer and Conan Remotes, and an unscanned Go Remote"
ok=1
create_repo "$GO" go remote "${UP}/goproxy" || ok=0
create_repo "$GO_OFF" go remote "${UP}/goproxy" || ok=0
create_repo "$CMP" composer remote "${UP}/composer" || ok=0
create_repo "$CON" conan remote "${UP}/conan" || ok=0
a="$(scan_cfg "$GO" fail_closed) $(scan_cfg "$CMP" fail_closed) $(scan_cfg "$CON" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closed fail_closed fail_closed" ]; then
  pass
else
  fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
fi

begin_test "control: a Remote WITHOUT scan_on_proxy streams the golang.org/x/text v0.3.0 zip unchanged, no X-AK-Scan"
pull "${BASE_URL}/go/${GO_OFF}/${GO_TEXT}"
if [ "$ST/$SCAN" = "200/" ] && [ "$BSHA" = "$(golden_sha "goproxy/${GO_TEXT}")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}'"
fi

begin_test "FIX #4952: the golang.org/x/text v0.3.0 module zip, which requires nothing, is 403 scan_blocked"
pull "${BASE_URL}/go/${GO}/${GO_TEXT}"
d=$(golden_sha "goproxy/${GO_TEXT}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")' (graded on contents only, it reads clean)"
fi

begin_test "FIX #4952: the guzzlehttp/guzzle 6.5.0 dist, which bundles no lockfile, is 403 scan_blocked"
pull "${BASE_URL}/composer/${CMP}/${CMP_GUZZLE}"
d=$(golden_sha "composer/zipball/guzzle.zip")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4952: the openssl/1.1.1k Conan archive, which requires nothing, is 403 scan_blocked"
pull "${BASE_URL}/conan/${CON}/${CON_OPENSSL}"
d=$(golden_sha "conan/${CON_OPENSSL}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4952: clean module, dist and Conan archives are 200 X-AK-Scan: clean with the pin cataloged"
res=""
for spec in "go/${GO}/${GO_CLEAN}|goproxy/${GO_CLEAN}" \
            "composer/${CMP}/${CMP_CLEAN}|composer/zipball/cleanpkg.zip" \
            "conan/${CON}/${CON_CLEAN}|conan/${CON_CLEAN}"; do
  url="${spec%%|*}"; golden="${spec##*|}"
  pull "${BASE_URL}/${url}"
  d=$(golden_sha "$golden")
  c=$(cataloged_of "$d")
  if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "${c:-0}" -ge 1 ] 2>/dev/null; then
    res="${res}y"
  else
    res="${res}n(${url%%/*}:${ST}/${SCAN}/cataloged=${c})"
  fi
done
if [ "$res" = "yyy" ]; then
  pass
else
  fail "results: ${res} (without the pin a clean Go zip or dist catalogs 0 components)"
fi

end_suite
