#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-proxy-go-rubygems-composer/oracle.sh - the scan-on-proxy gate
# on proxied Go module zips, RubyGems .gem files and Composer dist archives,
# Remote and Virtual
# =============================================================================
# artifact-keeper 1.12.0: #4103 (Go), #4104 (RubyGems), #4105 (Composer),
# epic #4097. Before them the three download handlers streamed a Remote's
# package straight through even with scan_on_proxy=true, and
# `GET /api/v1/formats` reported them `accepted`. They now go through
# proxy_helpers::serve_scanned_proxy_file:
#   * RubyGems: the gem the file name names, which its gemspec must declare,
#     is the scan's pin, so the engine grades that gem itself.
#   * Go and Composer: the archive must be the requested module / package
#     (zip entries under `{module}@{version}/` and a matching `go.mod`; a
#     `composer.json` naming the package), and is then graded on its
#     contents (the go.mod requirements, a bundled composer.lock).
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH. Verdicts come from the backend
# image's bundled Grype and its pre-seeded DB; nothing leaves the host.
#
# Fixtures (scan-on-proxy-maven-nuget/fixtures/mock_scan_upstream.py):
#   Go        example.com/dtfscan/vulnmod v1.0.0 (requires golang.org/x/text
#             v0.3.0), cleanmod v1.0.0, liarmod v2.0.0 (entries are @v1.0.0/)
#   RubyGems  rack 2.0.7, dtf-scanclean 1.0.0, dtf-scanliar 2.0.0 (gemspec
#             says 1.0.0)
#   Composer  dtf/vulnpkg (bundled composer.lock with guzzlehttp/guzzle
#             6.5.0), dtf/cleanpkg, dtf/liarpkg (composer.json names other/pkg)
#
# Green: an image carrying #4103-#4105. Red: ak-backend:1.11.5 (every FIX
# case; every control passes on both).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test, so
# a failed grep or curl must never end the run before end_suite.

begin_suite "scan-on-proxy-go-rubygems-composer"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

GO="sopa-go-${SUF}"         # Go Remote, fail_closed
GO_FO="sopa-gofo-${SUF}"    # Go Remote, fail_open
GO_OFF="sopa-gooff-${SUF}"  # Go Remote, no scanning (control)
GO_M="sopa-gom-${SUF}"      # Go Remote member of GO_V, fail_closed
GO_V="sopa-gov-${SUF}"      # Go Virtual over GO_M
GEM="sopa-gem-${SUF}"       # RubyGems Remote, fail_closed
GEM_RO="sopa-gemro-${SUF}"  # RubyGems Remote, record_only
GEM_OFF="sopa-gemoff-${SUF}" # RubyGems Remote, no scanning (control)
GEM_M="sopa-gemm-${SUF}"    # RubyGems Remote member of GEM_V, fail_closed
GEM_V="sopa-gemv-${SUF}"    # RubyGems Virtual over GEM_M
CMP="sopa-cmp-${SUF}"       # Composer Remote, fail_closed
CMP_OFF="sopa-cmpoff-${SUF}" # Composer Remote, no scanning (control)
CMP_M="sopa-cmpm-${SUF}"    # Composer Remote member of CMP_V, fail_closed
CMP_V="sopa-cmpv-${SUF}"    # Composer Virtual over CMP_M

GO_VULN="example.com/dtfscan/vulnmod/@v/v1.0.0.zip"
GO_CLEAN="example.com/dtfscan/cleanmod/@v/v1.0.0.zip"
GO_LIAR="example.com/dtfscan/liarmod/@v/v2.0.0.zip"
GO_MOD="example.com/dtfscan/vulnmod/@v/v1.0.0.mod"
RACK="gems/rack-2.0.7.gem"
GEM_CLEAN="gems/dtf-scanclean-1.0.0.gem"
GEM_LIAR="gems/dtf-scanliar-2.0.0.gem"
REF="0123456789abcdef0123456789abcdef01234567"
CMP_VULN="dist/dtf/vulnpkg/1.0.0/${REF}.zip"
CMP_CLEAN="dist/dtf/cleanpkg/1.0.0/${REF}.zip"
CMP_LIAR="dist/dtf/liarpkg/1.0.0/${REF}.zip"

cleanup() {
  local k
  for k in "$GO_V" "$GEM_V" "$CMP_V" "$GO_M" "$GEM_M" "$CMP_M" "$GO" "$GO_FO" "$GO_OFF" \
           "$GEM" "$GEM_RO" "$GEM_OFF" "$CMP" "$CMP_OFF"; do
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
begin_test "Setup: mock upstream reachable and the Go, RubyGems and Composer fixtures present"
if [ -n "$(golden_sha "goproxy/${GO_VULN}")" ] && [ -n "$(golden_sha "rubygems/${RACK}")" ] \
   && [ -n "$(golden_sha "composer/zipball/vulnpkg.zip")" ]; then
  pass
else
  fail "mock control endpoint ${MOCK} did not answer (or this mock predates the Go/RubyGems/Composer fixtures)"
fi

begin_test "Setup: Remotes (fail_closed, fail_open, record_only, unscanned) and a Virtual per format"
ok=1
for k in "$GO" "$GO_FO" "$GO_OFF" "$GO_M"; do create_repo "$k" go remote "${UP}/goproxy" || ok=0; done
for k in "$GEM" "$GEM_RO" "$GEM_OFF" "$GEM_M"; do create_repo "$k" rubygems remote "${UP}/rubygems" || ok=0; done
for k in "$CMP" "$CMP_OFF" "$CMP_M"; do create_repo "$k" composer remote "${UP}/composer" || ok=0; done
create_repo "$GO_V" go virtual || ok=0
create_repo "$GEM_V" rubygems virtual || ok=0
create_repo "$CMP_V" composer virtual || ok=0
api_post "/api/v1/repositories/${GO_V}/members" "{\"member_key\":\"${GO_M}\"}" >/dev/null 2>&1 || ok=0
api_post "/api/v1/repositories/${GEM_V}/members" "{\"member_key\":\"${GEM_M}\"}" >/dev/null 2>&1 || ok=0
api_post "/api/v1/repositories/${CMP_V}/members" "{\"member_key\":\"${CMP_M}\"}" >/dev/null 2>&1 || ok=0
a="$(scan_cfg "$GO" fail_closed) $(scan_cfg "$GO_FO" fail_open) $(scan_cfg "$GO_M" fail_closed)"
a="$a $(scan_cfg "$GEM" fail_closed) $(scan_cfg "$GEM_RO" record_only) $(scan_cfg "$GEM_M" fail_closed)"
a="$a $(scan_cfg "$CMP" fail_closed) $(scan_cfg "$CMP_M" fail_closed)"
want="fail_closed fail_open fail_closed fail_closed record_only fail_closed fail_closed fail_closed"
if [ "$ok" = 1 ] && [ "$a" = "$want" ]; then
  pass
else
  fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
fi

G="${BASE_URL}/go"
R="${BASE_URL}/gems"
P="${BASE_URL}/composer"

# ---------------------------------------------------------------------------
# Controls (pass on every image)
# ---------------------------------------------------------------------------
begin_test "control: Remotes WITHOUT scan_on_proxy stream the vulnerable module zip, gem and dist unchanged, no X-AK-Scan"
pull "${G}/${GO_OFF}/${GO_VULN}"; s1="$ST/$SCAN"; ok1=$([ "$BSHA" = "$(golden_sha "goproxy/${GO_VULN}")" ] && echo y)
pull "${R}/${GEM_OFF}/${RACK}"; s2="$ST/$SCAN"; ok2=$([ "$BSHA" = "$(golden_sha "rubygems/${RACK}")" ] && echo y)
pull "${P}/${CMP_OFF}/${CMP_VULN}"; s3="$ST/$SCAN"; ok3=$([ "$BSHA" = "$(golden_sha "composer/zipball/vulnpkg.zip")" ] && echo y)
if [ "$s1 $s2 $s3" = "200/ 200/ 200/" ] && [ "$ok1$ok2$ok3" = "yyy" ]; then
  pass
else
  fail "go=${s1} gem=${s2} composer=${s3} bytes-match='${ok1}${ok2}${ok3}'"
fi

begin_test "control: metadata through the fail_closed Remotes is not gated (go.mod, p2 metadata: 200, no X-AK-Scan)"
pull "${G}/${GO}/${GO_MOD}"; s1="$ST/$SCAN"
pull "${P}/${CMP}/p2/dtf/vulnpkg.json"; s2="$ST/$SCAN"
dist=$(jq -r '.packages["dtf/vulnpkg"][0].dist.url // empty' "$BODY" 2>/dev/null || true)
if [ "$s1 $s2" = "200/ 200/" ] && [[ "$dist" == *"/composer/${CMP}/dist/dtf/vulnpkg/"* ]]; then
  pass
else
  fail "go.mod=${s1} p2=${s2} dist.url='${dist}'"
fi

begin_test "control: GET /api/v1/formats lists the go, rubygems and composer handlers"
FMT="${WORK_DIR}/formats.json"
api_get "/api/v1/formats" > "$FMT" 2>/dev/null || true
fmt_field() { jq -r --arg k "$1" --arg f "$2" '[(if type == "array" then . else .items end)[] | select(.format_key==$k)][0][$f] // empty' "$FMT" 2>/dev/null || true; }
if [ "$(fmt_field go format_key) $(fmt_field rubygems format_key) $(fmt_field composer format_key)" = "go rubygems composer" ]; then
  pass
else
  fail "formats: $(head -c 200 "$FMT")"
fi

# ---------------------------------------------------------------------------
# The formats capability
# ---------------------------------------------------------------------------
begin_test "FIX #4103-#4105: /api/v1/formats reports go, rubygems and composer scan_on_proxy=enforced (helm stays accepted)"
got="$(fmt_field go scan_on_proxy) $(fmt_field rubygems scan_on_proxy) $(fmt_field composer scan_on_proxy) $(fmt_field helm scan_on_proxy)"
if [ "$got" = "enforced enforced enforced accepted" ]; then
  pass
else
  fail "go rubygems composer helm = '${got}' (1.11.x: accepted accepted accepted accepted)"
fi

# ---------------------------------------------------------------------------
# #4103 Go
# ---------------------------------------------------------------------------
begin_test "FIX #4103: fail_closed pull of a module zip requiring golang.org/x/text v0.3.0 is 403 scan_blocked"
pull "${G}/${GO}/${GO_VULN}"
d=$(golden_sha "goproxy/${GO_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(body_file)" = "v1.0.0.zip" ] \
   && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4103: a module zip with no vulnerable content is 200 X-AK-Scan: clean, and the second pull reuses the verdict and cache"
pull "${G}/${GO}/${GO_CLEAN}"
s1="$ST/$SCAN"; b1="$BSHA"
d=$(golden_sha "goproxy/${GO_CLEAN}")
h1=$(hits "/goproxy/${GO_CLEAN}")
pull "${G}/${GO}/${GO_CLEAN}"
h2=$(hits "/goproxy/${GO_CLEAN}")
if [ "$s1" = "200/clean" ] && [ "$b1" = "$d" ] && [ "$ST/$SCAN" = "200/clean" ] \
   && [ "$(verdict_of "$d")" = "clean" ] && [ "$(verdict_rows "$d")" = "1" ] && [ "$h1" = "$h2" ]; then
  pass
else
  fail "first=${s1} second=${ST}/${SCAN} verdict='$(verdict_of "$d")' rows=$(verdict_rows "$d") upstream GETs ${h1:-?} -> ${h2:-?}"
fi

begin_test "FIX #4103: a zip that is not the requested module version is withheld under fail_closed (423, no verdict row)"
pull "${G}/${GO}/${GO_LIAR}"
d=$(golden_sha "goproxy/${GO_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4103: fail_open first pull of the vulnerable zip is 200 X-AK-Scan: pending (no-store), then 403 once the async verdict lands"
# The fail_closed Remote above already recorded this digest's verdict; the
# fail_open Remote shares it (verdicts are per digest), so clear it first to
# see the fail-open first pull.
psql_q "DELETE FROM proxy_scan_results WHERE checksum_sha256='$(golden_sha "goproxy/${GO_VULN}")'" >/dev/null
pull "${G}/${GO_FO}/${GO_VULN}"
s1="$ST/$SCAN"; cc=$(hdr cache-control)
d=$(golden_sha "goproxy/${GO_VULN}")
go_vulnerable() { [ "$(verdict_of "$d")" = "vulnerable" ]; }
wait_until "vulnerable verdict for the fail_open module zip" 60 go_vulnerable || true
pull "${G}/${GO_FO}/${GO_VULN}"
if [ "$s1" = "200/pending" ] && [ "$cc" = "no-store" ] && [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "first=${s1} cache-control='${cc}' second=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4103: through a Virtual whose Remote member scans, the vulnerable zip is 403 and the clean one 200 clean"
pull "${G}/${GO_V}/${GO_VULN}"; s1="$ST/$(body_err)"
pull "${G}/${GO_V}/${GO_CLEAN}"
if [ "$s1" = "403/scan_blocked" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$(golden_sha "goproxy/${GO_CLEAN}")" ]; then
  pass
else
  fail "vulnerable=${s1} clean=${ST}/${SCAN}"
fi

# ---------------------------------------------------------------------------
# #4104 RubyGems
# ---------------------------------------------------------------------------
begin_test "FIX #4104: fail_closed pull of rack-2.0.7.gem is 403 scan_blocked with a 'vulnerable' verdict"
pull "${R}/${GEM}/${RACK}"
d=$(golden_sha "rubygems/${RACK}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(body_file)" = "rack-2.0.7.gem" ] \
   && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4104: a gem no advisory names is graded as itself and served 200 X-AK-Scan: clean"
pull "${R}/${GEM}/${GEM_CLEAN}"
d=$(golden_sha "rubygems/${GEM_CLEAN}")
cataloged=$(psql_q "SELECT components_cataloged FROM proxy_scan_results WHERE checksum_sha256='${d}' ORDER BY scanned_at DESC LIMIT 1")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ] && [ "${cataloged:-0}" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "status=${ST} scan='${SCAN}' verdict='$(verdict_of "$d")' components_cataloged='${cataloged}' (the pin must be cataloged)"
fi

begin_test "FIX #4104: a gem whose gemspec declares another version is withheld under fail_closed (423, no verdict row)"
pull "${R}/${GEM}/${GEM_LIAR}"
d=$(golden_sha "rubygems/${GEM_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4104: record_only serves rack-2.0.7.gem with X-AK-Scan: recorded (verdict kept, not enforced)"
pull "${R}/${GEM_RO}/${RACK}"
if [ "$ST" = "200" ] && [ "$SCAN" = "recorded" ] && [ "$BSHA" = "$(golden_sha "rubygems/${RACK}")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4104: through a Virtual whose Remote member scans, rack-2.0.7.gem is 403 scan_blocked"
pull "${R}/${GEM_V}/${RACK}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

# ---------------------------------------------------------------------------
# #4105 Composer
# ---------------------------------------------------------------------------
begin_test "FIX #4105: fail_closed pull of a dist bundling guzzlehttp/guzzle 6.5.0 is 403 scan_blocked"
pull "${P}/${CMP}/${CMP_VULN}"
d=$(golden_sha "composer/zipball/vulnpkg.zip")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(body_file)" = "vulnpkg-1.0.0.zip" ] \
   && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4105: a dist with no vulnerable content is 200 X-AK-Scan: clean"
pull "${P}/${CMP}/${CMP_CLEAN}"
d=$(golden_sha "composer/zipball/cleanpkg.zip")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' verdict='$(verdict_of "$d")' body=$(snippet)"
fi

begin_test "FIX #4105: a dist whose composer.json names another package is withheld under fail_closed (423, no verdict row)"
pull "${P}/${CMP}/${CMP_LIAR}"
d=$(golden_sha "composer/zipball/liarpkg.zip")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4105: through a Virtual whose Remote member scans, the vulnerable dist is 403 scan_blocked"
pull "${P}/${CMP_V}/${CMP_VULN}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

end_suite
