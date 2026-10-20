#!/usr/bin/env bash
# =============================================================================
# tiers/conda-proxy-scan-grading/oracle.sh - how the conda scan-on-proxy gate
#   grades what Grype catalogs, and what the dashboard counts as blocked
#   (artifact-keeper#4594, #4600, #4582)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda-scan` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH. The mock channel (http://172.16.<slot>.74/) starts empty; the
# oracle builds conda v1 packages with fixtures/build_pkg.py and copies them
# to /srv/noarch/ in the mock. Grype (bundled, seeded DB) does the grading.
#
# Packages (noarch, .tar.bz2):
#   tzdata-2026c-0       data only (share/zoneinfo/...): nothing to catalog
#   dtfwrap-1.0-0        vendors six 1.16.0 (a .dist-info): cataloged as
#                        `six`, never as `dtfwrap`; no advisories
#   dtfwrapvuln-1.0-0    vendors Jinja2 2.10: cataloged as `jinja2`, with
#                        long-published high advisories (CVE-2019-10906, ...)
#   dtfgenvuln-1.0-0     same vendored Jinja2, distinct bytes: the #4582 digest
#
# Repositories (keys suffixed per run):
#   CR  conda Remote, scan_on_proxy, fail_closed, block at >= high
#   CG  conda Remote, same policy: scans dtfgenvuln once, then scanning off
#   GR  generic Remote on the same mock, scan_on_proxy stored (generic does
#       not run the gate): caches the dtfgenvuln bytes whose digest carries
#       a vulnerable verdict
#   CP  conda Remote, no scanning
#
# Gates (RED on 1.10.0, where nothing is scanned; each CONTROL holds on both):
#   #4594  tzdata: 200 X-AK-Scan: clean, byte-exact, a `clean` verdict row with
#          components_cataloged = 0, the proxy-scans view says so, and a second
#          pull is served from that verdict with no second upstream fetch.
#   #4600  dtfwrap: 200 X-AK-Scan: clean, components_cataloged >= 1.
#          dtfwrapvuln: 403 scan_blocked, a `vulnerable` row with findings and
#          components_cataloged >= 1; a repeat pull is refused from the verdict.
#   #4582  policy_violations_blocked equals the gated Remote's blocked digests
#          (1: dtfwrapvuln) and does not move when the generic Remote caches
#          bytes whose digest is vulnerable.
#   CONTROL  the unscanned conda Remote and the generic Remote both serve the
#          vulnerable bytes byte-exact (scanning is opt-in and per format).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below must survive a non-2xx or a
# non-JSON body (the baseline image answers both), so evaluate them explicitly.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
MOCK="ak-dtf${SLOT}-mock-conda-scan"
UPSTREAM="http://172.16.${SLOT}.74/"

CR="cpg-scan-${SUF}"
CG="cpg-gate-${SUF}"
GR="cpg-gen-${SUF}"
CP="cpg-plain-${SUF}"

TZ="tzdata-2026c-0.tar.bz2"
WRAP="dtfwrap-1.0-0.tar.bz2"
WVULN="dtfwrapvuln-1.0-0.tar.bz2"
GVULN="dtfgenvuln-1.0-0.tar.bz2"

WORK="$(mktemp -d -t dtf-cpg-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null
}
sha_of() { sha256sum "$1" | awk '{print $1}'; }

# cget <path> <name>: anonymous GET; body in $WORK/<name>, headers in
# $WORK/<name>.h; echoes the status.
cget() {
  curl -s --max-time 120 -o "$WORK/$2" -D "$WORK/$2.h" -w '%{http_code}' "${BASE_URL}$1" 2>/dev/null || echo 000
}
xscan() { grep -i '^x-ak-scan:' "$WORK/$1.h" 2>/dev/null | head -1 | cut -d: -f2- | tr -d ' \r'; }
upstream_hits() { docker logs "$MOCK" 2>&1 | grep -c "GET /noarch/$1 "; }

# verdict_row <file>: "verdict|components_cataloged|findings_count" for the
# digest of the package bytes we built.
verdict_row() {
  psql_q "SELECT verdict || '|' || coalesce(components_cataloged::text, 'null') || '|' || findings_count FROM proxy_scan_results WHERE checksum_sha256 = '$(sha_of "$WORK/pkgs/$1")' AND scan_type = 'grype'"
}

scan_config() {  # scan_config <repo> <json>
  curl -s --max-time 30 -o "$WORK/sc.out" -w '%{http_code}' -X PUT -H "$(auth_header)" \
    -H 'Content-Type: application/json' -d "$2" \
    "${BASE_URL}/api/v1/repositories/$1/security" 2>/dev/null || echo 000
}
GATE='{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed","block_on_policy_violation":true,"severity_threshold":"high"}'

blocked_count() {
  curl -s --max-time 30 -H "$(auth_header)" "${BASE_URL}/api/v1/security/dashboard" 2>/dev/null \
    | jq -r '.policy_violations_blocked // empty' 2>/dev/null
}

begin_suite "conda-proxy-scan-grading (#4594 #4600 #4582)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: packages built and served by the mock, remotes configured"
auth_admin
setup_err=""
B="${HERE}/fixtures/build_pkg.py"
JINJA='site-packages/Jinja2-2.10.dist-info/METADATA=Metadata-Version: 2.1\nName: Jinja2\nVersion: 2.10\n'
SIX='site-packages/six-1.16.0.dist-info/METADATA=Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n'
{
  python3 -I "$B" "$WORK/pkgs" tzdata 2026c 0 'share/zoneinfo/DTF/Zone=TZif2 dtf zone data\n' \
    && python3 -I "$B" "$WORK/pkgs" dtfwrap 1.0 0 "$SIX" \
    && python3 -I "$B" "$WORK/pkgs" dtfwrapvuln 1.0 0 "$JINJA" \
    && python3 -I "$B" "$WORK/pkgs" dtfgenvuln 1.0 0 "$JINJA" 'share/dtfgenvuln/marker=generic\n'
} >/dev/null 2>"$WORK/build.err" || setup_err+="build packages: $(head -c 200 "$WORK/build.err"); "
docker exec "$MOCK" mkdir -p /srv/noarch >/dev/null 2>&1 || setup_err+="mkdir in mock; "
for f in "$TZ" "$WRAP" "$WVULN" "$GVULN"; do
  docker cp "$WORK/pkgs/$f" "${MOCK}:/srv/noarch/$f" >/dev/null 2>&1 || setup_err+="copy ${f} to mock; "
done
create_repo "$CR" conda remote "$UPSTREAM" || setup_err+="create ${CR}; "
create_repo "$CG" conda remote "$UPSTREAM" || setup_err+="create ${CG}; "
create_repo "$GR" generic remote "$UPSTREAM" || setup_err+="create ${GR}; "
create_repo "$CP" conda remote "$UPSTREAM" || setup_err+="create ${CP}; "
for r in "$CR" "$CG" "$GR"; do
  st="$(scan_config "$r" "$GATE")"
  [ "$st" = "200" ] || setup_err+="scan config ${r} HTTP ${st}: $(head -c 200 "$WORK/sc.out"); "
done
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# CONTROL - scanning is opt-in and per format
# =============================================================================
begin_test "CONTROL: an unscanned conda Remote serves the vulnerable package byte-exact"
st="$(cget "/conda/${CP}/noarch/${WVULN}" cp_wvuln)"
if [ "$st" = "200" ] && cmp -s "$WORK/cp_wvuln" "$WORK/pkgs/$WVULN"; then
  pass
else
  fail "unscanned conda Remote did not stream the package" "HTTP ${st}: $(head -c 200 "$WORK/cp_wvuln" | tr -d '\0')"
fi

# =============================================================================
# #4594 - nothing cataloged is graded clean on contents
# =============================================================================
begin_test "#4594: a data-only package under fail_closed is served clean, stored with components_cataloged = 0"
st="$(cget "/conda/${CR}/noarch/${TZ}" tz1)"
row="$(verdict_row "$TZ")"
if [ "$st" = "200" ] && [ "$(xscan tz1)" = "clean" ] && cmp -s "$WORK/tz1" "$WORK/pkgs/$TZ" \
   && [ "$row" = "clean|0|0" ]; then
  pass
else
  fail "data-only conda package not graded clean" \
    "HTTP ${st} X-AK-Scan=$(xscan tz1) body=$(head -c 160 "$WORK/tz1" | tr -d '\0'); verdict row=${row:-none}"
fi

begin_test "#4594: the second pull reuses the stored verdict (no upstream re-fetch) and the proxy-scans view reports components_cataloged = 0"
st="$(cget "/conda/${CR}/noarch/${TZ}" tz2)"
hits="$(upstream_hits "$TZ")"
vst="$(curl -s --max-time 30 -o "$WORK/view.json" -w '%{http_code}' -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${CR}/security/proxy-scans?path=noarch/${TZ}" 2>/dev/null || echo 000)"
if [ "$st" = "200" ] && [ "$(xscan tz2)" = "clean" ] && [ "$hits" = "1" ] && [ "$vst" = "200" ] \
   && jq -e --arg p "noarch/${TZ}" \
        'any(.items[]; .path == $p and .state == "clean" and .components_cataloged == 0)' \
        "$WORK/view.json" >/dev/null 2>&1; then
  pass
else
  fail "stored clean verdict not reused / not reported" \
    "HTTP ${st} X-AK-Scan=$(xscan tz2); upstream GETs=${hits} (want 1); view HTTP ${vst}: $(head -c 400 "$WORK/view.json")"
fi

# =============================================================================
# #4600 - a vendored-only catalog is graded on findings
# =============================================================================
begin_test "#4600: a package cataloged only under a vendored name, with no advisories, is served clean (components_cataloged >= 1)"
st="$(cget "/conda/${CR}/noarch/${WRAP}" wrap)"
row="$(verdict_row "$WRAP")"
if [ "$st" = "200" ] && [ "$(xscan wrap)" = "clean" ] && cmp -s "$WORK/wrap" "$WORK/pkgs/$WRAP" \
   && [[ "$row" =~ ^clean\|[1-9][0-9]*\|0$ ]]; then
  pass
else
  fail "vendored-only catalog not graded clean" \
    "HTTP ${st} X-AK-Scan=$(xscan wrap) body=$(head -c 200 "$WORK/wrap" | tr -d '\0'); verdict row=${row:-none}"
fi

begin_test "#4600: a package vendoring a vulnerable component is refused 403 scan_blocked, and the repeat pull is refused from the verdict"
st="$(cget "/conda/${CR}/noarch/${WVULN}" wv1)"
st2="$(cget "/conda/${CR}/noarch/${WVULN}" wv2)"
row="$(verdict_row "$WVULN")"
hits="$(upstream_hits "$WVULN")"
# CP fetched it once for the CONTROL; CR must add exactly one more.
if [ "$st" = "403" ] && jq -e --arg f "$WVULN" '.error == "scan_blocked" and .file == $f' "$WORK/wv1" >/dev/null 2>&1 \
   && [ "$st2" = "403" ] && [[ "$row" =~ ^vulnerable\|[1-9][0-9]*\|[1-9][0-9]*$ ]] && [ "$hits" = "2" ]; then
  pass
else
  fail "vulnerable vendored component not blocked" \
    "first HTTP ${st}: $(head -c 200 "$WORK/wv1" | tr -d '\0'); repeat HTTP ${st2}; verdict row=${row:-none}; upstream GETs=${hits} (want 2)"
fi

# =============================================================================
# #4582 - the dashboard counts only what a gated format refuses
# =============================================================================
begin_test "#4582: policy_violations_blocked counts the gated Remote's blocked digest and ignores a generic Remote caching a vulnerable digest"
st_g="$(cget "/conda/${CG}/noarch/${GVULN}" gv_conda)"
cfg="$(scan_config "$CG" '{"scan_enabled":false,"scan_on_proxy":false,"proxy_scan_action":"fail_closed"}')"
c1="$(blocked_count)"
st_r="$(cget "/api/v1/repositories/${GR}/download/noarch/${GVULN}" gv_gen)"
gen_cached="$(psql_q "SELECT count(*) FROM proxy_cache_artifacts pca JOIN repositories r ON r.id = pca.repository_id WHERE r.key = '${GR}' AND pca.checksum_sha256 = '$(sha_of "$WORK/pkgs/$GVULN")'")"
gv_row="$(verdict_row "$GVULN")"
c2="$(blocked_count)"
if [ "$st_r" != "200" ] || ! cmp -s "$WORK/gv_gen" "$WORK/pkgs/$GVULN"; then
  fail "CONTROL: the generic Remote did not serve the bytes" "HTTP ${st_r}: $(head -c 200 "$WORK/gv_gen" | tr -d '\0')"
elif [ "$st_g" = "403" ] && [ "$cfg" = "200" ] && [ "${gv_row%%|*}" = "vulnerable" ] && [ "$gen_cached" = "1" ] \
     && [ "$c1" = "1" ] && [ "$c2" = "1" ]; then
  pass
else
  fail "policy_violations_blocked does not track the gate" \
    "gated pull of ${GVULN} HTTP ${st_g}; verdict=${gv_row:-none}; generic cache rows=${gen_cached}; count with only ${CR} gating=${c1:-none} (want 1); after the generic Remote cached the vulnerable digest=${c2:-none} (want 1)"
fi

end_suite
