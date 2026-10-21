#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-proxy-conda-and-content/oracle.sh - the conda scan-on-proxy
#   gate and the conda content facts the 1.11.0 content epic persists and
#   enforces (artifact-keeper#4585, #4041, #4042/#4088/#4089, #4058, #4556,
#   #4516)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda-scan` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH. The mock channel (http://172.16.<slot>.74/) starts empty; the
# oracle builds conda v1 packages with the conda-proxy-scan-grading builder
# and copies the proxied ones to /srv/noarch/ in the mock. Grype (bundled,
# seeded DB) does the grading.
#
# Proxied packages (in the mock):
#   jinja2-2.10-0       vendors Jinja2 2.10 (high advisories): vulnerable
#   six-1.16.0-0        vendors six 1.16.0: clean
#   requests-2.31.0-0   bytes whose info/index.json says evil 6.6.6: the file
#                       name's identity is not backed by the package
# Hosted packages (uploaded):
#   dtfarch-2.0-h1      linux-64 AND osx-64 builds (two identities)
#   dtfnoarch-1.0-0     noarch
#   py-opencv-4.5.0     noarch python, aliased to PyPI opencv-python
#   dtfpyonly-1.0       noarch python, no PyPI mapping
#   dtfgpl-1.0-0        index.json license GPL-3.0-only
#   dtfmit-1.0-0        index.json license MIT
#
# Repositories (keys suffixed per run):
#   CR  conda Remote -> mock, scan_on_proxy fail_closed, block at >= high
#   CV  conda Virtual, member CR
#   CP  conda Remote -> mock, no scanning (CONTROL)
#   H   hosted conda, scan_on_upload: identity / inventory cases
#   L   hosted conda, scan_on_upload + policy denied_licenses=[gpl-3.0-only]
#   ST  staging conda -> RL local conda, same license policy (promotion)
#
# RED on 1.10.0 for every fix case; CONTROLs hold on both images.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"
: "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below must survive a non-2xx or a
# non-JSON body (the baseline image answers both), so evaluate them explicitly.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
MOCK="ak-dtf${SLOT}-mock-conda-scan"
UPSTREAM="http://172.16.${SLOT}.74/"
BUILDER="${DTF_DIR}/harness/tiers/conda-proxy-scan-grading/fixtures/build_pkg.py"

CR="spc-scan-${SUF}"
CV="spc-virt-${SUF}"
CP="spc-plain-${SUF}"
H="spc-host-${SUF}"
L="spc-lic-${SUF}"
ST="spc-stage-${SUF}"
RL="spc-rel-${SUF}"

VULN="jinja2-2.10-0.tar.bz2"
CLEAN="six-1.16.0-0.tar.bz2"
LIAR="requests-2.31.0-0.tar.bz2"
ARCH="dtfarch-2.0-h1.tar.bz2"
NOARCH="dtfnoarch-1.0-0.tar.bz2"
OPENCV="py-opencv-4.5.0-pyh0_0.tar.bz2"
PYONLY="dtfpyonly-1.0-pyh0_0.tar.bz2"
GPL="dtfgpl-1.0-0.tar.bz2"
MIT="dtfmit-1.0-0.tar.bz2"

WORK="$(mktemp -d -t dtf-spc-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
P="$WORK/pkgs"

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null
}
sha_of() { sha256sum "$1" | awk '{print $1}'; }

# cget <path> <name> [curl args]: GET; body $WORK/<name>, headers <name>.h
cget() {
  local p="$1" n="$2"; shift 2
  curl -s --max-time 120 -o "$WORK/$n" -D "$WORK/$n.h" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
xscan() { grep -i '^x-ak-scan:' "$WORK/$1.h" 2>/dev/null | head -1 | cut -d: -f2- | tr -d ' \r'; }
upstream_hits() { docker logs "$MOCK" 2>&1 | grep -c "GET /noarch/$1 "; }
is_blocked_body() { jq -e --arg f "$2" '.error == "scan_blocked" and .file == $f and (.reason | length) > 0' "$WORK/$1" >/dev/null 2>&1; }

conda_put() {  # conda_put <repo> <subdir> <local file> -> status
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT -H "$(auth_header)" \
    --data-binary "@$3" "${BASE_URL}/conda/$1/$2/$(basename "$3")" 2>/dev/null || echo 000
}
scan_config() {  # scan_config <repo> <json> -> status
  curl -s --max-time 30 -o "$WORK/sc.out" -w '%{http_code}' -X PUT -H "$(auth_header)" \
    -H 'Content-Type: application/json' -d "$2" \
    "${BASE_URL}/api/v1/repositories/$1/security" 2>/dev/null || echo 000
}
repo_id() { api_get "/api/v1/repositories/$1" 2>/dev/null | jq -r '.id // empty'; }
art_id() {  # art_id <repo id> <path>
  psql_q "SELECT id FROM artifacts WHERE repository_id = '$1' AND path = '$2' AND NOT is_deleted LIMIT 1"
}
art_json() {  # art_json <artifact id> <outname> -> status
  curl -s --max-time 30 -o "$WORK/$2" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/artifacts/$1" 2>/dev/null || echo 000
}
scans_done() {  # scans_done <artifact id>: every scan row for it is terminal
  local n
  n="$(psql_q "SELECT count(*) FILTER (WHERE status IN ('completed','failed')) || '/' || count(*) FROM scan_results WHERE artifact_id = '$1'")"
  [ -n "$n" ] && [ "${n%/*}" = "${n#*/}" ] && [ "${n#*/}" != "0" ]
}

begin_suite "scan-on-proxy-conda-and-content (#4585 #4041 #4042 #4058 #4556 #4516)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: packages built, proxied ones served by the mock, repositories configured"
auth_admin
setup_err=""
JINJA='site-packages/Jinja2-2.10.dist-info/METADATA=Metadata-Version: 2.1\nName: Jinja2\nVersion: 2.10\n'
SIX='site-packages/six-1.16.0.dist-info/METADATA=Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n'
{
  python3 -I "$BUILDER" "$P" jinja2 2.10 0 "$JINJA" \
    && python3 -I "$BUILDER" "$P" six 1.16.0 0 "$SIX" \
    && python3 -I "$BUILDER" "$P/liar" evil 6.6.6 0 "$JINJA" \
    && mv "$P/liar/evil-6.6.6-0.tar.bz2" "$P/$LIAR" \
    && python3 -I "$BUILDER" "$P/linux" dtfarch 2.0 h1 @subdir=linux-64 'lib/libdtfarch.so=linux\n' \
    && python3 -I "$BUILDER" "$P/osx" dtfarch 2.0 h1 @subdir=osx-64 'lib/libdtfarch.dylib=osx\n' \
    && python3 -I "$BUILDER" "$P" dtfnoarch 1.0 0 'share/dtfnoarch/data=1\n' \
    && python3 -I "$BUILDER" "$P" py-opencv 4.5.0 pyh0_0 @noarch=python 'site-packages/cv2/__init__.py=x = 1\n' \
    && python3 -I "$BUILDER" "$P" dtfpyonly 1.0 pyh0_0 @noarch=python 'site-packages/dtfpyonly/__init__.py=x = 1\n' \
    && python3 -I "$BUILDER" "$P" dtfgpl 1.0 0 @license=GPL-3.0-only 'share/dtfgpl/data=1\n' \
    && python3 -I "$BUILDER" "$P" dtfmit 1.0 0 @license=MIT 'share/dtfmit/data=1\n'
} >/dev/null 2>"$WORK/build.err" || setup_err+="build packages: $(head -c 200 "$WORK/build.err"); "
docker exec "$MOCK" mkdir -p /srv/noarch >/dev/null 2>&1 || setup_err+="mkdir in mock; "
for f in "$VULN" "$CLEAN" "$LIAR"; do
  docker cp "$P/$f" "${MOCK}:/srv/noarch/$f" >/dev/null 2>&1 || setup_err+="copy ${f} to mock; "
done
create_repo "$CR" conda remote "$UPSTREAM" || setup_err+="create ${CR}; "
create_repo "$CP" conda remote "$UPSTREAM" || setup_err+="create ${CP}; "
create_repo "$CV" conda virtual || setup_err+="create ${CV}; "
api_post "/api/v1/repositories/${CV}/members" "{\"member_key\":\"${CR}\"}" >/dev/null 2>&1 || setup_err+="add ${CR} to ${CV}; "
for r in "$H" "$L" "$RL"; do create_repo "$r" conda local || setup_err+="create ${r}; "; done
create_repo "$ST" conda staging || setup_err+="create ${ST}; "
st="$(scan_config "$CR" '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed","block_on_policy_violation":true,"severity_threshold":"high"}')"
[ "$st" = "200" ] || setup_err+="scan config ${CR} HTTP ${st}: $(head -c 200 "$WORK/sc.out"); "
for r in "$H" "$L"; do
  st="$(scan_config "$r" '{"scan_enabled":true,"scan_on_upload":true}')"
  [ "$st" = "200" ] || setup_err+="scan config ${r} HTTP ${st}; "
done
H_ID="$(repo_id "$H")"; L_ID="$(repo_id "$L")"; ST_ID="$(repo_id "$ST")"
[ -n "$H_ID" ] && [ -n "$L_ID" ] && [ -n "$ST_ID" ] || setup_err+="resolve repository ids; "
# The license policy exists BEFORE the L uploads, so their post-scan
# evaluation sees it; ST carries the same predicate for promotion.
for pair in "$L_ID:spc-lic" "$ST_ID:spc-promo"; do
  body="$(jq -nc --arg n "${pair#*:}-${SUF}" --arg r "${pair%%:*}" \
    '{name:$n, repository_id:$r, max_severity:"critical", block_unscanned:false, block_on_fail:false,
      predicates:{conda:{denied_licenses:["gpl-3.0-only"]}}}')"
  pst="$(curl -s --max-time 30 -o "$WORK/pol.out" -w '%{http_code}' -X POST -H "$(auth_header)" \
    -H 'Content-Type: application/json' -d "$body" "${BASE_URL}/api/v1/security/policies" 2>/dev/null || echo 000)"
  { [ "$pst" = "200" ] || [ "$pst" = "201" ]; } || setup_err+="policy ${pair#*:} HTTP ${pst}: $(head -c 200 "$WORK/pol.out"); "
done
for spec in "$H linux-64 $P/linux/$ARCH" "$H osx-64 $P/osx/$ARCH" "$H noarch $P/$NOARCH" \
            "$H noarch $P/$OPENCV" "$H noarch $P/$PYONLY" \
            "$L noarch $P/$GPL" "$L noarch $P/$MIT" "$ST noarch $P/$GPL" "$ST noarch $P/$MIT"; do
  # shellcheck disable=SC2086
  set -- $spec
  st="$(conda_put "$1" "$2" "$3")"
  { [ "$st" = "201" ] || [ "$st" = "200" ]; } || setup_err+="upload $(basename "$3") to $1/$2 -> HTTP ${st} $(head -c 160 "$WORK/put.out"); "
done
# A read-only API token for the /t/<token>/ URL forms.
TOKEN="$(api_post /api/v1/auth/tokens "{\"name\":\"spc-read-${SUF}\",\"scopes\":[\"read:artifacts\"]}" 2>/dev/null | jq -r '.token // empty')"
[ -n "$TOKEN" ] || setup_err+="mint read token; "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# CONTROL
# =============================================================================
begin_test "CONTROL: an unscanned conda Remote serves the vulnerable package byte-exact"
st="$(cget "/conda/${CP}/noarch/${VULN}" cp_vuln)"
if [ "$st" = "200" ] && cmp -s "$WORK/cp_vuln" "$P/$VULN"; then
  pass
else
  fail "unscanned conda Remote did not stream the package" "HTTP ${st}: $(head -c 200 "$WORK/cp_vuln" | tr -d '\0')"
fi

# =============================================================================
# #4585 - the conda scan-on-proxy gate
# =============================================================================
begin_test "#4585: GET /api/v1/formats reports conda and conda_native as scan_on_proxy=enforced"
fst="$(curl -s --max-time 30 -o "$WORK/formats.json" -w '%{http_code}' -H "$(auth_header)" "${BASE_URL}/api/v1/formats" 2>/dev/null || echo 000)"
got="$(jq -c '[.. | objects | select(.format_key? == "conda" or .format_key? == "conda_native") | {(.format_key): .scan_on_proxy}] | add' "$WORK/formats.json" 2>/dev/null)"
if [ "$fst" = "200" ] && [ "$got" = '{"conda":"enforced","conda_native":"enforced"}' ]; then
  pass
else
  fail "formats endpoint does not report the conda gate" "HTTP ${fst}: ${got:-none}"
fi

begin_test "#4585: a vulnerable package pulled through the Virtual is refused 403 scan_blocked; the Remote's own route then refuses it from the stored verdict"
st_v="$(cget "/conda/${CV}/noarch/${VULN}" v_vuln)"
st_r="$(cget "/conda/${CR}/noarch/${VULN}" r_vuln)"
verdict="$(psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256 = '$(sha_of "$P/$VULN")' AND scan_type = 'grype'")"
hits="$(upstream_hits "$VULN")"
# CP's CONTROL fetched it once; the Virtual walk fetches it once more for CR.
if [ "$st_v" = "403" ] && is_blocked_body v_vuln "$VULN" && [ "$st_r" = "403" ] && is_blocked_body r_vuln "$VULN" \
   && [ "$verdict" = "vulnerable" ] && [ "$hits" = "2" ]; then
  pass
else
  fail "vulnerable conda package not blocked" \
    "virtual HTTP ${st_v}: $(head -c 200 "$WORK/v_vuln" | tr -d '\0'); remote HTTP ${st_r}; verdict=${verdict:-none}; upstream GETs=${hits} (want 2)"
fi

begin_test "#4585: the blocked package's .sigs sidecar is refused with the package's scan_blocked body"
st_s="$(cget "/conda/${CR}/noarch/${VULN}.sigs" r_sigs)"
st_vs="$(cget "/conda/${CV}/noarch/${VULN}.sigs" v_sigs)"
if [ "$st_s" = "403" ] && is_blocked_body r_sigs "${VULN}.sigs" && [ "$st_vs" = "403" ] && is_blocked_body v_sigs "${VULN}.sigs"; then
  pass
else
  fail "sidecar of a blocked package not refused" \
    "remote HTTP ${st_s}: $(head -c 200 "$WORK/r_sigs" | tr -d '\0'); virtual HTTP ${st_vs}: $(head -c 200 "$WORK/v_sigs" | tr -d '\0')"
fi

begin_test "#4585: a clean package is served with X-AK-Scan: clean, byte-exact"
st="$(cget "/conda/${CR}/noarch/${CLEAN}" r_clean)"
if [ "$st" = "200" ] && [ "$(xscan r_clean)" = "clean" ] && cmp -s "$WORK/r_clean" "$P/$CLEAN"; then
  pass
else
  fail "clean conda package not served clean" "HTTP ${st} X-AK-Scan=$(xscan r_clean): $(head -c 200 "$WORK/r_clean" | tr -d '\0')"
fi

begin_test "#4585: both /t/<token>/ URL forms run the gate (blocked 403, clean 200 clean)"
t1="$(cget "/conda/t/${TOKEN}/${CR}/noarch/${VULN}" t1_vuln)"
t2="$(cget "/t/${TOKEN}/conda/${CR}/noarch/${VULN}" t2_vuln)"
t3="$(cget "/t/${TOKEN}/conda/${CR}/noarch/${CLEAN}" t3_clean)"
if [ "$t1" = "403" ] && is_blocked_body t1_vuln "$VULN" && [ "$t2" = "403" ] && is_blocked_body t2_vuln "$VULN" \
   && [ "$t3" = "200" ] && [ "$(xscan t3_clean)" = "clean" ] && cmp -s "$WORK/t3_clean" "$P/$CLEAN"; then
  pass
else
  fail "token URL forms bypass the gate" \
    "/conda/t/<token>/ HTTP ${t1}: $(head -c 160 "$WORK/t1_vuln" | tr -d '\0'); /t/<token>/conda/ HTTP ${t2}: $(head -c 160 "$WORK/t2_vuln" | tr -d '\0'); clean via token HTTP ${t3} X-AK-Scan=$(xscan t3_clean)"
fi

begin_test "#4585: a package whose index.json names another package is withheld 423 under fail_closed and nothing is recorded"
st="$(cget "/conda/${CR}/noarch/${LIAR}" r_liar)"
rows="$(psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256 = '$(sha_of "$P/$LIAR")'")"
if [ "$st" = "423" ] && jq -e '.error == "scan_pending"' "$WORK/r_liar" >/dev/null 2>&1 && [ "$rows" = "0" ]; then
  pass
else
  fail "identity mismatch not withheld" "HTTP ${st}: $(head -c 200 "$WORK/r_liar" | tr -d '\0'); verdict rows=${rows}"
fi

begin_test "#4585: the generic download route refuses a proxied conda file with scan_on_proxy_route_required"
st="$(cget "/api/v1/repositories/${CR}/download/noarch/${CLEAN}" gen_route -H "$(auth_header)")"
if [ "$st" = "403" ] && jq -e --arg f "$CLEAN" '.error == "scan_on_proxy_route_required" and .handler == "conda" and .file == $f' "$WORK/gen_route" >/dev/null 2>&1; then
  pass
else
  fail "generic route serves around the conda gate" "HTTP ${st}: $(head -c 300 "$WORK/gen_route" | tr -d '\0')"
fi

# =============================================================================
# #4041 - build-qualified identity purls
# =============================================================================
begin_test "#4041: two subdir builds of one name@version carry two build-qualified identity purls; noarch stays subdir=noarch"
A_LX="$(art_id "$H_ID" "linux-64/${ARCH}")"; A_OS="$(art_id "$H_ID" "osx-64/${ARCH}")"; A_NA="$(art_id "$H_ID" "noarch/${NOARCH}")"
art_json "$A_LX" a_lx.json >/dev/null; art_json "$A_OS" a_os.json >/dev/null; art_json "$A_NA" a_na.json >/dev/null
p_lx="$(jq -r '.metadata.identity.purl // empty' "$WORK/a_lx.json" 2>/dev/null)"
p_os="$(jq -r '.metadata.identity.purl // empty' "$WORK/a_os.json" 2>/dev/null)"
p_na="$(jq -r '.metadata.identity.purl // empty' "$WORK/a_na.json" 2>/dev/null)"
if [ "$p_lx" = "pkg:conda/dtfarch@2.0?build=h1&channel=${H}&subdir=linux-64&type=tar.bz2" ] \
   && [ "$p_os" = "pkg:conda/dtfarch@2.0?build=h1&channel=${H}&subdir=osx-64&type=tar.bz2" ] \
   && [ "$p_na" = "pkg:conda/dtfnoarch@1.0?build=0&channel=${H}&subdir=noarch&type=tar.bz2" ]; then
  pass
else
  fail "conda identity purls do not name the build" "linux-64=${p_lx:-none}; osx-64=${p_os:-none}; noarch=${p_na:-none}"
fi

# =============================================================================
# #4042 / #4088 / #4089 - the conda -> PyPI identity
# =============================================================================
begin_test "#4089/#4042: py-opencv is recorded as PyPI opencv-python; an unmapped package records that PyPI advisories were not queried"
A_CV="$(art_id "$H_ID" "noarch/${OPENCV}")"; A_PO="$(art_id "$H_ID" "noarch/${PYONLY}")"
art_json "$A_CV" a_cv.json >/dev/null; art_json "$A_PO" a_po.json >/dev/null
if jq -e '.metadata.identity.pypi.status == "mapped"
          and any(.metadata.identity.pypi.aliases[]; .pypi_name == "opencv-python" and .purl == "pkg:pypi/opencv-python@4.5.0")' \
        "$WORK/a_cv.json" >/dev/null 2>&1 \
   && jq -e '.metadata.identity.pypi.status == "unmapped"
             and (.metadata.identity.pypi.reason | contains("PyPI advisories were not queried"))' \
        "$WORK/a_po.json" >/dev/null 2>&1; then
  pass
else
  fail "conda -> PyPI identity not recorded" \
    "py-opencv: $(jq -c '.metadata.identity.pypi // "none"' "$WORK/a_cv.json" 2>/dev/null); dtfpyonly: $(jq -c '.metadata.identity.pypi // "none"' "$WORK/a_po.json" 2>/dev/null)"
fi

# =============================================================================
# #4058 - policy predicates on the download path
# =============================================================================
A_GPL="$(art_id "$L_ID" "noarch/${GPL}")"; A_MIT="$(art_id "$L_ID" "noarch/${MIT}")"
wait_until "scans of the license-policy uploads" 45 scans_done "$A_GPL" >/dev/null 2>&1
wait_until "scans of the license-policy uploads" 15 scans_done "$A_MIT" >/dev/null 2>&1

begin_test "#4058: under denied_licenses=[gpl-3.0-only] the GPL package is refused and quarantined with a [conda.license] reason; the MIT one downloads"
st_g="$(cget "/conda/${L}/noarch/${GPL}" l_gpl)"
st_m="$(cget "/conda/${L}/noarch/${MIT}" l_mit)"
reason="$(psql_q "SELECT quarantine_status || '|' || coalesce(quarantine_reason, '') FROM artifacts WHERE id = '${A_GPL}'")"
if { [ "$st_g" = "403" ] || [ "$st_g" = "409" ]; } && ! cmp -s "$WORK/l_gpl" "$P/$GPL" \
   && [[ "$reason" == *"[conda.license]"*"gpl-3.0-only"* ]] \
   && [ "$st_m" = "200" ] && cmp -s "$WORK/l_mit" "$P/$MIT"; then
  pass
else
  fail "license predicate not enforced on download" \
    "GPL HTTP ${st_g}: $(head -c 160 "$WORK/l_gpl" | tr -d '\0'); quarantine=${reason:-none}; MIT HTTP ${st_m}"
fi

# =============================================================================
# #4516 - admin hold queues
# =============================================================================
begin_test "#4516: the admin hold queues list the license block as an active hosted hold"
qst="$(curl -s --max-time 30 -o "$WORK/holds.json" -w '%{http_code}' -H "$(auth_header)" \
  "${BASE_URL}/api/v1/admin/holds/quarantine?kind=active&repository_key=${L}" 2>/dev/null || echo 000)"
sst="$(curl -s --max-time 30 -o "$WORK/summary.json" -w '%{http_code}' -H "$(auth_header)" \
  "${BASE_URL}/api/v1/admin/holds/summary" 2>/dev/null || echo 000)"
if [ "$qst" = "200" ] && [ "$sst" = "200" ] \
   && jq -e --arg id "$A_GPL" --arg p "noarch/${GPL}" --arg r "$L" '
        [.items[] | select(.artifact_id == $id)] | length == 1
        and .[0].source == "hosted" and .[0].path == $p and .[0].repository_key == $r
        and .[0].kind == "active" and .[0].is_blocked == true
        and (.[0].quarantine_reason | contains("[conda.license]"))' "$WORK/holds.json" >/dev/null 2>&1 \
   && jq -e --arg id "$A_MIT" '[.items[] | select(.artifact_id == $id)] | length == 0' "$WORK/holds.json" >/dev/null 2>&1 \
   && jq -e '.quarantine_active >= 1' "$WORK/summary.json" >/dev/null 2>&1; then
  pass
else
  fail "hold queues do not list the block" \
    "quarantine HTTP ${qst}: $(head -c 500 "$WORK/holds.json"); summary HTTP ${sst}: $(head -c 200 "$WORK/summary.json")"
fi

begin_test "#4516: a repository-scoped admin token is refused by the hold queues (an unscoped one is not)"
SCOPED="$(api_post /api/v1/auth/tokens "{\"name\":\"spc-scoped-${SUF}\",\"scopes\":[\"*\"],\"repo_selector\":{\"match_repos\":[\"${L_ID}\"]}}" 2>/dev/null | jq -r '.token // empty')"
UNSCOPED="$(api_post /api/v1/auth/tokens "{\"name\":\"spc-admin-${SUF}\",\"scopes\":[\"*\"]}" 2>/dev/null | jq -r '.token // empty')"
s_sc="$(curl -s --max-time 30 -o "$WORK/h_sc" -w '%{http_code}' -H "Authorization: Bearer ${SCOPED}" \
  "${BASE_URL}/api/v1/admin/holds/quarantine" 2>/dev/null || echo 000)"
s_un="$(curl -s --max-time 30 -o "$WORK/h_un" -w '%{http_code}' -H "Authorization: Bearer ${UNSCOPED}" \
  "${BASE_URL}/api/v1/admin/holds/quarantine" 2>/dev/null || echo 000)"
if [ -z "$SCOPED" ] || [ -z "$UNSCOPED" ]; then
  infra_fail "could not mint the admin tokens" "scoped=${SCOPED:+ok} unscoped=${UNSCOPED:+ok}"
elif { [ "$s_sc" = "403" ] || [ "$s_sc" = "404" ]; } && [ "$s_un" = "200" ] \
     && jq -e '.items | type == "array"' "$WORK/h_un" >/dev/null 2>&1; then
  pass
else
  fail "hold queue authorization wrong" "scoped token HTTP ${s_sc}: $(head -c 200 "$WORK/h_sc"); unscoped HTTP ${s_un}: $(head -c 200 "$WORK/h_un")"
fi

# =============================================================================
# #4058 / #4556 - the same predicate on promotion
# =============================================================================
begin_test "#4556/#4058: promotion under denied_licenses passes the MIT package with a passed [conda.license] gate result and refuses the GPL one"
S_MIT="$(art_id "$ST_ID" "noarch/${MIT}")"; S_GPL="$(art_id "$ST_ID" "noarch/${GPL}")"
pm="$(curl -s --max-time 60 -o "$WORK/pr_mit.json" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d "{\"target_repository\":\"${RL}\"}" \
  "${BASE_URL}/api/v1/promotion/repositories/${ST}/artifacts/${S_MIT}/promote" 2>/dev/null || echo 000)"
pg="$(curl -s --max-time 60 -o "$WORK/pr_gpl.json" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d "{\"target_repository\":\"${RL}\"}" \
  "${BASE_URL}/api/v1/promotion/repositories/${ST}/artifacts/${S_GPL}/promote" 2>/dev/null || echo 000)"
if [ "$pm" = "200" ] \
   && jq -e '.promoted == true and any(.gate_results[]; .rule == "policy-predicate" and .passed
             and (.reason | contains("[conda.license]")) and (.reason | contains("mit")))' "$WORK/pr_mit.json" >/dev/null 2>&1 \
   && { [ "$pg" = "200" ] || [ "$pg" = "403" ] || [ "$pg" = "409" ] || [ "$pg" = "422" ]; } \
   && jq -e '.promoted != true and (tostring | contains("[conda.license]"))' "$WORK/pr_gpl.json" >/dev/null 2>&1; then
  pass
else
  fail "license predicate not applied on promotion" \
    "MIT HTTP ${pm}: $(head -c 500 "$WORK/pr_mit.json"); GPL HTTP ${pg}: $(head -c 400 "$WORK/pr_gpl.json")"
fi

end_suite
