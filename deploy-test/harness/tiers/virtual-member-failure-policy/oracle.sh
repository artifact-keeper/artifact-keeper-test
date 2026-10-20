#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-member-failure-policy/oracle.sh: a virtual's merged metadata
#   fails loud on a failed member, and every readable member contributes
#   (artifact-keeper#4192 (+#4629), #4280/#4272, #4327, #4379)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-multi` and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bugs.
#
# Topology (keys suffixed per run; mock = http://172.16.<slot>.91):
#   Helm   HOK -> /ok/helm, HOK2 -> /ok2/helm, HFAIL -> /fail/helm (500)
#          HVG {HOK, HOK2}   HVS {HOK, HFAIL}   HVP {HOK, HFAIL} + partial
#   CRAN   COK, COK2, CFAIL; CVG {COK, COK2}  CVS {COK, CFAIL}  CVP + partial
#   Gems   GOK -> /ok/gems, GOK2 -> /ok2/gems, GFAIL -> /fail/gems
#          GVM {GOK, GOK2}   GVF {GOK, GFAIL}   GH hosted (empty)
#   NuGet  NERR -> /nuget/v2err/api/v2 (V2 feed, index.json answers 403)
#          NV {NERR}
#   Ansible AH hosted with dtfns.coll<suf> 1.0.0;  AV {AH}
#
# Every FIX case is RED on 1.10.0 and GREEN on 1.11.0+; every CONTROL holds on
# both.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly, so a non-zero helper (grep with no match, jq on a
# non-JSON error body) must not end the suite before the assertion runs.
set +e

SUF="${RUN_ID##*-}$$"
SLOT="${DTF_SLOT}"
MOCK="http://172.16.${SLOT}.91"
MOCK_CTR="ak-dtf${SLOT}-mock-multi"

HOK="vfp-hok-${SUF}";  HOK2="vfp-hok2-${SUF}";  HFAIL="vfp-hfail-${SUF}"
HVG="vfp-hvg-${SUF}";  HVS="vfp-hvs-${SUF}";    HVP="vfp-hvp-${SUF}"
COK="vfp-cok-${SUF}";  COK2="vfp-cok2-${SUF}";  CFAIL="vfp-cfail-${SUF}"
CVG="vfp-cvg-${SUF}";  CVS="vfp-cvs-${SUF}";    CVP="vfp-cvp-${SUF}"
GOK="vfp-gok-${SUF}";  GOK2="vfp-gok2-${SUF}";  GFAIL="vfp-gfail-${SUF}"
GVM="vfp-gvm-${SUF}";  GVF="vfp-gvf-${SUF}";    GH="vfp-gh-${SUF}"
NERR="vfp-nerr-${SUF}"; NV="vfp-nv-${SUF}"
AH="vfp-ah-${SUF}";    AV="vfp-av-${SUF}"
NU_ID="dtfnu-err${SUF}"
A_NS="dtfns"; A_NAME="coll${SUF}"

WORK="$(mktemp -d -t dtf-vfp-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
# get PATH OUT [curl args...] -> HTTP status (body in OUT, headers in OUT.h)
get() {
  local p="$1" out="$2"; shift 2
  curl -s --max-time 60 -D "${out}.h" -o "$out" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
# send METHOD PATH JSON -> HTTP status (body in $WORK/send.out)
send() {
  curl -s --max-time 60 -o "$WORK/send.out" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "${BASE_URL}$2" 2>/dev/null || echo 000
}
hdr() { grep -i "^$2:" "$1.h" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
ok2xx() { [ "$1" -ge 200 ] 2>/dev/null && [ "$1" -lt 300 ]; }
# mock_bytes PATH OUT: the mock's own answer, fetched from inside its container
mock_bytes() {
  docker exec "$MOCK_CTR" python3 -c "import sys,urllib.request; sys.stdout.buffer.write(urllib.request.urlopen('http://127.0.0.1$1').read())" > "$2" 2>/dev/null
}
mkrepo() {  # mkrepo JSON
  local st; st="$(send POST /api/v1/repositories "$1")"
  ok2xx "$st" || err+="create $(echo "$1" | jq -r .key) -> ${st} $(head -c 160 "$WORK/send.out"); "
}
remote() {  # remote KEY FORMAT UPSTREAM
  mkrepo "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"$3\"}"
}
virtual() {  # virtual KEY FORMAT MEMBER...
  local key="$1" fmt="$2" members="" prio=1 m; shift 2
  for m in "$@"; do
    members+="${members:+,}{\"repo_key\":\"${m}\",\"priority\":${prio}}"; prio=$((prio + 1))
  done
  mkrepo "{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"${fmt}\",\"repo_type\":\"virtual\",\"is_public\":true,\"member_repos\":[${members}]}"
}

begin_suite "virtual-member-failure-policy (#4192 #4280 #4272 #4327 #4379)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: remotes on the mock, virtuals, hosted Ansible collection"
auth_admin
err=""
remote "$HOK" helm "${MOCK}/ok/helm";   remote "$HOK2" helm "${MOCK}/ok2/helm"
remote "$HFAIL" helm "${MOCK}/fail/helm"
virtual "$HVG" helm "$HOK" "$HOK2"; virtual "$HVS" helm "$HOK" "$HFAIL"; virtual "$HVP" helm "$HOK" "$HFAIL"
remote "$COK" cran "${MOCK}/ok/cran";   remote "$COK2" cran "${MOCK}/ok2/cran"
remote "$CFAIL" cran "${MOCK}/fail/cran"
virtual "$CVG" cran "$COK" "$COK2"; virtual "$CVS" cran "$COK" "$CFAIL"; virtual "$CVP" cran "$COK" "$CFAIL"
remote "$GOK" rubygems "${MOCK}/ok/gems"; remote "$GOK2" rubygems "${MOCK}/ok2/gems"
remote "$GFAIL" rubygems "${MOCK}/fail/gems"
virtual "$GVM" rubygems "$GOK" "$GOK2"; virtual "$GVF" rubygems "$GOK" "$GFAIL"
mkrepo "{\"key\":\"${GH}\",\"name\":\"${GH}\",\"format\":\"rubygems\",\"repo_type\":\"local\",\"is_public\":true}"
remote "$NERR" nuget "${MOCK}/nuget/v2err/api/v2"
virtual "$NV" nuget "$NERR"
mkrepo "{\"key\":\"${AH}\",\"name\":\"${AH}\",\"format\":\"ansible\",\"repo_type\":\"local\",\"is_public\":true}"
virtual "$AV" ansible "$AH"

# Ansible collection 1.0.0 in the hosted member.
CDIR="$WORK/coll/${A_NS}/${A_NAME}"
mkdir -p "$CDIR/plugins/modules"
printf 'namespace: %s\nname: %s\nversion: "1.0.0"\nreadme: README.md\nauthors: [dtf]\nlicense: [MIT]\n' \
  "$A_NS" "$A_NAME" > "$CDIR/galaxy.yml"
jq -n --arg ns "$A_NS" --arg n "$A_NAME" \
  '{collection_info: {namespace: $ns, name: $n, version: "1.0.0", description: "dtf", license: ["MIT"], authors: ["dtf"], dependencies: {}}}' \
  > "$CDIR/MANIFEST.json"
echo "# dtf" > "$CDIR/README.md"
printf 'DOCUMENTATION = "module: hello"\n' > "$CDIR/plugins/modules/hello.py"
tar czf "$WORK/${A_NS}-${A_NAME}-1.0.0.tar.gz" -C "$WORK/coll" "${A_NS}/${A_NAME}"
st="$(curl -s --max-time 60 -o "$WORK/aup.out" -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -F "file=@$WORK/${A_NS}-${A_NAME}-1.0.0.tar.gz" \
  -F "collection={\"namespace\":\"${A_NS}\",\"name\":\"${A_NAME}\",\"version\":\"1.0.0\"};type=application/json" \
  "${BASE_URL}/ansible/${AH}/api/v3/artifacts/collections/" 2>/dev/null || echo 000)"
ok2xx "$st" || err+="ansible upload -> ${st} $(head -c 160 "$WORK/aup.out"); "

if [ -n "$err" ]; then
  infra_fail "setup did not complete" "$err"
  end_suite
fi
pass

# The partial opt-in is a 1.11.0 repository setting. On 1.10.0 the PATCH
# ignores the unknown field (or refuses it): either way the virtual stays
# strict-less, and the partial cases below are the red signal, not setup.
PARTIAL_ST=""
for v in "$HVP" "$CVP"; do
  PARTIAL_ST+="${v}=$(send PATCH "/api/v1/repositories/${v}" '{"virtual_metadata_partial":true}') "
done

# =============================================================================
# A. #4192: Helm and CRAN virtual merges fail loud on a failed member
# =============================================================================
begin_test "CONTROL: a Helm virtual over two healthy remotes merges both members' charts"
st="$(get "/helm/${HVG}/index.yaml" "$WORK/hvg.yaml")"
if [ "$st" = "200" ] && grep -q 'dtfhelm-ok:' "$WORK/hvg.yaml" && grep -q 'dtfhelm-ok2:' "$WORK/hvg.yaml"; then
  pass
else
  fail "HTTP ${st}, want 200 listing dtfhelm-ok and dtfhelm-ok2" "$(head -c 400 "$WORK/hvg.yaml")"
fi

begin_test "FIX #4192: a Helm virtual with a failing member answers 502 naming that member, not a 200 index without it"
st="$(get "/helm/${HVS}/index.yaml" "$WORK/hvs.yaml")"
# The cause names the upstream status the proxy reported (a 5xx: the mock's
# 500, or 503 once the proxy's breaker for that upstream has opened).
if [ "$st" = "502" ] && grep -q "member '${HFAIL}' failed: index.yaml: upstream fetch failed with 5" "$WORK/hvs.yaml"; then
  pass
else
  fail "HTTP ${st}, want 502 naming member '${HFAIL}' and its upstream 5xx" "$(head -c 400 "$WORK/hvs.yaml")"
fi

begin_test "FIX #4192: with virtual_metadata_partial a Helm virtual serves the healthy merge marked partial and uncacheable"
st="$(get "/helm/${HVP}/index.yaml" "$WORK/hvp.yaml")"
pm="$(hdr "$WORK/hvp.yaml" x-ak-partial-members)"; cc="$(hdr "$WORK/hvp.yaml" cache-control)"
wn="$(hdr "$WORK/hvp.yaml" warning)"
if [ "$st" = "200" ] && [ "$pm" = "$HFAIL" ] && [ "$cc" = "no-store" ] && [[ "$wn" == 199* ]] \
   && grep -q 'dtfhelm-ok:' "$WORK/hvp.yaml"; then
  pass
else
  fail "HTTP ${st} X-AK-Partial-Members='${pm}' Cache-Control='${cc}' Warning='${wn}' (PATCH: ${PARTIAL_ST}); want 200 + '${HFAIL}' + no-store + 199" \
    "$(head -c 300 "$WORK/hvp.yaml")"
fi

begin_test "CONTROL: a CRAN virtual over two healthy remotes concatenates both PACKAGES"
st="$(get "/cran/${CVG}/src/contrib/PACKAGES" "$WORK/cvg.txt")"
if [ "$st" = "200" ] && grep -qx 'Package: dtfcranok' "$WORK/cvg.txt" && grep -qx 'Package: dtfcranok2' "$WORK/cvg.txt"; then
  pass
else
  fail "HTTP ${st}, want 200 listing dtfcranok and dtfcranok2" "$(head -c 400 "$WORK/cvg.txt")"
fi

begin_test "FIX #4192: a CRAN virtual with a failing member answers 502 naming that member"
st="$(get "/cran/${CVS}/src/contrib/PACKAGES" "$WORK/cvs.txt")"
if [ "$st" = "502" ] && grep -q "member '${CFAIL}' failed" "$WORK/cvs.txt"; then
  pass
else
  fail "HTTP ${st}, want 502 naming member '${CFAIL}'" "$(head -c 400 "$WORK/cvs.txt")"
fi

begin_test "FIX #4192: with virtual_metadata_partial a CRAN virtual serves the healthy PACKAGES marked partial"
st="$(get "/cran/${CVP}/src/contrib/PACKAGES" "$WORK/cvp.txt")"
pm="$(hdr "$WORK/cvp.txt" x-ak-partial-members)"; cc="$(hdr "$WORK/cvp.txt" cache-control)"
if [ "$st" = "200" ] && [ "$pm" = "$CFAIL" ] && [ "$cc" = "no-store" ] && grep -qx 'Package: dtfcranok' "$WORK/cvp.txt"; then
  pass
else
  fail "HTTP ${st} X-AK-Partial-Members='${pm}' Cache-Control='${cc}'; want 200 + '${CFAIL}' + no-store" "$(head -c 300 "$WORK/cvp.txt")"
fi

begin_test "FIX #4192: each member failure counts in ak_virtual_member_metadata_failures_total, strict and partial alike"
st="$(curl -s --max-time 30 -o "$WORK/metrics.txt" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000)"
strict="$(grep -E "^ak_virtual_member_metadata_failures_total\{" "$WORK/metrics.txt" 2>/dev/null \
  | grep "format=\"helm\"" | grep "virtual_repo=\"${HVS}\"" | grep "member=\"${HFAIL}\"" | grep -c 'reason="fetch"')"
partial="$(grep -E "^ak_virtual_member_metadata_failures_total\{" "$WORK/metrics.txt" 2>/dev/null \
  | grep "virtual_repo=\"${CVP}\"" | grep -c "member=\"${CFAIL}\"")"
if [ "$st" = "200" ] && [ "${strict:-0}" -ge 1 ] && [ "${partial:-0}" -ge 1 ]; then
  pass
else
  fail "metrics HTTP ${st}; helm strict series ${strict:-0}, cran partial series ${partial:-0}; want both present" \
    "$(grep -E '^ak_virtual_member_metadata_failures_total' "$WORK/metrics.txt" 2>/dev/null | head -5)"
fi

# =============================================================================
# B. #4280/#4272: RubyGems Marshal specs indexes from remote members
# =============================================================================
begin_test "CONTROL: a hosted RubyGems repo serves specs.4.8.gz as gzipped Marshal 4.8"
st="$(get "/gems/${GH}/specs.4.8.gz" "$WORK/gh.gz")"
magic="$(gzip -dc "$WORK/gh.gz" 2>/dev/null | head -c 2 | od -An -tx1 | tr -d ' \n')"
if [ "$st" = "200" ] && [ "$magic" = "0408" ]; then
  pass
else
  fail "HTTP ${st}, Marshal header '${magic}', want 200 + 0408" "$(head -c 100 "$WORK/gh.gz" | od -c | head -3)"
fi

begin_test "FIX #4280: a RubyGems remote passes the upstream specs.4.8.gz through byte for byte"
st="$(get "/gems/${GOK}/specs.4.8.gz" "$WORK/gok.gz")"
mock_bytes "/ok/gems/specs.4.8.gz" "$WORK/mock-ok.gz"
got="$(sha256sum < "$WORK/gok.gz" | cut -c1-64)"; want="$(sha256sum < "$WORK/mock-ok.gz" | cut -c1-64)"
if [ "$st" = "200" ] && [ -s "$WORK/mock-ok.gz" ] && [ "$got" = "$want" ]; then
  pass
else
  fail "HTTP ${st}, $(wc -c < "$WORK/gok.gz") bytes sha ${got:0:12}; want the mock's $(wc -c < "$WORK/mock-ok.gz") bytes sha ${want:0:12}" \
    "$(gzip -dc "$WORK/gok.gz" 2>/dev/null | od -c | head -3)"
fi

begin_test "FIX #4280: a RubyGems virtual over two remotes decodes and merges both members' Marshal indexes"
st="$(get "/gems/${GVM}/specs.4.8.gz" "$WORK/gvm.gz")"
gzip -dc "$WORK/gvm.gz" > "$WORK/gvm.marshal" 2>/dev/null
if [ "$st" = "200" ] && grep -aq 'dtfgem-ok' "$WORK/gvm.marshal" && grep -aq 'dtfgem-ok2' "$WORK/gvm.marshal"; then
  pass
else
  fail "HTTP ${st}, $(wc -c < "$WORK/gvm.marshal") decoded bytes; want both dtfgem-ok and dtfgem-ok2" \
    "$(od -c "$WORK/gvm.marshal" | head -4)"
fi

begin_test "FIX #4272: a RubyGems virtual whose remote member fails answers 502 naming it, not a smaller index"
st="$(get "/gems/${GVF}/specs.4.8.gz" "$WORK/gvf.out")"
if [ "$st" = "502" ] && grep -q "member '${GFAIL}'" "$WORK/gvf.out"; then
  pass
else
  fail "HTTP ${st}, want 502 naming '${GFAIL}'" "$(head -c 300 "$WORK/gvf.out" | od -c | head -4)"
fi

# =============================================================================
# C. #4327: a V2 member whose index.json answers 403 stays in the virtual
# =============================================================================
begin_test "FIX #4327: the virtual's V2 feed lists the 403-index member's package versions"
st="$(get "/nuget/${NV}/v2/FindPackagesById()?id='${NU_ID}'" "$WORK/nv.xml")"
n="$(grep -o "<d:Version>[^<]*</d:Version>" "$WORK/nv.xml" 2>/dev/null | sort -u | tr -d '\n')"
if [ "$st" = "200" ] && [ "$n" = "<d:Version>1.0.0</d:Version><d:Version>2.0.0</d:Version>" ] \
   && grep -q "${BASE_URL}/nuget/${NV}/v2" "$WORK/nv.xml"; then
  pass
else
  fail "HTTP ${st} versions '${n}'; want 1.0.0 and 2.0.0 with links onto the virtual" "$(head -c 500 "$WORK/nv.xml")"
fi

begin_test "FIX #4327: a V2 download through the virtual serves the 403-index member's package bytes"
st="$(get "/nuget/${NV}/v2/package/${NU_ID}/1.0.0" "$WORK/nv.nupkg")"
mock_bytes "/nuget/v2err/api/v2/package/${NU_ID}/1.0.0" "$WORK/mock.nupkg"
if [ "$st" = "200" ] && [ -s "$WORK/mock.nupkg" ] && cmp -s "$WORK/nv.nupkg" "$WORK/mock.nupkg"; then
  pass
else
  fail "HTTP ${st}, $(wc -c < "$WORK/nv.nupkg") bytes; want the mock's $(wc -c < "$WORK/mock.nupkg") bytes" "$(head -c 200 "$WORK/nv.nupkg")"
fi

# =============================================================================
# D. #4379: Galaxy metadata routes of a Virtual Ansible repository
# =============================================================================
COLL="/api/v3/collections/${A_NS}/${A_NAME}"
begin_test "CONTROL: the hosted Ansible member lists its collection version"
st="$(get "/ansible/${AH}${COLL}/versions/" "$WORK/ah.json")"
if [ "$st" = "200" ] && jq -e '[.data[].version] == ["1.0.0"]' "$WORK/ah.json" >/dev/null 2>&1; then
  pass
else
  fail "HTTP ${st}, want 200 data[].version == [1.0.0]" "$(head -c 300 "$WORK/ah.json")"
fi

begin_test "FIX #4379: the virtual's versions/ lists the member's version, with an href on the virtual"
st="$(get "/ansible/${AV}${COLL}/versions/" "$WORK/av.json")"
if [ "$st" = "200" ] && jq -e --arg p "/ansible/${AV}/" \
     '[.data[].version] == ["1.0.0"] and (.data[0].href | contains($p))' "$WORK/av.json" >/dev/null 2>&1; then
  pass
else
  fail "HTTP ${st}, want data[].version == [1.0.0] with href under /ansible/${AV}/" "$(head -c 300 "$WORK/av.json")"
fi

begin_test "FIX #4379: the virtual's collection and version detail routes answer 200, download_url on the virtual"
st1="$(get "/ansible/${AV}${COLL}/" "$WORK/avc.json")"
st2="$(get "/ansible/${AV}${COLL}/versions/1.0.0/" "$WORK/avv.json")"
if [ "$st1" = "200" ] && [ "$st2" = "200" ] \
   && jq -e --arg n "$A_NAME" '.name == $n' "$WORK/avc.json" >/dev/null 2>&1 \
   && jq -e --arg p "/ansible/${AV}/" '.version == "1.0.0" and (.download_url | contains($p))' "$WORK/avv.json" >/dev/null 2>&1; then
  pass
else
  fail "collection HTTP ${st1}, version HTTP ${st2}; want 200/200 with download_url under /ansible/${AV}/" \
    "$(head -c 200 "$WORK/avc.json") | $(head -c 300 "$WORK/avv.json")"
fi

begin_test "CONTROL: the virtual's download route already served the member's tarball"
st="$(get "/ansible/${AV}/download/${A_NS}-${A_NAME}-1.0.0.tar.gz" "$WORK/av.tgz")"
if [ "$st" = "200" ] && cmp -s "$WORK/av.tgz" "$WORK/${A_NS}-${A_NAME}-1.0.0.tar.gz"; then
  pass
else
  fail "HTTP ${st}, $(wc -c < "$WORK/av.tgz") bytes; want the uploaded tarball" "$(head -c 200 "$WORK/av.tgz")"
fi

end_suite
