#!/usr/bin/env bash
# =============================================================================
# tiers/conda-virtual-merge-policy/oracle.sh: how a virtual conda channel
#   fetches, bounds and merges its remote members, and what it answers when
#   one fails (artifact-keeper#4555, #4192, #4601, #4145)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda
# limits.conda-virtual-merge` and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH. The mock logs one line per request
# ("mock-conda: "GET <path> HTTP/1.1" <code> -").
#
# Topology (keys suffixed per run):
#   H   hosted: c12-host 1.0
#   R   remote -> mock root   (dtfup-alpha 1.0/2.0, dtfup-blocked 1.0)
#   R2  remote -> mock /m2/   (noarch only as repodata.json.bz2: dtfm2-only)
#   RF  remote -> mock /fail/ (500 to everything)
#   RB  remote -> mock /big/  (~2 MiB repodata.json, over the 1 MiB ceiling)
#   VM  virtual {H, R, R2}    healthy merge
#   VF  virtual {H, R, RF}    strict (default) member-failure policy
#   VP  virtual {H, R, RF}    virtual_metadata_partial = true
#   VB  virtual {H, RB}       member over CONDA_VIRTUAL_MEMBER_MAX_BYTES
#
# Every FIX case is RED on ak-backend:1.10.0 and GREEN on 1.11.0+; every
# CONTROL holds on both. See the manifest for the bugs.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe captures its status and asserts on
# it explicitly.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
MOCK="http://172.16.${SLOT}.70"
MOCK_CTR="ak-dtf${SLOT}-mock-conda"

H="c12-host-${SUF}"
R="c12-remote-${SUF}"
R2="c12-m2-${SUF}"
RF="c12-fail-${SUF}"
RB="c12-big-${SUF}"
VM="c12-vmerge-${SUF}"
VF="c12-vstrict-${SUF}"
VP="c12-vpartial-${SUF}"
VB="c12-vbig-${SUF}"

HOSTED="c12-host-1.0-0.tar.bz2"
UP_ALPHA2="dtfup-alpha-2.0-0.tar.bz2"
UP_BLOCKED="dtfup-blocked-1.0-0.tar.bz2"
M2_ONLY="dtfm2-only-1.0-0.tar.bz2"

WORK="$(mktemp -d -t dtf-c12-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
# hget PATH OUTFILE [curl args...] -> HTTP status; headers in OUTFILE.hdr
hget() {
  local p="$1" out="$2"; shift 2
  curl -s --max-time 60 -D "${out}.hdr" -o "$out" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
hdr() { grep -i "^$2:" "${1}.hdr" 2>/dev/null | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
keys_of() { jq -c '[(.packages // {}), (.["packages.conda"] // {})] | add | keys' "$1" 2>/dev/null; }
# mock_log_lines <path-prefix>: request lines the mock logged under a prefix.
mock_log_lines() { docker logs "$MOCK_CTR" 2>&1 | grep -o "\"GET $1[^ ]* " | sed 's/^"GET //; s/ $//'; }

METRICS="$WORK/metrics.txt"
scrape_metrics() {
  curl -s --max-time 30 -o "$METRICS" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000
}
# metric_value <name> <label=value>... -> the first matching sample, or empty
metric_value() {
  local name="$1"; shift
  python3 -I - "$METRICS" "$name" "$@" <<'PY'
import re, sys
path, name, wanted = sys.argv[1], sys.argv[2], sys.argv[3:]
want = dict(w.split("=", 1) for w in wanted)
for line in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r'^([A-Za-z_:][\w:]*)\{(.*)\}\s+(\S+)', line)
    if not m or m.group(1) != name:
        continue
    labels = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', m.group(2)))
    if all(labels.get(k) == v for k, v in want.items()):
        print(m.group(3))
        break
PY
}
metric_ge1() { local v; v="$(metric_value "$@")"; [ -n "$v" ] && python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= 1 else 1)' "$v"; }

begin_suite "conda-virtual-merge-policy (#4555 #4192 #4601 #4145)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: admin auth, repositories, hosted upload, partial opt-in"
auth_admin
setup_err=""
create_repo "$H" conda local || setup_err+="create H; "
create_repo "$R" conda remote "${MOCK}/" || setup_err+="create R; "
create_repo "$R2" conda remote "${MOCK}/m2/" || setup_err+="create R2; "
create_repo "$RF" conda remote "${MOCK}/fail/" || setup_err+="create RF; "
create_repo "$RB" conda remote "${MOCK}/big/" || setup_err+="create RB; "
for v in "$VM" "$VF" "$VP" "$VB"; do create_repo "$v" conda virtual || setup_err+="create ${v}; "; done
for pair in "$VM:$H" "$VM:$R" "$VM:$R2" "$VF:$H" "$VF:$R" "$VF:$RF" "$VP:$H" "$VP:$R" "$VP:$RF" "$VB:$H" "$VB:$RB"; do
  api_post "/api/v1/repositories/${pair%%:*}/members" "{\"member_key\":\"${pair#*:}\"}" >/dev/null \
    || setup_err+="add ${pair#*:} to ${pair%%:*}; "
done
bash "${DTF_DIR}/fixtures/conda/build.sh" "$WORK" c12-host 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build ${HOSTED}; "
st="$(curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT -H "$(auth_header)" \
  --data-binary "@$WORK/${HOSTED}" "${BASE_URL}/conda/${H}/noarch/${HOSTED}" 2>/dev/null || echo 000)"
[ "$st" = "201" ] || [ "$st" = "200" ] || setup_err+="upload -> HTTP ${st}; "
# The partial opt-in is a 1.11.0 repository setting: recorded, not fatal.
VP_PATCH="$(curl -s --max-time 30 -o "$WORK/vp_patch.json" -w '%{http_code}' -X PATCH \
  -H "$(auth_header)" -H 'Content-Type: application/json' -d '{"virtual_metadata_partial":true}' \
  "${BASE_URL}/api/v1/repositories/${VP}" 2>/dev/null || echo 000)"
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# #4555 compressed-first member fetch, `unknown`, missing subdirs
# =============================================================================
begin_test "FIX #4555: the healthy virtual merges a member that publishes its repodata only as .bz2"
st="$(hget "/conda/${VM}/noarch/repodata.json" "$WORK/vm_rd.json")"
if [ "$st" = "200" ] \
   && jq -e --arg h "$HOSTED" --arg a "$UP_ALPHA2" --arg b "$UP_BLOCKED" --arg m "$M2_ONLY" \
        '.packages | has($h) and has($a) and has($b) and has($m)' "$WORK/vm_rd.json" >/dev/null 2>&1; then
  pass
else
  fail "the .bz2-only member's record is missing from the merge (want ${M2_ONLY})" \
    "HTTP ${st}: keys=$(keys_of "$WORK/vm_rd.json") $(head -c 200 "$WORK/vm_rd.json")"
fi

begin_test "FIX #4555: the member is fetched .zst first, then .bz2, and the plain .json is never requested once .bz2 answers"
m2_log="$(mock_log_lines /m2/noarch/repodata | tr '\n' ' ')"
first="$(mock_log_lines /m2/noarch/repodata | head -1)"
second="$(mock_log_lines /m2/noarch/repodata | sed -n 2p)"
if [ "$first" = "/m2/noarch/repodata.json.zst" ] && [ "$second" = "/m2/noarch/repodata.json.bz2" ] \
   && ! mock_log_lines /m2/noarch/repodata | grep -qx '/m2/noarch/repodata.json'; then
  pass
else
  fail "member fetch order is not .zst -> .bz2 (stopping there)" "mock requests under /m2/noarch/: ${m2_log:-none}"
fi

begin_test "FIX #4555: GET /conda/<virtual>/unknown/repodata.json is an empty index (200), not 400"
st="$(hget "/conda/${VM}/unknown/repodata.json" "$WORK/vm_unknown.json")"
if [ "$st" = "200" ] && jq -e '.info.subdir == "unknown" and (.packages == {}) and (.["packages.conda"] == {})' "$WORK/vm_unknown.json" >/dev/null 2>&1; then
  pass
else
  fail "virtual unknown subdir not served as an empty index" "HTTP ${st}: $(head -c 300 "$WORK/vm_unknown.json")"
fi

begin_test "CONTROL #4555: a subdir no remote member publishes (linux-64) merges to 200 with no remote records"
st="$(hget "/conda/${VM}/linux-64/repodata.json" "$WORK/vm_l64.json")"
if [ "$st" = "200" ] && jq -e '(.packages | length) == 0' "$WORK/vm_l64.json" >/dev/null 2>&1; then
  pass
else
  fail "missing subdir failed the virtual merge" "HTTP ${st}: $(head -c 300 "$WORK/vm_l64.json")"
fi

# 1.10.0 also answers 200 here (its merge tolerated any member failure); the
# 502 this guards against existed only inside 1.11.0 development (#4601).
begin_test "CONTROL #4601: channeldata.json merges to 200 when one remote member publishes none"
st="$(hget "/conda/${VM}/channeldata.json" "$WORK/vm_cd.json")"
if [ "$st" = "200" ] && jq -e '.packages | has("c12-host") and has("dtfup-alpha")' "$WORK/vm_cd.json" >/dev/null 2>&1; then
  pass
else
  fail "a member without channeldata.json failed the virtual's channeldata" "HTTP ${st}: $(head -c 300 "$WORK/vm_cd.json")"
fi

# =============================================================================
# #4192 member failure policy
# =============================================================================
begin_test "FIX #4192: a member whose upstream answers 500 fails the virtual's repodata.json and channeldata.json with 502 naming the member"
st_r="$(hget "/conda/${VF}/noarch/repodata.json" "$WORK/vf_rd.json")"
st_c="$(hget "/conda/${VF}/channeldata.json" "$WORK/vf_cd.json")"
if [ "$st_r" = "502" ] && grep -q "member '${RF}' failed" "$WORK/vf_rd.json" && grep -q "upstream fetch failed" "$WORK/vf_rd.json" \
   && [ "$st_c" = "502" ] && grep -q "member '${RF}' failed" "$WORK/vf_cd.json"; then
  pass
else
  fail "a failed member was silently dropped from the merge" \
    "repodata HTTP ${st_r}: $(head -c 300 "$WORK/vf_rd.json" | tr '\n' ' '); channeldata HTTP ${st_c}: $(head -c 200 "$WORK/vf_cd.json" | tr '\n' ' ')"
fi

begin_test "FIX #4192: with virtual_metadata_partial the healthy members are served 200, marked X-AK-Partial-Members, no-store, Warning 199"
st="$(hget "/conda/${VP}/noarch/repodata.json" "$WORK/vp_rd.json")"
pm="$(hdr "$WORK/vp_rd.json" X-AK-Partial-Members)"
cc="$(hdr "$WORK/vp_rd.json" Cache-Control)"
wn="$(hdr "$WORK/vp_rd.json" Warning)"
if [ "$VP_PATCH" = "200" ] && [ "$st" = "200" ] && [ "$pm" = "$RF" ] && [ "$cc" = "no-store" ] \
   && [ "${wn#199 }" != "$wn" ] && [ -z "$(hdr "$WORK/vp_rd.json" ETag)" ] \
   && jq -e --arg h "$HOSTED" --arg a "$UP_ALPHA2" '.packages | has($h) and has($a)' "$WORK/vp_rd.json" >/dev/null 2>&1; then
  pass
else
  fail "partial merge not marked" \
    "PATCH HTTP ${VP_PATCH}; GET HTTP ${st}; X-AK-Partial-Members='${pm}' Cache-Control='${cc}' Warning='${wn}' ETag='$(hdr "$WORK/vp_rd.json" ETag)'; keys=$(keys_of "$WORK/vp_rd.json")"
fi

begin_test "FIX #4555: a member over CONDA_VIRTUAL_MEMBER_MAX_BYTES fails the merge with 502 naming the member and the ceiling"
st="$(hget "/conda/${VB}/noarch/repodata.json" "$WORK/vb_rd.json")"
if [ "$st" = "502" ] && grep -q "member '${RB}' failed" "$WORK/vb_rd.json" \
   && grep -q "CONDA_VIRTUAL_MEMBER_MAX_BYTES" "$WORK/vb_rd.json"; then
  pass
else
  fail "an over-ceiling member was merged (or failed for another reason)" \
    "HTTP ${st}: $(head -c 300 "$WORK/vb_rd.json" | tr '\n' ' ') (records: $(jq '.packages | length' "$WORK/vb_rd.json" 2>/dev/null))"
fi

begin_test "CONTROL: the over-ceiling document itself proxies 200 through the single remote"
st="$(hget "/conda/${RB}/noarch/repodata.json" "$WORK/rb_rd.json")"
n="$(jq '.packages | length' "$WORK/rb_rd.json" 2>/dev/null)"
if [ "$st" = "200" ] && [ "$n" = "2600" ]; then
  pass
else
  fail "the remote no longer proxies the 2 MiB document" "HTTP ${st}, records=${n:-?}"
fi

begin_test "FIX #4192: ak_virtual_member_metadata_failures_total counts the fetch and cap failures per member"
mst="$(scrape_metrics)"
if [ "$mst" = "200" ] \
   && metric_ge1 ak_virtual_member_metadata_failures_total format=conda "virtual_repo=${VF}" "member=${RF}" reason=fetch \
   && metric_ge1 ak_virtual_member_metadata_failures_total format=conda "virtual_repo=${VB}" "member=${RB}" reason=cap; then
  pass
else
  fail "member failure metric missing" \
    "metrics HTTP ${mst}; $(grep '^ak_virtual_member_metadata_failures_total' "$METRICS" | head -6 | tr '\n' ' ')"
fi

# =============================================================================
# #4145 concurrent remote repodata under a two-buffer budget
# =============================================================================
# 1.10.0 has no #4051 attribution fetch and so no nested reservation: a
# control there. With the hold-and-wait, two of these would each hold 128 MiB
# of the 256 MiB budget and wait forever for 8 MiB more.
begin_test "CONTROL #4145: eight concurrent remote repodata.json GETs under a 256 MiB budget all answer 200 within 30 s"
t0="$(date +%s)"
for i in 1 2 3 4 5 6 7 8; do
  ( curl -s --max-time 30 -o "$WORK/cc${i}.json" -w '%{http_code}' \
      "${BASE_URL}/conda/${R}/noarch/repodata.json" 2>/dev/null || echo 000 ) > "$WORK/cc${i}.st" &
done
wait
elapsed=$(( $(date +%s) - t0 ))
codes=""; good=0
for i in 1 2 3 4 5 6 7 8; do
  c="$(cat "$WORK/cc${i}.st")"; codes+="${c} "
  if [ "$c" = "200" ] && jq -e --arg a "$UP_ALPHA2" '.packages | has($a)' "$WORK/cc${i}.json" >/dev/null 2>&1; then
    good=$((good + 1))
  fi
done
st_after="$(hget "/conda/${H}/noarch/repodata.json" "$WORK/h_after.json")"
if [ "$good" = "8" ] && [ "$elapsed" -le 30 ] && [ "$st_after" = "200" ]; then
  pass
else
  fail "concurrent remote repodata stalled or failed" "statuses: ${codes}; complete bodies=${good}; ${elapsed}s; hosted afterwards HTTP ${st_after}"
fi

end_suite
