#!/usr/bin/env bash
# =============================================================================
# tiers/conda-virtual-shards/oracle.sh: a virtual conda channel serves every
#   shard it lists, large upstream shard indexes, and the bounded virtual
#   merge (artifact-keeper#4607 / #4612 / #4608)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda-sharded
# limits.conda-merge-gate logging.json-file` with RATE_LIMIT_ENABLED=false,
# CONDA_VIRTUAL_MAX_CONCURRENT_MERGES=1 and CONDA_VIRTUAL_MERGE_QUEUE_SECS=2,
# and exported BASE_URL, DB_CONTAINER, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, COMMON_SH. The mock (fixtures of conda-sharded-remote-virtual)
# serves upstream channels at http://172.16.<slot>.71/<channel>/; it is read
# with `docker exec`, and every `.msgpack.zst` the registry serves is decoded
# by cep16.py inside that container.
#
# Topology (keys suffixed per run):
#   C  remote -> /clean/  (dtfsh-alpha, dtfsh-beta, dtfsh-gone: a shard with no
#                          record and one `removed` entry)      VC virtual [C]
#   G  remote -> /big/    (9.7 MiB shard index)                 VG virtual [G]
#   X  remote -> /huge/   (70.4 MiB shard index)                VX virtual [X]
#   S  remote -> /slow/   (each document 3 s late)              VS virtual [S]
#
# Gates (1.11.0; RED on 1.10.0, where a remote or virtual channel had no CEP-16
# documents and no merge gate existed):
#   #4607  every shard VC's index lists answers 200 with the bytes of its
#          address; the removed-only shard decodes to no record and one
#          `removed` entry.
#   #4612  G's and VG's indexes (9.7 MiB upstream) are served with the
#          upstream's names; a shard through G is served. X and VX answer 404
#          "publishes no CEP-16 shard index ... use repodata.json" and the
#          backend logs the ceiling.
#   #4608  20 parallel GETs of VC's repodata.json share one merge: one ETag,
#          ak_conda_virtual_merge_cache_misses_total{kind="repodata"} and
#          ..._cache_hits_total{kind="repodata"} move; a later GET is a cache
#          hit. While VS's merge holds the only slot, VG's repodata.json
#          answers 503 with Retry-After naming the limit, and
#          ak_conda_virtual_merge_rejected_total{reason="queue"} counts it.
# CONTROL (both images): VC's repodata.json carries the upstream records and
#   revalidates with 304 on its ETag; X's repodata.json (the fallback a client
#   takes) carries the upstream records; VS's repodata.json is eventually 200.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
MOCK="ak-dtf${SLOT}-mock-conda-sharded"
BACKEND="ak-dtf${SLOT}-backend"
UP="http://172.16.${SLOT}.71"

C="cvs-clean-${SUF}";  VC="cvs-vclean-${SUF}"
G="cvs-big-${SUF}";    VG="cvs-vbig-${SUF}"
X="cvs-huge-${SUF}";   VX="cvs-vhuge-${SUF}"
S="cvs-slow-${SUF}";   VS="cvs-vslow-${SUF}"
IDX="/noarch/repodata_shards.msgpack.zst"
PARALLEL=20

WORK="$(mktemp -d -t dtf-cvs-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
# fetch <tag> <path> [curl args...] -> HTTP status; body $WORK/<tag>.body,
# headers $WORK/<tag>.hdr (raw bytes, no --compressed)
fetch() {
  local tag="$1" path="$2"; shift 2
  curl -s --max-time 120 -D "$WORK/${tag}.hdr" -o "$WORK/${tag}.body" -w '%{http_code}' \
    "$@" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
header() {
  { grep -i "^$2:" "$WORK/$1.hdr" 2>/dev/null || true; } | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}
body_text() { head -c "${2:-300}" "$WORK/$1.body" 2>/dev/null | tr -dc '[:print:]' || true; }
decode() {
  docker exec -i "$MOCK" python3 /app/cep16.py < "$WORK/$1.body" > "$WORK/$1.json" 2>/dev/null \
    && jq -e 'has("doc")' "$WORK/$1.json" >/dev/null 2>&1
}
jqd() { jq -r "$2" "$WORK/$1.json" 2>/dev/null || true; }
mock_get() {
  docker exec "$MOCK" python3 -c \
    "import urllib.request,sys; sys.stdout.write(urllib.request.urlopen('http://127.0.0.1'+sys.argv[1]).read().decode())" \
    "$1" 2>/dev/null || true
}
addr() { jq -r --arg c "$1" --arg n "$2" '.[$c].shards[$n] // empty' "$WORK/manifest.json" 2>/dev/null || true; }
sha_of() { { sha256sum "$WORK/$1.body" 2>/dev/null || echo none; } | cut -d' ' -f1; }

METRICS="$WORK/metrics.txt"
scrape_metrics() {
  curl -s --max-time 30 -o "$METRICS" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000
}
# metric_sum <name> <label=value>... -> sum of every matching sample ("" if none)
metric_sum() {
  local name="$1"; shift
  python3 -I - "$METRICS" "$name" "$@" <<'PY' || true
import re, sys
path, name, wanted = sys.argv[1], sys.argv[2], sys.argv[3:]
want = dict(w.split("=", 1) for w in wanted)
total, seen = 0.0, False
for line in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r'^([A-Za-z_:][\w:]*)(?:\{(.*)\})?\s+(\S+)', line)
    if not m or m.group(1) != name:
        continue
    labels = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', m.group(2) or ""))
    if all(labels.get(k) == v for k, v in want.items()):
        total += float(m.group(3))
        seen = True
print(f"{total:g}" if seen else "")
PY
}
ge() { [ -n "$1" ] && python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)' "$1" "$2"; }

begin_suite "conda-virtual-shards (#4607 #4612 #4608)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, mock manifest, remotes and virtuals"
auth_admin
setup_err=""
mock_get /__manifest > "$WORK/manifest.json"
big_bytes="$(jq -r '.big.index_bytes // 0' "$WORK/manifest.json" 2>/dev/null || echo 0)"
huge_bytes="$(jq -r '.huge.index_bytes // 0' "$WORK/manifest.json" 2>/dev/null || echo 0)"
# The fixture's premise: big is past the 8 MiB first-try tier and under the
# 64 MiB ceiling; huge is past the ceiling.
if ! [ "$big_bytes" -gt 8388608 ] 2>/dev/null || ! [ "$big_bytes" -lt 67108864 ] 2>/dev/null \
   || ! [ "$huge_bytes" -gt 67108864 ] 2>/dev/null; then
  setup_err+="mock index sizes off (big=${big_bytes} huge=${huge_bytes}); "
fi
for pair in "$C:clean" "$G:big" "$X:huge" "$S:slow"; do
  create_repo "${pair%%:*}" conda remote "${UP}/${pair#*:}" || setup_err+="create remote ${pair#*:}; "
done
for pair in "$VC:$C" "$VG:$G" "$VX:$X" "$VS:$S"; do
  create_repo "${pair%%:*}" conda virtual || setup_err+="create virtual ${pair%%:*}; "
  api_post "/api/v1/repositories/${pair%%:*}/members" "{\"member_key\":\"${pair#*:}\"}" >/dev/null \
    || setup_err+="add ${pair#*:} to ${pair%%:*}; "
done
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

A_ALPHA="$(addr clean dtfsh-alpha)"
A_BETA="$(addr clean dtfsh-beta)"
A_GONE="$(addr clean dtfsh-gone)"
A_BIG_ALPHA="$(addr big dtfsh-alpha)"

# =============================================================================
# CONTROLS (true on both images)
# =============================================================================
begin_test "CONTROL: the virtual's repodata.json carries the upstream records and revalidates with 304"
st1="$(fetch vc_rd "/conda/${VC}/noarch/repodata.json")"
etag="$(header vc_rd ETag)"
st2="$(fetch vc_rd304 "/conda/${VC}/noarch/repodata.json" -H "If-None-Match: ${etag}")"
if [ "$st1" = "200" ] && [ -n "$etag" ] && [ "$st2" = "304" ] \
   && jq -e '.packages | has("dtfsh-alpha-2.0-0.tar.bz2") and has("dtfsh-beta-3.0-0.tar.bz2")' "$WORK/vc_rd.body" >/dev/null 2>&1; then
  pass
else
  fail "virtual ${VC} repodata.json or its revalidation is not as before" \
    "HTTP ${st1} ETag=[${etag}] keys=$(jq -c '.packages|keys' "$WORK/vc_rd.body" 2>/dev/null); If-None-Match HTTP ${st2}"
fi

begin_test "CONTROL: over a 70 MiB shard index, repodata.json (the client's fallback) still serves the upstream records"
st="$(fetch x_rd "/conda/${X}/noarch/repodata.json")"
if [ "$st" = "200" ] && jq -e '.packages | has("dtfsh-alpha-2.0-0.tar.bz2")' "$WORK/x_rd.body" >/dev/null 2>&1; then
  pass
else
  fail "remote ${X} repodata.json lost the upstream records" "HTTP ${st}: $(body_text x_rd 200)"
fi

# =============================================================================
# #4607: every shard the virtual lists is served, the removed-only one too
# =============================================================================
begin_test "#4607: the virtual's index lists the upstream shards, the removed-only one included"
st="$(fetch vc_idx "/conda/${VC}${IDX}")"
if [ "$st" = "200" ] && decode vc_idx \
   && [ "$(jq -c '.doc.shards | keys' "$WORK/vc_idx.json")" = '["dtfsh-alpha","dtfsh-beta","dtfsh-gone"]' ] \
   && [ "$(jqd vc_idx '.doc.shards["dtfsh-gone"].bin')" = "$A_GONE" ]; then
  pass
else
  fail "virtual ${VC} does not list the upstream shards" \
    "HTTP ${st}: $(body_text vc_idx 200) names=$(jq -c '.doc.shards // {} | keys' "$WORK/vc_idx.json" 2>/dev/null)"
fi

begin_test "#4607: every shard the virtual lists answers 200 with its address's bytes; the removed-only shard decodes to one removed entry"
detail=""
for pair in "alpha:${A_ALPHA}" "beta:${A_BETA}" "gone:${A_GONE}"; do
  name="${pair%%:*}"; a="${pair#*:}"
  st="$(fetch "vc_${name}" "/conda/${VC}/noarch/shards/${a}.msgpack.zst")"
  if [ "$st" != "200" ] || [ "$(sha_of "vc_${name}")" != "$a" ]; then
    detail+="dtfsh-${name} HTTP ${st} $(body_text "vc_${name}" 160); "
  fi
done
if [ -z "$detail" ] && decode vc_gone \
   && [ "$(jq -c '[(.doc.packages | length), (.doc["packages.conda"] | length), .doc.removed]' "$WORK/vc_gone.json")" = '[0,0,["dtfsh-gone-1.0-0.tar.bz2"]]' ]; then
  pass
else
  fail "virtual ${VC} does not serve every shard it lists" \
    "${detail}gone decoded=$(jq -c '.doc // .error' "$WORK/vc_gone.json" 2>/dev/null)"
fi

# =============================================================================
# #4612: a 9.7 MiB upstream index is served; a 70 MiB one is a clean 404
# =============================================================================
begin_test "#4612: a remote and a virtual over a 9.7 MiB upstream shard index serve it (was 502 past 8 MiB)"
st1="$(fetch g_idx "/conda/${G}${IDX}")"
st2="$(fetch vg_idx "/conda/${VG}${IDX}")"
st3="$(fetch g_alpha "/conda/${G}/noarch/shards/${A_BIG_ALPHA}.msgpack.zst")"
n1=""; n2=""
if [ "$st1" = "200" ] && decode g_idx; then n1="$(jqd g_idx '.doc.shards | length')"; fi
if [ "$st2" = "200" ] && decode vg_idx; then n2="$(jqd vg_idx '.doc.shards | length')"; fi
if [ -n "$n1" ] && [ "$n1" -gt 200000 ] 2>/dev/null && [ "$n1" = "$n2" ] \
   && [ "$(jqd g_idx '.doc.shards["dtfsh-alpha"].bin')" = "$A_BIG_ALPHA" ] \
   && [ "$(jqd vg_idx '.doc.shards["dtfsh-alpha"].bin')" = "$A_BIG_ALPHA" ] \
   && [ "$st3" = "200" ] && [ "$(sha_of g_alpha)" = "$A_BIG_ALPHA" ]; then
  pass
else
  fail "a ${big_bytes}-byte upstream shard index is not served" \
    "remote HTTP ${st1} names=${n1:-?} $(body_text g_idx 200); virtual HTTP ${st2} names=${n2:-?} $(body_text vg_idx 200); shard HTTP ${st3}"
fi

begin_test "#4612: past the 64 MiB ceiling the remote and the virtual answer 404 'use repodata.json', never 502, and the ceiling is logged"
st1="$(fetch x_idx "/conda/${X}${IDX}")"
st2="$(fetch vx_idx "/conda/${VX}${IDX}")"
logged="$(docker logs "$BACKEND" 2>&1 | grep -c "exceeds the shard-index ceiling" || true)"
if [ "$st1" = "404" ] && grep -q "publishes no CEP-16 shard index" "$WORK/x_idx.body" \
   && [ "$st2" = "404" ] && grep -q "publishes no CEP-16 shard index" "$WORK/vx_idx.body" \
   && [ "${logged:-0}" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "a ${huge_bytes}-byte upstream shard index is not treated as 'no shard index'" \
    "remote HTTP ${st1}: $(body_text x_idx 200); virtual HTTP ${st2}: $(body_text vx_idx 200); ceiling log lines=${logged}"
fi

# =============================================================================
# #4608: one shared merge, one ETag, metrics; 503 + Retry-After past the queue
# =============================================================================
begin_test "#4608: ${PARALLEL} parallel GETs of a virtual's repodata.json share one merge and one ETag; the merge metrics move"
scrape_metrics >/dev/null
miss0="$(metric_sum ak_conda_virtual_merge_cache_misses_total kind=repodata)"
hit0="$(metric_sum ak_conda_virtual_merge_cache_hits_total kind=repodata)"
# A fresh document shape: the .json.zst encoding has never been merged.
for i in $(seq 1 "$PARALLEL"); do
  fetch "par_${i}" "/conda/${VC}/noarch/repodata.json.zst" > "$WORK/par_${i}.st" &
done
wait
codes="$(for f in "$WORK"/par_*.st; do cat "$f"; echo; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
etags="$(for i in $(seq 1 "$PARALLEL"); do header "par_${i}" ETag; done | sort -u)"
n_etags="$(printf '%s\n' "$etags" | grep -c . || true)"
st_after="$(fetch par_after "/conda/${VC}/noarch/repodata.json.zst")"
st_304="$(fetch par_304 "/conda/${VC}/noarch/repodata.json.zst" -H "If-None-Match: $(header par_after ETag)")"
scrape_metrics >/dev/null
miss1="$(metric_sum ak_conda_virtual_merge_cache_misses_total kind=repodata)"
hit1="$(metric_sum ak_conda_virtual_merge_cache_hits_total kind=repodata)"
hitc="$(metric_sum ak_conda_virtual_merge_cache_hits_total kind=repodata via=cache)"
all200=1
for i in $(seq 1 "$PARALLEL"); do [ "$(cat "$WORK/par_${i}.st")" = "200" ] || all200=0; done
if [ "$all200" = "1" ] && [ "$n_etags" = "1" ] && [ "$st_after" = "200" ] && [ "$st_304" = "304" ] \
   && ge "$miss1" 1 && ge "$hit1" "$(( PARALLEL - 1 ))" && ge "$hitc" 1 \
   && python3 -I -c 'import sys; a=[float(x or 0) for x in sys.argv[1:]]; sys.exit(0 if a[1]-a[0] < 3 else 1)' "${miss0:-0}" "$miss1"; then
  pass
else
  fail "concurrent virtual merges are not shared" \
    "codes: ${codes} distinct ETags=${n_etags}; after HTTP ${st_after}, If-None-Match HTTP ${st_304}; ak_conda_virtual_merge_cache_misses_total{kind=repodata} ${miss0:-absent} -> ${miss1:-absent}; ..._cache_hits_total{kind=repodata} ${hit0:-absent} -> ${hit1:-absent} (via=cache ${hitc:-absent})"
fi

begin_test "#4608: while the only merge slot is held, another virtual's merge is shed with 503 + Retry-After"
scrape_metrics >/dev/null
rej0="$(metric_sum ak_conda_virtual_merge_rejected_total reason=queue)"
fetch vs_rd "/conda/${VS}/noarch/repodata.json" > "$WORK/vs_rd.st" &
slow_pid=$!
sleep 1.5
t0=$(date +%s)
st_shed="$(fetch vg_rd "/conda/${VG}/noarch/repodata.json")"
t1=$(date +%s)
retry="$(header vg_rd Retry-After)"
wait "$slow_pid"
st_slow="$(cat "$WORK/vs_rd.st")"
scrape_metrics >/dev/null
rej1="$(metric_sum ak_conda_virtual_merge_rejected_total reason=queue)"
if [ "$st_shed" = "503" ] && [ -n "$retry" ] && grep -q "CONDA_VIRTUAL_MAX_CONCURRENT_MERGES" "$WORK/vg_rd.body" \
   && ge "$rej1" "$(python3 -I -c 'import sys; print(float(sys.argv[1] or 0) + 1)' "${rej0:-0}")"; then
  pass
else
  fail "a queued virtual merge was not shed with 503" \
    "HTTP ${st_shed} after $((t1 - t0)) s, Retry-After=[${retry}]: $(body_text vg_rd 300); ak_conda_virtual_merge_rejected_total{reason=queue} ${rej0:-absent} -> ${rej1:-absent}"
fi

begin_test "CONTROL: the merge that held the slot completes with the slow upstream's records"
if [ "$st_slow" = "200" ] && jq -e '.packages | has("dtfsh-slow-1.0-0.tar.bz2")' "$WORK/vs_rd.body" >/dev/null 2>&1; then
  pass
else
  fail "the slow virtual's repodata.json did not complete" "HTTP ${st_slow}: $(body_text vs_rd 200)"
fi

end_suite
