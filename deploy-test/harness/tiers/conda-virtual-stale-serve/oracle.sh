#!/usr/bin/env bash
# =============================================================================
# tiers/conda-virtual-stale-serve/oracle.sh: a virtual conda channel merges a
#   subdir once for every encoding, and serves its kept merge while a rebuild
#   runs (artifact-keeper#4879)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda-stale` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, COMMON_SH. The mock
# (fixtures/mock_conda_stale.py) serves http://172.16.<slot>.72/ and is
# controlled with `docker exec`.
#
# Topology (keys suffixed per run):
#   H  local conda repo, one uploaded noarch package (dtfst-hosted 1.0)
#   R  remote -> the mock
#   V  virtual [H, R]
#
# Gates (RED on ak-backend:1.11.4, GREEN with the #4879 fix):
#   one merge   GET V noarch repodata.json, .json.zst and .json.bz2 moves
#               ak_conda_virtual_merge_cache_misses_total{kind="repodata"} by
#               exactly 1 (1.11.4: 3, one merge per encoding).
#   stale serve R's cache TTL is 4 s. Per cycle the mock moves to a new
#               generation that answers 8 s late; once R's cached linux-64
#               repodata has expired, GET V linux-64/repodata.json answers
#               within 3 s with the PREVIOUS generation (1.11.4: waits the
#               8 s rebuild and answers the new one). Gate: at least 2 of 3
#               cycles (scheduler jitter).
#   Warning     a stale answer carries `Warning: 110`, and
#               ak_conda_virtual_merge_cache_hits_total{via="stale"} moves.
# CONTROL (both images): V's noarch repodata.json lists the hosted and the
#   remote records; every encoding answers 200 with the same records; within
#   40 s of each cycle's bump the virtual serves the new generation.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
MOCK="ak-dtf${SLOT}-mock-conda-stale"
UP="http://172.16.${SLOT}.72"

H="cvss-host-${SUF}"
R="cvss-remote-${SUF}"
V="cvss-virt-${SUF}"
HOSTED_PKG="dtfst-hosted-1.0-0.tar.bz2"

MEMBER_TTL=4      # R's cache TTL (s)
UP_DELAY=8        # how late the mock answers after a bump (s)
FAST=3            # a stale answer comes back within this (s)
CYCLES=3
NEED=2            # cycles that must show a stale answer
REFRESH_WAIT=40   # how long a cycle waits for the new generation (s)

WORK="$(mktemp -d -t dtf-cvss-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
# fetch <tag> <path> [curl args...] -> "<status> <seconds>"; body $WORK/<tag>.body,
# headers $WORK/<tag>.hdr
fetch() {
  local tag="$1" path="$2"; shift 2
  curl -s --max-time 90 -D "$WORK/${tag}.hdr" -o "$WORK/${tag}.body" \
    -w '%{http_code} %{time_total}' "$@" "${BASE_URL}${path}" 2>/dev/null || echo "000 0"
}
header() {
  { grep -i "^$2:" "$WORK/$1.hdr" 2>/dev/null || true; } | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}
body_text() { head -c "${2:-300}" "$WORK/$1.body" 2>/dev/null | tr -dc '[:print:]' || true; }
# gen_of <tag> <subdir> -> the upstream generation the document lists ("" if none)
gen_of() {
  jq -r --arg p "dtfst-$2-gen" \
    '[(.packages // {}) | keys[] | select(startswith($p)) | ltrimstr($p) | split("-")[0]] | first // empty' \
    "$WORK/$1.body" 2>/dev/null || true
}
mock_get() {
  docker exec "$MOCK" python3 -c \
    "import urllib.request,sys; sys.stdout.write(urllib.request.urlopen('http://127.0.0.1'+sys.argv[1]).read().decode())" \
    "$1" 2>/dev/null || true
}
lt() { python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) < float(sys.argv[2]) else 1)' "$1" "$2"; }

METRICS="$WORK/metrics.txt"
scrape_metrics() {
  curl -s --max-time 30 -o "$METRICS" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000
}
# metric_sum <name> <label=value>... -> sum of every matching sample (0 if none)
metric_sum() {
  local name="$1"; shift
  python3 -I - "$METRICS" "$name" "$@" <<'PY' || echo 0
import re, sys
path, name, wanted = sys.argv[1], sys.argv[2], sys.argv[3:]
want = dict(w.split("=", 1) for w in wanted)
total = 0.0
for line in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r'^([A-Za-z_:][\w:]*)(?:\{(.*)\})?\s+(\S+)', line)
    if not m or m.group(1) != name:
        continue
    labels = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', m.group(2) or ""))
    if all(labels.get(k) == v for k, v in want.items()):
        total += float(m.group(3))
print(f"{total:g}")
PY
}
misses() { scrape_metrics >/dev/null; metric_sum ak_conda_virtual_merge_cache_misses_total kind=repodata; }
stale_hits() { scrape_metrics >/dev/null; metric_sum ak_conda_virtual_merge_cache_hits_total kind=repodata via=stale; }

begin_suite "conda-virtual-stale-serve (#4879)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, hosted + remote + virtual, one hosted upload"
auth_admin
setup_err=""
create_repo "$H" conda local || setup_err+="create hosted; "
create_repo "$R" conda remote "${UP}/" || setup_err+="create remote; "
create_repo "$V" conda virtual || setup_err+="create virtual; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${H}\"}" >/dev/null || setup_err+="add H to V; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R}\"}" >/dev/null || setup_err+="add R to V; "
bash "${DTF_DIR}/fixtures/conda/build.sh" "$WORK" dtfst-hosted 1.0 0 noarch >/dev/null 2>&1 \
  || setup_err+="build ${HOSTED_PKG}; "
st="$(curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT -H "$(auth_header)" \
  --data-binary "@$WORK/${HOSTED_PKG}" "${BASE_URL}/conda/${H}/noarch/${HOSTED_PKG}" 2>/dev/null || echo 000)"
[ "$st" = "201" ] || [ "$st" = "200" ] || setup_err+="upload -> HTTP ${st} $(head -c 200 "$WORK/put.out" 2>/dev/null); "
[ "$(scrape_metrics)" = "200" ] || setup_err+="metrics endpoint not readable; "
gen0="$(mock_get /__state | jq -r '.generation // empty' 2>/dev/null)"
[ "$gen0" = "1" ] || setup_err+="mock not at generation 1 (state: $(mock_get /__state)); "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# One merge for every encoding of a subdir
# =============================================================================
begin_test "CONTROL: every encoding of the virtual's noarch repodata answers 200 and the plain one lists hosted + remote records"
m0="$(misses)"
read -r st_json _ <<<"$(fetch v_json "/conda/${V}/noarch/repodata.json")"
read -r st_zst _ <<<"$(fetch v_zst "/conda/${V}/noarch/repodata.json.zst")"
read -r st_bz2 _ <<<"$(fetch v_bz2 "/conda/${V}/noarch/repodata.json.bz2")"
m1="$(misses)"
bz2_ok=no
if python3 -I -c 'import bz2,json,sys; d=json.loads(bz2.decompress(open(sys.argv[1],"rb").read())); sys.exit(0 if "dtfst-base-1.0-0.tar.bz2" in d["packages"] else 1)' \
     "$WORK/v_bz2.body" 2>/dev/null; then
  bz2_ok=yes
fi
if [ "$st_json" = "200" ] && [ "$st_zst" = "200" ] && [ "$st_bz2" = "200" ] && [ "$bz2_ok" = "yes" ] \
   && jq -e --arg h "$HOSTED_PKG" '.packages | has($h) and has("dtfst-base-1.0-0.tar.bz2") and has("dtfst-noarch-gen1-1.0-0.tar.bz2")' \
        "$WORK/v_json.body" >/dev/null 2>&1; then
  pass
else
  fail "the virtual's noarch repodata is not served in every encoding" \
    "json HTTP ${st_json} keys=$(jq -c '.packages|keys' "$WORK/v_json.body" 2>/dev/null) zst HTTP ${st_zst} bz2 HTTP ${st_bz2} (decodes with the records: ${bz2_ok})"
fi

begin_test "#4879: repodata.json, .zst and .bz2 of one subdir are ONE merge (merge misses move by 1, not 3)"
delta="$(python3 -I -c 'import sys; print(f"{float(sys.argv[2]) - float(sys.argv[1]):g}")' "${m0:-0}" "${m1:-0}")"
if [ "$delta" = "1" ]; then
  pass
else
  fail "three encodings of one subdir ran ${delta} merges" \
    "ak_conda_virtual_merge_cache_misses_total{kind=\"repodata\"} ${m0} -> ${m1} across GET .json, .json.zst, .json.bz2 (expected +1)"
fi

# =============================================================================
# Stale while revalidate
# =============================================================================
begin_test "setup: remote cache TTL ${MEMBER_TTL} s, prime the virtual's linux-64 merge"
setup_err=""
api_put "/api/v1/repositories/${R}/cache-ttl" "{\"cache_ttl_seconds\":${MEMBER_TTL}}" >/dev/null \
  || setup_err+="set cache TTL; "
read -r st _ <<<"$(fetch prime "/conda/${V}/linux-64/repodata.json")"
[ "$st" = "200" ] && [ "$(gen_of prime linux-64)" = "1" ] \
  || setup_err+="prime: HTTP ${st} gen=[$(gen_of prime linux-64)] $(body_text prime 200); "
if [ -n "$setup_err" ]; then
  infra_fail "stale-serve setup did not complete" "$setup_err"
  end_suite
fi
pass

stale_before="$(stale_hits)"
fast_prev=0
refreshed=0
warned=0
cycle_log=""
gen="1"
for c in $(seq 1 "$CYCLES"); do
  new="$(mock_get "/__bump?delay=${UP_DELAY}" | jq -r '.generation // empty' 2>/dev/null)"
  # Let R's cached linux-64 repodata expire (TTL plus a margin).
  sleep $((MEMBER_TTL + 2))
  read -r st secs <<<"$(fetch "c${c}" "/conda/${V}/linux-64/repodata.json")"
  got="$(gen_of "c${c}" linux-64)"
  warn="$(header "c${c}" Warning)"
  if [ "$st" = "200" ] && [ "$got" = "$gen" ] && lt "$secs" "$FAST"; then
    fast_prev=$((fast_prev + 1))
  fi
  case "$warn" in 110*) warned=$((warned + 1)) ;; esac
  # The rebuild lands: some later request serves the new generation.
  seen=""
  deadline=$((SECONDS + REFRESH_WAIT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    read -r pst _ <<<"$(fetch "c${c}p" "/conda/${V}/linux-64/repodata.json")"
    if [ "$pst" = "200" ] && [ "$(gen_of "c${c}p" linux-64)" = "$new" ]; then
      seen=yes
      break
    fi
    sleep 1
  done
  [ -n "$seen" ] && refreshed=$((refreshed + 1))
  cycle_log+="cycle ${c}: upstream gen ${gen}->${new}, first GET after expiry HTTP ${st} in ${secs}s served gen [${got}] Warning=[${warn}], new gen served within ${REFRESH_WAIT}s: ${seen:-no}; "
  gen="$new"
done
# Leave the mock fast for anything after this.
mock_get "/__bump?delay=0" >/dev/null
stale_after="$(stale_hits)"

begin_test "CONTROL: after each upstream change the virtual serves the new generation within ${REFRESH_WAIT} s"
if [ "$refreshed" -eq "$CYCLES" ]; then
  pass
else
  fail "the virtual did not pick up the new upstream generation" "$cycle_log"
fi

begin_test "#4879: once the member expired, the virtual answers within ${FAST} s with the PREVIOUS merge while it rebuilds (>= ${NEED}/${CYCLES} cycles)"
if [ "$fast_prev" -ge "$NEED" ]; then
  pass
else
  fail "a stale merge was not served during the rebuild (${fast_prev}/${CYCLES} cycles)" \
    "the upstream answers ${UP_DELAY} s late; a request that waits on the rebuild takes that long and gets the new generation. ${cycle_log}"
fi

begin_test "#4879: a stale answer carries Warning: 110 and counts as a via=\"stale\" cache hit"
stale_delta="$(python3 -I -c 'import sys; print(f"{float(sys.argv[2]) - float(sys.argv[1]):g}")' "${stale_before:-0}" "${stale_after:-0}")"
if [ "$warned" -ge 1 ] && python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= 1 else 1)' "$stale_delta"; then
  pass
else
  fail "no stale serve was signalled" \
    "responses with Warning: 110: ${warned}/${CYCLES}; ak_conda_virtual_merge_cache_hits_total{kind=\"repodata\",via=\"stale\"} ${stale_before} -> ${stale_after}"
fi

end_suite
