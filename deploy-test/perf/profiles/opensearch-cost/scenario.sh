#!/usr/bin/env bash
# =============================================================================
# profiles/opensearch-cost/scenario.sh — GEN=bash  (Phase 2b, search-index cost)
# =============================================================================
# Profiles OpenSearch component cost as a function of stored ARTIFACT COUNT.
# For each rung in COUNTS: DB-direct-seed COUNT artifacts (seed.sh), delete the
# OpenSearch `artifacts` index for a clean count, then:
#   INGEST phase  — POST /api/v1/admin/reindex (full O(N) bulk index) while
#                   sampling the OpenSearch + backend containers -> ingest cores.
#   INDEX size    — read the artifacts index store bytes + doc count.
#   QUERY phase   — fire a fixed search-query mix for QUERY_SECS at
#                   QUERY_CONCURRENCY while sampling -> steady-state query cores.
# Cores/RSS via host-side cgroup cpu.stat accounting (same method as scan-cost),
# so it works on the shell-less backend and captures OpenSearch JVM CPU exactly.
#
# HEADLINE (scenario-written): results/opensearch-cost/opensearch-cost.{json,md}
# — per-count OpenSearch cores pk/mean (ingest + query, separately), RSS, index
# bytes, docs. The shared harness still emits the standard metrics.json/report.md.
#
# Inputs (run.sh exports): BASE_URL, ADMIN_USER, ADMIN_PASS, ADMIN_TOKEN (after
#   auth_admin), RUN_ID, PERF_WORK_DIR, RAW_LOG, ITER, BACKEND_CONTAINER,
#   DB_CONTAINER. COMMON_SH -> corpus tests/lib/common.sh. Knobs from manifest:
#   COUNTS, SEED_REPOS, SEED_FORMAT, QUERY_SECS, QUERY_CONCURRENCY,
#   REINDEX_TIMEOUT, STATS_HZ.
# =============================================================================
set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(cd "${SCENARIO_DIR}/../.." && pwd)"
RESULTS="${PERF_DIR}/results/opensearch-cost"
mkdir -p "$RESULTS"
SEED_SH="${PERF_DIR}/harness/lib/seed.sh"

# shellcheck disable=SC1090
source "${COMMON_SH:?set COMMON_SH}"
WORK_DIR="${PERF_WORK_DIR:?set PERF_WORK_DIR}"; mkdir -p "$WORK_DIR"
auth_admin >/dev/null 2>&1 || { echo "opensearch-cost: auth failed at ${BASE_URL}" >&2; exit 1; }
: > "$RAW_LOG"

STATS_HZ="${STATS_HZ:-1}"
COUNTS="${COUNTS:-10000 100000 500000}"
SEED_REPOS="${SEED_REPOS:-10}"
SEED_FORMAT="${SEED_FORMAT:-generic}"
QUERY_SECS="${QUERY_SECS:-30}"
QUERY_CONCURRENCY="${QUERY_CONCURRENCY:-4}"
REINDEX_TIMEOUT="${REINDEX_TIMEOUT:-1200}"
SEED_PREFIX="osperf"

# --- discover the opensearch container ---------------------------------------
SLOT="${BACKEND_CONTAINER#ak-perf}"; SLOT="${SLOT%-backend}"
OS_CONTAINER="ak-dtf${SLOT}-opensearch"
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$OS_CONTAINER"; then
  alt="$(docker ps --filter "label=com.docker.compose.project=ak-perf${SLOT}" \
         --filter "label=com.docker.compose.service=opensearch" --format '{{.Names}}' 2>/dev/null | head -1)"
  [ -n "$alt" ] && OS_CONTAINER="$alt"
fi
OS_FOUND=0; docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$OS_CONTAINER" && OS_FOUND=1
echo "opensearch-cost: backend=${BACKEND_CONTAINER} os=${OS_CONTAINER} (found=${OS_FOUND})" >&2
[ "$OS_FOUND" = "1" ] || { echo "opensearch-cost: FATAL opensearch container not found" >&2;
  jq -n '{profile:"opensearch-cost",status:"BLOCKED",reason:"opensearch container not found",rungs:[]}' > "${RESULTS}/opensearch-cost.json"; exit 1; }

# --- OpenSearch REST via docker exec (curl is in the image; no host port) -----
os() { docker exec "$OS_CONTAINER" curl -s --max-time 30 "$@" 2>/dev/null; }
os_doc_count() { os "http://localhost:9200/artifacts/_count" | jq -r '.count // 0' 2>/dev/null || echo 0; }
os_index_bytes() {
  # force segments to disk, let the merge/flush settle, then read the store size.
  # Take the max over two reads so a mid-flush undercount doesn't win.
  os -X POST "http://localhost:9200/artifacts/_refresh" >/dev/null 2>&1
  os -X POST "http://localhost:9200/artifacts/_flush?wait_if_ongoing=true" >/dev/null 2>&1
  sleep 2
  local b1 b2 b
  b1="$(os "http://localhost:9200/artifacts/_stats/store" | jq -r '._all.primaries.store.size_in_bytes // 0' 2>/dev/null)"
  b2="$(os "http://localhost:9200/_cat/indices/artifacts?h=store.size&bytes=b" | tr -d ' \n')"
  case "$b1" in ''|*[!0-9]*) b1=0;; esac; case "$b2" in ''|*[!0-9]*) b2=0;; esac
  b=$(( b1 > b2 ? b1 : b2 ))
  [ "$b" -eq 0 ] && b="$(docker exec "$OS_CONTAINER" du -sb /usr/share/opensearch/data 2>/dev/null | awk '{print $1}')"
  echo "${b:-0}"
}
os_delete_artifacts_index() { os -X DELETE "http://localhost:9200/artifacts" >/dev/null 2>&1 || true; }

# --- host-side cgroup sampler (proven in scan-cost) --------------------------
start_sampler() {
  local out="$1"; : > "$out"
  local conts=("$OS_CONTAINER" "$BACKEND_CONTAINER")
  local names=() cpaths=() mpaths=() c pid cg base
  for c in "${conts[@]}"; do
    pid="$(docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null)"; { [ -z "$pid" ] || [ "$pid" = "0" ]; } && continue
    cg="$(awk -F: '/^0::/{print $3}' "/proc/${pid}/cgroup" 2>/dev/null)"; base="/sys/fs/cgroup${cg}"
    [ -f "${base}/cpu.stat" ] || continue
    names+=("$c"); cpaths+=("${base}/cpu.stat"); mpaths+=("${base}/memory.current")
  done
  ( while :; do
      local now i u m; now="$(date +%s%3N)"
      for i in "${!names[@]}"; do
        u="$(awk '/usage_usec/{print $2}' "${cpaths[$i]}" 2>/dev/null)"; m="$(cat "${mpaths[$i]}" 2>/dev/null)"
        [ -n "$u" ] && echo "${now} ${names[$i]} ${u} ${m:-0}" >> "$out"
      done
      sleep "$STATS_HZ"
    done ) >/dev/null 2>&1 &
  echo $!
}
stop_sampler() { local pid="$1"; [ -n "$pid" ] && kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true; }
# reduce -> "cores_peak cores_mean rss_peak_bytes samples"
reduce_container() {
  local f="$1" cont="$2"
  awk -v c="$cont" '
    $2==c { t=$1/1000.0; u=$3; m=$4+0; if(m>rpk)rpk=m;
      if(seen){ dt=t-pt; du=u-pu; if(dt>0){ cr=(du/1e6)/dt; if(cr>cpk)cpk=cr } } else { u0=u; t0=t; seen=1 }
      un=u; tn=t; pt=t; pu=u; n++ }
    END{ if(n==0){print "0 0 0 0"; exit}
      mean=(tn>t0)?((un-u0)/1e6)/(tn-t0):0; printf "%.3f %.3f %.0f %d", cpk, mean, rpk, n }' "$f"
}

# --- search query mix (drives OpenSearch query CPU) --------------------------
QTERMS=("$SEED_PREFIX" "bin" "seed" "1.0" "artifact" "generic")
# drives the search load for <seconds> at <concurrency>, appending one
# "<http_code> <time_total>" line per request to <raw-out>. Caller derives the
# request/error counts from the raw file (no process-substitution capture).
run_queries_for() {
  local secs="$1" conc="$2" raw="$3"; : > "$raw"
  local end=$(( $(date +%s) + secs )) w
  for w in $(seq 1 "$conc"); do
    ( while [ "$(date +%s)" -lt "$end" ]; do
        local term="${QTERMS[$(( RANDOM % ${#QTERMS[@]} ))]}" out
        out="$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 20 \
          -H "$(auth_header)" "${BASE_URL}/api/v1/search/quick?q=${term}&limit=20" 2>/dev/null || echo '000 0')"
        echo "$out" >> "$raw"
      done ) &
  done
  wait
}

RUNGS_JSON="[]"
append_rung() { RUNGS_JSON="$(jq -c --argjson r "$1" '. + [$r]' <<<"$RUNGS_JSON")"; }

# =============================================================================
# Scale-rung sweep
# =============================================================================
for COUNT in $COUNTS; do
  echo "opensearch-cost: === rung count=${COUNT} ===" >&2
  # 1. seed COUNT artifacts (idempotent reseed of this prefix -> DB holds exactly COUNT)
  bash "$SEED_SH" --db-container "$DB_CONTAINER" --count "$COUNT" --repos "$SEED_REPOS" \
       --format "$SEED_FORMAT" --prefix "$SEED_PREFIX" --run-id "$RUN_ID" >&2 2>&1 \
    || { echo "opensearch-cost: seed failed at count=${COUNT}" >&2; continue; }

  # 2. clean OpenSearch artifacts index so doc count reflects exactly this rung
  os_delete_artifacts_index

  # 3. INGEST phase: bulk reindex while sampling OpenSearch + backend
  local_sfile="${WORK_DIR}/stats-ingest-${COUNT}.jsonl"
  spid="$(start_sampler "$local_sfile")"
  t0="$(date +%s.%N)"
  # reindex is synchronous server-side; give curl the full budget. If the build
  # spawns it async, the doc-count poll below covers the remaining window.
  reidx_code="$(curl -s -o "${WORK_DIR}/reindex-${COUNT}.json" -w '%{http_code}' --max-time "$REINDEX_TIMEOUT" \
    -X POST -H "$(auth_header)" "${BASE_URL}/api/v1/admin/reindex" 2>/dev/null || echo 000)"
  # wait for the index to reach COUNT docs (covers sync + async)
  waited=0; docs=0
  while [ "$waited" -lt "$REINDEX_TIMEOUT" ]; do
    docs="$(os_doc_count)"
    [ "${docs:-0}" -ge "$COUNT" ] && break
    sleep "$STATS_HZ"; waited=$(( waited + STATS_HZ ))
  done
  t1="$(date +%s.%N)"
  stop_sampler "$spid"
  ingest_s="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')"
  ing_os="$(reduce_container "$local_sfile" "$OS_CONTAINER")"; ing_be="$(reduce_container "$local_sfile" "$BACKEND_CONTAINER")"
  read -r io_pk io_mn io_rss io_n <<<"$ing_os"; read -r ib_pk ib_mn ib_rss ib_n <<<"$ing_be"
  idx_bytes="$(os_index_bytes)"; docs="$(os_doc_count)"
  echo "opensearch-cost: [count=${COUNT}] INGEST reindex_http=${reidx_code} docs=${docs} ingest_s=${ingest_s} os_cores_pk=${io_pk} os_cores_mn=${io_mn} os_rss=$(( ${io_rss:-0}/1048576 ))MiB index=$(( ${idx_bytes:-0}/1048576 ))MiB" >&2

  # 4. QUERY phase: steady-state search load while sampling
  qsfile="${WORK_DIR}/stats-query-${COUNT}.jsonl"; qraw="${WORK_DIR}/qraw-${COUNT}.log"
  qpid="$(start_sampler "$qsfile")"
  qt0="$(date +%s.%N)"
  run_queries_for "$QUERY_SECS" "$QUERY_CONCURRENCY" "$qraw"
  q_count="$(wc -l < "$qraw" 2>/dev/null | tr -d ' ')"; q_count="${q_count:-0}"
  q_err="$(awk '$1<200||$1>=300{e++} END{print e+0}' "$qraw" 2>/dev/null)"; q_err="${q_err:-0}"
  qt1="$(date +%s.%N)"
  stop_sampler "$qpid"
  q_elapsed="$(awk -v a="$qt0" -v b="$qt1" 'BEGIN{printf "%.2f", b-a}')"
  q_os="$(reduce_container "$qsfile" "$OS_CONTAINER")"; read -r qo_pk qo_mn qo_rss qo_n <<<"$q_os"
  q_p="$(awk '{printf "%.1f\n",$2*1000}' "$qraw" 2>/dev/null | sort -n | awk '{a[NR]=$1} END{if(NR==0){print "0 0";exit} p50=a[int(0.5*(NR-1))+1]; p95=a[int(0.95*(NR-1))+1]; printf "%.1f %.1f",p50,p95}')"
  read -r q_p50 q_p95 <<<"$q_p"
  q_qps="$(awk -v n="$q_count" -v e="$q_elapsed" 'BEGIN{printf "%.1f",(e>0)?n/e:0}')"
  # feed a couple of Layer-A lines so the standard harness metrics build
  awk 'NR<=50{printf "sweep 1 generic 0 %s %s 0\n",$1,$2}' "$qraw" >> "$RAW_LOG" 2>/dev/null || true
  echo "opensearch-cost: [count=${COUNT}] QUERY qps=${q_qps} p50=${q_p50}ms p95=${q_p95}ms os_cores_pk=${qo_pk} os_cores_mn=${qo_mn} os_rss=$(( ${qo_rss:-0}/1048576 ))MiB errs=${q_err}" >&2

  append_rung "$(jq -n \
    --argjson count "$COUNT" --argjson docs "${docs:-0}" --argjson idx "${idx_bytes:-0}" \
    --argjson ingest_s "$ingest_s" --argjson io_pk "${io_pk:-0}" --argjson io_mn "${io_mn:-0}" --argjson io_rss "${io_rss:-0}" \
    --argjson ib_pk "${ib_pk:-0}" --argjson ib_mn "${ib_mn:-0}" \
    --argjson q_qps "$q_qps" --argjson q_p50 "$q_p50" --argjson q_p95 "$q_p95" \
    --argjson qo_pk "${qo_pk:-0}" --argjson qo_mn "${qo_mn:-0}" --argjson qo_rss "${qo_rss:-0}" \
    --argjson q_err "${q_err:-0}" --argjson q_count "${q_count:-0}" \
    '{artifact_count:$count, indexed_docs:$docs, index_bytes:$idx,
      ingest:{ duration_s:$ingest_s, opensearch:{cpu_cores_peak:$io_pk,cpu_cores_mean:$io_mn,rss_bytes_peak:$io_rss},
               backend:{cpu_cores_peak:$ib_pk,cpu_cores_mean:$ib_mn} },
      query:{ qps:$q_qps, latency_ms:{p50:$q_p50,p95:$q_p95}, requests:$q_count, errors:$q_err,
              opensearch:{cpu_cores_peak:$qo_pk,cpu_cores_mean:$qo_mn,rss_bytes_peak:$qo_rss} }}')"
done

# =============================================================================
# Headline side-artifact
# =============================================================================
jq -n --arg image "${BACKEND_IMAGE:-unknown}" --arg version "${VERSION:-unknown}" --arg run_id "$RUN_ID" \
  --arg os "$OS_CONTAINER" --argjson rungs "$RUNGS_JSON" \
  '{profile:"opensearch-cost", status:"OK", backend_image:$image, version:$version, run_id:$run_id,
    opensearch_container:$os, rungs:$rungs,
    note:"cores from host-side cgroup cpu.stat usage_usec (exact CPU-seconds/sec). INGEST = full /admin/reindex bulk of N docs (the O(N) cutover cost); per-artifact create indexing is a separate cheap async single-doc op not measured here. index_bytes = OpenSearch artifacts-index store size. QUERY = steady-state /search/quick load. OpenSearch cost scales with stored COUNT (index bytes + JVM working set), not rate."
  }' > "${RESULTS}/opensearch-cost.json"

{
  echo "# PTF opensearch-cost — OpenSearch resource cost vs stored artifact count"
  echo
  echo "backend image: \`${BACKEND_IMAGE:-unknown}\`  |  opensearch: \`${OS_CONTAINER}\`"
  echo
  echo "## OpenSearch cost per artifact count (cores = CPU-seconds/sec, host cgroup)"
  echo
  echo "| artifact count | indexed docs | index bytes | ingest s | ingest OS cores pk/mean | ingest OS RSS | query qps | query OS cores pk/mean | query OS RSS | query p95 |"
  echo "|---|---|---|---|---|---|---|---|---|---|"
  jq -r '.rungs[] | "| \(.artifact_count) | \(.indexed_docs) | \((.index_bytes/1048576)|floor)MiB | \(.ingest.duration_s) | \(.ingest.opensearch.cpu_cores_peak)/\(.ingest.opensearch.cpu_cores_mean) | \((.ingest.opensearch.rss_bytes_peak/1048576)|floor)MiB | \(.query.qps) | \(.query.opensearch.cpu_cores_peak)/\(.query.opensearch.cpu_cores_mean) | \((.query.opensearch.rss_bytes_peak/1048576)|floor)MiB | \(.query.latency_ms.p95)ms |"' \
    "${RESULTS}/opensearch-cost.json"
  echo
  echo "_INGEST = full /admin/reindex bulk of N docs (the O(N) cutover cost); steady per-upload indexing is a separate cheap async single-doc op. index_bytes = artifacts-index store size (grows with COUNT). QUERY = steady-state /search/quick load. OpenSearch cost is COUNT-driven (index size + JVM working set), not rate-driven._"
} > "${RESULTS}/opensearch-cost.md"

echo "opensearch-cost: wrote ${RESULTS}/opensearch-cost.{json,md} ($(jq '.rungs|length' "${RESULTS}/opensearch-cost.json") rungs)" >&2
