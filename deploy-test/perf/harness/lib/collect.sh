#!/usr/bin/env bash
# =============================================================================
# perf/harness/lib/collect.sh — PTF 4-layer metric collection
# =============================================================================
# Sourced by run.sh. Owns the capture of the four metric layers (design doc §3)
# and the reduction into ONE normalized per-iteration metrics.json:
#
#   Layer A  client-observed latency/throughput/error  (from the generator's RAW_LOG)
#   Layer B  container CPU%/RSS/IO                       (docker stats @1Hz sampler)
#   Layer C  backend-internal via AK unauth /metrics     (start/end snapshot + @1Hz)
#            + pg_stat_statements hotspot                (docker exec psql)
#   Layer D  storage bytes / dedup                       (volume du ground-truth)
#
# RECON-GROUNDED CAVEATS baked in here (verified against 1.6.2-rc on 2026-07-23):
#   * ak_http_request_duration_seconds is a Prometheus *summary* (count+sum, NO
#     buckets) -> server-side latency is a MEAN (delta sum / delta count), not a
#     p95. Field is backend_internal.http_mean_ms_server. Enabling histogram
#     buckets is a natural blue-side follow-up PTF would immediately consume.
#   * ak_storage_used_bytes / ak_artifacts_total gauges refresh on a scheduler
#     tick and stay 0 during a short run -> Layer D reads storage ground-truth
#     from the docker volume (du, sudo -n fallback), NOT the gauge.
#   * No ak_webhook_* / ak_proxy_cache_* / ak_artifact_upload_size_bytes series
#     are emitted by this build -> those fields are null and the report says n/a.
# =============================================================================

# ---- rig-quiesce guard ------------------------------------------------------
# perf_quiesce_guard <force 0|1> -> 0 = proceed, 1 = refuse.
# Baselines must be captured on a quiesced rig. Samples the 1-min host loadavg
# (plus a 2s idle re-sample to catch a transient spike) and compares against
# QUIESCE_LOADAVG_MAX (default ~0.6*nproc). WARN + refuse unless force=1.
perf_quiesce_guard() {
  local force="${1:-0}"
  local nproc; nproc="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
  local budget="${QUIESCE_LOADAVG_MAX:-$(awk -v n="$nproc" 'BEGIN{printf "%.2f", n*0.6}')}"
  local l1 l2 load
  l1="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)"
  sleep 2
  l2="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)"
  # use the lower of the two samples so a single transient tick doesn't block us
  load="$(awk -v a="$l1" -v b="$l2" 'BEGIN{print (a<b)?a:b}')"
  if awk -v v="$load" -v c="$budget" 'BEGIN{exit !(v>c)}'; then
    echo "!! rig-quiesce guard: 1-min loadavg ${load} > budget ${budget} (nproc=${nproc})." >&2
    echo "!! baselines must be captured quiesced; the current load will bake noise into the reference." >&2
    if [ "$force" = "1" ]; then
      echo ">> --force-baseline set: proceeding on a BUSY rig anyway (baseline may be noisy)." >&2
      return 0
    fi
    echo "!! refusing. Wait for the rig to settle, or re-run with --force-baseline to override." >&2
    return 1
  fi
  echo ">> rig-quiesce guard OK: 1-min loadavg ${load} <= budget ${budget} (nproc=${nproc})."
  return 0
}

# ---- k6 generator path ------------------------------------------------------
# perf_fetch_admin_token <base_url> <user> <pass> -> echoes bearer token.
perf_fetch_admin_token() {
  local base="$1" user="$2" pass="$3" i resp tok
  for i in $(seq 1 15); do
    resp="$(curl -s --max-time 10 -X POST "${base}/api/v1/auth/login" \
      -H 'Content-Type: application/json' \
      -d "{\"username\":\"${user}\",\"password\":\"${pass}\"}" 2>/dev/null)"
    tok="$(printf '%s' "$resp" | jq -r '.token // .access_token // empty' 2>/dev/null)"
    [ -n "$tok" ] && { printf '%s' "$tok"; return 0; }
    sleep 2
  done
  return 1
}

# perf_run_k6 <scenario.js> <summary-out.json> <stdout-log>
# Runs the containerized grafana/k6 generator joined to the slot's compose
# network so it reaches the backend by its in-network service name. The scenario
# writes its normalized Layer-A summary via handleSummary() to /out/summary.json.
# Required env: K6_IMAGE, PERF_NET, K6_TOKEN, BACKEND_INTERNAL_URL, RUN_ID, and
# the workload knobs (CONCURRENCY, REQUESTS_PER_CELL, SWEEP_SIZE_MB, ...).
perf_run_k6() {
  local script="$1" summary="$2" log="$3"
  local outdir; outdir="$(dirname "$summary")"
  : > "$summary"
  # k6 workload knobs derived from the shared manifest so bash and k6 drive a
  # comparable load. VUS = max concurrency in the sweep; ITER = total requests.
  local vus iters
  vus="$(printf '%s\n' $CONCURRENCY | sort -n | tail -1)"; vus="${vus:-8}"
  iters="${K6_ITERATIONS:-$(( ${REQUESTS_PER_CELL:-18} * $(printf '%s\n' $CONCURRENCY | wc -l) ))}"
  # k6's official image runs as its own uid; without --user it cannot write the
  # summary into the host-owned bind mount (permission denied). Run it as the
  # invoking user and make the out dir group/other-writable as belt-and-braces.
  chmod 0777 "$outdir" 2>/dev/null || true
  # per-invocation nonce: the harness calls this once per iteration (warmup + N
  # measured) with the SAME RUN_ID, so upload PATHS must be uniquified per call
  # or the 2nd+ iteration 409s on an already-existing immutable artifact.
  local nonce; nonce="$(date +%s%N)"
  docker run --rm --network "$PERF_NET" \
    --user "$(id -u):$(id -g)" \
    -e BASE_URL="$BACKEND_INTERNAL_URL" \
    -e TOKEN="$K6_TOKEN" \
    -e RUN_ID="$RUN_ID" \
    -e RUN_NONCE="$nonce" \
    -e VUS="$vus" \
    -e ITERATIONS="$iters" \
    -e SIZE_BYTES="$(( ${SWEEP_SIZE_MB:-4} * 1048576 ))" \
    -e THROTTLE_MS="${PERF_THROTTLE_MS:-0}" \
    -v "${outdir}:/out" \
    -v "${script}:/scenario.js:ro" \
    "$K6_IMAGE" run --quiet \
      --summary-trend-stats="avg,min,med,max,p(50),p(90),p(95),p(99)" \
      /scenario.js > "$log" 2>&1 || {
        echo "!! k6 run exited non-zero; tail of output:" >&2; tail -20 "$log" >&2 || true; }
  # k6 wrote /out/summary.json inside the container == ${outdir}/summary.json.
  if [ -f "${outdir}/summary.json" ] && [ "${outdir}/summary.json" != "$summary" ]; then
    mv -f "${outdir}/summary.json" "$summary"
  fi
}

# ---- byte / percent helpers -------------------------------------------------
# to_bytes "50.14MiB" -> integer bytes.  Handles B/kB/KiB/MB/MiB/GB/GiB.
perf_to_bytes() {
  echo "$1" | awk '{
    v=$0; n=v; sub(/[A-Za-z]+$/,"",n); u=v; sub(/^[0-9.]+/,"",u);
    mult=1;
    if(u=="B"||u=="")      mult=1;
    else if(u=="kB")       mult=1000;
    else if(u=="KiB")      mult=1024;
    else if(u=="MB")       mult=1000000;
    else if(u=="MiB")      mult=1048576;
    else if(u=="GB")       mult=1000000000;
    else if(u=="GiB")      mult=1073741824;
    else if(u=="TB")       mult=1000000000000;
    else if(u=="TiB")      mult=1099511627776;
    printf "%.0f", n*mult;
  }'
}

# ---- Layer B: docker stats sampler ------------------------------------------
# perf_start_stats_sampler <out.jsonl> <container...> -> echoes sampler PID.
perf_start_stats_sampler() {
  local out="$1"; shift
  local conts=("$@")
  : > "$out"
  # NB: redirect the background group's stdout OFF the caller's pipe, else a
  # `pid=$(perf_start_stats_sampler ...)` command substitution hangs forever
  # waiting for EOF (the bg loop keeps the pipe's write-end open). The per-tick
  # `>> "$out"` inside still targets the file.
  (
    while :; do
      docker stats --no-stream --format '{{json .}}' "${conts[@]}" 2>/dev/null >> "$out"
      sleep 1
    done
  ) >/dev/null 2>&1 &
  echo $!
}

# ---- Layer C: /metrics sampler ----------------------------------------------
# perf_start_metrics_sampler <url> <out.jsonl> -> echoes sampler PID.
# Each tick extracts just the volatile scalars we peak over (in-flight, pool).
perf_start_metrics_sampler() {
  local url="$1" out="$2"
  : > "$out"
  (
    while :; do
      local txt inflight active max
      txt="$(curl -s --max-time 3 "$url" 2>/dev/null)" || txt=""
      if [ -n "$txt" ]; then
        inflight="$(printf '%s\n' "$txt" | awk '/^ak_http_requests_in_flight/{s+=$NF} END{printf "%d", s+0}')"
        active="$(printf '%s\n' "$txt"  | awk '/^ak_db_pool_connections_active/{print $NF; exit}')"
        max="$(printf '%s\n' "$txt"     | awk '/^ak_db_pool_connections_max/{print $NF; exit}')"
        printf '{"t":%s,"in_flight":%s,"pool_active":%s,"pool_max":%s}\n' \
          "$(date +%s)" "${inflight:-0}" "${active:-0}" "${max:-0}" >> "$out"
      fi
      sleep 1
    done
  ) >/dev/null 2>&1 &
  echo $!
}

perf_stop_sampler() { local pid="$1"; [ -n "$pid" ] && kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true; }

# perf_metrics_snapshot <url> <outfile> — full /metrics text dump.
perf_metrics_snapshot() { curl -s --max-time 5 "$1" -o "$2" 2>/dev/null || : > "$2"; }

# ---- Layer C: pg_stat_statements hotspot ------------------------------------
# perf_pg_reset <db_container>
perf_pg_reset() {
  docker exec "$1" psql -U registry -d artifact_registry -tAc \
    "CREATE EXTENSION IF NOT EXISTS pg_stat_statements; SELECT pg_stat_statements_reset();" >/dev/null 2>&1 || true
}
# perf_pg_snapshot <db_container> <slow_ms> -> JSON {slow_queries,top_query_mean_ms,top_query}
perf_pg_snapshot() {
  local db="$1" slow="${2:-100}"
  local row
  row="$(docker exec "$db" psql -U registry -d artifact_registry -tAF '|' -c \
    "SELECT count(*) FILTER (WHERE mean_exec_time > ${slow}), COALESCE(max(mean_exec_time),0)
       FROM pg_stat_statements;" 2>/dev/null | tr -d ' ')"
  local top
  top="$(docker exec "$db" psql -U registry -d artifact_registry -tAc \
    "SELECT left(regexp_replace(query,'\s+',' ','g'),80) FROM pg_stat_statements
       ORDER BY mean_exec_time DESC LIMIT 1;" 2>/dev/null | head -1)"
  local slowq="${row%%|*}" meanms="${row##*|}"
  [ -z "$slowq" ] && slowq=0
  [ -z "$meanms" ] && meanms=0
  jq -n --argjson sq "${slowq:-0}" --arg mm "${meanms:-0}" --arg tq "${top:-}" \
    '{slow_queries:$sq, top_query_mean_ms:($mm|tonumber), top_query:$tq}'
}

# ---- Layer D: storage ground-truth ------------------------------------------
# perf_storage_bytes <volume_name> — bytes under <mount>/storage (du; sudo -n fallback).
perf_storage_bytes() {
  local vol="$1" mp
  mp="$(docker volume inspect "$vol" -f '{{.Mountpoint}}' 2>/dev/null)"
  [ -z "$mp" ] && { echo ""; return; }
  local b
  b="$(du -sb "${mp}/storage" 2>/dev/null | awk '{print $1}')"
  if [ -z "$b" ]; then
    b="$(sudo -n du -sb "${mp}/storage" 2>/dev/null | awk '{print $1}')"
  fi
  echo "${b:-}"
}

# ---- Prometheus text reducers (for start/end snapshots) ---------------------
# perf_prom_route_delta <startfile> <endfile> <count|sum> <method> <pathmatch>
#   returns delta of ak_http_request_duration_seconds_<count|sum> for the route.
perf_prom_route_delta() {
  local start="$1" end="$2" kind="$3" method="$4" pathm="$5"
  local metric="ak_http_request_duration_seconds_${kind}"
  local s e
  s="$(awk -v m="$metric" -v meth="$method" -v p="$pathm" \
        '$0 ~ "^"m && index($0,"method=\""meth"\"")>0 && index($0,p)>0 {v=$NF} END{printf "%.6f", v+0}' "$start")"
  e="$(awk -v m="$metric" -v meth="$method" -v p="$pathm" \
        '$0 ~ "^"m && index($0,"method=\""meth"\"")>0 && index($0,p)>0 {v=$NF} END{printf "%.6f", v+0}' "$end")"
  awk -v a="$s" -v b="$e" 'BEGIN{d=b-a; if(d<0)d=0; printf "%.6f", d}'
}
# perf_prom_5xx_delta <startfile> <endfile> — delta of sum(ak_http_responses_total{status=5xx}).
perf_prom_5xx_delta() {
  local s e
  s="$(awk '/^ak_http_responses_total/ && /status="5/ {v+=$NF} END{printf "%.0f", v+0}' "$1")"
  e="$(awk '/^ak_http_responses_total/ && /status="5/ {v+=$NF} END{printf "%.0f", v+0}' "$2")"
  awk -v a="$s" -v b="$e" 'BEGIN{d=b-a; if(d<0)d=0; printf "%.0f", d}'
}

# ---- percentile helper ------------------------------------------------------
# perf_pctl : reads numbers on stdin, echoes "p50 p90 p95 p99 max" (nearest-rank).
perf_pctl() {
  sort -n | awk '
    function q(p,  i){ i=int(p*(n-1)/100)+1; if(i<1)i=1; if(i>n)i=n; return a[i] }
    {a[NR]=$1}
    END{ n=NR; if(n==0){print "0 0 0 0 0"; exit}
      printf "%.3f %.3f %.3f %.3f %.3f", q(50),q(90),q(95),q(99), a[n] }'
}

# ---- Layer B reducer: docker-stats.jsonl for ONE container ------------------
# perf_layerB_container <stats.jsonl> <container> -> "cpu_peak cpu_mean rss_peak rss_mean blkr blkw"
perf_layerB_container() {
  local jsonl="$1" cont="$2"
  jq -r --arg c "$cont" 'select(.Name==$c) | [.CPUPerc, .MemUsage, .BlockIO] | @tsv' "$jsonl" 2>/dev/null | \
  awk -F'\t' '
    function tb(s,   n,u,m){ n=s; sub(/[A-Za-z]+$/,"",n); u=s; sub(/^[0-9.]+/,"",u);
      m=1; if(u=="kB")m=1000; else if(u=="KiB")m=1024; else if(u=="MB")m=1000000;
      else if(u=="MiB")m=1048576; else if(u=="GB")m=1000000000; else if(u=="GiB")m=1073741824;
      else if(u=="TB")m=1e12; else if(u=="TiB")m=1099511627776; else if(u=="B"||u=="")m=1;
      return n*m }
    { cpu=$1; sub(/%$/,"",cpu); cpu+=0;
      split($2,mu," / "); rss=tb(mu[1]);
      split($3,bio," / "); r=tb(bio[1]); w=tb(bio[2]);
      cnt++; csum+=cpu; if(cpu>cpk)cpk=cpu; if(rss>rpk)rpk=rss; rsum+=rss;
      if(r>rr)rr=r; if(w>ww)ww=w; }
    END{ if(cnt==0){print "0 0 0 0 0 0"; exit}
      printf "%.1f %.1f %.0f %.0f %.0f %.0f", cpk, csum/cnt, rpk, rsum/cnt, rr, ww }'
}

# ---- the normalized metrics.json builder ------------------------------------
# Reads its inputs from the environment (run.sh exports them). Writes <out>.
perf_build_metrics_json() {
  local out="$1"

  local total errors err_rate up_bytes
  local p50 p90 p95 p99 pmax
  local t50 t90 t95 t99 tmax tail_ratio maxc
  local mbps rps big_mbps

  if [ "${GEN:-bash}" = "k6" ]; then
    # ---- Layer A from the k6 handleSummary() JSON (already schema-shaped) ----
    # The k6 scenario maps k6's native metrics into the same app-latency schema
    # the bash path produces, so this branch is a straight jq read. Fields the
    # bash generator derives from workload phases (tail@maxC, bigfile MB/s) are
    # approximated from the whole-run distribution and noted in the report.
    local S="$K6_SUMMARY"
    [ -s "$S" ] || { echo "!! k6 summary missing/empty at ${S}" >&2; : > "$RAW_LOG" 2>/dev/null || true; }
    total=$(jq -r '.requests // 0'        "$S" 2>/dev/null); total="${total%.*}"
    errors=$(jq -r '.errors // 0'         "$S" 2>/dev/null); errors="${errors%.*}"
    err_rate=$(jq -r '.error_rate // 0'   "$S" 2>/dev/null)
    up_bytes=$(jq -r '.bytes_uploaded // 0' "$S" 2>/dev/null); up_bytes="${up_bytes%.*}"
    p50=$(jq -r '.latency_ms.p50 // 0'    "$S" 2>/dev/null)
    p90=$(jq -r '.latency_ms.p90 // 0'    "$S" 2>/dev/null)
    p95=$(jq -r '.latency_ms.p95 // 0'    "$S" 2>/dev/null)
    p99=$(jq -r '.latency_ms.p99 // 0'    "$S" 2>/dev/null)
    pmax=$(jq -r '.latency_ms.max // 0'   "$S" 2>/dev/null)
    rps=$(jq -r '.throughput_rps // 0'    "$S" 2>/dev/null)
    mbps=$(jq -r '.throughput_mbps // 0'  "$S" 2>/dev/null)
    maxc=$(jq -r '.max_concurrency // 0'  "$S" 2>/dev/null); maxc="${maxc%.*}"; maxc="${maxc:-1}"
    big_mbps="$mbps"
    # defensive: a missing/partial summary must yield 0s, never empty strings
    # (empty would make the --argjson assembly below fail and emit no iter file).
    local _z
    for _z in total errors err_rate up_bytes p50 p90 p95 p99 pmax rps mbps maxc big_mbps; do
      [ -n "${!_z}" ] || printf -v "$_z" '%s' 0
    done
    # tail-fairness approximated from the whole-run p50/p99 (k6 does not phase)
    t50="$p50"; t99="$p99"
    tail_ratio=$(awk -v a="$t99" -v b="$t50" 'BEGIN{ printf "%.3f", (b>0)? a/b : 0 }')
  else
    # ---- Layer A (client) from RAW_LOG ----
    read -r total errors up_bytes < <(awk '
      { tot++; code=$5; szb=$4; up=$7;
        if(code<200||code>=300) err++;
        ub+=up }
      END{ printf "%d %d %.0f", tot+0, err+0, ub+0 }' "$RAW_LOG")
    err_rate=$(awk -v e="$errors" -v t="$total" 'BEGIN{ printf "%.5f", (t>0)? e/t : 0 }')

    # latency percentiles over ALL requests (time_total s -> ms)
    local pA; pA=$(awk '{printf "%.3f\n", $6*1000}' "$RAW_LOG" | perf_pctl)
    read -r p50 p90 p95 p99 pmax <<<"$pA"

    # tail-fairness: p50/p99 at the MAX concurrency in the sweep phase
    maxc=$(awk '$1=="sweep"{print $2}' "$RAW_LOG" | sort -n | tail -1)
    maxc="${maxc:-1}"
    local pT; pT=$(awk -v c="$maxc" '$1=="sweep" && $2==c {printf "%.3f\n", $6*1000}' "$RAW_LOG" | perf_pctl)
    read -r t50 t90 t95 t99 tmax <<<"$pT"
    tail_ratio=$(awk -v a="$t99" -v b="$t50" 'BEGIN{ printf "%.3f", (b>0)? a/b : 0 }')

    # throughput: aggregate MB/s + req/s over the wall clock
    mbps=$(awk -v b="$up_bytes" -v d="$DURATION_S" 'BEGIN{ printf "%.2f", (d>0)? b/1000000/d : 0 }')
    rps=$(awk -v t="$total" -v d="$DURATION_S" 'BEGIN{ printf "%.2f", (d>0)? t/d : 0 }')
    # bigfile MB/s: pure transfer rate (sum bytes / sum time) over the bigfile phase
    big_mbps=$(awk '$1=="bigfile"{b+=$7; t+=$6} END{ printf "%.2f", (t>0)? b/1000000/t : 0 }' "$RAW_LOG")
  fi

  # ---- Layer B (docker stats) ----
  local be pg
  be=$(perf_layerB_container "$STATS_JSONL" "$BACKEND_CONTAINER")
  pg=$(perf_layerB_container "$STATS_JSONL" "$DB_CONTAINER")
  local be_cpk be_cmn be_rpk be_rmn be_br be_bw; read -r be_cpk be_cmn be_rpk be_rmn be_br be_bw <<<"$be"
  local pg_cpk pg_cmn pg_rpk pg_rmn pg_br pg_bw; read -r pg_cpk pg_cmn pg_rpk pg_rmn pg_br pg_bw <<<"$pg"

  # ---- Layer C (backend /metrics) ----
  # in-flight peak + pool saturation peak from the @1Hz sample stream
  local inflight_peak pool_max sat_peak pool_active_peak
  read -r inflight_peak pool_active_peak pool_max sat_peak < <(awk '
    { gsub(/[{}"]/,""); split($0,a,","); inf=0;act=0;mx=0;
      for(i in a){ split(a[i],kv,":"); if(kv[1]=="in_flight")inf=kv[2];
        if(kv[1]=="pool_active")act=kv[2]; if(kv[1]=="pool_max")mx=kv[2]; }
      if(inf>ipk)ipk=inf; if(act>apk)apk=act; if(mx>mmx)mmx=mx;
      if(mx>0){ s=act/mx*100; if(s>spk)spk=s } }
    END{ printf "%d %d %d %.1f", ipk+0, apk+0, mmx+0, spk+0 }' "$MSAMPLE_JSONL" 2>/dev/null)
  # server-side MEAN latency for the upload route (summary: delta sum / delta count)
  local dsum dcount http_mean_ms
  dsum=$(perf_prom_route_delta "$MSTART" "$MEND" sum PUT "/artifacts/")
  dcount=$(perf_prom_route_delta "$MSTART" "$MEND" count PUT "/artifacts/")
  http_mean_ms=$(awk -v s="$dsum" -v c="$dcount" 'BEGIN{ printf "%.1f", (c>0)? s/c*1000 : 0 }')
  local resp5xx; resp5xx=$(perf_prom_5xx_delta "$MSTART" "$MEND")
  local pgjson; pgjson=$(cat "$PG_JSON" 2>/dev/null || echo '{}')

  # ---- Layer D (storage) ----
  local sdelta dedup
  sdelta=$(awk -v a="${STORAGE_START:-0}" -v b="${STORAGE_END:-0}" 'BEGIN{ d=b-a; if(d<0)d=0; printf "%.0f", d }')
  dedup=$(awk -v u="$up_bytes" -v d="$sdelta" 'BEGIN{ printf "%.2f", (d>0)? u/d : 0 }')

  jq -n \
    --arg profile "$PROFILE" --arg version "$VERSION" --arg image "$BACKEND_IMAGE" \
    --arg run_id "$RUN_ID" --arg started "$STARTED_AT" \
    --argjson dur "$DURATION_S" \
    --argjson conc "$maxc" --argjson reqs "$total" --argjson szb "$SWEEP_BYTES_ENV" --arg fmts "$FORMATS" \
    --argjson requests "$total" --argjson errors "$errors" --argjson err_rate "$err_rate" \
    --argjson rps "$rps" --argjson mbps "$mbps" --argjson big_mbps "$big_mbps" \
    --argjson p50 "$p50" --argjson p90 "$p90" --argjson p95 "$p95" --argjson p99 "$p99" --argjson pmax "$pmax" \
    --argjson t50 "$t50" --argjson t99 "$t99" --argjson tratio "$tail_ratio" \
    --argjson be_cpk "$be_cpk" --argjson be_cmn "$be_cmn" --argjson be_rpk "$be_rpk" --argjson be_rmn "$be_rmn" \
    --argjson be_br "$be_br" --argjson be_bw "$be_bw" \
    --argjson pg_cpk "$pg_cpk" --argjson pg_rpk "$pg_rpk" \
    --argjson infl "$inflight_peak" --argjson pactive "$pool_active_peak" --argjson pmaxc "$pool_max" --argjson sat "$sat_peak" \
    --argjson httpmean "$http_mean_ms" --argjson r5xx "$resp5xx" --argjson pg "$pgjson" \
    --argjson upb "$up_bytes" --argjson sdelta "$sdelta" --argjson dedup "$dedup" \
    '{
      profile:$profile, version:$version, backend_image:$image, run_id:$run_id,
      started_at:$started, duration_s:$dur,
      workload:{ max_concurrency:$conc, requests:$reqs, sweep_size_bytes:$szb, formats:$fmts },
      app:{ requests:$requests, errors:$errors, error_rate:$err_rate,
            throughput_rps:$rps, throughput_mbps:$mbps, bigfile_mbps:$big_mbps,
            latency_ms:{p50:$p50,p90:$p90,p95:$p95,p99:$p99,max:$pmax},
            tail_at_max_conc:{p50:$t50,p99:$t99,p99_over_p50:$tratio} },
      resource:{ backend:{cpu_pct_peak:$be_cpk,cpu_pct_mean:$be_cmn,rss_bytes_peak:$be_rpk,rss_bytes_mean:$be_rmn,block_read_bytes:$be_br,block_write_bytes:$be_bw},
                 postgres:{cpu_pct_peak:$pg_cpk,rss_bytes_peak:$pg_rpk} },
      backend_internal:{ http_mean_ms_server:$httpmean,
                         db_pool:{active_peak:$pactive,max:$pmaxc,saturation_pct_peak:$sat},
                         in_flight_peak:$infl, responses_5xx:$r5xx,
                         webhook_backlog_peak:null, pg_stat:$pg },
      storage:{ bytes_uploaded:$upb, storage_used_bytes_delta:$sdelta, dedup_ratio:$dedup }
    }' > "$out"
}
