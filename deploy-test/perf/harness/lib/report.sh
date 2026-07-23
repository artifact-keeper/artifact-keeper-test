#!/usr/bin/env bash
# =============================================================================
# perf/harness/lib/report.sh — combine + baseline->delta verdict + report
# =============================================================================
# Sourced by run.sh. Three responsibilities (design doc §4/§5):
#   1. perf_combine         : fold N per-iteration metrics.json into ONE robust
#      metrics.json. Phase 2a HARDENING: default is a TRIMMED MEAN (drop the
#      single highest AND single lowest iteration, mean the rest) instead of a
#      bare median. On the shared rig, single-run noise is ~2-3x (Phase 1
#      finding); a trimmed mean over >=5 runs removes the one hot/cold outlier
#      each way and is far more stable than a median-of-3. Selectable via
#      PTF_COMBINE=trimmed|median (default trimmed). Count-like leaves are
#      rounded. metadata + pg_stat hotspot carried from the LAST iteration.
#   2. perf_render_report   : diff the run against a stored per-(version,profile)
#      baseline using the profile's thresholds budget, emit report.md, and print
#      a PASS / REGRESSION / IMPROVED verdict. Phase 2a HARDENING: each
#      baseline-relative guard now requires BOTH a percentage-budget breach AND
#      an absolute NOISE-FLOOR (tolerance band) breach before it fires
#      REGRESSION, so small drift inside the rig's noise floor no longer flaps
#      the gate. Percentile metrics (p95, tail ratio) get wider bands than the
#      deterministic ones. All budgets + bands are env-overridable (PTF_*).
#   3. exit non-zero on REGRESSION so a fleet/CI gate fails exactly like a DTF
#      oracle's non-zero exit.
# =============================================================================

# perf_combine <out.json> <iter1.json> [iter2.json ...]
# Trimmed-mean (default) or median combine of every guarded/reported numeric
# leaf across iterations. Set PTF_COMBINE=median to fall back to lower-middle
# median. With <=2 iterations trimming is impossible so a plain mean is used;
# with exactly 3 the trim leaves the middle value (== median).
perf_combine() {
  local out="$1"; shift
  local method="${PTF_COMBINE:-trimmed}"
  jq -s --arg method "$method" '
    # --- combiner: trimmed mean (drop 1 hi + 1 lo) or lower-middle median ---
    def med: sort | .[((length-1)/2)|floor];
    def tmean:
      sort as $s | ($s|length) as $n |
      if   $n <= 0 then 0
      elif $n <= 2 then ($s|add)/$n
      else ($s[1:-1]|add)/($n-2) end;
    def comb: if $method == "median" then med else tmean end;
    def rcomb: (comb|round);          # for count-like leaves
    ( map(.app.latency_ms.p50) ) as $p50 |
    (. ) as $runs |
    ($runs[-1]) as $m |
    {
      profile:$m.profile, version:$m.version, backend_image:$m.backend_image,
      run_id:$m.run_id, started_at:$m.started_at,
      iterations: ($runs|length),
      combine: $method,
      duration_s: ($runs|map(.duration_s)|comb),
      workload: $m.workload,
      app: {
        requests: ($runs|map(.app.requests)|rcomb),
        errors:   ($runs|map(.app.errors)|rcomb),
        error_rate:($runs|map(.app.error_rate)|comb),
        throughput_rps: ($runs|map(.app.throughput_rps)|comb),
        throughput_mbps:($runs|map(.app.throughput_mbps)|comb),
        bigfile_mbps:   ($runs|map(.app.bigfile_mbps)|comb),
        latency_ms: {
          p50:($runs|map(.app.latency_ms.p50)|comb),
          p90:($runs|map(.app.latency_ms.p90)|comb),
          p95:($runs|map(.app.latency_ms.p95)|comb),
          p99:($runs|map(.app.latency_ms.p99)|comb),
          max:($runs|map(.app.latency_ms.max)|comb)
        },
        tail_at_max_conc: {
          p50:($runs|map(.app.tail_at_max_conc.p50)|comb),
          p99:($runs|map(.app.tail_at_max_conc.p99)|comb),
          p99_over_p50:($runs|map(.app.tail_at_max_conc.p99_over_p50)|comb)
        }
      },
      resource: {
        backend: {
          cpu_pct_peak:($runs|map(.resource.backend.cpu_pct_peak)|comb),
          cpu_pct_mean:($runs|map(.resource.backend.cpu_pct_mean)|comb),
          rss_bytes_peak:($runs|map(.resource.backend.rss_bytes_peak)|rcomb),
          rss_bytes_mean:($runs|map(.resource.backend.rss_bytes_mean)|rcomb),
          block_read_bytes:($runs|map(.resource.backend.block_read_bytes)|rcomb),
          block_write_bytes:($runs|map(.resource.backend.block_write_bytes)|rcomb)
        },
        postgres: {
          cpu_pct_peak:($runs|map(.resource.postgres.cpu_pct_peak)|comb),
          rss_bytes_peak:($runs|map(.resource.postgres.rss_bytes_peak)|rcomb)
        }
      },
      backend_internal: {
        http_mean_ms_server:($runs|map(.backend_internal.http_mean_ms_server)|comb),
        db_pool: {
          active_peak:($runs|map(.backend_internal.db_pool.active_peak)|rcomb),
          max:($runs|map(.backend_internal.db_pool.max)|rcomb),
          saturation_pct_peak:($runs|map(.backend_internal.db_pool.saturation_pct_peak)|comb)
        },
        in_flight_peak:($runs|map(.backend_internal.in_flight_peak)|rcomb),
        responses_5xx:($runs|map(.backend_internal.responses_5xx)|rcomb),
        webhook_backlog_peak:null,
        pg_stat:$m.backend_internal.pg_stat
      },
      storage: {
        bytes_uploaded:($runs|map(.storage.bytes_uploaded)|rcomb),
        storage_used_bytes_delta:($runs|map(.storage.storage_used_bytes_delta)|rcomb),
        dedup_ratio:($runs|map(.storage.dedup_ratio)|comb)
      }
    }' "$@" > "$out"
}

# Back-compat alias: run.sh historically called perf_median_combine.
perf_median_combine() { perf_combine "$@"; }

# small helpers
_jn() { jq -r "$2 // 0" "$1"; }   # numeric leaf (default 0)
_human_bytes() { awk -v b="$1" 'BEGIN{ s="B"; v=b;
  if(v>=1073741824){v/=1073741824;s="GiB"} else if(v>=1048576){v/=1048576;s="MiB"} else if(v>=1024){v/=1024;s="KiB"}
  printf (s=="B")? "%.0f%s":"%.1f%s", v, s }'; }
_pct_delta() { awk -v a="$1" -v b="$2" 'BEGIN{ if(a==0){print "n/a"; exit} printf "%+.1f%%", (b-a)/a*100 }'; }

# perf_render_report <metrics.json> <baseline.json|""> <thresholds_file> <report.md> <baselines_dir> <profile>
# Prints "VERDICT: X" and returns 0 (PASS/IMPROVED/no-baseline) or 1 (REGRESSION).
perf_render_report() {
  local M="$1" B="$2" TH="$3" OUT="$4" BLDIR="$5" PROFILE="$6"

  # ---- threshold budgets + noise-floor bands ----------------------------------
  # Precedence (lowest -> highest):
  #   1. built-in defaults here
  #   2. the profile's thresholds file (sourced KV)  <- profile authoring point
  #   3. environment overrides via PTF_<NAME>          <- rig/run-time override
  # A baseline-relative metric only fires REGRESSION when it breaches BOTH its
  # percentage budget AND its absolute tolerance band, so drift inside the rig
  # noise floor cannot flap the verdict. Percentile metrics (p95, tail ratio)
  # carry WIDER bands than deterministic ones. Hard-ceiling metrics
  # (error_rate, pool saturation) are absolute and take no band.
  local P95_REGRESSION_PCT=15 THROUGHPUT_REGRESSION_PCT=10 RSS_REGRESSION_PCT=20
  local TAIL_FAIRNESS_RATIO_PCT=25 ERROR_RATE_ABS_MAX=0.01 POOL_SAT_ABS_MAX=95
  # tolerance bands (absolute units of each metric) — wide for percentiles:
  local P95_TOLERANCE_MS=75              # p95 must move >75ms AND >budget% to fail
  local TAIL_TOLERANCE_RATIO=0.60        # p99/p50 ratio must move >0.60 AND >budget%
  local THROUGHPUT_TOLERANCE_MBPS=30     # throughput must drop >30MB/s AND >budget%
  local RSS_TOLERANCE_BYTES=134217728    # peak RSS must rise >128MiB AND >budget%
  # shellcheck disable=SC1090
  [ -f "$TH" ] && source "$TH"
  # env (PTF_*) wins over the profile file:
  local _v
  for _v in P95_REGRESSION_PCT THROUGHPUT_REGRESSION_PCT RSS_REGRESSION_PCT \
            TAIL_FAIRNESS_RATIO_PCT ERROR_RATE_ABS_MAX POOL_SAT_ABS_MAX \
            P95_TOLERANCE_MS TAIL_TOLERANCE_RATIO THROUGHPUT_TOLERANCE_MBPS \
            RSS_TOLERANCE_BYTES; do
    local _env="PTF_${_v}"
    [ -n "${!_env:-}" ] && printf -v "$_v" '%s' "${!_env}"
  done

  # this-run values
  local this_p95 this_mbps this_rss this_tratio this_err this_sat
  this_p95=$(_jn "$M" '.app.latency_ms.p95')
  this_mbps=$(_jn "$M" '.app.throughput_mbps')
  this_rss=$(_jn "$M" '.resource.backend.rss_bytes_peak')
  this_tratio=$(_jn "$M" '.app.tail_at_max_conc.p99_over_p50')
  this_err=$(_jn "$M" '.app.error_rate')
  this_sat=$(_jn "$M" '.backend_internal.db_pool.saturation_pct_peak')

  local verdict="PASS" have_base=0
  local rows=""   # markdown rows

  # ---- hard-ceiling guards (baseline-independent) ----
  local err_v="PASS" sat_v="PASS"
  awk -v v="$this_err" -v c="$ERROR_RATE_ABS_MAX" 'BEGIN{exit !(v>c)}' && err_v="REGRESSION"
  awk -v v="$this_sat" -v c="$POOL_SAT_ABS_MAX" 'BEGIN{exit !(v>c)}' && sat_v="REGRESSION"
  [ "$err_v" = "REGRESSION" ] && verdict="REGRESSION"
  [ "$sat_v" = "REGRESSION" ] && verdict="REGRESSION"

  # ---- baseline-relative guards ----
  if [ -n "$B" ] && [ -f "$B" ]; then
    have_base=1
    local b_p95 b_mbps b_rss b_tratio
    b_p95=$(_jn "$B" '.app.latency_ms.p95')
    b_mbps=$(_jn "$B" '.app.throughput_mbps')
    b_rss=$(_jn "$B" '.resource.backend.rss_bytes_peak')
    b_tratio=$(_jn "$B" '.app.tail_at_max_conc.p99_over_p50')

    _guard_hi() { # metric that must NOT rise past base*(1+pct) AND by >band
      local name="$1" base="$2" this="$3" pct="$4" band="$5" fmt="$6"
      local v; v=$(awk -v b="$base" -v t="$this" -v p="$pct" -v tol="$band" 'BEGIN{
        if(t>b*(1+p/100) && (t-b)>tol) print "REGRESSION";
        else if(t<b*(1-p/100) && (b-t)>tol) print "IMPROVED";
        else print "PASS" }')
      [ "$v" = "REGRESSION" ] && verdict="REGRESSION"
      [ "$v" = "IMPROVED" ] && [ "$verdict" = "PASS" ] && verdict="IMPROVED"
      rows+="| ${name} | $(printf "$fmt" "$base") | $(printf "$fmt" "$this") | $(_pct_delta "$base" "$this") | +${pct}% & +$(printf "$fmt" "$band") | ${v} |"$'\n'
    }
    _guard_lo() { # metric that must NOT drop below base*(1-pct) AND by >band
      local name="$1" base="$2" this="$3" pct="$4" band="$5" fmt="$6"
      local v; v=$(awk -v b="$base" -v t="$this" -v p="$pct" -v tol="$band" 'BEGIN{
        if(t<b*(1-p/100) && (b-t)>tol) print "REGRESSION";
        else if(t>b*(1+p/100) && (t-b)>tol) print "IMPROVED";
        else print "PASS" }')
      [ "$v" = "REGRESSION" ] && verdict="REGRESSION"
      [ "$v" = "IMPROVED" ] && [ "$verdict" = "PASS" ] && verdict="IMPROVED"
      rows+="| ${name} | $(printf "$fmt" "$base") | $(printf "$fmt" "$this") | $(_pct_delta "$base" "$this") | -${pct}% & -$(printf "$fmt" "$band") | ${v} |"$'\n'
    }

    _guard_hi "p95 latency (ms)"        "$b_p95"    "$this_p95"    "$P95_REGRESSION_PCT"        "$P95_TOLERANCE_MS"          "%.1f"
    _guard_lo "throughput (MB/s)"       "$b_mbps"   "$this_mbps"   "$THROUGHPUT_REGRESSION_PCT" "$THROUGHPUT_TOLERANCE_MBPS" "%.2f"
    _guard_hi "peak backend RSS (bytes)" "$b_rss"   "$this_rss"    "$RSS_REGRESSION_PCT"        "$RSS_TOLERANCE_BYTES"       "%.0f"
    _guard_hi "tail p99/p50 @maxC"      "$b_tratio" "$this_tratio" "$TAIL_FAIRNESS_RATIO_PCT"   "$TAIL_TOLERANCE_RATIO"      "%.2f"
  fi

  # hard-ceiling rows always shown
  rows+="| error rate (abs) | n/a | $(printf '%.5f' "$this_err") | n/a | <= ${ERROR_RATE_ABS_MAX} | ${err_v} |"$'\n'
  rows+="| db-pool sat %% (abs) | n/a | $(printf '%.1f' "$this_sat") | n/a | <= ${POOL_SAT_ABS_MAX} | ${sat_v} |"$'\n'

  # ---- render markdown ----
  local badge="$verdict"

  local ver img rid ts iters dur cmb
  ver=$(jq -r '.version' "$M"); img=$(jq -r '.backend_image' "$M"); rid=$(jq -r '.run_id' "$M")
  ts=$(jq -r '.started_at' "$M"); iters=$(jq -r '.iterations // 1' "$M"); dur=$(jq -r '.duration_s' "$M")
  cmb=$(jq -r '.combine // "median"' "$M")

  {
    echo "# PTF report — ${PROFILE}"
    echo
    echo "**Verdict: ${badge}**"
    echo
    echo "| field | value |"
    echo "|---|---|"
    echo "| profile | ${PROFILE} |"
    echo "| version | ${ver} |"
    echo "| backend image | \`${img}\` |"
    echo "| run id | ${rid} |"
    echo "| started | ${ts} |"
    echo "| iterations (${cmb} of) | ${iters} |"
    echo "| median run duration | ${dur}s |"
    if [ "$have_base" = 1 ]; then echo "| baseline | \`$(basename "$(dirname "$B")")/$(basename "$B")\` |";
    else echo "| baseline | none (measurement-only; run with --baseline to record) |"; fi
    echo
    echo "## Guarded metrics (baseline -> delta)"
    echo
    echo "| metric | baseline | this run | delta | budget | verdict |"
    echo "|---|---|---|---|---|---|"
    printf '%s' "$rows"
    echo
    echo "## Layer A — client-observed (load generator)"
    echo
    echo "| p50 | p90 | p95 | p99 | max | throughput | bigfile MB/s | req/s | errors | error-rate |"
    echo "|---|---|---|---|---|---|---|---|---|---|"
    printf '| %sms | %sms | %sms | %sms | %sms | %s MB/s | %s | %s | %s | %s |\n' \
      "$(_jn "$M" '.app.latency_ms.p50')" "$(_jn "$M" '.app.latency_ms.p90')" \
      "$(_jn "$M" '.app.latency_ms.p95')" "$(_jn "$M" '.app.latency_ms.p99')" \
      "$(_jn "$M" '.app.latency_ms.max')" "$(_jn "$M" '.app.throughput_mbps')" \
      "$(_jn "$M" '.app.bigfile_mbps')" "$(_jn "$M" '.app.throughput_rps')" \
      "$(_jn "$M" '.app.errors')" "$(_jn "$M" '.app.error_rate')"
    echo
    echo "Tail fairness @ max concurrency ($(jq -r '.workload.max_concurrency' "$M")):"
    echo "p50=$(_jn "$M" '.app.tail_at_max_conc.p50')ms  p99=$(_jn "$M" '.app.tail_at_max_conc.p99')ms  p99/p50=$(_jn "$M" '.app.tail_at_max_conc.p99_over_p50')"
    echo
    echo "## Layer B — container resource (docker stats @1Hz)"
    echo
    echo "| container | CPU% peak | CPU% mean | RSS peak | RSS mean | block r/w |"
    echo "|---|---|---|---|---|---|"
    printf '| backend | %s | %s | %s | %s | %s / %s |\n' \
      "$(_jn "$M" '.resource.backend.cpu_pct_peak')" "$(_jn "$M" '.resource.backend.cpu_pct_mean')" \
      "$(_human_bytes "$(_jn "$M" '.resource.backend.rss_bytes_peak')")" \
      "$(_human_bytes "$(_jn "$M" '.resource.backend.rss_bytes_mean')")" \
      "$(_human_bytes "$(_jn "$M" '.resource.backend.block_read_bytes')")" \
      "$(_human_bytes "$(_jn "$M" '.resource.backend.block_write_bytes')")"
    printf '| postgres | %s | - | %s | - | - |\n' \
      "$(_jn "$M" '.resource.postgres.cpu_pct_peak')" \
      "$(_human_bytes "$(_jn "$M" '.resource.postgres.rss_bytes_peak')")"
    echo
    echo "## Layer C — backend-internal (AK /metrics + pg_stat)"
    echo
    echo "| server mean latency (upload route) | in-flight peak | db-pool active/max | pool sat % | 5xx | webhook backlog |"
    echo "|---|---|---|---|---|---|"
    printf '| %sms | %s | %s / %s | %s | %s | %s |\n' \
      "$(_jn "$M" '.backend_internal.http_mean_ms_server')" \
      "$(_jn "$M" '.backend_internal.in_flight_peak')" \
      "$(_jn "$M" '.backend_internal.db_pool.active_peak')" \
      "$(_jn "$M" '.backend_internal.db_pool.max')" \
      "$(_jn "$M" '.backend_internal.db_pool.saturation_pct_peak')" \
      "$(_jn "$M" '.backend_internal.responses_5xx')" \
      "$(jq -r '.backend_internal.webhook_backlog_peak // "n/a (not emitted by this build)"' "$M")"
    echo
    echo "pg_stat_statements top query: \`$(jq -r '.backend_internal.pg_stat.top_query // "n/a"' "$M")\`  "
    echo "slow queries (mean>100ms): $(jq -r '.backend_internal.pg_stat.slow_queries // 0' "$M")  top mean: $(jq -r '.backend_internal.pg_stat.top_query_mean_ms // 0' "$M")ms"
    echo
    echo "## Layer D — storage / dedup"
    echo
    echo "| bytes uploaded | storage delta (volume du) | dedup ratio |"
    echo "|---|---|---|"
    printf '| %s | %s | %sx |\n' \
      "$(_human_bytes "$(_jn "$M" '.storage.bytes_uploaded')")" \
      "$(_human_bytes "$(_jn "$M" '.storage.storage_used_bytes_delta')")" \
      "$(_jn "$M" '.storage.dedup_ratio')"

    # ---- version-over-version trend (if >1 baseline) ----
    if [ -d "$BLDIR" ]; then
      local bfiles; bfiles=$(find "$BLDIR" -name "${PROFILE}.json" 2>/dev/null | sort)
      local n; n=$(printf '%s\n' "$bfiles" | grep -c .)
      if [ "$n" -ge 2 ]; then
        echo
        echo "## Version-over-version trend"
        echo
        echo "| version | p95 (ms) | throughput (MB/s) | peak RSS |"
        echo "|---|---|---|---|"
        local f v
        while IFS= read -r f; do
          [ -z "$f" ] && continue
          v=$(basename "$(dirname "$f")")
          printf '| %s | %s | %s | %s |\n' "$v" \
            "$(_jn "$f" '.app.latency_ms.p95')" "$(_jn "$f" '.app.throughput_mbps')" \
            "$(_human_bytes "$(_jn "$f" '.resource.backend.rss_bytes_peak')")"
        done <<< "$bfiles"
      fi
    fi
    echo
    echo "## Hotspot summary (where is the time/pressure going)"
    echo
    echo "- worst client latency: p99 $(_jn "$M" '.app.latency_ms.p99')ms (max $(_jn "$M" '.app.latency_ms.max')ms)"
    echo "- peak backend RSS: $(_human_bytes "$(_jn "$M" '.resource.backend.rss_bytes_peak')")"
    echo "- peak db-pool saturation: $(_jn "$M" '.backend_internal.db_pool.saturation_pct_peak')%"
    echo "- peak in-flight requests: $(_jn "$M" '.backend_internal.in_flight_peak')"
    echo "- slowest DB query (pg_stat): $(jq -r '.backend_internal.pg_stat.top_query_mean_ms // 0' "$M")ms mean"
    echo
    echo "_Raw artifacts: metrics.json, docker-stats.jsonl, metrics-scrape.jsonl, metrics-start.txt, metrics-end.txt in this dir._"
  } > "$OUT"

  echo "VERDICT: ${verdict}"
  [ "$verdict" = "REGRESSION" ] && return 1
  return 0
}
