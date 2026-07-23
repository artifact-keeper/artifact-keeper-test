#!/usr/bin/env bash
# =============================================================================
# profiles/search-at-scale/scenario.sh — GEN=bash generator  (Phase 2b, #2516)
# =============================================================================
# Measures SEARCH/QUERY latency as the artifact table grows — the core
# million-artifact readiness signal (#2516). For a sequence of dataset scales
# (SCALE_K_VALUES, e.g. 10k / 100k / 500k) it:
#
#   1. RESETS the seeded dataset (seed.sh --truncate) at the START of every
#      measured iteration, then
#   2. grows the GLOBAL artifacts table to each K in turn (cumulative, ascending)
#      via harness/lib/seed.sh (DB-direct bulk insert, ~17k rows/s), and
#   3. at each K fires a fixed MIX of the read/query surfaces at QUERY_CONCURRENCY,
#      logging one RAW_LOG line per request for the harness Layer-A reducer AND
#      accumulating per-(scale,endpoint) percentiles for the scaling headline.
#
# WHY GLOBAL RESET-PER-ITERATION (not per-repo like metadata-scale):
#   quick_search / advanced_search scan the WHOLE artifacts table (no repo
#   scope) — search latency is a function of TOTAL row count, so the scale must
#   be the standing table size at measurement time. The harness runs one standing
#   stack across warm-up + RUNS iterations, so each iteration truncates and
#   re-grows 0 -> K1 -> K2 -> K3 to measure every scale independently. Equal
#   request counts per scale mean the union's p95 lands in the LARGEST-scale
#   bucket (it is the slow tail), so the harness-guarded aggregate `p95` tracks
#   at-scale search latency; the per-scale breakdown (stdout + PTF_SCALING_OUT)
#   is the p95-vs-count scaling table.
#
# RECON-GROUNDED — WHERE THE TIME GOES (target-backend @1.6.2-rc):
#   Both quick_search and advanced_search route through SearchService::search
#   (services/search_service.rs:273), whose predicate is an INLINE functional
#   full-text match:
#     to_tsvector('english', a.name||' '||a.path||' '||COALESCE(a.version,''))
#       @@ to_tsquery('english', $1)
#   There is NO GIN index on a stored tsvector column (none in migrations/), so
#   this recomputes to_tsvector for EVERY row on EVERY query == a sequential
#   scan, O(N) in the table size. A separate COUNT(*) for pagination repeats the
#   same full scan. The name-wildcard path (a.name ILIKE $3, '%pkg%') is likewise
#   non-sargable. Deep pages (page=N) add OFFSET cost. This is the #2516 cliff;
#   Layer C pg_stat_statements surfaces these as the dominant queries at scale.
#
# RATE LIMIT: /search carries a 300/min per-IP limiter (routes.rs:680). This
#   profile deliberately drives search well past that, so it MUST run with the
#   limiter OFF or every request past the bucket 429s and the measurement becomes
#   a rate-limit test. compose.base.yml reads RATE_LIMIT_ENABLED from the shell
#   (`${RATE_LIMIT_ENABLED:-true}`), so invoke the harness with
#   `RATE_LIMIT_ENABLED=false` exported. The scenario pre-flights for 429s and
#   warns loudly if the limiter is still on.
#
# RAW_LOG line format (one per request, harness contract):
#   <phase> <concurrency> <endpoint> <size_bytes> <http_code> <time_total_s> <resp_bytes>
#   phase = "s<K>" for each scale, EXCEPT the largest scale which is tagged
#   "sweep" so collect.sh's tail-fairness metric reflects the worst scale.
#
# Inputs (exported by run.sh): BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID,
#   PERF_WORK_DIR, RAW_LOG, ITER, DB_CONTAINER, PERF_THROTTLE_MS, COMMON_SH.
# Optional: PTF_SCALING_OUT (append per-(iter,scale,endpoint) JSONL there).
# =============================================================================
set -uo pipefail

SCEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- knobs: PTF_ env override wins, else manifest, else built-in default ------
# run.sh sources the manifest into ITS shell before invoking the scenario, so a
# bare `SCALE_K_VALUES=... run.sh` is clobbered by the manifest value and never
# reaches here. The stable run-time override channel is therefore a PTF_-prefixed
# env var (which the manifest never sets): PTF_SCALE_K_VALUES etc. Capture those
# first, then source the manifest for the committed defaults.
_env_scales="${PTF_SCALE_K_VALUES:-}"
_env_qc="${PTF_QUERY_CONCURRENCY:-}"
_env_rpe="${PTF_REQUESTS_PER_ENDPOINT:-}"
_env_repos="${PTF_SEED_REPOS:-}"
_env_term="${PTF_SEARCH_TERM:-}"
_env_size="${PTF_SEED_SIZE_BYTES:-}"
# shellcheck disable=SC1091
source "${SCEN_DIR}/manifest" >/dev/null 2>&1 || true
SCALE_K_VALUES="${_env_scales:-${SCALE_K_VALUES:-10000 100000 500000}}"
QUERY_CONCURRENCY="${_env_qc:-${QUERY_CONCURRENCY:-4}}"
REQUESTS_PER_ENDPOINT="${_env_rpe:-${REQUESTS_PER_ENDPOINT:-15}}"
SEED_REPOS="${_env_repos:-${SEED_REPOS:-5}}"
SEARCH_TERM="${_env_term:-${SEARCH_TERM:-pkg}}"
SEED_SIZE_BYTES="${_env_size:-${SEED_SIZE_BYTES:-1024}}"

QC="$QUERY_CONCURRENCY"
THROTTLE_MS="${PERF_THROTTLE_MS:-0}"

# --- corpus auth helpers + bulk seeder ---------------------------------------
# shellcheck disable=SC1090
source "${COMMON_SH:?set COMMON_SH}"
# common.sh resets WORK_DIR="" at source time; adopt the harness-provided dir.
WORK_DIR="${PERF_WORK_DIR:?set PERF_WORK_DIR}"
mkdir -p "$WORK_DIR"
# shellcheck disable=SC1091
source "${SCEN_DIR}/../../harness/lib/seed.sh"
: "${DB_CONTAINER:?set DB_CONTAINER}"

auth_admin >/dev/null 2>&1 || { echo "scenario: auth failed at ${BASE_URL}" >&2; exit 1; }
: > "$RAW_LOG"

# ascending, integer scales
SCALES=$(printf '%s\n' $SCALE_K_VALUES | sort -n | tr '\n' ' ')
LARGEST=$(printf '%s\n' $SCALES | sort -n | tail -1)

# --- one query request; appends a RAW_LOG line -------------------------------
# args: phase endpoint_label url
query_one() {
  local phase="$1" label="$2" url="$3"
  [ "$THROTTLE_MS" -gt 0 ] 2>/dev/null && sleep "$(awk -v m="$THROTTLE_MS" 'BEGIN{printf "%.3f", m/1000}')"
  local out
  out=$(curl -s -o /dev/null -w '%{http_code} %{time_total} %{size_download}' \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" "$url" 2>/dev/null) || out="000 0 0"
  # <phase> <concurrency> <endpoint> <size_bytes=0> <code> <time_total> <resp_bytes>
  # O_APPEND on a short (<4KB) line is atomic across the concurrent workers.
  echo "${phase} ${QC} ${label} 0 ${out}" >> "$RAW_LOG"
}

# fire N requests at QC concurrency against one endpoint url
run_endpoint() {
  local phase="$1" label="$2" url="$3" n="$4"
  local per=$(( (n + QC - 1) / QC ))
  local w
  for w in $(seq 1 "$QC"); do
    (
      local k
      for k in $(seq 1 "$per"); do query_one "$phase" "$label" "$url"; done
    ) &
  done
  wait
}

# --- pre-flight: is the rate limiter off? ------------------------------------
# Fire a short burst past 300/min and check for 429. If throttled, the numbers
# below are meaningless — warn loudly but continue (operator may want the data).
preflight_rate_limit() {
  local i seen429=0 code
  for i in $(seq 1 20); do
    code=$(curl -s -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      "${BASE_URL}/api/v1/search/quick?q=${SEARCH_TERM}&limit=1" 2>/dev/null) || code=000
    [ "$code" = "429" ] && { seen429=1; break; }
  done
  if [ "$seen429" = 1 ]; then
    echo "scenario: !! /search returned 429 in pre-flight — the rate limiter is ON." >&2
    echo "scenario: !! re-run the harness with RATE_LIMIT_ENABLED=false exported, else" >&2
    echo "scenario: !! search-at-scale measures the 300/min limiter, not query latency." >&2
  fi
}

# --- the fixed query mix at one scale ----------------------------------------
# GET-only reads across the search + listing surfaces that scan the artifacts
# table. resp_bytes (size_download) is logged as the Layer-A byte counter so
# throughput_mbps is a read-throughput proxy (this profile uploads nothing).
measure_scale() {
  local K="$1" phase="$2" repo1="$3"
  local rpe="$REQUESTS_PER_ENDPOINT"
  local enc_term; enc_term="$SEARCH_TERM"
  # quick search (global FTS seq-scan)
  run_endpoint "$phase" "quick"      "${BASE_URL}/api/v1/search/quick?q=${enc_term}&limit=20" "$rpe"
  # advanced search — FTS predicate ($1 to_tsvector path) + COUNT(*) full scan
  run_endpoint "$phase" "adv-fts"    "${BASE_URL}/api/v1/search/advanced?query=${enc_term}&per_page=20&page=1" "$rpe"
  # advanced search — name wildcard (a.name ILIKE '%term%', non-sargable)
  run_endpoint "$phase" "adv-ilike"  "${BASE_URL}/api/v1/search/advanced?name=%2A${enc_term}%2A&per_page=20&page=1" "$rpe"
  # advanced search — deep page (OFFSET cost on top of the scan)
  run_endpoint "$phase" "adv-deep"   "${BASE_URL}/api/v1/search/advanced?query=${enc_term}&per_page=20&page=25" "$rpe"
  # repo artifact listing (per-repo page, repo grows with global K)
  run_endpoint "$phase" "list"       "${BASE_URL}/api/v1/repositories/${repo1}/artifacts?page=1&per_page=50" "$rpe"
  run_endpoint "$phase" "list-deep"  "${BASE_URL}/api/v1/repositories/${repo1}/artifacts?page=20&per_page=50" "$rpe"
}

# --- nearest-rank percentiles for one scale's RAW_LOG rows -------------------
# echoes "n p50 p95 p99 err_rate" (latencies in ms) for a given phase[,endpoint]
scale_pctl() {
  local phase="$1" label="${2:-}"
  awk -v ph="$phase" -v lab="$label" '
    function q(p,  i){ if(n==0) return 0; i=int(p*(n-1)/100)+1; if(i<1)i=1; if(i>n)i=n; return a[i] }
    $1==ph && (lab=="" || $3==lab) {
      t[++m]=$6*1000; if($5<200||$5>=300) err++;
    }
    END{
      n=0; for(i=1;i<=m;i++){ n++; a[n]=t[i] }
      # sort a[]
      for(i=2;i<=n;i++){ key=a[i]; j=i-1; while(j>0 && a[j]>key){a[j+1]=a[j];j--} a[j+1]=key }
      er=(m>0)? err/m : 0;
      printf "%d %.1f %.1f %.1f %.4f\n", m, q(50), q(95), q(99), er
    }' "$RAW_LOG"
}

# =============================================================================
# main
# =============================================================================
PREFIX_BASE="sas"
echo "scenario iter ${ITER}: scales=[${SCALES}] qc=${QC} rpe=${REQUESTS_PER_ENDPOINT} repos=${SEED_REPOS} term='${SEARCH_TERM}'" >&2

# RESET this run's dataset so every iteration re-grows 0 -> ... independently.
perf_seed --db-container "$DB_CONTAINER" --count 0 --repos "$SEED_REPOS" \
  --format generic --prefix "$PREFIX_BASE" --run-id "$RUN_ID" --truncate --quiet \
  >/dev/null 2>&1 || echo "scenario: warn: dataset reset seed returned non-zero" >&2
REPO1="${PERF_SEED_PREFIX:-${PREFIX_BASE}}-r1"

preflight_rate_limit

for K in $SCALES; do
  # grow the GLOBAL table to K (cumulative; ON CONFLICT DO NOTHING no-ops lower ranges)
  perf_seed --db-container "$DB_CONTAINER" --count "$K" --repos "$SEED_REPOS" \
    --format generic --size-bytes "$SEED_SIZE_BYTES" --metadata 0 \
    --prefix "$PREFIX_BASE" --run-id "$RUN_ID" --quiet >/dev/null 2>&1 \
    || echo "scenario: warn: seed to K=${K} returned non-zero" >&2
  REPO1="${PERF_SEED_PREFIX:-${PREFIX_BASE}}-r1"

  phase="s${K}"; [ "$K" = "$LARGEST" ] && phase="sweep"
  measure_scale "$K" "$phase" "$REPO1"

  # per-scale headline + optional persisted JSONL
  read -r n p50 p95 p99 err < <(scale_pctl "$phase")
  echo ">> SCALING iter=${ITER} scale=${K} n=${n} p50=${p50}ms p95=${p95}ms p99=${p99}ms err=${err}" >&2
  for lab in quick adv-fts adv-ilike adv-deep list list-deep; do
    read -r en ep50 ep95 ep99 eerr < <(scale_pctl "$phase" "$lab")
    echo ">>   endpoint=${lab} n=${en} p50=${ep50}ms p95=${ep95}ms p99=${ep99}ms err=${eerr}" >&2
    if [ -n "${PTF_SCALING_OUT:-}" ]; then
      printf '{"iter":"%s","scale":%s,"endpoint":"%s","n":%s,"p50_ms":%s,"p95_ms":%s,"p99_ms":%s,"err_rate":%s}\n' \
        "$ITER" "$K" "$lab" "${en:-0}" "${ep50:-0}" "${ep95:-0}" "${ep99:-0}" "${eerr:-0}" >> "$PTF_SCALING_OUT"
    fi
  done
  if [ -n "${PTF_SCALING_OUT:-}" ]; then
    printf '{"iter":"%s","scale":%s,"endpoint":"ALL","n":%s,"p50_ms":%s,"p95_ms":%s,"p99_ms":%s,"err_rate":%s}\n' \
      "$ITER" "$K" "${n:-0}" "${p50:-0}" "${p95:-0}" "${p99:-0}" "${err:-0}" >> "$PTF_SCALING_OUT"
  fi
done

echo "scenario iter ${ITER}: $(wc -l < "$RAW_LOG") requests logged across $(printf '%s\n' $SCALES | wc -l) scales" >&2
