#!/usr/bin/env bash
# =============================================================================
# perf/harness/run.sh — THE Performance Test Framework (PTF) entrypoint
# =============================================================================
# PTF is the performance sibling of DTF. A DTF <tier> is a discriminating
# correctness oracle (RED->GREEN); a PTF <profile> is a repeatable performance
# scenario that MEASURES the service and COMPARES against a stored per-version
# baseline (baseline->delta: PASS / REGRESSION / IMPROVED).
#
# Usage:
#   run.sh <profile> --backend-image IMG [--baseline|--compare] [--keep]
#                    [--slot N] [--version V] [--throttle-ms MS]
#   run.sh ports [--slot N]
#
# Per-profile contract (mirrors DTF run_tier):
#   1. resolve profiles/<name>/manifest -> GEN, SCENARIO, PROFILES(storage), workload
#   2. claim a free PERF slot + its non-colliding port block (lib/ports.sh)
#   3. up -d --wait: DTF compose.base.yml + reused storage overlay + compose.metrics.yml
#      (compose.metrics.yml sets METRICS_PORT so /metrics is scrapeable unauth,
#       preloads pg_stat_statements, and re-namespaces the slot to ak-perf<N>)
#   4. warm-up run, then run the scenario RUNS times; capture all 4 metric layers
#      per iteration -> results/<profile>/iters/iter-K.json (lib/collect.sh)
#   5. median-combine the iterations -> results/<profile>/metrics.json
#   6. --baseline: write baselines/<version>/<profile>.json
#      --compare (default when a baseline exists): diff vs baseline -> report.md,
#      verdict (lib/report.sh); non-zero exit on REGRESSION
#   7. down -v unless --keep
# =============================================================================
set -uo pipefail

PERF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DTF_DIR="$(cd "${PERF_DIR}/.." && pwd)"   # reuse DTF compose.base.yml + storage overlays
# shellcheck source=lib/ports.sh
source "${PERF_DIR}/harness/lib/ports.sh"
# shellcheck source=lib/collect.sh
source "${PERF_DIR}/harness/lib/collect.sh"
# shellcheck source=lib/report.sh
source "${PERF_DIR}/harness/lib/report.sh"

# --- locate the artifact-keeper-test corpus (common.sh) ----------------------
resolve_test_root() {
  if [ -n "${AK_TEST_ROOT:-}" ] && [ -f "${AK_TEST_ROOT}/tests/lib/common.sh" ]; then echo "$AK_TEST_ROOT"; return 0; fi
  if [ -f "${DTF_DIR}/../tests/lib/common.sh" ]; then (cd "${DTF_DIR}/.." && pwd); return 0; fi
  if [ -f "/home/khan/artifact-keeper-redteam/test/tests/lib/common.sh" ]; then echo "/home/khan/artifact-keeper-redteam/test"; return 0; fi
  echo ""; return 1
}

# --- argument parsing --------------------------------------------------------
CMD="${1:-}"; shift || true
BACKEND_IMAGE_ARG=""; MODE=""; KEEP=0; SLOT_ARG=""; VERSION_ARG=""; THROTTLE_MS=0
FORCE_BASELINE=0; RUNS_ARG=""; WARMUP_ARG=""; GEN_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --backend-image) BACKEND_IMAGE_ARG="$2"; shift 2 ;;
    --baseline)      MODE="baseline"; shift ;;
    --compare)       MODE="compare"; shift ;;
    --keep)          KEEP=1; shift ;;
    --slot)          SLOT_ARG="$2"; shift 2 ;;
    --version)       VERSION_ARG="$2"; shift 2 ;;
    --throttle-ms)   THROTTLE_MS="$2"; shift 2 ;;
    --force-baseline) FORCE_BASELINE=1; MODE="baseline"; shift ;;
    --runs)          RUNS_ARG="$2"; shift 2 ;;
    --warmup)        WARMUP_ARG="$2"; shift 2 ;;
    --gen)           GEN_ARG="$2"; shift 2 ;;
    *) echo "!! unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$CMD" in
  "" | -h | --help) sed -n '2,38p' "${BASH_SOURCE[0]}"; exit 0 ;;
  ports) perf_ports "${SLOT_ARG:-1}"; exit 0 ;;
esac

PROFILE="$CMD"
MANIFEST="${PERF_DIR}/profiles/${PROFILE}/manifest"
[ -f "$MANIFEST" ] || { echo "!! no manifest for profile '${PROFILE}' (${MANIFEST})" >&2; exit 4; }

# --- resolve manifest + corpus + image ---------------------------------------
# Capture any env-provided GEN BEFORE sourcing the manifest, else the manifest's
# GEN= clobbers it (the literal `GEN=k6 bash run.sh ...` invocation must work).
GEN_ENV="${GEN:-}"
GEN=""; SCENARIO=""; SCENARIO_K6=""; PROFILES=""; THRESHOLDS="thresholds"; RUNS="5"; WARMUP="1"
# shellcheck disable=SC1090
source "$MANIFEST"
# generator kind precedence: --gen flag > GEN env > manifest default. Lets one
# profile drive both the bash and the k6 path (design doc §1 "two generator kinds").
GEN="${GEN_ARG:-${GEN_ENV:-${GEN:-}}}"
[ -n "$GEN" ] && [ -n "$PROFILES" ] || { echo "!! manifest must set GEN, PROFILES" >&2; exit 4; }
# iteration count + warm-up are configurable (Phase 2a: default RUNS raised to 5,
# more runs -> a tighter trimmed-mean -> a more stable verdict on the noisy rig).
RUNS="${RUNS_ARG:-${PTF_RUNS:-$RUNS}}"
WARMUP="${WARMUP_ARG:-${PTF_WARMUP:-$WARMUP}}"
case "$RUNS" in ''|*[!0-9]*) echo "!! --runs must be a positive integer" >&2; exit 2 ;; esac
[ "$RUNS" -ge 1 ] || { echo "!! --runs must be >= 1" >&2; exit 2; }
case "$WARMUP" in ''|*[!0-9]*) echo "!! --warmup must be a non-negative integer" >&2; exit 2 ;; esac
# resolve the scenario file for the selected generator
if [ "$GEN" = "k6" ]; then
  SCENARIO="${SCENARIO_K6:-scenario.js}"
else
  SCENARIO="${SCENARIO:-scenario.sh}"
fi
[ -f "${PERF_DIR}/profiles/${PROFILE}/${SCENARIO}" ] || { echo "!! generator '${GEN}' selected but scenario '${SCENARIO}' not found in profiles/${PROFILE}/" >&2; exit 4; }

AK_TEST_ROOT="$(resolve_test_root)"; [ -n "$AK_TEST_ROOT" ] || { echo "!! cannot locate artifact-keeper-test corpus (set AK_TEST_ROOT)" >&2; exit 5; }
export COMMON_SH="${AK_TEST_ROOT}/tests/lib/common.sh"
BACKEND_IMAGE="${BACKEND_IMAGE_ARG:-${BACKEND_IMAGE:-}}"
[ -n "$BACKEND_IMAGE" ] || { echo "!! --backend-image required" >&2; exit 2; }
export BACKEND_IMAGE
VERSION="${VERSION_ARG:-${BACKEND_IMAGE##*:}}"   # default: image tag

# --- rig-quiesce guard (baselines must be captured on a QUIESCED rig) ---------
# A --baseline is the canonical "known-good" number; capturing it while the rig
# is busy bakes contention noise into the reference and poisons every future
# --compare. Before a baseline we sample host load; if the 1-min loadavg exceeds
# the budget we WARN and REFUSE, unless --force-baseline (override) is given.
# QUIESCE_LOADAVG_MAX defaults to ~0.6*nproc; override via env.
if [ "$MODE" = "baseline" ]; then
  perf_quiesce_guard "$FORCE_BASELINE" || exit 8
fi

# --- claim slot + port block -------------------------------------------------
if [ -n "$SLOT_ARG" ]; then SLOT="$SLOT_ARG"; else SLOT="$(perf_claim_slot)" || exit 6; fi
perf_slot_env "$SLOT"
export DTF_SLOT="$PERF_SLOT"     # compose.base.yml interpolates ${DTF_SLOT} (overlay renames to ak-perf)
PROJECT="ak-perf${PERF_SLOT}"
BACKEND_CONTAINER="ak-perf${PERF_SLOT}-backend"
DB_CONTAINER="ak-perf${PERF_SLOT}-db"
VOLUME_NAME="ak-perf${PERF_SLOT}_data"
export DB_CONTAINER BACKEND_CONTAINER
export BASE_URL="http://127.0.0.1:${HTTP_PORT}"
export METRICS_URL="http://127.0.0.1:${METRICS_PORT}/metrics"
export ADMIN_USER="admin"
export ADMIN_PASS="${ADMIN_PASSWORD:-TestRunner!2026secure}"
export ADMIN_PASSWORD="$ADMIN_PASS"

# --- compose file list: base + storage overlay(s) + metrics overlay ----------
COMPOSE_FILES=(-f "${DTF_DIR}/compose.base.yml")
for p in $PROFILES; do
  f="${DTF_DIR}/profiles/${p}.yml"
  [ -f "$f" ] || { echo "!! overlay not found: profiles/${p}.yml" >&2; exit 3; }
  COMPOSE_FILES+=(-f "$f")
done
COMPOSE_FILES+=(-f "${PERF_DIR}/compose.metrics.yml")

RESULTS="${PERF_DIR}/results/${PROFILE}"
rm -rf "$RESULTS"; mkdir -p "$RESULTS/iters"

compose() { docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" "$@"; }

teardown() { [ "$KEEP" = "1" ] && { echo ">> --keep: leaving slot ${PERF_SLOT} up (${BASE_URL})"; return; }; compose down -v >/dev/null 2>&1 && echo ">> slot ${PERF_SLOT} down (volumes removed)"; }

echo "=== PTF profile: ${PROFILE}  (slot ${PERF_SLOT}, image ${BACKEND_IMAGE}, version ${VERSION}) ==="
echo ">>   HTTP=:${HTTP_PORT}  METRICS=:${METRICS_PORT}  PG=:${PG_PORT}  mode=${MODE:-auto}"
if ! compose up -d --wait; then
  echo "!! stack failed to come up healthy" >&2; compose logs backend --tail=80 || true; teardown; exit 7
fi

export RUN_ID="perf-${PROFILE}-${PERF_SLOT}-$(date +%s)"
export PROFILE VERSION GEN
export SWEEP_BYTES_ENV=$(( SWEEP_SIZE_MB * 1048576 ))
export CONCURRENCY FORMATS SWEEP_SIZE_MB REQUESTS_PER_CELL BIGFILE_SIZE_MB BIGFILE_COUNT DEDUP_COUNT
export PERF_THROTTLE_MS="$THROTTLE_MS"

# k6 path needs a bearer token in the harness shell (the bash scenario fetches
# its own via common.sh; the k6 container gets it via env). Fetch once up front.
if [ "$GEN" = "k6" ]; then
  K6_TOKEN="$(perf_fetch_admin_token "$BASE_URL" "$ADMIN_USER" "$ADMIN_PASS")" \
    || { echo "!! k6: failed to obtain admin token from ${BASE_URL}" >&2; teardown; exit 9; }
  export K6_TOKEN
  export K6_IMAGE="${K6_IMAGE:-grafana/k6:latest}"
  export PERF_NET="ak-perf${PERF_SLOT}-net"
  export BACKEND_INTERNAL_URL="http://backend:8080"
fi

# --- one measured iteration --------------------------------------------------
run_iteration() {
  local iter="$1" collect="$2"   # collect=1 to build metrics.json, 0 for warm-up
  local iwork; iwork="$(mktemp -d)"
  export PERF_WORK_DIR="$iwork"
  export RAW_LOG="${iwork}/raw.log"
  export ITER="$iter"

  local STATS_JSONL="${iwork}/docker-stats.jsonl"
  local MSAMPLE_JSONL="${iwork}/metrics-scrape.jsonl"
  local MSTART="${iwork}/metrics-start.txt"
  local MEND="${iwork}/metrics-end.txt"
  local PG_JSON="${iwork}/pg_stat.json"

  if [ "$collect" = "1" ]; then
    perf_pg_reset "$DB_CONTAINER"
    STORAGE_START="$(perf_storage_bytes "$VOLUME_NAME")"
    perf_metrics_snapshot "$METRICS_URL" "$MSTART"
    local spid mpid; spid="$(perf_start_stats_sampler "$STATS_JSONL" "$BACKEND_CONTAINER" "$DB_CONTAINER")"
    mpid="$(perf_start_metrics_sampler "$METRICS_URL" "$MSAMPLE_JSONL")"
    STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local t0; t0="$(date +%s.%N)"
    if [ "$GEN" = "k6" ]; then
      export K6_SUMMARY="${iwork}/k6-summary.json"
      perf_run_k6 "${PERF_DIR}/profiles/${PROFILE}/${SCENARIO}" "$K6_SUMMARY" "${iwork}/k6-stdout.log"
    else
      bash "${PERF_DIR}/profiles/${PROFILE}/${SCENARIO}"
    fi
    local t1; t1="$(date +%s.%N)"
    # Guarantee >=1 Layer-B sample even for sub-2s profiles (the periodic
    # docker-stats sampler needs ~1s per --no-stream tick; a fast run can end
    # before its first tick lands). This synchronous end-sample also captures
    # peak RSS at the moment of maximum load.
    docker stats --no-stream --format '{{json .}}' "$BACKEND_CONTAINER" "$DB_CONTAINER" >> "$STATS_JSONL" 2>/dev/null || true
    perf_stop_sampler "$spid"; perf_stop_sampler "$mpid"
    perf_metrics_snapshot "$METRICS_URL" "$MEND"
    STORAGE_END="$(perf_storage_bytes "$VOLUME_NAME")"
    perf_pg_snapshot "$DB_CONTAINER" 100 > "$PG_JSON"
    DURATION_S="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')"

    export STARTED_AT DURATION_S STATS_JSONL MSAMPLE_JSONL MSTART MEND PG_JSON STORAGE_START STORAGE_END
    perf_build_metrics_json "${RESULTS}/iters/iter-${iter}.json"
    echo ">> iter ${iter}: dur=${DURATION_S}s  requests=$(jq -r '.app.requests' "${RESULTS}/iters/iter-${iter}.json")  p95=$(jq -r '.app.latency_ms.p95' "${RESULTS}/iters/iter-${iter}.json")ms  MB/s=$(jq -r '.app.throughput_mbps' "${RESULTS}/iters/iter-${iter}.json")"
    # keep the LAST measured iteration's raw layer artifacts alongside the report
    cp -f "$STATS_JSONL" "$MSAMPLE_JSONL" "$MSTART" "$MEND" "$RESULTS/" 2>/dev/null || true
  else
    echo ">> warm-up iteration (discarded)..."
    if [ "$GEN" = "k6" ]; then
      export K6_SUMMARY="${iwork}/k6-summary.json"
      perf_run_k6 "${PERF_DIR}/profiles/${PROFILE}/${SCENARIO}" "$K6_SUMMARY" "${iwork}/k6-stdout.log" >/dev/null 2>&1 || true
    else
      bash "${PERF_DIR}/profiles/${PROFILE}/${SCENARIO}" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$iwork"
}

# --- warm-up + measured runs -------------------------------------------------
echo ">> generator=${GEN}  warm-up=${WARMUP}  measured runs=${RUNS}  combine=${PTF_COMBINE:-trimmed}"
for w in $(seq 1 "$WARMUP"); do run_iteration "warmup${w}" 0; done
ITER_JSONS=()
for k in $(seq 1 "$RUNS"); do
  run_iteration "$k" 1
  ITER_JSONS+=("${RESULTS}/iters/iter-${k}.json")
done

# --- combine (trimmed mean, default) -----------------------------------------
FINAL="${RESULTS}/metrics.json"
perf_combine "$FINAL" "${ITER_JSONS[@]}"
echo ">> combined metrics.json written (${PTF_COMBINE:-trimmed} of ${RUNS}): ${FINAL}"

# --- baseline / compare ------------------------------------------------------
BASELINES_DIR="${PERF_DIR}/baselines"
BASELINE_PATH="${BASELINES_DIR}/${VERSION}/${PROFILE}.json"
THRESHOLDS_FILE="${PERF_DIR}/profiles/${PROFILE}/${THRESHOLDS}"
REPORT_MD="${RESULTS}/report.md"

rc=0
if [ "$MODE" = "baseline" ]; then
  mkdir -p "$(dirname "$BASELINE_PATH")"; cp -f "$FINAL" "$BASELINE_PATH"
  echo ">> baseline recorded: baselines/${VERSION}/${PROFILE}.json"
  perf_render_report "$FINAL" "" "$THRESHOLDS_FILE" "$REPORT_MD" "$BASELINES_DIR" "$PROFILE"; rc=$?
else
  CMP=""
  if [ "$MODE" = "compare" ] || { [ -z "$MODE" ] && [ -f "$BASELINE_PATH" ]; }; then
    if [ -f "$BASELINE_PATH" ]; then CMP="$BASELINE_PATH"; else echo "!! --compare requested but no baseline at ${BASELINE_PATH}" >&2; fi
  fi
  perf_render_report "$FINAL" "$CMP" "$THRESHOLDS_FILE" "$REPORT_MD" "$BASELINES_DIR" "$PROFILE"; rc=$?
fi

echo "=== report: ${REPORT_MD} ==="
teardown
exit "$rc"
