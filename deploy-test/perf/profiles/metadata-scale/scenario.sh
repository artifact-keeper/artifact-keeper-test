#!/usr/bin/env bash
# =============================================================================
# profiles/metadata-scale/scenario.sh — GEN=bash generator  (Phase 2b, #2521)
# =============================================================================
# Measures how the WHOLE-REPO synchronous metadata/index regeneration time
# scales with repository size (artifact count K). This is the #2521 signal:
# an index endpoint that rebuilds the entire repo index from every artifact row
# on every request, uncached, so its latency grows with K.
#
# WORKLOAD (per measured iteration):
#   For each K in $SCALE_K_VALUES (ascending), grow ONE fresh per-iteration repo
#   to K artifacts with harness/lib/seed.sh (DB-direct, ~17k rows/s), then fire
#   $REGEN_REQUESTS_PER_K GETs at the regen endpoint and time each. Seeding is
#   cumulative WITHIN the iteration (1000 -> +9000 -> +40000), and the repo is
#   fresh each iteration (prefix embeds $ITER) so "K=1000" always regenerates
#   over exactly 1000 rows, never a leftover 50000 from a prior iteration.
#
# THE REGEN ENDPOINT (target-backend @1.6.2-rc, see manifest for the code path):
#   GET /{SCALE_FORMAT}/{repo_key}/{REGEN_PATH}
#   default rpm repomd.xml -> list_rpm_artifacts (O(K) fetch, no path filter) +
#   generate_repomd_xml_content (build+sha256 primary/filelists/other, O(K) CPU).
#   The response stays tiny (an index-of-indexes) while the work is O(K): latency
#   grows with K but bytes do not -> pure synchronous regen cost.
#
# K IS ENCODED IN THE RAW_LOG "concurrency" FIELD so the harness's existing
# Layer-A reduction does the right thing with ZERO changes to run.sh/report.sh:
#   - overall app.latency_ms.p95  == regen latency at the LARGEST K (the top
#     bucket dominates the tail; that is the guarded "at scale" number).
#   - app.tail_at_max_conc (phase=="sweep", concurrency==max K) == p99/p50 spread
#     of the largest-K regen.
# The per-K scaling curve (median regen ms at each K) is emitted to stderr as
# ">> SCALING ..." lines for the run console + the report author to lift.
#
# RAW_LOG line format (one per regen GET):
#   <phase> <concurrency=K> <format> <size_bytes=0> <http_code> <time_total_s> <resp_bytes>
#
# Inputs exported by run.sh: BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID,
#   PERF_WORK_DIR, RAW_LOG, ITER, DB_CONTAINER, PERF_THROTTLE_MS, COMMON_SH.
# =============================================================================
set -uo pipefail

# shellcheck disable=SC1090
source "${COMMON_SH:?set COMMON_SH}"
# common.sh resets WORK_DIR="" at source time; adopt the harness dir afterwards.
WORK_DIR="${PERF_WORK_DIR:?set PERF_WORK_DIR}"
mkdir -p "$WORK_DIR"

# --- resolve this profile's own knobs ----------------------------------------
# run.sh exports only the legacy upload-throughput workload set (CONCURRENCY,
# FORMATS, ...) to the scenario, so the metadata-scale knobs are pulled by
# re-sourcing our sibling manifest. NOTE: these knobs are configured IN THE
# MANIFEST, not via the environment -- run.sh sources the manifest into its own
# (exported) shell, so an env-provided SCALE_* value would be clobbered by the
# manifest before the scenario ever runs. Edit the manifest to change them.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(cd "${SELF_DIR}/../.." && pwd)"
# shellcheck disable=SC1091
source "${SELF_DIR}/manifest"
SCALE_K_VALUES="${SCALE_K_VALUES:-1000 10000 50000}"
SCALE_FORMAT="${SCALE_FORMAT:-rpm}"
REGEN_PATH="${REGEN_PATH:-repodata/repomd.xml}"
REGEN_REQUESTS_PER_K="${REGEN_REQUESTS_PER_K:-6}"
SEED_REPOS="${SEED_REPOS:-1}"
THROTTLE_MS="${PERF_THROTTLE_MS:-0}"

# --- auth + seeder -----------------------------------------------------------
auth_admin >/dev/null 2>&1 || { echo "scenario: auth failed at ${BASE_URL}" >&2; exit 1; }
# shellcheck disable=SC1091
source "${PERF_DIR}/harness/lib/seed.sh"
[ -n "${DB_CONTAINER:-}" ] || { echo "scenario: DB_CONTAINER not set by run.sh" >&2; exit 1; }

: > "$RAW_LOG"

# one regen GET; appends a RAW_LOG line. args: K repo_key
regen_get() {
  local k="$1" repo="$2"
  [ "$THROTTLE_MS" -gt 0 ] 2>/dev/null && sleep "$(awk -v m="$THROTTLE_MS" 'BEGIN{printf "%.3f", m/1000}')"
  local out
  out=$(curl -s -o /dev/null -w '%{http_code} %{time_total} %{size_download}' \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        "${BASE_URL}/${SCALE_FORMAT}/${repo}/${REGEN_PATH}" 2>/dev/null) || out="000 0 0"
  # phase="sweep" so the harness tail-fairness reduction keys on it; concurrency
  # field carries K; size_bytes=0 (GET, no upload).
  echo "sweep ${k} ${SCALE_FORMAT} 0 ${out}" >> "$RAW_LOG"
}

# --- per-K seed + measure ----------------------------------------------------
# fresh repo per iteration; seeded cumulatively across the ascending K list.
REPO_KEY=""
for K in $SCALE_K_VALUES; do
  # grow the repo to K total rows (idempotent; adds only the new rows).
  perf_seed --db-container "$DB_CONTAINER" --count "$K" --repos "$SEED_REPOS" \
            --format "$SCALE_FORMAT" --prefix "mds-i${ITER}" --run-id "$RUN_ID" \
            --metadata 1 --quiet >/dev/null 2>&1 \
    || { echo "scenario: seed to K=${K} failed" >&2; exit 1; }
  REPO_KEY="${PERF_SEED_PREFIX}-r1"

  # fire the regen GETs and collect their times for a per-K stderr summary.
  ktimes="${WORK_DIR}/ktimes_${K}.txt"; : > "$ktimes"
  for r in $(seq 1 "$REGEN_REQUESTS_PER_K"); do
    regen_get "$K" "$REPO_KEY"
    tail -1 "$RAW_LOG" | awk '{printf "%.3f\n", $6*1000}' >> "$ktimes"
  done

  # per-K scaling line: median + p95 (ms) + last HTTP code, to the run console.
  read -r kmed kp95 <<<"$(sort -n "$ktimes" | awk '
    {a[NR]=$1} END{ n=NR; if(n==0){print "0 0"; exit}
      m=a[int((n-1)/2)+1]; i=int(0.95*(n-1))+1; if(i<1)i=1; if(i>n)i=n;
      printf "%.1f %.1f", m, a[i] }')"
  klast=$(tail -1 "$RAW_LOG" | awk '{print $5}')
  echo ">> SCALING iter=${ITER} K=${K} n=${REGEN_REQUESTS_PER_K} median_ms=${kmed} p95_ms=${kp95} http=${klast} repo=${REPO_KEY}" >&2
done

echo "scenario iter ${ITER}: $(wc -l < "$RAW_LOG") regen GETs logged across K in [${SCALE_K_VALUES}]" >&2
