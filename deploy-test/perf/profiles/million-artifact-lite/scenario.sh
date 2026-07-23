#!/usr/bin/env bash
# =============================================================================
# profiles/million-artifact-lite/scenario.sh — GEN=bash generator  (Phase 3)
# =============================================================================
# The scaled-down proxy for #2516 "million-artifact readiness". It seeds a LARGE
# but rig-feasible dataset (default 500k artifacts across 5 repos — the "lite"
# that runs in a sane time via the DB-direct bulk seeder, NOT HTTP uploads) and
# then measures the read-plane operations a large customer actually cares about:
#
#   repo_list          list/paging of repositories        GET /repositories
#   artifact_list_p1   list/paging artifacts, shallow      GET /search/advanced?repository_key=&page=1
#   artifact_list_deep list/paging artifacts, DEEP offset  GET /search/advanced?repository_key=&page=DEEP
#   search_quick       quick full-text search              GET /search/quick?q=
#   search_advanced    advanced search + facets over all   GET /search/advanced?query=
#   artifact_metadata  metadata / index read               GET /artifacts/{id}/metadata
#   admin_stats        system stats (full-table aggregate) GET /admin/stats
#   storage_breakdown  per-repo storage stats aggregate    GET /admin/analytics/storage/breakdown
#   storage_growth     storage growth summary              GET /admin/analytics/storage/growth
#   backup             one backup create+execute timing    POST /admin/backups (+execute, bounded, optional)
#
# This is deliberately the heaviest PTF profile: the strategic large-customer
# "readiness at K" snapshot. The headline questions it answers:
#   * per-operation latency at K rows (which surfaces fall over — the #2516
#     hotspots: deep-offset paging, full-table stats/breakdown aggregates);
#   * "lightness": backend peak RSS + CPU while HOLDING K artifacts (Layer B);
#   * db-pool saturation + tail-fairness under concurrent read load (Layer C).
#
# TWO measured phases, both appended to $RAW_LOG (harness Layer-A contract):
#   ops   : concurrency=1, OPS_REPS clean reps of EACH op -> per-operation
#           percentiles (also mirrored to $PTF_OP_LOG for the readiness table).
#   sweep : concurrency=$SWEEP_CONCURRENCY mixed read load (phase label "sweep",
#           required by the harness tail-fairness + pool-saturation reducers).
#   backup: (optional, ONLY on measured iter 1) a single create+execute+poll
#           timing -> $PTF_OP_LOG ONLY (kept OUT of the guarded read aggregate).
#
# RAW_LOG line (harness contract, one per request):
#   <phase> <concurrency> <format> <size_bytes> <http_code> <time_total_s> <resp_bytes>
#   For reads field 7 carries the RESPONSE size (size_download) so Layer-A
#   throughput_mbps == read MB/s (uploads are ~0 here; this profile is read-plane).
#
# $PTF_OP_LOG side-channel (OPTIONAL; set by the operator on the run.sh env, has
# NO effect on the harness): one line per clean (concurrency=1) op request:
#   <iter> <op> <time_ms> <http_code> <resp_bytes>
#   The operator reduces it into the per-operation readiness table. Written only
#   on MEASURED iterations (ITER is numeric); warm-up (ITER=warmupN) is skipped.
#
# Inputs exported by run.sh: BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID,
#   PERF_WORK_DIR, RAW_LOG, ITER, DB_CONTAINER, PERF_THROTTLE_MS, plus the
#   workload knobs below (from the manifest). COMMON_SH -> corpus common.sh.
# Scale-profile knobs (manifest, overridable by env): PERF_DATASET_K,
#   PERF_DATASET_REPOS, PERF_SEED_SIZE_BYTES, OPS_REPS, SWEEP_CONCURRENCY,
#   SWEEP_REQS, PAGE_SIZE, SEARCH_TERM, MEASURE_BACKUP, READ_MAX_TIME.
# =============================================================================
set -uo pipefail

# shellcheck disable=SC1090
source "${COMMON_SH:?set COMMON_SH}"
WORK_DIR="${PERF_WORK_DIR:?set PERF_WORK_DIR}"
mkdir -p "$WORK_DIR"
auth_admin >/dev/null 2>&1 || { echo "scenario: auth failed at ${BASE_URL}" >&2; exit 1; }

: > "$RAW_LOG"
THROTTLE_MS="${PERF_THROTTLE_MS:-0}"

# ---- load the profile's workload knobs from the manifest --------------------
# run.sh exports only the upload-throughput knob set (CONCURRENCY/FORMATS/...),
# NOT this profile's scale knobs, and its manifest-sourcing does not re-export
# them to us. So source the manifest HERE to make it the authoritative source of
# this profile's workload (the analog of run.sh's export for the reference
# profile). The KV below then reads the manifest values (falling back to the
# defaults only if the manifest omits a key).
_MAL_MANIFEST="$(dirname "${BASH_SOURCE[0]}")/manifest"
# shellcheck disable=SC1090
[ -f "$_MAL_MANIFEST" ] && source "$_MAL_MANIFEST"

# ---- workload knobs (from manifest; default if unset) -----------------------
K="${PERF_DATASET_K:-500000}"
R="${PERF_DATASET_REPOS:-5}"
SEED_SIZE="${PERF_SEED_SIZE_BYTES:-4096}"
OPS_REPS="${OPS_REPS:-12}"
SWEEP_CONCURRENCY="${SWEEP_CONCURRENCY:-16}"
SWEEP_REQS="${SWEEP_REQS:-96}"
PAGE_SIZE="${PAGE_SIZE:-50}"
SEARCH_TERM="${SEARCH_TERM:-pkg}"     # every seeded name is '<prefix>-pkg-<n>' -> matches all rows
MEASURE_BACKUP="${MEASURE_BACKUP:-1}"
READ_MAX_TIME="${READ_MAX_TIME:-40}"  # per-request curl ceiling; a heavy op that hits it is a hotspot, not a hang

DB="${DB_CONTAINER:?set DB_CONTAINER}"
API="${BASE_URL}/api/v1"

# is this a measured iteration? (warm-up ITER is "warmupN")
MEASURED=0; case "$ITER" in ''|*[!0-9]*) MEASURED=0 ;; *) MEASURED=1 ;; esac

_psql() { docker exec -i "$DB" psql -v ON_ERROR_STOP=1 -U registry -d artifact_registry -qtA "$@" 2>/dev/null; }

# =============================================================================
# 1. Seed the large dataset ONCE per run.sh invocation (idempotent).
#    The DB persists across warm-up + measured iterations within one slot, so we
#    seed on the first invocation (warm-up) and every later iteration finds the
#    rows already present and skips (no re-scan cost, no timing contamination).
# =============================================================================
SEED_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../harness/lib" && pwd)/seed.sh"
# reproduce seed.sh's prefix scoping so the count-check targets the same rows
SEED_PREFIX="mal-$(printf '%s' "$RUN_ID" | tr -cd 'A-Za-z0-9-')"

seeded_count() { _psql -c "SELECT count(*) FROM artifacts WHERE path LIKE 'seed/${SEED_PREFIX}/%';" | tr -d '[:space:]'; }

cur="$(seeded_count)"; cur="${cur:-0}"
if [ "${cur:-0}" -lt "$K" ]; then
  echo ">> [mal] seeding K=${K} artifacts across R=${R} repos (prefix ${SEED_PREFIX}, have ${cur})..." >&2
  # shellcheck disable=SC1090
  source "$SEED_SH"
  perf_seed --db-container "$DB" --count "$K" --repos "$R" --format generic \
            --size-bytes "$SEED_SIZE" --prefix mal --run-id "$RUN_ID" --metadata 1 --quiet \
    || { echo "scenario: seed FAILED" >&2; exit 1; }
  cur="$(seeded_count)"; cur="${cur:-0}"
  echo ">> [mal] seeded; artifacts now ${cur}" >&2
else
  echo ">> [mal] dataset already present (${cur} >= ${K}); skipping seed" >&2
fi

REPO1="${SEED_PREFIX}-r1"
PER_REPO=$(( K / R )); [ "$PER_REPO" -lt 1 ] && PER_REPO=1
DEEP_PAGE=$(( PER_REPO / PAGE_SIZE - 1 )); [ "$DEEP_PAGE" -lt 1 ] && DEEP_PAGE=1
# resolve one artifact id for the metadata read surface
AID="$(_psql -c "SELECT id FROM artifacts WHERE path LIKE 'seed/${SEED_PREFIX}/%' LIMIT 1;" | tr -d '[:space:]')"

# =============================================================================
# 2. Timed request primitive. Appends the harness RAW_LOG line, and (for clean
#    concurrency=1 ops on measured iterations) mirrors to $PTF_OP_LOG.
# =============================================================================
# timed_get <op> <concurrency> <url> [emit_oplog:0|1]
timed_get() {
  local op="$1" c="$2" url="$3" oplog="${4:-1}"
  [ "$THROTTLE_MS" -gt 0 ] 2>/dev/null && sleep "$(awk -v m="$THROTTLE_MS" 'BEGIN{printf "%.3f", m/1000}')"
  local out code ttot bytes
  out=$(curl -s -o /dev/null --max-time "$READ_MAX_TIME" \
        -w '%{http_code} %{time_total} %{size_download}' \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        "$url" 2>/dev/null) || out="000 ${READ_MAX_TIME} 0"
  read -r code ttot bytes <<<"$out"
  # O_APPEND on a short line is atomic across concurrent workers.
  echo "${op} ${c} ${op} 0 ${code} ${ttot} ${bytes}" >> "$RAW_LOG"
  if [ "$oplog" = "1" ] && [ "$MEASURED" = "1" ] && [ -n "${PTF_OP_LOG:-}" ]; then
    local tms; tms=$(awk -v t="$ttot" 'BEGIN{printf "%.3f", t*1000}')
    echo "${ITER} ${op} ${tms} ${code} ${bytes}" >> "$PTF_OP_LOG"
  fi
}

# one clean pass over every read surface (concurrency=1)
one_op_pass() {
  local rep="$1"
  # rotate the paging depth a little so we sample shallow AND deep offsets
  local mid=$(( (DEEP_PAGE / 2) + 1 ))
  timed_get repo_list          1 "${API}/repositories?page=1&per_page=${PAGE_SIZE}"
  timed_get artifact_list_p1   1 "${API}/search/advanced?repository_key=${REPO1}&page=1&per_page=${PAGE_SIZE}"
  timed_get artifact_list_mid  1 "${API}/search/advanced?repository_key=${REPO1}&page=${mid}&per_page=${PAGE_SIZE}"
  timed_get artifact_list_deep 1 "${API}/search/advanced?repository_key=${REPO1}&page=${DEEP_PAGE}&per_page=${PAGE_SIZE}"
  timed_get search_quick       1 "${API}/search/quick?q=${SEARCH_TERM}&limit=20"
  timed_get search_advanced    1 "${API}/search/advanced?query=${SEARCH_TERM}&per_page=20"
  [ -n "$AID" ] && timed_get artifact_metadata 1 "${API}/artifacts/${AID}/metadata"
  timed_get admin_stats        1 "${API}/admin/stats"
  timed_get storage_breakdown  1 "${API}/admin/analytics/storage/breakdown"
  timed_get storage_growth     1 "${API}/admin/analytics/storage/growth"
}

# =============================================================================
# 3. Phase: ops (concurrency=1) — clean per-operation latencies at scale.
# =============================================================================
for rep in $(seq 1 "$OPS_REPS"); do one_op_pass "$rep"; done

# =============================================================================
# 4. Phase: sweep (concurrency=$SWEEP_CONCURRENCY) — mixed concurrent read load.
#    Drives db-pool saturation + tail-fairness (harness keys tail on phase=sweep
#    at the max concurrency). Each worker loops a rotating mix of read ops.
# =============================================================================
if [ "$SWEEP_CONCURRENCY" -gt 0 ] && [ "$SWEEP_REQS" -gt 0 ]; then
  per=$(( (SWEEP_REQS + SWEEP_CONCURRENCY - 1) / SWEEP_CONCURRENCY ))
  for w in $(seq 1 "$SWEEP_CONCURRENCY"); do
    (
      for k in $(seq 1 "$per"); do
        # rotate across a representative mix (light + heavy) so the tail reflects
        # real contention on the expensive aggregates, not just the cheap list.
        case $(( (w + k) % 5 )) in
          0) timed_get sweep "$SWEEP_CONCURRENCY" "${API}/search/advanced?repository_key=${REPO1}&page=${DEEP_PAGE}&per_page=${PAGE_SIZE}" 0 ;;
          1) timed_get sweep "$SWEEP_CONCURRENCY" "${API}/search/quick?q=${SEARCH_TERM}&limit=20" 0 ;;
          2) timed_get sweep "$SWEEP_CONCURRENCY" "${API}/admin/stats" 0 ;;
          3) timed_get sweep "$SWEEP_CONCURRENCY" "${API}/repositories?page=1&per_page=${PAGE_SIZE}" 0 ;;
          *) timed_get sweep "$SWEEP_CONCURRENCY" "${API}/search/advanced?query=${SEARCH_TERM}&per_page=20" 0 ;;
        esac
      done
    ) &
  done
  wait
fi

# =============================================================================
# 5. Phase: backup (optional; measured iter 1 only). One create+execute+poll
#    timing at scale. Kept OUT of RAW_LOG (not a guarded read metric); recorded
#    to $PTF_OP_LOG. Fully non-fatal + bounded so a missing/slow backup surface
#    never fails or hangs the profile.
# =============================================================================
if [ "$MEASURE_BACKUP" = "1" ] && [ "$MEASURED" = "1" ] && [ "$ITER" = "1" ]; then
  echo ">> [mal] backup timing (iter 1)..." >&2
  bt0="$(date +%s.%N)"
  bresp="$(curl -s --max-time 30 -X POST -H "Authorization: Bearer ${ADMIN_TOKEN}" \
           -H 'Content-Type: application/json' \
           -d "{\"name\":\"mal-${RUN_ID}\",\"description\":\"ptf million-artifact-lite\"}" \
           "${API}/admin/backups" 2>/dev/null)"
  bid="$(printf '%s' "$bresp" | jq -r '.id // .backup.id // empty' 2>/dev/null)"
  bcode_final=000
  if [ -n "$bid" ]; then
    curl -s -o /dev/null --max-time 30 -X POST -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      "${API}/admin/backups/${bid}/execute" 2>/dev/null
    # poll status up to ~90s
    for _p in $(seq 1 45); do
      st="$(curl -s --max-time 15 -H "Authorization: Bearer ${ADMIN_TOKEN}" "${API}/admin/backups/${bid}" 2>/dev/null | jq -r '.status // .backup.status // empty' 2>/dev/null)"
      case "$st" in completed|success|failed|error|cancelled) bcode_final="$st"; break ;; esac
      sleep 2
    done
    [ "$bcode_final" = "000" ] && bcode_final="timeout"
  else
    bcode_final="unsupported"
  fi
  bt1="$(date +%s.%N)"
  bms="$(awk -v a="$bt0" -v b="$bt1" 'BEGIN{printf "%.1f", (b-a)*1000}')"
  echo ">> [mal] backup: status=${bcode_final} elapsed=${bms}ms" >&2
  [ -n "${PTF_OP_LOG:-}" ] && echo "${ITER} backup ${bms} ${bcode_final} 0" >> "$PTF_OP_LOG"
fi

echo "scenario iter ${ITER}: $(wc -l < "$RAW_LOG") read requests logged (K=${cur}, deep_page=${DEEP_PAGE})" >&2
