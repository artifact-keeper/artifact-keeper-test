#!/usr/bin/env bash
# =============================================================================
# profiles/upload-throughput/scenario.sh — GEN=bash generator  (Phase 1)
# =============================================================================
# Generalizes the corpus test/tests/stress/test-throughput.sh from a sequential
# static-floor check into a concurrency/size/format sweep that emits ONE raw
# line per request for the harness to reduce into Layer-A percentiles + MB/s.
#
# Three workload phases (all PUT /api/v1/repositories/{key}/artifacts/{path}):
#   sweep   : concurrency sweep C in $CONCURRENCY, $REQUESTS_PER_CELL uploads of
#             $SWEEP_SIZE_MB per cell, per format in $FORMATS -> percentiles,
#             throughput_rps, error-rate, tail-fairness (#2598).
#   bigfile : C=1, $BIGFILE_COUNT uploads of $BIGFILE_SIZE_MB -> raw MB/s.
#   dedup   : $DEDUP_COUNT uploads of ONE identical blob -> Layer-D dedup signal.
#
# RAW_LOG line format (one per request):
#   <phase> <concurrency> <format> <size_bytes> <http_code> <time_total_s> <upload_bytes>
#
# Inputs (exported by run.sh): BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID,
#   WORK_DIR, RAW_LOG, ITER, CONCURRENCY, SWEEP_SIZE_MB, REQUESTS_PER_CELL,
#   FORMATS, BIGFILE_SIZE_MB, BIGFILE_COUNT, DEDUP_COUNT, PERF_THROTTLE_MS.
#   COMMON_SH points at the corpus tests/lib/common.sh (auth/repo helpers).
# =============================================================================
set -uo pipefail

# shellcheck disable=SC1090
source "${COMMON_SH:?set COMMON_SH}"
# common.sh resets WORK_DIR="" at source time, so adopt the harness-provided dir
# AFTER sourcing (run.sh passes it as PERF_WORK_DIR).
WORK_DIR="${PERF_WORK_DIR:?set PERF_WORK_DIR}"
mkdir -p "$WORK_DIR"
auth_admin >/dev/null 2>&1 || { echo "scenario: auth failed at ${BASE_URL}" >&2; exit 1; }

: > "$RAW_LOG"
THROTTLE_MS="${PERF_THROTTLE_MS:-0}"

# --- pre-generate one random payload per distinct size -----------------------
gen_payload() {  # <size_mb> -> path (cached per size)
  local mb="$1"
  local f="${WORK_DIR}/payload_${mb}mb.bin"
  [ -f "$f" ] || dd if=/dev/urandom bs=1048576 count="$mb" of="$f" 2>/dev/null
  echo "$f"
}

# one PUT; appends a RAW_LOG line. args: phase concurrency format repo path file sizebytes
put_one() {
  local phase="$1" c="$2" fmt="$3" repo="$4" path="$5" file="$6" szb="$7"
  [ "$THROTTLE_MS" -gt 0 ] 2>/dev/null && sleep "$(awk -v m="$THROTTLE_MS" 'BEGIN{printf "%.3f", m/1000}')"
  local out
  out=$(curl -s -o /dev/null -w '%{http_code} %{time_total} %{size_upload}' \
        -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@${file}" \
        "${BASE_URL}/api/v1/repositories/${repo}/artifacts/${path}" 2>/dev/null) || out="000 0 0"
  # O_APPEND on a short (<4KB) line is atomic across the concurrent workers.
  echo "${phase} ${c} ${fmt} ${szb} ${out}" >> "$RAW_LOG"
}

SWEEP_BYTES=$(( SWEEP_SIZE_MB * 1048576 ))
sweep_file="$(gen_payload "$SWEEP_SIZE_MB")"

# --- phase: sweep (per format, per concurrency) ------------------------------
gidx=0
for fmt in $FORMATS; do
  repo="perf-ut-${fmt}-${ITER}-${RUN_ID}"
  create_repo "$repo" "$fmt" "local" >/dev/null 2>&1 || create_local_repo "$repo" generic >/dev/null 2>&1
  for c in $CONCURRENCY; do
    per=$(( (REQUESTS_PER_CELL + c - 1) / c ))
    for w in $(seq 1 "$c"); do
      (
        for k in $(seq 1 "$per"); do
          # path must be globally unique within the run (c AND w AND k) so an
          # immutable format (maven) never 409s on a re-used path across cells.
          put_one sweep "$c" "$fmt" "$repo" "sweep/c${c}/w${w}/n${k}.bin" "$sweep_file" "$SWEEP_BYTES"
        done
      ) &
    done
    wait
  done
done

# --- phase: bigfile (raw MB/s, C=1) ------------------------------------------
if [ "${BIGFILE_COUNT:-0}" -gt 0 ]; then
  big_file="$(gen_payload "$BIGFILE_SIZE_MB")"
  big_bytes=$(( BIGFILE_SIZE_MB * 1048576 ))
  repo="perf-ut-bigfile-${ITER}-${RUN_ID}"
  create_local_repo "$repo" generic >/dev/null 2>&1
  for k in $(seq 1 "$BIGFILE_COUNT"); do
    put_one bigfile 1 generic "$repo" "big/n${k}.bin" "$big_file" "$big_bytes"
  done
fi

# --- phase: dedup (identical blob N times) -----------------------------------
if [ "${DEDUP_COUNT:-0}" -gt 0 ]; then
  dedup_file="${WORK_DIR}/dedup_blob.bin"
  [ -f "$dedup_file" ] || dd if=/dev/urandom bs=1048576 count="$SWEEP_SIZE_MB" of="$dedup_file" 2>/dev/null
  repo="perf-ut-dedup-${ITER}-${RUN_ID}"
  create_local_repo "$repo" generic >/dev/null 2>&1
  for k in $(seq 1 "$DEDUP_COUNT"); do
    put_one dedup 1 generic "$repo" "dedup/n${k}.bin" "$dedup_file" "$SWEEP_BYTES"
  done
fi

echo "scenario iter ${ITER}: $(wc -l < "$RAW_LOG") requests logged" >&2
