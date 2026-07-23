#!/usr/bin/env bash
# =============================================================================
# profiles/scan-cost/scenario.sh — GEN=bash generator (Phase 2b, scan-stack cost)
# =============================================================================
# Profiles the vulnerability-scan stack (scanner-adapter + Trivy + in-backend
# grype) resource cost as a function of the scan-submission RATE. Per the
# cost-model recon: scan compute is fire-and-forget, hard-capped at ~4 concurrent
# (MAX_CONCURRENT_SCAN_EXTRACTIONS), and scales with rate x per-scan service
# time, NOT stored artifact count. This scenario drives REAL uploads of a REAL
# vulnerable fixture (grype + Trivy find genuine CVEs => genuine CPU), then:
#   * measures the per-scan service time (warm),
#   * sweeps steady scan-submission RATES (SCAN_RATES) holding each SUSTAIN_SECS,
#   * fires a repo-wide-rescan BURST to saturate the ~4 cap,
# sampling per-container CPU cores + peak RSS for {adapter, backend, postgres}
# at each phase.
#
# HEADLINE (this scenario writes it, the shared harness cannot — report.sh only
# knows backend+postgres): results/scan-cost/scan-cost.{json,md} — a per-rate
# table of scan-stack peak/mean CPU cores + peak RSS + scans/min + in-flight-peak
# vs cap. The shared harness still produces the standard metrics.json/report.md
# (Layer A upload latency, Layer B backend+pg) for the BACKEND under scan load.
#
# RAW_LOG line format (one per upload, so Layer A still builds):
#   <phase> <concurrency> <format> <size_bytes> <http_code> <time_total_s> <upload_bytes>
#
# Inputs (exported by run.sh): BASE_URL, ADMIN_USER, ADMIN_PASS, ADMIN_TOKEN
#   (after auth_admin), RUN_ID, PERF_WORK_DIR, RAW_LOG, ITER, BACKEND_CONTAINER,
#   DB_CONTAINER. COMMON_SH -> corpus tests/lib/common.sh (auth/repo helpers).
#   Scenario knobs from the manifest: SCAN_RATES, SUSTAIN_SECS, POOL_ARTIFACTS,
#   BURST_ARTIFACTS, STATS_HZ, TRIVY_WARM, EXPECTED_CAP.
# =============================================================================
set -uo pipefail

# --- locate our persistent results dir (side-artifact target) ----------------
# run.sh runs this as `bash <perf>/profiles/scan-cost/scenario.sh` and has
# already `mkdir -p`'d results/scan-cost. $PERF_WORK_DIR is a per-iteration
# mktemp (deleted after the iteration), so the headline goes to RESULTS instead.
SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(cd "${SCENARIO_DIR}/../.." && pwd)"
RESULTS="${PERF_DIR}/results/scan-cost"
mkdir -p "$RESULTS"

# shellcheck disable=SC1090
source "${COMMON_SH:?set COMMON_SH}"
# common.sh resets WORK_DIR="" at source; adopt the harness-provided dir after.
WORK_DIR="${PERF_WORK_DIR:?set PERF_WORK_DIR}"
mkdir -p "$WORK_DIR"
auth_admin >/dev/null 2>&1 || { echo "scan-cost: auth failed at ${BASE_URL}" >&2; exit 1; }
: > "$RAW_LOG"

STATS_HZ="${STATS_HZ:-1}"
SUSTAIN_SECS="${SUSTAIN_SECS:-60}"
POOL_ARTIFACTS="${POOL_ARTIFACTS:-12}"
BURST_ARTIFACTS="${BURST_ARTIFACTS:-24}"
EXPECTED_CAP="${EXPECTED_CAP:-4}"
SCAN_RATES="${SCAN_RATES:-6 30 120}"
TRIVY_WARM="${TRIVY_WARM:-1}"

# --- discover the scanner-adapter (trivy) container --------------------------
# scanners.trivy.yml names it ak-dtf<SLOT>-trivy (DTF_SLOT == PERF_SLOT in a PTF
# run); the backend container is ak-perf<SLOT>-backend. Derive the slot, verify,
# and fall back to the compose service-label lookup.
SLOT="${BACKEND_CONTAINER#ak-perf}"; SLOT="${SLOT%-backend}"
ADAPTER_CONTAINER="ak-dtf${SLOT}-trivy"
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$ADAPTER_CONTAINER"; then
  alt="$(docker ps --filter "label=com.docker.compose.project=ak-perf${SLOT}" \
         --filter "label=com.docker.compose.service=trivy" \
         --format '{{.Names}}' 2>/dev/null | head -1)"
  [ -n "$alt" ] && ADAPTER_CONTAINER="$alt"
fi
ADAPTER_FOUND=0
docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$ADAPTER_CONTAINER" && ADAPTER_FOUND=1
echo "scan-cost: backend=${BACKEND_CONTAINER} db=${DB_CONTAINER} adapter=${ADAPTER_CONTAINER} (found=${ADAPTER_FOUND})" >&2

# --- pre-warm the Trivy vuln DB in the adapter (move the ~100MiB download out
#     of the measured scans; mirrors tiers/supply-chain/oracle.sh) ------------
if [ "$ADAPTER_FOUND" = "1" ] && [ "$TRIVY_WARM" = "1" ]; then
  echo "scan-cost: pre-warming Trivy vuln DB in ${ADAPTER_CONTAINER} ..." >&2
  for attempt in 1 2 3 4 5; do
    if docker exec "$ADAPTER_CONTAINER" sh -c \
        'trivy image --cache-dir "${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}" --download-db-only' \
        >/dev/null 2>&1; then
      echo "scan-cost:   Trivy DB warm (attempt ${attempt})" >&2; break
    fi
    echo "scan-cost:   DB warm attempt ${attempt}/5 failed; retry in 5s" >&2; sleep 5
  done
fi

# --- build a REAL, HEAVY vulnerable fixture ----------------------------------
# A single lockfile is milliseconds of scanner CPU (too light to measure). To
# make grype + trivy-fs do genuine, MEASURABLE work per scan, the fixture is a
# tree of FIXTURE_PACKAGES npm packages, each with a package.json +
# package-lock.json pinning known-vulnerable versions, plus a big multi-ecosystem
# lockfile. grype/trivy match EVERY listed package against their vuln DBs, so
# per-scan CPU scales with the package count — the knob that turns the near-idle
# micro-scan into a representative one. FIXTURE_PACKAGES is the per-scan weight.
FIXTURE_PACKAGES="${FIXTURE_PACKAGES:-250}"
FIXROOT="${WORK_DIR}/fixture/app"
mkdir -p "$FIXROOT"
# vulnerable version pool (all have real advisories grype/trivy flag)
VULN_NPM=( "lodash:4.17.4" "minimist:1.2.0" "handlebars:4.0.11" "marked:0.3.6" \
           "js-yaml:3.11.0" "moment:2.19.3" "tar:2.2.1" "debug:2.6.8" \
           "qs:6.3.1" "negotiator:0.6.0" "mem:1.1.0" "hoek:4.2.0" )
np="${#VULN_NPM[@]}"
for i in $(seq 1 "$FIXTURE_PACKAGES"); do
  d="${FIXROOT}/node_modules/pkg${i}"; mkdir -p "$d"
  nv="${VULN_NPM[$(( i % np ))]}"; name="${nv%%:*}"; ver="${nv##*:}"
  printf '{"name":"pkg%s","version":"1.0.0","dependencies":{"%s":"%s"}}\n' "$i" "$name" "$ver" > "${d}/package.json"
  printf '{"name":"pkg%s","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{"%s":{"version":"%s","resolved":"https://registry.npmjs.org/%s/-/%s-%s.tgz"}}}\n' \
    "$i" "$name" "$ver" "$name" "$name" "$ver" > "${d}/package-lock.json"
done
# a root lockfile grype reads as one big project too
{ printf '{"name":"ptf-scan-cost","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{'
  for i in $(seq 0 $(( np - 1 ))); do
    nv="${VULN_NPM[$i]}"; name="${nv%%:*}"; ver="${nv##*:}"
    [ "$i" -gt 0 ] && printf ','
    printf '"%s":{"version":"%s","resolved":"https://registry.npmjs.org/%s/-/%s-%s.tgz"}' "$name" "$ver" "$name" "$name" "$ver"
  done
  printf '}}\n'; } > "${FIXROOT}/package-lock.json"
FIXTURE_TGZ="${WORK_DIR}/scan-cost-fixture.tgz"
tar -C "${WORK_DIR}/fixture" -czf "$FIXTURE_TGZ" app 2>/dev/null
FIXTURE_BYTES="$(stat -c '%s' "$FIXTURE_TGZ" 2>/dev/null || echo 0)"
echo "scan-cost: fixture = ${FIXTURE_PACKAGES} vuln packages, ${FIXTURE_BYTES} bytes gz" >&2

REPO_KEY="perf-scancost-${ITER}-${RUN_ID}"
create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1 \
  || create_repo "$REPO_KEY" generic local >/dev/null 2>&1 \
  || { echo "scan-cost: could not create repo ${REPO_KEY}" >&2; exit 1; }
# resolve the repository UUID (repo-wide rescan needs repository_id, not key)
REPO_ID="$(curl -s -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REPO_KEY}" 2>/dev/null \
  | jq -r '.id // .repository.id // empty' 2>/dev/null)"
echo "scan-cost: repo ${REPO_KEY} id=${REPO_ID:-<unresolved>}" >&2

# --- upload one fixture copy; append RAW_LOG; echo the artifact_id ------------
upload_one() {
  local path="$1" out code tt su
  out=$(curl -s -o /dev/null -w '%{http_code} %{time_total} %{size_upload}' \
        -X PUT -H "$(auth_header)" -H "Content-Type: application/gzip" \
        --data-binary "@${FIXTURE_TGZ}" \
        "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${path}" 2>/dev/null) || out="000 0 0"
  read -r code tt su <<<"$out"
  echo "sweep 1 generic ${FIXTURE_BYTES} ${code} ${tt} ${su}" >> "$RAW_LOG"
  # resolve id from the repo listing (upload response shape varies by build)
  curl -s -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null \
    | jq -er --arg p "$path" '.items | map(select(.path==$p or .name==$p)) | first | .id // empty' 2>/dev/null || echo ""
}

# trigger a scan for one artifact (force=true => always re-scans). echoes HTTP code.
trigger_artifact() {
  local id="$1"
  curl -s -o /dev/null -w '%{http_code}' -X POST -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg id "$id" '{artifact_id:$id, force:true}')" \
    "${BASE_URL}/api/v1/security/scan" 2>/dev/null || echo "000"
}

# repo scans list -> "<terminal_rows> <nonterminal_rows> <total_rows>"
repo_scan_counts() {
  local body
  body=$(curl -s -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/security/scans?per_page=1000" 2>/dev/null)
  printf '%s' "$body" | jq -r '
    (.items // .scans // []) as $it |
    ($it | map(select((.status|ascii_downcase) as $s | $s=="completed" or $s=="clean" or $s=="failed" or $s=="error" or $s=="timeout" or $s=="not_applicable")) | length) as $term |
    "\($term) \(($it|length)-$term) \($it|length)"' 2>/dev/null || echo "0 0 0"
}

# --- per-container CGROUP sampler --------------------------------------------
# docker-stats CPUPerc is sampled too coarsely (~2.5s effective) to catch short,
# bursty scan CPU (it under-read a 27% adapter spike as 0.9%). Instead we read
# the container's cgroup-v2 cumulative CPU time (cpu.stat usage_usec) +
# memory.current per tick; the DELTA in CPU-microseconds over an interval is the
# EXACT cores consumed in that interval, independent of snapshot timing. Line
# format: "<epoch_ms> <container> <usage_usec> <mem_bytes>".
# Reads cgroup files from the HOST (via the container's init-PID cgroup path),
# NOT `docker exec`, because the backend is a shell-less hardened image (#2059)
# where `docker exec sh` fails. Host-side reads work for every container and add
# no exec overhead. Resolves each container's cgroup base ONCE, then reads
# cpu.stat + memory.current per tick.
start_scan_sampler() {
  local out="$1"; : > "$out"
  local conts=("$BACKEND_CONTAINER" "$DB_CONTAINER")
  [ "$ADAPTER_FOUND" = "1" ] && conts=("$ADAPTER_CONTAINER" "${conts[@]}")
  local names=() cpaths=() mpaths=() c pid cg base
  for c in "${conts[@]}"; do
    pid="$(docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null)"
    { [ -z "$pid" ] || [ "$pid" = "0" ]; } && continue
    cg="$(awk -F: '/^0::/{print $3}' "/proc/${pid}/cgroup" 2>/dev/null)"
    base="/sys/fs/cgroup${cg}"
    [ -f "${base}/cpu.stat" ] || continue
    names+=("$c"); cpaths+=("${base}/cpu.stat"); mpaths+=("${base}/memory.current")
  done
  (
    while :; do
      local now i u m
      now="$(date +%s%3N)"
      for i in "${!names[@]}"; do
        u="$(awk '/usage_usec/{print $2}' "${cpaths[$i]}" 2>/dev/null)"
        m="$(cat "${mpaths[$i]}" 2>/dev/null)"
        [ -n "$u" ] && echo "${now} ${names[$i]} ${u} ${m:-0}" >> "$out"
      done
      sleep "$STATS_HZ"
    done
  ) >/dev/null 2>&1 &
  echo $!
}
stop_sampler() { local pid="$1"; [ -n "$pid" ] && kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true; }

# reduce cgroup sampler log for ONE container -> "cores_peak cores_mean rss_peak_bytes samples"
# cores_peak = max over any inter-tick interval; cores_mean = total CPU-seconds
# over the whole window / window seconds (the cost-model input).
reduce_container() {
  local f="$1" cont="$2"
  awk -v c="$cont" '
    $2==c {
      t=$1/1000.0; u=$3; m=$4+0;
      if(m>rpk)rpk=m;
      if(seen){ dt=t-pt; du=u-pu; if(dt>0){ cores=(du/1e6)/dt; if(cores>cpk)cpk=cores } }
      else { u0=u; t0=t; seen=1 }
      un=u; tn=t; pt=t; pu=u; n++
    }
    END{ if(n==0){print "0 0 0 0"; exit}
      mean=(tn>t0)?((un-u0)/1e6)/(tn-t0):0;
      printf "%.3f %.3f %.0f %d", cpk, mean, rpk, n }' "$f"
}

# max non-terminal (in-flight) rows observed across a poll log (one int/line)
reduce_inflight_peak() { awk 'BEGIN{m=0}{if($1>m)m=$1}END{print m+0}' "$1" 2>/dev/null || echo 0; }

# --- measure ONE warm per-scan service time (submit -> all rows terminal) ----
measure_service_time() {
  local id="$1" t0 t1 term nonterm total elapsed=0
  t0="$(date +%s.%N)"
  trigger_artifact "$id" >/dev/null
  while [ "$elapsed" -lt 180 ]; do
    read -r term nonterm total < <(repo_scan_counts)
    [ "${total:-0}" -gt 0 ] && [ "${nonterm:-1}" -eq 0 ] && break
    sleep 2; elapsed=$(( elapsed + 2 ))
  done
  t1="$(date +%s.%N)"
  awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}'
}

# =============================================================================
# Build the pre-uploaded artifact pool (uploads are cheap; scans are the cost)
# =============================================================================
POOL_IDS=()
NPOOL=$(( POOL_ARTIFACTS > BURST_ARTIFACTS ? POOL_ARTIFACTS : BURST_ARTIFACTS ))
echo "scan-cost: uploading pool of ${NPOOL} fixture artifacts ..." >&2
for i in $(seq 1 "$NPOOL"); do
  id="$(upload_one "pool/a${i}.tgz")"
  [ -n "$id" ] && POOL_IDS+=("$id")
done
echo "scan-cost: pool ready (${#POOL_IDS[@]}/${NPOOL} ids resolved)" >&2
if [ "${#POOL_IDS[@]}" -eq 0 ]; then
  echo "scan-cost: FATAL no artifact ids resolved; cannot drive scans" >&2
  jq -n --arg reason "no artifact ids resolved after upload (upload or list API failure)" \
    '{profile:"scan-cost", status:"BLOCKED", reason:$reason, phases:[]}' > "${RESULTS}/scan-cost.json"
  exit 1
fi

# one warm service-time sample (also confirms scans actually complete)
SERVICE_T="$(measure_service_time "${POOL_IDS[0]}")"
echo "scan-cost: warm per-scan service time ~= ${SERVICE_T}s" >&2

PHASES_JSON="[]"
append_phase() { PHASES_JSON="$(jq -c --argjson p "$1" '. + [$p]' <<<"$PHASES_JSON")"; }

# --- run one steady-rate phase ----------------------------------------------
# args: label rate_per_min sustain_secs  (rate<=0 => burst=all-at-once)
run_phase() {
  local label="$1" rate="$2" sustain="$3"
  local sfile="${WORK_DIR}/stats-${label}.jsonl" ifile="${WORK_DIR}/inflight-${label}.log"
  : > "$ifile"
  local spid; spid="$(start_scan_sampler "$sfile")"
  # in-flight poller
  ( while :; do read -r _t nt _tot < <(repo_scan_counts); echo "${nt:-0}" >> "$ifile"; sleep "$STATS_HZ"; done ) >/dev/null 2>&1 &
  local ipid="$!"

  # baseline scan-row count so we measure rows ADDED during this phase, not the
  # cumulative repo total (force re-scans accumulate rows).
  local rows_before _nt0 _tot0
  read -r rows_before _nt0 _tot0 < <(repo_scan_counts); rows_before="${_tot0:-0}"

  local submitted=0 t0 t1 t0i pn="${#POOL_IDS[@]}"
  t0="$(date +%s.%N)"; t0i="$(date +%s)"
  if [ "$rate" -le 0 ]; then
    # BURST: fire N triggers back-to-back to saturate the ~cap. Prefer a single
    # repo-wide rescan (repository_id, per the trigger_scan handler); fall back
    # to a per-artifact fan if repo-wide is unavailable.
    local rc=400
    if [ -n "$REPO_ID" ]; then
      rc=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$(auth_header)" \
            -H "Content-Type: application/json" \
            -d "$(jq -n --arg r "$REPO_ID" '{repository_id:$r, force:true}')" \
            "${BASE_URL}/api/v1/security/scan" 2>/dev/null || echo 000)
    fi
    if [[ "$rc" == 2* ]]; then
      submitted="$BURST_ARTIFACTS"
      echo "scan-cost: [${label}] repo-wide rescan accepted (HTTP ${rc})" >&2
    else
      echo "scan-cost: [${label}] repo-wide rescan HTTP ${rc}; falling back to per-artifact fan" >&2
      local n bpids=()
      for n in $(seq 0 $(( BURST_ARTIFACTS - 1 ))); do
        trigger_artifact "${POOL_IDS[$(( n % pn ))]}" >/dev/null &
        bpids+=("$!"); submitted=$(( submitted + 1 ))
      done
      # wait ONLY on the trigger curls, never bare `wait` (the sampler + poller
      # are also background jobs of this shell and never exit).
      [ "${#bpids[@]}" -gt 0 ] && wait "${bpids[@]}" 2>/dev/null
    fi
  else
    # STEADY: submit at `rate`/min (interval=60/rate) for `sustain` secs. Each
    # trigger runs FOREGROUND (curl ~200ms); the interval sleep paces the rate.
    # No bare `wait` here — it would block on the never-ending sampler/poller.
    local interval; interval="$(awk -v r="$rate" 'BEGIN{printf "%.3f", 60.0/r}')"
    local end_epoch=$(( $(date +%s) + sustain )) k=0
    while [ "$(date +%s)" -lt "$end_epoch" ]; do
      trigger_artifact "${POOL_IDS[$(( k % pn ))]}" >/dev/null
      submitted=$(( submitted + 1 )); k=$(( k + 1 ))
      sleep "$interval"
    done
  fi

  # settle: wait for the async scans to register as in-flight (bounded), so a
  # poll landing BEFORE the fire-and-forget rows appear cannot false-drain.
  local settle=0 term nonterm total
  while [ "$settle" -lt 15 ]; do
    read -r term nonterm total < <(repo_scan_counts)
    { [ "${nonterm:-0}" -gt 0 ] || [ "${total:-0}" -gt "$rows_before" ]; } && break
    sleep 1; settle=$(( settle + 1 ))
  done
  # drain floor: guarantee the measured window covers the REAL processing time
  # even when the 1Hz poller cannot observe fast (~service_t) scans concurrently.
  # Lower bound = service_t x ceil(submitted / cap), clamped to [5,180]s. The
  # cgroup CPU-seconds captured over this window give accurate mean cores.
  local st_int; st_int="$(awk -v s="${SERVICE_T:-2}" 'BEGIN{v=(s<1?1:s); printf "%d", (v==int(v)?v:int(v)+1)}')"
  local min_active=$(( st_int * ( (submitted + EXPECTED_CAP - 1) / EXPECTED_CAP ) ))
  [ "$min_active" -lt 5 ] && min_active=5; [ "$min_active" -gt 180 ] && min_active=180
  # drain: until all repo scans terminal AND the floor has elapsed (bounded)
  local drain=0 since0=0
  while [ "$drain" -lt 300 ]; do
    read -r term nonterm total < <(repo_scan_counts)
    since0=$(( $(date +%s) - t0i ))
    [ "${nonterm:-1}" -eq 0 ] && [ "$since0" -ge "$min_active" ] && break
    sleep "$STATS_HZ"; drain=$(( drain + STATS_HZ ))
  done
  t1="$(date +%s.%N)"
  stop_sampler "$spid"; stop_sampler "$ipid"

  read -r term nonterm total < <(repo_scan_counts)
  local completed=$(( ${total:-0} - rows_before )); [ "$completed" -lt 0 ] && completed=0
  local elapsed; elapsed="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')"
  local a_c b_c d_c; a_c="$(reduce_container "$sfile" "$ADAPTER_CONTAINER")"
  b_c="$(reduce_container "$sfile" "$BACKEND_CONTAINER")"; d_c="$(reduce_container "$sfile" "$DB_CONTAINER")"
  local a_pk a_mn a_rss a_n; read -r a_pk a_mn a_rss a_n <<<"$a_c"
  local b_pk b_mn b_rss b_n; read -r b_pk b_mn b_rss b_n <<<"$b_c"
  local dpk dmn drss dn;    read -r dpk dmn drss dn    <<<"$d_c"
  local ifpeak; ifpeak="$(reduce_inflight_peak "$ifile")"
  # scans/min = scan ROWS COMPLETED during THIS phase (rows added) / elapsed.
  local spm; spm="$(awk -v t="$completed" -v e="$elapsed" 'BEGIN{printf "%.1f", (e>0)? t*60.0/e : 0}')"

  echo "scan-cost: [${label}] submitted=${submitted} completed_rows=${completed} elapsed=${elapsed}s scans/min=${spm} adapter_cores_peak=${a_pk} adapter_cores_mean=${a_mn} backend_cores_peak=${b_pk} inflight_peak=${ifpeak}" >&2
  append_phase "$(jq -n \
    --arg label "$label" --argjson rate "$rate" --argjson sustain "$sustain" \
    --argjson submitted "$submitted" --argjson rows "$completed" --argjson elapsed "$elapsed" \
    --argjson spm "$spm" --argjson ifpeak "$ifpeak" --argjson cap "$EXPECTED_CAP" \
    --argjson a_pk "${a_pk:-0}" --argjson a_mn "${a_mn:-0}" --argjson a_rss "${a_rss:-0}" \
    --argjson b_pk "${b_pk:-0}" --argjson b_mn "${b_mn:-0}" --argjson b_rss "${b_rss:-0}" \
    --argjson d_pk "${dpk:-0}"  --argjson d_rss "${drss:-0}" \
    '{label:$label, rate_per_min:$rate, sustain_secs:$sustain, submitted:$submitted,
      scan_rows_completed:$rows, elapsed_s:$elapsed, scans_per_min:$spm,
      inflight_peak:$ifpeak, cap:$cap,
      scan_stack:{ adapter:{cpu_cores_peak:$a_pk, cpu_cores_mean:$a_mn, rss_bytes_peak:$a_rss},
                   backend:{cpu_cores_peak:$b_pk, cpu_cores_mean:$b_mn, rss_bytes_peak:$b_rss},
                   postgres:{cpu_cores_peak:$d_pk, rss_bytes_peak:$d_rss} }}')"
}

# =============================================================================
# Steady-rate sweep + burst
# =============================================================================
for r in $SCAN_RATES; do run_phase "steady-${r}pm" "$r" "$SUSTAIN_SECS"; done
run_phase "burst" 0 0

# =============================================================================
# Write the headline side-artifact (json + md)
# =============================================================================
jq -n \
  --arg image "${BACKEND_IMAGE:-unknown}" --arg version "${VERSION:-unknown}" \
  --arg run_id "$RUN_ID" --arg adapter "$ADAPTER_CONTAINER" --argjson found "$ADAPTER_FOUND" \
  --argjson service_t "${SERVICE_T:-0}" --argjson cap "$EXPECTED_CAP" \
  --argjson fixture_bytes "${FIXTURE_BYTES:-0}" --argjson pool "${#POOL_IDS[@]}" \
  --argjson phases "$PHASES_JSON" \
  '{profile:"scan-cost", status:"OK", backend_image:$image, version:$version, run_id:$run_id,
    adapter_container:$adapter, adapter_found:($found==1),
    warm_per_scan_service_time_s:$service_t, concurrency_cap:$cap,
    fixture_bytes:$fixture_bytes, pool_artifacts:$pool, phases:$phases,
    note:"cores from cgroup cpu.stat usage_usec delta / interval (exact CPU-seconds/sec; cpu_cores_mean = total CPU-seconds over the phase / window). Scan compute is fire-and-forget capped at concurrency_cap. Headline = scan_stack.adapter cores vs rate_per_min. inflight_peak is a 1Hz poll and can under-read scans shorter than the poll period."
  }' > "${RESULTS}/scan-cost.json"

{
  echo "# PTF scan-cost — scan-stack resource cost vs scan-submission rate"
  echo
  echo "backend image: \`${BACKEND_IMAGE:-unknown}\`  |  adapter: \`${ADAPTER_CONTAINER}\` (found=${ADAPTER_FOUND})"
  echo "warm per-scan service time: ~${SERVICE_T}s  |  concurrency cap: ${EXPECTED_CAP}  |  fixture: ${FIXTURE_BYTES} bytes"
  echo
  echo "## Scan-stack cost per rate (cores = CPU-seconds/sec, host-normalized)"
  echo
  echo "| phase | rate/min | scans/min | adapter cores peak | adapter cores mean | adapter RSS peak | backend cores peak | in-flight peak | cap |"
  echo "|---|---|---|---|---|---|---|---|---|"
  jq -r '.phases[] | "| \(.label) | \(.rate_per_min) | \(.scans_per_min) | \(.scan_stack.adapter.cpu_cores_peak) | \(.scan_stack.adapter.cpu_cores_mean) | \(.scan_stack.adapter.rss_bytes_peak/1048576|floor)MiB | \(.scan_stack.backend.cpu_cores_peak) | \(.inflight_peak) | \(.cap) |"' \
    "${RESULTS}/scan-cost.json"
  echo
  echo "_cores from cgroup cpu.stat usage_usec (exact CPU-seconds/sec); cores mean = total CPU-seconds / phase window. Scans are fire-and-forget, capped at ${EXPECTED_CAP} concurrent; in-flight-peak (a 1Hz poll) approaching the cap means the offered rate is saturating the scan pool. cores_mean is the cost-model input (cores per sustained rate)._"
  echo
  echo "_Caveats: (1) scans/min + in-flight are derived from GET /repositories/{key}/security/scans, which COLLAPSES not_applicable rows per artifact and paginates, so throughput/backlog under-read at high rate (the CORES numbers, from cgroup, are unaffected). (2) This fixture drives the FILESYSTEM/dependency scan path (grype + trivy fs over lockfiles), which is CPU-light — the dominant cost here is the adapter's fixed ~1.2GB RSS (the Trivy vuln DB) and the BACKEND CPU for scan orchestration, NOT adapter CPU. The heavy-CPU container-IMAGE scan path (trivy image = layer unpack + OS-package scan) needs an OCI push driver and is the next increment._"
} > "${RESULTS}/scan-cost.md"

echo "scan-cost: wrote ${RESULTS}/scan-cost.json + scan-cost.md" >&2
echo "scan-cost iter ${ITER}: $(wc -l < "$RAW_LOG") uploads logged, $(jq '.phases|length' "${RESULTS}/scan-cost.json") phases" >&2
