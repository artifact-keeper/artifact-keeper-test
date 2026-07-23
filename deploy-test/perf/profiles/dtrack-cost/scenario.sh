#!/usr/bin/env bash
# =============================================================================
# profiles/dtrack-cost/scenario.sh — GEN=bash  (Phase 2b, Dependency-Track cost)
# =============================================================================
# Profiles Dependency-Track component cost: the fixed heavy-JVM RSS floor + cores
# + its Postgres DB growth vs the number of SBOMs/components tracked.
#   IDLE floor  — sample DT idle (post-boot, no load) -> fixed JVM RSS + cores.
#   Per rung    — upload RUNG_BOMS synthetic CycloneDX SBOMs (COMPONENTS_PER_BOM
#                 unique components each) directly to DT /api/v1/bom, sampling DT
#                 + its Postgres during ingest + settle; record DT cores/RSS and
#                 the dependency_track DB size, vs cumulative component count.
# Cores/RSS via host-side cgroup cpu.stat accounting.
#
# NVD/OSV mirroring is OFF (see the overlay): this measures INGEST + STORAGE; the
# vuln-ANALYSIS CPU (mirror sync + per-component matching) is a separate periodic
# cost the offline rig can't exercise and is reported as unexercised.
#
# HEADLINE (scenario-written): results/dtrack-cost/dtrack-cost.{json,md}.
#
# Inputs (run.sh exports): BACKEND_CONTAINER, DB_CONTAINER, RUN_ID,
#   PERF_WORK_DIR, RAW_LOG. Manifest exports: DTRACK_PORT, RUNG_BOMS,
#   COMPONENTS_PER_BOM, IDLE_SECS, SETTLE_SECS, STATS_HZ.
# =============================================================================
set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(cd "${SCENARIO_DIR}/../.." && pwd)"
RESULTS="${PERF_DIR}/results/dtrack-cost"; mkdir -p "$RESULTS"

# shellcheck disable=SC1090
source "${COMMON_SH:?set COMMON_SH}"
WORK_DIR="${PERF_WORK_DIR:?set PERF_WORK_DIR}"; mkdir -p "$WORK_DIR"
: > "$RAW_LOG"

STATS_HZ="${STATS_HZ:-1}"
RUNG_BOMS="${RUNG_BOMS:-10 40 150}"
COMPONENTS_PER_BOM="${COMPONENTS_PER_BOM:-100}"
IDLE_SECS="${IDLE_SECS:-25}"
SETTLE_SECS="${SETTLE_SECS:-40}"
DTRACK_PORT="${DTRACK_PORT:-8093}"
DT_URL="http://127.0.0.1:${DTRACK_PORT}"

# --- discover DT + db containers ---------------------------------------------
SLOT="${BACKEND_CONTAINER#ak-perf}"; SLOT="${SLOT%-backend}"
DT_CONTAINER="ak-dtf${SLOT}-dtrack-api"
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$DT_CONTAINER"; then
  alt="$(docker ps --filter "label=com.docker.compose.project=ak-perf${SLOT}" \
         --filter "label=com.docker.compose.service=dependency-track-apiserver" --format '{{.Names}}' 2>/dev/null | head -1)"
  [ -n "$alt" ] && DT_CONTAINER="$alt"
fi
DT_FOUND=0; docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$DT_CONTAINER" && DT_FOUND=1
echo "dtrack-cost: dt=${DT_CONTAINER} (found=${DT_FOUND}) db=${DB_CONTAINER} url=${DT_URL}" >&2
[ "$DT_FOUND" = "1" ] || { echo "dtrack-cost: FATAL DT container not found" >&2;
  jq -n '{profile:"dtrack-cost",status:"BLOCKED",reason:"DT container not found",rungs:[]}' > "${RESULTS}/dtrack-cost.json"; exit 1; }

# --- wait for DT REST ready (host port) --------------------------------------
dt_ready=0
for i in $(seq 1 60); do
  v="$(curl -s --max-time 5 "${DT_URL}/api/version" 2>/dev/null)"
  printf '%s' "$v" | grep -q version && { dt_ready=1; break; }
  sleep 3
done
echo "dtrack-cost: DT ready=${dt_ready} version=$(curl -s --max-time 5 "${DT_URL}/api/version" 2>/dev/null | jq -rc '{version,uuid}' 2>/dev/null)" >&2
[ "$dt_ready" = "1" ] || { echo "dtrack-cost: FATAL DT REST not ready" >&2;
  jq -n '{profile:"dtrack-cost",status:"BLOCKED",reason:"DT REST /api/version not ready",rungs:[]}' > "${RESULTS}/dtrack-cost.json"; exit 1; }

# --- provision a permissioned API key (login -> team -> grant -> key), the same
#     flow as docker/init-dtrack.sh; DT enforces permissions even with auth off.
DT_ADMIN_USER="admin"; DT_DEFAULT_PASS="admin"; DT_NEW_PASS="PtfDtrack!2026"
DT_PERMS="BOM_UPLOAD PROJECT_CREATION_UPLOAD PORTFOLIO_MANAGEMENT VIEW_PORTFOLIO VIEW_VULNERABILITY"
dt_login() { curl -s --max-time 15 -X POST "${DT_URL}/api/v1/user/login" \
  -H 'Content-Type: application/x-www-form-urlencoded' -d "username=${DT_ADMIN_USER}&password=$1" 2>/dev/null; }
DT_TOKEN="$(dt_login "$DT_NEW_PASS")"
if [ -z "$DT_TOKEN" ] || printf '%s' "$DT_TOKEN" | grep -qiE 'FORCE_PASSWORD|invalid|unauthorized'; then
  curl -s -o /dev/null --max-time 15 -X POST "${DT_URL}/api/v1/user/forceChangePassword" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "username=${DT_ADMIN_USER}&password=${DT_DEFAULT_PASS}&newPassword=${DT_NEW_PASS}&confirmPassword=${DT_NEW_PASS}" 2>/dev/null || true
  DT_TOKEN="$(dt_login "$DT_NEW_PASS")"
fi
API_KEY=""
if [ -n "$DT_TOKEN" ] && ! printf '%s' "$DT_TOKEN" | grep -qiE 'FORCE_PASSWORD|invalid|unauthorized'; then
  team_json="$(curl -s --max-time 15 "${DT_URL}/api/v1/team" -H "Authorization: Bearer ${DT_TOKEN}" 2>/dev/null)"
  team_uuid="$(printf '%s' "$team_json" | jq -r '.[] | select(.name=="Administrators") | .uuid' 2>/dev/null | head -1)"
  [ -z "$team_uuid" ] && team_uuid="$(printf '%s' "$team_json" | jq -r '.[0].uuid // empty' 2>/dev/null)"
  for P in $DT_PERMS; do
    curl -s -o /dev/null --max-time 15 -X POST "${DT_URL}/api/v1/permission/${P}/team/${team_uuid}" \
      -H "Authorization: Bearer ${DT_TOKEN}" 2>/dev/null || true
  done
  API_KEY="$(curl -s --max-time 15 -X PUT "${DT_URL}/api/v1/team/${team_uuid}/key" \
    -H "Authorization: Bearer ${DT_TOKEN}" 2>/dev/null | jq -r '.key // .apikey // empty' 2>/dev/null)"
  echo "dtrack-cost: provisioned API key on team ${team_uuid} (key=${API_KEY:+present})" >&2
fi
[ -n "$API_KEY" ] || { echo "dtrack-cost: FATAL could not provision DT API key" >&2;
  jq -n '{profile:"dtrack-cost",status:"BLOCKED",reason:"could not provision DT API key (login/team/key flow failed)",rungs:[]}' > "${RESULTS}/dtrack-cost.json"; exit 1; }

# --- host-side cgroup sampler (DT + db) --------------------------------------
start_sampler() {
  local out="$1"; : > "$out"
  local conts=("$DT_CONTAINER" "$DB_CONTAINER")
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
reduce_container() {
  local f="$1" cont="$2"
  awk -v c="$cont" '
    $2==c { t=$1/1000.0; u=$3; m=$4+0; if(m>rpk)rpk=m;
      if(seen){ dt=t-pt; du=u-pu; if(dt>0){ cr=(du/1e6)/dt; if(cr>cpk)cpk=cr } } else { u0=u; t0=t; seen=1 }
      un=u; tn=t; pt=t; pu=u; n++ }
    END{ if(n==0){print "0 0 0 0"; exit}
      mean=(tn>t0)?((un-u0)/1e6)/(tn-t0):0; printf "%.3f %.3f %.0f %d", cpk, mean, rpk, n }' "$f"
}
dt_db_bytes() {
  docker exec "$DB_CONTAINER" psql -U registry -d dependency_track -tAc \
    "SELECT pg_database_size('dependency_track')" 2>/dev/null | tr -d ' \n' || echo 0
}

# --- synthetic CycloneDX SBOM (unique components) + upload -------------------
# build_bom <bom_index> -> writes base64 CycloneDX to $WORK_DIR/bom.b64
build_bom() {
  local bi="$1" f="${WORK_DIR}/bom.json" k
  { printf '{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":['
    for k in $(seq 1 "$COMPONENTS_PER_BOM"); do
      [ "$k" -gt 1 ] && printf ','
      printf '{"type":"library","name":"pkg_%s_%s","version":"1.0.%s","purl":"pkg:npm/pkg_%s_%s@1.0.%s"}' \
        "$bi" "$k" "$k" "$bi" "$k" "$k"
    done
    printf ']}'; } > "$f"
  base64 -w0 "$f" > "${WORK_DIR}/bom.b64"
}
# upload_bom <project_name> -> echoes http code
upload_bom() {
  local proj="$1"
  curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT "${DT_URL}/api/v1/bom" \
    -H "Content-Type: application/json" -H "X-Api-Key: ${API_KEY}" \
    -d "$(jq -n --arg p "$proj" --rawfile b "${WORK_DIR}/bom.b64" \
          '{projectName:$p, projectVersion:"1.0", autoCreate:true, bom:$b}')" 2>/dev/null || echo 000
}

RUNGS_JSON="[]"
append_rung() { RUNGS_JSON="$(jq -c --argjson r "$1" '. + [$r]' <<<"$RUNGS_JSON")"; }

# =============================================================================
# 1. IDLE JVM floor
# =============================================================================
echo "dtrack-cost: sampling IDLE JVM floor for ${IDLE_SECS}s ..." >&2
idle_sfile="${WORK_DIR}/stats-idle.jsonl"
ipid="$(start_sampler "$idle_sfile")"
sleep "$IDLE_SECS"
stop_sampler "$ipid"
idle_dt="$(reduce_container "$idle_sfile" "$DT_CONTAINER")"
read -r idle_pk idle_mn idle_rss idle_n <<<"$idle_dt"
db_base="$(dt_db_bytes)"; [ -z "$db_base" ] && db_base=0
echo "dtrack-cost: IDLE dt_cores_pk=${idle_pk} dt_cores_mn=${idle_mn} dt_rss=$(( ${idle_rss:-0}/1048576 ))MiB db_base=$(( ${db_base:-0}/1048576 ))MiB" >&2

# =============================================================================
# 2. Cumulative BOM upload rungs
# =============================================================================
total_boms=0; total_components=0
for RB in $RUNG_BOMS; do
  sfile="${WORK_DIR}/stats-rung-${total_boms}.jsonl"
  spid="$(start_sampler "$sfile")"
  ups=0; errs=0
  for b in $(seq 1 "$RB"); do
    total_boms=$(( total_boms + 1 ))
    build_bom "$total_boms"
    code="$(upload_bom "ptf-dtrack-${RUN_ID}-${total_boms}")"
    case "$code" in 2*) ups=$(( ups+1 ));; *) errs=$(( errs+1 ));; esac
    echo "sweep 1 generic 0 ${code} 0 0" >> "$RAW_LOG"
  done
  total_components=$(( total_boms * COMPONENTS_PER_BOM ))
  # settle: let DT finish async BOM processing while we keep sampling
  sleep "$SETTLE_SECS"
  stop_sampler "$spid"
  r_dt="$(reduce_container "$sfile" "$DT_CONTAINER")"; read -r r_pk r_mn r_rss r_n <<<"$r_dt"
  r_db="$(reduce_container "$sfile" "$DB_CONTAINER")"; read -r db_pk db_mn db_rss db_n <<<"$r_db"
  db_now="$(dt_db_bytes)"; [ -z "$db_now" ] && db_now=0
  db_delta=$(( ${db_now:-0} - ${db_base:-0} )); [ "$db_delta" -lt 0 ] && db_delta=0
  echo "dtrack-cost: [boms=${total_boms} components=${total_components}] dt_cores_pk=${r_pk} dt_cores_mn=${r_mn} dt_rss=$(( ${r_rss:-0}/1048576 ))MiB db_total=$(( ${db_now:-0}/1048576 ))MiB db_delta=$(( db_delta/1048576 ))MiB uploads=${ups} errs=${errs}" >&2
  append_rung "$(jq -n \
    --argjson boms "$total_boms" --argjson comps "$total_components" \
    --argjson pk "${r_pk:-0}" --argjson mn "${r_mn:-0}" --argjson rss "${r_rss:-0}" \
    --argjson dbtot "${db_now:-0}" --argjson dbdelta "$db_delta" \
    --argjson dbpk "${db_pk:-0}" --argjson dbrss "${db_rss:-0}" \
    --argjson ups "$ups" --argjson errs "$errs" \
    '{boms:$boms, components:$comps,
      dtrack:{cpu_cores_peak:$pk, cpu_cores_mean:$mn, rss_bytes_peak:$rss},
      dtrack_db:{total_bytes:$dbtot, delta_bytes:$dbdelta, pg_cpu_cores_peak:$dbpk, pg_rss_bytes_peak:$dbrss},
      uploads_ok:$ups, upload_errors:$errs}')"
done

# =============================================================================
# Headline side-artifact
# =============================================================================
jq -n --arg image "${BACKEND_IMAGE:-unknown}" --arg version "${VERSION:-unknown}" --arg run_id "$RUN_ID" \
  --arg dt "$DT_CONTAINER" --argjson idle_pk "${idle_pk:-0}" --argjson idle_mn "${idle_mn:-0}" \
  --argjson idle_rss "${idle_rss:-0}" --argjson db_base "${db_base:-0}" \
  --argjson comps_per_bom "$COMPONENTS_PER_BOM" --argjson rungs "$RUNGS_JSON" \
  '{profile:"dtrack-cost", status:"OK", backend_image:$image, version:$version, run_id:$run_id,
    dtrack_container:$dt, components_per_bom:$comps_per_bom,
    idle_floor:{cpu_cores_peak:$idle_pk, cpu_cores_mean:$idle_mn, rss_bytes:$idle_rss, db_bytes:$db_base},
    rungs:$rungs,
    note:"cores from host-side cgroup cpu.stat usage_usec. idle_floor = DT JVM RSS/cores with no load (the FIXED per-enable cost). rungs = DT cores/RSS during BOM ingest + settle, and dependency_track Postgres DB bytes, vs cumulative component count (the per-component slope). NVD/OSV mirroring is OFF, so the vuln-ANALYSIS CPU is NOT included here (separate periodic cost)."
  }' > "${RESULTS}/dtrack-cost.json"

{
  echo "# PTF dtrack-cost — Dependency-Track cost vs SBOMs/components tracked"
  echo
  echo "backend image: \`${BACKEND_IMAGE:-unknown}\`  |  dt: \`${DT_CONTAINER}\`  |  components/BOM: ${COMPONENTS_PER_BOM}"
  echo
  echo "**Idle JVM floor (fixed per-enable cost):** DT RSS $(( ${idle_rss:-0}/1048576 ))MiB, idle cores pk/mean ${idle_pk}/${idle_mn}, DT-DB base $(( ${db_base:-0}/1048576 ))MiB"
  echo
  echo "## DT cost per component count (cores = CPU-seconds/sec, host cgroup)"
  echo
  echo "| BOMs | components | DT cores pk/mean | DT RSS | DT-DB total | DT-DB delta | pg cores pk | uploads/err |"
  echo "|---|---|---|---|---|---|---|---|"
  jq -r '.rungs[] | "| \(.boms) | \(.components) | \(.dtrack.cpu_cores_peak)/\(.dtrack.cpu_cores_mean) | \((.dtrack.rss_bytes_peak/1048576)|floor)MiB | \((.dtrack_db.total_bytes/1048576)|floor)MiB | \((.dtrack_db.delta_bytes/1048576)|floor)MiB | \(.dtrack_db.pg_cpu_cores_peak) | \(.uploads_ok)/\(.upload_errors) |"' \
    "${RESULTS}/dtrack-cost.json"
  echo
  echo "_idle_floor = the FIXED heavy-JVM cost the moment DT is enabled; rungs add the per-component slope (DT ingest cores + dependency_track Postgres growth). NVD/OSV mirroring is OFF, so the vuln-ANALYSIS CPU (mirror sync + matching) is NOT measured — it is a separate periodic cost. DT BOM processing is async; DT cores/DB are sampled across upload + a ${SETTLE_SECS}s settle._"
} > "${RESULTS}/dtrack-cost.md"

echo "dtrack-cost: wrote ${RESULTS}/dtrack-cost.{json,md} ($(jq '.rungs|length' "${RESULTS}/dtrack-cost.json") rungs)" >&2
