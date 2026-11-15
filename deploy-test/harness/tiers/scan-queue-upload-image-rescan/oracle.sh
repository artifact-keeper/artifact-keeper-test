#!/usr/bin/env bash
# =============================================================================
# tiers/scan-queue-upload-image-rescan/oracle.sh: scan_on_upload and pushed
#   OCI images go through the durable scan queue (artifact-keeper#5946), and a
#   newer vulnerability-database build queues one low-priority rescan per
#   digest (artifact-keeper#5947)
# =============================================================================
# run.sh has stood up `storage.filesystem` and exported BASE_URL, DB_CONTAINER,
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH and the slot's port block.
#
# Phases (each recreates only the backend: postgres and the data volume stay):
#   0  base stack, queue off (default)          CONTROL in-process scans
#   1  queue on, worker off                     FIX #5946 jobs, no scan yet
#   2  queue on, worker on                      FIX #5946 queue drains
#      (then the oracle seeds the old DB build on two digests' scan rows)
#   3  queue on, worker on, rescan cap unset    CONTROL no rescan
#   4  + SCAN_RESCAN_MAX_PER_DAY=100, claim hold FIX #5947 one rescan/digest
#
# Repositories (keys suffixed per run; all scan_enabled + scan_on_upload):
#   C_GEN generic, C_OCI docker     phase 0 (queue off)
#   GEN1, GEN2 generic: the same npm.tgz bytes (digest D1)
#   OCI docker: one manifest pushed as v1, v1, v2 (digest D2)
#   GEN3 generic: docs.zip (digest D3, never seeded)
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe captures its status and asserts on it.
set +e

begin_suite "scan-queue-upload-image-rescan"
auth_admin
setup_workdir
require_cmd python3

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAKE_FX="${DTF_DIR}/harness/tiers/scan-on-upload-native-and-completeness/fixtures/make_fixtures.py"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
W="$WORK_DIR"
FX="${W}/fx"
PROJECT="ak-dtf${DTF_SLOT}"
OLD_BUILD="2020-01-01 00:00:00+00"

C_GEN="sq-cgen-${SUF}"; C_OCI="sq-coci-${SUF}"
GEN1="sq-gen1-${SUF}"; GEN2="sq-gen2-${SUF}"; GEN3="sq-gen3-${SUF}"; OCI="sq-oci-${SUF}"
ALL_REPOS="$C_GEN $C_OCI $GEN1 $GEN2 $GEN3 $OCI"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
psql_x() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -qc "$1" >/dev/null 2>&1; }
drop_hold() {
  psql_x "DROP TRIGGER IF EXISTS dtf_sq_hold_rescan ON scan_queue; DROP FUNCTION IF EXISTS dtf_sq_hold_rescan();"
}
cleanup() {
  local k
  drop_hold
  for k in $ALL_REPOS; do api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true; done
}
add_exit_handler "cleanup"

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# put FILE URL [content-type] -> HTTP status
put() {
  curl -s -o "${W}/put.out" -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" \
    -H "Content-Type: ${3:-application/octet-stream}" --data-binary "@$1" "$2" 2>/dev/null || echo 000
}
# push_image REPO TAG -> "<blob statuses> <manifest status>"
push_image() {
  local b d s=""
  for b in oci-config.json oci-layer.tar.gz; do
    d="sha256:$(sha256sum "${FX}/${b}" | cut -d' ' -f1)"
    s+=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X POST -H "$(auth_header)" \
      -H 'Content-Type: application/octet-stream' --data-binary "@${FX}/${b}" \
      "${BASE_URL}/v2/$1/img/blobs/uploads/?digest=${d}" 2>/dev/null || echo 000)
  done
  echo "${s} $(put "${FX}/oci-manifest.json" "${BASE_URL}/v2/$1/img/manifests/$2" application/vnd.oci.image.manifest.v1+json)"
}
repo_id() { api_get "/api/v1/repositories/$1" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true; }
# scans REPO [extra SQL predicate] -> scan_results rows (any status) of the repo's artifacts
scans() {
  psql_q "SELECT count(*) FROM scan_results s JOIN artifacts a ON a.id = s.artifact_id
          JOIN repositories r ON r.id = a.repository_id WHERE r.key = '$1' ${2:-}"
}
# every_row_scanned REPO SINCE: every artifact row of REPO has a completed scan created after SINCE
every_row_scanned() {
  [ "$(psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
       WHERE r.key = '$1' AND a.is_deleted = false AND ${3:-true}
         AND NOT EXISTS (SELECT 1 FROM scan_results s WHERE s.artifact_id = a.id
                         AND s.status = 'completed' AND s.created_at > '$2')")" = "0" ] \
  && [ "$(psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
       WHERE r.key = '$1' AND a.is_deleted = false AND ${3:-true}")" -ge 1 ] 2>/dev/null
}
# queue_get -> writes $W/q.json (the admin queue view, first 100 jobs); HTTP status
queue_get() {
  curl -s -o "${W}/q.json" -w '%{http_code}' --max-time 30 -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/security/scan-queue?per_page=100" 2>/dev/null || echo 000
}
# jobs_of KIND [REPO_ID] -> count of listed jobs of KIND (and repository)
jobs_of() {
  jq --arg k "$1" --arg r "${2:-}" '[.items[]? | select(.kind == $k and ($r == "" or .repository_id == $r))] | length' \
    "${W}/q.json" 2>/dev/null || echo -1
}
# art_ids REPO -> JSON array of the repository's artifact ids
art_ids() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT coalesce(json_agg(a.id), '[]') FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '$1'" \
    2>/dev/null | tr -d '[:space:]'
}
# repo_jobs REPO [KIND] -> listed jobs that name REPO (repository_id) or one of
# its artifacts (artifact_id: a hosted_upload job carries only the artifact)
repo_jobs() {
  local rid ids
  rid="$(repo_id "$1")"; ids="$(art_ids "$1")"
  jq --arg r "$rid" --argjson a "${ids:-[]}" --arg k "${2:-}" \
    '[.items[]? | select(($k == "" or .kind == $k) and ((.repository_id != null and .repository_id == $r)
       or (.artifact_id != null and (.artifact_id as $x | $a | index($x)) != null)))] | length' \
    "${W}/q.json" 2>/dev/null || echo -1
}
jobs_brief() {
  jq -c '[.items[]? | {kind, state, priority, repository_id, digest, artifact_id}]' "${W}/q.json" 2>/dev/null | head -c 1500
}
db_now() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "SELECT now()" 2>/dev/null | head -1 | sed 's/^ *//'; }

# recreate_backend WORKER [extra overlay...]: queue on; only the backend restarts.
recreate_backend() {
  local -a files=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml"
                  -f "${HERE}/fixtures/scan-queue.yml")
  local w="$1" x; shift
  for x in "$@"; do files+=(-f "${HERE}/fixtures/${x}"); done
  DTF_SQ_WORKER="$w" docker compose -p "$PROJECT" "${files[@]}" \
    up -d --no-deps --force-recreate --wait backend >"${W}/recreate.log" 2>&1 \
    || { tail -20 "${W}/recreate.log"; return 1; }
  wait_until "backend health after recreate" 120 curl -sf --max-time 3 "${BASE_URL}/health" || return 1
  auth_admin >/dev/null 2>&1
}
scan_on() {
  [ "$(api_put "/api/v1/repositories/$1/security" '{"scan_enabled":true,"scan_on_upload":true}' 2>/dev/null \
      | jq -r '.scan_on_upload' 2>/dev/null || true)" = "true" ]
}

# =============================================================================
begin_test "setup: fixtures and scan_on_upload repositories"
mkdir -p "$FX"
python3 -I "$MAKE_FX" "$FX" "$SUF" >"${W}/names.json" 2>"${W}/mk.err"
FX0="${W}/fx0"; mkdir -p "$FX0"
python3 -I "$MAKE_FX" "$FX0" "${SUF}c" >/dev/null 2>>"${W}/mk.err"
D1="$(sha256sum "${FX}/npm.tgz" | cut -d' ' -f1)"
D2="$(sha256sum "${FX}/oci-manifest.json" | cut -d' ' -f1)"
D3="$(sha256sum "${FX}/docs.zip" | cut -d' ' -f1)"
ok=1
for pair in "$C_GEN:generic" "$C_OCI:docker" "$GEN1:generic" "$GEN2:generic" "$GEN3:generic" "$OCI:docker"; do
  k="${pair%%:*}"
  create_repo "$k" "${pair#*:}" local || ok=0
  scan_on "$k" || ok=0
done
if [ "$ok" = 1 ] && [ -s "${FX}/npm.tgz" ] && [ -s "${FX}/oci-manifest.json" ]; then pass
else fail "setup ok=${ok} $(head -c 200 "${W}/mk.err" 2>/dev/null)"; fi

# =============================================================================
# Phase 0: the queue off (default)
# =============================================================================
reset_case
begin_test "CONTROL: queue off: a generic upload and an image push are scanned in-process and leave no queue job"
s_gen=$(put "${FX0}/npm.tgz" "${BASE_URL}/api/v1/repositories/${C_GEN}/artifacts/pkg/c-${SUF}.tgz")
s_oci=$(FX="$FX0" push_image "$C_OCI" v1)
note "upload=${s_gen} push=${s_oci}"
[[ "$s_gen" =~ ^20[01]$ ]] || fail_g "generic upload answered ${s_gen}"
[ "$s_oci" = "201201 201" ] || fail_g "image push answered ${s_oci}"
both_scanned() { [ "$(scans "$C_GEN" "AND s.status = 'completed'")" -ge 1 ] && [ "$(scans "$C_OCI" "AND s.status = 'completed'")" -ge 1 ]; } 2>/dev/null
wait_until "in-process scans" 120 both_scanned
cg="$(scans "$C_GEN" "AND s.status = 'completed'")"; co="$(scans "$C_OCI" "AND s.status = 'completed'")"
note "completed scans: ${C_GEN}=${cg} ${C_OCI}=${co}"
[ "${cg:-0}" -ge 1 ] 2>/dev/null || fail_g "the generic upload was not scanned"
[ "${co:-0}" -ge 1 ] 2>/dev/null || fail_g "the pushed image was not scanned"
qs="$(queue_get)"
en="$(jq -r '.enabled' "${W}/q.json" 2>/dev/null)"
n=$(( $(repo_jobs "$C_GEN") + $(repo_jobs "$C_OCI") ))
note "queue view: HTTP ${qs} enabled=${en} jobs for these repositories=${n}"
[ "$qs" = "200" ] || fail_g "the queue view answered ${qs}"
[ "$en" = "false" ] || fail_g "the queue view reports enabled=${en} with the queue off"
[ "$n" = "0" ] || fail_g "the queue holds ${n} job(s) for in-process scans"
finish_case "with the queue off scans no longer ran in-process as before"

# =============================================================================
# Phase 1: queue on, worker off
# =============================================================================
begin_test "setup: recreate the backend with SCAN_QUEUE_ENABLED=true, SCAN_WORKER_ENABLED=false"
if recreate_backend false; then pass; else fail "recreate failed"; fi

reset_case
begin_test "FIX #5946: queue on, worker off: three pushes of one manifest are ONE hosted_image job, each upload one hosted_upload job, nothing scanned yet"
p1=$(push_image "$OCI" v1); p2=$(push_image "$OCI" v1); p3=$(push_image "$OCI" v2)
u1=$(put "${FX}/npm.tgz" "${BASE_URL}/api/v1/repositories/${GEN1}/artifacts/pkg/a-${SUF}.tgz")
u2=$(put "${FX}/npm.tgz" "${BASE_URL}/api/v1/repositories/${GEN2}/artifacts/pkg/b-${SUF}.tgz")
u3=$(put "${FX}/docs.zip" "${BASE_URL}/api/v1/repositories/${GEN3}/artifacts/docs/d-${SUF}.zip")
note "push v1=${p1} v1-again=${p2} v2=${p3}; uploads ${u1} ${u2} ${u3}"
# Long enough for an in-process scan of these small files to land (they do in
# phase 0 within seconds), so "nothing scanned" means nothing ran.
sleep 20
queue_get >/dev/null
note "jobs: $(jobs_brief)"
OCI_ID="$(repo_id "$OCI")"
ni=$(repo_jobs "$OCI" hosted_image)
nu1=$(repo_jobs "$GEN1" hosted_upload); nu2=$(repo_jobs "$GEN2" hosted_upload); nu3=$(repo_jobs "$GEN3" hosted_upload)
idig="$(jq -r --arg r "$OCI_ID" '[.items[]? | select(.kind == "hosted_image" and .repository_id == $r) | .digest] | first // ""' "${W}/q.json")"
HOSTED_PRIO="$(jq -r '[.items[]? | select(.kind == "hosted_image" or .kind == "hosted_upload") | .priority] | min // ""' "${W}/q.json")"
note "hosted_image=${ni} (digest ${idig}) hosted_upload gen1=${nu1} gen2=${nu2} gen3=${nu3} hosted priority=${HOSTED_PRIO}"
[ "$ni" = "1" ] || fail_g "${ni} hosted_image job(s) for one manifest pushed three times, expected 1"
case "$idig" in *"$D2"*) ;; *) fail_g "the hosted_image job's digest '${idig}' is not the manifest digest ${D2}";; esac
[ "$nu1" = "1" ] && [ "$nu2" = "1" ] && [ "$nu3" = "1" ] || fail_g "hosted_upload jobs gen1=${nu1} gen2=${nu2} gen3=${nu3}, expected 1 each"
pre=0; for k in "$OCI" "$GEN1" "$GEN2" "$GEN3"; do pre=$(( pre + $(scans "$k") )); done
note "scan rows before any worker: ${pre}"
[ "$pre" = "0" ] || fail_g "${pre} scan row(s) were written in-process with the queue on"
finish_case "scan_on_upload did not go through the scan queue"

# =============================================================================
# Phase 2: worker on
# =============================================================================
begin_test "setup: recreate the backend with the worker on (SCAN_RESCAN_MAX_PER_DAY unset)"
T_WORKER="$(db_now)"
if recreate_backend true; then pass; else fail "recreate failed"; fi

reset_case
begin_test "FIX #5946: worker on: the queue drains and every tag row and upload gets a completed scan written after the worker started"
all_done() {
  local k
  for k in "$OCI" "$GEN1" "$GEN2" "$GEN3"; do every_row_scanned "$k" "$T_WORKER" "a.checksum_sha256 IN ('${D1}','${D2}','${D3}')" || return 1; done
}
wait_until "worker scans" 180 all_done
queue_get >/dev/null
left=0; for k in "$OCI" "$GEN1" "$GEN2" "$GEN3"; do left=$(( left + $(repo_jobs "$k") )); done
note "jobs left for these repositories: ${left} $(jobs_brief)"
for k in "$OCI" "$GEN1" "$GEN2" "$GEN3"; do
  note "${k}: completed scans since the worker started=$(scans "$k" "AND s.status = 'completed' AND s.created_at > '${T_WORKER}'"), before=$(scans "$k" "AND s.created_at <= '${T_WORKER}'")"
done
all_done || fail_g "not every tag row / upload has a completed scan written by the worker"
[ "$left" = "0" ] || fail_g "${left} job(s) still queued for these repositories"
finish_case "the queued scans were not run by the worker"

# The rows the rescan phase works on, and the build they record now.
note_rows() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT r.key, a.path, s.scan_type, s.status, s.is_reused, s.vuln_db_published_at, s.vuln_db_version
     FROM scan_results s JOIN artifacts a ON a.id = s.artifact_id JOIN repositories r ON r.id = a.repository_id
     WHERE r.key IN ('${OCI}','${GEN1}','${GEN2}','${GEN3}') ORDER BY r.key, a.path, s.created_at" 2>/dev/null
}
echo "   scan rows after phase 2:"; note_rows | sed 's/^/     /'

begin_test "setup: seed the recorded DB build on the Grype scan rows of D1 and D2 to ${OLD_BUILD} (D3 keeps its real build)"
SEED_SQL="UPDATE scan_results SET vuln_db_published_at = '${OLD_BUILD}'
  WHERE status = 'completed' AND scan_type = 'grype'
    AND artifact_id IN (SELECT id FROM artifacts WHERE checksum_sha256 IN ('${D1}','${D2}'))"
SEEDED_IDS_SQL="SELECT string_agg(id::text, ',' ORDER BY id) FROM scan_results
  WHERE vuln_db_published_at = '${OLD_BUILD}' AND artifact_id IN (SELECT id FROM artifacts WHERE checksum_sha256 IN ('${D1}','${D2}'))"
psql_x "$SEED_SQL"
SEEDED="$(psql_q "$SEEDED_IDS_SQL")"
note "seeded rows: ${SEEDED:-none}"
if [ -n "$SEEDED" ]; then pass; else fail "no scan rows to seed (phase 2 wrote none)"; fi

# =============================================================================
# Phase 3: SCAN_RESCAN_MAX_PER_DAY unset
# =============================================================================
begin_test "setup: recreate the backend (queue and worker on, SCAN_RESCAN_MAX_PER_DAY still unset)"
T3="$(db_now)"
if recreate_backend true; then pass; else fail "recreate failed"; fi

reset_case
begin_test "CONTROL: SCAN_RESCAN_MAX_PER_DAY unset: the seeded rows queue no rescan job and get no new scan in 30 s"
sleep 30
queue_get >/dev/null
nr=$(jobs_of rescan)
new3=0; for k in "$OCI" "$GEN1" "$GEN2" "$GEN3"; do new3=$(( new3 + $(scans "$k" "AND s.created_at > '${T3}'") )); done
note "rescan jobs=${nr} new scan rows=${new3}"
[ "$nr" = "0" ] || fail_g "${nr} rescan job(s) queued with the cap unset"
[ "$new3" = "0" ] || fail_g "${new3} new scan row(s) with the cap unset"
finish_case "rescans ran with SCAN_RESCAN_MAX_PER_DAY unset"

# =============================================================================
# Phase 4: SCAN_RESCAN_MAX_PER_DAY=100
# =============================================================================
begin_test "setup: hold new rescan jobs (test-only trigger), recreate with SCAN_RESCAN_MAX_PER_DAY=100"
psql_x "CREATE OR REPLACE FUNCTION dtf_sq_hold_rescan() RETURNS trigger LANGUAGE plpgsql AS
  \$\$ BEGIN NEW.next_attempt_at := now() + interval '1 hour'; RETURN NEW; END \$\$;
  DROP TRIGGER IF EXISTS dtf_sq_hold_rescan ON scan_queue;
  CREATE TRIGGER dtf_sq_hold_rescan BEFORE INSERT ON scan_queue FOR EACH ROW
    WHEN (NEW.kind = 'rescan') EXECUTE FUNCTION dtf_sq_hold_rescan();"
hold_rc=$?
if [ "$hold_rc" = 0 ] && recreate_backend true rescan-cap.yml; then pass; else fail "hold=${hold_rc} or recreate failed"; fi

reset_case
begin_test "FIX #5947: a newer DB build queues ONE low-priority rescan per seeded digest (D1 in two repos, D2 under two tags), not D3; each row gets a new scan and the seeded rows stay"
has_rescans() { queue_get >/dev/null; [ "$(jobs_of rescan)" -ge 2 ] 2>/dev/null; }
wait_until "rescan jobs" 60 has_rescans
sleep 3; queue_get >/dev/null
note "jobs: $(jobs_brief)"
nr=$(jobs_of rescan)
digs="$(jq -r '[.items[]? | select(.kind == "rescan") | .digest] | sort | join(",")' "${W}/q.json" 2>/dev/null)"
prios="$(jq -r '[.items[]? | select(.kind == "rescan") | .priority] | unique | join(",")' "${W}/q.json" 2>/dev/null)"
note "rescan jobs=${nr} digests=${digs} priorities=${prios} (hosted priority ${HOSTED_PRIO:-unknown})"
[ "$nr" = "2" ] || fail_g "${nr} rescan job(s), expected 2 (one per seeded digest, 4 rows)"
case ",${digs}," in *"$D1"*) ;; *) fail_g "no rescan job for D1";; esac
case ",${digs}," in *"$D2"*) ;; *) fail_g "no rescan job for D2";; esac
case ",${digs}," in *"$D3"*) fail_g "D3, already on the current build, was queued";; esac
if [ -n "$prios" ] && [ "${prios//,/}" = "$prios" ] && [ -n "${HOSTED_PRIO:-}" ]; then
  [ "$prios" -lt "$HOSTED_PRIO" ] 2>/dev/null || fail_g "rescan priority ${prios} is not below the hosted priority ${HOSTED_PRIO}"
else
  fail_g "rescan priorities '${prios}' vs hosted '${HOSTED_PRIO:-}' cannot be compared"
fi
# Release the hold: the worker claims them on its next tick.
T4="$(db_now)"
drop_hold
psql_x "UPDATE scan_queue SET next_attempt_at = now() WHERE kind = 'rescan'"
rescanned() {
  [ "$(psql_q "SELECT count(*) FROM artifacts a WHERE a.checksum_sha256 IN ('${D1}','${D2}') AND a.is_deleted = false
       AND a.repository_id IN (SELECT id FROM repositories WHERE key IN ('${OCI}','${GEN1}','${GEN2}'))
       AND NOT EXISTS (SELECT 1 FROM scan_results s WHERE s.artifact_id = a.id AND s.status = 'completed'
                       AND s.scan_type = 'grype' AND s.created_at > '${T4}'
                       AND s.vuln_db_published_at > '${OLD_BUILD}')")" = "0" ]
}
rescans_done() { rescanned && queue_get >/dev/null && [ "$(jobs_of rescan)" = "0" ]; }
wait_until "rescans complete" 180 rescans_done
queue_get >/dev/null
nr_left=$(jobs_of rescan)
rows="$(psql_q "SELECT count(*) FROM artifacts a WHERE a.checksum_sha256 IN ('${D1}','${D2}') AND a.is_deleted = false
       AND a.repository_id IN (SELECT id FROM repositories WHERE key IN ('${OCI}','${GEN1}','${GEN2}'))")"
kept="$(psql_q "$SEEDED_IDS_SQL")"
d3new="$(scans "$GEN3" "AND s.created_at > '${T3}'")"
echo "   scan rows after the rescans:"; note_rows | sed 's/^/     /'
note "rows of D1/D2=${rows} rescan jobs left=${nr_left} D3 new rows=${d3new}"
rescanned || fail_g "not every row of D1/D2 got a completed Grype scan on a newer build"
[ "${rows:-0}" -ge 4 ] 2>/dev/null || fail_g "${rows} artifact rows of D1/D2, expected at least 4"
[ "$kept" = "$SEEDED" ] || fail_g "seeded rows changed: before=${SEEDED} after=${kept:-none}"
[ "$nr_left" = "0" ] || fail_g "${nr_left} rescan job(s) still queued"
[ "$d3new" = "0" ] || fail_g "D3 got ${d3new} new scan row(s)"
finish_case "a DB build change did not queue one rescan per digest, or lost the old results"

end_suite
