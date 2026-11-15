#!/usr/bin/env bash
# =============================================================================
# tiers/scan-queue-hosted-ahead-of-backfill/oracle.sh
#   #6032 hosted upload and pushed-image scans are claimed ahead of a fail-open
#         proxy scan backlog, and the backlog ages so it still drains
#   #6033 SCAN_WORKER_CONCURRENCY unset follows MAX_CONCURRENT_SCAN_EXTRACTIONS
# See the manifest for the bugs and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, TRIVY_PORT
# (the mock's published control port), DB_CONTAINER, RELEASE_GATE=1, COMMON_SH.
#
# Phases (each recreates only the backend):
#   A  queue on, worker off                     60 backlog pulls, then H1 + H2
#   B  worker on, concurrency 1, aging default  FIX #6032 order, CONTROL drain
#   C  worker off, then on with aging 20 s      FIX #6032 aging
#   D  worker off, then on, concurrency unset   FIX #6033 capacity and running
#   E  worker on, concurrency 2                 CONTROL capacity 2
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe captures its status and asserts on it.
set +e

begin_suite "scan-queue-hosted-ahead-of-backfill"

# Version floor first, before any case can pass: on a backend below 1.12.1 the
# whole tier is NOT APPLICABLE (the 1.12.0 gate runs this main tree).
begin_test "version floor: the #6032 claim order ships in backend >= 1.12.1"
if ! require_feature "scan_queue_hosted_ahead_of_backfill"; then end_suite; exit 0; fi
pass

auth_admin
setup_workdir
require_cmd python3

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAKE_FX="${DTF_DIR}/harness/tiers/scan-on-upload-native-and-completeness/fixtures/make_fixtures.py"
W="$WORK_DIR"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
PROJECT="ak-dtf${DTF_SLOT}"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"   # where the BACKEND reaches the mock
N_BACKLOG="${SQB_BACKLOG:-60}"
N_DRAIN="${SQB_DRAIN:-12}"
AGING=20
HOSTED_BOUND=45

REMOTE="sqb-npm-${SUF}"   # npm Remote, scan_on_proxy, fail_open
HG="sqb-gen-${SUF}"       # generic, scan_on_upload (H1, phase A)
HO="sqb-oci-${SUF}"       # docker, scan_on_upload (H2, phase A)
HG2="sqb-gen2-${SUF}"     # generic, scan_on_upload (H3, phase C)
ALL_REPOS="$REMOTE $HG $HO $HG2"
cleanup() {
  local k
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

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
db_now() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "SELECT now()" 2>/dev/null | head -1 | sed 's/^ *//'; }
uri() { jq -rn --arg v "$1" '$v|@uri'; }

# recreate_backend WORKER CONCURRENCY|"" AGING|"": only the backend restarts.
recreate_backend() {
  local -a files=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml"
                  -f "${DTF_DIR}/profiles/upstreams.mock-files.yml"
                  -f "${DTF_DIR}/profiles/limits.scan-one-permit.yml"
                  -f "${HERE}/fixtures/scan-queue.yml")
  [ -n "$2" ] && files+=(-f "${HERE}/fixtures/worker-concurrency.yml")
  [ -n "$3" ] && files+=(-f "${HERE}/fixtures/backfill-aging.yml")
  DTF_SQ_WORKER="$1" DTF_SQ_CONCURRENCY="$2" DTF_SQ_AGING="$3" docker compose -p "$PROJECT" "${files[@]}" \
    up -d --no-deps --force-recreate --wait backend >"${W}/recreate.log" 2>&1 \
    || { tail -20 "${W}/recreate.log"; return 1; }
  wait_until "backend health after recreate" 120 curl -sf --max-time 3 "${BASE_URL}/health" || return 1
  auth_admin >/dev/null 2>&1
}

# put FILE URL [content-type] -> HTTP status
put() {
  curl -s -o "${W}/put.out" -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" \
    -H "Content-Type: ${3:-application/octet-stream}" --data-binary "@$1" "$2" 2>/dev/null || echo 000
}
# push_image DIR REPO TAG -> "<blob statuses> <manifest status>"
push_image() {
  local b d s=""
  for b in oci-config.json oci-layer.tar.gz; do
    d="sha256:$(sha256sum "$1/${b}" | cut -d' ' -f1)"
    s+=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X POST -H "$(auth_header)" \
      -H 'Content-Type: application/octet-stream' --data-binary "@$1/${b}" \
      "${BASE_URL}/v2/$2/img/blobs/uploads/?digest=${d}" 2>/dev/null || echo 000)
  done
  echo "${s} $(put "$1/oci-manifest.json" "${BASE_URL}/v2/$2/img/manifests/$3" application/vnd.oci.image.manifest.v1+json)"
}
# pull_group GROUP -> "<served 200 pending>/<total>"
pull_group() {
  local name ok=0 n=0 st sc
  while IFS=$'\t' read -r name _; do
    n=$((n+1))
    st=$(curl -s -D "${W}/pull.h" -o /dev/null -w '%{http_code}' --max-time 60 \
      "${BASE_URL}/npm/${REMOTE}/${name}/-/${name}-1.0.0.tgz" 2>/dev/null || echo 000)
    sc=$(grep -i '^x-ak-scan:' "${W}/pull.h" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//')
    [ "$st/$sc" = "200/pending" ] && ok=$((ok+1))
  done < "${W}/fx/$1.list"
  echo "${ok}/${n}"
}
digests_sql() { awk -F'\t' '{printf "%s'"'"'%s'"'"'", (NR>1?",":""), $2}' "${W}/fx/$1.list"; }
pending_backfill() { psql_q "SELECT count(*) FROM scan_queue WHERE kind = 'proxy_file' AND state = 'pending' AND digest IN ($(digests_sql "$1"))"; }
verdicts() { psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256 IN ($(digests_sql "$1"))${2:+ AND $2}"; }
backfill_left() { psql_q "SELECT count(*) FROM scan_queue WHERE kind = 'proxy_file' AND digest IN ($(digests_sql "$1"))"; }
# hosted_done REPO[:SHA256]... : every artifact row of each repository (only
# the one with that checksum, for an image: the manifest) has a completed scan
# written after $T_WORKER
hosted_done() {
  local x k f
  for x in "$@"; do
    k="${x%%:*}"; f="true"
    [ "$k" != "$x" ] && f="a.checksum_sha256 = '${x#*:}'"
    [ "$(psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
         WHERE r.key = '${k}' AND a.is_deleted = false AND ${f}")" -ge 1 ] 2>/dev/null || return 1
    [ "$(psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
         WHERE r.key = '${k}' AND a.is_deleted = false AND ${f}
           AND NOT EXISTS (SELECT 1 FROM scan_results s WHERE s.artifact_id = a.id
                           AND s.status = 'completed' AND s.created_at > '${T_WORKER}')")" = "0" ] || return 1
  done
}
# hosted_last REPO... -> the latest completion of their scans since $T_WORKER
hosted_last() {
  local keys="" k
  for k in "$@"; do keys="${keys}${keys:+,}'${k}'"; done
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT max(coalesce(s.completed_at, s.created_at)) FROM scan_results s
       JOIN artifacts a ON a.id = s.artifact_id JOIN repositories r ON r.id = a.repository_id
      WHERE r.key IN (${keys}) AND s.status = 'completed' AND s.created_at > '${T_WORKER}'" 2>/dev/null | head -1 | sed 's/^ *//'
}
secs_between() { psql_q "SELECT round(extract(epoch FROM ('$2'::timestamptz - '$1'::timestamptz)))::int"; }
scan_on_upload() {
  [ "$(api_put "/api/v1/repositories/$1/security" '{"scan_enabled":true,"scan_on_upload":true}' 2>/dev/null \
      | jq -r '.scan_on_upload' 2>/dev/null || true)" = "true" ]
}
# metric NAME -> the unlabelled sample of NAME on /api/v1/admin/metrics, or ""
metric() {
  curl -s --max-time 10 -H "$(auth_header)" "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null \
    | awk -v n="$1" '$1 == n { v = $2 } END { if (v != "") printf "%d", v + 0 }'
}

# =============================================================================
begin_test "setup: fixtures in the mock upstream, a fail_open npm Remote and scan_on_upload repositories"
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
mkdir -p "${W}/fx" "${W}/h1" "${W}/h3"
n=$(python3 -I "${HERE}/fixtures/build_backlog.py" "${W}/fx" "$UP" "a:${N_BACKLOG}" o:3 n:3 "d:${N_DRAIN}" 2>"${W}/fx.err") || n=""
python3 -I "$MAKE_FX" "${W}/h1" "${SUF}h1" >/dev/null 2>>"${W}/fx.err"
python3 -I "$MAKE_FX" "${W}/h3" "${SUF}h3" >/dev/null 2>>"${W}/fx.err"
err=""
[ -n "$n" ] && [ -s "${W}/h1/npm.tgz" ] && [ -s "${W}/h3/npm.tgz" ] || err="fixtures: $(head -c 300 "${W}/fx.err")"
while IFS=$'\t' read -r p f ct; do
  b=$(curl -s --max-time 20 -X PUT --data-binary @"$f" "${MOCK}/__file?path=$(uri "$p")&ctype=$(uri "$ct")" \
        | jq -r '.bytes // empty' 2>/dev/null) || b=""
  [ "$b" = "$(stat -c %s "$f")" ] || err="${err} mock:${p}"
done < "${W}/fx/files.tsv"
create_repo "$REMOTE" npm remote "${UP}/npm" || err="${err} remote"
act="$(api_put "/api/v1/repositories/${REMOTE}/security" \
  '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_open"}' 2>/dev/null \
  | jq -r '.proxy_scan_action // empty' 2>/dev/null)"
[ "$act" = "fail_open" ] || err="${err} proxy_scan_action='${act}'"
for pair in "$HG:generic" "$HO:docker" "$HG2:generic"; do
  create_repo "${pair%%:*}" "${pair#*:}" local || err="${err} create:${pair%%:*}"
  scan_on_upload "${pair%%:*}" || err="${err} scan_on_upload:${pair%%:*}"
done
if [ -z "$err" ]; then pass; else infra_fail "setup:${err}"; end_suite; fi

# =============================================================================
# Phase A: queue on, worker off. Backlog first, hosted work after it.
# =============================================================================
begin_test "setup: recreate the backend with SCAN_QUEUE_ENABLED=true, SCAN_WORKER_ENABLED=false"
if recreate_backend false "" ""; then pass; else infra_fail "recreate failed"; end_suite; fi

begin_test "setup: ${N_BACKLOG} first pulls through the fail_open Remote queue ${N_BACKLOG} proxy_file jobs, then an upload and an image push queue hosted jobs"
served=$(pull_group a)
sleep 1
u1=$(put "${W}/h1/npm.tgz" "${BASE_URL}/api/v1/repositories/${HG}/artifacts/pkg/h1-${SUF}.tgz")
p1=$(push_image "${W}/h1" "$HO" v1)
pa=$(pending_backfill a)
ph=$(psql_q "SELECT count(*) FROM scan_queue WHERE kind IN ('hosted_upload','hosted_image') AND state = 'pending'
              AND (repository_id IN (SELECT id FROM repositories WHERE key IN ('${HG}','${HO}'))
                   OR artifact_id IN (SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id
                                      WHERE r.key IN ('${HG}','${HO}')))")
echo "   pulls served 200 pending: ${served}; upload=${u1} push=${p1}; pending proxy_file=${pa} hosted=${ph}"
if [ "$served" = "${N_BACKLOG}/${N_BACKLOG}" ] && [ "${pa:-0}" -ge "$N_BACKLOG" ] 2>/dev/null \
   && [[ "$u1" =~ ^20[01]$ ]] && [ "$p1" = "201201 201" ] && [ "${ph:-0}" -ge 2 ] 2>/dev/null; then
  pass
else
  infra_fail "could not build the backlog: served=${served} pending proxy_file=${pa} upload=${u1} push=${p1} hosted jobs=${ph} (the claim order cannot be judged without it)"
  end_suite
fi

# =============================================================================
# Phase B: worker on, one job at a time, default aging window (600 s)
# =============================================================================
begin_test "setup: recreate the backend with the worker on and SCAN_WORKER_CONCURRENCY=1"
T_WORKER="$(db_now)"
if recreate_backend true 1 ""; then pass; else infra_fail "recreate failed"; end_suite; fi

reset_case
begin_test "FIX #6032: an upload and an image push queued behind ${N_BACKLOG} fail-open proxy scans get their verdicts first, within ${HOSTED_BOUND} s"
H2_D="$(sha256sum "${W}/h1/oci-manifest.json" | cut -d' ' -f1)"
wait_until "hosted verdicts" 240 hosted_done "$HG" "${HO}:${H2_D}"
if hosted_done "$HG" "${HO}:${H2_D}"; then
  H_DONE="$(hosted_last "$HG" "$HO")"
  lat=$(secs_between "$T_WORKER" "$H_DONE")
  before=$(verdicts a "scanned_at < '${H_DONE}'")
  note "hosted verdicts ${lat}s after the worker started; backlog verdicts before them: ${before}/${N_BACKLOG}"
  [ "${before:-99}" -le 1 ] 2>/dev/null || fail_g "${before} of ${N_BACKLOG} backlog scans ran before the hosted scans (the hosted jobs waited for the backlog)"
  [ "${lat:-999}" -le "$HOSTED_BOUND" ] 2>/dev/null || fail_g "hosted verdicts took ${lat}s, over the ${HOSTED_BOUND}s bound"
else
  fail_g "the upload and the pushed image had no completed scan 240 s after the worker started (backlog verdicts so far: $(verdicts a))"
fi
finish_case "hosted scans were not claimed ahead of the fail-open backlog"

reset_case
begin_test "CONTROL: the ${N_BACKLOG}-job backlog still drains, every pull gets a verdict and no proxy_file job is left"
all_a() { [ "$(verdicts a)" = "$N_BACKLOG" ] && [ "$(backfill_left a)" = "0" ]; }
wait_until "backlog drain" $(( 60 + N_BACKLOG * 5 )) all_a
va=$(verdicts a); la=$(backfill_left a)
last="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT max(scanned_at) FROM proxy_scan_results WHERE checksum_sha256 IN ($(digests_sql a))" 2>/dev/null | head -1 | sed 's/^ *//')"
note "verdicts ${va}/${N_BACKLOG}, proxy_file jobs left ${la}, drained $( [ -n "$last" ] && secs_between "$T_WORKER" "$last" )s after the worker started"
[ "$va" = "$N_BACKLOG" ] || fail_g "${va}/${N_BACKLOG} backlog pulls have a verdict"
[ "$la" = "0" ] || fail_g "${la} proxy_file job(s) still queued"
finish_case "the fail-open backlog did not drain"

# =============================================================================
# Phase C: aging. Old backfill, then an upload, then new backfill.
# =============================================================================
begin_test "setup: worker off; 3 backfill jobs, 35 s later an upload, then 3 more backfill jobs"
ok=1
recreate_backend false "" "" || ok=0
so=$(pull_group o)
sleep 35
u3=$(put "${W}/h3/npm.tgz" "${BASE_URL}/api/v1/repositories/${HG2}/artifacts/pkg/h3-${SUF}.tgz")
sleep 2
sn=$(pull_group n)
# The gaps the expectation rests on, read from the queue itself.
h3_at="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT max(created_at) FROM scan_queue WHERE kind = 'hosted_upload' AND state = 'pending'
     AND artifact_id IN (SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${HG2}')" \
  2>/dev/null | head -1 | sed 's/^ *//')"
o_at="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT max(created_at) FROM scan_queue WHERE kind = 'proxy_file' AND digest IN ($(digests_sql o))" 2>/dev/null | head -1 | sed 's/^ *//')"
n_at="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT min(created_at) FROM scan_queue WHERE kind = 'proxy_file' AND digest IN ($(digests_sql n))" 2>/dev/null | head -1 | sed 's/^ *//')"
g_old=""; g_new=""
[ -n "$h3_at" ] && [ -n "$o_at" ] && [ -n "$n_at" ] && { g_old=$(secs_between "$o_at" "$h3_at"); g_new=$(secs_between "$h3_at" "$n_at"); }
echo "   old=${so} upload=${u3} new=${sn}; old backfill queued ${g_old}s before the upload, new backfill ${g_new}s after it"
if [ "$ok" = 1 ] && [ "$so" = "3/3" ] && [ "$sn" = "3/3" ] && [[ "$u3" =~ ^20[01]$ ]] \
   && [ "${g_old:-0}" -ge $(( AGING + 5 )) ] 2>/dev/null && [ "${g_new:--1}" -ge 0 ] 2>/dev/null \
   && [ "$(pending_backfill o)" = "3" ] && [ "$(pending_backfill n)" = "3" ]; then
  pass
else
  infra_fail "aging setup: recreate=${ok} old=${so} new=${sn} upload=${u3} gaps old=${g_old} new=${g_new} pending old=$(pending_backfill o) new=$(pending_backfill n)"
  end_suite
fi

begin_test "setup: recreate with the worker on, SCAN_WORKER_CONCURRENCY=1, SCAN_QUEUE_BACKFILL_AGING_SECS=${AGING}"
T_WORKER="$(db_now)"
if recreate_backend true 1 "$AGING"; then pass; else infra_fail "recreate failed"; end_suite; fi

reset_case
begin_test "FIX #6032: with a ${AGING} s aging window, backfill queued before the window ends goes ahead of a newer upload, and backfill queued after the upload waits for it"
c_done() { [ "$(verdicts o)" = "3" ] && [ "$(verdicts n)" = "3" ] && hosted_done "$HG2"; }
wait_until "aging phase verdicts" 180 c_done
if c_done; then
  H3_DONE="$(hosted_last "$HG2")"
  o_after=$(verdicts o "scanned_at > '${H3_DONE}'")
  n_before=$(verdicts n "scanned_at < '${H3_DONE}'")
  note "upload verdict at ${H3_DONE}; old backfill after it: ${o_after}/3; new backfill before it: ${n_before}/3"
  [ "$o_after" = "0" ] || fail_g "${o_after} of 3 backfill jobs queued ${g_old}s before the upload (window ${AGING}s) ran after it: backfill does not age"
  [ "$n_before" = "0" ] || fail_g "${n_before} of 3 backfill jobs queued after the upload ran before it: hosted scans are not ahead of younger backfill"
else
  fail_g "not every scan of the aging phase completed in 180 s: old=$(verdicts o)/3 new=$(verdicts n)/3 upload done=$(hosted_done "$HG2" && echo yes || echo no)"
fi
finish_case "the claim order does not merge hosted scans and aged backfill by age"

# =============================================================================
# Phase D: SCAN_WORKER_CONCURRENCY unset, one extraction permit (#6033)
# =============================================================================
begin_test "version floor: the #6033 default ships in backend >= 1.12.1"
D_ON=0
if require_feature "scan_worker_concurrency_default"; then pass; D_ON=1; fi

if [ "$D_ON" = 1 ]; then
  begin_test "setup: worker off, ${N_DRAIN} backfill jobs queued"
  ok=1
  recreate_backend false "" "" || ok=0
  sd=$(pull_group d)
  if [ "$ok" = 1 ] && [ "$sd" = "${N_DRAIN}/${N_DRAIN}" ] && [ "$(pending_backfill d)" = "$N_DRAIN" ]; then pass
  else infra_fail "recreate=${ok} served=${sd} pending=$(pending_backfill d)"; end_suite; fi

  begin_test "setup: recreate with the worker on and SCAN_WORKER_CONCURRENCY unset (MAX_CONCURRENT_SCAN_EXTRACTIONS=1)"
  if recreate_backend true "" ""; then pass; else infra_fail "recreate failed"; end_suite; fi

  reset_case
  begin_test "FIX #6033: SCAN_WORKER_CONCURRENCY unset follows MAX_CONCURRENT_SCAN_EXTRACTIONS=1: slot capacity 1, never more than 1 job running"
  max_run=0; cap=""; t_end=$(( $(date +%s) + 60 + N_DRAIN * 5 ))
  while [ "$(date +%s)" -lt "$t_end" ]; do
    r=$(psql_q "SELECT count(*) FROM scan_queue WHERE state = 'running'")
    [ "${r:-0}" -gt "$max_run" ] 2>/dev/null && max_run="$r"
    [ -z "$cap" ] && cap="$(metric ak_scan_worker_slots_capacity)"
    [ "$(verdicts d)" = "$N_DRAIN" ] && [ "$(backfill_left d)" = "0" ] && [ -n "$cap" ] && break
    sleep 0.5
  done
  [ -z "$cap" ] && cap="$(metric ak_scan_worker_slots_capacity)"
  started="$(docker logs "ak-dtf${DTF_SLOT}-backend" 2>&1 | grep 'Scan worker started' | tail -1 | grep -o 'concurrency=[0-9]*')"
  note "ak_scan_worker_slots_capacity=${cap:-absent}; most scan_queue rows running at once: ${max_run}; verdicts $(verdicts d)/${N_DRAIN}; log: ${started:-no start line}"
  [ "$cap" = "1" ] || fail_g "ak_scan_worker_slots_capacity is '${cap:-absent}', expected 1 (MAX_CONCURRENT_SCAN_EXTRACTIONS=1)"
  [ "$max_run" -le 1 ] 2>/dev/null || fail_g "${max_run} jobs were running at once with one extraction permit"
  [ "$(verdicts d)" = "$N_DRAIN" ] || fail_g "only $(verdicts d)/${N_DRAIN} backfill pulls got a verdict"
  finish_case "the unset worker concurrency does not follow the extraction limit"

  begin_test "setup: recreate with SCAN_WORKER_CONCURRENCY=2"
  if recreate_backend true 2 ""; then pass; else infra_fail "recreate failed"; end_suite; fi

  begin_test "CONTROL: a set SCAN_WORKER_CONCURRENCY=2 wins over the extraction limit: slot capacity 2"
  cap2=""
  has_cap() { cap2="$(metric ak_scan_worker_slots_capacity)"; [ -n "$cap2" ]; }
  wait_until "slot capacity gauge" 45 has_cap
  cap2="$(metric ak_scan_worker_slots_capacity)"
  if [ "$cap2" = "2" ]; then pass; else fail "ak_scan_worker_slots_capacity is '${cap2:-absent}', expected 2"; fi
fi

end_suite
