#!/usr/bin/env bash
# =============================================================================
# tiers/scanner-adapter-on-demand/oracle.sh
#   #5945 the backend waits SCANNER_ADAPTER_READY_TIMEOUT_SECS for an adapter
#         that is started on demand, and still fails closed past it
#   #5948 the adapter's scan and report routes require SCANNER_SCAN_TOKEN, the
#         backend sends TRIVY_ADAPTER_TOKEN, and the probes stay open
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, TRIVY_PORT (the adapter's published port), BACKEND_IMAGE,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below judges its own result.
set +e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX="${HERE}/fixtures"
PROJECT="ak-dtf${DTF_SLOT}"
ADAPTER="ak-dtf${DTF_SLOT}-trivy"
ADAPTER_URL="http://127.0.0.1:${TRIVY_PORT}"
FILES=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml"
       -f "${DTF_DIR}/profiles/scanners.trivy.yml" -f "${FX}/on-demand.yml")
SCAN_WAIT=300
START_DELAY=25     # seconds the adapter stays down after the scan request
BUDGET=60          # SCANNER_ADAPTER_READY_TIMEOUT_SECS under test
OVER_BUDGET=80     # seconds the adapter stays down in the past-the-budget case
PAD_MIB=1

setup_workdir
W="$WORK_DIR"
require_cmd python3

# Generated per run, never committed. The oracle exports it for the compose
# overlay; it is never printed.
DTF_ADAPTER_SCAN_TOKEN="dtf-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export DTF_ADAPTER_SCAN_TOKEN

jqr(){ jq -r "$1" 2>/dev/null || true; }
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '\r' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

SFX="$(printf '%s' "${RUN_ID##*-}" | tr -cd '0-9' | tail -c 8)"
REPO="saod${DTF_SLOT}-${SFX}"
REG_TOKEN=""

# recreate <service> [READY_TIMEOUT]: recreate one service with the overlay
# and wait for it to be healthy. Prints "up" or the failure.
recreate(){
  local svc="$1"
  DTF_ADAPTER_READY_TIMEOUT_SECS="${2:-}" docker compose -p "$PROJECT" "${FILES[@]}" \
    up -d --no-deps --force-recreate --wait "$svc" >"${W}/up-${svc}.log" 2>&1 \
    && { echo up; return; }
  echo "failed: $(tail -3 "${W}/up-${svc}.log" | tr '\n' ' ' | head -c 300)"
}
backend_env(){ docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "ak-dtf${DTF_SLOT}-backend" 2>/dev/null | grep "^$1=" | cut -d= -f2-; }

# push_image <name> <tag>: build a unique image and push it; echoes the
# manifest artifact id (empty on failure).
push_image(){
  local name="$1" tag="$2" d="$W/img-$1" dg ldg cdg loc code
  dg="$(python3 -I "$FX/mkimage.py" "$d" "${REPO}-${name}" "$PAD_MIB")" || return 0
  read -r ldg cdg < "$d/digests"
  for pair in "layer:$ldg" "config:$cdg"; do
    loc="$(curl -s --max-time 30 -D - -o /dev/null -X POST -H "Authorization: Bearer ${REG_TOKEN}" \
      "${BASE_URL}/v2/${REPO}/${name}/blobs/uploads/" | grep -i '^location:' | head -1 | tr -d '\r' | sed 's/^[Ll]ocation: *//')"
    [ -n "$loc" ] || return 0
    [[ "$loc" == http* ]] || loc="${BASE_URL}${loc}"
    if [[ "$loc" == *"?"* ]]; then loc="${loc}&digest=${pair#*:}"; else loc="${loc}?digest=${pair#*:}"; fi
    code="$(curl -s --max-time 120 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer ${REG_TOKEN}" \
      -H 'Content-Type: application/octet-stream' --data-binary "@$d/${pair%%:*}" "$loc")" || code=000
    [[ "$code" =~ ^20[01]$ ]] || return 0
  done
  code="$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer ${REG_TOKEN}" \
    -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$d/manifest" \
    "${BASE_URL}/v2/${REPO}/${name}/manifests/${tag}")" || code=000
  [[ "$code" =~ ^20[01]$ ]] || return 0
  psqlq "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id
         WHERE r.key='${REPO}' AND a.checksum_sha256='${dg#sha256:}' AND NOT a.is_deleted ORDER BY a.created_at DESC LIMIT 1"
}
trigger(){ # artifact_id -> HTTP code
  curl -s --max-time 30 -o "$W/trig.out" -w '%{http_code}' -X POST "${BASE_URL}/api/v1/security/scan" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"artifact_id\":\"$1\",\"bypass_dedup\":true}" || echo 000
}
image_rows(){ psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='image'"; }
# image_row <artifact_id>: "status|findings|seconds from start to end|error"
# of the latest image scan
image_row(){
  psqlq "SELECT status||'|'||findings_count||'|'||
                COALESCE(round(extract(epoch FROM (completed_at - COALESCE(started_at, created_at))))::text,'')||'|'||
                COALESCE(left(regexp_replace(error_message, '\s+', ' ', 'g'),240),'')
         FROM scan_results WHERE artifact_id='$1' AND scan_type='image' ORDER BY created_at DESC LIMIT 1"
}
wait_settled(){ # artifact_id timeout
  local t=0
  while [ "$t" -lt "$2" ]; do
    [ "$(image_rows "$1")" -ge 1 ] 2>/dev/null && \
    [ "$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='image' AND status IN ('pending','running')")" = "0" ] && return 0
    sleep 2; t=$((t+2))
  done
  return 1
}
wait_running(){ # artifact_id -> 0 once the image row is running
  local _
  for _ in $(seq 1 150); do
    [ "$(psqlq "SELECT status FROM scan_results WHERE artifact_id='$1' AND scan_type='image' ORDER BY created_at DESC LIMIT 1")" = "running" ] && return 0
    sleep 0.2
  done
  return 1
}
adapter_ready(){ curl -sf --max-time 5 "${ADAPTER_URL}/probe/ready" >/dev/null 2>&1; }
wait_adapter_ready(){ local t=0; while [ "$t" -lt 90 ] && ! adapter_ready; do sleep 1; t=$((t+1)); done; adapter_ready; }
# direct <method> <path> [auth]: HTTP code of a request straight to the adapter
direct(){
  local args=(-s --max-time 15 -o "$W/direct.out" -w '%{http_code}' -X "$1")
  [ -n "${3:-}" ] && args+=(-H "Authorization: $3")
  if [ "$1" = POST ]; then
    args+=(-H 'Content-Type: application/json' -d '{"registry":{"url":"http://backend:8080"},"artifact":{"repository":"dtf/none","tag":"v1","mime_type":"application/vnd.oci.image.manifest.v1+json"}}')
  fi
  curl "${args[@]}" "${ADAPTER_URL}$2" 2>/dev/null || echo 000
}

# on_demand_scan <artifact_id> <down_seconds>: stop the adapter, request the
# scan, start the adapter <down_seconds> later, wait for the row to settle.
# Sets OD_TRIGGER, OD_RUNNING, OD_ROW.
on_demand_scan(){
  local id="$1" down="$2"
  docker stop -t 2 "$ADAPTER" >/dev/null 2>&1 || fail_g "docker stop ${ADAPTER} failed"
  adapter_ready && fail_g "adapter still answers after docker stop"
  OD_TRIGGER="$(trigger "$id")"
  OD_RUNNING=0; wait_running "$id" && OD_RUNNING=1
  sleep "$down"
  docker start "$ADAPTER" >/dev/null 2>&1 || fail_g "docker start ${ADAPTER} failed"
  wait_adapter_ready || fail_g "adapter not ready within 90s of docker start"
  wait_settled "$id" "$SCAN_WAIT" || true
  OD_ROW="$(image_row "$id")"
}

begin_suite "scanner-adapter-on-demand"
auth_admin

# =============================================================================
begin_test "setup: adapter with a scan token, backend with the token and a ${BUDGET}s readiness wait, warm Trivy DB"
reset_case
create_repo "$REPO" docker local || fail_g "create docker repository ${REPO}"
REG_TOKEN="$(curl -s --max-time 30 -u "${ADMIN_USER:-admin}:${ADMIN_PASS}" "${BASE_URL}/v2/token" | jqr '.token // .access_token // empty')"
[ -n "$REG_TOKEN" ] || fail_g "no registry token from /v2/token"
r="$(recreate trivy)"; [ "$r" = up ] || fail_g "recreate adapter: $r"
r="$(recreate backend "$BUDGET")"; [ "$r" = up ] || fail_g "recreate backend: $r"
wait_adapter_ready || fail_g "adapter not ready on ${ADAPTER_URL}"
[ "$(backend_env SCANNER_ADAPTER_READY_TIMEOUT_SECS)" = "$BUDGET" ] || fail_g "backend does not carry SCANNER_ADAPTER_READY_TIMEOUT_SECS=${BUDGET}"
[ "$(backend_env TRIVY_ADAPTER_TOKEN)" = "$DTF_ADAPTER_SCAN_TOKEN" ] || fail_g "backend does not carry the generated TRIVY_ADAPTER_TOKEN"
auth_admin
warmed=0
for attempt in 1 2 3 4 5; do
  if docker exec "$ADAPTER" sh -c 'trivy image --cache-dir "${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}" --download-db-only' >/dev/null 2>&1; then
    warmed=1; break
  fi
  echo "   DB warm attempt ${attempt}/5 failed; retrying in 5s"; sleep 5
done
[ "$warmed" = 1 ] || fail_g "could not download the Trivy DB in ${ADAPTER} (ghcr.io/aquasecurity/trivy-db)"
finish_case "setup failed"
[ "$FAILS" -eq 0 ] || end_suite

# =============================================================================
begin_test "CONTROL: the adapter's probes and metadata answer without a token"
reset_case
for p in /probe/ready /probe/healthy /api/v1/metadata; do
  c="$(direct GET "$p")"
  note "GET ${p} without a token -> ${c}"
  [ "$c" = 200 ] || fail_g "GET ${p} without a token -> ${c}, expected 200"
done
finish_case "probes or metadata refused without a token"

# =============================================================================
begin_test "FIX #5948: with SCANNER_SCAN_TOKEN set, a scan or report call without the right token gets 401"
reset_case
for auth in "" "Bearer wrong-${SFX}"; do
  label="${auth:+a wrong token}"; label="${label:-no token}"
  c="$(direct POST /api/v1/scan "$auth")"
  note "POST /api/v1/scan with ${label} -> ${c}"
  [ "$c" = 401 ] || fail_g "POST /api/v1/scan with ${label} -> ${c}, expected 401 (pre-fix: 202, anyone on the network can make the adapter pull an image)"
  c="$(direct GET /api/v1/scan/dtf-unknown/report "$auth")"
  note "GET /api/v1/scan/{id}/report with ${label} -> ${c}"
  [ "$c" = 401 ] || fail_g "GET /api/v1/scan/{id}/report with ${label} -> ${c}, expected 401"
  c="$(direct POST /api/v1/filesystem/scan "$auth")"
  note "POST /api/v1/filesystem/scan with ${label} -> ${c}"
  [ "$c" = 401 ] || fail_g "POST /api/v1/filesystem/scan with ${label} -> ${c}, expected 401"
done
c="$(direct GET /api/v1/scan/dtf-unknown/report "Bearer ${DTF_ADAPTER_SCAN_TOKEN}")"
note "GET /api/v1/scan/{unknown id}/report with the token -> ${c}"
[ "$c" = 404 ] || fail_g "the right token reaches the report handler: got ${c}, expected 404 for an unknown id"
finish_case "the adapter's scan routes accept unauthenticated callers"

# =============================================================================
begin_test "FIX #5948: the backend, configured with TRIVY_ADAPTER_TOKEN, scans through an adapter that requires it"
reset_case
gate="$(direct POST /api/v1/scan)"
A1="$(push_image token v1)"
c="$(trigger "${A1:-none}")"
wait_settled "${A1:-none}" "$SCAN_WAIT" || true
row="$(image_row "${A1:-none}")"
note "adapter refuses an unauthenticated scan: ${gate}; artifact ${A1:-none}; trigger -> ${c}"
note "image row status|findings|seconds|error = ${row:-none}"
[ "$gate" = 401 ] || fail_g "the adapter does not require the token (unauthenticated scan -> ${gate}), so this scan proves nothing about the backend sending it"
[ -n "$A1" ] || fail_g "image push failed"
[ "$c" = 200 ] || fail_g "trigger -> ${c} $(head -c 200 "$W/trig.out")"
[ "${row%%|*}" = completed ] || fail_g "image scan '${row}', expected completed"
f="$(echo "$row" | cut -d'|' -f2)"
[ "${f:-0}" -ge 1 ] 2>/dev/null || fail_g "image scan reported ${f:-no} findings, expected libcrypto1.1's CVEs"
logs="$(docker logs "ak-dtf${DTF_SLOT}-backend" 2>&1)"
if printf '%s' "$logs" | grep -qF "$DTF_ADAPTER_SCAN_TOKEN"; then fail_g "the adapter token appears in the backend log"; fi
if psqlq "SELECT count(*) FROM scan_results WHERE error_message LIKE '%${DTF_ADAPTER_SCAN_TOKEN}%'" | grep -qv '^0$'; then
  fail_g "the adapter token appears in a scan error message"
fi
finish_case "the backend does not authenticate to the adapter"

# =============================================================================
begin_test "FIX #5945: an adapter started ${START_DELAY}s after the scan request is waited for (SCANNER_ADAPTER_READY_TIMEOUT_SECS=${BUDGET}) and the scan completes"
reset_case
A2="$(push_image ondemand v1)"
on_demand_scan "${A2:-none}" "$START_DELAY"
note "artifact ${A2:-none}; trigger -> ${OD_TRIGGER}; image row running while the adapter was down: ${OD_RUNNING}"
note "image row status|findings|seconds|error = ${OD_ROW:-none}"
[ -n "$A2" ] || fail_g "image push failed"
[ "$OD_TRIGGER" = 200 ] || fail_g "trigger -> ${OD_TRIGGER}"
[ "$OD_RUNNING" = 1 ] || fail_g "the image scan never started while the adapter was down"
[ "${OD_ROW%%|*}" = completed ] || fail_g "image scan '${OD_ROW}', expected completed (pre-fix: failed within the fixed three-attempt gate, 'Scanner adapter ... is unreachable')"
f="$(echo "$OD_ROW" | cut -d'|' -f2)"
[ "${f:-0}" -ge 1 ] 2>/dev/null || fail_g "image scan reported ${f:-no} findings, expected libcrypto1.1's CVEs"
finish_case "a scan does not wait for an adapter started on demand"

# =============================================================================
begin_test "FIX #5945: an adapter still down after the ${BUDGET}s budget fails the scan closed at the budget, naming it unreachable"
reset_case
A3="$(push_image overbudget v1)"
on_demand_scan "${A3:-none}" "$OVER_BUDGET"
secs="$(echo "$OD_ROW" | cut -d'|' -f3)"
note "artifact ${A3:-none}; trigger -> ${OD_TRIGGER}; adapter down for ${OVER_BUDGET}s"
note "image row status|findings|seconds|error = ${OD_ROW:-none}"
[ -n "$A3" ] || fail_g "image push failed"
[ "${OD_ROW%%|*}" = failed ] || fail_g "image scan '${OD_ROW}', expected failed (fail-closed, never completed with 0 findings)"
[ "${secs:-0}" -ge $((BUDGET - 5)) ] 2>/dev/null || fail_g "the scan failed after ${secs:-?}s, before the ${BUDGET}s budget (pre-fix: about 16s or less)"
[ "${secs:-999}" -le $((BUDGET + 20)) ] 2>/dev/null || fail_g "the scan failed after ${secs:-?}s, long after the ${BUDGET}s budget"
echo "$OD_ROW" | grep -q "unreachable" || fail_g "the error does not say the adapter was unreachable"
finish_case "the readiness budget is not honoured, or the scan does not fail closed past it"

# =============================================================================
begin_test "CONTROL: with the default readiness wait, an adapter started ${START_DELAY}s after the scan request fails the scan closed"
reset_case
r="$(recreate backend "")"; [ "$r" = up ] || fail_g "recreate backend with the default wait: $r"
[ -z "$(backend_env SCANNER_ADAPTER_READY_TIMEOUT_SECS)" ] || fail_g "backend still carries SCANNER_ADAPTER_READY_TIMEOUT_SECS"
auth_admin
A4="$(push_image default v1)"
on_demand_scan "${A4:-none}" "$START_DELAY"
secs="$(echo "$OD_ROW" | cut -d'|' -f3)"
note "artifact ${A4:-none}; trigger -> ${OD_TRIGGER}"
note "image row status|findings|seconds|error = ${OD_ROW:-none}"
[ -n "$A4" ] || fail_g "image push failed"
[ "${OD_ROW%%|*}" = failed ] || fail_g "image scan '${OD_ROW}', expected failed (the default wait is about 16s)"
[ "${secs:-999}" -lt "$START_DELAY" ] 2>/dev/null || fail_g "the scan took ${secs:-?}s to fail, expected under ${START_DELAY}s with the default wait"
finish_case "the default readiness wait changed"

end_suite
