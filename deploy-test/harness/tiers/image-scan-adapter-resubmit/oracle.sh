#!/usr/bin/env bash
# =============================================================================
# tiers/image-scan-adapter-resubmit/oracle.sh
#   #5657 the backend resubmits an image scan the scanner adapter lost to a
#         restart, and one that failed on trivy's cache lock because another
#         scan held it
# See the manifest for the fix and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the adapter's published port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADAPTER="ak-dtf${DTF_SLOT}-trivy"
ADAPTER_URL="http://127.0.0.1:${TRIVY_PORT}"
SCAN_WAIT=300
LOCK_HOLD=12       # seconds another process holds trivy's cache lock
PAD_MIB=4          # MiB of random bytes in each layer

setup_workdir
W="$WORK_DIR"
require_cmd python3

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
REPO="isar${DTF_SLOT}-${SFX}"
REG_TOKEN=""

# push_image <name> <tag>: build a unique image and push it; echoes the
# manifest artifact id (empty on failure).
push_image(){
  local name="$1" tag="$2" d="$W/img-$1" dg ldg cdg loc code
  dg="$(python3 -I "$HERE/fixtures/mkimage.py" "$d" "${REPO}-${name}" "$PAD_MIB")" || return 0
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
# image_row <artifact_id>: "status|findings|error" of the latest image scan
image_row(){
  psqlq "SELECT status||'|'||findings_count||'|'||COALESCE(left(regexp_replace(error_message, '\s+', ' ', 'g'),200),'')
         FROM scan_results WHERE artifact_id='$1' AND scan_type='image' ORDER BY created_at DESC LIMIT 1"
}
image_settled(){ # artifact_id min_rows
  [ "$(image_rows "$1")" -ge "$2" ] 2>/dev/null && \
  [ "$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='image' AND status IN ('pending','running')")" = "0" ]
}
wait_settled(){ # artifact_id min_rows timeout
  local t=0
  while [ "$t" -lt "$3" ]; do image_settled "$1" "$2" && return 0; sleep 2; t=$((t+2)); done
  return 1
}
adapter_ready(){ curl -sf --max-time 5 "${ADAPTER_URL}/probe/ready" >/dev/null 2>&1; }

begin_suite "image-scan-adapter-resubmit"
auth_admin

# =============================================================================
begin_test "setup: docker repository, registry token, warm Trivy DB in the adapter"
reset_case
create_repo "$REPO" docker local || fail_g "create docker repository ${REPO}"
REG_TOKEN="$(curl -s --max-time 30 -u "${ADMIN_USER:-admin}:${ADMIN_PASS}" "${BASE_URL}/v2/token" | jqr '.token // .access_token // empty')"
[ -n "$REG_TOKEN" ] || fail_g "no registry token from /v2/token"
adapter_ready || fail_g "adapter not ready on ${ADAPTER_URL}"
# The first scan would otherwise pay the ~100 MiB DB download inline (the
# supply-chain tier does the same pre-warm).
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
begin_test "CONTROL: one image scan through the adapter completes with libcrypto1.1's CVEs"
reset_case
A0="$(push_image base v1)"
c="$(trigger "${A0:-none}")"
wait_settled "${A0:-none}" 1 "$SCAN_WAIT" || true
row="$(image_row "${A0:-none}")"
note "artifact ${A0:-none}; trigger -> ${c}; image row status|findings|error = ${row:-none}"
[ -n "$A0" ] || fail_g "image push failed"
[ "$c" = "200" ] || fail_g "trigger -> ${c} $(head -c 200 "$W/trig.out")"
[ "${row%%|*}" = "completed" ] || fail_g "image scan '${row}', expected completed"
f="$(echo "$row" | cut -d'|' -f2)"
[ "${f:-0}" -ge 1 ] 2>/dev/null || fail_g "image scan reported ${f:-no} findings, expected the openssl 1.1.1c CVEs"
finish_case "image scan baseline"

# =============================================================================
begin_test "FIX #5657: an image scan whose adapter is restarted mid-scan is resubmitted and completes"
reset_case
A1="$(push_image restart v1)"
c="$(trigger "${A1:-none}")"
# The backend marks the image row running, checks the adapter's readiness and
# submits the job, then polls for the report every few seconds. Restart the
# adapter in that gap: the new process has no record of the job, so the
# backend's next poll fails (pre-fix: the scan fails) or answers 404 unknown
# scan id (fixed: the backend submits the scan again).
acc=0
for _ in $(seq 1 150); do
  [ "$(psqlq "SELECT status FROM scan_results WHERE artifact_id='${A1:-none}' AND scan_type='image' ORDER BY created_at DESC LIMIT 1")" = "running" ] && { acc=1; break; }
  sleep 0.2
done
sleep 1.5
st_before="$(psqlq "SELECT status FROM scan_results WHERE artifact_id='${A1:-none}' AND scan_type='image' ORDER BY created_at DESC LIMIT 1")"
docker restart -t 0 "$ADAPTER" >/dev/null 2>&1 || fail_g "docker restart ${ADAPTER} failed"
t=0; while [ "$t" -lt 60 ] && ! adapter_ready; do sleep 1; t=$((t+1)); done
wait_settled "${A1:-none}" 1 "$SCAN_WAIT" || true
row="$(image_row "${A1:-none}")"
note "artifact ${A1:-none}; trigger -> ${c}; image row running before the restart: ${acc}; row status at restart: ${st_before:-none}; adapter ready again after ${t}s"
note "image row status|findings|error = ${row:-none}"
[ -n "$A1" ] || fail_g "image push failed"
[ "$acc" = 1 ] || fail_g "the image scan never started before the restart (cannot interrupt it)"
[ "$st_before" = "running" ] || fail_g "the image scan was ${st_before:-gone} when the adapter was restarted (not mid-scan)"
[ "${row%%|*}" = "completed" ] || fail_g "image scan '${row}' after the adapter restart, expected completed (pre-fix: failed on the transport error or 404 unknown scan id)"
finish_case "a scan lost to an adapter restart fails"

# =============================================================================
# Trivy holds an exclusive lock on <cache>/fanal/fanal.db for a whole image
# scan and gives up after 5 s. Six scans at once in one adapter pod hit it in
# the issue; here another process holds the lock (the PR's "another process on
# a shared cache volume" case), which fails the scan the same way, every time.
begin_test "FIX #5657: an image scan that fails on trivy's cache lock is resubmitted and completes once the lock is free"
reset_case
A2="$(push_image cachelock v1)"
docker exec -d "$ADAPTER" sh -c "flock -x \"\${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}/fanal/fanal.db\" sleep ${LOCK_HOLD}" >/dev/null 2>&1 || true
sleep 1
held=0
docker exec "$ADAPTER" sh -c 'flock -n -x "${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}/fanal/fanal.db" true' >/dev/null 2>&1 || held=1
c="$(trigger "${A2:-none}")"
wait_settled "${A2:-none}" 1 "$SCAN_WAIT" || true
row="$(image_row "${A2:-none}")"
lockerr="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A2:-none}' AND scan_type='image' AND error_message LIKE '%cache may be in use by another process%'")"
note "artifact ${A2:-none}; cache lock held for ${LOCK_HOLD}s: ${held}; trigger -> ${c}; image rows failed on the cache lock: ${lockerr:-0}"
note "image row status|findings|error = ${row:-none}"
[ -n "$A2" ] || fail_g "image push failed"
[ "$held" = 1 ] || fail_g "could not hold trivy's cache lock in ${ADAPTER}"
[ "${row%%|*}" = "completed" ] || fail_g "image scan '${row}', expected completed (pre-fix: 'cache may be in use by another process: timeout' fails the scan)"
finish_case "a scan that hit trivy's cache lock fails"

end_suite
