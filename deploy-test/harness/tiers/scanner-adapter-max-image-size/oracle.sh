#!/usr/bin/env bash
# =============================================================================
# tiers/scanner-adapter-max-image-size/oracle.sh
#   #5909 with SCANNER_MAX_IMAGE_BYTES set, the scanner adapter refuses an
#         image over the limit before trivy runs (report 422,
#         X-Scan-Status: TooLarge), and the backend records the scan failed
#         with the adapter's "not scanned: image too large" reason, never
#         completed (clean)
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
MOCKREG="ak-dtf${DTF_SLOT}-maxreg"
MOCK_URL="http://dtf-rega:5000"
FILES=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml"
       -f "${DTF_DIR}/profiles/scanners.trivy.yml" -f "${FX}/max-image-size.yml")
SCAN_WAIT=300
LIMIT=4194304      # SCANNER_MAX_IMAGE_BYTES under test (4 MiB)
BIG_PAD_MIB=8      # random, incompressible: about 8 MiB compressed, over LIMIT
REPORT_MT="application/vnd.security.vulnerability.report; version=1.1"

setup_workdir
W="$WORK_DIR"
require_cmd python3

# The mock registry is started with docker run, so the harness' `down -v`
# does not know it: remove it by its exact name on every exit.
remove_mockreg(){ docker rm -f "$MOCKREG" >/dev/null 2>&1 || true; }
add_exit_handler remove_mockreg

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
REPO="samax${DTF_SLOT}-${SFX}"
REG_TOKEN=""

# recreate_adapter <limit or "">: recreate the adapter with the overlay
# (empty = SCANNER_MAX_IMAGE_BYTES unset) and wait for it. Prints "up" or the
# failure.
recreate_adapter(){
  DTF_MAX_IMAGE_BYTES="$1" docker compose -p "$PROJECT" "${FILES[@]}" \
    up -d --no-deps --force-recreate --wait trivy >"${W}/up-trivy.log" 2>&1 \
    && { echo up; return; }
  echo "failed: $(tail -3 "${W}/up-trivy.log" | tr '\n' ' ' | head -c 300)"
}
adapter_env(){ docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$ADAPTER" 2>/dev/null | grep "^$1=" | cut -d= -f2-; }
adapter_ready(){ curl -sf --max-time 5 "${ADAPTER_URL}/probe/ready" >/dev/null 2>&1; }
wait_adapter_ready(){ local t=0; while [ "$t" -lt 120 ] && ! adapter_ready; do sleep 1; t=$((t+1)); done; adapter_ready; }

# mkimg <datadir> <repo> <tag> [mkimage args...]: build one image; echoes
# "<manifest digest> <layer digest> <diff id> <config+layer bytes>".
mkimg(){ python3 -I "$FX/mkimage.py" "$@"; }

# push_image <name> <mkimage args...>: build a unique image and push it to the
# backend's own registry as ${REPO}/<name>:v1; echoes "<artifact id> <bytes>"
# (empty on failure).
push_image(){
  local name="$1" d="$W/push-$1" out dg ldg cdg size loc code blob
  shift
  out="$(mkimg "$d" "${REPO}/${name}" v1 --mark "${RUN_ID}-${name}" "$@")" || return 0
  read -r dg ldg _ size <<<"$out"
  cdg="$(jq -r '.config.digest' "$d/manifests/${REPO}__${name}/v1")"
  for blob in "$ldg" "$cdg"; do
    loc="$(curl -s --max-time 30 -D - -o /dev/null -X POST -H "Authorization: Bearer ${REG_TOKEN}" \
      "${BASE_URL}/v2/${REPO}/${name}/blobs/uploads/" | grep -i '^location:' | head -1 | tr -d '\r' | sed 's/^[Ll]ocation: *//')"
    [ -n "$loc" ] || return 0
    [[ "$loc" == http* ]] || loc="${BASE_URL}${loc}"
    if [[ "$loc" == *"?"* ]]; then loc="${loc}&digest=${blob}"; else loc="${loc}?digest=${blob}"; fi
    code="$(curl -s --max-time 120 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer ${REG_TOKEN}" \
      -H 'Content-Type: application/octet-stream' --data-binary "@$d/blobs/${blob#sha256:}" "$loc")" || code=000
    [[ "$code" =~ ^20[01]$ ]] || return 0
  done
  code="$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer ${REG_TOKEN}" \
    -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$d/manifests/${REPO}__${name}/v1" \
    "${BASE_URL}/v2/${REPO}/${name}/manifests/v1")" || code=000
  [[ "$code" =~ ^20[01]$ ]] || return 0
  local id
  id="$(psqlq "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id
         WHERE r.key='${REPO}' AND a.checksum_sha256='${dg#sha256:}' AND NOT a.is_deleted ORDER BY a.created_at DESC LIMIT 1")"
  [ -n "$id" ] && echo "$id $size"
}
trigger(){ # artifact_id -> HTTP code
  curl -s --max-time 30 -o "$W/trig.out" -w '%{http_code}' -X POST "${BASE_URL}/api/v1/security/scan" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"artifact_id\":\"$1\",\"bypass_dedup\":true}" || echo 000
}
image_rows(){ psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='image'"; }
# image_row <artifact_id>: "status|findings|recorded findings|error" of the
# latest image scan
image_row(){
  psqlq "SELECT s.status||'|'||s.findings_count||'|'||
                (SELECT count(*) FROM scan_findings f WHERE f.scan_result_id=s.id)||'|'||
                COALESCE(left(regexp_replace(s.error_message, '\s+', ' ', 'g'),300),'')
         FROM scan_results s WHERE s.artifact_id='$1' AND s.scan_type='image' ORDER BY s.created_at DESC LIMIT 1"
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
# backend_scan <artifact id>: trigger a scan and wait for the image row.
# Sets BS_TRIGGER, BS_ROW.
backend_scan(){
  BS_TRIGGER="$(trigger "$1")"
  wait_settled "$1" "$SCAN_WAIT" || true
  BS_ROW="$(image_row "$1")"
}

# direct_scan <repository> <tag>: submit a scan of the mock registry's image
# straight to the adapter and poll its report until it is no longer pending.
# Sets DS_SUBMIT, DS_CODE, DS_STATUS (X-Scan-Status) and DS_BODY.
direct_scan(){
  local id t=0 hdr
  DS_SUBMIT="$(curl -s --max-time 30 -o "$W/ds-submit.out" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"registry\":{\"url\":\"${MOCK_URL}\"},\"artifact\":{\"repository\":\"$1\",\"tag\":\"$2\",\"mime_type\":\"application/vnd.oci.image.manifest.v1+json\"}}" \
    "${ADAPTER_URL}/api/v1/scan" 2>/dev/null)" || DS_SUBMIT=000
  id="$(jqr '.id // empty' < "$W/ds-submit.out")"
  DS_CODE=none; DS_STATUS=""; DS_BODY=""
  [ -n "$id" ] || return 0
  while [ "$t" -lt "$SCAN_WAIT" ]; do
    DS_CODE="$(curl -s --max-time 30 -D "$W/ds-hdr" -o "$W/ds-body" -w '%{http_code}' \
      -H "Accept: ${REPORT_MT}" "${ADAPTER_URL}/api/v1/scan/${id}/report" 2>/dev/null)" || DS_CODE=000
    [ "$DS_CODE" = 302 ] || break
    sleep 2; t=$((t+2))
  done
  hdr="$(grep -i '^x-scan-status:' "$W/ds-hdr" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')"
  DS_STATUS="$hdr"
  DS_BODY="$(head -c 4000 "$W/ds-body" | tr -d '\r')"
}
ds_vulns(){ local n; n="$(jq '.vulnerabilities | length' "$W/ds-body" 2>/dev/null)"; echo "${n:-0}"; }
# reg_requests <repository> <kind>: requests to the mock registry for that
# repository's manifests or blobs
reg_requests(){ docker exec "$MOCKREG" cat /tmp/reqlog 2>/dev/null | grep -c " /v2/$1/$2/"; }

begin_suite "scanner-adapter-max-image-size"
auth_admin

# =============================================================================
begin_test "setup: mock registry with an oversized and a small image, adapter with SCANNER_MAX_IMAGE_BYTES=${LIMIT}, warm Trivy DB"
reset_case
create_repo "$REPO" docker local || fail_g "create docker repository ${REPO}"
REG_TOKEN="$(curl -s --max-time 30 -u "${ADMIN_USER:-admin}:${ADMIN_PASS}" "${BASE_URL}/v2/token" | jqr '.token // .access_token // empty')"
[ -n "$REG_TOKEN" ] || fail_g "no registry token from /v2/token"
read -r _ BIG_LAYER _ BIG_BYTES <<<"$(mkimg "$W/regdata" dtf/big v1 --pad-mib "$BIG_PAD_MIB" --mark "${RUN_ID}-big")"
read -r _ _ _ SMALL_BYTES <<<"$(mkimg "$W/regdata" dtf/small v1 --mark "${RUN_ID}-small")"
note "mock images: dtf/big:v1 ${BIG_BYTES:-?} bytes (layer ${BIG_LAYER:-?}), dtf/small:v1 ${SMALL_BYTES:-?} bytes; limit ${LIMIT}"
[ "${BIG_BYTES:-0}" -gt "$LIMIT" ] 2>/dev/null || fail_g "the oversized image is not over the limit"
[ "${SMALL_BYTES:-999999999}" -lt "$LIMIT" ] 2>/dev/null || fail_g "the small image is not under the limit"
remove_mockreg
docker run -d --name "$MOCKREG" --network "ak-dtf${DTF_SLOT}-net" --network-alias dtf-rega --network-alias dtf-regb \
  --security-opt label=disable -v "$FX/ocireg.py:/app/ocireg.py:ro" python:3.12-slim python3 /app/ocireg.py >/dev/null 2>&1 \
  || fail_g "docker run ${MOCKREG} failed"
docker exec "$MOCKREG" mkdir -p /data >/dev/null 2>&1
docker cp "$W/regdata/." "${MOCKREG}:/data/" >/dev/null 2>&1 || fail_g "docker cp the registry data into ${MOCKREG} failed"
r="$(recreate_adapter "$LIMIT")"; [ "$r" = up ] || fail_g "recreate adapter: $r"
[ "$(adapter_env SCANNER_MAX_IMAGE_BYTES)" = "$LIMIT" ] || fail_g "adapter does not carry SCANNER_MAX_IMAGE_BYTES=${LIMIT}"
warmed=0
for attempt in 1 2 3 4 5; do
  if docker exec "$ADAPTER" sh -c 'trivy image --cache-dir "${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}" --download-db-only' >/dev/null 2>&1; then
    warmed=1; break
  fi
  echo "   DB warm attempt ${attempt}/5 failed; retrying in 5s"; sleep 5
done
[ "$warmed" = 1 ] || fail_g "could not download the Trivy DB in ${ADAPTER} (ghcr.io/aquasecurity/trivy-db)"
wait_adapter_ready || fail_g "adapter not ready on ${ADAPTER_URL}"
c="$(docker exec "$ADAPTER" wget -qO- "${MOCK_URL}/v2/" 2>/dev/null)"
[ "$c" = "{}" ] || fail_g "the adapter cannot reach the mock registry at ${MOCK_URL}"
finish_case "setup failed"
[ "$FAILS" -eq 0 ] || { remove_mockreg; end_suite; }

# =============================================================================
begin_test "FIX #5909: with SCANNER_MAX_IMAGE_BYTES=${LIMIT}, a direct scan of a ${BIG_PAD_MIB} MiB image gets 422 TooLarge and trivy never pulls a layer"
reset_case
direct_scan dtf/big v1
note "submit -> ${DS_SUBMIT}; report -> ${DS_CODE}, X-Scan-Status: ${DS_STATUS:-none}"
note "report body: $(printf '%s' "$DS_BODY" | head -c 300)"
mreq="$(reg_requests dtf/big manifests)"; breq="$(reg_requests dtf/big blobs)"
note "mock registry requests for dtf/big: ${mreq} manifest, ${breq} blob"
[ "$DS_SUBMIT" = 202 ] || fail_g "submit -> ${DS_SUBMIT}, expected 202"
[ "$DS_CODE" = 422 ] || fail_g "report -> ${DS_CODE}, expected 422 (pre-fix: trivy pulls the image and the report is 200)"
[ "$DS_STATUS" = TooLarge ] || fail_g "X-Scan-Status '${DS_STATUS}', expected TooLarge"
case "$DS_BODY" in *"not scanned: image too large"*) ;; *) fail_g "the body does not say 'not scanned: image too large'";; esac
case "$DS_BODY" in *"dtf-rega:5000/dtf/big:v1"*) ;; *) fail_g "the body does not name the image dtf-rega:5000/dtf/big:v1";; esac
case "$DS_BODY" in *" ${BIG_BYTES} bytes"*) ;; *) fail_g "the body does not give the image size ${BIG_BYTES} bytes";; esac
case "$DS_BODY" in *"SCANNER_MAX_IMAGE_BYTES=${LIMIT}"*) ;; *) fail_g "the body does not name SCANNER_MAX_IMAGE_BYTES=${LIMIT}";; esac
[ "${mreq:-0}" -ge 1 ] 2>/dev/null || fail_g "the adapter never read the manifest of dtf/big"
[ "${breq:-1}" = 0 ] || fail_g "${breq} blob request(s) for dtf/big reached the registry: trivy ran and pulled the image"
finish_case "an image over SCANNER_MAX_IMAGE_BYTES is scanned instead of refused"

# =============================================================================
begin_test "CONTROL: with SCANNER_MAX_IMAGE_BYTES=${LIMIT}, a direct scan of an image under the limit is scanned (200 with findings)"
reset_case
direct_scan dtf/small v1
n="$(ds_vulns)"
note "submit -> ${DS_SUBMIT}; report -> ${DS_CODE}, X-Scan-Status: ${DS_STATUS:-none}; ${n} vulnerabilities"
[ "$DS_CODE" = 200 ] || fail_g "report -> ${DS_CODE} $(printf '%s' "$DS_BODY" | head -c 200), expected 200"
[ "${n:-0}" -ge 1 ] 2>/dev/null || fail_g "the report has ${n:-no} vulnerabilities, expected libcrypto1.1's CVEs"
[ "$(reg_requests dtf/small blobs)" -ge 1 ] 2>/dev/null || fail_g "trivy did not pull dtf/small's blobs"
finish_case "an image under the limit is not scanned normally"

# =============================================================================
begin_test "FIX #5909: through the backend, an image over the limit is recorded failed with 'image too large', never completed (clean)"
reset_case
read -r A1 A1_BYTES <<<"$(push_image big --pad-mib "$BIG_PAD_MIB")"
backend_scan "${A1:-none}"
note "artifact ${A1:-none} (${A1_BYTES:-?} bytes); trigger -> ${BS_TRIGGER}"
note "image row status|findings|recorded findings|error = ${BS_ROW:-none}"
note "every scan row for it: $(psqlq "SELECT string_agg(scan_type||':'||status||':'||findings_count, ', ' ORDER BY created_at) FROM scan_results WHERE artifact_id='${A1:-00000000-0000-0000-0000-000000000000}'")"
[ -n "$A1" ] || fail_g "image push failed"
[ "$BS_TRIGGER" = 200 ] || fail_g "trigger -> ${BS_TRIGGER} $(head -c 200 "$W/trig.out")"
IFS='|' read -r st fc rf err <<<"$BS_ROW"
[ "$st" = failed ] || fail_g "image scan status '${st:-none}', expected failed (pre-fix: completed with libcrypto1.1's CVEs)"
[ "${fc:-x}" = 0 ] || fail_g "image scan findings_count ${fc:-none}, expected 0 (no report)"
[ "${rf:-x}" = 0 ] || fail_g "${rf:-?} findings recorded for the refused scan, expected none"
case "$err" in *"image too large"*) ;; *) fail_g "error_message '${err}' does not carry the adapter's 'image too large' reason";; esac
case "$err" in *"SCANNER_MAX_IMAGE_BYTES=${LIMIT}"*) ;; *) fail_g "error_message does not name SCANNER_MAX_IMAGE_BYTES=${LIMIT}";; esac
done_rows="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A1:-00000000-0000-0000-0000-000000000000}' AND scan_type='image' AND status='completed'")"
[ "${done_rows:-x}" = 0 ] || fail_g "${done_rows:-?} completed image scan row(s) for the refused image: recorded as scanned"
finish_case "the backend does not record an image refused as too large as not scanned"

# =============================================================================
begin_test "CONTROL: through the backend, with SCANNER_MAX_IMAGE_BYTES=${LIMIT}, an image under the limit completes with findings"
reset_case
read -r A2 A2_BYTES <<<"$(push_image small)"
backend_scan "${A2:-none}"
note "artifact ${A2:-none} (${A2_BYTES:-?} bytes); trigger -> ${BS_TRIGGER}"
note "image row status|findings|recorded findings|error = ${BS_ROW:-none}"
[ -n "$A2" ] || fail_g "image push failed"
[ "$BS_TRIGGER" = 200 ] || fail_g "trigger -> ${BS_TRIGGER} $(head -c 200 "$W/trig.out")"
IFS='|' read -r st fc _ _ <<<"$BS_ROW"
[ "$st" = completed ] || fail_g "image scan '${BS_ROW}', expected completed"
[ "${fc:-0}" -ge 1 ] 2>/dev/null || fail_g "image scan reported ${fc:-no} findings, expected libcrypto1.1's CVEs"
finish_case "an image under the limit does not scan normally through the backend"

# =============================================================================
begin_test "CONTROL: with SCANNER_MAX_IMAGE_BYTES unset (default), an image over ${LIMIT} bytes scans normally, direct and through the backend"
reset_case
r="$(recreate_adapter "")"; [ "$r" = up ] || fail_g "recreate adapter without the limit: $r"
[ -z "$(adapter_env SCANNER_MAX_IMAGE_BYTES)" ] || fail_g "adapter still carries SCANNER_MAX_IMAGE_BYTES=$(adapter_env SCANNER_MAX_IMAGE_BYTES)"
wait_adapter_ready || fail_g "adapter not ready on ${ADAPTER_URL} after the recreate"
read -r _ _ _ BIG2_BYTES <<<"$(mkimg "$W/regdata2" dtf/big2 v1 --pad-mib "$BIG_PAD_MIB" --mark "${RUN_ID}-big2")"
docker cp "$W/regdata2/." "${MOCKREG}:/data/" >/dev/null 2>&1 || fail_g "docker cp dtf/big2 into ${MOCKREG} failed"
direct_scan dtf/big2 v1
n="$(ds_vulns)"
note "direct: dtf/big2:v1 ${BIG2_BYTES:-?} bytes; report -> ${DS_CODE}, X-Scan-Status: ${DS_STATUS:-none}; ${n} vulnerabilities; $(reg_requests dtf/big2 blobs) blob request(s)"
[ "$DS_CODE" = 200 ] || fail_g "direct report -> ${DS_CODE} $(printf '%s' "$DS_BODY" | head -c 200), expected 200"
[ "${n:-0}" -ge 1 ] 2>/dev/null || fail_g "the direct report has ${n:-no} vulnerabilities, expected libcrypto1.1's CVEs"
read -r A3 A3_BYTES <<<"$(push_image bigdefault --pad-mib "$BIG_PAD_MIB")"
backend_scan "${A3:-none}"
note "backend: artifact ${A3:-none} (${A3_BYTES:-?} bytes); trigger -> ${BS_TRIGGER}"
note "image row status|findings|recorded findings|error = ${BS_ROW:-none}"
[ -n "$A3" ] || fail_g "image push failed"
[ "${A3_BYTES:-0}" -gt "$LIMIT" ] 2>/dev/null || fail_g "the pushed image is not over ${LIMIT} bytes"
IFS='|' read -r st fc _ _ <<<"$BS_ROW"
[ "$st" = completed ] || fail_g "image scan '${BS_ROW}', expected completed"
[ "${fc:-0}" -ge 1 ] 2>/dev/null || fail_g "image scan reported ${fc:-no} findings, expected libcrypto1.1's CVEs"
finish_case "the default (no limit) no longer scans a large image"

remove_mockreg
end_suite
