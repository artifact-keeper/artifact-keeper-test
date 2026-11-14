#!/usr/bin/env bash
# =============================================================================
# tiers/scanner-adapter-cache-partition/oracle.sh
#   #5943 SCANNER_TRIVY_CACHE_PARTITION_MODE=registry gives each registry host
#         its own trivy analysis-cache partition, so an adapter (and trivy
#         server) shared by several Artifact Keeper instances never reuses one
#         instance's cached layer analysis for another instance's image.
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, TRIVY_PORT (the adapter's published port), BACKEND_IMAGE,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"
: "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below judges its own result.
set +e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX="${HERE}/fixtures"
PROJECT="ak-dtf${DTF_SLOT}"
NET="ak-dtf${DTF_SLOT}-net"
ADAPTER="ak-dtf${DTF_SLOT}-trivy"
ADAPTER_URL="http://127.0.0.1:${TRIVY_PORT}"
REG="ak-dtf${DTF_SLOT}-sacp-reg"
SRV="ak-dtf${DTF_SLOT}-sacp-trivysrv"
# The trivy server the adapter's bundled trivy 0.76.0 talks to (client and
# server versions must match). Pinned by digest.
TRIVY_SERVER_IMAGE="ghcr.io/artifact-keeper/trivy@sha256:47199755ccf75b3c6776b0e6bca8a95ed8ca83fe330c7458bec30e661ded5835"
REG_IMAGE="python:3.12-slim"
REGA="http://dtf-rega:5000"    # registry host of instance A
REGB="http://dtf-regb:5000"    # registry host of instance B
BASE_FILES=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml"
            -f "${DTF_DIR}/profiles/scanners.trivy.yml" -f "${FX}/trivy-server.yml")
REPORT_MIME='application/vnd.security.vulnerability.report; version=1.1'
MANIFEST_MIME='application/vnd.oci.image.manifest.v1+json'

setup_workdir
W="$WORK_DIR"
require_cmd python3

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# The trivy server and the mock registry are started with `docker run`; the
# harness' per-tier teardown does not know them, so remove them (by name) on
# every exit path.
cleanup(){ docker rm -f "$REG" "$SRV" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# recreate_adapter [extra overlay...]: recreate the adapter with the overlays
# and wait for it to be ready (it follows the trivy server's readiness).
recreate_adapter(){
  local files=("${BASE_FILES[@]}") f
  for f in "$@"; do files+=(-f "$f"); done
  docker compose -p "$PROJECT" "${files[@]}" up -d --no-deps --force-recreate --wait trivy \
    >"${W}/up-trivy.log" 2>&1 || { echo "failed: $(tail -3 "${W}/up-trivy.log" | tr '\n' ' ' | head -c 300)"; return; }
  local t=0
  while [ "$t" -lt 120 ]; do
    curl -sf --max-time 5 "${ADAPTER_URL}/probe/ready" >/dev/null 2>&1 && { echo up; return; }
    sleep 2; t=$((t+2))
  done
  echo "failed: adapter not ready within 120s: $(docker logs --tail 5 "$ADAPTER" 2>&1 | tr '\n' ' ' | head -c 300)"
}
adapter_env(){ docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$ADAPTER" 2>/dev/null | grep "^$1=" | cut -d= -f2-; }

# mkimg <repo> <args...>: build an image into the registry data dir; echoes
# "<manifest digest> <layer digest> <diff id> <bytes>".
mkimg(){ local repo="$1"; shift; python3 -I "$FX/mkimage.py" "$W/regdata" "$repo" v1 "$@"; }

# submit <registry url> <repo> -> HTTP code; the job id goes to $W/submit.out
submit(){
  local body
  body="$(printf '{"registry":{"url":"%s"},"artifact":{"repository":"%s","tag":"v1","mime_type":"%s"}}' "$1" "$2" "$MANIFEST_MIME")"
  curl -s --max-time 30 -o "$W/submit.out" -w '%{http_code}' -X POST "${ADAPTER_URL}/api/v1/scan" \
    -H 'Content-Type: application/json' -d "$body" 2>/dev/null || echo 000
}
# scan_count <registry url> <repo>: vulnerability count of the finished scan,
# or ERR:<detail>.
scan_count(){
  local code id t=0
  code="$(submit "$1" "$2")"
  [ "$code" = 202 ] || { echo "ERR:submit ${code} $(head -c 200 "$W/submit.out")"; return; }
  id="$(jq -r '.id // empty' "$W/submit.out" 2>/dev/null)"
  [ -n "$id" ] || { echo "ERR:no job id"; return; }
  while [ "$t" -lt 300 ]; do
    code="$(curl -s --max-time 30 -o "$W/report.json" -w '%{http_code}' -H "Accept: ${REPORT_MIME}" \
      "${ADAPTER_URL}/api/v1/scan/${id}/report" 2>/dev/null || echo 000)"
    case "$code" in
      200) jq -r '(.vulnerabilities // []) | length' "$W/report.json" 2>/dev/null || echo "ERR:bad report"; return ;;
      302|000) sleep 1; t=$((t+1)) ;;
      *) echo "ERR:report ${code} $(head -c 200 "$W/report.json")"; return ;;
    esac
  done
  echo "ERR:report not ready in 300s"
}
is_num(){ [[ "$1" =~ ^[0-9]+$ ]]; }
meta_mode(){ curl -s --max-time 15 "${ADAPTER_URL}/api/v1/metadata" 2>/dev/null \
  | jq -r '.properties["env.SCANNER_TRIVY_CACHE_PARTITION_MODE"] // "absent"' 2>/dev/null; }

begin_suite "scanner-adapter-cache-partition"

# =============================================================================
begin_test "setup: shared trivy server, two registry hosts, genuine and forged images, adapter in client mode"
reset_case
SFX="$(printf '%s' "${RUN_ID##*-}" | tr -cd '0-9' | tail -c 8)"
# Three genuine images with distinct layers (a fresh cache key per case) and,
# for two of them, a forged image whose single layer holds no packages but
# whose config claims the genuine layer's diff ID.
read -r _ _ _ _ <<<"$(mkimg "genuine/base" --mark "base-${SFX}")"
read -r _ _ G1_DIFF _ <<<"$(mkimg "genuine/app1" --mark "app1-${SFX}")"
read -r _ _ G2_DIFF _ <<<"$(mkimg "genuine/app2" --mark "app2-${SFX}")"
mkimg "forged/app1" --claim-diff-id "$G1_DIFF" >/dev/null
mkimg "forged/app2" --claim-diff-id "$G2_DIFF" >/dev/null
[ -n "${G1_DIFF:-}" ] && [ -n "${G2_DIFF:-}" ] || fail_g "mkimage.py did not build the images"
note "genuine diff ids claimed by the forged images: app1 ${G1_DIFF:-?} app2 ${G2_DIFF:-?}"

cleanup
docker run -d --name "$REG" --network "$NET" --network-alias dtf-rega --network-alias dtf-regb \
  --security-opt label=disable -v "${FX}/ocireg.py:/app/ocireg.py:ro" \
  "$REG_IMAGE" python3 /app/ocireg.py >/dev/null 2>"$W/reg.err" || fail_g "start mock registry: $(head -c 300 "$W/reg.err")"
docker cp "$W/regdata/." "${REG}:/data/" >/dev/null 2>&1 || fail_g "copy images into the mock registry"
docker run -d --name "$SRV" --network "$NET" --network-alias dtf-trivysrv \
  -e TRIVY_DB_REPOSITORY="${TRIVY_DB_REPOSITORY:-ghcr.io/aquasecurity/trivy-db:2}" \
  -e TRIVY_USERNAME="${TRIVY_USERNAME:-}" -e TRIVY_PASSWORD="${TRIVY_PASSWORD:-}" \
  --entrypoint trivy "$TRIVY_SERVER_IMAGE" server --listen 0.0.0.0:4954 >/dev/null 2>"$W/srv.err" \
  || fail_g "start trivy server: $(head -c 300 "$W/srv.err")"
ready=0
for _ in $(seq 1 90); do
  docker logs "$SRV" 2>&1 | grep -q "Listening 0.0.0.0:4954" && { ready=1; break; }
  sleep 2
done
[ "$ready" = 1 ] || fail_g "trivy server not listening within 180s (it downloads the vuln DB from ${TRIVY_DB_REPOSITORY:-ghcr.io/aquasecurity/trivy-db:2}): $(docker logs --tail 5 "$SRV" 2>&1 | tr '\n' ' ' | head -c 300)"
r="$(recreate_adapter)"; [ "$r" = up ] || fail_g "recreate adapter in client mode: $r"
[ "$(adapter_env SCANNER_TRIVY_SERVER)" = "http://dtf-trivysrv:4954" ] || fail_g "adapter does not carry SCANNER_TRIVY_SERVER"
[ -z "$(adapter_env SCANNER_TRIVY_CACHE_PARTITION_MODE)" ] || fail_g "adapter carries SCANNER_TRIVY_CACHE_PARTITION_MODE in the default-mode setup"
finish_case "setup failed"
[ "$FAILS" -eq 0 ] || end_suite

# =============================================================================
begin_test "CONTROL: default (static) mode: a genuine image scanned on a fresh cache key reports its vulnerabilities, and metadata adds no partition-mode property"
reset_case
BASE_N="$(scan_count "$REGB" genuine/base)"
mode="$(meta_mode)"
note "genuine/base via ${REGB}: ${BASE_N} vulnerabilities; metadata partition-mode property: ${mode}"
is_num "$BASE_N" && [ "$BASE_N" -ge 1 ] || fail_g "genuine image -> '${BASE_N}', expected >= 1 vulnerabilities (libcrypto1.1 1.1.1c-r0)"
[ "$mode" = absent ] || fail_g "metadata reports partition mode '${mode}' in the default mode, expected no property (the metadata document is unchanged)"
finish_case "a genuine image does not scan normally in the default mode"

# =============================================================================
begin_test "CONTROL: default (static) mode is unchanged: one partition for every registry host, and a request without a registry host is still accepted"
reset_case
F1="$(scan_count "$REGA" forged/app1)"
G1="$(scan_count "$REGB" genuine/app1)"
code="$(submit "" genuine/app1)"
note "static mode: forged/app1 via ${REGA}: ${F1}; then genuine/app1 via ${REGB}: ${G1} (fresh-key count: ${BASE_N})"
note "static mode: POST /api/v1/scan with an empty registry.url -> ${code}"
[ "$F1" = 0 ] || fail_g "forged image -> '${F1}', expected 0 (its layer holds no packages)"
# In static mode the second host reuses the first host's analysis of the
# claimed layer: this is the documented single-partition behaviour that an
# adapter shared by several instances must opt out of with registry mode.
[ "$G1" = 0 ] || fail_g "genuine/app1 after the forged image -> '${G1}', expected 0: static mode keeps one shared partition, as before (a change here changes the default)"
[ "$code" = 202 ] || fail_g "static mode refused a request without a registry host (${code}), expected 202 as before"
finish_case "the default static partition behaviour changed"

# =============================================================================
begin_test "FIX #5943: SCANNER_TRIVY_CACHE_PARTITION_MODE=registry is applied and reported in the adapter metadata"
reset_case
r="$(recreate_adapter "${FX}/registry-mode.yml")"; [ "$r" = up ] || fail_g "recreate adapter in registry mode: $r"
[ "$(adapter_env SCANNER_TRIVY_CACHE_PARTITION_MODE)" = registry ] || fail_g "adapter does not carry SCANNER_TRIVY_CACHE_PARTITION_MODE=registry"
mode="$(meta_mode)"
logline="$(docker logs "$ADAPTER" 2>&1 | grep -i 'partition mode' | tail -1)"
note "metadata partition-mode property: ${mode}"
note "startup log: ${logline:-none}"
[ "$mode" = registry ] || fail_g "metadata partition-mode property '${mode}', expected 'registry' (pre-fix: the variable is ignored)"
if printf '%s' "$(curl -s --max-time 15 "${ADAPTER_URL}/api/v1/metadata")${logline}" | grep -q 'dtf|'; then
  fail_g "the metadata or the startup log shows a partition value"
fi
finish_case "registry partition mode is not applied"

# =============================================================================
begin_test "FIX #5943: in registry mode a forged image on one registry host does not poison the genuine image's scan on another host"
reset_case
F2="$(scan_count "$REGA" forged/app2)"
G2="$(scan_count "$REGB" genuine/app2)"
note "registry mode: forged/app2 via ${REGA}: ${F2}; then genuine/app2 via ${REGB}: ${G2} (fresh-key count: ${BASE_N})"
[ "$F2" = 0 ] || fail_g "forged image -> '${F2}', expected 0"
is_num "$G2" || fail_g "genuine/app2 scan error: ${G2}"
if is_num "$G2" && [ "$G2" -eq 0 ]; then
  fail_g "genuine/app2 via ${REGB} reported 0 vulnerabilities: a false clean, the forged image's analysis from ${REGA} was reused (pre-fix behaviour)"
fi
is_num "$G2" && is_num "$BASE_N" && [ "$G2" -ne "$BASE_N" ] && fail_g "genuine/app2 reported ${G2}, expected the same ${BASE_N} as on a fresh cache key"
finish_case "a registry host's cached layer analysis is reused for another host"

# =============================================================================
begin_test "FIX #5943: in registry mode a scan request without a registry host is refused with 400"
reset_case
code="$(submit "" genuine/app2)"
note "registry mode: POST /api/v1/scan with an empty registry.url -> ${code} $(head -c 150 "$W/submit.out")"
[ "$code" = 400 ] || fail_g "empty registry.url -> ${code}, expected 400 (pre-fix: 202, scanned in the shared partition)"
code="$(submit "http://" genuine/app2)"
note "registry mode: POST /api/v1/scan with registry.url 'http://' -> ${code}"
[ "$code" = 400 ] || fail_g "scheme-only registry.url -> ${code}, expected 400"
finish_case "a request with no registry host is not refused in registry mode"

cleanup
end_suite
