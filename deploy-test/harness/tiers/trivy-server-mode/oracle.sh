#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/trivy-server-mode/oracle.sh
#   #4351  with SCANNER_TRIVY_SERVER set, the scanner adapter scans as a
#          client of a `trivy server`: it keeps no vulnerability DB of its own,
#          and /probe/ready is 200 only while that server has a DB loaded and
#          runs the same trivy release as the bundled client
#   #4712  a scan against a server on another trivy release fails closed
#          ("client/server mode needs matching releases")
# The adapter under test is $SCANNER_ADAPTER_IMAGE; see the manifest.
#
# run.sh exported BASE_URL, RUN_ID, DTF_SLOT, TRIVY_PORT (the adapter's
# published :8090), SCANNER_ADAPTER_IMAGE (the manifest's), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"
: "${TRIVY_PORT:?}"; : "${SCANNER_ADAPTER_IMAGE:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

ADAPTER="http://127.0.0.1:${TRIVY_PORT}"
ADAPTER_CTR="ak-dtf${DTF_SLOT}-trivy"
NET="ak-dtf${DTF_SLOT}-net"
SRV_VOL="ak-dtf${DTF_SLOT}_trivysrv"
OTHER_VOL="ak-dtf${DTF_SLOT}_trivysrv_other"
OTHER_SRV="ak-dtf${DTF_SLOT}-trivy-server-other"
OTHER_CLI="ak-dtf${DTF_SLOT}-trivy-client-other"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$@" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

cleanup_other(){
  docker rm -f "$OTHER_SRV" "$OTHER_CLI" >/dev/null 2>&1
  docker volume rm "$OTHER_VOL" >/dev/null 2>&1
}
add_exit_handler cleanup_other

# A workspace whose requirements.txt pins a release with published CVEs.
mkdir -p "${W}/ws"
printf 'jinja2==2.10\n' > "${W}/ws/requirements.txt"
tar -C "${W}/ws" -cf "${W}/ws.tar" requirements.txt

ready_code(){ curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$1/probe/ready"; }
# fs_scan <adapter base>: submit the workspace and wait for the report.
# Sets SCAN_CODE (report status) and SCAN_BODY.
fs_scan(){
  local id i
  id="$(curl -s --max-time 30 -X POST -H 'Content-Type: application/x-tar' --data-binary "@${W}/ws.tar" "$1/api/v1/filesystem/scan" | jqr '.id // empty')"
  SCAN_CODE="000"; SCAN_BODY=""
  [ -n "$id" ] || return
  for i in $(seq 1 90); do
    SCAN_CODE="$(curl -s -o "${W}/report" -w '%{http_code}' --max-time 30 "$1/api/v1/filesystem/scan/${id}/report")"
    case "$SCAN_CODE" in 200|4??|5??) break;; esac
    sleep 2
  done
  [ "$i" -ge 1 ] || true
  SCAN_BODY="$(cat "${W}/report" 2>/dev/null)"
}
vuln_count(){ jq '[.. | objects | select(has("VulnerabilityID"))] | length' <<<"$1" 2>/dev/null || echo 0; }

begin_suite "trivy-server-mode"

# =============================================================================
begin_test "setup: the adapter and the trivy server are up and the server has loaded its DB"
CLIENT_VER="$(docker exec "$ADAPTER_CTR" trivy --version 2>/dev/null | sed -n 's/^Version: //p' | head -1)"
SRV_INFO=""
for _i in $(seq 1 60); do
  SRV_INFO="$(docker exec "$ADAPTER_CTR" wget -qO- http://trivy-server:4954/version 2>/dev/null)"
  [ -n "$(jqr '.VulnerabilityDB.UpdatedAt // empty' <<<"$SRV_INFO")" ] && break
  sleep 4
done
SRV_VER="$(jqr '.Version // empty' <<<"$SRV_INFO")"
echo "-- adapter image ${SCANNER_ADAPTER_IMAGE}: bundled trivy ${CLIENT_VER:-?}; trivy-server ${SRV_VER:-?}, DB updated $(jqr '.VulnerabilityDB.UpdatedAt // "never"' <<<"$SRV_INFO")"
[ -n "$CLIENT_VER" ] || { infra_fail "cannot read the adapter's bundled trivy version"; end_suite; }
[ -n "$(jqr '.VulnerabilityDB.UpdatedAt // empty' <<<"$SRV_INFO")" ] || { infra_fail "the trivy server never loaded a vulnerability DB (it downloads one from TRIVY_DB_REPOSITORY: this tier needs internet)"; end_suite; }
# The profile's server is meant to match the adapter (TRIVY_SERVER_IMAGE). A
# mismatch is reported, not refused: an adapter that ignores
# SCANNER_TRIVY_SERVER altogether must still be judged by the cases below.
[ "$SRV_VER" = "$CLIENT_VER" ] || echo "-- NOTE: trivy-server ${SRV_VER} != bundled ${CLIENT_VER}; set TRIVY_SERVER_IMAGE=ghcr.io/aquasecurity/trivy:${CLIENT_VER} for a server-mode adapter"
# The other trivy release, for the mismatch cases.
case "$CLIENT_VER" in 0.76.*) OTHER_VER="0.74.0";; *) OTHER_VER="0.76.0";; esac
pass

# =============================================================================
begin_test "CONTROL: the adapter becomes ready and its metadata names Trivy"
reset_case
rc=""
for _i in $(seq 1 60); do rc="$(ready_code "$ADAPTER")"; [ "$rc" = "200" ] && break; sleep 4; done
meta="$(curl -s --max-time 10 "${ADAPTER}/api/v1/metadata")"
note "/probe/ready: ${rc}; metadata scanner: $(jqr -c '.scanner // empty' <<<"$meta")"
[ "$rc" = "200" ] || fail_g "the adapter never became ready (${rc})"
[ "$(jqr '.scanner.name // empty' <<<"$meta")" = "Trivy" ] || fail_g "the adapter metadata does not name Trivy"
finish_case "the adapter does not start"

begin_test "#4351: in server mode a scan of jinja2==2.10 completes against the server's DB, and the adapter holds no DB of its own"
reset_case
fs_scan "$ADAPTER"
MAIN_REPORT="$SCAN_BODY"
local_db="$(docker exec "$ADAPTER_CTR" sh -c 'ls -d /home/scanner/.cache/trivy/db 2>/dev/null' 2>/dev/null)"
srv_dl="$(jqr '.VulnerabilityDB.DownloadedAt // empty' <<<"$SRV_INFO")"
scan_dl="$(jqr '.vulnerability_db.downloaded_at // empty' <<<"$MAIN_REPORT")"
note "scan report: ${SCAN_CODE}, $(vuln_count "$MAIN_REPORT") vulnerabilities, scanner_version=$(jqr '.scanner_version // empty' <<<"$MAIN_REPORT")"
note "adapter-local DB dir: ${local_db:-none}; server DB downloaded_at ${srv_dl:-?}; scan's vulnerability_db.downloaded_at ${scan_dl:-?}"
[ "$SCAN_CODE" = "200" ] || fail_g "the scan answered ${SCAN_CODE}: ${SCAN_BODY:0:200}"
[ "$(vuln_count "$MAIN_REPORT")" -ge 1 ] 2>/dev/null || fail_g "the scan found no vulnerability in jinja2 2.10"
[ -z "$local_db" ] || fail_g "the adapter downloaded its own vulnerability DB (${local_db})"
{ [ -n "$scan_dl" ] && [ "${scan_dl%%.*}" = "${srv_dl%%.*}" ]; } || fail_g "the scan's DB (${scan_dl:-none}) is not the trivy server's (${srv_dl:-none})"
finish_case "the adapter does not scan as a client of the trivy server"

# A second trivy server on the other release, serving a copy of the same DB
# (one trivy server holds a lock on its cache, so it cannot be shared), and a
# second adapter of the image under test pointed at it.
begin_test "#4351: an adapter whose trivy server runs another trivy release is not ready"
reset_case
cleanup_other
docker run --rm -u 0 --security-opt label=disable -v "${SRV_VOL}:/src:ro" -v "${OTHER_VOL}:/dst" \
  postgres:16-alpine sh -c 'cp -r /src/db /dst/' >/dev/null 2>&1
docker run -d --name "$OTHER_SRV" --network "$NET" -v "${OTHER_VOL}:/cache" \
  "ghcr.io/aquasecurity/trivy:${OTHER_VER}" server --listen 0.0.0.0:4954 --cache-dir /cache --skip-db-update >/dev/null 2>&1
docker run -d --name "$OTHER_CLI" --network "$NET" -p 127.0.0.1::8090 -e SCANNER_ADAPTER_ADDR=:8090 \
  -e "SCANNER_TRIVY_SERVER=http://${OTHER_SRV}:4954" "$SCANNER_ADAPTER_IMAGE" >/dev/null 2>&1
OP="$(docker port "$OTHER_CLI" 8090 2>/dev/null | head -1 | sed 's/.*://')"
OTHER="http://127.0.0.1:${OP:-0}"
oinfo=""
for _i in $(seq 1 30); do
  oinfo="$(docker exec "$ADAPTER_CTR" wget -qO- "http://${OTHER_SRV}:4954/version" 2>/dev/null)"
  [ -n "$(jqr '.VulnerabilityDB.UpdatedAt // empty' <<<"$oinfo")" ] && break
  sleep 2
done
note "other trivy server: version $(jqr '.Version // "?"' <<<"$oinfo"), DB $(jqr '.VulnerabilityDB.UpdatedAt // "none"' <<<"$oinfo")"
if [ -z "$(jqr '.VulnerabilityDB.UpdatedAt // empty' <<<"$oinfo")" ]; then
  infra_fail "the ${OTHER_VER} trivy server did not come up with the copied DB"; end_suite
fi
orc=""
for _i in $(seq 1 15); do
  orc="$(ready_code "$OTHER")"
  [ "$orc" = "200" ] || [ "$orc" = "503" ] && { sleep 3; orc="$(ready_code "$OTHER")"; break; }
  sleep 2
done
note "/probe/ready of an adapter (trivy ${CLIENT_VER}) on the trivy ${OTHER_VER} server: ${orc}; $(docker logs "$OTHER_CLI" 2>&1 | grep -m1 'not ready' | cut -c21-220)"
[ "$orc" = "503" ] || fail_g "the adapter is ready (${orc}) against a server on another trivy release"
finish_case "readiness does not reflect the trivy server's release"

begin_test "#4351/#4712: a scan through that adapter fails closed naming the release mismatch"
reset_case
fs_scan "$OTHER"
note "scan report: ${SCAN_CODE} ${SCAN_BODY:0:220}"
[ "$SCAN_CODE" != "200" ] || fail_g "the scan succeeded against a server on another trivy release ($(vuln_count "$SCAN_BODY") vulnerabilities)"
grep -q 'needs matching releases' <<<"$SCAN_BODY" || fail_g "the failure does not name the release mismatch"
finish_case "a client/server release mismatch does not fail the scan closed"

begin_test "#4712: the adapter bundles trivy 0.76.0 or later, the release the stock trivy server sidecar runs"
reset_case
note "bundled trivy ${CLIENT_VER}; this profile's default server image ghcr.io/aquasecurity/trivy:0.76.0"
version_ge "$CLIENT_VER" "0.76.0" || fail_g "the adapter bundles trivy ${CLIENT_VER}, older than the 0.76.0 server it ships with (every scan against that server fails closed)"
finish_case "the adapter and the stock trivy server are on different releases"

end_suite
