#!/usr/bin/env bash
# =============================================================================
# tiers/scanner-adapter-java-db/oracle.sh
#   #5913 concurrent first JAR scans no longer race on trivy's on-demand Java
#         DB download, and an image without JARs still scans when the Java DB
#         cannot be fetched
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
BASE_FILES=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml"
            -f "${DTF_DIR}/profiles/scanners.trivy.yml")
CACHE=/home/scanner/.cache/trivy
SCAN_WAIT=300
JAR_SCAN_WAIT=900  # first JAR scans include the ~1 GiB Java DB download
CONCURRENT=3

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
REPO="sajd${DTF_SLOT}-${SFX}"
REG_TOKEN=""

# recreate_adapter [overlay]: recreate the adapter, with the overlay file if
# given, and wait for it to be healthy. Prints "up" or the failure.
recreate_adapter(){
  local files=("${BASE_FILES[@]}")
  [ -n "${1:-}" ] && files+=(-f "$1")
  docker compose -p "$PROJECT" "${files[@]}" up -d --no-deps --force-recreate --wait trivy \
    >"${W}/up-trivy.log" 2>&1 && { echo up; return; }
  echo "failed: $(tail -3 "${W}/up-trivy.log" | tr '\n' ' ' | head -c 300)"
}
adapter_env(){ docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$ADAPTER" 2>/dev/null | grep "^$1=" | cut -d= -f2-; }
adapter_ready(){ curl -sf --max-time 5 "${ADAPTER_URL}/probe/ready" >/dev/null 2>&1; }
wait_adapter_ready(){ local t=0; while [ "$t" -lt 120 ] && ! adapter_ready; do sleep 1; t=$((t+1)); done; adapter_ready; }
java_db_present(){ docker exec "$ADAPTER" sh -c "test -s ${CACHE}/java-db/metadata.json" >/dev/null 2>&1; }
drop_java_db(){ docker exec "$ADAPTER" sh -c "rm -rf ${CACHE}/java-db ${CACHE}/.java-db-*" >/dev/null 2>&1; }

# push_image <name> <tag> [jar]: build a unique image and push it; echoes the
# manifest artifact id (empty on failure).
push_image(){
  local name="$1" tag="$2" d="$W/img-$1" dg ldg cdg loc code
  dg="$(python3 -I "$FX/mkimage.py" "$d" "${REPO}-${name}" 0 "${3:-}")" || return 0
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
  curl -s --max-time 30 -o "$W/trig-$1.out" -w '%{http_code}' -X POST "${BASE_URL}/api/v1/security/scan" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"artifact_id\":\"$1\",\"bypass_dedup\":true}" || echo 000
}
image_rows(){ psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='image'"; }
# image_row <artifact_id>: "status|findings|error" of the latest image scan
image_row(){
  psqlq "SELECT status||'|'||findings_count||'|'||COALESCE(left(regexp_replace(error_message, '\s+', ' ', 'g'),2000),'')
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
# scan_one <artifact_id> <timeout>: trigger, wait, echo the row
scan_one(){
  local c
  c="$(trigger "$1")"
  [ "$c" = 200 ] || { echo "trigger|0|HTTP ${c} $(head -c 200 "$W/trig-$1.out")"; return; }
  wait_settled "$1" "$2" || true
  image_row "$1"
}

begin_suite "scanner-adapter-java-db"
auth_admin

# =============================================================================
begin_test "setup: docker repository, warm Trivy vulnerability DB, empty Java DB cache"
reset_case
create_repo "$REPO" docker local || fail_g "create docker repository ${REPO}"
REG_TOKEN="$(curl -s --max-time 30 -u "${ADMIN_USER:-admin}:${ADMIN_PASS}" "${BASE_URL}/v2/token" | jqr '.token // .access_token // empty')"
[ -n "$REG_TOKEN" ] || fail_g "no registry token from /v2/token"
wait_adapter_ready || fail_g "adapter not ready on ${ADAPTER_URL}"
warmed=0
for attempt in 1 2 3 4 5; do
  if docker exec "$ADAPTER" sh -c "trivy image --cache-dir ${CACHE} --download-db-only --no-progress" >/dev/null 2>&1; then
    warmed=1; break
  fi
  echo "   DB warm attempt ${attempt}/5 failed; retrying in 5s"; sleep 5
done
[ "$warmed" = 1 ] || fail_g "could not download the Trivy DB in ${ADAPTER} (ghcr.io/aquasecurity/trivy-db)"
A_PLAIN="$(push_image plain v1)"
A_JAR0="$(push_image jar0 v1 jar)"
A_JARS=()
for i in $(seq 1 "$CONCURRENT"); do A_JARS+=("$(push_image "jar${i}" v1 jar)"); done
A_AFTER="$(push_image jarafter v1 jar)"
for a in "$A_PLAIN" "$A_JAR0" "${A_JARS[@]}" "$A_AFTER"; do [ -n "$a" ] || fail_g "an image push failed"; done
finish_case "setup failed"
[ "$FAILS" -eq 0 ] || end_suite

# =============================================================================
begin_test "CONTROL: Java DB unreachable with SCANNER_TRIVY_SKIP_DB_UPDATE=true: an image with no JAR still scans to completion"
reset_case
r="$(recreate_adapter "${FX}/java-db-unreachable.yml")"; [ "$r" = up ] || fail_g "recreate adapter: $r"
wait_adapter_ready || fail_g "adapter not ready after the recreate"
[ "$(adapter_env SCANNER_TRIVY_SKIP_DB_UPDATE)" = true ] || fail_g "adapter does not carry SCANNER_TRIVY_SKIP_DB_UPDATE=true"
drop_java_db
java_db_present && fail_g "a Java DB is already in the adapter cache; the case proves nothing"
row="$(scan_one "${A_PLAIN:-none}" "$SCAN_WAIT")"
note "image without a JAR: status|findings|error = ${row:-none}"
[ "${row%%|*}" = completed ] || fail_g "image scan '${row}', expected completed (an image without JARs never needs the Java DB)"
f="$(echo "$row" | cut -d'|' -f2)"
[ "${f:-0}" -ge 1 ] 2>/dev/null || fail_g "image scan reported ${f:-no} findings, expected libcrypto1.1's CVEs"
finish_case "an image without JARs failed because the Java DB could not be fetched"

# =============================================================================
begin_test "CONTROL: same adapter: an image with a JAR fails closed, naming the Java DB"
reset_case
row="$(scan_one "${A_JAR0:-none}" "$SCAN_WAIT")"
note "image with a JAR: status|findings|error = ${row:-none}"
[ "${row%%|*}" = failed ] || fail_g "image scan '${row}', expected failed (trivy cannot analyze a JAR without the Java DB; never completed with 0 findings)"
echo "$row" | grep -qi "java db" || fail_g "the error does not name the Java DB"
finish_case "a JAR image without a reachable Java DB did not fail closed"

# =============================================================================
begin_test "FIX #5913: ${CONCURRENT} concurrent first scans of images with a JAR, adapter /tmp limited to 3 GiB, all complete with one Java DB download"
reset_case
# Empty the Java DB cache in the old container: the new adapter starts its
# download as soon as it is up, into the same volume.
drop_java_db
java_db_present && fail_g "could not empty the Java DB cache"
r="$(recreate_adapter "${FX}/tmp-limit.yml")"; [ "$r" = up ] || fail_g "recreate adapter: $r"
wait_adapter_ready || fail_g "adapter not ready after the recreate"
[ -z "$(adapter_env SCANNER_TRIVY_SKIP_DB_UPDATE)" ] || fail_g "adapter still carries SCANNER_TRIVY_SKIP_DB_UPDATE"
[ -z "$(adapter_env TRIVY_JAVA_DB_REPOSITORY)" ] || fail_g "adapter still carries the unreachable TRIVY_JAVA_DB_REPOSITORY"
tmpcap="$(docker exec "$ADAPTER" df -m /tmp 2>/dev/null | awk 'NR==2{print $2}')"
note "adapter /tmp size: ${tmpcap:-?} MiB"
[ -n "$tmpcap" ] && [ "$tmpcap" -le 3200 ] 2>/dev/null || fail_g "the adapter's /tmp is not the 3 GiB tmpfs from fixtures/tmp-limit.yml"
for a in "${A_JARS[@]}"; do
  c="$(trigger "${a:-none}")"
  [ "$c" = 200 ] || fail_g "trigger ${a:-none} -> ${c}"
done
completed=0
for a in "${A_JARS[@]}"; do
  wait_settled "${a:-none}" "$JAR_SCAN_WAIT" || true
  row="$(image_row "${a:-none}")"
  note "JAR image ${a:-none}: status|findings|error = ${row:-none}"
  if [ "${row%%|*}" = completed ]; then
    completed=$((completed+1))
    f="$(echo "$row" | cut -d'|' -f2)"
    [ "${f:-0}" -ge 1 ] 2>/dev/null || fail_g "JAR image ${a} completed with ${f:-no} findings, expected CVEs"
  fi
done
[ "$completed" = "$CONCURRENT" ] || fail_g "${completed} of ${CONCURRENT} concurrent first JAR scans completed (pre-fix: every trivy process downloads the Java DB itself, staging ~1.9 GiB each in /tmp and unpacking over the others in <cache>/java-db: 'no space left on device' or 'chmod .../java-db/trivy-java.db: no such file or directory')"
java_db_present || fail_g "no Java DB in the adapter cache after the scans"
downloads="$(docker logs "$ADAPTER" 2>&1 | grep -c 'downloading the trivy Java DB')"
note "Java DB downloads logged by the adapter: ${downloads}"
[ "$downloads" = 1 ] || fail_g "the adapter logged ${downloads} Java DB downloads, expected exactly 1 (pre-fix: none, every trivy process downloads on its own)"
leftovers="$(docker exec "$ADAPTER" sh -c "ls -d ${CACHE}/.java-db-* 2>/dev/null | wc -l" 2>/dev/null | tr -d ' ')"
[ "${leftovers:-0}" = 0 ] || fail_g "${leftovers} Java DB staging directories left in the cache"
finish_case "concurrent first JAR scans race on the Java DB download"

# =============================================================================
begin_test "CONTROL: a JAR image scanned afterwards completes with the Java DB in place"
reset_case
before="$(docker logs "$ADAPTER" 2>&1 | grep -c 'downloading the trivy Java DB')"
row="$(scan_one "${A_AFTER:-none}" "$SCAN_WAIT")"
after="$(docker logs "$ADAPTER" 2>&1 | grep -c 'downloading the trivy Java DB')"
note "JAR image: status|findings|error = ${row:-none}; Java DB downloads logged before/after: ${before}/${after}"
[ "${row%%|*}" = completed ] || fail_g "image scan '${row}', expected completed"
[ "$before" = "$after" ] || fail_g "the Java DB was downloaded again for a later scan"
finish_case "a later JAR scan did not reuse the Java DB"

end_suite
