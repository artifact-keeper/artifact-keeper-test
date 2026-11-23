#!/usr/bin/env bash
# =============================================================================
# tiers/ops-log-noise-1130/oracle.sh: fresh-install, upload and GC log noise,
#   generic health grades and ak_build_info (artifact-keeper#5656)
# =============================================================================
# run.sh has stood up filesystem + logging.json-file on a fresh database and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BACKEND_CTR="${DB_CONTAINER%-db}-backend"
SUF="${RUN_ID##*-}$$"
REPO="noise-gen-${SUF}"
UPLOADS=5
WORK="$(mktemp -d -t dtf-noise-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

backend_log() { docker logs ${1:+--since "$1"} "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
count() { grep -c "$1" || true; }

begin_suite "ops-log-noise-1130"

begin_test "setup: admin login and a generic repository"
auth_admin
if ! create_local_repo "$REPO" generic >/dev/null 2>&1; then
  infra_fail "could not create generic repository ${REPO}"; end_suite
fi
pass

# =============================================================================
# Fresh install
# =============================================================================
BOOT="$(backend_log)"
NOTICES="$(count 'sqlx::postgres::notice' <<<"$BOOT")"
SKIPPING="$(count 'does not exist, skipping' <<<"$BOOT")"
STARTED="$(count 'Background schedulers started' <<<"$BOOT")"
echo "  fresh install: ${NOTICES} postgres notice line(s) (${SKIPPING} 'does not exist, skipping'), 'Background schedulers started' x${STARTED}, $(wc -l <<<"$BOOT" | tr -d ' ') lines" >&2

begin_test "FIX #5656: a fresh install logs no Postgres NOTICE lines"
if [ "$NOTICES" = "0" ]; then
  pass
else
  fail "${NOTICES} sqlx::postgres::notice lines on a fresh install" "$(grep 'sqlx::postgres::notice' <<<"$BOOT" | head -3 | cut -c1-300)"
fi

begin_test "FIX #5656: 'Background schedulers started' is logged once"
if [ "$STARTED" = "1" ]; then pass; else fail "logged ${STARTED} times"; fi

# =============================================================================
# Uploads
# =============================================================================
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1
IDS=()
UP_EV=""
for i in $(seq 1 "$UPLOADS"); do
  head -c 4096 /dev/urandom > "${WORK}/f$i.bin"
  code="$(curl -s -m 30 -X PUT -H "$(auth_header)" -H 'Content-Type: application/octet-stream' \
    --data-binary "@${WORK}/f$i.bin" -o "${WORK}/up$i.json" -w '%{http_code}' \
    "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/noise/f$i.bin" 2>/dev/null)"
  id="$(jq -r '.id // empty' "${WORK}/up$i.json" 2>/dev/null)"
  UP_EV+="f$i=${code}:${id:0:8} "
  [ -n "$id" ] && IDS+=("$id")
done
if [ "${#IDS[@]}" != "$UPLOADS" ]; then infra_fail "uploads did not all succeed" "$UP_EV"; end_suite; fi
# The quality check runs in the background after each upload.
HEALTH_EV=""
HAVE=0; RATED=0
for _ in $(seq 1 15); do
  HAVE=0; RATED=0; HEALTH_EV=""
  for id in "${IDS[@]}"; do
    body="$(curl -s -m 10 -H "$(auth_header)" "${BASE_URL}/api/v1/quality/health/artifacts/${id}" 2>/dev/null)"
    # A health row exists once the check ran; an unscanned generic file has
    # no component score, so it is unrated: null score, grade and metadata.
    present="$(jq -r 'has("artifact_id")' <<<"$body" 2>/dev/null)"
    g="$(jq -r '.health_grade // "null"' <<<"$body" 2>/dev/null)"
    sc="$(jq -r '.health_score // "null"' <<<"$body" 2>/dev/null)"
    m="$(jq -r '.metadata_score // "null"' <<<"$body" 2>/dev/null)"
    HEALTH_EV+="${id:0:8}=score:${sc}/grade:${g}/meta:${m} "
    [ "$present" = "true" ] && HAVE=$((HAVE + 1))
    [ "$present" = "true" ] && { [ "$g" != "null" ] || [ "$sc" != "null" ] || [ "$m" != "null" ]; } && RATED=$((RATED + 1))
  done
  [ "$HAVE" = "$UPLOADS" ] && break
  sleep 2
done
sleep 2
ULOG="$(backend_log "$T0")"
QLINES="$(grep -E 'Quality check completed|Artifact health score recalculated' <<<"$ULOG" | count 'INFO')"
echo "  uploads: ${UP_EV}; health: ${HEALTH_EV}; quality INFO lines: ${QLINES}" >&2

begin_test "CONTROL: every upload's quality check ran (a health score exists for each)"
if [ "$HAVE" = "$UPLOADS" ]; then pass; else fail "health scores for ${HAVE}/${UPLOADS} uploads" "$HEALTH_EV"; fi

begin_test "FIX #5656: ${UPLOADS} uploads log no quality-check INFO line"
if [ "$QLINES" = "0" ]; then
  pass
else
  fail "${QLINES} quality-check INFO lines for ${UPLOADS} uploads" "$(grep -E 'Quality check completed|Artifact health score recalculated' <<<"$ULOG" | head -2 | cut -c1-300)"
fi

begin_test "FIX #5656: unscanned generic artifacts are unrated (null score, grade and metadata score), not graded F"
if [ "$HAVE" = "$UPLOADS" ] && [ "$RATED" = "0" ]; then
  pass
else
  fail "generic artifacts graded on package metadata" "$HEALTH_EV"
fi

# =============================================================================
# Storage GC summary
# =============================================================================
T1="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1
GC_CODE="$(curl -s -m 120 -X POST -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d '{"dry_run": false}' -o "${WORK}/gc.json" -w '%{http_code}' "${BASE_URL}/api/v1/admin/storage-gc" 2>/dev/null)"
sleep 2
GC_LINES="$(backend_log "$T1" | count 'Storage GC complete')"
echo "  storage-gc: HTTP ${GC_CODE} $(head -c 200 "${WORK}/gc.json"); summary lines: ${GC_LINES}" >&2

begin_test "FIX #5656: a live storage GC pass that finds nothing still logs a 'Storage GC complete' line"
if [ "$GC_CODE" = "200" ] && [ "${GC_LINES:-0}" -ge 1 ]; then
  pass
else
  fail "GC answered ${GC_CODE} and logged ${GC_LINES} summary lines" "$(head -c 300 "${WORK}/gc.json")"
fi

# =============================================================================
# ak_build_info
# =============================================================================
curl -s -m 15 -H "$(auth_header)" "${BASE_URL}/api/v1/admin/metrics" -o "${WORK}/metrics.txt" 2>/dev/null
BI="$(grep -E '^ak_build_info\{' "${WORK}/metrics.txt" | head -1)"
HELP="$(grep -c '^# HELP ak_build_info ' "${WORK}/metrics.txt" || true)"
echo "  metrics: ${BI:-<no ak_build_info>} (HELP lines ${HELP})" >&2

begin_test "FIX #5656: /api/v1/admin/metrics exports ak_build_info{version,git} 1 with # HELP text"
if [[ "$BI" == *'version="'* ]] && [[ "$BI" == *' 1' ]] && [ "$HELP" = "1" ]; then
  pass
else
  fail "ak_build_info missing or malformed" "${BI:-none}"
fi

end_suite
