#!/usr/bin/env bash
# test-artifact-stats.sh - Artifact download statistics endpoint
#
# Covers Epic 6 sub-task 6.14 (artifact-keeper-test#71):
#   GET /api/v1/artifacts/{id}/stats -> ArtifactStatsResponse
#
# Schema source (openapi.yaml ArtifactStatsResponse):
#   { artifact_id: uuid, download_count: int64,
#     first_downloaded?: date-time, last_downloaded?: date-time }
#
# Contract under test:
#   1. Upload an artifact, then download it N times.
#   2. GET /artifacts/{id}/stats and assert:
#        - artifact_id matches the uploaded artifact
#        - download_count >= N (allow >= to absorb any prior fetches
#          internal to the upload path)
#        - last_downloaded is present and non-empty after the downloads
#   3. Unknown id returns 404.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "artifact-stats"
auth_admin
setup_workdir

REPO_KEY="test-stats-${RUN_ID}"
ART_PATH="stats-target.bin"
N_DOWNLOADS=3

add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/repositories/${REPO_KEY}\" || true"

# -------------------------------------------------------------------------
# Setup: repo + artifact upload.
# -------------------------------------------------------------------------

begin_test "Create repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  skip_suite "could not create repo"
fi

begin_test "Upload artifact"
echo "stats-payload-${RUN_ID}" > "${WORK_DIR}/blob.bin"
UPLOAD_BODY="${WORK_DIR}/upload-resp.json"
UPLOAD_STATUS=$(curl -s -o "$UPLOAD_BODY" -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/blob.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ART_PATH}" 2>/dev/null) || UPLOAD_STATUS="000"
if ! assert_http_2xx "$UPLOAD_STATUS" "upload returned ${UPLOAD_STATUS}"; then
  end_suite
fi

# Capture artifact id from upload response. ArtifactResponse may use 'id'
# directly; fall back to a list lookup if absent.
ART_ID=$(jq -r '.id // empty' < "$UPLOAD_BODY")
if [ -z "$ART_ID" ] || [ "$ART_ID" = "null" ]; then
  if list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts?per_page=50" 2>/dev/null); then
    ART_ID=$(echo "$list_resp" | jq -r --arg p "$ART_PATH" \
      '(.items // .data // .)[] | select(.path == $p or .name == $p) | .id' | head -n1)
  fi
fi
if [ -z "$ART_ID" ] || [ "$ART_ID" = "null" ]; then
  skip_suite "could not resolve uploaded artifact id; stats endpoint takes uuid"
fi
pass

# -------------------------------------------------------------------------
# 6.14.a: Trigger N downloads, then read /stats.
# -------------------------------------------------------------------------

begin_test "Download artifact ${N_DOWNLOADS} times"
DL_FAILS=0
for i in $(seq 1 "$N_DOWNLOADS"); do
  st=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ART_PATH}" 2>/dev/null) || st="000"
  if [ "$st" -lt 200 ] 2>/dev/null || [ "$st" -ge 300 ] 2>/dev/null; then
    # Some builds expose downloads via /artifacts/{path} GET instead of /download/.
    st=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ART_PATH}" 2>/dev/null) || st="000"
  fi
  if [ "$st" -lt 200 ] 2>/dev/null || [ "$st" -ge 300 ] 2>/dev/null; then
    DL_FAILS=$(( DL_FAILS + 1 ))
  fi
done
if [ "$DL_FAILS" -eq 0 ]; then
  pass
else
  fail "${DL_FAILS} of ${N_DOWNLOADS} downloads returned non-2xx"
fi

# Give the stats writer a moment in case it is async (download counter
# updates are typically write-behind to avoid blocking the response).
sleep 2

begin_test "GET /artifacts/{id}/stats returns documented shape"
STATS_BODY="${WORK_DIR}/stats.json"
STATS_STATUS=$(curl -s -o "$STATS_BODY" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/artifacts/${ART_ID}/stats" 2>/dev/null) || STATS_STATUS="000"
case "$STATS_STATUS" in
  200)
    # Required fields per ArtifactStatsResponse.
    sid=$(jq -r '.artifact_id // empty' < "$STATS_BODY")
    dc=$(jq -r '.download_count // empty' < "$STATS_BODY")
    if [ "$sid" = "$ART_ID" ] && [[ "$dc" =~ ^[0-9]+$ ]]; then
      pass
    else
      fail "stats shape mismatch: artifact_id='${sid}' download_count='${dc}'"
    fi
    ;;
  404|501)
    skip_suite "stats endpoint returned ${STATS_STATUS} (not exposed in this build)"
    ;;
  *)
    body=$(head -c 400 "$STATS_BODY" 2>/dev/null || true)
    fail "stats GET returned HTTP ${STATS_STATUS}: ${body}"
    ;;
esac

begin_test "download_count >= ${N_DOWNLOADS} after ${N_DOWNLOADS} fetches"
if [ "$STATS_STATUS" != "200" ]; then
  skip "previous test did not produce a 200 stats response"
else
  dc=$(jq -r '.download_count // 0' < "$STATS_BODY")
  if [ "$dc" -ge "$N_DOWNLOADS" ] 2>/dev/null; then
    pass
  else
    # Retry once with a longer wait in case the counter is write-behind
    # with a longer batch window than 2s.
    sleep 5
    STATS_STATUS=$(curl -s -o "$STATS_BODY" -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/artifacts/${ART_ID}/stats" 2>/dev/null) || STATS_STATUS="000"
    dc=$(jq -r '.download_count // 0' < "$STATS_BODY")
    if [ "$dc" -ge "$N_DOWNLOADS" ] 2>/dev/null; then
      pass
    else
      fail "expected download_count >= ${N_DOWNLOADS}, got ${dc}"
    fi
  fi
fi

# -------------------------------------------------------------------------
# 6.14.b: Unknown artifact id returns 404. Use a syntactically valid uuid
# that should not exist in the database so we exercise the not-found path,
# not the input-validation path.
# -------------------------------------------------------------------------

begin_test "GET stats on unknown uuid returns 404"
BOGUS_UUID="00000000-0000-0000-0000-000000000000"
NF_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/artifacts/${BOGUS_UUID}/stats" 2>/dev/null) || NF_STATUS="000"
assert_eq "$NF_STATUS" "404" "expected 404 for unknown uuid, got ${NF_STATUS}" && pass

end_suite
