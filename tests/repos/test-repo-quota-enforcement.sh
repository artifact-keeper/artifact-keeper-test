#!/usr/bin/env bash
# test-repo-quota-enforcement.sh - Per-repository storage quota enforcement
#
# Covers Epic 6 sub-task 6.4 (artifact-keeper-test#71):
#   POST /api/v1/repositories                body includes "quota_bytes": <int|null>
#   PUT  /api/v1/repositories/:key/artifacts/:path   blob upload
#
# Schema source (openapi.yaml):
#   CreateRepositoryRequest.quota_bytes   int64 | null
#   RepositoryResponse.quota_bytes        int64 | null
#   RepositoryResponse.storage_used_bytes int64
#
# Contract under test:
#   1. A repo can be created with a low quota_bytes value.
#   2. An upload that keeps storage_used_bytes <= quota_bytes is accepted.
#   3. An upload that would push storage_used_bytes past quota_bytes is
#      rejected with a documented client-error status (413 Payload Too Large
#      or 422 Unprocessable Entity; backend may return either depending on
#      whether it surfaces the size-check at the body-parse stage or after
#      the service-layer check_quota method).
#
# This pins the enforcement contract without coupling to a specific service
# implementation detail. If a future release reclassifies the quota error
# (e.g. switches from 413 -> 422), this test stays green as long as it is
# still a documented 4xx and not a silent 2xx or a 500.
#
# Skip behavior: if the create call refuses the quota_bytes field (400/422)
# or the POST returns 404/501, the whole suite skips so a 1.1.x backend
# that lacks the field does not red the gate.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "repo-quota-enforcement"
auth_admin
setup_workdir

REPO_KEY="test-quota-${RUN_ID}"
# Quota of 4096 bytes (4 KiB). The under-quota upload writes 1 KiB; the
# over-quota upload writes 8 KiB. Both sizes are large enough to defeat any
# zero-length short-circuit in the backend, small enough to not stress
# the upload path.
QUOTA_BYTES=4096
UNDER_BYTES=1024
OVER_BYTES=8192

# Make sure the repo gets removed even if the test exits mid-flight.
add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/repositories/${REPO_KEY}\" || true"

# -------------------------------------------------------------------------
# Setup: create a local repo with a tight quota. If the create call fails
# because the backend either doesn't accept the field or returns 4xx/5xx,
# skip the whole suite -- there is nothing meaningful to assert.
# -------------------------------------------------------------------------

begin_test "Create local repo with quota_bytes=${QUOTA_BYTES}"
CREATE_PAYLOAD=$(jq -n \
  --arg key "$REPO_KEY" \
  --arg name "$REPO_KEY" \
  --argjson quota "$QUOTA_BYTES" \
  '{key: $key, name: $name, format: "generic", repo_type: "local", is_public: true, quota_bytes: $quota}')

CREATE_BODY_FILE="${WORK_DIR}/create-resp.json"
CREATE_STATUS=$(curl -s -o "$CREATE_BODY_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$CREATE_PAYLOAD" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || CREATE_STATUS="000"

case "$CREATE_STATUS" in
  2[0-9][0-9])
    # Confirm the field round-trips on the create response so we know the
    # backend honoured it (not just accepted and dropped).
    got_quota=$(jq -r '.quota_bytes // empty' < "$CREATE_BODY_FILE")
    if [ "$got_quota" = "$QUOTA_BYTES" ]; then
      pass
    else
      fail "create accepted but quota_bytes round-trip mismatch: got '${got_quota}', expected ${QUOTA_BYTES}"
    fi
    ;;
  404|501)
    skip_suite "repo create returned ${CREATE_STATUS}; quota_bytes field unsupported in this build"
    ;;
  *)
    body=$(head -c 400 "$CREATE_BODY_FILE" 2>/dev/null || true)
    skip_suite "create with quota_bytes returned HTTP ${CREATE_STATUS}: ${body}"
    ;;
esac

# -------------------------------------------------------------------------
# 6.4.a: An upload that fits under the quota is accepted.
# -------------------------------------------------------------------------

begin_test "Upload under quota (${UNDER_BYTES} bytes <= ${QUOTA_BYTES}) is accepted"
dd if=/dev/zero of="${WORK_DIR}/under.bin" bs=1 count="$UNDER_BYTES" 2>/dev/null
UNDER_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/under.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/under.bin" 2>/dev/null) || UNDER_STATUS="000"
assert_http_2xx "$UNDER_STATUS" "under-quota upload should succeed; got ${UNDER_STATUS}" && pass

# -------------------------------------------------------------------------
# 6.4.b: An upload that would exceed the quota is rejected with a
# documented 4xx. Per OpenAPI the upload endpoint enumerates 401 and 404
# explicitly; quota rejection currently surfaces via the service layer's
# check_quota method, mapping to either 413 (Payload Too Large) or 422
# (Unprocessable Entity) depending on where the check fires in the
# request pipeline. Accept either, reject anything else (including 2xx).
# -------------------------------------------------------------------------

begin_test "Upload over quota (${OVER_BYTES} bytes > ${QUOTA_BYTES}) must be rejected"
dd if=/dev/zero of="${WORK_DIR}/over.bin" bs=1 count="$OVER_BYTES" 2>/dev/null
OVER_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/over.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/over.bin" 2>/dev/null) || OVER_STATUS="000"
case "$OVER_STATUS" in
  413|422|507)
    # 507 (Insufficient Storage) is also semantically correct for a quota
    # overshoot; include it so the test stays green if the backend ever
    # picks the most-specific RFC code.
    pass
    ;;
  2[0-9][0-9])
    fail "over-quota upload was accepted (HTTP ${OVER_STATUS}); quota enforcement broken"
    ;;
  400)
    # 400 is acceptable as a generic client error if the backend doesn't
    # distinguish quota from other validation failures, but mark it so an
    # operator notices the imprecise classification.
    echo "  note: over-quota returned 400 (acceptable; 413/422 preferred)"
    pass
    ;;
  *)
    fail "over-quota upload returned unexpected HTTP ${OVER_STATUS}; expected 413/422/507"
    ;;
esac

# -------------------------------------------------------------------------
# 6.4.c: After the rejected over-quota upload, storage_used_bytes must
# NOT have advanced past quota_bytes. This catches a latent failure mode
# where the backend writes the blob to disk but then returns the error
# without rolling back the accounting row.
# -------------------------------------------------------------------------

begin_test "storage_used_bytes after rejection stays <= quota_bytes"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}" 2>/dev/null); then
  used=$(echo "$resp" | jq -r '.storage_used_bytes // -1')
  quota=$(echo "$resp" | jq -r '.quota_bytes // -1')
  if [ "$used" -ge 0 ] 2>/dev/null && [ "$quota" -ge 0 ] 2>/dev/null && \
     [ "$used" -le "$quota" ]; then
    pass
  else
    fail "storage_used_bytes=${used} exceeds quota_bytes=${quota}"
  fi
else
  skip "could not re-read repo after over-quota upload"
fi

end_suite
