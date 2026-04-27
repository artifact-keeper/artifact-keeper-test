#!/usr/bin/env bash
# test-finding-acknowledge.sh - Finding acknowledge / suppress lifecycle E2E test
#
# Covers Epic 2 sub-task 2.2 (artifact-keeper-test#68): the
#   POST   /api/v1/security/findings/{id}/acknowledge
#   DELETE /api/v1/security/findings/{id}/acknowledge
# endpoints that ship in v1.1.9 (customer pain #2 from
# https://github.com/orgs/artifact-keeper/discussions/872).
#
# Flow:
#   1. Create a Docker/OCI repo, push a manifest, trigger a scan, wait for
#      it to complete, list findings.
#   2. POST acknowledge with {"reason": "..."} on the first finding. Assert
#      the response shows is_acknowledged=true, the reason round-trips, and
#      acknowledged_at / acknowledged_by are populated.
#   3. Re-list findings to verify the acknowledgment persisted.
#   4. DELETE acknowledge. Assert the finding reverts (is_acknowledged=false,
#      reason / acknowledged_at / acknowledged_by all cleared to null).
#   5. Verify a non-existent finding ID returns a clean 404 on both POST and
#      DELETE (no 500s).
#
# Self-test mode (EXPECT_FAILURE=1):
#   Inverts the final exit code; see test-scan-findings-list.sh.
#
# Requires: curl, jq, shasum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "finding-acknowledge"
auth_admin
setup_workdir

REPO_KEY="test-ack-${RUN_ID}"
IMAGE_NAME="ack-target"
# RUN_ID gives stronger isolation than wall-clock seconds (see findings-list).
UNIQUE_TAG="1.0.${RUN_ID}"
# 60s leaves headroom under the 120s TEST_TIMEOUT in run-suite.sh.
SCAN_TIMEOUT="${SCAN_TIMEOUT:-60}"
ACK_REASON="risk accepted by E2E test ${RUN_ID}"
ACK_REASON_2="re-acked with a different reason by ${RUN_ID}"
ARTIFACT_ID=""
SCAN_ID=""
FINDING_ID=""
SCANNER_AVAILABLE=true

# Cleanup: combined trap deletes the repo and removes the workdir. Replaces
# setup_workdir's EXIT-only trap; INT/TERM are added so SIGTERM from the
# run-suite `timeout` wrapper still triggers cleanup.
cleanup_repo() {
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split per common.sh
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
trap 'cleanup_repo; [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" 2>/dev/null || true' EXIT INT TERM

# ---------------------------------------------------------------------------
# Build a scannable OCI image (same shape as test-scan-findings-list.sh).
# ---------------------------------------------------------------------------

begin_test "Create Docker/OCI repository"
repo_resp=""
repo_payload="{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"docker\",\"repo_type\":\"local\",\"is_public\":true}"
if repo_resp=$(api_post "/api/v1/repositories" "$repo_payload"); then
  REPO_ID=$(echo "$repo_resp" | jq -r '.id // empty')
  if [ -z "$REPO_ID" ]; then
    if repo_resp=$(api_get "/api/v1/repositories/${REPO_KEY}"); then
      REPO_ID=$(echo "$repo_resp" | jq -r '.id // empty')
    fi
  fi
  if [ -n "${REPO_ID:-}" ]; then pass; else fail "could not determine repo ID"; fi
else
  fail "could not create docker repository"
fi

begin_test "Obtain registry token"
TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then TOKEN=$(echo "$token_resp" | jq -r '.token // empty'); fi
if [ -n "$TOKEN" ]; then pass; else fail "could not obtain registry token"; fi

begin_test "Upload config blob"
CONFIG_CONTENT='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},"config":{}}'
CONFIG_DIGEST="sha256:$(printf '%s' "$CONFIG_CONTENT" | shasum -a 256 | awk '{print $1}')"
CONFIG_SIZE=${#CONFIG_CONTENT}
upload_resp=$(curl -s -D "$WORK_DIR/config-headers.txt" -o /dev/null \
  -X POST -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" 2>/dev/null) || true
location=$(grep -i '^location:' "$WORK_DIR/config-headers.txt" 2>/dev/null | tr -d '\r' | awk '{print $2}') || true
put_status=000
if [ -n "$location" ]; then
  if [[ "$location" == http* ]]; then put_url="$location"; else put_url="${BASE_URL}${location}"; fi
  if [[ "$put_url" == *"?"* ]]; then put_url="${put_url}&digest=${CONFIG_DIGEST}"; else put_url="${put_url}?digest=${CONFIG_DIGEST}"; fi
  put_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
    -d "$CONFIG_CONTENT" "$put_url") || true
fi
if [ "$put_status" = "201" ]; then pass; else fail "config blob PUT returned ${put_status}"; fi

begin_test "Upload layer blob"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/layer.bin" 2>/dev/null
LAYER_DIGEST="sha256:$(shasum -a 256 "${WORK_DIR}/layer.bin" | awk '{print $1}')"
LAYER_SIZE=$(wc -c < "${WORK_DIR}/layer.bin" | tr -d ' ')
layer_resp=$(curl -s -D "$WORK_DIR/layer-headers.txt" -o /dev/null \
  -X POST -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" 2>/dev/null) || true
layer_loc=$(grep -i '^location:' "$WORK_DIR/layer-headers.txt" 2>/dev/null | tr -d '\r' | awk '{print $2}') || true
layer_put_status=000
if [ -n "$layer_loc" ]; then
  if [[ "$layer_loc" == http* ]]; then layer_put_url="$layer_loc"; else layer_put_url="${BASE_URL}${layer_loc}"; fi
  if [[ "$layer_put_url" == *"?"* ]]; then layer_put_url="${layer_put_url}&digest=${LAYER_DIGEST}"; else layer_put_url="${layer_put_url}?digest=${LAYER_DIGEST}"; fi
  layer_put_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/layer.bin" "$layer_put_url") || true
fi
if [ "$layer_put_status" = "201" ]; then pass; else fail "layer blob PUT returned ${layer_put_status}"; fi

begin_test "Push OCI manifest"
MANIFEST=$(cat <<EOFM
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "${CONFIG_DIGEST}", "size": ${CONFIG_SIZE} },
  "layers": [
    { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "${LAYER_DIGEST}", "size": ${LAYER_SIZE} }
  ]
}
EOFM
)
manifest_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  -d "$MANIFEST" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/manifests/${UNIQUE_TAG}") || true
if [ "$manifest_status" = "201" ] || [ "$manifest_status" = "200" ]; then pass; else fail "manifest PUT returned ${manifest_status}"; fi

# ---------------------------------------------------------------------------
# Resolve artifact_id, trigger scan, wait for completion.
# ---------------------------------------------------------------------------

begin_test "Resolve artifact_id"
list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || true
if [ -n "$list_resp" ]; then
  ARTIFACT_ID=$(echo "$list_resp" | jq -r --arg tag "$UNIQUE_TAG" --arg img "$IMAGE_NAME" '
    if type == "array" then . elif .items then .items else [] end
    | map(select(((.path // "") | contains($tag)) or ((.version // "") == $tag) or ((.name // "") | contains($img))))
    | .[0].id // empty
  ')
fi
if [ -n "$ARTIFACT_ID" ]; then pass; else fail "could not resolve artifact_id"; fi

begin_test "Trigger scan and wait for completion"
if [ -z "$ARTIFACT_ID" ]; then
  skip "no artifact_id"
else
  # Status-aware trigger: distinguish "scanner not configured" (skip) from
  # "scanner crashed / endpoint moved / 5xx" (fail). See
  # test-scan-findings-list.sh for full rationale on why we body-match on
  # HTTP 500 -- backend returns 500 for "scanner not configured" today
  # (security.rs:482); 501/503 are accepted forward-compat.
  trigger_status=$(curl -s -o "$WORK_DIR/trigger-resp.json" -w '%{http_code}' \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"artifact_id\":\"${ARTIFACT_ID}\"}" \
    "${BASE_URL}/api/v1/security/scan") || trigger_status=000
  if [ "$trigger_status" = "501" ] || [ "$trigger_status" = "503" ]; then
    SCANNER_AVAILABLE=false
    skip "scanner service not configured (HTTP ${trigger_status})"
  elif [ "$trigger_status" = "500" ] && grep -qi "scanner.*not.*configured" "$WORK_DIR/trigger-resp.json"; then
    SCANNER_AVAILABLE=false
    skip "scanner service not configured (HTTP 500, body: $(head -c 120 "$WORK_DIR/trigger-resp.json"))"
  elif [[ ! "$trigger_status" =~ ^2[0-9][0-9]$ ]]; then
    fail "POST /security/scan returned HTTP ${trigger_status} (body: $(head -c 200 "$WORK_DIR/trigger-resp.json"))"
  else
    # Allowlist terminal states. Backend writes 'running' as the in-flight
    # value (scan_result_service.rs:99); the original denylist of {pending,
    # queued, scanning, in_progress} treated 'running' as terminal and exited
    # the loop on the very first poll.
    elapsed=0
    final_status=""
    while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
      scans_resp=$(api_get "/api/v1/security/scans?artifact_id=${ARTIFACT_ID}&per_page=10" 2>/dev/null) || true
      if [ -n "$scans_resp" ]; then
        SCAN_ID=$(echo "$scans_resp" | jq -r '.items[0].id // empty')
        final_status=$(echo "$scans_resp" | jq -r '.items[0].status // empty')
        case "$final_status" in
          completed|failed|error|cancelled)
            break
            ;;
        esac
      fi
      sleep 5
      elapsed=$((elapsed + 5))
    done
    if [ -z "$SCAN_ID" ]; then
      SCANNER_AVAILABLE=false
      skip "no scan record produced for artifact within ${SCAN_TIMEOUT}s"
    else
      case "$final_status" in
        completed|failed|error|cancelled)
          pass
          ;;
        *)
          SCANNER_AVAILABLE=false
          skip "scan did not reach a terminal state within ${SCAN_TIMEOUT}s (status=${final_status:-unknown})"
          ;;
      esac
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Pick the first finding from the scan. If the scan produced 0 findings (a
# clean dummy layer), we can still exercise the 404 path against a synthetic
# UUID, but we must skip the round-trip lifecycle assertions.
# ---------------------------------------------------------------------------

begin_test "Locate a finding to acknowledge"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$SCAN_ID" ]; then
  skip "no scan_id"
else
  findings_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings?page=1&per_page=50" 2>/dev/null) || true
  FINDING_ID=$(echo "$findings_resp" | jq -r '.items[0].id // empty')
  if [ -n "$FINDING_ID" ]; then
    pass
  else
    skip "scan produced 0 findings; lifecycle assertions will be skipped"
  fi
fi

# ---------------------------------------------------------------------------
# 2.2.a -- POST acknowledge sets is_acknowledged=true and round-trips reason.
# ---------------------------------------------------------------------------

begin_test "POST acknowledge marks finding acknowledged"
if [ -z "$FINDING_ID" ]; then
  skip "no finding to acknowledge"
else
  ack_payload=$(jq -n --arg r "$ACK_REASON" '{reason: $r}')
  ack_resp=$(api_post "/api/v1/security/findings/${FINDING_ID}/acknowledge" "$ack_payload" 2>/dev/null) || true
  if [ -z "$ack_resp" ]; then
    fail "POST /findings/${FINDING_ID}/acknowledge returned empty body"
  else
    is_ack=$(echo "$ack_resp" | jq -r '.is_acknowledged // empty')
    got_reason=$(echo "$ack_resp" | jq -r '.acknowledged_reason // empty')
    ack_at=$(echo "$ack_resp" | jq -r '.acknowledged_at // empty')
    ack_by=$(echo "$ack_resp" | jq -r '.acknowledged_by // empty')
    # acknowledged_by is set to auth.user_id server-side (UUID v4). We
    # assert UUID shape to catch a regression that would put e.g. the
    # username string here, without depending on a /me lookup.
    uuid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    # acknowledged_at is server-side NOW(); must be a recent ISO 8601
    # timestamp. We don't try to parse it portably (date -d on Linux vs
    # date -j -f on macOS); we just bound the shape and require non-empty.
    iso_re='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
    if [ "$is_ack" != "true" ]; then
      fail "expected is_acknowledged=true, got '${is_ack}'"
    elif [ "$got_reason" != "$ACK_REASON" ]; then
      fail "reason did not round-trip: sent='${ACK_REASON}', got='${got_reason}'"
    elif [ -z "$ack_at" ] || [ "$ack_at" = "null" ]; then
      fail "acknowledged_at not set after POST"
    elif ! [[ "$ack_at" =~ $iso_re ]]; then
      fail "acknowledged_at='${ack_at}' is not an ISO 8601 timestamp"
    elif [ -z "$ack_by" ] || [ "$ack_by" = "null" ]; then
      fail "acknowledged_by not set after POST"
    elif ! [[ "$ack_by" =~ $uuid_re ]]; then
      fail "acknowledged_by='${ack_by}' is not a UUID (expected user_id)"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.2.b -- Acknowledgment persists in subsequent list responses.
# ---------------------------------------------------------------------------

begin_test "Acknowledgment visible in subsequent findings list"
if [ -z "$FINDING_ID" ]; then
  skip "no finding to acknowledge"
else
  list_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings?per_page=200" 2>/dev/null) || true
  is_ack=$(echo "$list_resp" | jq -r --arg fid "$FINDING_ID" '.items[]? | select(.id == $fid) | .is_acknowledged')
  got_reason=$(echo "$list_resp" | jq -r --arg fid "$FINDING_ID" '.items[]? | select(.id == $fid) | .acknowledged_reason // empty')
  if [ "$is_ack" != "true" ]; then
    fail "list view shows is_acknowledged='${is_ack}' for finding ${FINDING_ID}, expected true"
  elif [ "$got_reason" != "$ACK_REASON" ]; then
    fail "list view shows reason='${got_reason}', expected '${ACK_REASON}'"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 2.2.c -- DELETE acknowledge clears is_acknowledged + all ack metadata.
# ---------------------------------------------------------------------------

begin_test "DELETE acknowledge reverts finding to unacknowledged"
if [ -z "$FINDING_ID" ]; then
  skip "no finding to revoke"
else
  # The handler returns 200 with the updated FindingResponse on DELETE. We
  # use curl directly so we can capture the body; api_delete only returns
  # the status from -sf which discards the body on non-2xx but we want both.
  rev_status=$(curl -s -o "$WORK_DIR/revoke-resp.json" -w '%{http_code}' \
    -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/findings/${FINDING_ID}/acknowledge") || rev_status=000
  if [ "$rev_status" != "200" ]; then
    fail "DELETE /findings/${FINDING_ID}/acknowledge returned HTTP ${rev_status}"
  else
    rev_body=$(cat "$WORK_DIR/revoke-resp.json")
    is_ack=$(echo "$rev_body" | jq -r '.is_acknowledged // empty')
    # For the four ack fields, use jq -e to bind both shape AND value:
    # the field must be present in the response AND its value must be JSON
    # null. The previous `// "null"` fallback could not distinguish a
    # missing key from a literal-string "null" value or a real null, so a
    # backend that just dropped the keys (or returned a real string "null")
    # would silently pass.
    if [ "$is_ack" != "false" ]; then
      fail "expected is_acknowledged=false after revoke, got '${is_ack}'"
    elif ! echo "$rev_body" | jq -e 'has("acknowledged_reason") and .acknowledged_reason == null' > /dev/null 2>&1; then
      fail "expected acknowledged_reason=null after revoke, got '$(echo "$rev_body" | jq -c .acknowledged_reason 2>/dev/null)'"
    elif ! echo "$rev_body" | jq -e 'has("acknowledged_at") and .acknowledged_at == null' > /dev/null 2>&1; then
      fail "expected acknowledged_at=null after revoke, got '$(echo "$rev_body" | jq -c .acknowledged_at 2>/dev/null)'"
    elif ! echo "$rev_body" | jq -e 'has("acknowledged_by") and .acknowledged_by == null' > /dev/null 2>&1; then
      fail "expected acknowledged_by=null after revoke, got '$(echo "$rev_body" | jq -c .acknowledged_by 2>/dev/null)'"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.2.d -- Revoked state is reflected in subsequent list responses.
# ---------------------------------------------------------------------------

begin_test "Revoked state visible in subsequent findings list"
if [ -z "$FINDING_ID" ]; then
  skip "no finding to verify"
else
  list_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings?per_page=200" 2>/dev/null) || true
  is_ack=$(echo "$list_resp" | jq -r --arg fid "$FINDING_ID" '.items[]? | select(.id == $fid) | .is_acknowledged')
  if [ "$is_ack" != "false" ]; then
    fail "list view still shows is_acknowledged='${is_ack}' after revoke"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 2.2.e -- POST acknowledge on a non-existent finding returns 404, not 5xx.
# This is independent of scanner availability so we always run it.
# ---------------------------------------------------------------------------

begin_test "POST acknowledge on unknown finding returns 404"
fake_id="00000000-0000-0000-0000-000000000000"
ack_payload=$(jq -n '{reason: "should not exist"}')
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$ack_payload" \
  "${BASE_URL}/api/v1/security/findings/${fake_id}/acknowledge") || status=000
if [ "$status" = "404" ]; then
  pass
else
  fail "expected 404 for unknown finding, got HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 2.2.f -- DELETE acknowledge on a non-existent finding returns 404, not 5xx.
# ---------------------------------------------------------------------------

begin_test "DELETE acknowledge on unknown finding returns 404"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/security/findings/${fake_id}/acknowledge") || status=000
if [ "$status" = "404" ]; then
  pass
else
  fail "expected 404 for unknown finding revoke, got HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 2.2.g -- POST acknowledge with malformed body (missing reason) returns
# 4xx (not 5xx). Reason is required per AcknowledgeRequest.
# ---------------------------------------------------------------------------

begin_test "POST acknowledge with missing reason returns 4xx"
if [ -z "$FINDING_ID" ]; then
  # We still want to exercise input validation even without a real finding;
  # use the synthetic UUID. A 404 (no such finding) is also acceptable here
  # because route ordering in axum applies path extraction before body parse;
  # but the canonical contract is "validate body first, then look up". Either
  # way we want a 4xx.
  target_id="$fake_id"
else
  target_id="$FINDING_ID"
fi
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d '{}' \
  "${BASE_URL}/api/v1/security/findings/${target_id}/acknowledge") || status=000
if [[ "$status" =~ ^4[0-9][0-9]$ ]]; then
  pass
else
  fail "expected 4xx for missing reason, got HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 2.2.h -- POST acknowledge is idempotent: re-acking with a different reason
# overwrites the prior reason and keeps is_acknowledged=true. Pins the
# contract so a future "already acked" 409 regression is caught loudly.
# Note: this re-acks the SAME finding from the lifecycle test, so it must
# run AFTER the DELETE-revoke step (and we re-POST first).
# ---------------------------------------------------------------------------

begin_test "POST acknowledge is idempotent (re-ack overwrites reason)"
if [ -z "$FINDING_ID" ]; then
  skip "no finding to re-acknowledge"
else
  # First ack again to set known state.
  ack_payload_1=$(jq -n --arg r "$ACK_REASON" '{reason: $r}')
  ack_resp_1=$(api_post "/api/v1/security/findings/${FINDING_ID}/acknowledge" "$ack_payload_1" 2>/dev/null) || true
  ack_payload_2=$(jq -n --arg r "$ACK_REASON_2" '{reason: $r}')
  reack_status=$(curl -s -o "$WORK_DIR/reack-resp.json" -w '%{http_code}' \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$ack_payload_2" \
    "${BASE_URL}/api/v1/security/findings/${FINDING_ID}/acknowledge") || reack_status=000
  if [ -z "$ack_resp_1" ]; then
    fail "first re-ack returned empty body (priming step failed)"
  elif [ "$(echo "$ack_resp_1" | jq -r '.is_acknowledged // empty')" != "true" ]; then
    fail "priming re-ack did not set is_acknowledged=true (got '$(echo "$ack_resp_1" | jq -r '.is_acknowledged // empty')')"
  elif [ "$reack_status" != "200" ]; then
    fail "second POST acknowledge returned HTTP ${reack_status} (expected 200; idempotent overwrite)"
  else
    reack_body=$(cat "$WORK_DIR/reack-resp.json")
    is_ack=$(echo "$reack_body" | jq -r '.is_acknowledged // empty')
    new_reason=$(echo "$reack_body" | jq -r '.acknowledged_reason // empty')
    if [ "$is_ack" != "true" ]; then
      fail "expected is_acknowledged=true after re-ack, got '${is_ack}'"
    elif [ "$new_reason" != "$ACK_REASON_2" ]; then
      fail "re-ack did not overwrite reason: got '${new_reason}', expected '${ACK_REASON_2}'"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.2.i -- DELETE acknowledge is idempotent: revoking an already-revoked
# finding must not 5xx. Per the backend (scan_result_service.rs revoke
# pattern), a second DELETE returns 200 with the same unchanged
# is_acknowledged=false row; some implementations may return 404. Either
# is acceptable; 5xx is not.
# ---------------------------------------------------------------------------

begin_test "DELETE acknowledge is idempotent (no 5xx on already-revoked)"
if [ -z "$FINDING_ID" ]; then
  skip "no finding to double-revoke"
else
  # First revoke (might be a no-op if 2.2.h re-acked then nothing revoked).
  curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/findings/${FINDING_ID}/acknowledge" > /dev/null || true
  # Second revoke should not 5xx.
  status=$(curl -s -o "$WORK_DIR/double-revoke-resp.json" -w '%{http_code}' \
    -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/findings/${FINDING_ID}/acknowledge") || status=000
  if [[ "$status" =~ ^5[0-9][0-9]$ ]]; then
    fail "second DELETE returned HTTP ${status} (5xx); expected 200 (idempotent) or 404"
  elif [ "$status" = "200" ]; then
    # Verify the body still reflects revoked state -- catches a regression
    # where the second DELETE returns 200 with stale is_acknowledged=true.
    body=$(cat "$WORK_DIR/double-revoke-resp.json")
    body_is_ack=$(echo "$body" | jq -r '.is_acknowledged // empty')
    if [ "$body_is_ack" != "false" ]; then
      fail "second DELETE returned 200 but is_acknowledged='${body_is_ack}' (expected false)"
    else
      pass
    fi
  elif [ "$status" = "404" ]; then
    pass
  else
    fail "second DELETE returned unexpected HTTP ${status}; expected 200 (idempotent) or 404"
  fi
fi

# ---------------------------------------------------------------------------
# 2.2.j -- Empty-string reason. The backend's AcknowledgeRequest type does
# not enforce a min length on `reason`, so an empty string is currently
# accepted at the wire level. We accept either 2xx (no validation) or 4xx
# (future validation added) but reject 5xx, which is always wrong.
# Tighten this once the contract is finalized one way or the other.
# ---------------------------------------------------------------------------

begin_test "POST acknowledge with empty-string reason"
if [ -z "$FINDING_ID" ]; then
  skip "no finding to test empty reason"
else
  empty_payload='{"reason":""}'
  status=$(curl -s -o "$WORK_DIR/empty-reason-resp.json" -w '%{http_code}' \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$empty_payload" \
    "${BASE_URL}/api/v1/security/findings/${FINDING_ID}/acknowledge") || status=000
  if [[ "$status" =~ ^5[0-9][0-9]$ ]]; then
    fail "empty reason returned HTTP ${status} (5xx); contract requires 2xx (accepted) or 4xx (rejected)"
  elif [[ "$status" =~ ^2[0-9][0-9]$ ]] || [[ "$status" =~ ^4[0-9][0-9]$ ]]; then
    pass
  else
    fail "empty reason returned unexpected HTTP ${status}"
  fi
fi

# ---------------------------------------------------------------------------
# Wrap up. EXPECT_FAILURE=1 inverts the suite exit code. Inversion is only
# meaningful when at least one real test ran -- an all-skipped run would
# otherwise turn into a self-test FAIL on a healthy scanner-less backend.
# See test-scan-findings-list.sh for the same wrapper.
# ---------------------------------------------------------------------------

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  end_suite_rc=0
  ( end_suite ) || end_suite_rc=$?

  if [ "$_PASS_COUNT" -eq 0 ] && [ "$_FAIL_COUNT" -eq 0 ]; then
    echo ""
    echo "EXPECT_FAILURE=1 but suite produced no PASS or FAIL (only ${_SKIP_COUNT} skips)."
    echo "Inversion has no signal; exiting 1 to flag the broken self-test invocation."
    exit 1
  fi

  if [ "$end_suite_rc" -ne 0 ]; then
    echo ""
    echo "EXPECT_FAILURE=1 and suite failed as expected -- inverting to PASS"
    exit 0
  else
    echo ""
    echo "EXPECT_FAILURE=1 but suite passed -- inverting to FAIL"
    exit 1
  fi
fi

end_suite
