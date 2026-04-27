#!/usr/bin/env bash
# test-scan-findings-list.sh - Scan findings list / filter / paginate E2E test
#
# Covers Epic 2 sub-task 2.1 (artifact-keeper-test#68): the
#   GET /api/v1/security/scans/{id}/findings
# endpoint added in v1.1.9 (customer pain #2 from
# https://github.com/orgs/artifact-keeper/discussions/872).
#
# Flow:
#   1. Create a Docker/OCI repo and push a minimal manifest. The Trivy image
#      scanner that ships with the dev compose stack picks this up and emits
#      real findings when CVEs are matched against the layer hash.
#   2. Wait for the scan to leave pending/in_progress.
#   3. Find the scan_id via GET /api/v1/security/scans?artifact_id=...
#   4. GET /scans/{id}/findings and assert the documented response shape:
#        { "items": [{id, scan_result_id, artifact_id, severity, title,
#                     cve_id?, affected_component?, ...}], "total": N }
#   5. Verify pagination: page=1 returns items, page=999 returns an empty
#      items array (and total is unchanged).
#
# The Trivy scanner may not be enabled on every backend (gate stack vs. demo
# vs. local-dev). If it isn't, we record skip() rather than fail() so the
# release-gate suite stays clean on minimal stacks.
#
# Self-test mode (EXPECT_FAILURE=1):
#   Inverts the final exit code. Used by CI smoke jobs that intentionally
#   point this test at a backend without a scanner to confirm the test
#   detects (and skips) gracefully rather than reporting false-pass.
#
# Requires: curl, jq, shasum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-findings-list"
auth_admin
setup_workdir

REPO_KEY="test-findings-list-${RUN_ID}"
IMAGE_NAME="findings-target"
UNIQUE_TAG="1.0.$(date +%s)"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-90}"
ARTIFACT_ID=""
SCAN_ID=""
SCANNER_AVAILABLE=true

# ---------------------------------------------------------------------------
# Cleanup trap: best-effort delete of the repo so we don't leak state across
# release-gate runs, plus rm of WORK_DIR (setup_workdir set the rm trap; we
# replace it with a combined trap so the repo cleanup happens too). Pattern
# borrowed from test-scan-completes-with-real-findings.sh on the unmerged
# scan-completion branch.
# ---------------------------------------------------------------------------
cleanup_repo() {
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split per common.sh
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
trap 'cleanup_repo; [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" 2>/dev/null || true' EXIT

# ---------------------------------------------------------------------------
# Build a scannable artifact via the OCI registry path. We use Docker/OCI
# (not npm) because the bundled ImageScanner produces deterministic findings
# against a known layer; npm tarballs only get scanned when the backend's
# trivy_fs scanner is wired up, which the gate stack does not always do.
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
  if [ -n "${REPO_ID:-}" ]; then
    pass
  else
    fail "repo created but could not determine repo ID"
  fi
else
  fail "could not create docker repository"
fi

# ---------------------------------------------------------------------------
# Obtain a registry token for v2 calls.
# ---------------------------------------------------------------------------

begin_test "Obtain registry token"
TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then
  TOKEN=$(echo "$token_resp" | jq -r '.token // empty')
fi
if [ -n "$TOKEN" ]; then
  pass
else
  fail "could not obtain registry token"
fi

# ---------------------------------------------------------------------------
# Push a minimal OCI image (config blob + layer + manifest).
# ---------------------------------------------------------------------------

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
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "${CONFIG_DIGEST}",
    "size": ${CONFIG_SIZE}
  },
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
# Resolve the artifact_id for the manifest we just pushed. The management
# API exposes artifacts by repository key; we filter by the manifest tag we
# used so we don't pick up unrelated rows when the suite re-runs.
# ---------------------------------------------------------------------------

begin_test "Resolve artifact_id for pushed manifest"
list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || true
if [ -n "$list_resp" ]; then
  ARTIFACT_ID=$(echo "$list_resp" | jq -r --arg tag "$UNIQUE_TAG" --arg img "$IMAGE_NAME" '
    if type == "array" then .
    elif .items then .items
    else []
    end
    | map(select(
        ((.path // "") | contains($tag)) or
        ((.version // "") == $tag) or
        ((.name // "") | contains($img))
      ))
    | .[0].id // empty
  ')
fi
if [ -n "$ARTIFACT_ID" ]; then
  pass
else
  fail "could not resolve artifact_id from artifact list"
fi

# ---------------------------------------------------------------------------
# Trigger an on-demand scan against the resolved artifact_id and wait for
# the scan to leave pending/queued/in_progress. If the scanner service is
# not configured, the trigger returns 5xx; we treat that as a skip rather
# than a hard failure (release-gate runs against minimal stacks).
# ---------------------------------------------------------------------------

begin_test "Trigger scan and wait for completion"
if [ -z "$ARTIFACT_ID" ]; then
  skip "no artifact_id, cannot trigger scan"
else
  trigger_payload="{\"artifact_id\":\"${ARTIFACT_ID}\"}"
  trigger_resp=$(api_post "/api/v1/security/scan" "$trigger_payload" 2>/dev/null) || true
  if [ -z "$trigger_resp" ]; then
    SCANNER_AVAILABLE=false
    skip "scanner service not configured (POST /security/scan returned error)"
  else
    # Poll the scans list filtered by artifact_id until status != pending/queued/in_progress.
    elapsed=0
    final_status=""
    while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
      scans_resp=$(api_get "/api/v1/security/scans?artifact_id=${ARTIFACT_ID}&per_page=10" 2>/dev/null) || true
      if [ -n "$scans_resp" ]; then
        # Pick the most recent scan (handler returns ordered by created_at DESC).
        SCAN_ID=$(echo "$scans_resp" | jq -r '.items[0].id // empty')
        final_status=$(echo "$scans_resp" | jq -r '.items[0].status // empty')
        if [ -n "$SCAN_ID" ] && [ -n "$final_status" ] \
           && [ "$final_status" != "pending" ] \
           && [ "$final_status" != "queued" ] \
           && [ "$final_status" != "scanning" ] \
           && [ "$final_status" != "in_progress" ]; then
          break
        fi
      fi
      sleep 5
      elapsed=$((elapsed + 5))
    done
    if [ -z "$SCAN_ID" ]; then
      SCANNER_AVAILABLE=false
      skip "no scan record produced for artifact within ${SCAN_TIMEOUT}s"
    elif [ "$final_status" = "pending" ] || [ "$final_status" = "queued" ] \
         || [ "$final_status" = "scanning" ] || [ "$final_status" = "in_progress" ]; then
      SCANNER_AVAILABLE=false
      skip "scan did not complete within ${SCAN_TIMEOUT}s (status=${final_status})"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.1.a -- GET /scans/{id}/findings returns the documented envelope.
# ---------------------------------------------------------------------------

begin_test "Findings list returns items + total envelope"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable, cannot exercise findings listing"
elif [ -z "$SCAN_ID" ]; then
  skip "no scan_id available"
else
  resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings" 2>/dev/null) || true
  if [ -z "$resp" ]; then
    fail "GET /scans/${SCAN_ID}/findings returned empty body"
  elif ! echo "$resp" | jq -e '.items | type == "array"' > /dev/null 2>&1; then
    fail "response missing 'items' array (got: $(echo "$resp" | head -c 200))"
  elif ! echo "$resp" | jq -e '.total | type == "number"' > /dev/null 2>&1; then
    fail "response missing numeric 'total' (got: $(echo "$resp" | head -c 200))"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 2.1.b -- Each finding item carries the documented identification fields.
# We don't fail if findings are empty (a clean scan is a valid outcome on
# the minimal random-bytes layer used here); we only fail if findings exist
# but are missing required schema fields.
# ---------------------------------------------------------------------------

begin_test "Each finding has required identification fields"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$SCAN_ID" ]; then
  skip "no scan_id available"
else
  resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings" 2>/dev/null) || true
  count=$(echo "$resp" | jq '.items | length // 0')
  if [ "$count" = "0" ]; then
    skip "scan produced 0 findings on dummy layer (clean scan is acceptable)"
  else
    # Required fields per FindingResponse in backend/src/api/handlers/security.rs.
    # cve_id, affected_component, etc. are Option<String> so we don't require them.
    missing=$(echo "$resp" | jq -r '
      .items[]
      | select(
          .id == null
          or .scan_result_id == null
          or .artifact_id == null
          or .severity == null
          or .title == null
          or .is_acknowledged == null
          or .created_at == null
        )
      | .id // "anon"
    ' | head -3)
    if [ -n "$missing" ]; then
      fail "finding(s) missing required fields: ${missing}"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.1.c -- Severity values are from the documented set.
# ---------------------------------------------------------------------------

begin_test "Finding severities are documented values"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$SCAN_ID" ]; then
  skip "no scan_id available"
else
  resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings" 2>/dev/null) || true
  count=$(echo "$resp" | jq '.items | length // 0')
  if [ "$count" = "0" ]; then
    skip "no findings on dummy layer"
  else
    bad=$(echo "$resp" | jq -r '
      .items[].severity
      | select(. != "critical" and . != "high" and . != "medium" and . != "low" and . != "info")
    ' | head -3)
    if [ -n "$bad" ]; then
      fail "unexpected severity value(s): ${bad}"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.1.d -- Pagination: page=1 with per_page=1 returns at most one item;
# total stays consistent with the unpaginated call.
# ---------------------------------------------------------------------------

begin_test "Pagination page=1 per_page=1 returns subset"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$SCAN_ID" ]; then
  skip "no scan_id available"
else
  full_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings" 2>/dev/null) || true
  full_total=$(echo "$full_resp" | jq -r '.total // 0')
  page1_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings?page=1&per_page=1" 2>/dev/null) || true
  page1_count=$(echo "$page1_resp" | jq '.items | length // 0')
  page1_total=$(echo "$page1_resp" | jq -r '.total // 0')
  if [ -z "$full_total" ] || [ "$page1_total" != "$full_total" ]; then
    fail "total mismatch between unpaginated (${full_total}) and page=1 (${page1_total})"
  elif [ "$full_total" = "0" ]; then
    # No findings: page=1 must still return a well-formed empty envelope.
    if [ "$page1_count" = "0" ]; then
      pass
    else
      fail "page=1 returned ${page1_count} items but total=0"
    fi
  else
    if [ "$page1_count" -le 1 ]; then
      pass
    else
      fail "page=1&per_page=1 returned ${page1_count} items, expected <=1"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.1.e -- Pagination: page=999 returns an empty items array (well past the
# last page) but total remains the same and the response is still a valid
# envelope (regression guard for #872 customer pain: out-of-range pages
# previously 500'd or returned malformed JSON).
# ---------------------------------------------------------------------------

begin_test "Pagination page=999 returns empty items"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$SCAN_ID" ]; then
  skip "no scan_id available"
else
  resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings?page=999&per_page=50" 2>/dev/null) || true
  if [ -z "$resp" ]; then
    fail "page=999 returned empty body (expected envelope with empty items)"
  elif ! echo "$resp" | jq -e '.items | type == "array"' > /dev/null 2>&1; then
    fail "page=999 response is not a valid envelope: $(echo "$resp" | head -c 200)"
  else
    items_count=$(echo "$resp" | jq '.items | length')
    if [ "$items_count" = "0" ]; then
      pass
    else
      fail "page=999 expected 0 items, got ${items_count}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.1.f -- Listing findings for a non-existent scan id returns a clean 404
# (regression guard: previously returned 500 when the scan_id had no rows).
# ---------------------------------------------------------------------------

begin_test "Findings for unknown scan_id returns 404 or empty 200"
fake_scan_id="00000000-0000-0000-0000-000000000000"
status=$(curl -s -o "$WORK_DIR/fake-scan-resp.json" -w '%{http_code}' \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/security/scans/${fake_scan_id}/findings") || status=000
# The handler's scan_result_service.list_findings returns (vec, count); when
# no rows match, this is a valid 200 with empty items + total=0 (the route
# does not pre-validate scan existence). Either 200 (empty envelope) or 404
# is acceptable; what we DON'T want is a 500.
if [ "$status" = "200" ]; then
  body=$(cat "$WORK_DIR/fake-scan-resp.json")
  if echo "$body" | jq -e '.items | type == "array"' > /dev/null 2>&1; then
    items_len=$(echo "$body" | jq '.items | length')
    total=$(echo "$body" | jq '.total')
    if [ "$items_len" = "0" ] && [ "$total" = "0" ]; then
      pass
    else
      fail "unknown scan_id returned non-empty envelope: items=${items_len}, total=${total}"
    fi
  else
    fail "unknown scan_id 200 response is not a valid envelope: $(echo "$body" | head -c 200)"
  fi
elif [ "$status" = "404" ]; then
  pass
else
  fail "unknown scan_id returned HTTP ${status} (expected 200-empty or 404, never 5xx)"
fi

# ---------------------------------------------------------------------------
# Wrap up. EXPECT_FAILURE=1 inverts the suite exit code so CI smoke jobs can
# point this test at a known-broken backend and verify the test catches it.
# ---------------------------------------------------------------------------

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  # Run end_suite in a subshell so it doesn't terminate us; capture its exit.
  if ( end_suite ); then
    echo ""
    echo "EXPECT_FAILURE=1 but suite passed -- inverting to FAIL"
    exit 1
  else
    echo ""
    echo "EXPECT_FAILURE=1 and suite failed as expected -- inverting to PASS"
    exit 0
  fi
fi

end_suite
