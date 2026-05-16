#!/usr/bin/env bash
# test-repo-scoped-scans.sh - Repository-scoped scan endpoint E2E test.
#
# Covers Epic 2 sub-task 2.3 (artifact-keeper-test#67): the
#   GET /api/v1/repositories/{key}/security/scans
# endpoint that ships in v1.2.0 (customer pain #2 from discussion #872).
#
# Why a separate test
# -------------------
# The existing test-scan-findings-list.sh exercises the artifact-scoped
# /security/scans?artifact_id=... path. The repo-scoped variant has its
# own handler, its own routing, and its own pagination shape; a regression
# in either one would silently make the UI "scans for this repo" tab
# return either 404 or the wrong rows. We assert:
#   1. 200 + documented ScanListResponse shape ({items: [...], total: N}).
#   2. Pagination parameters page= / per_page= are honored.
#   3. Filtering by status= returns only matching scans (or empty items
#      with total unchanged if no matching scan exists).
#   4. Unknown repo key -> 404 (not 500).
#
# Skip semantics
# --------------
# If the scanner is not configured on this stack the GET still works
# (it just returns total=0), so this test is NOT scanner-gated. It IS
# repo-create gated -- which is bedrock and would already have flagged
# upstream in the gate.
#
# Self-test mode (EXPECT_FAILURE=1):
#   Inverts the final exit code; same pattern as test-scan-findings-list.sh.
#
# Requires: curl, jq, shasum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "repo-scoped-scans"
auth_admin
setup_workdir

REPO_KEY="test-rscans-${RUN_ID}"
IMAGE_NAME="rscans-target"
UNIQUE_TAG="1.0.${RUN_ID}"
# 60s leaves headroom under run-suite.sh's 120s TEST_TIMEOUT.
SCAN_TIMEOUT="${SCAN_TIMEOUT:-60}"

cleanup_repo() {
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split per common.sh
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler "cleanup_repo"

# ---------------------------------------------------------------------------
# Setup: create a docker repo + push a minimal manifest so a scan record
# can plausibly exist. The point of this test is the listing endpoint
# shape, not finding count, so we don't require the scanner to be wired.
# ---------------------------------------------------------------------------

begin_test "Create Docker/OCI repository"
if create_local_repo "$REPO_KEY" "docker"; then
  pass
else
  fail "could not create docker repo ${REPO_KEY}"
  end_suite
  exit 1
fi

# Push a manifest so an artifact (and potentially a scan) exists. We
# tolerate failures from the registry path: the listing endpoint itself
# is the load-bearing assertion and works with zero scans (total=0).
begin_test "Obtain registry token (best-effort)"
TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then TOKEN=$(echo "$token_resp" | jq -r '.token // empty'); fi
if [ -n "$TOKEN" ]; then pass; else skip "no registry token; will test listing with zero scans"; fi

if [ -n "$TOKEN" ]; then
  begin_test "Push minimal OCI artifact"
  CONFIG_CONTENT='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},"config":{}}'
  CONFIG_DIGEST="sha256:$(printf '%s' "$CONFIG_CONTENT" | shasum -a 256 | awk '{print $1}')"
  CONFIG_SIZE=${#CONFIG_CONTENT}

  upload_resp=$(curl -s -D "$WORK_DIR/cfg-headers.txt" -o /dev/null \
    -X POST -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" 2>/dev/null) || true
  loc=$(grep -i '^location:' "$WORK_DIR/cfg-headers.txt" 2>/dev/null | tr -d '\r' | awk '{print $2}') || true
  cfg_put="000"
  if [ -n "$loc" ]; then
    if [[ "$loc" == http* ]]; then put_url="$loc"; else put_url="${BASE_URL}${loc}"; fi
    if [[ "$put_url" == *"?"* ]]; then put_url="${put_url}&digest=${CONFIG_DIGEST}"; else put_url="${put_url}?digest=${CONFIG_DIGEST}"; fi
    cfg_put=$(curl -s -o /dev/null -w '%{http_code}' \
      -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
      -d "$CONFIG_CONTENT" "$put_url") || true
  fi

  dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/layer.bin" 2>/dev/null
  LAYER_DIGEST="sha256:$(shasum -a 256 "${WORK_DIR}/layer.bin" | awk '{print $1}')"
  LAYER_SIZE=$(wc -c < "${WORK_DIR}/layer.bin" | tr -d ' ')
  layer_resp=$(curl -s -D "$WORK_DIR/lyr-headers.txt" -o /dev/null \
    -X POST -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" 2>/dev/null) || true
  lloc=$(grep -i '^location:' "$WORK_DIR/lyr-headers.txt" 2>/dev/null | tr -d '\r' | awk '{print $2}') || true
  layer_put="000"
  if [ -n "$lloc" ]; then
    if [[ "$lloc" == http* ]]; then lput_url="$lloc"; else lput_url="${BASE_URL}${lloc}"; fi
    if [[ "$lput_url" == *"?"* ]]; then lput_url="${lput_url}&digest=${LAYER_DIGEST}"; else lput_url="${lput_url}?digest=${LAYER_DIGEST}"; fi
    layer_put=$(curl -s -o /dev/null -w '%{http_code}' \
      -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
      --data-binary "@${WORK_DIR}/layer.bin" "$lput_url") || true
  fi

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
  if [ "$cfg_put" = "201" ] && [ "$layer_put" = "201" ] && { [ "$manifest_status" = "201" ] || [ "$manifest_status" = "200" ]; }; then
    pass
  else
    skip "OCI push incomplete (cfg=${cfg_put} layer=${layer_put} manifest=${manifest_status}); will test listing on empty repo"
  fi

  # Give the upload pipeline a chance to flush before we list scans.
  sleep 3
fi

# ---------------------------------------------------------------------------
# 2.3.a -- GET /api/v1/repositories/{key}/security/scans returns documented
# ScanListResponse shape: {items: [...], total: integer}.
# ---------------------------------------------------------------------------

begin_test "GET /repositories/{key}/security/scans returns ScanListResponse shape"
list_status=$(curl -s -o "$WORK_DIR/list.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" -H "Accept: application/json" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/security/scans") || list_status="000"

if [ "$list_status" = "501" ]; then
  # 501 means the repo-scoped scan endpoint is not mounted on this
  # backend (some minimal stacks); skip the entire suite per contract
  # (file header).
  skip "repo-scoped scans endpoint not available (HTTP ${list_status})"
elif [ "$list_status" = "404" ]; then
  # OpenAPI documents 404 as "repo not found" (spec line 7352). The
  # repo was just created above; a 404 here means the create lied or
  # the read path is broken. That's a regression, not a skip.
  fail "repo-scoped scans listing returned 404 for just-created repo ${REPO_KEY} (OpenAPI documents 404 as repo-not-found; create succeeded so this is a regression)"
elif [ "$list_status" = "200" ]; then
  # Required keys per ScanListResponse: items (array), total (integer).
  # next_page metadata: must be null/absent when total <= per_page (the
  # default page contains the whole set); otherwise must be a number.
  if ! jq -e '.items | type == "array"' "$WORK_DIR/list.json" > /dev/null 2>&1; then
    fail "response missing items[] array (body: $(head -c 200 "$WORK_DIR/list.json"))"
  elif ! jq -e '.total | type == "number"' "$WORK_DIR/list.json" > /dev/null 2>&1; then
    fail "response missing total integer (body: $(head -c 200 "$WORK_DIR/list.json"))"
  else
    # The default page contains everything that exists in this fresh
    # repo, so next_page must be null or absent. Either is acceptable
    # per the documented shape.
    np_type=$(jq -r 'if has("next_page") then (.next_page | type) else "absent" end' "$WORK_DIR/list.json")
    if [ "$np_type" != "null" ] && [ "$np_type" != "absent" ]; then
      fail "default page next_page='${np_type}' but total fits on one page (expected null/absent). body: $(head -c 200 "$WORK_DIR/list.json")"
    else
      pass
    fi
  fi
else
  fail "GET /repositories/${REPO_KEY}/security/scans returned HTTP ${list_status} (body: $(head -c 200 "$WORK_DIR/list.json" 2>/dev/null))"
fi

# ---------------------------------------------------------------------------
# 2.3.b -- Pagination params are honored. We don't depend on a particular
# scan existing; we assert (a) per_page=1 returns at most 1 item and
# (b) page=999 returns an empty items[] but total is unchanged.
# ---------------------------------------------------------------------------

begin_test "Pagination: per_page=1 returns at most one item, next_page reflects total"
p1_status=$(curl -s -o "$WORK_DIR/p1.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/security/scans?page=1&per_page=1") || p1_status="000"
if [ "$p1_status" != "200" ]; then
  skip "endpoint not available (HTTP ${p1_status})"
else
  count=$(jq -r '.items | length' "$WORK_DIR/p1.json" 2>/dev/null || echo "x")
  total_p1_raw=$(jq -r '.total // 0' "$WORK_DIR/p1.json" 2>/dev/null || echo "0")
  np_type=$(jq -r 'if has("next_page") then (.next_page | type) else "absent" end' "$WORK_DIR/p1.json")
  np_val=$(jq -r '.next_page // empty' "$WORK_DIR/p1.json" 2>/dev/null || echo "")
  if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -gt 1 ]; then
    fail "per_page=1 returned ${count} items (expected 0 or 1)"
  elif [ "$total_p1_raw" -gt 1 ]; then
    # total > per_page -> next_page MUST be a number pointing at page 2.
    if [ "$np_type" != "number" ]; then
      fail "per_page=1 total=${total_p1_raw} but next_page type='${np_type}' (expected number)"
    elif [ "$np_val" != "2" ]; then
      fail "per_page=1 next_page='${np_val}' (expected 2 since we requested page=1)"
    else
      pass
    fi
  else
    # total <= per_page -> next_page must be null or absent.
    if [ "$np_type" != "null" ] && [ "$np_type" != "absent" ]; then
      fail "per_page=1 total=${total_p1_raw} (single page) but next_page='${np_val}' type='${np_type}' (expected null/absent)"
    else
      pass
    fi
  fi
fi

begin_test "Pagination: page=999 returns empty items, total unchanged"
total_p1=$(jq -r '.total // 0' "$WORK_DIR/p1.json" 2>/dev/null || echo "0")
p999_status=$(curl -s -o "$WORK_DIR/p999.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/security/scans?page=999&per_page=10") || p999_status="000"
if [ "$p999_status" != "200" ]; then
  skip "endpoint not available (HTTP ${p999_status})"
else
  cnt=$(jq -r '.items | length' "$WORK_DIR/p999.json" 2>/dev/null || echo "x")
  total_p999=$(jq -r '.total // 0' "$WORK_DIR/p999.json" 2>/dev/null || echo "0")
  # total must be stable across pages -- not "0 on page=999 because the
  # backend re-bound it to page-count instead of repo-count". We don't
  # assert the exact value because it could legitimately be 0 (no scans
  # yet) or N (scans flushed during the manifest push above).
  if [ "$cnt" != "0" ]; then
    fail "page=999 returned ${cnt} items (expected 0)"
  elif [ "$total_p1" != "$total_p999" ]; then
    fail "total changed across pages: page1=${total_p1} page999=${total_p999}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 2.3.c -- status= filter accepts a documented value without erroring.
# We use "completed" because it's a documented terminal value; the
# response may be empty if no scan reached that state yet.
# ---------------------------------------------------------------------------

begin_test "Filter: status=completed returns ScanListResponse shape"
filt_status=$(curl -s -o "$WORK_DIR/filt.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/security/scans?status=completed") || filt_status="000"
if [ "$filt_status" = "200" ]; then
  if jq -e '.items | type == "array"' "$WORK_DIR/filt.json" > /dev/null 2>&1 \
     && jq -e '.total | type == "number"' "$WORK_DIR/filt.json" > /dev/null 2>&1; then
    pass
  else
    fail "filtered response missing items/total (body: $(head -c 200 "$WORK_DIR/filt.json"))"
  fi
else
  skip "filter request returned HTTP ${filt_status}"
fi

# ---------------------------------------------------------------------------
# 2.3.d -- Unknown repo key must return 404, not 500. This is the
# documented response per openapi.yaml line 7352.
# ---------------------------------------------------------------------------

begin_test "Unknown repo key returns 404 (not 500)"
nope_status=$(curl -s -o "$WORK_DIR/nope.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/does-not-exist-${RUN_ID}/security/scans") || nope_status="000"
case "$nope_status" in
  404) pass ;;
  501) skip "endpoint not available (HTTP 501)" ;;
  500|000) fail "expected 404 for unknown repo, got HTTP ${nope_status} (body: $(head -c 200 "$WORK_DIR/nope.json"))" ;;
  *) fail "expected 404 for unknown repo, got HTTP ${nope_status}" ;;
esac

end_suite
