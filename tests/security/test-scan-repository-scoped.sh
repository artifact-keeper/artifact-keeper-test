#!/usr/bin/env bash
# test-scan-repository-scoped.sh - Repo-scoped scan listing E2E test
#
# Covers Epic 2 sub-task 2.3 (artifact-keeper-test#68):
#   GET /api/v1/repositories/{key}/security/scans
# must return only scans for the named repository. The global
# /api/v1/security/scans endpoint is exercised by other tests; this test
# pins the per-repo scoping contract.
#
# Flow:
#   1. Create two Docker/OCI repositories (scope-a, scope-b).
#   2. Push a minimal manifest into each so each has a scannable artifact.
#   3. Trigger a scan on each artifact, wait for terminal status.
#   4. GET /repositories/<scope-a>/security/scans and assert:
#        - scan_a appears
#        - scan_b does NOT appear
#      Then do the mirror assertion against scope-b.
#
# If the scanner is not configured on this backend, the trigger returns
# 5xx (or a 500 with "scanner not configured" body) and we skip rather
# than fail; see test-scan-findings-list.sh for full rationale.
#
# Requires: curl, jq, shasum

set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-repository-scoped"
auth_admin
setup_workdir

REPO_KEY_A="test-scope-a-${RUN_ID}"
REPO_KEY_B="test-scope-b-${RUN_ID}"
IMAGE_NAME="scope-target"
UNIQUE_TAG="1.0.${RUN_ID}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-60}"
ARTIFACT_ID_A=""
ARTIFACT_ID_B=""
SCAN_ID_A=""
SCAN_ID_B=""
SCANNER_AVAILABLE=true

cleanup_repos() {
  # shellcheck disable=SC2086
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY_A}" > /dev/null 2>&1 || true
  # shellcheck disable=SC2086
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY_B}" > /dev/null 2>&1 || true
}
add_exit_handler 'cleanup_repos'

# push_manifest REPO_KEY -> echoes ARTIFACT_ID for the pushed manifest tag
push_manifest() {
  local repo_key="$1"
  local token_resp token put_status layer_put_status manifest_status
  local config_digest config_size layer_digest layer_size
  local upload_resp location put_url layer_resp layer_loc layer_put_url
  local list_resp artifact_id

  token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/v2/token" 2>/dev/null) || true
  token=$(echo "$token_resp" | jq -r '.token // empty')
  if [ -z "$token" ]; then
    echo "could not obtain registry token" >&2
    return 1
  fi

  local config_content='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},"config":{}}'
  config_digest="sha256:$(printf '%s' "$config_content" | shasum -a 256 | awk '{print $1}')"
  config_size=${#config_content}

  upload_resp=$(curl -s -D "$WORK_DIR/${repo_key}-cfg.txt" -o /dev/null \
    -X POST -H "Authorization: Bearer $token" \
    "${BASE_URL}/v2/${repo_key}/${IMAGE_NAME}/blobs/uploads/" 2>/dev/null) || true
  location=$(grep -i '^location:' "$WORK_DIR/${repo_key}-cfg.txt" 2>/dev/null | tr -d '\r' | awk '{print $2}') || true
  if [ -z "$location" ]; then return 1; fi
  if [[ "$location" == http* ]]; then put_url="$location"; else put_url="${BASE_URL}${location}"; fi
  if [[ "$put_url" == *"?"* ]]; then put_url="${put_url}&digest=${config_digest}"; else put_url="${put_url}?digest=${config_digest}"; fi
  put_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Authorization: Bearer $token" -H "Content-Type: application/octet-stream" \
    -d "$config_content" "$put_url") || true
  [ "$put_status" = "201" ] || return 1

  # Distinct random bytes per repo so the artifact rows are independent.
  dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/${repo_key}-layer.bin" 2>/dev/null
  layer_digest="sha256:$(shasum -a 256 "${WORK_DIR}/${repo_key}-layer.bin" | awk '{print $1}')"
  layer_size=$(wc -c < "${WORK_DIR}/${repo_key}-layer.bin" | tr -d ' ')
  layer_resp=$(curl -s -D "$WORK_DIR/${repo_key}-layer.txt" -o /dev/null \
    -X POST -H "Authorization: Bearer $token" \
    "${BASE_URL}/v2/${repo_key}/${IMAGE_NAME}/blobs/uploads/" 2>/dev/null) || true
  layer_loc=$(grep -i '^location:' "$WORK_DIR/${repo_key}-layer.txt" 2>/dev/null | tr -d '\r' | awk '{print $2}') || true
  if [ -z "$layer_loc" ]; then return 1; fi
  if [[ "$layer_loc" == http* ]]; then layer_put_url="$layer_loc"; else layer_put_url="${BASE_URL}${layer_loc}"; fi
  if [[ "$layer_put_url" == *"?"* ]]; then layer_put_url="${layer_put_url}&digest=${layer_digest}"; else layer_put_url="${layer_put_url}?digest=${layer_digest}"; fi
  layer_put_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Authorization: Bearer $token" -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/${repo_key}-layer.bin" "$layer_put_url") || true
  [ "$layer_put_status" = "201" ] || return 1

  local manifest
  manifest=$(cat <<EOFM
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "${config_digest}", "size": ${config_size} },
  "layers": [ { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "${layer_digest}", "size": ${layer_size} } ]
}
EOFM
)
  manifest_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Authorization: Bearer $token" \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    -d "$manifest" \
    "${BASE_URL}/v2/${repo_key}/${IMAGE_NAME}/manifests/${UNIQUE_TAG}") || true
  if [ "$manifest_status" != "201" ] && [ "$manifest_status" != "200" ]; then return 1; fi

  list_resp=$(api_get "/api/v1/repositories/${repo_key}/artifacts" 2>/dev/null) || true
  artifact_id=$(echo "$list_resp" | jq -r --arg tag "$UNIQUE_TAG" --arg img "$IMAGE_NAME" '
    if type == "array" then . elif .items then .items else [] end
    | map(select(((.path // "") | contains($tag)) or ((.version // "") == $tag) or ((.name // "") | contains($img))))
    | .[0].id // empty
  ')
  [ -n "$artifact_id" ] || return 1
  echo "$artifact_id"
}

# ---------------------------------------------------------------------------
# Set up scope-a and scope-b
# ---------------------------------------------------------------------------

begin_test "Create two Docker/OCI repos"
if create_repo "$REPO_KEY_A" "docker" "local" && create_repo "$REPO_KEY_B" "docker" "local"; then
  pass
else
  fail "could not create both scope repos"
fi

begin_test "Push manifest into scope-a"
if ARTIFACT_ID_A=$(push_manifest "$REPO_KEY_A"); then pass; else fail "push to scope-a failed"; fi

begin_test "Push manifest into scope-b"
if ARTIFACT_ID_B=$(push_manifest "$REPO_KEY_B"); then pass; else fail "push to scope-b failed"; fi

begin_test "Trigger scan on scope-a artifact"
if [ -z "$ARTIFACT_ID_A" ]; then
  skip "no artifact id for scope-a"
else
  rc=0
  SCAN_ID_A=$(trigger_and_wait_scan "$ARTIFACT_ID_A" "$SCAN_TIMEOUT") || rc=$?
  case "$rc" in
    0) pass ;;
    2) SCANNER_AVAILABLE=false; skip "scanner unavailable (rc=2)" ;;

    3) fail "scan accepted but did not reach a terminal state within ${SCAN_TIMEOUT}s (stuck running)" ;;

    *) fail "scan-a did not complete (rc=$rc)" ;;
  esac
fi

begin_test "Trigger scan on scope-b artifact"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$ARTIFACT_ID_B" ]; then
  skip "no artifact id for scope-b"
else
  rc=0
  SCAN_ID_B=$(trigger_and_wait_scan "$ARTIFACT_ID_B" "$SCAN_TIMEOUT") || rc=$?
  case "$rc" in
    0) pass ;;
    2) SCANNER_AVAILABLE=false; skip "scanner unavailable (rc=2)" ;;

    3) fail "scan accepted but did not reach a terminal state within ${SCAN_TIMEOUT}s (stuck running)" ;;

    *) fail "scan-b did not complete (rc=$rc)" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 2.3.a -- scope-a's repo-scoped scan list contains scan-a, NOT scan-b.
# This is the load-bearing assertion: the endpoint must filter by repo.
# ---------------------------------------------------------------------------

begin_test "GET /repositories/scope-a/security/scans contains scan-a only"
if ! $SCANNER_AVAILABLE || [ -z "$SCAN_ID_A" ] || [ -z "$SCAN_ID_B" ]; then
  skip "scanner unavailable or one of the scans missing"
else
  resp=$(api_get "/api/v1/repositories/${REPO_KEY_A}/security/scans?per_page=200" 2>/dev/null) || true
  if [ -z "$resp" ]; then
    fail "repo-scoped scan list returned empty body"
  elif ! echo "$resp" | jq -e '.items | type == "array"' > /dev/null 2>&1; then
    fail "response missing 'items' array (got: $(echo "$resp" | head -c 200))"
  else
    has_a=$(echo "$resp" | jq -r --arg id "$SCAN_ID_A" '.items[]? | select(.id == $id) | .id')
    has_b=$(echo "$resp" | jq -r --arg id "$SCAN_ID_B" '.items[]? | select(.id == $id) | .id')
    if [ -z "$has_a" ]; then
      fail "scope-a list missing scan-a (${SCAN_ID_A})"
    elif [ -n "$has_b" ]; then
      fail "scope-a list leaked scan-b (${SCAN_ID_B}) -- repo scoping broken"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.3.b -- mirror assertion against scope-b.
# ---------------------------------------------------------------------------

begin_test "GET /repositories/scope-b/security/scans contains scan-b only"
if ! $SCANNER_AVAILABLE || [ -z "$SCAN_ID_A" ] || [ -z "$SCAN_ID_B" ]; then
  skip "scanner unavailable or one of the scans missing"
else
  resp=$(api_get "/api/v1/repositories/${REPO_KEY_B}/security/scans?per_page=200" 2>/dev/null) || true
  if [ -z "$resp" ]; then
    fail "repo-scoped scan list returned empty body"
  elif ! echo "$resp" | jq -e '.items | type == "array"' > /dev/null 2>&1; then
    fail "response missing 'items' array"
  else
    has_a=$(echo "$resp" | jq -r --arg id "$SCAN_ID_A" '.items[]? | select(.id == $id) | .id')
    has_b=$(echo "$resp" | jq -r --arg id "$SCAN_ID_B" '.items[]? | select(.id == $id) | .id')
    if [ -z "$has_b" ]; then
      fail "scope-b list missing scan-b (${SCAN_ID_B})"
    elif [ -n "$has_a" ]; then
      fail "scope-b list leaked scan-a (${SCAN_ID_A}) -- repo scoping broken"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.3.c -- Unknown repo key returns 404, never 5xx (regression guard).
# ---------------------------------------------------------------------------

begin_test "Unknown repo key returns 404"
fake_key="nonexistent-${RUN_ID}-xyz"
status=$(curl -s -o /dev/null -w '%{http_code}' -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${fake_key}/security/scans") || status=000
if [ "$status" = "404" ]; then
  pass
elif [[ "$status" =~ ^5[0-9][0-9]$ ]]; then
  fail "unknown repo returned ${status} (5xx); expected 404"
else
  fail "unknown repo returned HTTP ${status}; expected 404"
fi

end_suite
