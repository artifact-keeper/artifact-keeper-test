#!/usr/bin/env bash
# test-auto-scan-on-upload.sh -- Auto-scan-on-upload trigger E2E
#
# Covers Epic 2 sub-task 2.12 (artifact-keeper-test#67): with a repository
# configured for auto_scan=true, uploading an artifact MUST produce a scan
# record without an explicit POST /security/scan call.
#
# Load-bearing observable
# -----------------------
# After the upload, the per-artifact scan list at
#   GET /api/v1/security/artifacts/{id}/scans
# must contain at least one row whose created_at falls AFTER the timestamp
# we captured before the upload. We DO NOT call POST /security/scan; if the
# row appears, the auto-scan-on-upload listener fired. If no row appears
# within AUTO_SCAN_WAIT seconds, the listener is broken and we FAIL.
#
# This is the exact failure class the test guards: a backend that silently
# drops the post-upload event (no listener wired, listener panics, eligibility
# filter excludes everything) would otherwise look healthy because the
# upload itself returns 201.
#
# Skip semantics
# --------------
# If POST /api/v1/repositories/{key}/scan-config returns 404, the
# auto-scan-on-upload feature is not mounted on this backend; SKIP cleanly.
# 5xx from that endpoint is a real failure (subsystem broken).
#
# Requires: curl, jq, tar
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auto-scan-on-upload"
auth_admin
setup_workdir

REPO_KEY="auto-scan-${RUN_ID}"
PACKAGE_NAME="auto-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"
AUTO_SCAN_WAIT="${AUTO_SCAN_WAIT:-90}"

cleanup() {
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler 'cleanup'

begin_test "Build fixture"
mkdir -p "${WORK_DIR}/pkg"
cat > "${WORK_DIR}/pkg/package.json" <<'EOF'
{"name":"auto-fixture","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}
EOF
if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" pkg 2>/dev/null; then
  pass
else
  fail "could not build fixture tarball"
fi

begin_test "Create repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo ${REPO_KEY}"
fi

begin_test "Enable auto_scan on repository scan-config"
cfg_payload='{"auto_scan":true}'
cfg_status=$(curl -s -o "${WORK_DIR}/cfg.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$cfg_payload" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/scan-config") || cfg_status="000"
case "$cfg_status" in
  200|201|204) pass ;;
  404)
    # Fall back to PUT in case the backend exposes the config as a PUT-only resource.
    cfg_status=$(curl -s -o "${WORK_DIR}/cfg.json" -w '%{http_code}' $CURL_TIMEOUT \
      -X PUT -H "$(auth_header)" -H "Content-Type: application/json" \
      -d "$cfg_payload" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/scan-config") || cfg_status="000"
    case "$cfg_status" in
      200|201|204) pass ;;
      404)         skip "scan-config endpoint not mounted (HTTP 404); auto-scan-on-upload feature not shipped on this backend"
                   end_suite ;;
      *)           fail "PUT scan-config returned HTTP ${cfg_status} (body: $(head -c 200 "${WORK_DIR}/cfg.json"))" ;;
    esac
    ;;
  *) fail "POST scan-config returned HTTP ${cfg_status} (body: $(head -c 200 "${WORK_DIR}/cfg.json"))" ;;
esac

# Capture the cutoff BEFORE upload. Any scan whose created_at is strictly
# AFTER this epoch is the one auto-scan produced for our upload. The 2s
# sleep absorbs `date +%s` 1-second truncation against the backend clock.
TEST_START_EPOCH=$(date -u +%s)
sleep 2

begin_test "Upload artifact"
up_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || up_status="000"
case "$up_status" in
  200|201) pass ;;
  *)       fail "upload returned HTTP ${up_status}" ;;
esac

begin_test "Resolve artifact_id"
art_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" 2>/dev/null || true)
ARTIFACT_ID=$(echo "$art_resp" | jq -r '.id // .artifact_id // empty' 2>/dev/null || echo "")
if [ -n "$ARTIFACT_ID" ]; then
  pass
else
  fail "could not resolve artifact_id for ${ARTIFACT_PATH}"
fi

# Load-bearing assertion: observe the scan APPEAR without us calling
# POST /security/scan. Polling stops as soon as any scan row exists whose
# created_at is fresh relative to the pre-upload epoch.
begin_test "Auto-scan produces a scan row within ${AUTO_SCAN_WAIT}s (no manual trigger)"
if [ -z "$ARTIFACT_ID" ]; then
  skip "no artifact_id; cannot poll scans"
else
  elapsed=0
  observed=0
  observed_id=""
  observed_created=""
  while [ "$elapsed" -lt "$AUTO_SCAN_WAIT" ]; do
    resp=$(api_get "/api/v1/security/artifacts/${ARTIFACT_ID}/scans" 2>/dev/null || true)
    if [ -n "$resp" ]; then
      # Pick the newest row whose created_at (ISO8601) parses to >= TEST_START_EPOCH.
      observed_id=$(echo "$resp" | jq -r --argjson cutoff "$TEST_START_EPOCH" '
        .items // [] | map(select(
          .created_at != null and
          (.created_at | sub("\\.[0-9]+Z?$"; "Z") | sub("\\+[0-9:]+$"; "Z")
            | fromdateiso8601? // 0) >= $cutoff
        )) | .[0].id // empty' 2>/dev/null || echo "")
      observed_created=$(echo "$resp" | jq -r --arg id "$observed_id" '
        .items[]? | select(.id == $id) | .created_at // empty' 2>/dev/null || echo "")
      if [ -n "$observed_id" ]; then
        observed=1
        break
      fi
    fi
    sleep 5
    elapsed=$(( elapsed + 5 ))
  done
  if [ "$observed" = "1" ]; then
    echo "  observed auto-scan id=${observed_id} created_at=${observed_created}"
    pass
  else
    fail "no scan row observed for artifact ${ARTIFACT_ID} within ${AUTO_SCAN_WAIT}s after upload; auto-scan-on-upload listener appears broken"
  fi
fi

end_suite
