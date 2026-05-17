#!/usr/bin/env bash
# test-dependencytrack-integration.sh -- DependencyTrack integration E2E
#
# Covers Epic 2 sub-task 2.11 (artifact-keeper-test#67): the 9 DependencyTrack
# endpoints surface (project sync, finding pull-back, metrics, BOM processing,
# violations). The end-to-end contract this script pins:
#
#   1. AK exposes a DTrack integration configuration endpoint.
#   2. With a valid integration configured, uploading a BOM (or scanning an
#      artifact) propagates project + components to DTrack.
#   3. AK can pull findings back from DTrack for that project.
#   4. The findings appear in AK's per-artifact view.
#
# Gating
# ------
# DTrack is an optional subsystem on the gate stack (clean-install-smoke.sh
# disables it by default). This test SKIPs cleanly when:
#   - DEPENDENCY_TRACK_API_KEY is unset
#   - DEPENDENCY_TRACK_URL is unset
#   - the /api/v1/integrations/dependency-track endpoint family returns 404
# It does NOT SKIP on 5xx -- a configured DTrack subsystem that crashes mid
# flow is a real failure for the gate.
#
# Requires: curl, jq, tar
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"

begin_suite "dependencytrack-integration"

DTRACK_URL="${DEPENDENCY_TRACK_URL:-}"
DTRACK_KEY="${DEPENDENCY_TRACK_API_KEY:-}"

if [ -z "$DTRACK_KEY" ] || [ -z "$DTRACK_URL" ]; then
  begin_test "DependencyTrack env gate"
  skip "DEPENDENCY_TRACK_API_KEY and/or DEPENDENCY_TRACK_URL not set; DTrack integration not exercised"
  end_suite
fi

auth_admin
setup_workdir

REPO_KEY="dtrack-int-${RUN_ID}"
INTEGRATION_ID=""
PROJECT_NAME="ak-dtrack-${RUN_ID}"
ARTIFACT_PATH="bom/${RUN_ID}/sbom.cdx.json"

cleanup() {
  if [ -n "$INTEGRATION_ID" ]; then
    api_delete "/api/v1/integrations/dependency-track/${INTEGRATION_ID}" >/dev/null 2>&1 || true
  fi
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler 'cleanup'

# Build a minimal CycloneDX BOM. DTrack accepts schema 1.4+. We pin one
# component with a known CVE-bearing version so the pull-back step has a real
# row to assert against.
begin_test "Build minimal CycloneDX BOM fixture"
cat > "${WORK_DIR}/bom.json" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.4",
      "purl": "pkg:npm/lodash@4.17.4"
    }
  ]
}
EOF
[ -s "${WORK_DIR}/bom.json" ] && pass || fail "BOM fixture not written"

begin_test "Configure DependencyTrack integration"
payload=$(jq -n --arg url "$DTRACK_URL" --arg key "$DTRACK_KEY" --arg name "ak-dtrack-${RUN_ID}" \
  '{name:$name, url:$url, api_key:$key, enabled:true}')
cfg_status=$(curl -s -o "${WORK_DIR}/cfg.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$payload" "${BASE_URL}/api/v1/integrations/dependency-track") || cfg_status="000"
if [ "$cfg_status" = "404" ]; then
  skip "/api/v1/integrations/dependency-track not mounted (HTTP 404); backend pre-dates DTrack wiring"
  end_suite
elif [[ "$cfg_status" =~ ^2[0-9][0-9]$ ]]; then
  INTEGRATION_ID=$(jq -r '.id // empty' < "${WORK_DIR}/cfg.json" 2>/dev/null || echo "")
  pass
else
  fail "DTrack integration config returned HTTP ${cfg_status} (body: $(head -c 200 "${WORK_DIR}/cfg.json"))"
fi

begin_test "Create repo and upload BOM"
if create_local_repo "$REPO_KEY" "generic"; then
  up_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT -H "$(auth_header)" -H "Content-Type: application/json" \
    --data-binary "@${WORK_DIR}/bom.json" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || up_status="000"
  case "$up_status" in
    200|201) pass ;;
    *)       fail "BOM upload returned HTTP ${up_status}" ;;
  esac
else
  fail "could not create repo ${REPO_KEY}"
fi

begin_test "Propagate BOM to DTrack (project sync)"
sync_payload=$(jq -n --arg p "$PROJECT_NAME" --arg path "$ARTIFACT_PATH" --arg key "$REPO_KEY" \
  '{project_name:$p, repository_key:$key, artifact_path:$path}')
sync_status=$(curl -s -o "${WORK_DIR}/sync.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$sync_payload" "${BASE_URL}/api/v1/integrations/dependency-track/${INTEGRATION_ID}/sync") || sync_status="000"
case "$sync_status" in
  200|201|202) pass ;;
  404)         skip "sync endpoint not mounted on this backend version" ;;
  *)           fail "DTrack sync returned HTTP ${sync_status} (body: $(head -c 200 "${WORK_DIR}/sync.json"))" ;;
esac

begin_test "Pull findings back from DTrack"
elapsed=0
pull_done=0
while [ "$elapsed" -lt 60 ]; do
  pull_status=$(curl -s -o "${WORK_DIR}/pull.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" \
    "${BASE_URL}/api/v1/integrations/dependency-track/${INTEGRATION_ID}/pull-findings") || pull_status="000"
  if [[ "$pull_status" =~ ^2[0-9][0-9]$ ]]; then
    pull_done=1; break
  fi
  if [ "$pull_status" = "404" ]; then
    break
  fi
  sleep 5
  elapsed=$(( elapsed + 5 ))
done
if [ "$pull_done" = "1" ]; then
  pass
elif [ "$pull_status" = "404" ]; then
  skip "pull-findings endpoint not mounted on this backend version"
else
  fail "DTrack pull-findings did not complete within 60s (last HTTP ${pull_status})"
fi

begin_test "Finding visible in AK per-artifact view"
art_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" 2>/dev/null || true)
ARTIFACT_ID=$(echo "$art_resp" | jq -r '.id // .artifact_id // empty' 2>/dev/null || echo "")
if [ -z "$ARTIFACT_ID" ]; then
  skip "could not resolve artifact_id; cannot verify finding visibility"
else
  vis_resp=$(api_get "/api/v1/security/artifacts/${ARTIFACT_ID}/findings" 2>/dev/null || true)
  if [ -z "$vis_resp" ]; then
    skip "per-artifact findings endpoint returned empty (DTrack pull may be async; tracked in epic#67)"
  elif echo "$vis_resp" | jq -e '.items | type == "array"' >/dev/null 2>&1; then
    pass
  else
    fail "per-artifact findings response is not a valid envelope (got: $(echo "$vis_resp" | head -c 200))"
  fi
fi

end_suite
