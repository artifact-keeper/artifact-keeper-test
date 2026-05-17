#!/usr/bin/env bash
# test-openscap-scanner.sh - OpenSCAP compliance scanner E2E test
#
# Covers Epic 2 sub-task 2.14 (artifact-keeper-test#67): OpenSCAP wrapper
# ships in docker-compose.local-dev.yml on port 8091 with zero E2E coverage.
#
# Backend integration notes (read while writing this test):
#   - openscap_scanner.rs: name()="openscap", scan_type()="openscap".
#     convert_findings stores rule_id in RawFinding.affected_component and
#     sets source="openscap"; cve_id is intentionally None (compliance, not CVEs).
#   - There is NO GET /api/v1/security/scanners endpoint. Closest proxy is
#     GET /api/v1/system/config -> .scanners.openscap_enabled (boolean
#     derived from CFG.openscap_url). We pair that with a post-trigger
#     check that a scan_type="openscap" row materializes.
#   - POST /api/v1/security/scan has no scanner-selector field
#     (TriggerScanRequest = {artifact_id?, repository_id?}); the trigger fans
#     out to every configured scanner. We filter the scans list by
#     scan_type=openscap to isolate this scanner.
#   - OpenSCAP::is_applicable accepts container manifests, RPMs, DEBs only.
#     We use the OCI manifest path, matching test-scan-findings-list.sh.
#
# Gate: skip cleanly if OPENSCAP_URL is unset AND
# scanners.openscap_enabled=false. Release-gate against minimal stacks
# without the sidecar must not hard-fail here.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "openscap-scanner"
auth_admin
setup_workdir

REPO_KEY="repo-${RUN_ID}-oscap"
IMAGE_NAME="oscap-target"
UNIQUE_TAG="1.0.${RUN_ID}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-90}"
ARTIFACT_ID=""
SCAN_ID=""

cleanup_repo() {
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split per common.sh
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler 'cleanup_repo'

# Gate: accept either OPENSCAP_URL set in the runner env (local-dev opt-in,
# port 8091 docker-compose service) OR the backend's /api/v1/system/config
# reporting scanners.openscap_enabled=true. Either means the wrapper is
# wired up; skip otherwise.

begin_test "OpenSCAP scanner is registered with backend"
openscap_enabled=false
config_resp=$(curl -sf $CURL_TIMEOUT "${BASE_URL}/api/v1/system/config" 2>/dev/null) || true
if [ -n "$config_resp" ]; then
  if echo "$config_resp" | jq -e '.scanners.openscap_enabled == true' > /dev/null 2>&1; then
    openscap_enabled=true
  fi
fi
if [ "$openscap_enabled" != "true" ] && [ -n "${OPENSCAP_URL:-}" ]; then
  # Local-dev path: caller asserts the sidecar is up via env. Still verify
  # we can reach the configured URL's /health endpoint so we fail loudly if
  # OPENSCAP_URL is set but stale.
  if curl -sf --max-time 5 "${OPENSCAP_URL%/}/health" > /dev/null 2>&1; then
    openscap_enabled=true
  fi
fi
if [ "$openscap_enabled" = "true" ]; then
  pass
else
  skip "openscap service not configured (system/config.scanners.openscap_enabled=false and OPENSCAP_URL unset)"
  end_suite
  exit 0
fi

# Build a scannable OCI manifest. OpenSCAP only applies to container
# manifests/RPMs/DEBs per is_applicable; push a minimal config+layer+manifest
# in the same shape as test-scan-findings-list.sh.

begin_test "Create Docker/OCI repository for openscap target"
if create_repo "$REPO_KEY" "docker" "local"; then
  pass
else
  fail "could not create docker repository ${REPO_KEY}"
fi

begin_test "Obtain registry token"
TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then
  TOKEN=$(echo "$token_resp" | jq -r '.token // empty')
fi
if [ -n "$TOKEN" ]; then pass; else fail "could not obtain registry token"; fi

begin_test "Push config blob, layer, and manifest"
CONFIG_CONTENT='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},"config":{}}'
CONFIG_DIGEST="sha256:$(printf '%s' "$CONFIG_CONTENT" | shasum -a 256 | awk '{print $1}')"
CONFIG_SIZE=${#CONFIG_CONTENT}
curl -s -D "$WORK_DIR/h-cfg.txt" -o /dev/null -X POST -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" > /dev/null 2>&1 || true
cfg_loc=$(grep -i '^location:' "$WORK_DIR/h-cfg.txt" 2>/dev/null | tr -d '\r' | awk '{print $2}')
[[ "$cfg_loc" == http* ]] || cfg_loc="${BASE_URL}${cfg_loc}"
[[ "$cfg_loc" == *"?"* ]] && cfg_loc="${cfg_loc}&digest=${CONFIG_DIGEST}" || cfg_loc="${cfg_loc}?digest=${CONFIG_DIGEST}"
cfg_put=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" -d "$CONFIG_CONTENT" "$cfg_loc") || cfg_put=000

dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/layer.bin" 2>/dev/null
LAYER_DIGEST="sha256:$(shasum -a 256 "${WORK_DIR}/layer.bin" | awk '{print $1}')"
LAYER_SIZE=$(wc -c < "${WORK_DIR}/layer.bin" | tr -d ' ')
curl -s -D "$WORK_DIR/h-layer.txt" -o /dev/null -X POST -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" > /dev/null 2>&1 || true
layer_loc=$(grep -i '^location:' "$WORK_DIR/h-layer.txt" 2>/dev/null | tr -d '\r' | awk '{print $2}')
[[ "$layer_loc" == http* ]] || layer_loc="${BASE_URL}${layer_loc}"
[[ "$layer_loc" == *"?"* ]] && layer_loc="${layer_loc}&digest=${LAYER_DIGEST}" || layer_loc="${layer_loc}?digest=${LAYER_DIGEST}"
layer_put=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" --data-binary "@${WORK_DIR}/layer.bin" "$layer_loc") || layer_put=000

MANIFEST="{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"${CONFIG_DIGEST}\",\"size\":${CONFIG_SIZE}},\"layers\":[{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"${LAYER_DIGEST}\",\"size\":${LAYER_SIZE}}]}"
manifest_status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" -d "$MANIFEST" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/manifests/${UNIQUE_TAG}") || manifest_status=000

if [ "$cfg_put" = "201" ] && [ "$layer_put" = "201" ] && { [ "$manifest_status" = "201" ] || [ "$manifest_status" = "200" ]; }; then
  pass
else
  fail "OCI push failed (config=${cfg_put} layer=${layer_put} manifest=${manifest_status})"
fi

begin_test "Resolve artifact_id for pushed manifest"
list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || true
if [ -n "$list_resp" ]; then
  ARTIFACT_ID=$(echo "$list_resp" | jq -r --arg tag "$UNIQUE_TAG" --arg img "$IMAGE_NAME" '
    (if type == "array" then . elif .items then .items else [] end)
    | map(select(((.path // "") | contains($tag)) or ((.version // "") == $tag) or ((.name // "") | contains($img))))
    | .[0].id // empty')
fi
if [ -n "$ARTIFACT_ID" ]; then pass; else fail "could not resolve artifact_id"; fi

# Trigger fans out to every configured scanner; filter the scans list by
# scan_type=openscap so this test isn't satisfied by trivy/grype finishing
# first on the same artifact.

begin_test "Trigger scan and wait for openscap scan_result to complete"
if [ -z "$ARTIFACT_ID" ]; then
  skip "no artifact_id, cannot trigger scan"
else
  trigger_status=$(curl -s -o "$WORK_DIR/trigger.json" -w '%{http_code}' \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"artifact_id\":\"${ARTIFACT_ID}\"}" \
    "${BASE_URL}/api/v1/security/scan") || trigger_status=000

  if [[ ! "$trigger_status" =~ ^2[0-9][0-9]$ ]]; then
    fail "POST /security/scan returned HTTP ${trigger_status}" "$(head -c 300 "$WORK_DIR/trigger.json")"
  else
    elapsed=0
    final_status=""
    while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
      scans_resp=$(api_get "/api/v1/security/scans?artifact_id=${ARTIFACT_ID}&per_page=20" 2>/dev/null) || true
      if [ -n "$scans_resp" ]; then
        # Pick the most recent openscap-typed scan for this artifact.
        SCAN_ID=$(echo "$scans_resp" | jq -r '[.items[] | select(.scan_type=="openscap")] | .[0].id // empty')
        final_status=$(echo "$scans_resp" | jq -r '[.items[] | select(.scan_type=="openscap")] | .[0].status // empty')
        case "$final_status" in
          completed|failed|error|cancelled) break ;;
        esac
      fi
      sleep 5
      elapsed=$((elapsed + 5))
    done
    if [ -z "$SCAN_ID" ]; then
      fail "no openscap scan_result row materialized within ${SCAN_TIMEOUT}s (scanner reports openscap_enabled=true but no scan_type=openscap row was created; orchestrator gating bug or applicability mismatch)"
    elif [ "$final_status" = "completed" ]; then
      pass
    else
      fail "openscap scan did not complete (status=${final_status:-unknown})" "scan_id=${SCAN_ID}"
    fi
  fi
fi

# Findings-shape assertions per openscap_scanner.rs convert_findings:
#   source="openscap", affected_component carries the XCCDF rule_id,
#   severity in {info,low,medium,high}. 0 findings on a synthetic OCI
#   layer is acceptable (matches test-scan-findings-list.sh precedent).

begin_test "OpenSCAP findings carry rule_id (affected_component), source, profile-shape severity"
if [ -z "$SCAN_ID" ]; then
  skip "no openscap scan_id available"
else
  findings_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings" 2>/dev/null) || true
  if [ -z "$findings_resp" ]; then
    fail "GET /scans/${SCAN_ID}/findings returned empty body"
  else
    count=$(echo "$findings_resp" | jq '.items | length // 0')
    if [ "$count" = "0" ]; then
      skip "openscap produced 0 findings on synthetic OCI layer (clean scan is acceptable; profile may not match container content)"
    else
      bad_source=$(echo "$findings_resp" | jq -r '[.items[] | select(.source != "openscap")] | length')
      bad_rule=$(echo "$findings_resp" | jq -r '[.items[] | select((.affected_component // "") | startswith("xccdf_") | not)] | length')
      bad_sev=$(echo "$findings_resp" | jq -r '[.items[] | select(.severity != "info" and .severity != "low" and .severity != "medium" and .severity != "high")] | length')
      if [ "$bad_source" != "0" ]; then
        fail "${bad_source} finding(s) have source != \"openscap\" on a scan_type=openscap row"
      elif [ "$bad_rule" != "0" ]; then
        fail "${bad_rule} finding(s) have no XCCDF rule_id in affected_component (openscap_scanner.rs:209 sets this; missing means the convert path was bypassed)"
      elif [ "$bad_sev" != "0" ]; then
        fail "${bad_sev} finding(s) carry severity outside openscap's documented set {info,low,medium,high}"
      else
        pass
      fi
    fi
  fi
fi

# probe_version() caches "openscap-X.Y.Z" from the sidecar's /health.
# Missing version = sidecar /health broken or cache not populated.

begin_test "OpenSCAP scan row reports scanner_version from /health probe"
if [ -z "$SCAN_ID" ]; then
  skip "no openscap scan_id available"
else
  scan_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}" 2>/dev/null) || true
  ver=$(echo "$scan_resp" | jq -r '.scanner_version // empty')
  if [ -z "$ver" ]; then
    # Not a hard fail: version probe is best-effort (returns None on /health
    # errors). Skip with a precise reason so a stale sidecar is visible.
    skip "scan completed but scanner_version is null (sidecar /health probe returned no version; not a finding-correctness issue)"
  elif [[ "$ver" == openscap-* ]]; then
    pass
  else
    fail "scanner_version='${ver}' does not match expected 'openscap-X.Y.Z' shape from probe_version() in openscap_scanner.rs"
  fi
fi

end_suite
