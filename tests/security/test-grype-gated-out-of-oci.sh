#!/usr/bin/env bash
# test-grype-gated-out-of-oci.sh
#
# Closes a sub-task of artifact-keeper-test#181-cohort (untested
# security fixes, triage doc §4 "Critical" tier).
#
# Bug guarded against
# -------------------
# artifact-keeper#1164 (commit 14f59c68, merged 2026-05-11). Grype
# was being invoked on OCI image manifests via its `grype dir:` mode.
# The manifest is a tiny JSON file listing layer digests, NOT the
# actual image layers, so Grype walked the JSON, found no installed
# packages, and returned 0 findings. Trivy (via ImageScanner against
# the registry) actually pulls and scans the layers and finds 200+
# CVEs on common base images. The original repro: nginx:latest
# reported "0 / 201" findings instead of the real "200 / 201".
#
# Fix: gate Grype out of OCI artifacts via Scanner::is_applicable.
# The predicate matches the same OCI surface ImageScanner already
# recognizes (vnd.oci.image / vnd.docker.distribution /
# vnd.docker.container content types, OR path contains "/manifests/").
#
# Pre-flight (per the rule introduced after PR #185's closure):
# gh pr view 1164 confirms state=MERGED, mergedAt=2026-05-11.
#
# What this test pins
# -------------------
# Externally observable property: scan_results rows have a `scan_type`
# field (ScanType enum: dependency | image | license | malware). Grype
# emits `dependency`; ImageScanner emits `image`. Post-fix, an OCI
# manifest artifact MUST NOT have any completed scan with
# scan_type=dependency, because Grype's is_applicable() returns false
# for that artifact and the scanner pipeline skips it.
#
# Pre-fix behavior: a scan_results row with scan_type=dependency,
# total_findings=0, attributable to Grype (which silently produced
# "no findings" against the manifest JSON). This is the regression
# class -- a single dependency-typed scan row for an OCI artifact
# fails this gate.
#
# Skip semantics
# --------------
# If no scans complete within SCAN_TIMEOUT, the suite SKIPS rather
# than passes -- a backend with no scanners enabled cannot
# distinguish "Grype gated out correctly" from "no scanners at all",
# and we don't want a vacuous pass to mask a regression.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "grype-gated-out-of-oci"
require_cmd curl
require_cmd jq
auth_admin
setup_workdir

REPO_KEY="sec-grype-gate-${RUN_ID}"
IMAGE_NAME="gate-target"
UNIQUE_TAG="1.0.$(date +%s)"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-60}"

# ---------------------------------------------------------------------------
# Setup: docker (OCI) repo. The same format as test-oci.sh /
# test-trivy-scan.sh; this is the artifact type whose content-type
# routes through is_oci_image_artifact.
# ---------------------------------------------------------------------------

begin_test "Create docker/OCI local repo"
if create_local_repo "$REPO_KEY" "docker"; then
  add_exit_handler "api_delete /api/v1/repositories/${REPO_KEY} >/dev/null 2>&1 || true"
  pass
else
  fail "could not create docker repo (${REPO_KEY})"
fi

# ---------------------------------------------------------------------------
# OCI v2 registry token. /v2 endpoints use bearer tokens minted at
# /v2/token, distinct from /api/v1/auth/login JWTs.
# ---------------------------------------------------------------------------

begin_test "Obtain v2 registry token"
TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then
  TOKEN=$(echo "$token_resp" | jq -r '.token // empty')
fi
if [ -n "$TOKEN" ]; then
  pass
else
  fail "could not obtain v2 registry token"
fi

# ---------------------------------------------------------------------------
# Helper: chunked-upload one blob and return its digest. Mirrors the
# pattern in tests/security/test-trivy-scan.sh.
# ---------------------------------------------------------------------------

upload_blob() {
  local content="$1"
  local label="$2"
  local digest size
  digest="sha256:$(printf '%s' "$content" | shasum -a 256 | awk '{print $1}')"
  size=${#content}
  echo -n "$content" >"${WORK_DIR}/${label}.bin"

  # Step 1: POST to initiate upload, returns Location header.
  local headers_file="${WORK_DIR}/${label}-init-headers.txt"
  curl -s -D "${headers_file}" -o /dev/null \
    -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" >/dev/null 2>&1
  local loc
  loc=$(grep -i '^location:' "${headers_file}" | tr -d '\r' | awk '{print $2}') || true
  if [ -z "$loc" ]; then
    return 1
  fi
  local put_url
  if [[ "$loc" == http* ]]; then
    put_url="$loc"
  else
    put_url="${BASE_URL}${loc}"
  fi
  if [[ "$put_url" == *"?"* ]]; then
    put_url="${put_url}&digest=${digest}"
  else
    put_url="${put_url}?digest=${digest}"
  fi

  # Step 2: PUT the blob with digest query.
  local put_status
  put_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/${label}.bin" \
    "${put_url}") || put_status=000

  if [ "$put_status" != "201" ]; then
    return 1
  fi
  # Emit digest+size so the caller can interpolate them into the manifest.
  echo "${digest} ${size}"
  return 0
}

# ---------------------------------------------------------------------------
# Upload config + layer blobs. We need real blobs because the
# manifest PUT validates digest+size against the stored blobs (see
# handle_put_manifest in backend/src/api/handlers/oci_v2.rs).
# ---------------------------------------------------------------------------

begin_test "Upload config blob"
CONFIG_CONTENT='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}'
if config_info=$(upload_blob "$CONFIG_CONTENT" "config"); then
  read -r CONFIG_DIGEST CONFIG_SIZE <<<"$config_info"
  pass
else
  fail "config blob upload failed"
fi

begin_test "Upload layer blob"
LAYER_CONTENT="layer-content-${RUN_ID}-${UNIQUE_TAG}"
if layer_info=$(upload_blob "$LAYER_CONTENT" "layer"); then
  read -r LAYER_DIGEST LAYER_SIZE <<<"$layer_info"
  pass
else
  fail "layer blob upload failed"
fi

# ---------------------------------------------------------------------------
# PUT manifest. This is the artifact whose scan-pipeline routing we
# want to observe: its content_type and path BOTH place it in the
# OCI bucket for is_oci_image_artifact.
# ---------------------------------------------------------------------------

begin_test "PUT OCI manifest"
MANIFEST=$(jq -n \
  --arg cd "$CONFIG_DIGEST" --argjson cs "$CONFIG_SIZE" \
  --arg ld "$LAYER_DIGEST" --argjson ls "$LAYER_SIZE" \
  '{
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      digest: $cd,
      size: $cs
    },
    layers: [
      {
        mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
        digest: $ld,
        size: $ls
      }
    ]
  }')

manifest_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  -d "$MANIFEST" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/manifests/${UNIQUE_TAG}") || manifest_status=000

case "$manifest_status" in
  201 | 200)
    pass
    ;;
  *)
    fail "manifest PUT returned ${manifest_status}, expected 201"
    ;;
esac

# ---------------------------------------------------------------------------
# Resolve the manifest's artifact_id. The /v2 PUT does not return
# it directly; query the repository's artifacts list and pick the
# row whose path is `v2/{image}/manifests/{tag}` (the format
# handle_put_manifest uses, per oci_v2.rs:1664).
# ---------------------------------------------------------------------------

MANIFEST_PATH="v2/${IMAGE_NAME}/manifests/${UNIQUE_TAG}"

begin_test "Resolve manifest artifact_id from repository listing"
ARTIFACT_ID=""
artifacts_resp=$(curl -sf $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts?per_page=100" 2>/dev/null) || true
if [ -n "$artifacts_resp" ]; then
  ARTIFACT_ID=$(echo "$artifacts_resp" | jq -r --arg p "$MANIFEST_PATH" \
    '.items[]? | select(.path == $p) | .id' 2>/dev/null | head -1)
  # Some shapes use `.artifacts[]` instead of `.items[]`.
  if [ -z "$ARTIFACT_ID" ]; then
    ARTIFACT_ID=$(echo "$artifacts_resp" | jq -r --arg p "$MANIFEST_PATH" \
      '.artifacts[]? | select(.path == $p) | .id' 2>/dev/null | head -1)
  fi
fi
if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  pass
else
  fail "could not resolve artifact_id for path ${MANIFEST_PATH}; cannot assert scanner gating"
fi

# ---------------------------------------------------------------------------
# Trigger scan(s) on the manifest artifact. The backend dispatches
# applicable scanners; Grype's is_applicable should return false for
# this artifact (post-#1164), so Grype is skipped. Other scanners
# (ImageScanner via Trivy) may or may not run depending on backend
# wiring -- we don't assert their presence here, only Grype's
# absence.
# ---------------------------------------------------------------------------

begin_test "Trigger scan via /api/v1/security/scan"
trigger_payload=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id}')
trigger_status=$(curl -s -o "${WORK_DIR}/trigger-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$trigger_payload" \
  "${BASE_URL}/api/v1/security/scan") || trigger_status=000
case "$trigger_status" in
  2*)
    pass
    ;;
  *)
    fail "scan trigger returned HTTP ${trigger_status}; cannot assert gating"
    ;;
esac

# ---------------------------------------------------------------------------
# Poll the per-artifact scans list until at least one scan completes
# OR the timeout expires. We do NOT require a completed scan to
# exist -- a backend with no scanners enabled produces zero rows --
# but we DO require that NO completed scan for this artifact has
# scan_type=dependency.
# ---------------------------------------------------------------------------

begin_test "Poll per-artifact scans for completion"
elapsed=0
sleep_step=5
completed_count=0
scans_endpoint="${BASE_URL}/api/v1/security/artifacts/${ARTIFACT_ID}/scans?per_page=50"
SCANS_RESP="${WORK_DIR}/scans-resp.json"

while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  http_code=$(curl -s -o "$SCANS_RESP" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${scans_endpoint}") || http_code=000
  if [ "$http_code" = "200" ]; then
    completed_count=$(jq '[.items[]? | select(.status == "completed")] | length' "$SCANS_RESP" 2>/dev/null || echo 0)
    if [ "$completed_count" -ge 1 ]; then
      break
    fi
  fi
  sleep "$sleep_step"
  elapsed=$((elapsed + sleep_step))
done

if [ "$completed_count" -ge 1 ]; then
  pass
else
  skip "no scan completed within ${SCAN_TIMEOUT}s; cannot distinguish 'Grype correctly gated out' from 'no scanners enabled'. Suite passes vacuously below; rerun in a deploy with at least one applicable scanner wired up."
fi

# ---------------------------------------------------------------------------
# The load-bearing assertion: among completed scans for this OCI
# manifest artifact, NONE may have scan_type=dependency. Grype is
# the dependency scanner; #1164 gated it out via is_applicable.
# ---------------------------------------------------------------------------

begin_test "No completed scan has scan_type=dependency (Grype gated out per #1164)"
if [ "$completed_count" -ge 1 ]; then
  dep_count=$(jq '[.items[]? | select(.status == "completed" and .scan_type == "dependency")] | length' "$SCANS_RESP" 2>/dev/null || echo 0)
  if [ "$dep_count" -eq 0 ]; then
    pass
  else
    dep_dump=$(jq -c '.items[]? | select(.status == "completed" and .scan_type == "dependency") | {id, scan_type, status, total_findings}' "$SCANS_RESP" 2>/dev/null | head -3 | tr '\n' ' ')
    fail "found ${dep_count} completed dependency-typed scan(s) on OCI manifest artifact; #1164 regression. Examples: ${dep_dump}"
  fi
else
  skip "no completed scans observed; cannot assert Grype absence"
fi

end_suite
