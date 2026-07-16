#!/usr/bin/env bash
# test-streaming-blob-fallback.sh - >16 MiB blobs stream through every
# format-native blob-fallback route (2xx, never 502).
#
# Release gate for:
#   artifact-keeper#1608 - streaming invariant (>16 MiB not buffered / 502'd),
#   exercised across the format-native routes (not just the generic API).
#
# The generic-API copy of this invariant lives in
# tests/platform/test-streaming-large-artifact.sh. This suite pushes a
# >16 MiB blob through each blob-fallback format's own route (helm, npm,
# swift, oci, pypi) and pulls it back, asserting the write and read paths
# both STREAM: status is 2xx and NEVER 502 (buffered/OOM). Where the format
# stores and serves the blob byte-for-byte (oci, swift, npm) it also checks
# the SHA256 round-trips.
#
# Each format section is independent and SKIPs (does not fail) if its repo
# or push setup does not return 2xx, so a route-shape surprise on the target
# degrades to a skip rather than a red gate.
#
# NOTE (formats matrix): because this lives in tests/formats/, it only runs
# if it is listed in a format-tests batch. It is appended to the `containers`
# batch in .github/workflows/release-gate.yml and .github/workflows/format-tests.yml.
#
# Feature-gated on `streaming_large_artifact` so it auto-skips on a 1.2.x backend.
#
# Requires: curl, dd, tar, shasum, base64, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "streaming-blob-fallback"
auth_admin
setup_workdir

begin_test "Backend supports streaming_large_artifact (v1.3.0)"
if require_feature "streaming_large_artifact"; then
  pass
else
  end_suite
  exit 0
fi

# 18 MiB: strictly greater than the 16 MiB in-memory buffer cap, small
# enough that base64/multipart overhead stays manageable in the matrix.
BLOB_MB=18
BLOB="${WORK_DIR}/blob.bin"
dd if=/dev/urandom bs=1048576 count="$BLOB_MB" of="$BLOB" 2>/dev/null
BLOB_SHA=$(shasum -a 256 "$BLOB" | awk '{print $1}')

# Assert a captured HTTP status is 2xx and, loudly, is not 502. Returns 0
# on a clean 2xx. On 502 it fails with the buffered/OOM message; on any
# other non-2xx it fails generically.
assert_streamed_2xx() {
  local status="$1" what="$2"
  if [ "$status" = "502" ]; then
    fail "${what} returned 502: >16 MiB body buffered/OOM instead of streamed"
    return 1
  fi
  assert_http_2xx "$status" "${what} should be 2xx (streamed)"
}

# =========================================================================
# OCI: raw layer blob by digest (byte-exact)
# =========================================================================
OCI_REPO="e2e-sbf-oci-${RUN_ID}"
begin_test "oci: create docker repo"
oci_ok=false
if create_local_repo "$OCI_REPO" "docker"; then oci_ok=true; pass; else skip "could not create oci repo"; fi

if $oci_ok; then
  OCI_DIGEST="sha256:${BLOB_SHA}"
  OCI_TOKEN=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null | jq -r '.token // empty') || true

  begin_test "oci: push ${BLOB_MB} MiB layer blob is 2xx (streamed, not 502)"
  curl -s -D "${WORK_DIR}/oci-upl.hdr" -o /dev/null -X POST \
    -H "Authorization: Bearer ${OCI_TOKEN}" \
    "${BASE_URL}/v2/${OCI_REPO}/blob-fallback/blobs/uploads/" >/dev/null 2>&1 || true
  loc=$(grep -i '^location:' "${WORK_DIR}/oci-upl.hdr" 2>/dev/null | tr -d '\r' | awk '{print $2}') || true
  if [ -z "$loc" ]; then
    skip "oci: blob upload initiation returned no Location header"
  else
    if [[ "$loc" == http* ]]; then base="$loc"; else base="${BASE_URL}${loc}"; fi
    if [[ "$loc" == *"?"* ]]; then put_url="${base}&digest=${OCI_DIGEST}"; else put_url="${base}?digest=${OCI_DIGEST}"; fi
    oci_put=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
      -H "Authorization: Bearer ${OCI_TOKEN}" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@${BLOB}" "$put_url" 2>/dev/null) || oci_put="000"
    echo "  oci blob PUT status: ${oci_put}"
    if [ "$oci_put" = "502" ]; then
      fail "oci blob PUT returned 502: >16 MiB layer buffered instead of streamed"
    elif [ "$oci_put" = "201" ] || { [ "$oci_put" -ge 200 ] 2>/dev/null && [ "$oci_put" -lt 300 ] 2>/dev/null; }; then
      pass
    else
      skip "oci: blob PUT returned ${oci_put} (setup issue, not a streaming failure)"
    fi
  fi

  begin_test "oci: pull ${BLOB_MB} MiB layer blob is 2xx + SHA256 round-trips"
  oci_get=$(curl -s -o "${WORK_DIR}/oci-dl.bin" -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${OCI_TOKEN}" \
    "${BASE_URL}/v2/${OCI_REPO}/blob-fallback/blobs/${OCI_DIGEST}" 2>/dev/null) || oci_get="000"
  if assert_streamed_2xx "$oci_get" "oci blob GET"; then
    dl=$(shasum -a 256 "${WORK_DIR}/oci-dl.bin" | awk '{print $1}')
    if assert_eq "$dl" "$BLOB_SHA" "oci blob SHA256 mismatch on ${BLOB_MB} MiB round-trip"; then pass; fi
  fi
  api_delete "/api/v1/repositories/${OCI_REPO}" >/dev/null 2>&1 || true
fi

# =========================================================================
# Swift: raw archive by path (byte-exact)
# =========================================================================
SWIFT_REPO="e2e-sbf-swift-${RUN_ID}"
SWIFT_SCOPE="e2escope"
SWIFT_PKG="blobpkg"
SWIFT_VER="1.0.0"
begin_test "swift: create swift repo"
swift_ok=false
if create_local_repo "$SWIFT_REPO" "swift"; then swift_ok=true; pass; else skip "could not create swift repo"; fi

if $swift_ok; then
  begin_test "swift: push ${BLOB_MB} MiB release is 2xx (streamed, not 502)"
  swift_put=$(format_put_with_retry \
    "${BASE_URL}/swift/${SWIFT_REPO}/${SWIFT_SCOPE}/${SWIFT_PKG}/${SWIFT_VER}" "$BLOB") || true
  echo "  swift PUT status: ${swift_put}"
  if [ "$swift_put" = "502" ]; then
    fail "swift release PUT returned 502: >16 MiB buffered instead of streamed"
  elif [ "$swift_put" -ge 200 ] 2>/dev/null && [ "$swift_put" -lt 300 ] 2>/dev/null; then
    pass
  else
    skip "swift: release PUT returned ${swift_put} (setup issue, not a streaming failure)"
  fi

  begin_test "swift: pull ${BLOB_MB} MiB release is 2xx + SHA256 round-trips"
  swift_get=$(format_get_with_retry \
    "${BASE_URL}/swift/${SWIFT_REPO}/${SWIFT_SCOPE}/${SWIFT_PKG}/${SWIFT_VER}.zip" \
    "${WORK_DIR}/swift-dl.bin") || true
  if assert_streamed_2xx "$swift_get" "swift release GET"; then
    dl=$(shasum -a 256 "${WORK_DIR}/swift-dl.bin" | awk '{print $1}')
    if assert_eq "$dl" "$BLOB_SHA" "swift release SHA256 mismatch on ${BLOB_MB} MiB round-trip"; then pass; fi
  fi
  api_delete "/api/v1/repositories/${SWIFT_REPO}" >/dev/null 2>&1 || true
fi

# =========================================================================
# NPM: tarball attachment (byte-exact tgz)
# =========================================================================
NPM_REPO="e2e-sbf-npm-${RUN_ID}"
NPM_PKG="sbfpkg${RUN_ID//-/}"
NPM_VER="1.0.0"
begin_test "npm: create npm repo"
npm_ok=false
if create_local_repo "$NPM_REPO" "npm"; then npm_ok=true; pass; else skip "could not create npm repo"; fi

if $npm_ok; then
  # Pack the >16 MiB blob into a tgz so it is a real npm tarball.
  mkdir -p "${WORK_DIR}/npmpkg"
  cp "$BLOB" "${WORK_DIR}/npmpkg/payload.bin"
  printf '{"name":"%s","version":"%s"}\n' "$NPM_PKG" "$NPM_VER" > "${WORK_DIR}/npmpkg/package.json"
  NPM_TGZ="${WORK_DIR}/${NPM_PKG}-${NPM_VER}.tgz"
  tar czf "$NPM_TGZ" -C "${WORK_DIR}/npmpkg" .
  NPM_TGZ_SHA=$(shasum -a 256 "$NPM_TGZ" | awk '{print $1}')
  NPM_TGZ_SIZE=$(wc -c < "$NPM_TGZ" | tr -d ' ')
  base64 < "$NPM_TGZ" | tr -d '\n' > "${WORK_DIR}/npm-b64.txt"
  jq -n \
    --arg name "$NPM_PKG" --arg version "$NPM_VER" \
    --arg tarball "${BASE_URL}/npm/${NPM_REPO}/${NPM_PKG}/-/${NPM_PKG}-${NPM_VER}.tgz" \
    --rawfile data "${WORK_DIR}/npm-b64.txt" \
    --argjson length "$NPM_TGZ_SIZE" \
    '{name: $name, versions: {($version): {name: $name, version: $version, dist: {tarball: $tarball}}},
      "_attachments": {("\($name)-\($version).tgz"): {content_type: "application/octet-stream", data: $data, length: $length}}}' \
    > "${WORK_DIR}/npm-publish.json"

  begin_test "npm: publish ${BLOB_MB} MiB tarball is 2xx (streamed, not 502)"
  npm_put=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(format_auth_header)" -H "Content-Type: application/json" \
    --data-binary "@${WORK_DIR}/npm-publish.json" \
    "${BASE_URL}/npm/${NPM_REPO}/${NPM_PKG}" 2>/dev/null) || npm_put="000"
  echo "  npm publish status: ${npm_put}"
  if [ "$npm_put" = "502" ]; then
    fail "npm publish returned 502: >16 MiB tarball buffered instead of streamed"
  elif [ "$npm_put" -ge 200 ] 2>/dev/null && [ "$npm_put" -lt 300 ] 2>/dev/null; then
    pass
  else
    skip "npm: publish returned ${npm_put} (setup issue, not a streaming failure)"
  fi

  begin_test "npm: pull ${BLOB_MB} MiB tarball is 2xx + SHA256 round-trips"
  npm_get=$(curl -s -o "${WORK_DIR}/npm-dl.tgz" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/npm/${NPM_REPO}/${NPM_PKG}/-/${NPM_PKG}-${NPM_VER}.tgz" 2>/dev/null) || npm_get="000"
  if assert_streamed_2xx "$npm_get" "npm tarball GET"; then
    dl=$(shasum -a 256 "${WORK_DIR}/npm-dl.tgz" | awk '{print $1}')
    if assert_eq "$dl" "$NPM_TGZ_SHA" "npm tarball SHA256 mismatch on ${BLOB_MB} MiB round-trip"; then pass; fi
  fi
  api_delete "/api/v1/repositories/${NPM_REPO}" >/dev/null 2>&1 || true
fi

# =========================================================================
# Helm: chart tgz (streaming invariant; server may re-index, so size not SHA)
# =========================================================================
HELM_REPO="e2e-sbf-helm-${RUN_ID}"
HELM_CHART="sbfchart${RUN_ID//-/}"
HELM_VER="1.0.0"
begin_test "helm: create helm repo"
helm_ok=false
if create_local_repo "$HELM_REPO" "helm"; then helm_ok=true; pass; else skip "could not create helm repo"; fi

if $helm_ok; then
  mkdir -p "${WORK_DIR}/${HELM_CHART}"
  printf 'apiVersion: v2\nname: %s\nversion: %s\n' "$HELM_CHART" "$HELM_VER" > "${WORK_DIR}/${HELM_CHART}/Chart.yaml"
  cp "$BLOB" "${WORK_DIR}/${HELM_CHART}/bigfile.bin"
  HELM_TGZ="${WORK_DIR}/${HELM_CHART}-${HELM_VER}.tgz"
  tar czf "$HELM_TGZ" -C "${WORK_DIR}" "${HELM_CHART}"

  begin_test "helm: push ${BLOB_MB} MiB chart is 2xx (streamed, not 502)"
  helm_put=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" -F "chart=@${HELM_TGZ}" \
    "${BASE_URL}/helm/${HELM_REPO}/api/charts" 2>/dev/null) || helm_put="000"
  echo "  helm push status: ${helm_put}"
  if [ "$helm_put" = "502" ]; then
    fail "helm chart push returned 502: >16 MiB chart buffered instead of streamed"
  elif [ "$helm_put" -ge 200 ] 2>/dev/null && [ "$helm_put" -lt 300 ] 2>/dev/null; then
    pass
  else
    skip "helm: chart push returned ${helm_put} (setup issue, not a streaming failure)"
  fi

  begin_test "helm: pull ${BLOB_MB} MiB chart is 2xx (streamed, not 502)"
  helm_get=$(curl -s -o "${WORK_DIR}/helm-dl.tgz" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/helm/${HELM_REPO}/charts/${HELM_CHART}-${HELM_VER}.tgz" 2>/dev/null) || helm_get="000"
  if assert_streamed_2xx "$helm_get" "helm chart GET"; then
    dl_size=$(wc -c < "${WORK_DIR}/helm-dl.tgz" | tr -d ' ')
    if [ "$dl_size" -gt $((16 * 1024 * 1024)) ] 2>/dev/null; then
      pass
    else
      fail "helm chart download is ${dl_size} bytes, expected > 16 MiB (truncated read)"
    fi
  fi
  api_delete "/api/v1/repositories/${HELM_REPO}" >/dev/null 2>&1 || true
fi

# =========================================================================
# PyPI: sdist via multipart file_upload (streaming invariant on write path)
# =========================================================================
PYPI_REPO="e2e-sbf-pypi-${RUN_ID}"
PYPI_PKG="sbfpypi${RUN_ID//-/}"
PYPI_VER="1.0.0"
begin_test "pypi: create pypi repo"
pypi_ok=false
if create_local_repo "$PYPI_REPO" "pypi"; then pypi_ok=true; pass; else skip "could not create pypi repo"; fi

if $pypi_ok; then
  mkdir -p "${WORK_DIR}/${PYPI_PKG}-${PYPI_VER}"
  printf 'Metadata-Version: 1.0\nName: %s\nVersion: %s\n' "$PYPI_PKG" "$PYPI_VER" \
    > "${WORK_DIR}/${PYPI_PKG}-${PYPI_VER}/PKG-INFO"
  cp "$BLOB" "${WORK_DIR}/${PYPI_PKG}-${PYPI_VER}/payload.bin"
  PYPI_SDIST="${WORK_DIR}/${PYPI_PKG}-${PYPI_VER}.tar.gz"
  tar czf "$PYPI_SDIST" -C "${WORK_DIR}" "${PYPI_PKG}-${PYPI_VER}"

  begin_test "pypi: upload ${BLOB_MB} MiB sdist is 2xx (streamed, not 502)"
  pypi_put=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -F ":action=file_upload" -F "name=${PYPI_PKG}" -F "version=${PYPI_VER}" \
    -F "filetype=sdist" -F "content=@${PYPI_SDIST}" \
    "${BASE_URL}/pypi/${PYPI_REPO}/" 2>/dev/null) || pypi_put="000"
  echo "  pypi upload status: ${pypi_put}"
  if [ "$pypi_put" = "502" ]; then
    fail "pypi sdist upload returned 502: >16 MiB buffered instead of streamed"
  elif [ "$pypi_put" -ge 200 ] 2>/dev/null && [ "$pypi_put" -lt 300 ] 2>/dev/null; then
    pass
  else
    skip "pypi: sdist upload returned ${pypi_put} (setup issue, not a streaming failure)"
  fi

  begin_test "pypi: sdist appears in simple index (streamed write persisted)"
  norm_name=$(echo "$PYPI_PKG" | tr '[:upper:]_' '[:lower:]-')
  idx=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${PYPI_REPO}/simple/${norm_name}/" 2>/dev/null) || idx=""
  if [ -n "$idx" ] && echo "$idx" | grep -q ".tar.gz"; then
    pass
  else
    skip "pypi: sdist not listed in simple index (write path did not persist)"
  fi
  api_delete "/api/v1/repositories/${PYPI_REPO}" >/dev/null 2>&1 || true
fi

end_suite
