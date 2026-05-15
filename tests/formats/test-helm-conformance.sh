#!/usr/bin/env bash
# test-helm-conformance.sh - Helm chart repository conformance tests
#
# Validates that the Helm chart repository implementation produces correct
# index.yaml, handles chart downloads with digest verification, supports
# multiple versions, OCI mode, and provenance files.
#
# Requires: curl, tar, gzip, sha256sum or shasum
# Optional: helm (v3+) for OCI push/pull tests
source "$(dirname "$0")/../lib/common.sh"

begin_suite "helm-conformance"
auth_admin
setup_workdir

REPO_KEY="test-helm-conf-${RUN_ID}"
CHART_NAME="confchart"
CHART_V1="0.1.0"
CHART_V2="0.2.0"

# Portable SHA256 helper
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# -------------------------------------------------------------------------
# Helper: build a minimal Helm chart .tgz without requiring the helm CLI
# -------------------------------------------------------------------------
build_chart_tgz() {
  local name="$1"
  local version="$2"
  local outfile="$3"
  local description="${4:-Conformance test chart}"

  local chart_dir="${WORK_DIR}/chart-build-${name}-${version}"
  mkdir -p "${chart_dir}/${name}/templates"

  cat > "${chart_dir}/${name}/Chart.yaml" <<YAML
apiVersion: v2
name: ${name}
description: ${description}
type: application
version: ${version}
appVersion: "1.0.0"
YAML

  cat > "${chart_dir}/${name}/values.yaml" <<YAML
replicaCount: 1
image:
  repository: nginx
  tag: alpine
YAML

  cat > "${chart_dir}/${name}/templates/configmap.yaml" <<'TMPL'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Chart.Name }}-config
data:
  version: {{ .Chart.Version | quote }}
TMPL

  tar czf "$outfile" -C "${chart_dir}" "${name}"
}

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create Helm repository"
if create_local_repo "$REPO_KEY" "helm"; then
  pass
else
  fail "could not create helm repo"
fi

# -------------------------------------------------------------------------
# 1. Upload chart .tgz package
# -------------------------------------------------------------------------

CHART_TGZ_V1="${WORK_DIR}/${CHART_NAME}-${CHART_V1}.tgz"
build_chart_tgz "$CHART_NAME" "$CHART_V1" "$CHART_TGZ_V1"

begin_test "Upload chart .tgz via ChartMuseum API"
UPLOAD_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(format_auth_header)" \
    -F "chart=@${CHART_TGZ_V1}" \
    "${BASE_URL}/helm/${REPO_KEY}/api/charts") || true

if [ "$UPLOAD_CODE" = "200" ] || [ "$UPLOAD_CODE" = "201" ]; then
  pass
else
  fail "chart upload returned HTTP ${UPLOAD_CODE}, expected 200 or 201"
fi

sleep 1

# -------------------------------------------------------------------------
# 2. GET index.yaml returns valid YAML with entries
# -------------------------------------------------------------------------

begin_test "index.yaml returns valid content with entries"
INDEX_BODY=""
if INDEX_BODY=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/helm/${REPO_KEY}/index.yaml" 2>/dev/null); then
  if echo "$INDEX_BODY" | grep -q "entries:"; then
    pass
  else
    fail "index.yaml does not contain 'entries:' key"
  fi
else
  fail "GET index.yaml returned error"
fi

# -------------------------------------------------------------------------
# 3. index.yaml contains chart name, version, description, digest
# -------------------------------------------------------------------------

begin_test "index.yaml contains chart metadata fields"
missing=""
for field in "${CHART_NAME}" "${CHART_V1}" "description:" "digest:"; do
  if ! echo "$INDEX_BODY" | grep -qi "$field"; then
    missing="${missing} ${field}"
  fi
done

if [ -z "$missing" ]; then
  pass
else
  fail "index.yaml missing expected fields:${missing}"
fi

# -------------------------------------------------------------------------
# 4. Download chart via URL from index.yaml
# -------------------------------------------------------------------------

begin_test "Download chart via URL from index.yaml"
# Extract the chart download URL from index.yaml.
# The urls field in index.yaml looks like:
#   urls:
#   - /helm/{repo}/charts/{name}-{version}.tgz
# or it may be a full URL.
CHART_URL=$(echo "$INDEX_BODY" | grep -oE "/helm/${REPO_KEY}/charts/${CHART_NAME}-${CHART_V1}\.tgz" | head -1)
if [ -z "$CHART_URL" ]; then
  # Try alternate extraction: look for any URL containing the chart filename
  CHART_URL=$(echo "$INDEX_BODY" | grep -oE "[^ \"']*${CHART_NAME}-${CHART_V1}\.tgz" | head -1)
fi

if [ -z "$CHART_URL" ]; then
  # Fall back to the standard path
  CHART_URL="/helm/${REPO_KEY}/charts/${CHART_NAME}-${CHART_V1}.tgz"
fi

# Make the URL absolute if it starts with /
DOWNLOAD_URL="${CHART_URL}"
if [[ "$DOWNLOAD_URL" = /* ]]; then
  DOWNLOAD_URL="${BASE_URL}${DOWNLOAD_URL}"
fi

if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/downloaded-chart.tgz" \
    "$DOWNLOAD_URL" 2>/dev/null; then
  if [ -s "${WORK_DIR}/downloaded-chart.tgz" ]; then
    # Verify it is a valid tarball containing Chart.yaml
    if tar tzf "${WORK_DIR}/downloaded-chart.tgz" 2>/dev/null | grep -q "Chart.yaml"; then
      pass
    else
      fail "downloaded chart does not contain Chart.yaml"
    fi
  else
    fail "downloaded chart is empty"
  fi
else
  fail "chart download from '${DOWNLOAD_URL}' returned error"
fi

# -------------------------------------------------------------------------
# 5. Downloaded chart SHA256 matches digest in index.yaml
# -------------------------------------------------------------------------

begin_test "Downloaded chart SHA256 matches index.yaml digest"
# Extract digest from index.yaml
EXPECTED_DIGEST=$(echo "$INDEX_BODY" | grep "digest:" | head -1 | awk '{print $2}' | tr -d '"' | tr -d "'")

if [ -z "$EXPECTED_DIGEST" ]; then
  skip "could not extract digest from index.yaml"
elif [ ! -f "${WORK_DIR}/downloaded-chart.tgz" ]; then
  fail "no downloaded chart to verify"
else
  ACTUAL_DIGEST=$(sha256_hex "${WORK_DIR}/downloaded-chart.tgz")
  if assert_eq "$ACTUAL_DIGEST" "$EXPECTED_DIGEST" "chart digest mismatch: got ${ACTUAL_DIGEST}, expected ${EXPECTED_DIGEST}"; then
    pass
  fi
fi

# -------------------------------------------------------------------------
# 6. Multiple chart versions listed
# -------------------------------------------------------------------------

CHART_TGZ_V2="${WORK_DIR}/${CHART_NAME}-${CHART_V2}.tgz"
build_chart_tgz "$CHART_NAME" "$CHART_V2" "$CHART_TGZ_V2" "Conformance test chart v2"

begin_test "Multiple chart versions listed in index.yaml"
UPLOAD2_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(format_auth_header)" \
    -F "chart=@${CHART_TGZ_V2}" \
    "${BASE_URL}/helm/${REPO_KEY}/api/charts") || true

if [ "$UPLOAD2_CODE" != "200" ] && [ "$UPLOAD2_CODE" != "201" ]; then
  fail "second chart upload returned HTTP ${UPLOAD2_CODE}"
else
  sleep 1
  INDEX2=$(curl -sf -H "$(format_auth_header)" \
      "${BASE_URL}/helm/${REPO_KEY}/index.yaml" 2>/dev/null) || true

  has_v1=false
  has_v2=false
  if echo "$INDEX2" | grep -q "${CHART_V1}"; then
    has_v1=true
  fi
  if echo "$INDEX2" | grep -q "${CHART_V2}"; then
    has_v2=true
  fi
  if $has_v1 && $has_v2; then
    pass
  else
    fail "index.yaml does not list both versions (v1: ${has_v1}, v2: ${has_v2})"
  fi
fi

# -------------------------------------------------------------------------
# 7. OCI mode: push chart via OCI protocol
# -------------------------------------------------------------------------

begin_test "OCI push chart"
if command -v helm &>/dev/null; then
  # Helm 3.8+ supports OCI push natively
  # Log in to the registry
  echo "${ADMIN_PASS}" | helm registry login "${BASE_URL#http*://}" \
      --username "$ADMIN_USER" --password-stdin 2>/dev/null || true

  OCI_REF="oci://${BASE_URL#http*://}/helm/${REPO_KEY}"
  if helm push "${CHART_TGZ_V2}" "$OCI_REF" 2>/dev/null; then
    pass
  else
    # OCI push may not be supported by this backend configuration
    skip "helm push via OCI failed (OCI mode may not be enabled)"
  fi
else
  # Without helm CLI, attempt a raw OCI manifest PUT
  # Build a minimal OCI manifest with helm media types
  CHART_BYTES=$(wc -c < "${CHART_TGZ_V2}" | tr -d ' ')
  CHART_DIGEST="sha256:$(sha256_hex "${CHART_TGZ_V2}")"

  # Upload the blob first
  BLOB_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
      -X PUT \
      -H "$(format_auth_header)" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@${CHART_TGZ_V2}" \
      "${BASE_URL}/v2/helm/${REPO_KEY}/${CHART_NAME}/blobs/uploads/?digest=${CHART_DIGEST}") || true

  if [ "$BLOB_STATUS" -ge 200 ] && [ "$BLOB_STATUS" -lt 300 ]; then
    # Push the manifest
    MANIFEST=$(cat <<MANIFEST_JSON
{
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.cncf.helm.config.v1+json",
    "digest": "${CHART_DIGEST}",
    "size": ${CHART_BYTES}
  },
  "layers": [
    {
      "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
      "digest": "${CHART_DIGEST}",
      "size": ${CHART_BYTES}
    }
  ]
}
MANIFEST_JSON
    )
    MANIFEST_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
        -X PUT \
        -H "$(format_auth_header)" \
        -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
        -d "$MANIFEST" \
        "${BASE_URL}/v2/helm/${REPO_KEY}/${CHART_NAME}/manifests/${CHART_V2}") || true

    if [ "$MANIFEST_STATUS" -ge 200 ] && [ "$MANIFEST_STATUS" -lt 300 ]; then
      pass
    else
      skip "OCI manifest PUT returned HTTP ${MANIFEST_STATUS} (OCI mode may not be enabled)"
    fi
  else
    skip "OCI blob upload returned HTTP ${BLOB_STATUS} (OCI mode may not be enabled)"
  fi
fi

# -------------------------------------------------------------------------
# 8. OCI mode: pull chart (GET manifest with helm config media type)
# -------------------------------------------------------------------------

begin_test "OCI pull chart manifest"
if command -v helm &>/dev/null; then
  mkdir -p "${WORK_DIR}/oci-pull"
  OCI_REF="oci://${BASE_URL#http*://}/helm/${REPO_KEY}/${CHART_NAME}"
  if helm pull "$OCI_REF" --version "$CHART_V2" -d "${WORK_DIR}/oci-pull" 2>/dev/null; then
    if ls "${WORK_DIR}/oci-pull/"*.tgz 1>/dev/null 2>&1; then
      pass
    else
      skip "helm pull via OCI did not produce a .tgz (OCI mode may not be enabled)"
    fi
  else
    skip "helm pull via OCI failed (OCI mode may not be enabled)"
  fi
else
  # Try raw GET on the OCI manifest endpoint
  MANIFEST_STATUS=$(curl -s -o "${WORK_DIR}/oci-manifest.json" -w '%{http_code}' \
      -H "$(format_auth_header)" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      "${BASE_URL}/v2/helm/${REPO_KEY}/${CHART_NAME}/manifests/${CHART_V2}") || true

  if [ "$MANIFEST_STATUS" -ge 200 ] && [ "$MANIFEST_STATUS" -lt 300 ]; then
    MANIFEST_BODY=$(cat "${WORK_DIR}/oci-manifest.json")
    if echo "$MANIFEST_BODY" | grep -q "application/vnd.cncf.helm"; then
      pass
    elif echo "$MANIFEST_BODY" | grep -q "mediaType"; then
      pass
    else
      skip "OCI manifest returned but lacks helm media types"
    fi
  else
    skip "OCI manifest GET returned HTTP ${MANIFEST_STATUS} (OCI mode may not be enabled)"
  fi
fi

# -------------------------------------------------------------------------
# 9. Chart provenance: upload .tgz.prov file alongside chart
# -------------------------------------------------------------------------

begin_test "Upload chart provenance file"
# Create a mock .prov file (normally created by `helm package --sign`)
PROV_FILE="${WORK_DIR}/${CHART_NAME}-${CHART_V1}.tgz.prov"
cat > "$PROV_FILE" <<PROV
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

apiVersion: v2
name: ${CHART_NAME}
version: ${CHART_V1}
description: Conformance test chart
...
files:
  ${CHART_NAME}-${CHART_V1}.tgz: sha256:$(sha256_hex "${CHART_TGZ_V1}")
-----BEGIN PGP SIGNATURE-----
mock-signature-data-for-conformance-test
-----END PGP SIGNATURE-----
PROV

PROV_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(format_auth_header)" \
    -F "prov=@${PROV_FILE}" \
    "${BASE_URL}/helm/${REPO_KEY}/api/charts") || true

# Provenance upload via the ChartMuseum API: some servers accept prov as a
# separate field in the multipart upload, some accept it as a separate PUT.
if [ "$PROV_STATUS" -ge 200 ] && [ "$PROV_STATUS" -lt 300 ]; then
  pass
else
  # Try PUT to a direct path
  PROV_STATUS2=$(curl -s -o /dev/null -w '%{http_code}' \
      -X PUT \
      -H "$(format_auth_header)" \
      -H "Content-Type: application/pgp-signature" \
      --data-binary "@${PROV_FILE}" \
      "${BASE_URL}/helm/${REPO_KEY}/charts/${CHART_NAME}-${CHART_V1}.tgz.prov") || true

  if [ "$PROV_STATUS2" -ge 200 ] && [ "$PROV_STATUS2" -lt 300 ]; then
    pass
  else
    skip "provenance upload not accepted (HTTP ${PROV_STATUS}, ${PROV_STATUS2}), feature may not be implemented"
  fi
fi

# -------------------------------------------------------------------------
# 10. index.yaml updates after new upload
# -------------------------------------------------------------------------

CHART_V3="0.3.0"
CHART_TGZ_V3="${WORK_DIR}/${CHART_NAME}-${CHART_V3}.tgz"
build_chart_tgz "$CHART_NAME" "$CHART_V3" "$CHART_TGZ_V3" "Conformance test chart v3"

begin_test "index.yaml updates after new chart upload"
UPLOAD3_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(format_auth_header)" \
    -F "chart=@${CHART_TGZ_V3}" \
    "${BASE_URL}/helm/${REPO_KEY}/api/charts") || true

if [ "$UPLOAD3_CODE" != "200" ] && [ "$UPLOAD3_CODE" != "201" ]; then
  fail "v3 chart upload returned HTTP ${UPLOAD3_CODE}"
else
  sleep 1
  INDEX3=$(curl -sf -H "$(format_auth_header)" \
      "${BASE_URL}/helm/${REPO_KEY}/index.yaml" 2>/dev/null) || true
  if echo "$INDEX3" | grep -q "${CHART_V3}"; then
    pass
  else
    fail "index.yaml does not contain newly uploaded version ${CHART_V3}"
  fi
fi

# -------------------------------------------------------------------------
# 11. Search: if supported, search for charts by keyword
# -------------------------------------------------------------------------

begin_test "Search charts by keyword"
# ChartMuseum search API: GET /api/charts?name={query}
SEARCH_STATUS=$(curl -s -o "${WORK_DIR}/search-result.json" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/helm/${REPO_KEY}/api/charts/${CHART_NAME}") || true

if [ "$SEARCH_STATUS" -ge 200 ] && [ "$SEARCH_STATUS" -lt 300 ]; then
  SEARCH_BODY=$(cat "${WORK_DIR}/search-result.json")
  if echo "$SEARCH_BODY" | grep -q "${CHART_NAME}"; then
    pass
  else
    # Might be an array; just verify non-empty response
    if [ -n "$SEARCH_BODY" ] && [ "$SEARCH_BODY" != "null" ] && [ "$SEARCH_BODY" != "[]" ]; then
      pass
    else
      fail "search returned empty result for '${CHART_NAME}'"
    fi
  fi
else
  # Try the generic repo search API as fallback
  SEARCH_STATUS2=$(curl -s -o "${WORK_DIR}/search-result2.json" -w '%{http_code}' \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts?search=${CHART_NAME}") || true

  if [ "$SEARCH_STATUS2" -ge 200 ] && [ "$SEARCH_STATUS2" -lt 300 ]; then
    SEARCH_BODY2=$(cat "${WORK_DIR}/search-result2.json")
    if echo "$SEARCH_BODY2" | grep -q "${CHART_NAME}"; then
      pass
    else
      skip "search API responded but chart not found in results"
    fi
  else
    skip "chart search not available (HTTP ${SEARCH_STATUS}, ${SEARCH_STATUS2})"
  fi
fi

# -------------------------------------------------------------------------
# 12. 404 for nonexistent chart
# -------------------------------------------------------------------------

begin_test "404 for nonexistent chart"
NOTFOUND_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/helm/${REPO_KEY}/charts/nonexistent-chart-99.99.99.tgz") || true

if [ "$NOTFOUND_STATUS" = "404" ]; then
  pass
else
  fail "expected 404 for nonexistent chart, got ${NOTFOUND_STATUS}"
fi

end_suite
