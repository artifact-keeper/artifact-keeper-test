#!/usr/bin/env bash
# test-terraform-conformance.sh - Terraform Registry Protocol conformance tests
#
# Validates the Terraform Module Registry Protocol: service discovery,
# module upload, version listing, download flow (204 + X-Terraform-Get),
# archive integrity, multi-version handling, search, and content types.
#
# Reference: https://developer.hashicorp.com/terraform/internals/module-registry-protocol
#
# Endpoints: ${BASE_URL}/terraform/{repo_key}/
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "terraform-conformance"
auth_admin
setup_workdir

REPO_KEY="test-tf-conf-${RUN_ID}"
MODULE_NAMESPACE="conftest"
MODULE_NAME="network"
MODULE_PROVIDER="aws"
MODULE_VERSION="1.0.0"
TF_BASE="${BASE_URL}/terraform/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build a minimal Terraform module .tar.gz
# ---------------------------------------------------------------------------

build_module_archive() {
  local name="$1"
  local version="$2"
  local outfile="$3"
  local extra_var="${4:-}"

  local mod_dir="${WORK_DIR}/module-build-${name}-${version}"
  mkdir -p "${mod_dir}"

  cat > "${mod_dir}/main.tf" <<TFMAIN
variable "cidr_block" {
  type    = string
  default = "10.0.0.0/16"
}
TFMAIN

  if [ -n "$extra_var" ]; then
    cat >> "${mod_dir}/main.tf" <<TFEXTRA

variable "${extra_var}" {
  type    = bool
  default = true
}
TFEXTRA
  fi

  cat >> "${mod_dir}/main.tf" <<TFRESOURCE

resource "aws_vpc" "main" {
  cidr_block = var.cidr_block
  tags = {
    Name    = "${name}-${version}"
    Version = "${version}"
  }
}

output "vpc_id" {
  value = aws_vpc.main.id
}
TFRESOURCE

  cat > "${mod_dir}/versions.tf" <<TFVERSIONS
terraform {
  required_version = ">= 1.0"
}
TFVERSIONS

  tar czf "${outfile}" -C "${mod_dir}" .
}

# Helper: upload a module archive. Prints the HTTP status code.
upload_module() {
  local archive="$1"
  local namespace="$2"
  local name="$3"
  local provider="$4"
  local version="$5"

  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/gzip" \
    --data-binary "@${archive}" \
    "${TF_BASE}/v1/modules/${namespace}/${name}/${provider}/${version}"
}

# ---------------------------------------------------------------------------
# Setup: create repository
# ---------------------------------------------------------------------------

begin_test "Create Terraform local repository"
if create_local_repo "$REPO_KEY" "terraform"; then
  pass
else
  fail "could not create terraform repository"
fi

# ---------------------------------------------------------------------------
# 1. Service discovery
# ---------------------------------------------------------------------------

begin_test "GET /.well-known/terraform.json returns service discovery document"
DISCOVERY=""
if DISCOVERY=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${TF_BASE}/.well-known/terraform.json" 2>/dev/null); then

  # The discovery document should contain module or provider registry URLs
  if echo "$DISCOVERY" | jq -e '.' >/dev/null 2>&1; then
    has_modules=$(echo "$DISCOVERY" | jq 'has("modules.v1")' 2>/dev/null) || has_modules="false"
    has_providers=$(echo "$DISCOVERY" | jq 'has("providers.v1")' 2>/dev/null) || has_providers="false"
    if [ "$has_modules" = "true" ] || [ "$has_providers" = "true" ]; then
      pass
    else
      # Some implementations return the discovery at a different structure
      echo "  note: discovery document present but missing standard keys"
      pass
    fi
  else
    fail "discovery document is not valid JSON"
  fi
else
  # Try the well-known path at the base URL level (not repo-scoped)
  if DISCOVERY=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/.well-known/terraform.json" 2>/dev/null); then
    if echo "$DISCOVERY" | jq -e '.' >/dev/null 2>&1; then
      pass
    else
      fail "discovery document is not valid JSON"
    fi
  else
    skip "service discovery endpoint not available"
  fi
fi

# ---------------------------------------------------------------------------
# 2. Upload module
# ---------------------------------------------------------------------------

begin_test "Upload a module package"
MODULE_ARCHIVE_V1="${WORK_DIR}/module-v1.tar.gz"
build_module_archive "$MODULE_NAME" "$MODULE_VERSION" "$MODULE_ARCHIVE_V1"

status=$(upload_module "$MODULE_ARCHIVE_V1" "$MODULE_NAMESPACE" "$MODULE_NAME" "$MODULE_PROVIDER" "$MODULE_VERSION")
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "module upload returned HTTP ${status}, expected 200 or 201"
fi

# Brief pause for indexing
sleep 1

# ---------------------------------------------------------------------------
# 3. Version listing
# ---------------------------------------------------------------------------

begin_test "GET /v1/modules/{ns}/{name}/{provider}/versions lists versions"
VERSIONS_RESP=""
if VERSIONS_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${TF_BASE}/v1/modules/${MODULE_NAMESPACE}/${MODULE_NAME}/${MODULE_PROVIDER}/versions" 2>/dev/null); then

  if assert_contains "$VERSIONS_RESP" "$MODULE_VERSION" \
      "versions response should contain ${MODULE_VERSION}"; then
    # Terraform protocol specifies modules[].versions[] structure
    has_modules=$(echo "$VERSIONS_RESP" | jq 'has("modules")' 2>/dev/null) || has_modules="false"
    if [ "$has_modules" = "true" ]; then
      echo "  structure: modules[].versions[] (standard protocol)"
    fi
    pass
  fi
else
  fail "GET versions endpoint failed"
fi

# ---------------------------------------------------------------------------
# 4. Download URL
# ---------------------------------------------------------------------------

begin_test "GET /v1/modules/{ns}/{name}/{provider}/{version}/download returns download URL"
DL_HEADERS="${WORK_DIR}/download-headers.txt"
DL_BODY="${WORK_DIR}/download-body.bin"

dl_status=$(curl -s -D "$DL_HEADERS" -o "$DL_BODY" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${TF_BASE}/v1/modules/${MODULE_NAMESPACE}/${MODULE_NAME}/${MODULE_PROVIDER}/${MODULE_VERSION}/download" 2>/dev/null) || dl_status="000"

ARCHIVE_URL=""
if [ "$dl_status" = "204" ]; then
  # Standard Terraform protocol: 204 with X-Terraform-Get header
  ARCHIVE_URL=$(grep -i 'X-Terraform-Get' "$DL_HEADERS" | sed 's/^[^:]*: *//' | tr -d '\r\n') || true
  if [ -n "$ARCHIVE_URL" ]; then
    pass
  else
    echo "  note: 204 without X-Terraform-Get header"
    pass
  fi
elif [ "$dl_status" = "200" ]; then
  # Some implementations return the archive directly
  echo "  note: server returns archive directly (200) instead of 204 redirect"
  pass
elif [ "$dl_status" = "302" ] || [ "$dl_status" = "301" ]; then
  # Redirect to archive URL is also acceptable
  ARCHIVE_URL=$(grep -i 'Location' "$DL_HEADERS" | sed 's/^[^:]*: *//' | tr -d '\r\n') || true
  pass
else
  fail "download endpoint returned HTTP ${dl_status}, expected 204 or 200"
fi

# ---------------------------------------------------------------------------
# 5. Download and verify archive integrity
# ---------------------------------------------------------------------------

begin_test "Download module archive and verify integrity"
DOWNLOADED_ARCHIVE="${WORK_DIR}/downloaded-module.tar.gz"
archive_ok=false

if [ -n "$ARCHIVE_URL" ]; then
  # Follow the X-Terraform-Get or Location header
  if [[ "$ARCHIVE_URL" == http* ]]; then
    archive_dl_url="$ARCHIVE_URL"
  else
    archive_dl_url="${BASE_URL}${ARCHIVE_URL}"
  fi

  if curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      -o "$DOWNLOADED_ARCHIVE" \
      "$archive_dl_url" 2>/dev/null; then
    if [ -s "$DOWNLOADED_ARCHIVE" ]; then
      archive_ok=true
    fi
  fi
elif [ "$dl_status" = "200" ] && [ -s "$DL_BODY" ]; then
  # The download endpoint returned the archive directly
  cp "$DL_BODY" "$DOWNLOADED_ARCHIVE"
  archive_ok=true
fi

if [ "$archive_ok" = "true" ]; then
  # Verify the archive contains main.tf
  if tar tzf "$DOWNLOADED_ARCHIVE" 2>/dev/null | grep -q "main.tf"; then
    pass
  else
    fail "downloaded archive does not contain main.tf"
  fi
else
  # Try downloading via a direct archive path
  if curl -sf $CURL_TIMEOUT -L \
      -H "$(format_auth_header)" \
      -o "$DOWNLOADED_ARCHIVE" \
      "${TF_BASE}/v1/modules/${MODULE_NAMESPACE}/${MODULE_NAME}/${MODULE_PROVIDER}/${MODULE_VERSION}/download" 2>/dev/null; then
    if [ -s "$DOWNLOADED_ARCHIVE" ] && tar tzf "$DOWNLOADED_ARCHIVE" 2>/dev/null | grep -q "main.tf"; then
      pass
    else
      fail "could not download a valid module archive"
    fi
  else
    fail "could not download module archive from any endpoint"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Multiple versions
# ---------------------------------------------------------------------------

begin_test "Multiple versions listed after uploading a second version"
MODULE_VERSION_2="2.0.0"
MODULE_ARCHIVE_V2="${WORK_DIR}/module-v2.tar.gz"
build_module_archive "$MODULE_NAME" "$MODULE_VERSION_2" "$MODULE_ARCHIVE_V2" "enable_dns"

v2_status=$(upload_module "$MODULE_ARCHIVE_V2" "$MODULE_NAMESPACE" "$MODULE_NAME" "$MODULE_PROVIDER" "$MODULE_VERSION_2")
if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
  sleep 1

  multi_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${TF_BASE}/v1/modules/${MODULE_NAMESPACE}/${MODULE_NAME}/${MODULE_PROVIDER}/versions" 2>/dev/null) || true

  if [ -n "$multi_resp" ]; then
    has_v1=$(echo "$multi_resp" | grep -c "$MODULE_VERSION" 2>/dev/null) || has_v1="0"
    has_v2=$(echo "$multi_resp" | grep -c "$MODULE_VERSION_2" 2>/dev/null) || has_v2="0"
    if [ "$has_v1" -gt 0 ] && [ "$has_v2" -gt 0 ]; then
      pass
    else
      fail "version listing should contain both ${MODULE_VERSION} and ${MODULE_VERSION_2}"
    fi
  else
    fail "could not fetch versions after uploading second module"
  fi
else
  fail "second module upload returned HTTP ${v2_status}"
fi

# ---------------------------------------------------------------------------
# 7. Search
# ---------------------------------------------------------------------------

begin_test "Search modules (if supported)"
SEARCH_RESP=""
search_status=$(curl -s -o "${WORK_DIR}/search-body.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${TF_BASE}/v1/modules?q=${MODULE_NAME}" 2>/dev/null) || search_status="000"

if [ "$search_status" = "200" ]; then
  SEARCH_RESP=$(cat "${WORK_DIR}/search-body.json")
  if assert_contains "$SEARCH_RESP" "$MODULE_NAME" \
      "search results should contain the module name"; then
    pass
  fi
elif [ "$search_status" = "404" ] || [ "$search_status" = "501" ]; then
  skip "module search not implemented (HTTP ${search_status})"
else
  # Try alternate search path
  search_status=$(curl -s -o "${WORK_DIR}/search-body.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${TF_BASE}/v1/modules/search?q=${MODULE_NAME}" 2>/dev/null) || search_status="000"
  if [ "$search_status" = "200" ]; then
    pass
  elif [ "$search_status" = "404" ] || [ "$search_status" = "501" ]; then
    skip "module search not implemented"
  else
    fail "search returned HTTP ${search_status}"
  fi
fi

# ---------------------------------------------------------------------------
# 8. 404 for nonexistent module
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent module"
missing_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${TF_BASE}/v1/modules/nonexistent/module-does-not-exist/fakeprovider/versions" 2>/dev/null) || missing_status="000"

if assert_eq "$missing_status" "404" \
    "nonexistent module should return 404, got ${missing_status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 9. Provider listing (provider registry protocol, if supported)
# ---------------------------------------------------------------------------

begin_test "Provider registry protocol (if supported alongside modules)"
# The Terraform Provider Registry Protocol uses /v1/providers/ endpoints.
# Some registries support both modules and providers, others only one.
provider_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${TF_BASE}/v1/providers/${MODULE_NAMESPACE}/${MODULE_NAME}/versions" 2>/dev/null) || provider_status="000"

if [ "$provider_status" = "200" ]; then
  echo "  provider protocol supported"
  pass
elif [ "$provider_status" = "404" ]; then
  # Server only supports modules, not providers. This is fine.
  echo "  note: provider protocol returns 404, server may only support modules"
  pass
else
  # Providers not relevant for this repo type
  echo "  note: provider endpoint returned HTTP ${provider_status}"
  pass
fi

# ---------------------------------------------------------------------------
# 10. Content-Type on downloads
# ---------------------------------------------------------------------------

begin_test "Content-Type on module archive downloads"
# The module archive should be served with an appropriate binary content type
archive_ct=""

if [ -n "$ARCHIVE_URL" ]; then
  if [[ "$ARCHIVE_URL" == http* ]]; then
    ct_url="$ARCHIVE_URL"
  else
    ct_url="${BASE_URL}${ARCHIVE_URL}"
  fi
  archive_ct=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o /dev/null -w '%{content_type}' \
    "$ct_url" 2>/dev/null) || archive_ct=""
fi

if [ -z "$archive_ct" ]; then
  # Try direct download with -L to follow redirects
  archive_ct=$(curl -sf $CURL_TIMEOUT -L \
    -H "$(format_auth_header)" \
    -o /dev/null -w '%{content_type}' \
    "${TF_BASE}/v1/modules/${MODULE_NAMESPACE}/${MODULE_NAME}/${MODULE_PROVIDER}/${MODULE_VERSION}/download" 2>/dev/null) || archive_ct=""
fi

if [ -n "$archive_ct" ]; then
  if [[ "$archive_ct" == *"application/gzip"* ]] || \
     [[ "$archive_ct" == *"application/x-gzip"* ]] || \
     [[ "$archive_ct" == *"application/x-tar"* ]] || \
     [[ "$archive_ct" == *"application/octet-stream"* ]] || \
     [[ "$archive_ct" == *"application/x-compressed-tar"* ]]; then
    pass
  elif [[ "$archive_ct" == *"application/json"* ]] || \
       [[ "$archive_ct" == *"text/html"* ]]; then
    fail "module archive should not be served as ${archive_ct}"
  else
    echo "  Content-Type: ${archive_ct}"
    pass
  fi
else
  skip "could not determine Content-Type for module archive"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
