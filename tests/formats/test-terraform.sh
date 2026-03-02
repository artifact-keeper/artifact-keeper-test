#!/usr/bin/env bash
# test-terraform.sh - Terraform module registry E2E test (curl-based)
#
# Uploads a module archive to the Terraform registry endpoint, verifies
# version listing via the Terraform registry protocol, and downloads the
# module back.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "terraform"
auth_admin
setup_workdir

REPO_KEY="test-terraform-${RUN_ID}"
MODULE_NAMESPACE="e2etest"
MODULE_NAME="vpc"
MODULE_PROVIDER="aws"
MODULE_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create Terraform repository"
if create_local_repo "$REPO_KEY" "terraform"; then
  pass
else
  fail "could not create terraform repository"
fi

# -----------------------------------------------------------------------
# Generate a minimal Terraform module archive
# -----------------------------------------------------------------------
begin_test "Upload module"
MODULE_DIR="$WORK_DIR/module"
mkdir -p "$MODULE_DIR"

cat > "$MODULE_DIR/main.tf" <<'EOF'
variable "cidr_block" {
  type    = string
  default = "10.0.0.0/16"
}

resource "aws_vpc" "main" {
  cidr_block = var.cidr_block
  tags = {
    Name = "e2e-test-vpc"
  }
}

output "vpc_id" {
  value = aws_vpc.main.id
}
EOF

MODULE_ARCHIVE="$WORK_DIR/module.tar.gz"
tar czf "$MODULE_ARCHIVE" -C "$MODULE_DIR" .

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${MODULE_ARCHIVE}" \
  "${BASE_URL}/terraform/${REPO_KEY}/v1/modules/${MODULE_NAMESPACE}/${MODULE_NAME}/${MODULE_PROVIDER}/${MODULE_VERSION}") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "module upload returned ${upload_status}, expected 200 or 201"
fi

# -----------------------------------------------------------------------
# Verify version listing
# -----------------------------------------------------------------------
begin_test "List module versions"
versions_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/terraform/${REPO_KEY}/v1/modules/${MODULE_NAMESPACE}/${MODULE_NAME}/${MODULE_PROVIDER}/versions" 2>/dev/null) || true

if [ -z "$versions_resp" ]; then
  fail "could not fetch module versions"
else
  if echo "$versions_resp" | grep -q "$MODULE_VERSION"; then
    pass
  else
    fail "version ${MODULE_VERSION} not found in versions response"
  fi
fi

# -----------------------------------------------------------------------
# Download module
# -----------------------------------------------------------------------
begin_test "Download module"
dl_file="$WORK_DIR/downloaded-module.tar.gz"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/terraform/${REPO_KEY}/v1/modules/${MODULE_NAMESPACE}/${MODULE_NAME}/${MODULE_PROVIDER}/${MODULE_VERSION}/download" 2>/dev/null) || true

if [ "$dl_status" = "200" ] || [ "$dl_status" = "204" ]; then
  pass
else
  # Some implementations return a redirect with the download URL
  dl_status=$(curl -sf -L -o "$dl_file" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/terraform/${REPO_KEY}/v1/modules/${MODULE_NAMESPACE}/${MODULE_NAME}/${MODULE_PROVIDER}/${MODULE_VERSION}/download" 2>/dev/null) || true
  if [ "$dl_status" = "200" ]; then
    pass
  else
    fail "module download returned ${dl_status}, expected 200"
  fi
fi

# -----------------------------------------------------------------------
# Verify downloaded archive contents
# -----------------------------------------------------------------------
begin_test "Verify downloaded module contents"
if [ -f "$dl_file" ] && tar tzf "$dl_file" 2>/dev/null | grep -q "main.tf"; then
  pass
else
  fail "downloaded archive does not contain main.tf"
fi

end_suite
