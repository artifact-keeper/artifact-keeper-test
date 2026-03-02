#!/usr/bin/env bash
# test-chef.sh - Chef cookbook registry E2E test (curl-based)
#
# Uploads a minimal cookbook tarball to the Chef registry endpoint,
# verifies the universe endpoint, and lists artifacts via the
# management API.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "chef"
auth_admin
setup_workdir

REPO_KEY="test-chef-${RUN_ID}"
COOKBOOK_NAME="e2e_hello"
COOKBOOK_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create Chef local repository"
if create_local_repo "$REPO_KEY" "chef"; then
  pass
else
  fail "could not create chef repo"
fi

# -----------------------------------------------------------------------
# Generate a minimal cookbook tarball
# -----------------------------------------------------------------------
begin_test "Upload cookbook"
CB_DIR="$WORK_DIR/${COOKBOOK_NAME}"
mkdir -p "$CB_DIR/recipes"

cat > "$CB_DIR/metadata.json" <<EOF
{
  "name": "${COOKBOOK_NAME}",
  "version": "${COOKBOOK_VERSION}",
  "description": "E2E test cookbook for Chef registry",
  "maintainer": "E2E Test",
  "maintainer_email": "test@example.com",
  "license": "MIT",
  "platforms": {},
  "dependencies": {}
}
EOF

cat > "$CB_DIR/metadata.rb" <<EOF
name '${COOKBOOK_NAME}'
version '${COOKBOOK_VERSION}'
description 'E2E test cookbook for Chef registry'
maintainer 'E2E Test'
maintainer_email 'test@example.com'
license 'MIT'
EOF

cat > "$CB_DIR/recipes/default.rb" <<'EOF'
log 'Hello from Chef E2E test!'
EOF

CB_TARBALL="$WORK_DIR/${COOKBOOK_NAME}-${COOKBOOK_VERSION}.tar.gz"
tar czf "$CB_TARBALL" -C "$WORK_DIR" "$COOKBOOK_NAME"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${CB_TARBALL}" \
  "${BASE_URL}/chef/${REPO_KEY}/${COOKBOOK_NAME}/${COOKBOOK_VERSION}") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  # Try alternate upload path (api/v1/cookbooks style)
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${CB_TARBALL}" \
    "${BASE_URL}/chef/${REPO_KEY}/api/v1/cookbooks/${COOKBOOK_NAME}/versions/${COOKBOOK_VERSION}" 2>/dev/null) || true
  if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
    pass
  else
    fail "cookbook upload returned ${upload_status}, expected 200 or 201"
  fi
fi

# -----------------------------------------------------------------------
# Query universe endpoint
# -----------------------------------------------------------------------
begin_test "Query universe endpoint"
universe_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/chef/${REPO_KEY}/universe" 2>/dev/null) || true

if [ -z "$universe_resp" ]; then
  # Try alternate universe path
  universe_resp=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/chef/${REPO_KEY}/api/v1/universe" 2>/dev/null) || true
fi

if [ -n "$universe_resp" ] && echo "$universe_resp" | grep -q "$COOKBOOK_NAME"; then
  pass
else
  fail "cookbook ${COOKBOOK_NAME} not found in universe endpoint"
fi

# -----------------------------------------------------------------------
# List artifacts via management API
# -----------------------------------------------------------------------
begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$COOKBOOK_NAME" "artifact list should contain cookbook"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
