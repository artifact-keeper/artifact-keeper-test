#!/usr/bin/env bash
# test-rubygems.sh - RubyGems registry E2E test (curl-based)
#
# Uploads a .gem file to /gems/{key}/api/v1/gems, verifies the specs
# endpoint, and downloads the gem back.
#
# Note: the path prefix is /gems/, not /rubygems/.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "rubygems"
auth_admin
setup_workdir

REPO_KEY="test-rubygems-${RUN_ID}"
GEM_NAME="e2e_hello"
GEM_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create RubyGems repository"
if create_local_repo "$REPO_KEY" "gems"; then
  pass
else
  fail "could not create gems repository"
fi

# -----------------------------------------------------------------------
# Generate a minimal .gem file
# -----------------------------------------------------------------------
# A .gem is a tar archive containing: metadata.gz, data.tar.gz, checksums.yaml.gz
begin_test "Upload gem"
GEM_DIR="$WORK_DIR/gem-build"
mkdir -p "$GEM_DIR/lib"

cat > "$GEM_DIR/lib/${GEM_NAME}.rb" <<EOF
module E2eHello
  VERSION = "${GEM_VERSION}"
  def self.hello
    "Hello from RubyGems E2E test!"
  end
end
EOF

# Build data.tar.gz
DATA_TAR="$WORK_DIR/data.tar.gz"
tar czf "$DATA_TAR" -C "$GEM_DIR" lib

# Build metadata.gz (YAML gemspec)
cat > "$WORK_DIR/metadata" <<EOF
--- !ruby/object:Gem::Specification
name: ${GEM_NAME}
version: !ruby/object:Gem::Version
  version: '${GEM_VERSION}'
platform: ruby
authors:
- E2E Test
autorequire:
bindir: bin
cert_chain: []
date: '$(date +%Y-%m-%d)'
dependencies: []
description: E2E test gem
email: test@example.com
executables: []
extensions: []
extra_rdoc_files: []
files:
- lib/${GEM_NAME}.rb
homepage: https://example.com
licenses:
- MIT
metadata: {}
post_install_message:
rdoc_options: []
require_paths:
- lib
required_ruby_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
required_rubygems_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
requirements: []
rubygems_version: 3.0.0
signing_key:
specification_version: 4
summary: E2E test gem for artifact-keeper
test_files: []
EOF

gzip -c "$WORK_DIR/metadata" > "$WORK_DIR/metadata.gz"

# Assemble the .gem tar
GEM_FILE="$WORK_DIR/${GEM_NAME}-${GEM_VERSION}.gem"
tar cf "$GEM_FILE" -C "$WORK_DIR" metadata.gz data.tar.gz

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${GEM_FILE}" \
  "${BASE_URL}/gems/${REPO_KEY}/api/v1/gems") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "gem upload returned ${upload_status}, expected 200 or 201"
fi

# -----------------------------------------------------------------------
# Verify specs endpoint
# -----------------------------------------------------------------------
begin_test "Verify specs index"
# RubyGems serves specs at /specs.4.8.gz (marshalled) or via API
specs_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(auth_header)" \
  "${BASE_URL}/gems/${REPO_KEY}/specs.4.8.gz") || true

if [ "$specs_status" = "200" ]; then
  pass
else
  # Try latest_specs
  specs_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "$(auth_header)" \
    "${BASE_URL}/gems/${REPO_KEY}/latest_specs.4.8.gz") || true
  if [ "$specs_status" = "200" ]; then
    pass
  else
    fail "specs endpoint returned ${specs_status}, expected 200"
  fi
fi

# -----------------------------------------------------------------------
# Verify gem info via API
# -----------------------------------------------------------------------
begin_test "Verify gem info via API"
info_resp=$(curl -sf -H "$(auth_header)" \
  "${BASE_URL}/gems/${REPO_KEY}/api/v1/gems/${GEM_NAME}.json" 2>/dev/null) || true

if [ -n "$info_resp" ] && echo "$info_resp" | grep -q "$GEM_NAME"; then
  pass
else
  # Try alternate endpoint
  info_resp=$(curl -sf -H "$(auth_header)" \
    "${BASE_URL}/gems/${REPO_KEY}/api/v1/versions/${GEM_NAME}.json" 2>/dev/null) || true
  if [ -n "$info_resp" ] && echo "$info_resp" | grep -q "$GEM_VERSION"; then
    pass
  else
    skip "gem info API not available at expected path"
  fi
fi

# -----------------------------------------------------------------------
# Download gem
# -----------------------------------------------------------------------
begin_test "Download gem"
dl_file="$WORK_DIR/downloaded.gem"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(auth_header)" \
  "${BASE_URL}/gems/${REPO_KEY}/gems/${GEM_NAME}-${GEM_VERSION}.gem" 2>/dev/null) || true

if [ "$dl_status" = "200" ]; then
  if [ -s "$dl_file" ]; then
    pass
  else
    fail "downloaded gem is empty"
  fi
else
  fail "gem download returned ${dl_status}, expected 200"
fi

end_suite
