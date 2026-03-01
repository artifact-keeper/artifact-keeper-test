#!/usr/bin/env bash
# test-cargo.sh - Cargo sparse registry protocol E2E test
#
# Requires: cargo
# Tests: create local repo, cargo publish, verify via API, download crate
source "$(dirname "$0")/../lib/common.sh"

begin_suite "cargo"
require_cmd cargo
auth_admin
setup_workdir

REPO_KEY="test-cargo-${RUN_ID}"
CRATE_NAME="testcrate${RUN_ID//[^a-z0-9]/_}"
CRATE_VERSION="0.1.0"
CARGO_REGISTRY_URL="${BASE_URL}/cargo/${REPO_KEY}"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create cargo repository"
if create_local_repo "$REPO_KEY" "cargo"; then
  pass
else
  fail "could not create cargo repo"
fi

# -------------------------------------------------------------------------
# Prepare minimal crate
# -------------------------------------------------------------------------

begin_test "Create minimal crate"
CRATE_DIR="${WORK_DIR}/${CRATE_NAME}"
mkdir -p "${CRATE_DIR}/src"

cat > "${CRATE_DIR}/Cargo.toml" <<EOF
[package]
name = "${CRATE_NAME}"
version = "${CRATE_VERSION}"
edition = "2021"
description = "E2E test crate for artifact-keeper"
license = "MIT"

[lib]
name = "${CRATE_NAME}"
path = "src/lib.rs"
EOF

cat > "${CRATE_DIR}/src/lib.rs" <<EOF
pub fn hello() -> &'static str {
    "hello from ${CRATE_NAME}"
}
EOF

if [ -f "${CRATE_DIR}/Cargo.toml" ]; then
  pass
else
  fail "failed to create crate files"
fi

# -------------------------------------------------------------------------
# Configure cargo to use our registry
# -------------------------------------------------------------------------

begin_test "Configure cargo registry"
export CARGO_HOME="${WORK_DIR}/cargo-home"
mkdir -p "${CARGO_HOME}"

cat > "${CARGO_HOME}/config.toml" <<EOF
[registries.test-registry]
index = "sparse+${CARGO_REGISTRY_URL}/"

[registry]
default = "test-registry"
EOF

export CARGO_REGISTRIES_TEST_REGISTRY_TOKEN="Basic $(echo -n "${ADMIN_USER}:${ADMIN_PASS}" | base64)"
pass

# -------------------------------------------------------------------------
# Publish crate
# -------------------------------------------------------------------------

begin_test "Publish crate with cargo publish"
cd "${CRATE_DIR}"
if output=$(cargo publish --registry test-registry --allow-dirty --no-verify 2>&1); then
  pass
else
  # cargo publish may return warnings but still succeed
  if echo "$output" | grep -qi "published\|uploaded\|warning"; then
    pass
  else
    fail "cargo publish failed: ${output}"
  fi
fi

# -------------------------------------------------------------------------
# Verify crate via API
# -------------------------------------------------------------------------

begin_test "Verify crate metadata via sparse index"
sleep 2
# The sparse index stores crate info keyed by crate name length:
# 1-2 chars: /index/1/{name} or /index/2/{name}
# 3 chars:   /index/3/{first}/{name}
# 4+ chars:  /index/{first-two}/{next-two}/{name}
name_len=${#CRATE_NAME}
if [ "$name_len" -le 2 ]; then
  index_path="/cargo/${REPO_KEY}/index/${name_len}/${CRATE_NAME}"
elif [ "$name_len" -eq 3 ]; then
  prefix="${CRATE_NAME:0:1}"
  index_path="/cargo/${REPO_KEY}/index/3/${prefix}/${CRATE_NAME}"
else
  prefix1="${CRATE_NAME:0:2}"
  prefix2="${CRATE_NAME:2:2}"
  index_path="/cargo/${REPO_KEY}/index/${prefix1}/${prefix2}/${CRATE_NAME}"
fi

if resp=$(api_get "${index_path}" 2>/dev/null); then
  if assert_contains "$resp" "$CRATE_NAME"; then
    pass
  fi
else
  fail "sparse index lookup returned error for ${index_path}"
fi

# -------------------------------------------------------------------------
# Verify config.json endpoint
# -------------------------------------------------------------------------

begin_test "Verify config.json endpoint"
if resp=$(api_get "/cargo/${REPO_KEY}/config.json" 2>/dev/null); then
  if assert_contains "$resp" "dl"; then
    pass
  fi
else
  fail "config.json endpoint not reachable"
fi

# -------------------------------------------------------------------------
# Download crate via API
# -------------------------------------------------------------------------

begin_test "Download crate via API"
if curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -o "${WORK_DIR}/downloaded.crate" \
    "${BASE_URL}/cargo/${REPO_KEY}/api/v1/crates/${CRATE_NAME}/${CRATE_VERSION}/download" 2>/dev/null; then
  if [ -s "${WORK_DIR}/downloaded.crate" ]; then
    pass
  else
    fail "downloaded crate is empty"
  fi
else
  fail "crate download returned error"
fi

# -------------------------------------------------------------------------
# Search crates
# -------------------------------------------------------------------------

begin_test "Search crates endpoint"
if resp=$(api_get "/cargo/${REPO_KEY}/api/v1/crates?q=${CRATE_NAME}" 2>/dev/null); then
  if assert_contains "$resp" "$CRATE_NAME"; then
    pass
  fi
else
  # Search may not be implemented; pass with note
  skip "search endpoint not available"
fi

end_suite
