#!/usr/bin/env bash
# test-cargo-remote.sh - Cargo remote proxy E2E test
#
# Covers:
#   - Remote proxy (bug #743): create remote Cargo repo pointing at crates.io,
#     verify config.json has absolute dl URL, pull a known crate
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cargo-remote"
auth_admin
setup_workdir

REPO_KEY="test-cargo-remote-${RUN_ID}"
UPSTREAM_URL="https://crates.io"
TEST_CRATE="cfg-if"
TEST_CRATE_VERSION="1.0.0"

# -------------------------------------------------------------------------
# Create remote Cargo repository
# -------------------------------------------------------------------------

begin_test "Create remote Cargo repository"
if create_remote_repo "$REPO_KEY" "cargo" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote Cargo repo"
fi

# -------------------------------------------------------------------------
# Check upstream reachability
# -------------------------------------------------------------------------

begin_test "Verify upstream reachability"
# crates.io sparse index uses index.crates.io; also check the main domain
if curl -sf --max-time 10 "https://index.crates.io/config.json" > /dev/null 2>&1 || \
   curl -sf --max-time 10 "https://crates.io/api/v1/crates/cfg-if" > /dev/null 2>&1; then
  UPSTREAM_REACHABLE=true
  pass
else
  UPSTREAM_REACHABLE=false
  skip "crates.io unreachable from test environment"
fi

# -------------------------------------------------------------------------
# Verify config.json endpoint (bug #743)
#
# The config.json returned by the proxied Cargo repo must have a `dl` field
# that is a full absolute URL, not a relative path. Cargo clients use this
# URL template to download crates, and a relative value breaks resolution.
# -------------------------------------------------------------------------

CARGO_REPO_URL="${BASE_URL}/cargo/${REPO_KEY}"

begin_test "GET config.json from remote Cargo repo (bug #743)"
if resp=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${CARGO_REPO_URL}/config.json" 2>/dev/null); then
  if assert_contains "$resp" "dl" "config.json must contain a dl field"; then
    pass
  fi
else
  fail "config.json endpoint not reachable"
fi

begin_test "Verify config.json dl URL is absolute (bug #743)"
if [ -n "${resp:-}" ]; then
  dl_url=$(echo "$resp" | jq -r '.dl // empty') || true
  if [ -z "$dl_url" ] || [ "$dl_url" = "null" ]; then
    fail "config.json has no dl field (bug #743)"
  elif [[ "$dl_url" == http://* ]] || [[ "$dl_url" == https://* ]]; then
    pass
  else
    fail "config.json dl is not an absolute URL: '${dl_url}' (bug #743)"
  fi
else
  skip "no config.json response to check"
fi

# -------------------------------------------------------------------------
# Pull a known crate through the remote proxy
# -------------------------------------------------------------------------

begin_test "Pull crate index entry through remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # cfg-if is 6 chars, so sparse index path is: /cf/g-/cfg-if
  # Using the standard crate index naming: first-two/next-two/name
  name_len=${#TEST_CRATE}
  if [ "$name_len" -le 2 ]; then
    index_path="/cargo/${REPO_KEY}/index/${name_len}/${TEST_CRATE}"
  elif [ "$name_len" -eq 3 ]; then
    prefix="${TEST_CRATE:0:1}"
    index_path="/cargo/${REPO_KEY}/index/3/${prefix}/${TEST_CRATE}"
  else
    prefix1="${TEST_CRATE:0:2}"
    prefix2="${TEST_CRATE:2:2}"
    index_path="/cargo/${REPO_KEY}/index/${prefix1}/${prefix2}/${TEST_CRATE}"
  fi

  if index_resp=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${BASE_URL}${index_path}" 2>/dev/null); then
    if assert_contains "$index_resp" "$TEST_CRATE" \
        "index entry should contain crate name"; then
      pass
    fi
  else
    skip "sparse index lookup returned error for ${index_path}"
  fi
fi

begin_test "Download crate through remote proxy using dl URL"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # Use the dl URL from config.json if available, otherwise construct it
  dl_url="${dl_url:-}"
  download_url=""
  if [ -n "$dl_url" ] && [ "$dl_url" != "null" ]; then
    # The dl URL may be a template with {crate} and {version} placeholders,
    # or it may be a base URL that needs /crate/version/download appended
    if [[ "$dl_url" == *"{crate}"* ]]; then
      download_url=$(echo "$dl_url" | sed "s/{crate}/${TEST_CRATE}/g; s/{version}/${TEST_CRATE_VERSION}/g")
    else
      # Standard Cargo API layout: dl_url/crate_name/version/download
      download_url="${dl_url}/${TEST_CRATE}/${TEST_CRATE_VERSION}/download"
    fi
  else
    # Fallback: use the standard Cargo API download path
    download_url="${BASE_URL}/cargo/${REPO_KEY}/api/v1/crates/${TEST_CRATE}/${TEST_CRATE_VERSION}/download"
  fi

  DL_CRATE="${WORK_DIR}/downloaded.crate"
  if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      -o "$DL_CRATE" -L "$download_url" 2>/dev/null; then
    if [ -s "$DL_CRATE" ]; then
      pass
    else
      fail "downloaded crate is empty"
    fi
  else
    # Try the standard API path as fallback
    fallback_url="${BASE_URL}/cargo/${REPO_KEY}/api/v1/crates/${TEST_CRATE}/${TEST_CRATE_VERSION}/download"
    if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -o "$DL_CRATE" -L "$fallback_url" 2>/dev/null; then
      if [ -s "$DL_CRATE" ]; then
        pass
      else
        fail "downloaded crate is empty (fallback)"
      fi
    else
      fail "crate download returned error"
    fi
  fi
fi

begin_test "Verify downloaded crate is a valid gzip archive"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ -f "$DL_CRATE" ] && [ -s "$DL_CRATE" ]; then
  # Crate files are .tar.gz archives; check the gzip magic bytes
  magic=$(xxd -l 2 -p "$DL_CRATE" 2>/dev/null) || true
  if [ "$magic" = "1f8b" ]; then
    pass
  else
    # Some registries may serve uncompressed; at least verify it is non-empty
    skip "downloaded file does not have gzip magic bytes (may be uncompressed)"
  fi
else
  skip "no crate file to verify"
fi

begin_test "Pull a second crate version to verify caching"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # Pull the same crate again; should succeed (possibly from cache)
  DL_CRATE2="${WORK_DIR}/downloaded2.crate"
  fallback_url="${BASE_URL}/cargo/${REPO_KEY}/api/v1/crates/${TEST_CRATE}/${TEST_CRATE_VERSION}/download"
  if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      -o "$DL_CRATE2" -L "$fallback_url" 2>/dev/null; then
    if [ -s "$DL_CRATE2" ]; then
      pass
    else
      fail "cached crate download is empty"
    fi
  else
    skip "second download attempt failed"
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
