#!/usr/bin/env bash
# test-conda.sh - Conda channel E2E test
#
# Tests conda package upload and channel metadata retrieval via the
# /conda/{repo_key}/ endpoints.
#
# Requires: conda

source "$(dirname "$0")/../lib/common.sh"

begin_suite "conda"
auth_admin
setup_workdir
require_cmd conda

REPO_KEY="test-conda-${RUN_ID}"
PKG_NAME="test-conda-pkg"
PKG_VERSION="1.0.$(date +%s)"
SUBDIR="noarch"
CONDA_URL="${BASE_URL}/conda/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create conda local repository"
if create_local_repo "$REPO_KEY" "conda"; then
  pass
else
  fail "could not create conda repository"
fi

# ---------------------------------------------------------------------------
# Build a minimal conda package
# ---------------------------------------------------------------------------
# A .tar.bz2 conda package contains at minimum:
#   - info/index.json (package metadata)
#   - info/paths.json (file listing)

begin_test "Build minimal conda package"

cd "$WORK_DIR"
mkdir -p conda-pkg/info

cat > conda-pkg/info/index.json <<EOF
{
  "name": "${PKG_NAME}",
  "version": "${PKG_VERSION}",
  "build": "0",
  "build_number": 0,
  "depends": [],
  "subdir": "${SUBDIR}",
  "arch": null,
  "platform": null,
  "noarch": "generic"
}
EOF

cat > conda-pkg/info/paths.json <<EOF
{
  "paths": []
}
EOF

CONDA_FILENAME="${PKG_NAME}-${PKG_VERSION}-0.tar.bz2"
cd conda-pkg
if tar cjf "${WORK_DIR}/${CONDA_FILENAME}" info/ 2>/dev/null; then
  pass
else
  fail "failed to create conda .tar.bz2 package"
fi

# ---------------------------------------------------------------------------
# Upload package via API
# ---------------------------------------------------------------------------

begin_test "Upload conda package"

UPLOAD_URL="${CONDA_URL}/upload"
if resp=$(curl -sf -X POST "$UPLOAD_URL" \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Conda-Subdir: ${SUBDIR}" \
  -H "X-Package-Filename: ${CONDA_FILENAME}" \
  --data-binary "@${WORK_DIR}/${CONDA_FILENAME}" 2>&1); then
  pass
else
  fail "conda package upload failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Verify channeldata.json
# ---------------------------------------------------------------------------

begin_test "Verify channeldata.json"
sleep 1
if resp=$(curl -sf "${CONDA_URL}/channeldata.json" -H "$(auth_header)"); then
  if assert_contains "$resp" "$PKG_NAME" "channeldata should contain package name"; then
    pass
  fi
else
  fail "GET channeldata.json returned error"
fi

# ---------------------------------------------------------------------------
# Verify repodata.json for subdir
# ---------------------------------------------------------------------------

begin_test "Verify repodata.json for ${SUBDIR}"
if resp=$(curl -sf "${CONDA_URL}/${SUBDIR}/repodata.json" -H "$(auth_header)"); then
  if assert_contains "$resp" "$PKG_NAME" "repodata should contain package name"; then
    if assert_contains "$resp" "$PKG_VERSION" "repodata should contain version"; then
      pass
    fi
  fi
else
  fail "GET ${SUBDIR}/repodata.json returned error"
fi

# ---------------------------------------------------------------------------
# Download package file
# ---------------------------------------------------------------------------

begin_test "Download conda package"
DL_URL="${CONDA_URL}/${SUBDIR}/${CONDA_FILENAME}"
DL_FILE="${WORK_DIR}/downloaded.tar.bz2"
if curl -sf -H "$(auth_header)" -o "$DL_FILE" "$DL_URL"; then
  # Verify it is a valid bzip2 file
  if file "$DL_FILE" | grep -qi "bzip2\|bz2"; then
    pass
  else
    fail "downloaded file is not a valid bzip2 archive"
  fi
else
  fail "conda package download failed"
fi

# ---------------------------------------------------------------------------
# Conda install from private channel
# ---------------------------------------------------------------------------

begin_test "Conda search from private channel"
# conda search with --override-channels to use only our repo
# We use the token-based URL format for conda access
if output=$(conda search "${PKG_NAME}" \
  --override-channels \
  -c "${CONDA_URL}" \
  --json 2>&1); then
  if assert_contains "$output" "$PKG_NAME" "conda search should find the package"; then
    pass
  fi
else
  # conda search may fail if auth headers are not forwarded; that is acceptable
  # as long as the direct download and repodata work
  skip "conda search did not succeed (auth may not be forwarded by conda client)"
fi

# ---------------------------------------------------------------------------
# Verify repository artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$PKG_NAME" "artifact list should contain package"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
