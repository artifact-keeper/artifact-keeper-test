#!/usr/bin/env bash
# test-pypi-scoped-token.sh - PyPI publish with a least-privilege token
# (artifact-keeper#3041, fixed by artifact-keeper#2993, shipped in v1.7.0)
#
# Regression: the PyPI twine upload path gated on the bare "write" scope,
# which ALLOWED_SCOPES cannot mint. A least-privilege repo-scoped token
# holding read:artifacts+write:artifacts was therefore always rejected with
# 403 "Token does not have required scope" even though it is exactly the
# credential CI pipelines are supposed to publish with. The #2993 fix moved
# the artifact upload paths to the colon-form write:artifacts requirement.
#
# Flow:
#   1. Create a hosted PyPI repo.
#   2. Mint a repo-scoped token with scopes read:artifacts+write:artifacts
#      via POST /api/v1/repositories/{key}/tokens.
#   3. Upload an sdist through the twine endpoint using that token as the
#      Basic-auth password (the pip-netrc / Artifactory-style credential
#      shape the format endpoints accept).
#   4. Assert HTTP success, and assert the pre-fix failure mode is gone:
#      the response must NOT be a 403 mentioning a required scope.
#   5. Assert the package is listable and downloadable with the same token.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-scoped-token"
auth_admin
setup_workdir

begin_test "Backend accepts colon-form write:artifacts on upload paths (artifact-keeper#2993)"
require_feature "pypi_scoped_token_publish" || { end_suite; exit 0; }
pass

REPO_KEY="test-pypi-scoped-${RUN_ID}"
PKG_NAME="scopedpkg${RUN_ID//-/}"
PKG_VERSION="1.0.0"
PYPI_URL="${BASE_URL}/pypi/${REPO_KEY}"
SCOPED_TOKEN=""
SCOPED_TOKEN_ID=""

# ---------------------------------------------------------------------------
# Setup: hosted repo + least-privilege repo-scoped token
# ---------------------------------------------------------------------------

begin_test "Create pypi local repository"
if create_local_repo "$REPO_KEY" "pypi"; then
  pass
else
  fail "could not create pypi repository"
fi

begin_test "Mint repo-scoped read:artifacts+write:artifacts token"
# Raw curl rather than api_post: api_post uses `curl -sf`, which discards the
# response body on any non-2xx and collapses every failure into one shell exit
# code. With the `|| true` the call site needs, that left ${resp} empty on
# exactly the path the diagnostic is for, so the mint failure printed a bare
# "failed: " with no status and no body. Capture both, the way put_members in
# tests/repos/test-virtual-members-concurrent-put.sh does.
MINT_BODY_FILE="${WORK_DIR}/token-mint-resp.json"
MINT_STATUS=$(curl -s -o "$MINT_BODY_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"e2e-scoped-publish-${RUN_ID}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\"],\"expires_in_days\":1}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/tokens" 2>/dev/null) || MINT_STATUS="000"
resp=$(cat "$MINT_BODY_FILE" 2>/dev/null || true)
SCOPED_TOKEN=$(echo "$resp" | jq -r '.token // empty' 2>/dev/null) || SCOPED_TOKEN=""
SCOPED_TOKEN_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null) || SCOPED_TOKEN_ID=""
if [ -n "$SCOPED_TOKEN" ] && [ "$SCOPED_TOKEN" != "null" ]; then
  pass
else
  fail "repo-scoped token mint failed: HTTP ${MINT_STATUS}" "${resp:0:400}"
fi

# ---------------------------------------------------------------------------
# Build a minimal sdist (mirrors test-pypi.sh)
# ---------------------------------------------------------------------------

begin_test "Build sdist package"
cd "$WORK_DIR"
SDIST_DIR="${PKG_NAME}-${PKG_VERSION}"
mkdir -p "$SDIST_DIR"
cat > "${SDIST_DIR}/PKG-INFO" <<EOF
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${PKG_VERSION}
Summary: E2E scoped-token publish probe
EOF
cat > "${SDIST_DIR}/setup.py" <<EOF
from setuptools import setup
setup(name="${PKG_NAME}", version="${PKG_VERSION}")
EOF
SDIST_FILE="${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}.tar.gz"
if tar czf "$SDIST_FILE" -C "$WORK_DIR" "$SDIST_DIR"; then
  pass
else
  fail "failed to create sdist tarball"
fi

# ---------------------------------------------------------------------------
# Upload with the scoped token (the #3041 regression path)
# ---------------------------------------------------------------------------

SDIST_BASENAME=$(basename "$SDIST_FILE")
SDIST_SHA256=$(shasum -a 256 "$SDIST_FILE" | cut -d' ' -f1)
UPLOAD_BODY_FILE="${WORK_DIR}/upload-resp.txt"
UPLOAD_STATUS="000"

begin_test "Upload sdist with write:artifacts token succeeds"
if [ -z "${SCOPED_TOKEN:-}" ] || [ "$SCOPED_TOKEN" = "null" ]; then
  skip "no scoped token from mint step"
else
  UPLOAD_STATUS=$(curl -s -o "$UPLOAD_BODY_FILE" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST "${PYPI_URL}/" \
    -u "${ADMIN_USER}:${SCOPED_TOKEN}" \
    -F ":action=file_upload" \
    -F "name=${PKG_NAME}" \
    -F "version=${PKG_VERSION}" \
    -F "sha256_digest=${SDIST_SHA256}" \
    -F "filetype=sdist" \
    -F "content=@${SDIST_FILE};filename=${SDIST_BASENAME}" 2>/dev/null) || UPLOAD_STATUS="000"
  if assert_http_2xx "$UPLOAD_STATUS" "scoped-token upload should succeed"; then
    pass
  fi
fi

begin_test "Pre-fix 403 required-scope rejection is gone (artifact-keeper#3041 fingerprint)"
if [ -z "${SCOPED_TOKEN:-}" ] || [ "$SCOPED_TOKEN" = "null" ]; then
  skip "no scoped token from mint step"
else
  upload_body=$(head -c 400 "$UPLOAD_BODY_FILE" 2>/dev/null || true)
  if [ "$UPLOAD_STATUS" = "403" ] && echo "$upload_body" | grep -qi "required scope"; then
    fail "regression fingerprint (artifact-keeper#3041): write:artifacts token got 403 required-scope on upload" "$upload_body"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Verify the package is listable and downloadable with the same token
# ---------------------------------------------------------------------------

NORMALIZED_NAME=$(echo "$PKG_NAME" | tr '_' '-')

begin_test "Package listable via simple index with scoped token"
if [ -z "${SCOPED_TOKEN:-}" ] || [ "$SCOPED_TOKEN" = "null" ]; then
  skip "no scoped token from mint step"
else
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${SCOPED_TOKEN}" \
      "${PYPI_URL}/simple/${NORMALIZED_NAME}/" 2>/dev/null); then
    if assert_contains "$resp" ".tar.gz" "package index should list the sdist"; then
      pass
    fi
  else
    fail "GET ${PYPI_URL}/simple/${NORMALIZED_NAME}/ returned error with scoped token"
  fi
fi

begin_test "Package downloadable with scoped token (checksum round-trip)"
if [ -z "${SCOPED_TOKEN:-}" ] || [ "$SCOPED_TOKEN" = "null" ]; then
  skip "no scoped token from mint step"
else
  DL_FILE="${WORK_DIR}/downloaded.tar.gz"
  if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${SCOPED_TOKEN}" -o "$DL_FILE" \
      "${PYPI_URL}/simple/${NORMALIZED_NAME}/${SDIST_BASENAME}" 2>/dev/null; then
    DL_SHA256=$(shasum -a 256 "$DL_FILE" | cut -d' ' -f1)
    if assert_eq "$DL_SHA256" "$SDIST_SHA256" "SHA256 mismatch after scoped-token round-trip"; then
      pass
    fi
  else
    fail "download with scoped token failed"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

if [ -n "${SCOPED_TOKEN_ID:-}" ] && [ "$SCOPED_TOKEN_ID" != "null" ]; then
  api_delete "/api/v1/repositories/${REPO_KEY}/tokens/${SCOPED_TOKEN_ID}" > /dev/null 2>&1 || true
fi
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
