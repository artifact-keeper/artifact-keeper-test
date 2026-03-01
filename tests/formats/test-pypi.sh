#!/usr/bin/env bash
# test-pypi.sh - PyPI (PEP 503) E2E test
#
# Tests twine-style upload via multipart POST and pip install via the
# /pypi/{repo_key}/ endpoints.
#
# Requires: python3, pip3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi"
auth_admin
setup_workdir
require_cmd python3

REPO_KEY="test-pypi-${RUN_ID}"
PKG_NAME="test-pypi-pkg-${RUN_ID//-/_}"  # PyPI normalizes dashes to underscores
PKG_VERSION="1.0.$(date +%s)"
PYPI_URL="${BASE_URL}/pypi/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create pypi local repository"
if create_local_repo "$REPO_KEY" "pypi"; then
  pass
else
  fail "could not create pypi repository"
fi

# ---------------------------------------------------------------------------
# Build source distribution
# ---------------------------------------------------------------------------

begin_test "Build sdist package"

cd "$WORK_DIR"
mkdir -p "${PKG_NAME}"

cat > "${PKG_NAME}/setup.py" <<EOF
from setuptools import setup
setup(
    name="${PKG_NAME}",
    version="${PKG_VERSION}",
    py_modules=["${PKG_NAME}"],
    description="E2E test package for PyPI format",
)
EOF

cat > "${PKG_NAME}/${PKG_NAME}.py" <<EOF
__version__ = "${PKG_VERSION}"
def hello():
    return "Hello from ${PKG_NAME}"
EOF

cd "${PKG_NAME}"
if python3 setup.py sdist --formats=gztar > /dev/null 2>&1; then
  SDIST_FILE=$(ls dist/*.tar.gz 2>/dev/null | head -1)
  if [ -n "$SDIST_FILE" ]; then
    pass
  else
    fail "sdist created but no .tar.gz found"
  fi
else
  fail "python3 setup.py sdist failed"
fi

# ---------------------------------------------------------------------------
# Upload via curl (multipart POST, mimicking twine)
# ---------------------------------------------------------------------------

begin_test "Upload sdist via multipart POST"

SDIST_BASENAME=$(basename "$SDIST_FILE")
SDIST_SHA256=$(shasum -a 256 "$SDIST_FILE" | cut -d' ' -f1)

if resp=$(curl -sf -X POST "${PYPI_URL}/" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -F ":action=file_upload" \
  -F "name=${PKG_NAME}" \
  -F "version=${PKG_VERSION}" \
  -F "sha256_digest=${SDIST_SHA256}" \
  -F "filetype=sdist" \
  -F "content=@${SDIST_FILE};filename=${SDIST_BASENAME}" 2>&1); then
  pass
else
  fail "multipart upload failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Verify PEP 503 root index
# ---------------------------------------------------------------------------

begin_test "Verify PEP 503 root index"
sleep 1

# PyPI normalizes names: underscores become dashes in the simple index
NORMALIZED_NAME=$(echo "$PKG_NAME" | tr '_' '-')

if resp=$(curl -sf "${PYPI_URL}/simple/"); then
  if assert_contains "$resp" "$NORMALIZED_NAME" "root index should list the package"; then
    pass
  fi
else
  fail "GET ${PYPI_URL}/simple/ returned error"
fi

# ---------------------------------------------------------------------------
# Verify PEP 503 package index
# ---------------------------------------------------------------------------

begin_test "Verify PEP 503 package index"
if resp=$(curl -sf "${PYPI_URL}/simple/${NORMALIZED_NAME}/"); then
  if assert_contains "$resp" ".tar.gz" "package index should list the sdist"; then
    pass
  fi
else
  fail "GET ${PYPI_URL}/simple/${NORMALIZED_NAME}/ returned error"
fi

# ---------------------------------------------------------------------------
# Install via pip
# ---------------------------------------------------------------------------

begin_test "Install package with pip"

TRUSTED_HOST=$(echo "$BASE_URL" | sed -E 's|https?://||' | cut -d: -f1)

cd "$WORK_DIR"
mkdir -p pip-install-test

if pip3 install \
  --index-url "${PYPI_URL}/simple/" \
  --trusted-host "$TRUSTED_HOST" \
  --target "${WORK_DIR}/pip-install-test" \
  "${PKG_NAME}==${PKG_VERSION}" 2>&1; then
  pass
else
  fail "pip install failed"
fi

# ---------------------------------------------------------------------------
# Verify installed package content
# ---------------------------------------------------------------------------

begin_test "Verify installed package content"
export PYTHONPATH="${WORK_DIR}/pip-install-test:${PYTHONPATH:-}"
if output=$(python3 -c "from ${PKG_NAME} import hello; print(hello())" 2>&1); then
  if assert_contains "$output" "Hello from ${PKG_NAME}"; then
    pass
  fi
else
  fail "import of installed package failed: ${output}"
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
