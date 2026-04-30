#!/usr/bin/env bash
# test-pypi-native-client.sh - PyPI native client smoke test
#
# Pushes a sdist via real `twine upload` and pulls it back via real
# `pip install`. The existing test-pypi.sh emulates the twine wire format
# with curl multipart, which is fine for protocol coverage but does not
# catch issues that only twine itself surfaces (auth realm parsing,
# 415 on missing filetype, redirect handling, .pypirc precedence).
#
# Skipped automatically when python3 is missing or twine cannot be
# bootstrapped.
#
# Requires: python3, pip3 (twine is installed on demand into a venv)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-native-client"
auth_admin
setup_workdir
require_cmd python3

REPO_KEY="test-pypi-nc-${RUN_ID}"
PKG_NAME="ak_native_smoke_${RUN_ID//-/_}"
PKG_VERSION="1.0.$(date +%s)"
PYPI_URL="${BASE_URL}/pypi/${REPO_KEY}"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create pypi local repository"
if create_local_repo "$REPO_KEY" "pypi"; then
  pass
else
  fail "could not create pypi repository"
fi

# -------------------------------------------------------------------------
# Bootstrap an isolated venv with twine + pip
#
# We use a venv rather than --user because the runner's site-packages may
# already have an incompatible twine, and because we want the test to be
# fully reproducible regardless of what the host has installed.
# -------------------------------------------------------------------------

begin_test "Bootstrap venv with twine"
VENV_DIR="${WORK_DIR}/venv"
if ! python3 -m venv "$VENV_DIR" 2>/dev/null; then
  skip "python3 -m venv failed (venv module may be missing)"
  end_suite
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# Pin twine to a known-good version. No floating :latest equivalents.
#
# twine 6.x is required because setuptools 75.x emits Metadata-Version 2.4
# in PKG-INFO, which twine 5.1.1's bundled pkginfo cannot parse. With the
# old combination twine reports "Metadata is missing required fields:
# Name, Version" before the upload ever leaves the client.
TWINE_VERSION="6.1.0"
if ! pip install --quiet --disable-pip-version-check "twine==${TWINE_VERSION}" 2>"${WORK_DIR}/pip-bootstrap.log"; then
  skip "could not install twine==${TWINE_VERSION}: $(tail -n 5 "${WORK_DIR}/pip-bootstrap.log" | tr '\n' ' ')"
  end_suite
fi

if command -v twine &>/dev/null; then
  pass
else
  fail "twine not on PATH after pip install"
fi

# -------------------------------------------------------------------------
# Build a real sdist + wheel
#
# We build both and upload both. The wheel is what `pip install` resolves
# to in the next step: an sdist would force pip to bootstrap its build
# backend (setuptools>=61) from the same private index, which doesn't
# proxy public PyPI in this test, so that resolution would always fail.
# The sdist is still uploaded so the index-listing assertions stay
# meaningful and so the upload path itself is exercised against both
# distribution types (twine treats them differently in its multipart
# encoding).
# -------------------------------------------------------------------------

begin_test "Build sdist tarball and wheel"
SRC_DIR="${WORK_DIR}/src"
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

cat > pyproject.toml <<EOF
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "${PKG_NAME}"
version = "${PKG_VERSION}"
description = "Artifact Keeper native-client smoke test package"
EOF

mkdir -p "${PKG_NAME}"
cat > "${PKG_NAME}/__init__.py" <<EOF
__version__ = "${PKG_VERSION}"
def hello():
    return "hello from ${PKG_NAME}"
EOF

# Pin the build backend version so this test does not break when
# setuptools or pyproject-build changes their CLI. wheel is required
# for `python -m build --wheel` to succeed without network calls.
if ! pip install --quiet --disable-pip-version-check "build==1.2.2" "setuptools==75.6.0" "wheel==0.45.1" 2>"${WORK_DIR}/pip-build.log"; then
  skip "could not install build/setuptools/wheel: $(tail -n 5 "${WORK_DIR}/pip-build.log" | tr '\n' ' ')"
  end_suite
fi

if python -m build --sdist --wheel --outdir "${WORK_DIR}/dist" "${SRC_DIR}" > "${WORK_DIR}/build.log" 2>&1; then
  pass
else
  fail "python -m build failed; tail: $(tail -n 10 "${WORK_DIR}/build.log" | tr '\n' ' ')"
fi

SDIST_FILE=$(ls "${WORK_DIR}/dist/"*.tar.gz 2>/dev/null | head -n1)
WHEEL_FILE=$(ls "${WORK_DIR}/dist/"*.whl 2>/dev/null | head -n1)

# -------------------------------------------------------------------------
# twine upload
# -------------------------------------------------------------------------

begin_test "twine upload pushes sdist and wheel"
if [ -z "$SDIST_FILE" ] || [ ! -s "$SDIST_FILE" ]; then
  fail "no sdist file to upload"
elif [ -z "$WHEEL_FILE" ] || [ ! -s "$WHEEL_FILE" ]; then
  fail "no wheel file to upload"
else
  upload_log="${WORK_DIR}/twine-upload.log"
  if TWINE_USERNAME="$ADMIN_USER" \
     TWINE_PASSWORD="$ADMIN_PASS" \
     twine upload \
       --repository-url "${PYPI_URL}/" \
       --non-interactive \
       --disable-progress-bar \
       "$SDIST_FILE" "$WHEEL_FILE" \
       > "$upload_log" 2>&1; then
    pass
  else
    fail "twine upload failed; tail: $(tail -n 15 "$upload_log" | tr '\n' ' ')"
  fi
fi

# -------------------------------------------------------------------------
# pip install from the simple index
# -------------------------------------------------------------------------

begin_test "pip install pulls package from simple index"
TRUSTED_HOST=$(echo "$BASE_URL" | sed -E 's|https?://||' | cut -d: -f1)
INSTALL_TARGET="${WORK_DIR}/install-target"
mkdir -p "$INSTALL_TARGET"

# pip on private index needs credentials in the URL. Build the index URL
# with embedded basic auth, which is what real users do for non-PyPI
# indexes that lack token auth. We splice the credentials in manually
# rather than using bash parameter substitution to keep the shape
# obvious to a reader.
if [[ "$BASE_URL" == https://* ]]; then
  AUTHED_BASE="https://${ADMIN_USER}:${ADMIN_PASS}@${BASE_URL#https://}"
else
  AUTHED_BASE="http://${ADMIN_USER}:${ADMIN_PASS}@${BASE_URL#http://}"
fi
INDEX_URL="${AUTHED_BASE}/pypi/${REPO_KEY}/simple/"

install_log="${WORK_DIR}/pip-install.log"
# --only-binary=:all: forces pip to resolve the wheel and never fall back
# to the sdist. Falling back would require pip to bootstrap setuptools>=61
# from this same private index, which doesn't proxy public PyPI, so an
# sdist resolution would always fail with "No matching distribution
# found for setuptools>=61". Keeping the install wheel-only also matches
# how the upload step above publishes both sdist + wheel: this asserts
# the wheel survived the round trip.
if pip install \
    --quiet \
    --disable-pip-version-check \
    --index-url "$INDEX_URL" \
    --trusted-host "$TRUSTED_HOST" \
    --only-binary=:all: \
    --target "$INSTALL_TARGET" \
    "${PKG_NAME}==${PKG_VERSION}" \
    > "$install_log" 2>&1; then
  pass
else
  fail "pip install failed; tail: $(tail -n 15 "$install_log" | tr '\n' ' ')"
fi

# -------------------------------------------------------------------------
# Import the installed module to confirm bytes round-tripped intact
# -------------------------------------------------------------------------

begin_test "Import installed module"
if PYTHONPATH="$INSTALL_TARGET" python -c "import ${PKG_NAME}; print(${PKG_NAME}.hello())" \
    > "${WORK_DIR}/import.log" 2>&1; then
  if assert_contains "$(cat "${WORK_DIR}/import.log")" "hello from ${PKG_NAME}"; then
    pass
  fi
else
  fail "import failed; tail: $(tail -n 10 "${WORK_DIR}/import.log" | tr '\n' ' ')"
fi

deactivate || true

end_suite
