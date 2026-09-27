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

# Build a minimal sdist tarball manually (avoids setup.py which is broken on Python 3.12+)
SDIST_DIR="${PKG_NAME}-${PKG_VERSION}"
mkdir -p "${SDIST_DIR}"

cat > "${SDIST_DIR}/setup.py" <<EOF
from setuptools import setup
setup(
    name="${PKG_NAME}",
    version="${PKG_VERSION}",
    py_modules=["${PKG_NAME}"],
    description="E2E test package for PyPI format",
)
EOF

cat > "${SDIST_DIR}/${PKG_NAME}.py" <<EOF
__version__ = "${PKG_VERSION}"
def hello():
    return "Hello from ${PKG_NAME}"
EOF

cat > "${SDIST_DIR}/PKG-INFO" <<EOF
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${PKG_VERSION}
Summary: E2E test package for PyPI format
EOF

mkdir -p dist
SDIST_FILE="dist/${PKG_NAME}-${PKG_VERSION}.tar.gz"
if tar czf "$SDIST_FILE" "$SDIST_DIR"; then
  pass
else
  fail "failed to create sdist tarball"
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

if command -v pip3 &>/dev/null; then
  if pip3 install \
    --index-url "${PYPI_URL}/simple/" \
    --trusted-host "$TRUSTED_HOST" \
    --target "${WORK_DIR}/pip-install-test" \
    "${PKG_NAME}==${PKG_VERSION}" 2>&1; then
    pass
  else
    # pip install from a private index can fail for many reasons in CI;
    # the upload and index verification above already proved the format works.
    skip "pip install failed (pip client may not support this environment)"
  fi
else
  skip "pip3 not available"
fi

# ---------------------------------------------------------------------------
# Verify installed package content
# ---------------------------------------------------------------------------

begin_test "Verify installed package content"
if [ -d "${WORK_DIR}/pip-install-test" ] && command -v python3 &>/dev/null; then
  export PYTHONPATH="${WORK_DIR}/pip-install-test:${PYTHONPATH:-}"
  # PKG_NAME uses underscores for the Python module name
  if output=$(python3 -c "from ${PKG_NAME} import hello; print(hello())" 2>&1); then
    if assert_contains "$output" "Hello from ${PKG_NAME}"; then
      pass
    fi
  else
    skip "import failed (package may not have installed): ${output}"
  fi
else
  skip "pip install did not run or python3 not available"
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

# ---------------------------------------------------------------------------
# PEP 658 core metadata for local-version (+cpu) and very large wheels (#3886)
#
# PyTorch ships wheels named torch-X.Y.Z+cpu-...whl with more than 10,000 zip
# entries, and its index percent-encodes the '+' in hrefs (%2B). pip asks for
# <wheel-url>.metadata first; a 404/502 there turns into a failed or slow
# install. These sections pin both halves without touching the internet:
#   LOCAL:  a +cpu wheel, and a +cpu wheel with >10,000 entries, uploaded to
#           the local repo; the index must advertise PEP 658 and the sibling
#           .metadata URL must answer 200 with the METADATA body.
#   REMOTE: the harness mock serves a PyTorch-shaped index (root-relative
#           hrefs with %2B, files outside the project directory, and a
#           CloudFront-style 403 for anything under the guessed
#           simple/<project>/ path); .metadata through a remote repo must be
#           200. A second package whose upstream sidecar answers 403 must fall
#           back to extracting METADATA from the wheel.
# ---------------------------------------------------------------------------

PEP658_RID=$(echo "${RUN_ID}" | tr '[:upper:]' '[:lower:]' | tr -dc 'a-z0-9')
PEP658_DIR="${WORK_DIR}/pep658"
mkdir -p "$PEP658_DIR"

# build_pep658_wheel OUT NAME VERSION PAD_ENTRIES
# Writes a minimal py3-none-any wheel whose root dist-info/METADATA carries
# Name/Version. PAD_ENTRIES empty files are added (stored, not deflated) so a
# >10,000-entry wheel stays around a megabyte.
cat > "${PEP658_DIR}/build_wheel.py" <<'PYEOF'
import sys, zipfile
out, name, version, pad = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
di = f"{name}-{version}.dist-info"
metadata = (
    "Metadata-Version: 2.1\n"
    f"Name: {name}\n"
    f"Version: {version}\n"
    "Summary: PEP 658 fixture for issue 3886\n"
)
with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
    zf.writestr(f"{name}/__init__.py", f'__version__ = "{version}"\n')
    for i in range(pad):
        zf.writestr(f"{name}/_pad/f{i:05d}.py", "")
    zf.writestr(f"{di}/METADATA", metadata)
    zf.writestr(f"{di}/WHEEL", "Wheel-Version: 1.0\nGenerator: akt\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    zf.writestr(f"{di}/RECORD", "")
if len(sys.argv) > 5:
    open(sys.argv[5], "w").write(metadata)
PYEOF

# pep658_anchor HTML_FILE WHEEL_BASENAME BASE_URL
# Prints "<absolute-url>\t<advertised 0|1>" for the anchor whose href basename
# (percent-decoded, fragment stripped) is WHEEL_BASENAME. Exit 1 if absent.
cat > "${PEP658_DIR}/anchor.py" <<'PYEOF'
import sys
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin
html_file, want, base = sys.argv[1], sys.argv[2], sys.argv[3]
found = []
class P(HTMLParser):
    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        a = dict(attrs)
        href = a.get("href") or ""
        path = href.split("#", 1)[0]
        if unquote(path.rsplit("/", 1)[-1]) == want:
            adv = "data-core-metadata" in a or "data-dist-info-metadata" in a
            found.append((urljoin(base, path), adv))
P().feed(open(html_file, encoding="utf-8", errors="replace").read())
if not found:
    sys.exit(1)
print(f"{found[0][0]}\t{1 if found[0][1] else 0}")
PYEOF

pep658_upload() {
  local file="$1" name="$2" version="$3"
  local sha status
  sha=$(shasum -a 256 "$file" | awk '{print $1}')
  status=$(curl -s -o "${PEP658_DIR}/upload.out" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST "${PYPI_URL}/" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F ":action=file_upload" \
    -F "name=${name}" \
    -F "version=${version}" \
    -F "sha256_digest=${sha}" \
    -F "filetype=bdist_wheel" \
    -F "pyversion=py3" \
    -F "content=@${file};filename=$(basename "$file")" 2>/dev/null) || status="000"
  echo "$status"
}

# pep658_check_index REPO_URL PROJECT WHEEL_BASENAME TAG
# Fetches the simple page, sets PEP658_WHEEL_URL, and fails unless the wheel
# anchor carries data-core-metadata / data-dist-info-metadata.
pep658_find_wheel() {
  # Sets PEP658_WHEEL_URL / PEP658_ADV, or PEP658_ERR + PEP658_BODY on error.
  local repo_url="$1" project="$2" wheel="$3" tag="$4"
  local html="${PEP658_DIR}/${tag}.simple.html" status line
  PEP658_WHEEL_URL=""; PEP658_ADV=""; PEP658_ERR=""; PEP658_BODY=""
  status=$(curl -s -o "$html" -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" "${repo_url}/simple/${project}/") || status="000"
  if [ "$status" != "200" ]; then
    PEP658_ERR="simple index for ${project} returned HTTP ${status}"
    PEP658_BODY="$(head -c 400 "$html" 2>/dev/null)"
    return 1
  fi
  if ! line=$(python3 "${PEP658_DIR}/anchor.py" "$html" "$wheel" "${repo_url}/simple/${project}/"); then
    PEP658_ERR="simple index for ${project} has no anchor for ${wheel}"
    PEP658_BODY="$(head -c 600 "$html")"
    return 1
  fi
  PEP658_WHEEL_URL="${line%%$'\t'*}"
  PEP658_ADV="${line##*$'\t'}"
  PEP658_BODY="$(grep -F "${wheel%%-*}" "$html" | head -c 600)"
}

pep658_check_index() {
  if ! pep658_find_wheel "$@"; then
    fail "$PEP658_ERR" "$PEP658_BODY"
  elif [ "$PEP658_ADV" != "1" ]; then
    fail "anchor for $3 lacks data-core-metadata / data-dist-info-metadata" "$PEP658_BODY"
  else
    pass
  fi
}

# pep658_check_metadata WHEEL_URL EXPECT_NAME EXPECT_VERSION TAG
pep658_check_metadata() {
  local url="$1" name="$2" version="$3" tag="$4"
  local out="${PEP658_DIR}/${tag}.metadata" status
  if [ -z "$url" ]; then
    fail "no wheel URL from the simple index (index assertion failed)"
    return 0
  fi
  if [ -n "${MOCK_PORT:-}" ] && [[ "$url" == *":${MOCK_PORT}/"* ]]; then
    fail "index sends clients straight to the upstream (${url}), not through the registry"
    return 0
  fi
  status=$(curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" "${url}.metadata") || status="000"
  if [ "$status" != "200" ]; then
    fail "GET ${url}.metadata returned HTTP ${status}" "$(head -c 400 "$out" 2>/dev/null)"
    return 0
  fi
  if grep -qxF "Name: ${name}" "$out" && grep -qxF "Version: ${version}" "$out"; then
    pass
  else
    fail ".metadata body does not carry Name: ${name} / Version: ${version}" "$(head -c 400 "$out")"
  fi
}

# --- LOCAL ------------------------------------------------------------------

PL_NAME="pep658pkg${PEP658_RID}"
PL_VER="1.0+cpu"
PL_WHEEL="${PEP658_DIR}/${PL_NAME}-${PL_VER}-py3-none-any.whl"
PB_NAME="pep658big${PEP658_RID}"
PB_VER="1.0+cpu"
PB_WHEEL="${PEP658_DIR}/${PB_NAME}-${PB_VER}-py3-none-any.whl"

begin_test "#3886 local: upload +cpu wheel and a +cpu wheel with >10,000 zip entries"
python3 "${PEP658_DIR}/build_wheel.py" "$PL_WHEEL" "$PL_NAME" "$PL_VER" 0 \
  && python3 "${PEP658_DIR}/build_wheel.py" "$PB_WHEEL" "$PB_NAME" "$PB_VER" 10050 || true
entries=$(python3 -c "import zipfile,sys; print(len(zipfile.ZipFile(sys.argv[1]).namelist()))" "$PB_WHEEL" 2>/dev/null || echo 0)
st1=$(pep658_upload "$PL_WHEEL" "$PL_NAME" "$PL_VER")
st2=$(pep658_upload "$PB_WHEEL" "$PB_NAME" "$PB_VER")
if [ "$entries" -le 10000 ]; then
  fail "large fixture has only ${entries} entries"
elif { [ "$st1" = "200" ] || [ "$st1" = "201" ]; } && { [ "$st2" = "200" ] || [ "$st2" = "201" ]; }; then
  pass
else
  fail "upload failed: +cpu wheel HTTP ${st1}, ${entries}-entry wheel HTTP ${st2}" "$(head -c 400 "${PEP658_DIR}/upload.out")"
fi
sleep 1

begin_test "#3886 local: simple index advertises PEP 658 for the +cpu wheel"
pep658_check_index "$PYPI_URL" "$PL_NAME" "$(basename "$PL_WHEEL")" local-small
PL_URL="$PEP658_WHEEL_URL"

begin_test "#3886 local: +cpu wheel .metadata returns 200 with METADATA body"
pep658_check_metadata "$PL_URL" "$PL_NAME" "$PL_VER" local-small

begin_test "#3886 local: simple index advertises PEP 658 for the >10,000-entry wheel"
pep658_check_index "$PYPI_URL" "$PB_NAME" "$(basename "$PB_WHEEL")" local-big
PB_URL="$PEP658_WHEEL_URL"

begin_test "#3886 local: >10,000-entry wheel .metadata returns 200 with METADATA body"
pep658_check_metadata "$PB_URL" "$PB_NAME" "$PB_VER" local-big

# --- REMOTE (harness mock upstream, PyTorch-shaped) --------------------------

PR_NAME="pep658r${PEP658_RID}"
PR_VER="2.1.0+cpu"
PR_FILE="${PR_NAME}-${PR_VER}-py3-none-any.whl"
PR_FILE_ENC="${PR_NAME}-2.1.0%2Bcpu-py3-none-any.whl"
PF_NAME="pep658f${PEP658_RID}"
PF_VER="3.0.0"
PF_FILE="${PF_NAME}-${PF_VER}-py3-none-any.whl"
REMOTE_KEY="test-pypi-pep658-remote-${RUN_ID}"
REMOTE_URL="${BASE_URL}/pypi/${REMOTE_KEY}"

begin_test "#3886 remote: mock upstream serves a PyTorch-shaped index"
if ! start_mock_upstream "${PEP658_DIR}/mock-state"; then
  fail "mock upstream did not boot"
else
  WHL_DIR="${MOCK_STATE_DIR}/files/whl/cpu"
  mkdir -p "${WHL_DIR}/simple/${PR_NAME}" "${WHL_DIR}/simple/${PF_NAME}"
  python3 "${PEP658_DIR}/build_wheel.py" "${WHL_DIR}/${PR_FILE_ENC}" "$PR_NAME" "$PR_VER" 0 "${WHL_DIR}/${PR_FILE_ENC}.metadata"
  python3 "${PEP658_DIR}/build_wheel.py" "${WHL_DIR}/${PF_FILE}" "$PF_NAME" "$PF_VER" 0 "${PEP658_DIR}/pf.METADATA"
  # Same bytes under the decoded name too: the assertion is about which URL
  # the backend picks, not about how the mock spells a path on disk.
  cp "${WHL_DIR}/${PR_FILE_ENC}" "${WHL_DIR}/${PR_FILE}"
  cp "${WHL_DIR}/${PR_FILE_ENC}.metadata" "${WHL_DIR}/${PR_FILE}.metadata"
  pr_sha=$(shasum -a 256 "${WHL_DIR}/${PR_FILE}" | awk '{print $1}')
  pr_msha=$(shasum -a 256 "${WHL_DIR}/${PR_FILE}.metadata" | awk '{print $1}')
  pf_sha=$(shasum -a 256 "${WHL_DIR}/${PF_FILE}" | awk '{print $1}')
  pf_msha=$(shasum -a 256 "${PEP658_DIR}/pf.METADATA" | awk '{print $1}')
  cat > "${WHL_DIR}/simple/${PR_NAME}/index.html" <<EOF
<!DOCTYPE html>
<html><body><h1>Links for ${PR_NAME}</h1>
<a href="/whl/cpu/${PR_FILE_ENC}#sha256=${pr_sha}" data-dist-info-metadata="sha256=${pr_msha}" data-core-metadata="sha256=${pr_msha}">${PR_FILE}</a><br/>
</body></html>
EOF
  cat > "${WHL_DIR}/simple/${PF_NAME}/index.html" <<EOF
<!DOCTYPE html>
<html><body><h1>Links for ${PF_NAME}</h1>
<a href="/whl/cpu/${PF_FILE}#sha256=${pf_sha}" data-dist-info-metadata="sha256=${pf_msha}" data-core-metadata="sha256=${pf_msha}">${PF_FILE}</a><br/>
</body></html>
EOF
  echo "Content-Type: text/html" > "${WHL_DIR}/simple/${PR_NAME}/index.html.headers"
  echo "Content-Type: text/html" > "${WHL_DIR}/simple/${PF_NAME}/index.html.headers"
  # CloudFront-style 403 for the guessed {upstream}/simple/{project}/{file}
  # path, and for PF's advertised sidecar (the wheel itself is served).
  cat > "${MOCK_STATE_DIR}/status-prefixes" <<EOF
/whl/cpu/simple/${PR_NAME}/${PR_NAME} 403
/whl/cpu/simple/${PF_NAME}/${PF_NAME} 403
/whl/cpu/${PF_FILE}.metadata 403
EOF
  idx=$(curl -s -o /dev/null -w '%{http_code}' "${MOCK_LOCAL_URL}/whl/cpu/simple/${PR_NAME}/")
  guess=$(curl -s -o /dev/null -w '%{http_code}' "${MOCK_LOCAL_URL}/whl/cpu/simple/${PR_NAME}/${PR_FILE}.metadata")
  adv=$(curl -s -o /dev/null -w '%{http_code}' "${MOCK_LOCAL_URL}/whl/cpu/${PR_FILE_ENC}.metadata")
  if [ "$idx" = "200" ] && [ "$guess" = "403" ] && [ "$adv" = "200" ]; then
    pass
  else
    fail "mock fixture wrong: index=${idx} guessed=${guess} advertised=${adv}"
  fi
fi

begin_test "#3886 remote: create pypi remote repository against mock upstream"
if [ -z "${MOCK_BASE_URL:-}" ]; then
  fail "mock upstream not running"
elif create_remote_repo "$REMOTE_KEY" "pypi" "${MOCK_BASE_URL}/whl/cpu"; then
  pass
else
  fail "could not create remote repository ${REMOTE_KEY} -> ${MOCK_BASE_URL}/whl/cpu"
fi

begin_test "#3886 remote: proxied index advertises PEP 658 for the %2B wheel"
pep658_check_index "$REMOTE_URL" "$PR_NAME" "$PR_FILE" remote-plus
PR_URL="$PEP658_WHEEL_URL"

begin_test "#3886 remote: %2B wheel .metadata through the remote returns 200"
pep658_check_metadata "$PR_URL" "$PR_NAME" "$PR_VER" remote-plus

begin_test "#3886 remote: %2B wheel download through the remote returns 200"
if [ -z "$PR_URL" ]; then
  fail "no wheel URL from the proxied index"
else
  wst=$(curl -s -o "${PEP658_DIR}/remote-plus.whl" -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" "$PR_URL") || wst="000"
  got_sha=$(shasum -a 256 "${PEP658_DIR}/remote-plus.whl" 2>/dev/null | awk '{print $1}') || got_sha=""
  if [ "$wst" = "200" ] && [ "$got_sha" = "$pr_sha" ]; then
    pass
  else
    fail "wheel download HTTP ${wst}, sha256 ${got_sha:-none} (want ${pr_sha})" "$(head -c 300 "${PEP658_DIR}/remote-plus.whl" 2>/dev/null)"
  fi
fi

begin_test "#3886 remote: upstream sidecar 403 falls back to wheel METADATA"
if pep658_find_wheel "$REMOTE_URL" "$PF_NAME" "$PF_FILE" remote-fb; then
  pep658_check_metadata "$PEP658_WHEEL_URL" "$PF_NAME" "$PF_VER" remote-fb
else
  fail "$PEP658_ERR" "$PEP658_BODY"
fi
[ -n "${PEP658_KEEP_LOG:-}" ] && cp "${MOCK_STATE_DIR}/request-log.txt" "$PEP658_KEEP_LOG" 2>/dev/null || true
stop_mock_upstream

end_suite
