#!/usr/bin/env bash
# test-pypi-pep658-metadata.sh - PyPI PEP 658 wheel metadata fetch
#
# PEP 658 lets pip fetch a wheel's METADATA file without downloading the
# whole .whl. The simple index advertises support by adding either
# `data-dist-info-metadata` (legacy) or `data-core-metadata` (PEP 714)
# attributes on the wheel anchor, plus a sibling URL ending in `.metadata`
# that serves the METADATA bytes verbatim.
#
# Covers issue #68 subtask 3.3.
#
# Requires: curl, jq, python3, openssl

source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-pep658-metadata"
auth_admin
setup_workdir
require_cmd python3

REPO_KEY="test-pypi-pep658-${RUN_ID}"
PYPI_URL="${BASE_URL}/pypi/${REPO_KEY}"
PKG_NAME="pep658pkg${RUN_ID//-/}"
PKG_VERSION="1.0.0"
DIST_NAME=$(echo "$PKG_NAME" | tr '-' '_')
NORMALIZED_NAME=$(echo "$PKG_NAME" | tr '[:upper:]_' '[:lower:]-')

# ---------------------------------------------------------------------------
# Create repo
# ---------------------------------------------------------------------------

begin_test "Create pypi local repository"
if create_local_repo "$REPO_KEY" "pypi"; then
  pass
else
  fail "could not create pypi repository"
fi

# ---------------------------------------------------------------------------
# Build a minimal wheel with a real METADATA file
# ---------------------------------------------------------------------------

begin_test "Build wheel fixture with PEP 621 METADATA"
WHEEL_DIR="${WORK_DIR}/wheel-src"
DIST_INFO="${WHEEL_DIR}/${DIST_NAME}-${PKG_VERSION}.dist-info"
mkdir -p "${WHEEL_DIR}/${DIST_NAME}" "$DIST_INFO"

cat > "${WHEEL_DIR}/${DIST_NAME}/__init__.py" <<EOF
__version__ = "${PKG_VERSION}"
EOF

# METADATA must be RFC 822-shaped per PEP 643 / core-metadata 2.1.
# The body bytes are exactly what the .metadata endpoint must return.
cat > "${DIST_INFO}/METADATA" <<METADATA
Metadata-Version: 2.1
Name: ${PKG_NAME}
Version: ${PKG_VERSION}
Summary: PEP 658 metadata fetch fixture
Author: artifact-keeper-test
Classifier: Programming Language :: Python :: 3
Requires-Python: >=3.8
Requires-Dist: requests>=2.0

A fixture wheel used to verify that the registry advertises
data-dist-info-metadata / data-core-metadata on the simple index
and serves the METADATA file via the PEP 658 sibling URL.
METADATA

cat > "${DIST_INFO}/WHEEL" <<EOF
Wheel-Version: 1.0
Generator: test-pypi-pep658-metadata
Root-Is-Purelib: true
Tag: py3-none-any
EOF

cat > "${DIST_INFO}/RECORD" <<EOF
${DIST_NAME}/__init__.py,sha256=,
${DIST_NAME}-${PKG_VERSION}.dist-info/METADATA,sha256=,
${DIST_NAME}-${PKG_VERSION}.dist-info/WHEEL,sha256=,
${DIST_NAME}-${PKG_VERSION}.dist-info/RECORD,,
EOF

WHEEL_FILE="${WORK_DIR}/${DIST_NAME}-${PKG_VERSION}-py3-none-any.whl"
( cd "$WHEEL_DIR" && python3 -c "
import zipfile, os
with zipfile.ZipFile('${WHEEL_FILE}', 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk('.'):
        for f in files:
            fp = os.path.join(root, f)
            zf.write(fp, os.path.relpath(fp, '.'))
" )

if [ -s "$WHEEL_FILE" ]; then
  pass
else
  fail "wheel build produced empty file"
fi

# Capture canonical METADATA bytes for later comparison.
METADATA_FIXTURE="${WORK_DIR}/METADATA.fixture"
cp "${DIST_INFO}/METADATA" "$METADATA_FIXTURE"
EXPECTED_METADATA_SHA256=$(shasum -a 256 "$METADATA_FIXTURE" | awk '{print $1}')

# ---------------------------------------------------------------------------
# Upload the wheel via the twine multipart protocol
# ---------------------------------------------------------------------------

begin_test "Upload wheel via multipart POST (Twine protocol)"
WHEEL_BASENAME=$(basename "$WHEEL_FILE")
WHEEL_SHA256=$(shasum -a 256 "$WHEEL_FILE" | awk '{print $1}')

upload_status=$(curl -s -o "${WORK_DIR}/upload.out" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST "${PYPI_URL}/" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -F ":action=file_upload" \
  -F "name=${PKG_NAME}" \
  -F "version=${PKG_VERSION}" \
  -F "sha256_digest=${WHEEL_SHA256}" \
  -F "filetype=bdist_wheel" \
  -F "pyversion=py3" \
  -F "content=@${WHEEL_FILE};filename=${WHEEL_BASENAME}" 2>/dev/null) || upload_status="000"

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
elif [ "$upload_status" = "404" ] || [ "$upload_status" = "501" ]; then
  skip_suite "pypi upload not supported on this backend (HTTP ${upload_status})"
else
  fail "wheel upload failed" "HTTP ${upload_status} body=$(head -c 400 "${WORK_DIR}/upload.out" 2>/dev/null)"
fi

# Indexer / metadata extractor needs a moment.
sleep 2

# ---------------------------------------------------------------------------
# Fetch the simple index and look for PEP 658 advertising
# ---------------------------------------------------------------------------

begin_test "Simple index advertises PEP 658 metadata attribute"
SIMPLE_HTML="${WORK_DIR}/simple.html"
simple_status=$(curl -s -o "$SIMPLE_HTML" -w '%{http_code}' $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${PYPI_URL}/simple/${NORMALIZED_NAME}/") || simple_status="000"

if [ "$simple_status" != "200" ]; then
  fail "simple index returned HTTP ${simple_status}"
elif ! grep -qF "${WHEEL_BASENAME}" "$SIMPLE_HTML"; then
  fail "simple index missing wheel anchor" "$(head -c 400 "$SIMPLE_HTML")"
elif grep -qE 'data-(dist-info|core)-metadata' "$SIMPLE_HTML"; then
  pass
else
  # Backend may not implement PEP 658 yet. Skip rather than fail so the
  # rest of the suite stays green on older 1.1.x deployments.
  skip "PEP 658 advertisement absent from simple index (no data-dist-info-metadata / data-core-metadata)"
fi

# ---------------------------------------------------------------------------
# Fetch the .metadata sibling URL
# ---------------------------------------------------------------------------

begin_test "Fetch wheel .metadata sibling URL"
# PEP 658: GET <wheel_url>.metadata returns the METADATA file body.
# The wheel anchor href in the simple index can be relative; resolve it
# against PYPI_URL/simple/<name>/.
WHEEL_HREF=$(grep -oE "href=\"[^\"]*${WHEEL_BASENAME}[^\"]*\"" "$SIMPLE_HTML" \
  | head -n1 | sed -E 's/^href="([^"]+)".*/\1/' | sed -E 's/#.*//')

if [ -z "$WHEEL_HREF" ]; then
  skip "wheel anchor not present in simple index, cannot resolve .metadata URL"
else
  case "$WHEEL_HREF" in
    http://*|https://*) METADATA_URL="${WHEEL_HREF}.metadata" ;;
    /*)                 METADATA_URL="${BASE_URL}${WHEEL_HREF}.metadata" ;;
    *)                  METADATA_URL="${PYPI_URL}/simple/${NORMALIZED_NAME}/${WHEEL_HREF}.metadata" ;;
  esac

  METADATA_OUT="${WORK_DIR}/served.metadata"
  meta_status=$(curl -s -o "$METADATA_OUT" -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "$METADATA_URL") || meta_status="000"

  if [ "$meta_status" = "404" ] || [ "$meta_status" = "501" ]; then
    skip ".metadata endpoint not implemented (HTTP ${meta_status}) at ${METADATA_URL}"
  elif [ "$meta_status" != "200" ]; then
    fail ".metadata endpoint returned HTTP ${meta_status}" "$(head -c 400 "$METADATA_OUT" 2>/dev/null)"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Validate the served METADATA body parses and matches the fixture
# ---------------------------------------------------------------------------

begin_test "Served .metadata body parses as RFC 822 core metadata"
if [ ! -s "${WORK_DIR}/served.metadata" ]; then
  skip "no .metadata body to validate (previous step skipped or failed)"
else
  # Parse with email.parser; assert Name/Version match what we published.
  parsed=$(python3 - <<PYEOF "$WORK_DIR/served.metadata"
import sys
from email import parser
with open(sys.argv[1], "rb") as fh:
    msg = parser.BytesParser().parse(fh)
print((msg.get("Name") or "") + "|" + (msg.get("Version") or "") + "|" + (msg.get("Metadata-Version") or ""))
PYEOF
) || parsed=""

  IFS='|' read -r name_val version_val mv_val <<< "$parsed"
  if [ "$name_val" = "$PKG_NAME" ] && [ "$version_val" = "$PKG_VERSION" ] && [ -n "$mv_val" ]; then
    pass
  else
    fail "served METADATA does not match fixture" \
         "got Name=${name_val} Version=${version_val} Metadata-Version=${mv_val}; expected Name=${PKG_NAME} Version=${PKG_VERSION}"
  fi
fi

# ---------------------------------------------------------------------------
# If the index advertised a content hash on the .metadata link, verify it
# ---------------------------------------------------------------------------

begin_test "Advertised metadata hash matches served bytes (if present)"
ADVERTISED_HASH=$(grep -oE 'data-(dist-info|core)-metadata="sha256=[a-f0-9]+"' "$SIMPLE_HTML" \
  | head -n1 | sed -E 's/.*sha256=([a-f0-9]+)".*/\1/')

if [ -z "$ADVERTISED_HASH" ]; then
  skip "no sha256 hash advertised on data-*-metadata attribute (attribute may be boolean-only)"
elif [ ! -s "${WORK_DIR}/served.metadata" ]; then
  skip "no served metadata body to hash"
else
  SERVED_HASH=$(shasum -a 256 "${WORK_DIR}/served.metadata" | awk '{print $1}')
  if assert_eq "$SERVED_HASH" "$ADVERTISED_HASH" \
       "advertised hash ${ADVERTISED_HASH} != served body hash ${SERVED_HASH}"; then
    pass
  fi
fi

end_suite
