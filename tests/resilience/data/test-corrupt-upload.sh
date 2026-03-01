#!/usr/bin/env bash
# test-corrupt-upload.sh - Verify server handles malformed uploads cleanly
#
# Uploads truncated, invalid, and zero-byte files to various format repos.
# Verifies the server either rejects them with a 4xx status or handles them
# without returning 500 errors or panics.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "data-corrupt-upload"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
GENERIC_REPO="data-corrupt-gen-${RUN_ID}"
NPM_REPO="data-corrupt-npm-${RUN_ID}"
PYPI_REPO="data-corrupt-pypi-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create repos for different formats
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$GENERIC_REPO" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Create npm repository"
if create_local_repo "$NPM_REPO" "npm"; then
  pass
else
  fail "could not create npm repo"
fi

begin_test "Create pypi repository"
if create_local_repo "$PYPI_REPO" "pypi"; then
  pass
else
  fail "could not create pypi repo"
fi

# ---------------------------------------------------------------------------
# Test: truncated tar.gz
# ---------------------------------------------------------------------------

begin_test "Upload truncated tar.gz to generic repo"
# Create a valid gzip header but truncate the content
printf '\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03' > "${WORK_DIR}/truncated.tar.gz"
dd if=/dev/urandom bs=100 count=1 >> "${WORK_DIR}/truncated.tar.gz" 2>/dev/null

trunc_status=$(curl -s -o "${WORK_DIR}/trunc-response.txt" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/truncated.tar.gz" \
  "${BASE_URL}/api/v1/repositories/${GENERIC_REPO}/artifacts/files/v1/truncated.tar.gz" 2>/dev/null || echo "000")
echo "  Truncated tar.gz upload status: ${trunc_status}"

# Accept 2xx (generic repo may accept any bytes) or 4xx (validation rejection)
# Reject 5xx as that indicates an unhandled error
if [ "$trunc_status" -ge 500 ] 2>/dev/null && [ "$trunc_status" -lt 600 ] 2>/dev/null; then
  fail "server returned 5xx (${trunc_status}) for truncated tar.gz"
else
  pass
fi

# ---------------------------------------------------------------------------
# Test: invalid JSON metadata for npm
# ---------------------------------------------------------------------------

begin_test "Upload invalid JSON metadata to npm repo"
# npm publish sends a PUT with JSON. Send garbage instead.
echo "this is not valid json {{{" > "${WORK_DIR}/bad-npm.json"

npm_status=$(curl -s -o "${WORK_DIR}/npm-response.txt" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary "@${WORK_DIR}/bad-npm.json" \
  "${BASE_URL}/npm/${NPM_REPO}/corrupt-pkg-${RUN_ID}" 2>/dev/null || echo "000")
echo "  Invalid npm JSON upload status: ${npm_status}"

if [ "$npm_status" -ge 500 ] 2>/dev/null && [ "$npm_status" -lt 600 ] 2>/dev/null; then
  fail "server returned 5xx (${npm_status}) for invalid npm JSON"
else
  echo "  Server returned ${npm_status} (expected 4xx rejection or clean handling)"
  pass
fi

# Check for panic in response
if [ -f "${WORK_DIR}/npm-response.txt" ]; then
  npm_body=$(cat "${WORK_DIR}/npm-response.txt")
  if echo "$npm_body" | grep -qi "panic"; then
    fail "npm response contains 'panic'"
  fi
fi

# ---------------------------------------------------------------------------
# Test: zero-byte file
# ---------------------------------------------------------------------------

begin_test "Upload zero-byte file to generic repo"
touch "${WORK_DIR}/empty.bin"

zero_status=$(curl -s -o "${WORK_DIR}/zero-response.txt" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/empty.bin" \
  "${BASE_URL}/api/v1/repositories/${GENERIC_REPO}/artifacts/files/v1/empty.bin" 2>/dev/null || echo "000")
echo "  Zero-byte upload status: ${zero_status}"

if [ "$zero_status" -ge 500 ] 2>/dev/null && [ "$zero_status" -lt 600 ] 2>/dev/null; then
  fail "server returned 5xx (${zero_status}) for zero-byte file"
else
  pass
fi

# ---------------------------------------------------------------------------
# Test: binary garbage as pypi package
# ---------------------------------------------------------------------------

begin_test "Upload binary garbage as pypi package"
dd if=/dev/urandom bs=256 count=1 of="${WORK_DIR}/garbage.whl" 2>/dev/null

pypi_status=$(curl -s -o "${WORK_DIR}/pypi-response.txt" -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -F ":action=file_upload" \
  -F "name=corrupt-pkg-${RUN_ID}" \
  -F "version=1.0.0" \
  -F "filetype=bdist_wheel" \
  -F "content=@${WORK_DIR}/garbage.whl" \
  "${BASE_URL}/pypi/${PYPI_REPO}/" 2>/dev/null || echo "000")
echo "  Binary garbage as pypi upload status: ${pypi_status}"

if [ "$pypi_status" -ge 500 ] 2>/dev/null && [ "$pypi_status" -lt 600 ] 2>/dev/null; then
  fail "server returned 5xx (${pypi_status}) for garbage pypi upload"
else
  pass
fi

# ---------------------------------------------------------------------------
# Test: very long filename
# ---------------------------------------------------------------------------

begin_test "Upload with excessively long filename"
LONG_NAME=$(printf 'a%.0s' {1..500})
long_status=$(curl -s -o "${WORK_DIR}/long-response.txt" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "some content" \
  "${BASE_URL}/api/v1/repositories/${GENERIC_REPO}/artifacts/files/v1/${LONG_NAME}.bin" 2>/dev/null || echo "000")
echo "  Long filename upload status: ${long_status}"

if [ "$long_status" -ge 500 ] 2>/dev/null && [ "$long_status" -lt 600 ] 2>/dev/null; then
  fail "server returned 5xx (${long_status}) for long filename"
else
  pass
fi

# ---------------------------------------------------------------------------
# Verify server is still healthy after all corrupt uploads
# ---------------------------------------------------------------------------

begin_test "Server still healthy after corrupt uploads"
health_status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$health_status" -ge 200 ] 2>/dev/null && [ "$health_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "server not healthy after corrupt upload tests (status: ${health_status})"
fi

# Verify no response contained a panic
begin_test "No response contained panic or stack trace"
found_panic=false
for resp_file in "${WORK_DIR}"/*-response.txt; do
  if [ -f "$resp_file" ]; then
    body=$(cat "$resp_file")
    if echo "$body" | grep -qi "panic\|stack trace\|RUST_BACKTRACE"; then
      fail "response in $(basename "$resp_file") contains panic/stack trace"
      found_panic=true
      break
    fi
  fi
done
if [ "$found_panic" = false ]; then
  pass
fi

end_suite
