#!/usr/bin/env bash
# test-debian-xz-proxy.sh - Regression tests for Debian .xz index support
# and path traversal protection in the dists catch-all proxy.
#
# Bug #814:
#   1. Debian remote proxy returned 404 for .xz-compressed indices
#      (Packages.xz, Sources.xz, etc.)
#   2. The dists catch-all proxy had no path traversal protection,
#      allowing ../ sequences to escape the repository root.
#
# Requires: curl, ar (from binutils), tar, gzip
source "$(dirname "$0")/../lib/common.sh"

begin_suite "debian-xz-proxy"
auth_admin
setup_workdir

REPO_KEY="test-deb-xz-${RUN_ID}"
DISTRIBUTION="stable"
COMPONENT="main"
PKG_ARCH="amd64"

# -------------------------------------------------------------------------
# Helper: build a minimal .deb package from scratch using ar + tar
# -------------------------------------------------------------------------
build_deb() {
  local name="$1"
  local version="$2"
  local arch="$3"
  local outfile="$4"

  local build_dir="${WORK_DIR}/deb-build-${name}-${version}-${arch}"
  mkdir -p "${build_dir}"

  # debian-binary
  echo "2.0" > "${build_dir}/debian-binary"

  # control.tar.gz
  local ctrl_dir="${build_dir}/control-root"
  mkdir -p "${ctrl_dir}"
  cat > "${ctrl_dir}/control" <<CTRL
Package: ${name}
Version: ${version}
Section: utils
Priority: optional
Architecture: ${arch}
Maintainer: CI <ci@example.com>
Description: XZ proxy regression test package (${name} ${version} ${arch})
CTRL
  tar czf "${build_dir}/control.tar.gz" -C "${ctrl_dir}" ./control

  # data.tar.gz (minimal tree)
  local data_dir="${build_dir}/data-root"
  mkdir -p "${data_dir}/usr/share/doc/${name}"
  echo "${name} ${version}" > "${data_dir}/usr/share/doc/${name}/README"
  tar czf "${build_dir}/data.tar.gz" -C "${data_dir}" .

  # Assemble with ar
  if command -v ar &>/dev/null; then
    (cd "${build_dir}" && ar rcs "${outfile}" debian-binary control.tar.gz data.tar.gz 2>/dev/null)
  else
    cat "${build_dir}/debian-binary" "${build_dir}/control.tar.gz" "${build_dir}/data.tar.gz" > "${outfile}"
  fi
}

# -------------------------------------------------------------------------
# 1. Create repository and upload a test .deb
# -------------------------------------------------------------------------

begin_test "Create debian repository"
if create_local_repo "$REPO_KEY" "debian"; then
  pass
else
  fail "could not create debian repo"
fi

DEB_FILE="${WORK_DIR}/xztest_1.0.0_${PKG_ARCH}.deb"
build_deb "xztest" "1.0.0" "$PKG_ARCH" "$DEB_FILE"

begin_test "Upload test .deb package"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/vnd.debian.binary-package" \
    --data-binary "@${DEB_FILE}" \
    "${BASE_URL}/debian/${REPO_KEY}/pool/${COMPONENT}/xztest_1.0.0_${PKG_ARCH}.deb")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  fail "pool upload returned HTTP ${HTTP_CODE}, expected 2xx"
fi

# Allow metadata generation to complete
sleep 1

# -------------------------------------------------------------------------
# 2. Verify Packages.xz is served (the core .xz fix)
# -------------------------------------------------------------------------

DISTS_PREFIX="/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-${PKG_ARCH}"

begin_test "Packages.xz returns 200"
XZ_STATUS=$(curl -s -o "${WORK_DIR}/Packages.xz" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}${DISTS_PREFIX}/Packages.xz") || true

if [ "$XZ_STATUS" -ge 200 ] && [ "$XZ_STATUS" -lt 300 ]; then
  if [ -s "${WORK_DIR}/Packages.xz" ]; then
    pass
  else
    fail "Packages.xz returned ${XZ_STATUS} but body is empty"
  fi
else
  fail "Packages.xz returned HTTP ${XZ_STATUS}, expected 2xx"
fi

# -------------------------------------------------------------------------
# 3. Verify Packages.gz is still served (regression check)
# -------------------------------------------------------------------------

begin_test "Packages.gz still returns 200"
GZ_STATUS=$(curl -s -o "${WORK_DIR}/Packages.gz" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}${DISTS_PREFIX}/Packages.gz") || true

if [ "$GZ_STATUS" -ge 200 ] && [ "$GZ_STATUS" -lt 300 ]; then
  if [ -s "${WORK_DIR}/Packages.gz" ]; then
    pass
  else
    fail "Packages.gz returned ${GZ_STATUS} but body is empty"
  fi
else
  fail "Packages.gz returned HTTP ${GZ_STATUS}, expected 2xx"
fi

# -------------------------------------------------------------------------
# 4. Verify uncompressed Packages is still served
# -------------------------------------------------------------------------

begin_test "Uncompressed Packages still returns 200"
PLAIN_BODY=""
if PLAIN_BODY=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}${DISTS_PREFIX}/Packages" 2>/dev/null); then
  if echo "$PLAIN_BODY" | grep -q "Package: xztest"; then
    pass
  else
    fail "uncompressed Packages does not contain 'Package: xztest'"
  fi
else
  fail "uncompressed Packages endpoint returned error"
fi

# -------------------------------------------------------------------------
# 5. Verify .xz content decompresses to valid Packages data
# -------------------------------------------------------------------------

begin_test "Packages.xz decompresses to valid index"
if command -v xz &>/dev/null; then
  if xz -dc "${WORK_DIR}/Packages.xz" 2>/dev/null | grep -q "Package: xztest"; then
    pass
  else
    # The file was served, but decompression did not yield the expected content.
    # Check if the file at least decompresses without error.
    if xz -t "${WORK_DIR}/Packages.xz" 2>/dev/null; then
      fail "Packages.xz decompresses but does not contain 'Package: xztest'"
    else
      fail "Packages.xz is not valid xz data"
    fi
  fi
else
  skip "xz command not available, cannot verify decompression"
fi

# -------------------------------------------------------------------------
# 6. Path traversal on a hosted repo serves nothing.
#
# A hosted repo answers any unknown dists path with 404 (dists_proxy_catchall),
# so the assertion is on what is served: 400 or 404, and none of the bytes the
# probe is after. curl runs with --path-as-is throughout, or it would resolve
# the dot segments itself and the probe would never reach the backend.
# -------------------------------------------------------------------------

DISTS_BASE="/debian/${REPO_KEY}/dists/${DISTRIBUTION}"

# probe_traversal LABEL URL OUTFILE: echoes the HTTP status.
probe_traversal() {
  curl -s --path-as-is -o "$2" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "$1" || echo "000"
}

# assert_refused LABEL STATUS OUTFILE: 400/404 and no file content in the body.
assert_refused() {
  local label="$1" status="$2" body="$3"
  if [ "$status" != "400" ] && [ "$status" != "404" ]; then
    fail "${label} returned HTTP ${status}, expected 400 or 404"
  elif grep -qE '^root:|Package: xztest|^debian-binary' "$body" 2>/dev/null; then
    fail "${label} returned HTTP ${status} with file content in the body"
  else
    pass
  fi
}

begin_test "Hosted repo: path traversal with ../ is refused"
assert_refused "path traversal ../" \
  "$(probe_traversal "${BASE_URL}${DISTS_BASE}/../../../etc/passwd" "${WORK_DIR}/t1.out")" "${WORK_DIR}/t1.out"

begin_test "Hosted repo: path traversal with encoded %2e%2e is refused"
assert_refused "percent-encoded traversal" \
  "$(probe_traversal "${BASE_URL}${DISTS_BASE}/%2e%2e/%2e%2e/%2e%2e/etc/passwd" "${WORK_DIR}/t2.out")" "${WORK_DIR}/t2.out"

begin_test "Hosted repo: mid-path traversal (../../pool) does not reach the stored .deb"
assert_refused "mid-path traversal" \
  "$(probe_traversal "${BASE_URL}${DISTS_BASE}/${COMPONENT}/../../pool/main/xztest_1.0.0_amd64.deb" "${WORK_DIR}/t3.out")" "${WORK_DIR}/t3.out"

# -------------------------------------------------------------------------
# 7. Valid nested dists path is not rejected
# -------------------------------------------------------------------------

begin_test "Valid nested dists path returns 200 or 404 (not 400)"
# A legitimate deeply nested path under dists should never be rejected as
# a path traversal. It should return 200 if the resource exists, or 404
# if it does not, but never 400.
VALID_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}${DISTS_BASE}/${COMPONENT}/binary-${PKG_ARCH}/Packages") || true

if [ "$VALID_STATUS" = "400" ]; then
  fail "valid nested path was rejected with 400, path traversal filter is too aggressive"
elif [ "$VALID_STATUS" -ge 200 ] && [ "$VALID_STATUS" -lt 500 ]; then
  pass
else
  fail "valid nested path returned unexpected HTTP ${VALID_STATUS}"
fi

begin_test "Hosted repo: fully percent-encoded traversal (%2e%2e%2f) is refused"
assert_refused "fully percent-encoded traversal" \
  "$(probe_traversal "${BASE_URL}${DISTS_BASE}/%2e%2e%2f%2e%2e%2fetc%2fpasswd" "${WORK_DIR}/t4.out")" "${WORK_DIR}/t4.out"

# -------------------------------------------------------------------------
# 8. #814 proper: the catch-all only fetches upstream on a REMOTE repo, so that
#    is where a traversal could escape. The mock records every request the
#    backend makes; a dists fetch must arrive, the probes must not.
# -------------------------------------------------------------------------

begin_test "Remote repo: traversal probes never leave the upstream's dists tree"
if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip "needs MOCK_UPSTREAM_HOSTNAME reachable from the backend pod"
elif ! start_mock_upstream "${WORK_DIR}/mock-state"; then
  fail "mock upstream did not start"
else
  mkdir -p "${MOCK_STATE_DIR}/files/deb/dists/${DISTRIBUTION}/${COMPONENT}/i18n" "${MOCK_STATE_DIR}/files/etc"
  echo "translation canary" > "${MOCK_STATE_DIR}/files/deb/dists/${DISTRIBUTION}/${COMPONENT}/i18n/Translation-en"
  echo "root:traversal-canary" > "${MOCK_STATE_DIR}/files/etc/passwd"

  REMOTE_KEY="${REPO_KEY}-remote"
  if ! create_remote_repo "$REMOTE_KEY" "debian" "${MOCK_BASE_URL}/deb"; then
    fail "could not create debian remote repo"
  else
    REMOTE_DISTS="${BASE_URL}/debian/${REMOTE_KEY}/dists/${DISTRIBUTION}"
    CONTROL_STATUS=$(probe_traversal "${REMOTE_DISTS}/${COMPONENT}/i18n/Translation-en" "${WORK_DIR}/r0.out")
    REMOTE_BAD=""
    n=0
    for probe in \
        "../../../../etc/passwd" \
        "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" \
        "${COMPONENT}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" \
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"; do
      n=$((n + 1))
      st=$(probe_traversal "${REMOTE_DISTS}/${probe}" "${WORK_DIR}/r${n}.out")
      if [ "$st" != "400" ] && [ "$st" != "404" ]; then
        REMOTE_BAD="${REMOTE_BAD} ${probe}=>${st}"
      fi
      if grep -q 'traversal-canary' "${WORK_DIR}/r${n}.out" 2>/dev/null; then
        REMOTE_BAD="${REMOTE_BAD} ${probe}=>leaked"
      fi
    done
    MOCK_LOG="${MOCK_STATE_DIR}/request-log.txt"
    if [ "$CONTROL_STATUS" != "200" ] || ! grep -q "dists/${DISTRIBUTION}/${COMPONENT}/i18n/Translation-en" "$MOCK_LOG"; then
      fail "control fetch through the remote returned HTTP ${CONTROL_STATUS}; the probes prove nothing"
    elif grep -qE 'etc(/|%2[fF])passwd' "$MOCK_LOG"; then
      fail "a traversal probe reached the upstream" "$(grep -E 'etc(/|%2[fF])passwd' "$MOCK_LOG" | head -5)"
    elif [ -n "$REMOTE_BAD" ]; then
      fail "traversal probe not refused:${REMOTE_BAD}"
    else
      pass
    fi
  fi
fi

end_suite
