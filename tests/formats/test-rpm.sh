#!/usr/bin/env bash
# test-rpm.sh - RPM/YUM repository E2E test
#
# Requires: curl, gzip; docker (optional, for the dnf client check; image
#           RPM_CLIENT_IMAGE, default rockylinux:9)
# Tests: create local repo, upload .rpm package, verify repodata and download;
#        dependency metadata in primary.xml + dnf dependency resolution (#3801)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rpm"
auth_admin
setup_workdir

REPO_KEY="test-rpm-${RUN_ID}"
PKG_NAME="testpkg"
PKG_VERSION="1.0.0"
RPM_FILE="${PKG_NAME}-${PKG_VERSION}-1.x86_64.rpm"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create rpm repository"
if create_local_repo "$REPO_KEY" "rpm"; then
  pass
else
  fail "could not create rpm repo"
fi

# -------------------------------------------------------------------------
# Build a minimal .rpm package (or binary blob)
# -------------------------------------------------------------------------

begin_test "Create minimal .rpm package"
if command -v rpmbuild &>/dev/null; then
  # Build a real RPM if rpmbuild is available
  RPM_TOPDIR="${WORK_DIR}/rpmbuild"
  mkdir -p "${RPM_TOPDIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

  cat > "${RPM_TOPDIR}/SPECS/${PKG_NAME}.spec" <<EOF
Name:    ${PKG_NAME}
Version: ${PKG_VERSION}
Release: 1
Summary: E2E test RPM package
License: MIT
BuildArch: x86_64

%description
Test package for artifact-keeper RPM registry.

%install
mkdir -p %{buildroot}/usr/bin
echo '#!/bin/sh' > %{buildroot}/usr/bin/${PKG_NAME}
echo 'echo hello from ${PKG_NAME}' >> %{buildroot}/usr/bin/${PKG_NAME}
chmod 755 %{buildroot}/usr/bin/${PKG_NAME}

%files
/usr/bin/${PKG_NAME}
EOF

  rpmbuild --define "_topdir ${RPM_TOPDIR}" -bb "${RPM_TOPDIR}/SPECS/${PKG_NAME}.spec" 2>/dev/null
  RPM_PATH=$(find "${RPM_TOPDIR}/RPMS" -name "*.rpm" -type f | head -1)
  if [ -n "$RPM_PATH" ]; then
    cp "$RPM_PATH" "${WORK_DIR}/${RPM_FILE}"
  fi
else
  # Create a minimal binary blob with the RPM magic number.
  # The RPM lead is: 4-byte magic (0xed 0xab 0xee 0xdb) + header.
  # This is enough for the registry to accept it as an RPM upload.
  printf '\xed\xab\xee\xdb' > "${WORK_DIR}/${RPM_FILE}"
  # Add some padding to make it look like a real RPM (96-byte lead)
  dd if=/dev/zero bs=1 count=92 2>/dev/null >> "${WORK_DIR}/${RPM_FILE}"
  # Append a small payload so the file is not trivially empty
  echo "${PKG_NAME}-${PKG_VERSION}" >> "${WORK_DIR}/${RPM_FILE}"
fi

if [ -s "${WORK_DIR}/${RPM_FILE}" ]; then
  pass
else
  fail "failed to create .rpm package"
fi

# -------------------------------------------------------------------------
# Upload .rpm via PUT
# -------------------------------------------------------------------------

begin_test "Upload .rpm via packages endpoint"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/x-rpm" \
    --data-binary "@${WORK_DIR}/${RPM_FILE}" \
    "${BASE_URL}/rpm/${REPO_KEY}/packages/${RPM_FILE}")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  fail "packages upload returned HTTP ${HTTP_CODE}, expected 2xx"
fi

# -------------------------------------------------------------------------
# Verify repomd.xml
# -------------------------------------------------------------------------

begin_test "Verify repomd.xml"
sleep 1
if resp=$(api_get "/rpm/${REPO_KEY}/repodata/repomd.xml" 2>/dev/null); then
  if assert_contains "$resp" "repomd"; then
    pass
  fi
else
  fail "repomd.xml endpoint returned error"
fi

# -------------------------------------------------------------------------
# Verify primary.xml.gz
# -------------------------------------------------------------------------

begin_test "Verify primary.xml.gz"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/primary.xml.gz" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/primary.xml.gz" 2>/dev/null; then
  if [ -s "${WORK_DIR}/primary.xml.gz" ]; then
    pass
  else
    fail "primary.xml.gz is empty"
  fi
else
  fail "primary.xml.gz endpoint returned error"
fi

# -------------------------------------------------------------------------
# Download .rpm from packages
# -------------------------------------------------------------------------

begin_test "Download .rpm from packages endpoint"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/downloaded.rpm" \
    "${BASE_URL}/rpm/${REPO_KEY}/packages/${RPM_FILE}" 2>/dev/null; then
  if [ -s "${WORK_DIR}/downloaded.rpm" ]; then
    pass
  else
    fail "downloaded .rpm is empty"
  fi
else
  fail "package download returned error"
fi

# -------------------------------------------------------------------------
# Verify filelists.xml.gz and other.xml.gz
# -------------------------------------------------------------------------

begin_test "Verify filelists.xml.gz"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/filelists.xml.gz" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/filelists.xml.gz" 2>/dev/null; then
  if [ -s "${WORK_DIR}/filelists.xml.gz" ]; then
    pass
  else
    fail "filelists.xml.gz is empty"
  fi
else
  fail "filelists.xml.gz endpoint returned error"
fi

begin_test "Verify other.xml.gz"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/other.xml.gz" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/other.xml.gz" 2>/dev/null; then
  if [ -s "${WORK_DIR}/other.xml.gz" ]; then
    pass
  else
    fail "other.xml.gz is empty"
  fi
else
  fail "other.xml.gz endpoint returned error"
fi

# -------------------------------------------------------------------------
# Upload via alternative POST endpoint
# -------------------------------------------------------------------------

begin_test "Upload .rpm via POST upload endpoint"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/x-rpm" \
    -H "X-Package-Filename: ${RPM_FILE}" \
    --data-binary "@${WORK_DIR}/${RPM_FILE}" \
    "${BASE_URL}/rpm/${REPO_KEY}/upload")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  if [ "$HTTP_CODE" = "409" ]; then
    pass  # already exists is acceptable
  else
    fail "POST upload returned HTTP ${HTTP_CODE}"
  fi
fi

# =========================================================================
# artifact-keeper#3801: dependency metadata in a Local repo's primary.xml
# =========================================================================
# A Local RPM repository used to serve a primary.xml whose <format> block held
# only license and sourcerpm: no <rpm:provides>, <rpm:requires> or any other
# dependency list. dnf/yum resolve dependencies from primary.xml alone, so
# installing a package from the repo never pulled in what it needs.
#
# Fixtures (deploy-test/fixtures/rpm, rebuilt by build.sh there):
#   akdep-lib-1.0-1.noarch.rpm  Provides: akdep-libfoo = 1.0
#   akdep-app-2.0-1.noarch.rpm  Requires: akdep-libfoo >= 1.0
# Both go into a dedicated repo so the magic-bytes blob above (when rpmbuild
# is absent) cannot disturb the client check.

RPM_FIXTURE_DIR="$(cd "$(dirname "$0")/../../deploy-test/fixtures/rpm" 2>/dev/null && pwd)"
DEPS_REPO_KEY="test-rpm-deps-${RUN_ID}"
DEPS_LIB_RPM="akdep-lib-1.0-1.noarch.rpm"
DEPS_APP_RPM="akdep-app-2.0-1.noarch.rpm"
RPM_CLIENT_IMAGE="${RPM_CLIENT_IMAGE:-rockylinux:9}"

# pkg_block <primary.xml> <name>: print the <package> element for <name>.
pkg_block() {
  awk -v want="<name>$2</name>" 'BEGIN { RS = "</package>" } index($0, want) { print; exit }' "$1"
}

# dep_list <package block> <tag>: print the <rpm:TAG>...</rpm:TAG> list.
dep_list() {
  printf '%s\n' "$1" | tr '\n' ' ' | sed -n "s|.*\(<rpm:$2>.*</rpm:$2>\).*|\1|p"
}

# decompress_to <in> <out>: by the extension repomd.xml advertised.
decompress_to() {
  case "$1" in
    *.gz)  gzip -dc "$1" > "$2" ;;
    *.zst) zstd -qdc "$1" > "$2" ;;
    *.xz)  xz -dc "$1" > "$2" ;;
    *.bz2) bzip2 -dc "$1" > "$2" ;;
    *)     cp "$1" "$2" ;;
  esac
}

begin_test "#3801 create rpm repository for dependency metadata"
if [ -z "$RPM_FIXTURE_DIR" ] || [ ! -s "${RPM_FIXTURE_DIR}/${DEPS_LIB_RPM}" ] || \
   [ ! -s "${RPM_FIXTURE_DIR}/${DEPS_APP_RPM}" ]; then
  fail "fixture RPMs missing under deploy-test/fixtures/rpm"
elif create_local_repo "$DEPS_REPO_KEY" "rpm"; then
  pass
else
  fail "could not create rpm repo ${DEPS_REPO_KEY}"
fi

for _rpm in "$DEPS_LIB_RPM" "$DEPS_APP_RPM"; do
  begin_test "#3801 upload ${_rpm}"
  HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X PUT \
      -H "$(format_auth_header)" \
      -H "Content-Type: application/x-rpm" \
      --data-binary "@${RPM_FIXTURE_DIR}/${_rpm}" \
      "${BASE_URL}/rpm/${DEPS_REPO_KEY}/packages/${_rpm}") || HTTP_CODE="000"
  if [ "$HTTP_CODE" -ge 200 ] 2>/dev/null && [ "$HTTP_CODE" -lt 300 ]; then
    pass
  else
    fail "upload of ${_rpm} returned HTTP ${HTTP_CODE}, expected 2xx"
  fi
done

begin_test "#3801 repomd.xml advertises primary metadata"
PRIMARY_HREF=""
if curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" -o "${WORK_DIR}/deps-repomd.xml" \
    "${BASE_URL}/rpm/${DEPS_REPO_KEY}/repodata/repomd.xml"; then
  PRIMARY_HREF=$(awk 'BEGIN { RS = "</data>" } /<data type="primary">/ { print; exit }' \
      "${WORK_DIR}/deps-repomd.xml" | grep -o 'href="[^"]*"' | head -1 | sed 's/^href="//; s/"$//')
  if [ -n "$PRIMARY_HREF" ]; then
    pass
  else
    fail "no <data type=\"primary\"> location in repomd.xml" "$(head -c 1500 "${WORK_DIR}/deps-repomd.xml")"
  fi
else
  fail "repomd.xml for ${DEPS_REPO_KEY} returned an error"
fi

begin_test "#3801 fetch primary metadata named by repomd.xml"
PRIMARY_XML="${WORK_DIR}/deps-primary.xml"
if [ -z "$PRIMARY_HREF" ]; then
  fail "no primary href to fetch"
else
  PRIMARY_RAW="${WORK_DIR}/deps-$(basename "$PRIMARY_HREF")"
  if curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" -o "$PRIMARY_RAW" \
        "${BASE_URL}/rpm/${DEPS_REPO_KEY}/${PRIMARY_HREF}" && \
     decompress_to "$PRIMARY_RAW" "$PRIMARY_XML" && \
     grep -q '<name>akdep-app</name>' "$PRIMARY_XML" && \
     grep -q '<name>akdep-lib</name>' "$PRIMARY_XML"; then
    pass
  else
    fail "could not fetch/decompress ${PRIMARY_HREF} or it lacks both packages" \
      "$(head -c 1500 "$PRIMARY_XML" 2>/dev/null)"
  fi
fi

begin_test "#3801 primary.xml lists akdep-libfoo in akdep-lib <rpm:provides>"
LIB_BLOCK=$(pkg_block "$PRIMARY_XML" akdep-lib 2>/dev/null || true)
LIB_PROVIDES=$(dep_list "$LIB_BLOCK" provides)
if [ -z "$LIB_PROVIDES" ]; then
  fail "akdep-lib has no <rpm:provides> in primary.xml" "$LIB_BLOCK"
elif assert_contains "$LIB_PROVIDES" 'name="akdep-libfoo" flags="EQ" epoch="0" ver="1.0"' \
       "akdep-lib <rpm:provides> lacks akdep-libfoo = 1.0"; then
  pass
fi

begin_test "#3801 primary.xml lists akdep-libfoo in akdep-app <rpm:requires>"
APP_BLOCK=$(pkg_block "$PRIMARY_XML" akdep-app 2>/dev/null || true)
APP_REQUIRES=$(dep_list "$APP_BLOCK" requires)
if [ -z "$APP_REQUIRES" ]; then
  fail "akdep-app has no <rpm:requires> in primary.xml" "$APP_BLOCK"
elif assert_contains "$APP_REQUIRES" 'name="akdep-libfoo" flags="GE" epoch="0" ver="1.0"' \
       "akdep-app <rpm:requires> lacks akdep-libfoo >= 1.0"; then
  if assert_not_contains "$APP_REQUIRES" 'rpmlib(' \
       "rpmlib() requires must be dropped, as createrepo_c does"; then
    pass
  fi
fi

# -------------------------------------------------------------------------
# Real client: dnf in an EL9 container resolves the dependency from the repo
# -------------------------------------------------------------------------
DNF_LOG="${WORK_DIR}/dnf-client.log"
DNF_STATE="unavailable"   # unavailable | ran | broken
if command -v docker &>/dev/null && \
   { docker image inspect "$RPM_CLIENT_IMAGE" &>/dev/null || docker pull -q "$RPM_CLIENT_IMAGE" &>/dev/null; }; then
  # --network host so the container reaches BASE_URL exactly as the runner
  # does. Credentials go in via the environment, not the command line.
  AKT_BASEURL="${BASE_URL}/rpm/${DEPS_REPO_KEY}/" AKT_USER="$ADMIN_USER" AKT_PASS="$ADMIN_PASS" \
  timeout 600 docker run --rm --network host \
    -e AKT_BASEURL -e AKT_USER -e AKT_PASS \
    "$RPM_CLIENT_IMAGE" bash -c '
cat > /etc/yum.repos.d/akt-deps.repo <<EOF
[akt-deps]
name=artifact-keeper e2e deps
baseurl=${AKT_BASEURL}
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=0
username=${AKT_USER}
password=${AKT_PASS}
EOF
dnf -y --disablerepo="*" --enablerepo=akt-deps install akdep-app
echo "DNF_INSTALL_RC=$?"
echo "INSTALLED_BEGIN"
rpm -qa --qf "%{NAME}\n" "akdep-*"
echo "INSTALLED_END"
echo "REPOQUERY_BEGIN"
dnf -q --disablerepo="*" --enablerepo=akt-deps repoquery --requires akdep-app
echo "REPOQUERY_END"
' > "$DNF_LOG" 2>&1 || true
  if grep -q '^DNF_INSTALL_RC=' "$DNF_LOG"; then DNF_STATE="ran"; else DNF_STATE="broken"; fi
fi

# dnf_precheck: record skip/fail when the client never got to run. Returns 1
# if the caller should not evaluate the log.
dnf_precheck() {
  case "$DNF_STATE" in
    ran) return 0 ;;
    unavailable) skip "docker or ${RPM_CLIENT_IMAGE} unavailable; cannot run the dnf client" ;;
    *) fail "dnf client container did not run to completion" "$(tail -n 40 "$DNF_LOG")" ;;
  esac
  return 1
}

begin_test "#3801 dnf install akdep-app from the Local repo succeeds"
if ! dnf_precheck; then
  :
elif grep -q '^DNF_INSTALL_RC=0$' "$DNF_LOG"; then
  pass
else
  fail "dnf install akdep-app failed" "$(tail -n 40 "$DNF_LOG")"
fi

begin_test "#3801 dnf pulls in akdep-lib as a dependency of akdep-app"
if dnf_precheck; then
  INSTALLED=$(sed -n '/^INSTALLED_BEGIN$/,/^INSTALLED_END$/p' "$DNF_LOG")
  if printf '%s\n' "$INSTALLED" | grep -qx 'akdep-app' && \
     printf '%s\n' "$INSTALLED" | grep -qx 'akdep-lib'; then
    pass
  else
    fail "expected both akdep-app and akdep-lib installed, got: $(printf '%s' "$INSTALLED" | grep -v '_BEGIN\|_END' | tr '\n' ' ')" \
      "$(tail -n 40 "$DNF_LOG")"
  fi
fi

begin_test "#3801 dnf repoquery --requires akdep-app lists akdep-libfoo"
if dnf_precheck; then
  REQS=$(sed -n '/^REPOQUERY_BEGIN$/,/^REPOQUERY_END$/p' "$DNF_LOG")
  if printf '%s\n' "$REQS" | grep -q '^akdep-libfoo >= 1.0$'; then
    pass
  else
    fail "repoquery --requires did not list 'akdep-libfoo >= 1.0'" "$REQS"
  fi
fi

end_suite
