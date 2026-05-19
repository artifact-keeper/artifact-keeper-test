#!/usr/bin/env bash
# test-debian-release-gpg-verify.sh
#
# End-to-end GPG signature validation for the Debian/APT repository
# signing chain.
#
# Covers Epic 4 sub-task 4.4 (#72) which was previously partial:
# `tests/formats/test-debian-conformance.sh` checks that
# `Release.gpg` exists as a file but does NOT validate the signature
# against the published public key. This test invokes the same `gpg
# --verify` flow that a real `apt update` client would run, so a
# regression that ships a malformed signature, the wrong key, or
# strips the signing chain entirely fails this gate even though the
# files still 200.
#
# artifact-keeper#1236 (commit 50c4d412, merged 2026-05-19) replaced
# placeholder Debian repo signing with real OpenPGP (rpgp / pgp
# crate). Pre-#1236 the Release.gpg / InRelease endpoints either
# 404'd or returned non-OpenPGP bytes; nothing in this repo would
# have caught a regression to that state. Post-#1236 the signatures
# must verify against the published gpg-key.asc.
#
# Test surfaces
# -------------
# 1. GET /debian/{repo}/dists/{dist}/Release      -> 200, text body
# 2. GET /debian/{repo}/dists/{dist}/Release.gpg  -> 200, detached signature
# 3. GET /debian/{repo}/dists/{dist}/InRelease    -> 200, inline-signed
# 4. GET /debian/{repo}/dists/{dist}/gpg-key.asc  -> 200, ASCII-armored public key
# 5. gpg --verify Release.gpg Release             -> exit 0 against the imported key
# 6. gpg --verify InRelease                       -> exit 0 against the imported key
# 7. Corrupted Release MUST fail verification     -> sig actually covers the body
#
# All gpg operations use a per-test GNUPGHOME under WORK_DIR so the
# runner's real keyring is untouched and parallel runs don't race.
#
# Requires: curl, gpg (v2+). dpkg-deb OR ar (binutils) for .deb
# construction so we have a real package whose metadata flows into
# the Release manifest.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "debian-release-gpg-verify"
require_cmd curl
require_cmd gpg
auth_admin
setup_workdir

REPO_KEY="test-deb-gpg-${RUN_ID}"
PKG_NAME="gpgtestpkg"
PKG_VERSION="1.0.0"
PKG_ARCH="amd64"
DISTRIBUTION="stable"
COMPONENT="main"
DEB_FILE="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"

# Per-test GNUPGHOME so we never touch the runner's real keyring.
# gpg requires 700 permissions on this dir or it warns; setting it
# explicitly so the warning doesn't pollute the test output.
GPG_HOME="${WORK_DIR}/gnupg-${RUN_ID}"
mkdir -p "${GPG_HOME}"
chmod 700 "${GPG_HOME}"
export GNUPGHOME="${GPG_HOME}"

# ---------------------------------------------------------------------------
# Create repo + upload a real .deb so the Release manifest has
# something to describe. The fix in #1236 signs whatever the Release
# generator emits; we want the manifest non-empty so a regression
# that signs a degenerate empty Release still trips this test.
# ---------------------------------------------------------------------------

begin_test "Create debian local repo"
if create_local_repo "$REPO_KEY" "debian"; then
  add_exit_handler "api_delete /api/v1/repositories/${REPO_KEY} >/dev/null 2>&1 || true"
  pass
else
  fail "could not create debian repo (${REPO_KEY})"
fi

begin_test "Build minimal .deb package"
DEB_DIR="${WORK_DIR}/deb-build"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/bin"
cat >"${DEB_DIR}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Section: utils
Priority: optional
Architecture: ${PKG_ARCH}
Maintainer: Test <test@example.com>
Description: GPG-verify regression-guard test package
EOF
echo '#!/bin/sh' >"${DEB_DIR}/usr/bin/${PKG_NAME}"
echo "echo gpg-test" >>"${DEB_DIR}/usr/bin/${PKG_NAME}"
chmod 755 "${DEB_DIR}/usr/bin/${PKG_NAME}"

if command -v dpkg-deb >/dev/null 2>&1; then
  if ! dpkg-deb --build "${DEB_DIR}" "${WORK_DIR}/${DEB_FILE}" >/dev/null 2>&1; then
    fail "dpkg-deb --build failed"
  fi
elif command -v ar >/dev/null 2>&1; then
  # Manual .deb assembly: ar archive of debian-binary + control.tar.gz + data.tar.gz
  (cd "${WORK_DIR}" && echo "2.0" >debian-binary)
  (cd "${DEB_DIR}/DEBIAN" && tar czf "${WORK_DIR}/control.tar.gz" ./control)
  (cd "${DEB_DIR}" && tar czf "${WORK_DIR}/data.tar.gz" ./usr)
  (cd "${WORK_DIR}" && ar rcs "${DEB_FILE}" debian-binary control.tar.gz data.tar.gz)
else
  fail "neither dpkg-deb nor ar available; cannot build a .deb"
fi

if [ -s "${WORK_DIR}/${DEB_FILE}" ]; then
  pass
else
  fail ".deb file is empty or missing"
fi

begin_test "Upload .deb via pool PUT"
http_code=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/vnd.debian.binary-package" \
  --data-binary "@${WORK_DIR}/${DEB_FILE}" \
  "${BASE_URL}/debian/${REPO_KEY}/pool/${COMPONENT}/${DEB_FILE}") || http_code=000
case "$http_code" in
  2*)
    pass
    ;;
  *)
    fail "pool upload returned HTTP ${http_code}, expected 2xx"
    ;;
esac

# ---------------------------------------------------------------------------
# Fetch the four signing-chain artifacts. We require all four; a
# missing endpoint is a regression in itself (pre-#1236 some of
# these routes returned 404 or non-OpenPGP bytes since the
# placeholder signer wasn't wired up).
# ---------------------------------------------------------------------------

DISTS_URL_BASE="${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}"
RELEASE_FILE="${WORK_DIR}/Release"
RELEASE_GPG_FILE="${WORK_DIR}/Release.gpg"
INRELEASE_FILE="${WORK_DIR}/InRelease"
KEY_FILE="${WORK_DIR}/gpg-key.asc"

fetch_artifact() {
  local url="$1"
  local out="$2"
  local desc="$3"
  local http_code
  http_code=$(curl -s -o "${out}" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" "${url}") || http_code=000
  case "$http_code" in
    200)
      if [ -s "${out}" ]; then
        pass
        return 0
      fi
      fail "${desc} returned 200 with empty body"
      return 1
      ;;
    *)
      fail "${desc} returned HTTP ${http_code}, expected 200"
      return 1
      ;;
  esac
}

begin_test "Fetch Release manifest"
fetch_artifact "${DISTS_URL_BASE}/Release" "${RELEASE_FILE}" "Release"

begin_test "Fetch Release.gpg detached signature"
fetch_artifact "${DISTS_URL_BASE}/Release.gpg" "${RELEASE_GPG_FILE}" "Release.gpg"

begin_test "Fetch InRelease inline-signed manifest"
fetch_artifact "${DISTS_URL_BASE}/InRelease" "${INRELEASE_FILE}" "InRelease"

begin_test "Fetch gpg-key.asc public key"
fetch_artifact "${DISTS_URL_BASE}/gpg-key.asc" "${KEY_FILE}" "gpg-key.asc"

# ---------------------------------------------------------------------------
# Shape sanity: each file MUST carry the appropriate OpenPGP armor
# header. A regression that ships a JSON / HTML / placeholder body
# with a 200 status would still pass the fetch tests above; this
# pins the actual content shape before we hand bytes to gpg.
# ---------------------------------------------------------------------------

begin_test "Release.gpg has OpenPGP signature armor"
if head -1 "${RELEASE_GPG_FILE}" | grep -q '^-----BEGIN PGP SIGNATURE-----$'; then
  pass
else
  fail "Release.gpg missing PGP SIGNATURE armor; got first line: $(head -1 "${RELEASE_GPG_FILE}")"
fi

begin_test "InRelease has OpenPGP signed-message armor"
if head -1 "${INRELEASE_FILE}" | grep -q '^-----BEGIN PGP SIGNED MESSAGE-----$'; then
  pass
else
  fail "InRelease missing PGP SIGNED MESSAGE armor; got first line: $(head -1 "${INRELEASE_FILE}")"
fi

begin_test "gpg-key.asc has OpenPGP public-key armor"
if head -1 "${KEY_FILE}" | grep -q '^-----BEGIN PGP PUBLIC KEY BLOCK-----$'; then
  pass
else
  fail "gpg-key.asc missing PGP PUBLIC KEY armor; got first line: $(head -1 "${KEY_FILE}")"
fi

# ---------------------------------------------------------------------------
# Import the repo's public key into the per-test GNUPGHOME. From here
# any gpg --verify will check signatures against THIS key only.
# Pinning the keyring means a regression that signs Release with the
# wrong key (e.g. an unrelated bootstrap key from another repo) fails
# verification even though armor headers look right.
# ---------------------------------------------------------------------------

begin_test "Import gpg-key.asc into per-test keyring"
if gpg --batch --import "${KEY_FILE}" >/dev/null 2>&1; then
  pass
else
  fail "gpg --import on gpg-key.asc failed; the published key is malformed"
fi

# ---------------------------------------------------------------------------
# The load-bearing assertions. apt itself runs the same gpg --verify
# shape against the repository's Release.gpg / InRelease, so this is
# the literal contract a real client checks.
# ---------------------------------------------------------------------------

begin_test "gpg --verify Release.gpg Release (detached signature valid)"
verify_log="${WORK_DIR}/verify-release-gpg.log"
if gpg --batch --verify "${RELEASE_GPG_FILE}" "${RELEASE_FILE}" >"${verify_log}" 2>&1; then
  pass
else
  fail "gpg verify of Release.gpg against Release failed; diagnostic: $(tail -3 "${verify_log}" | tr '\n' ' ')"
fi

begin_test "gpg --verify InRelease (inline signature valid)"
verify_log="${WORK_DIR}/verify-inrelease.log"
if gpg --batch --verify "${INRELEASE_FILE}" >"${verify_log}" 2>&1; then
  pass
else
  fail "gpg verify of InRelease failed; diagnostic: $(tail -3 "${verify_log}" | tr '\n' ' ')"
fi

# Negative control: a corrupted Release MUST fail verification. Pins
# that the signature actually covers the Release body (i.e. is not a
# constant blob that verifies regardless of payload).
begin_test "Corrupted Release fails verification (signature covers body)"
corrupted_release="${WORK_DIR}/Release.corrupted"
cp "${RELEASE_FILE}" "${corrupted_release}"
printf '\nx-tamper: 1\n' >>"${corrupted_release}"
verify_log="${WORK_DIR}/verify-corrupted.log"
if gpg --batch --verify "${RELEASE_GPG_FILE}" "${corrupted_release}" >"${verify_log}" 2>&1; then
  fail "corrupted Release verified successfully -- the detached signature is either constant or does not cover the manifest body"
else
  pass
fi

end_suite
