#!/usr/bin/env bash
# test-debian-packages-xz.sh - Debian Packages.xz in apt-update flow (#72.5)
#
# `apt update` on a Debian client will preferentially fetch
# dists/<suite>/<comp>/binary-<arch>/Packages.xz (and bz2/gz/zst) instead
# of the uncompressed Packages, because xz compresses ~70% better. The
# 1.1.x backend ships Packages.xz (see test-debian-xz-proxy.sh) but no
# conformance test ties the .xz payload to the dist Release manifest the
# way apt-secure does:
#
#   apt fetches Release -> reads "SHA256:" section -> looks up the row for
#   <comp>/binary-<arch>/Packages.xz -> fetches Packages.xz -> verifies
#   the on-disk SHA256 matches the Release row -> xz-decompresses ->
#   parses the package list.
#
# This test exercises that end-to-end path:
#   1. Upload a .deb so the repo has Packages content
#   2. Fetch Packages.xz, decompress with `xz -d`, assert the uploaded
#      package appears (parsed in Packages line format)
#   3. Fetch dists/<suite>/Release and locate the Packages.xz row in the
#      SHA256: block; assert the on-disk SHA256 matches (this is the
#      assertion `apt update` itself performs)
#
# Builds on test-debian-xz-proxy.sh which only proved the .xz endpoint
# returns 200 with non-empty body; that test never decoded the .xz nor
# matched it against the Release manifest.
#
# Requires: curl, ar (binutils), tar, gzip, xz (xz-utils, stock on Ubuntu).

source "$(dirname "$0")/../lib/common.sh"

begin_suite "debian-packages-xz"
auth_admin
setup_workdir

REPO_KEY="test-deb-pkgxz-${RUN_ID}"
DISTRIBUTION="stable"
COMPONENT="main"
PKG_NAME="apttest"
PKG_VERSION="1.2.3"
PKG_ARCH="amd64"
DEB_FILE="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"

if ! command -v xz >/dev/null 2>&1; then
  skip_suite "xz not available on runner; cannot decode Packages.xz"
fi
if ! command -v ar >/dev/null 2>&1; then
  skip_suite "ar (binutils) not available; cannot assemble .deb fixture"
fi

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

build_deb() {
  local name="$1" version="$2" arch="$3" outfile="$4"
  local build_dir="${WORK_DIR}/deb-build-${name}-${version}-${arch}"
  mkdir -p "${build_dir}"
  echo "2.0" > "${build_dir}/debian-binary"

  local ctrl_dir="${build_dir}/control-root"
  mkdir -p "${ctrl_dir}"
  cat > "${ctrl_dir}/control" <<CTRL
Package: ${name}
Version: ${version}
Section: utils
Priority: optional
Architecture: ${arch}
Maintainer: CI <ci@example.com>
Description: apt-update Packages.xz integration test (${name} ${version})
CTRL
  tar czf "${build_dir}/control.tar.gz" -C "${ctrl_dir}" ./control

  local data_dir="${build_dir}/data-root"
  mkdir -p "${data_dir}/usr/share/doc/${name}"
  echo "${name} ${version}" > "${data_dir}/usr/share/doc/${name}/README"
  tar czf "${build_dir}/data.tar.gz" -C "${data_dir}" .

  (cd "${build_dir}" && ar rcs "${outfile}" debian-binary control.tar.gz data.tar.gz 2>/dev/null)
}

# ---------------------------------------------------------------------------
# 1. Create repo and upload a deb so the repo has Packages content.
# ---------------------------------------------------------------------------

begin_test "Create Debian repo"
if create_local_repo "$REPO_KEY" "debian"; then
  pass
else
  fail "could not create debian repo"
  end_suite
fi

DEB_PATH="${WORK_DIR}/${DEB_FILE}"
build_deb "$PKG_NAME" "$PKG_VERSION" "$PKG_ARCH" "$DEB_PATH"

begin_test "Upload .deb so repo has Packages content"
UP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/vnd.debian.binary-package" \
    --data-binary "@${DEB_PATH}" \
    "${BASE_URL}/debian/${REPO_KEY}/pool/${COMPONENT}/${DEB_FILE}") || UP_STATUS="000"

if [ "$UP_STATUS" -ge 200 ] 2>/dev/null && [ "$UP_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "pool PUT returned HTTP ${UP_STATUS}, expected 2xx"
  end_suite
fi

# Allow async metadata generation. The xz indexer runs after the .deb
# is committed to storage, same as Packages and Packages.gz.
sleep 2

DISTS_PREFIX="/debian/${REPO_KEY}/dists/${DISTRIBUTION}"
BIN_PREFIX="${DISTS_PREFIX}/${COMPONENT}/binary-${PKG_ARCH}"
PKG_XZ_FILE="${WORK_DIR}/Packages.xz"

# ---------------------------------------------------------------------------
# 2. Fetch and decompress Packages.xz, then parse the Packages line
#    format and assert the package appears with the correct version &
#    architecture.
# ---------------------------------------------------------------------------

begin_test "GET ${BIN_PREFIX}/Packages.xz returns 2xx with non-empty body"
XZ_STATUS=$(curl -s -o "$PKG_XZ_FILE" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}${BIN_PREFIX}/Packages.xz") || XZ_STATUS="000"

if [ "$XZ_STATUS" = "404" ] || [ "$XZ_STATUS" = "501" ]; then
  skip_suite "Packages.xz not available on this backend (HTTP ${XZ_STATUS})"
elif [ "$XZ_STATUS" -ge 200 ] 2>/dev/null && [ "$XZ_STATUS" -lt 300 ] 2>/dev/null \
     && [ -s "$PKG_XZ_FILE" ]; then
  pass
else
  fail "Packages.xz GET returned HTTP ${XZ_STATUS} (body empty=$([ ! -s "$PKG_XZ_FILE" ] && echo yes || echo no))"
  end_suite
fi

begin_test "xz -d decompresses Packages.xz to valid Packages line-format"
PKG_PLAIN="${WORK_DIR}/Packages.decoded"
if ! xz -dc "$PKG_XZ_FILE" > "$PKG_PLAIN" 2>"${WORK_DIR}/xz.err"; then
  fail "xz -d failed on Packages.xz" "$(head -c 400 "${WORK_DIR}/xz.err")"
elif [ ! -s "$PKG_PLAIN" ]; then
  fail "decompressed Packages is empty"
else
  # Packages format is RFC822-style: "Field: Value" lines, blank-line-
  # separated stanzas. Verify the structure rather than just grep'ing
  # for the package name: this catches a backend that hands out junk
  # bytes that happen to contain our package name.
  if grep -q "^Package: " "$PKG_PLAIN" \
     && grep -q "^Architecture: " "$PKG_PLAIN" \
     && grep -q "^Filename: " "$PKG_PLAIN" \
     && grep -q "^SHA256: " "$PKG_PLAIN"; then
    pass
  else
    fail "decompressed Packages missing required RFC822 fields (Package/Architecture/Filename/SHA256)" \
         "$(head -c 400 "$PKG_PLAIN")"
  fi
fi

begin_test "Parsed Packages.xz contains uploaded package stanza"
# Walk stanzas (separated by blank lines) and find the one matching our
# uploaded package by Package: + Version: + Architecture: triple. This is
# exactly what apt's pkgCacheGenerator does, modulo the awk vs C++.
FOUND=$(awk -v p="$PKG_NAME" -v v="$PKG_VERSION" -v a="$PKG_ARCH" '
  BEGIN { RS=""; FS="\n" }
  {
    have_p=0; have_v=0; have_a=0
    for (i=1; i<=NF; i++) {
      if ($i == "Package: " p)       have_p=1
      if ($i == "Version: " v)       have_v=1
      if ($i == "Architecture: " a)  have_a=1
    }
    if (have_p && have_v && have_a) { print "match"; exit }
  }
' "$PKG_PLAIN") || true

if [ "$FOUND" = "match" ]; then
  pass
else
  fail "decompressed Packages has no stanza for ${PKG_NAME} ${PKG_VERSION} ${PKG_ARCH}" \
       "$(head -c 600 "$PKG_PLAIN")"
fi

# ---------------------------------------------------------------------------
# 3. apt-update integrity check: fetch dists/<suite>/Release, find the
#    SHA256 row for <comp>/binary-<arch>/Packages.xz, and assert that
#    the SHA256 of the bytes we downloaded matches. apt rejects the
#    repo if this check fails.
# ---------------------------------------------------------------------------

begin_test "Release file contains SHA256 row for Packages.xz"
REL_FILE="${WORK_DIR}/Release"
REL_STATUS=$(curl -s -o "$REL_FILE" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}${DISTS_PREFIX}/Release") || REL_STATUS="000"

if [ "$REL_STATUS" -lt 200 ] 2>/dev/null || [ "$REL_STATUS" -ge 300 ] 2>/dev/null \
   || [ ! -s "$REL_FILE" ]; then
  fail "Release GET returned HTTP ${REL_STATUS}, body empty=$([ ! -s "$REL_FILE" ] && echo yes || echo no)"
else
  # The SHA256: section is followed by lines of "<hash> <size> <path>".
  # We pull the row whose path ends in /Packages.xz under our component
  # and arch. The path may be relative ("main/binary-amd64/Packages.xz")
  # or absolute - we match the suffix.
  REL_ROW=$(awk -v want="${COMPONENT}/binary-${PKG_ARCH}/Packages.xz" '
    /^SHA256:/ { in_sha=1; next }
    /^[^[:space:]]/ { in_sha=0 }
    in_sha && $0 ~ want {
      # Trim leading whitespace and emit "<hash> <size> <path>".
      sub(/^[[:space:]]+/, "")
      print
      exit
    }
  ' "$REL_FILE") || true

  if [ -n "$REL_ROW" ]; then
    pass
  else
    # If Release doesn't list Packages.xz at all, apt would fall back
    # to Packages or Packages.gz; the manifest gap is still a bug.
    fail "Release SHA256 block has no row for ${COMPONENT}/binary-${PKG_ARCH}/Packages.xz" \
         "$(grep -A 30 '^SHA256:' "$REL_FILE" | head -c 800)"
  fi
fi

begin_test "On-disk SHA256 of Packages.xz matches Release manifest row"
if [ -z "${REL_ROW:-}" ]; then
  skip "no Release row to compare against (upstream test failed)"
else
  EXPECTED_SHA=$(echo "$REL_ROW" | awk '{print $1}')
  ACTUAL_SHA=$(sha256_hex "$PKG_XZ_FILE")
  if [ "$ACTUAL_SHA" = "$EXPECTED_SHA" ]; then
    pass
  else
    fail "Packages.xz SHA256 mismatch (apt would reject this repo)" \
         "expected=${EXPECTED_SHA} actual=${ACTUAL_SHA} row=${REL_ROW}"
  fi
fi

end_suite
