#!/bin/sh
# =============================================================================
# fixtures/debian/build.sh — bake the mock APT upstream tree (PKT-A, #2459/#2460)
# =============================================================================
# Generates a fixed, self-consistent Debian `dists/` tree for the debian-remote
# tier's mock upstream (profiles/upstreams.debian.yml). Runs INSIDE the
# nginx:alpine upstream container at start (busybox `sh`/`sha256sum`/`wc`), so
# there is no committed binary blob and the SHA256 `Release` table is computed
# from the EXACT bytes served. Writes into the nginx webroot ($1, default
# /usr/share/nginx/html) then returns; the container command execs nginx after.
#
# Layout produced (dist / component / arch):
#   dists/bookworm/Release              signed-shaped SHA256 table (CORRECT)
#   dists/bookworm/InRelease            identical plain content (parser-compatible)
#   dists/bookworm/{main,contrib}/binary-{amd64,arm64}/Packages
#        -> bytes whose sha/size MATCH the bookworm/Release table (clean serve)
#   dists/bookworm-evil/Release         SHA256 table pinning the CLEAN sha/size
#   dists/bookworm-evil/InRelease       identical to Release
#   dists/bookworm-evil/main/binary-amd64/Packages
#        -> TAMPERED bytes (sha now != the pinned Release entry) => the #2459 red
#
# #2459: AK proxying dists/bookworm-evil/.../Packages loads bookworm-evil/Release
#        (which vouches for the clean sha), hashes the tampered body, mismatch,
#        `enforce_dists_integrity` -> 502. The clean bookworm tree serves 200.
# #2460: the full main+contrib x amd64+arm64 matrix exists, so a filtered-out
#        component/arch is a real 404 from the filter gate, not a dead route
#        (the allow-all guard in the oracle re-serves them 200 to prove it).
# =============================================================================
set -eu

ROOT="${1:-/usr/share/nginx/html}"
DATE="$(date -u '+%a, %d %b %Y %H:%M:%S UTC' 2>/dev/null || echo 'Thu, 01 Jan 1970 00:00:00 UTC')"

# emit_packages DEST COMPONENT ARCH MARKER
# Writes a minimal but valid-shaped Packages stanza with a unique marker so the
# oracle can body-assert the served bytes (never curl -o /dev/null).
emit_packages() {
  _dest="$1"; _comp="$2"; _arch="$3"; _marker="$4"
  mkdir -p "$(dirname "$_dest")"
  cat > "$_dest" <<EOF
Package: dtf-marker-${_comp}-${_arch}
Version: 1.0.0
Architecture: ${_arch}
Maintainer: DTF debian-remote fixture <dtf@example.invalid>
Filename: pool/${_comp}/d/dtf-marker/dtf-marker-${_comp}-${_arch}_1.0.0_${_arch}.deb
Size: 512
MD5sum: 0123456789abcdef0123456789abcdef
Description: DTF debian-remote fixture package
 DTF-PKG-MARKER=${_marker} component=${_comp} arch=${_arch}
EOF
}

sha_of() { sha256sum "$1" | cut -d' ' -f1; }
size_of() { wc -c < "$1" | tr -d ' '; }

# release_header DIST -> stdout (deb822 headers up to and including "SHA256:")
release_header() {
  cat <<EOF
Origin: DTF
Label: DTF Debian Remote Fixture
Suite: $1
Codename: $1
Version: 2026.7
Architectures: amd64 arm64
Components: main contrib
Date: ${DATE}
Description: DTF debian-remote mock upstream ($1)
SHA256:
EOF
}

# ------------------------------------------------------------------ bookworm
# Clean, fully self-consistent tree: every Packages sha/size matches Release.
BW="${ROOT}/dists/bookworm"
mkdir -p "$BW"
for comp in main contrib; do
  for arch in amd64 arm64; do
    emit_packages "${BW}/${comp}/binary-${arch}/Packages" "$comp" "$arch" "bookworm-${comp}-${arch}-CLEAN"
  done
done

{
  release_header bookworm
  for comp in main contrib; do
    for arch in amd64 arm64; do
      f="${BW}/${comp}/binary-${arch}/Packages"
      printf ' %s %s %s\n' "$(sha_of "$f")" "$(size_of "$f")" "${comp}/binary-${arch}/Packages"
    done
  done
} > "${BW}/Release"
cp "${BW}/Release" "${BW}/InRelease"

# ------------------------------------------------------------- bookworm-evil
# Release pins the CLEAN sha/size, but the served Packages is TAMPERED.
EV="${ROOT}/dists/bookworm-evil"
mkdir -p "${EV}/main/binary-amd64"

# 1) clean reference bytes -> the sha/size the Release will vouch for
CLEAN_TMP="$(mktemp)"
emit_packages "$CLEAN_TMP" main amd64 "bookworm-evil-CLEAN-REFERENCE"
CLEAN_SHA="$(sha_of "$CLEAN_TMP")"
CLEAN_SIZE="$(size_of "$CLEAN_TMP")"

# 2) Release/InRelease vouch for the clean sha/size at the amd64 Packages path
{
  release_header bookworm-evil
  printf ' %s %s %s\n' "$CLEAN_SHA" "$CLEAN_SIZE" "main/binary-amd64/Packages"
} > "${EV}/Release"
cp "${EV}/Release" "${EV}/InRelease"

# 3) the ACTUALLY SERVED Packages is tampered => sha != the Release entry
emit_packages "${EV}/main/binary-amd64/Packages" main amd64 "bookworm-evil-TAMPERED-POISON-DO-NOT-TRUST"
printf '\n# extra injected bytes to guarantee a sha/size divergence\n' >> "${EV}/main/binary-amd64/Packages"

TAMPER_SHA="$(sha_of "${EV}/main/binary-amd64/Packages")"
rm -f "$CLEAN_TMP"

echo "[debian-fixture] built tree under ${ROOT}"
echo "[debian-fixture] bookworm-evil Release pins clean sha=${CLEAN_SHA} size=${CLEAN_SIZE}"
echo "[debian-fixture] bookworm-evil SERVED (tampered) sha=${TAMPER_SHA}"
if [ "$CLEAN_SHA" = "$TAMPER_SHA" ]; then
  echo "[debian-fixture] FATAL: tampered sha equals clean sha (fixture non-discriminating)" >&2
  exit 1
fi
