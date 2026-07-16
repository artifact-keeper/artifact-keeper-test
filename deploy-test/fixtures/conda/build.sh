#!/usr/bin/env bash
# =============================================================================
# fixtures/conda/build.sh — host-craft a minimal conda v1 (.tar.bz2) package
# =============================================================================
# A conda v1 package is "just an archive with metadata": a bzip2-compressed tar
# with `info/index.json` (+ `info/paths.json` + `info/files`) and the payload
# files. NO conda-build / anaconda toolchain needed — we tar it on the host.
#
# The package installs a single grep-able marker file
#   share/<name>/marker.txt   ->  <prefix>/share/<name>/marker.txt
# so the conda plugin's fc_assert can prove the REAL client actually followed
# the advertised repodata location, downloaded, and LINKED the package (not
# merely that repodata listed it).
#
# Usage:
#   build.sh <out-dir> [name] [version] [build] [subdir] [marker-token]
#
# Deterministic; writes <out-dir>/<name>-<version>-<build>.tar.bz2 and echoes
# that path on stdout. Nothing is committed to the tree (built into $WORK_DIR).
# =============================================================================
set -euo pipefail

OUT_DIR="${1:-${WORK_DIR:?build.sh: pass an out-dir or set WORK_DIR}}"
NAME="${2:-dtf-marker}"
VERSION="${3:-1.0}"
BUILD="${4:-0}"
SUBDIR="${5:-noarch}"
MARKER_TOKEN="${6:-DTF-CONDA-INSTALLED-${VERSION}}"

mkdir -p "$OUT_DIR"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/info" "$work/share/${NAME}"

# --- payload: the marker file -------------------------------------------------
printf '%s\n' "$MARKER_TOKEN" > "$work/share/${NAME}/marker.txt"
msize="$(wc -c < "$work/share/${NAME}/marker.txt" | tr -d ' ')"
msha="$(sha256sum "$work/share/${NAME}/marker.txt" | awk '{print $1}')"

# --- info/index.json ----------------------------------------------------------
# noarch packages carry `"noarch":"generic"`; an arch package (e.g.
# subdir=linux-aarch64) omits it. build_number is 0. depends=[] so the later
# solve resolves purely from the AK channel with --override-channels.
if [ "$SUBDIR" = "noarch" ]; then
  noarch_field='"noarch":"generic",'
  platform_field='"platform":null,'
else
  noarch_field=''
  platform_field='"platform":"linux",'
fi
cat > "$work/info/index.json" <<JSON
{"name":"${NAME}","version":"${VERSION}","build":"${BUILD}","build_number":0,${noarch_field}${platform_field}"subdir":"${SUBDIR}","depends":[],"license":"MIT"}
JSON

# --- info/paths.json ----------------------------------------------------------
# conda links files listed here (path_type=hardlink). Without a correct
# paths.json the client extracts but does not LINK the marker into the prefix,
# so fc_assert would (correctly) fail — this is what makes the test real.
cat > "$work/info/paths.json" <<JSON
{"paths_version":1,"paths":[{"_path":"share/${NAME}/marker.txt","path_type":"hardlink","sha256":"${msha}","size_in_bytes":${msize}}]}
JSON

# --- info/files (legacy fallback list) ---------------------------------------
printf '%s\n' "share/${NAME}/marker.txt" > "$work/info/files"

# --- pack: bzip2 tar with info/ first (conda convention) ----------------------
out="${OUT_DIR}/${NAME}-${VERSION}-${BUILD}.tar.bz2"
tar -cjf "$out" -C "$work" info share

echo "$out"
