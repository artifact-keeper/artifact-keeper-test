#!/usr/bin/env bash
# =============================================================================
# fixtures/go/build.sh — host-craft a conformant Go module zip (+ go.mod)
# =============================================================================
# The WHOLE POINT of the go leg: the module zip MUST use the strict
# `<module>@<version>/` internal prefix that `golang.org/x/mod/zip.Unzip`
# (the code path inside `go mod download`) enforces. The corpus test-go.sh
# hand-rolls a `zip -r` layout and, when the layout is even slightly off, the
# real client rejects it and the corpus SKIPS ("may require exact zip layout").
# Getting this prefix right is what turns the go leg from skipped into GATING.
#
# A Go module zip is "just an archive with metadata": every file lives under
# `<module>@<version>/`, a `go.mod` sits at `<module>@<version>/go.mod`
# declaring the module path, and at least one buildable .go file provides the
# marker function the consumer calls. NO Go toolchain is needed on the host —
# we build the zip deterministically with python's zipfile so the internal
# prefix is byte-exact (no `zip` quirks, stable mtime).
#
# Usage:
#   build.sh <out-dir> <module> <version> [pkg] [marker-token]
#     module  e.g. example.com/dtf/marker   (the REAL path; NOT bang-encoded —
#             the zip prefix always uses the canonical module path, only the
#             GOPROXY URL uses !-encoding)
#     version e.g. v1.0.0
#     pkg     Go package name declared in the .go file (default: last path
#             segment, lowercased to a valid identifier)
#
# Writes (deterministic names under <out-dir>):
#   <out>/<slug>@<version>.zip   the module zip (prefix = <module>@<version>/)
#   <out>/<slug>@<version>.mod   the standalone go.mod (served on .mod route)
# and echoes the ZIP path on stdout (the .mod path is the same with .mod ext).
# Nothing is committed to the tree (built into $WORK_DIR).
# =============================================================================
set -euo pipefail

OUT_DIR="${1:-${WORK_DIR:?build.sh: pass an out-dir or set WORK_DIR}}"
MODULE="${2:-example.com/dtf/marker}"
VERSION="${3:-v1.0.0}"
PKG="${4:-}"
MARKER_TOKEN="${5:-DTF-GO-INSTALLED-${VERSION}}"

if [ -z "$PKG" ]; then
  PKG="${MODULE##*/}"
  # lowercase + strip anything not a valid Go identifier char
  PKG="$(printf '%s' "$PKG" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_')"
  [ -n "$PKG" ] || PKG="marker"
fi

mkdir -p "$OUT_DIR"
# A filesystem-safe slug for the output filenames (the module path has slashes).
SLUG="$(printf '%s' "$MODULE" | tr '/' '_')"
ZIP_OUT="${OUT_DIR}/${SLUG}@${VERSION}.zip"
MOD_OUT="${OUT_DIR}/${SLUG}@${VERSION}.mod"

GOMOD_CONTENT="module ${MODULE}

go 1.21
"
GOFILE_CONTENT="// Package ${PKG} is a one-file DTF conformance marker module.
package ${PKG}

// Marker returns a grep-able token proving the REAL go client followed the
// GOPROXY-advertised .info -> .zip path, downloaded, extracted, and BUILT the
// module (not merely that the proxy listed it).
func Marker() string {
	return \"${MARKER_TOKEN}\"
}
"

# The standalone go.mod served on the .mod route must byte-match the go.mod
# inside the zip (the go client cross-checks module path consistency).
printf '%s' "$GOMOD_CONTENT" > "$MOD_OUT"

PREFIX="${MODULE}@${VERSION}"

MODULE="$MODULE" VERSION="$VERSION" PREFIX="$PREFIX" ZIP_OUT="$ZIP_OUT" \
GOMOD_CONTENT="$GOMOD_CONTENT" GOFILE_CONTENT="$GOFILE_CONTENT" PKG="$PKG" \
python3 - <<'PY'
import os, zipfile

prefix   = os.environ["PREFIX"]
zip_out  = os.environ["ZIP_OUT"]
gomod    = os.environ["GOMOD_CONTENT"]
gofile   = os.environ["GOFILE_CONTENT"]

# Deterministic mtime so the produced zip is reproducible.
zi_time = (1980, 1, 1, 0, 0, 0)

entries = [
    (f"{prefix}/go.mod", gomod),
    (f"{prefix}/marker.go", gofile),
]

if os.path.exists(zip_out):
    os.remove(zip_out)

with zipfile.ZipFile(zip_out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for name, content in entries:
        zi = zipfile.ZipInfo(name, date_time=zi_time)
        zi.external_attr = 0o644 << 16
        zf.writestr(zi, content)
PY

[ -s "$ZIP_OUT" ] || { echo "build.sh: produced empty zip" >&2; exit 1; }
echo "$ZIP_OUT"
