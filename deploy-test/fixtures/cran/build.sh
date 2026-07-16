#!/usr/bin/env bash
# =============================================================================
# fixtures/cran/build.sh — host-craft a minimal CRAN source package tarball
# =============================================================================
# A CRAN source package is "just an archive with metadata": a gzipped tar whose
# single top-level directory is the package name and which carries a DESCRIPTION
# (DCF metadata), a NAMESPACE, and the R sources. NO R toolchain is needed to
# BUILD it — we tar it on the host. R only needs it at CONSUME time to install.
#
# The package exports one grep-able marker function
#   dtf_marker_ping()  ->  "<marker-token>"
# so the cran plugin's fc_assert can prove the REAL client (Rscript
# install.packages) actually followed the advertised PACKAGES index, downloaded
# the source tarball from src/contrib/, installed it, and can call into it — not
# merely that PACKAGES listed it.
#
# Usage:
#   build.sh <out-dir> [name] [version] [marker-token]
#
# Deterministic; writes <out-dir>/<name>_<version>.tar.gz and echoes that path
# on stdout. Nothing is committed to the tree (built into $WORK_DIR).
# =============================================================================
set -euo pipefail

OUT_DIR="${1:-${WORK_DIR:?build.sh: pass an out-dir or set WORK_DIR}}"
NAME="${2:-dtf.marker}"
VERSION="${3:-1.0}"
MARKER_TOKEN="${4:-DTF-CRAN-INSTALLED-${VERSION}}"

mkdir -p "$OUT_DIR"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pkgdir="$work/${NAME}"
mkdir -p "$pkgdir/R"

# --- DESCRIPTION (DCF) --------------------------------------------------------
# The mandatory fields for R CMD INSTALL: Package, Version, License. Title +
# Description keep `R CMD check`-grade tooling happy. No compiled code, no deps,
# so the install resolves purely from the AK repo (repos=<FC_INT_URL>).
cat > "$pkgdir/DESCRIPTION" <<DCF
Package: ${NAME}
Type: Package
Title: DTF Conformance Marker
Version: ${VERSION}
Authors@R: person("DTF", "Rig", role = c("aut", "cre"), email = "dtf@example.invalid")
Description: A dependency-free marker package used by the DTF format-conformance
    tier to prove a real R client installed it from an Artifact Keeper CRAN repo.
License: MIT
Encoding: UTF-8
DCF

# --- NAMESPACE ----------------------------------------------------------------
# Export the marker function explicitly so `library()` + a direct call work.
cat > "$pkgdir/NAMESPACE" <<'NS'
export(dtf_marker_ping)
NS

# --- R/marker.R ---------------------------------------------------------------
cat > "$pkgdir/R/marker.R" <<RSRC
dtf_marker_ping <- function() {
  "${MARKER_TOKEN}"
}
RSRC

# --- pack: gzipped tar with the package dir at the top level ------------------
# CRAN source tarballs are `<name>_<version>.tar.gz` containing `<name>/...`.
out="${OUT_DIR}/${NAME}_${VERSION}.tar.gz"
tar -czf "$out" -C "$work" "${NAME}"

echo "$out"
