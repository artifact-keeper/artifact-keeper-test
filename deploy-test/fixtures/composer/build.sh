#!/usr/bin/env bash
# =============================================================================
# fixtures/composer/build.sh — host-craft a minimal Composer package zip
# =============================================================================
# A Composer "dist" package is "just a zip with a composer.json at the root".
# NO php/composer toolchain needed — we zip it on the host. The archive carries
# a single grep-able marker source file
#   src/Marker.php   ->  vendor/<vendor>/<package>/src/Marker.php
# containing a marker token, so the composer plugin's fc_assert can prove the
# REAL client actually FOLLOWED the advertised `dist.url` back to AK, downloaded
# the archive, and extracted it into `vendor/` (installation-source: dist) —
# not merely that packages.json listed the name, and NOT a `source` git
# fallback (the #2361/#2370/#2421 relative-dist-url regression class).
#
# Usage:
#   build.sh <out-dir> [vendor] [package] [version] [marker-token]
#
# Deterministic; writes <out-dir>/<vendor>-<package>-<version>.zip and echoes
# that path on stdout. Nothing is committed to the tree (built into $WORK_DIR).
# =============================================================================
set -euo pipefail

OUT_DIR="${1:-${WORK_DIR:?build.sh: pass an out-dir or set WORK_DIR}}"
VENDOR="${2:-dtf}"
PACKAGE="${3:-marker}"
VERSION="${4:-1.0.0}"
MARKER_TOKEN="${5:-DTF-COMPOSER-INSTALLED-${VERSION}}"

mkdir -p "$OUT_DIR"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/src"

# --- composer.json (root manifest) -------------------------------------------
# An explicit "version" makes the hosted registry index this as ${VERSION}
# rather than the default dev-main. require is php-only so the solve resolves
# purely from the AK repo. The PSR-4 autoload maps Dtf\ -> src/.
cat > "$work/composer.json" <<JSON
{
  "name": "${VENDOR}/${PACKAGE}",
  "description": "DTF format-conformance marker package",
  "version": "${VERSION}",
  "type": "library",
  "license": "MIT",
  "autoload": {
    "psr-4": { "Dtf\\\\": "src/" }
  },
  "require": { "php": ">=8.0" }
}
JSON

# --- src/Marker.php (the grep-able marker payload) ---------------------------
cat > "$work/src/Marker.php" <<PHP
<?php
namespace Dtf;

// ${MARKER_TOKEN}
class Marker {
    public const TOKEN = "${MARKER_TOKEN}";
    public function ping(): string { return self::TOKEN; }
}
PHP

# --- pack: a plain zip with composer.json at the archive root ----------------
out="${OUT_DIR}/${VENDOR}-${PACKAGE}-${VERSION}.zip"
rm -f "$out"
( cd "$work" && zip -qr "$out" composer.json src )

echo "$out"
