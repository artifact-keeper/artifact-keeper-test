#!/usr/bin/env bash
# =============================================================================
# fixtures/terraform/build.sh — host-craft a minimal Terraform provider zip.
# =============================================================================
# A Terraform provider package is just a zip whose top level contains an
# executable named `terraform-provider-<type>_v<version>`. We add a grep-able
# marker file too (the conformance token). No Go toolchain / real plugin needed:
# the network-mirror feasibility leg only needs a byte-exact archive to publish
# and to hash (h1/zh verification), not a runnable provider.
#
# args:   <workdir> <type> <version> <os> <arch> <marker_token>
# stdout: absolute path to the produced .zip (the only thing on stdout)
# =============================================================================
set -euo pipefail
work="$1"; type_name="$2"; ver="$3"; os="$4"; arch="$5"; token="$6"

stage="${work}/tfprov-${type_name}-${ver}-${os}-${arch}"
rm -rf "$stage"; mkdir -p "$stage"

bin="terraform-provider-${type_name}_v${ver}"
# A tiny, deterministic "binary" (a shell stub) + the marker file.
printf '#!/bin/sh\n# dtf terraform provider marker stub\necho "%s"\n' "$token" > "${stage}/${bin}"
chmod +x "${stage}/${bin}"
printf '%s\n' "$token" > "${stage}/marker.txt"

zip="${work}/terraform-provider-${type_name}_${ver}_${os}_${arch}.zip"
rm -f "$zip"
# -X strips extra file attributes for a deterministic archive.
( cd "$stage" && zip -q -X "$zip" "${bin}" marker.txt )

echo "$zip"
