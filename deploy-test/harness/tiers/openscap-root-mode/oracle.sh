#!/usr/bin/env bash
# =============================================================================
# tiers/openscap-root-mode/oracle.sh
#   #6000 with user namespaces blocked, OPENSCAP_RUN_AS_ROOT lets the sidecar
#         evaluate the image's unpacked root filesystem
# The cases are the openscap-evaluates-image-rootfs oracle's, run against the
# root-mode sidecar (profile scanners.openscap-root), plus its check that every
# RHEL image was evaluated with isolation=root.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export OSCAP_EXPECT_ISOLATION=root
export OSCAP_SUITE_NAME=openscap-root-mode
exec bash "$HERE/../openscap-evaluates-image-rootfs/oracle.sh"
