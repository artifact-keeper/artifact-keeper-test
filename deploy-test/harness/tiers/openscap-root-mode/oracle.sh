#!/usr/bin/env bash
# =============================================================================
# tiers/openscap-root-mode/oracle.sh
#   #6000 with OPENSCAP_RUN_AS_ROOT (the sidecar started as root, default
#         seccomp), the sidecar evaluates the image's unpacked root
#         filesystem without a user namespace
# Runs the openscap-evaluates-image-rootfs cases (CONTROL: the three images
# push and the clean image has neither deliberate break; FIX #6000: the
# noncompliant image's own findings, Debian and RPM not_applicable) against
# the root-mode sidecar (profile scanners.openscap-root), then this tier's own
# case: every RHEL image was evaluated with isolation=root.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
ROOT_MODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export OSCAP_EXPECT_ISOLATION=root
export OSCAP_SUITE_NAME=openscap-root-mode
OSCAP_SOURCED=1
# shellcheck source=/dev/null
source "$ROOT_MODE_DIR/../openscap-evaluates-image-rootfs/oracle.sh"

# =============================================================================
begin_test "FIX #6000: root mode evaluated the RHEL images without a user namespace (isolation=root)"
reset_case
health="$(docker exec "$SIDECAR" python3 -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8091/health').read().decode())" 2>/dev/null || true)"
n="$(jqr '.evaluations.root // 0' <<<"$health")"
u="$(jqr '.evaluations.userns // 0' <<<"$health")"
rar="$(jqr '.run_as_root' <<<"$health")"
note "sidecar /health evaluations: $(jqr '.evaluations // "none"' <<<"$health" | tr -d '\n ') run_as_root=${rar:-none}"
[ "$rar" = "true" ] || fail_g "sidecar /health run_as_root=${rar:-none}, expected true (user \"0\" with OPENSCAP_RUN_AS_ROOT=true); the pre-fix wrapper has no root mode"
[ "${n:-0}" -ge 2 ] 2>/dev/null || fail_g "expected at least two scans evaluated with isolation=root (the two RHEL images), got ${n:-0}"
[ "${u:-0}" = "0" ] || fail_g "${u} scans used a user namespace; root mode must not"
finish_case "root mode did not evaluate the images"

end_suite
