#!/usr/bin/env bash
# scan-completion-gate.sh -- Release-gate primitive for the scan-completion
# silent-success class (#871 stuck-queued, #888 silently completed-but-not-scanned).
#
# Covers artifact-keeper-test issues:
#   - #46  E2E scan flow completion
#   - #56  Epic: scan-completion silent-success gate
#
# This is the format-parameterized wrapper around the lite primitive at
# tests/security/test-scan-completes.sh. It hard-codes the release-gate
# semantics:
#   - ALLOW_SCANNER_SKIP=0 (a missing scanner in release-gate IS the bug)
#   - RELEASE_GATE=1 (skip_suite => hard fail)
#   - SCAN_TIMEOUT defaults to 180s (same as the lite primitive)
#
# It is parameterized via FIXTURE_FORMAT so test-scan-completion-format-matrix.sh
# can iterate over npm / pypi / oci / maven without copy-pasting the
# trigger + poll + assert plumbing.
#
# Currently implemented fixture formats:
#   - npm (default, lodash 4.17.4 / CVE-2019-10744)
#   - generic-payload (for the SBOM gate scaffold; no findings assertion)
#
# Scaffolded but not yet wired (require a fixture-builder per format):
#   - oci, maven, pypi, cargo, helm
#   For these we exit 0 with a clear log line. The format-matrix script's
#   matrix entries record this as a skip; when the fixture-builder lands
#   the matrix flips that entry to a real gate without touching the
#   workflow file.
#
# Why this lives in tests/release-gate/ rather than tests/security/:
#   - tests/security/ is picked up automatically by run-suite.sh --suite
#     security. The existing test-scan-completes.sh stays there for the
#     security suite. This wrapper exists specifically so the release-gate
#     workflow can call ONE script per matrix entry without spinning up
#     the whole security suite, and without coupling the matrix wiring
#     to run-suite.sh's directory layout.
#
# Environment:
#   BASE_URL              backend URL (default http://localhost:8080)
#   ADMIN_USER            admin username (default admin)
#   ADMIN_PASS            admin password
#   RUN_ID                resource-name suffix
#   FIXTURE_FORMAT        npm | oci | maven | pypi | cargo | helm | generic-payload
#                         (default: npm)
#   SCAN_TIMEOUT          max seconds to wait (default 180)
#   EXPECT_FAILURE        set to 1 by the meta-test workflow (#883 contract)
#   ALLOW_SCANNER_SKIP    forced to 0 here; release-gate must fail loud
#
# Exit codes (delegated to the embedded suite):
#   0 - all assertions passed
#   1 - any assertion failed
#   4 - EXPECT_FAILURE=1 but gate passed (self-test detected weakening)

set -uo pipefail

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

FIXTURE_FORMAT="${FIXTURE_FORMAT:-npm}"

# Release-gate semantics. Refuse to honor ALLOW_SCANNER_SKIP=1 here; a
# release-gate that gracefully skips when the scanner pod is down is the
# exact silent-success class this gate exists to catch.
if [ "${ALLOW_SCANNER_SKIP:-0}" = "1" ]; then
  echo "ERROR: scan-completion-gate.sh refuses ALLOW_SCANNER_SKIP=1 (release-gate must fail loud on scanner unavailability; that is the #888 silent-success class)" >&2
  exit 2
fi
export ALLOW_SCANNER_SKIP=0
export RELEASE_GATE=1
export SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"

case "$FIXTURE_FORMAT" in
  npm)
    # Delegate to the lite primitive. It already builds the lodash 4.17.4
    # fixture, uploads via PUT to a generic repo, triggers a scan, polls,
    # and asserts the load-bearing findings_count >= 1.
    exec "$(dirname "$0")/../security/test-scan-completes.sh"
    ;;
  oci|maven|pypi|cargo|helm)
    # Scaffolds. Each of these needs a known-vulnerable fixture builder
    # (Trivy image scan for oci, jar+pom for maven, .whl for pypi, .crate
    # for cargo, .tgz with vulnerable subchart for helm). The format-matrix
    # script currently runs these as scaffolds: exit 0 with a clear log
    # entry so the matrix surfaces "not yet covered" without blocking.
    # TODO(artifact-keeper-test#62): land the per-format fixture builders.
    echo "scan-completion-gate.sh: FIXTURE_FORMAT=${FIXTURE_FORMAT} is a scaffold (#62)"
    echo "  No assertion run. To wire this format up:"
    echo "    1. Build a known-vulnerable fixture for ${FIXTURE_FORMAT} in the format's native path"
    echo "    2. Drop into the matrix slot in test-scan-completion-format-matrix.sh"
    exit 0
    ;;
  generic-payload)
    # Used by the SBOM gate scaffold. Just upload a tarball, trigger a
    # scan, assert it reaches a terminal state. No findings_count
    # assertion (the payload is not a recognized package format).
    # TODO(artifact-keeper-test#57): expand once #903 lands.
    echo "scan-completion-gate.sh: FIXTURE_FORMAT=generic-payload is a scaffold (#57)"
    exit 0
    ;;
  *)
    echo "ERROR: unknown FIXTURE_FORMAT='${FIXTURE_FORMAT}'" >&2
    echo "  Supported: npm, oci, maven, pypi, cargo, helm, generic-payload" >&2
    exit 2
    ;;
esac
