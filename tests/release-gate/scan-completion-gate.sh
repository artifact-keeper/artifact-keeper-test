#!/usr/bin/env bash
# scan-completion-gate.sh -- Release-gate primitive for the scan-completion
# silent-success class (#871 stuck-queued, #888 silently completed-but-not-scanned).
#
# Covers artifact-keeper-test issues:
#   - #46  E2E scan flow completion
#   - #56  Epic: scan-completion silent-success gate
#
# This is the release-gate-specific entry point around the lite primitive
# at tests/security/test-scan-completes.sh. It exists for ONE reason: to
# hard-code release-gate semantics so neither the workflow author nor a
# future contributor can dial them back without editing this file:
#   - ALLOW_SCANNER_SKIP=0 (a missing scanner in release-gate IS the bug)
#   - RELEASE_GATE=1 (skip_suite => hard fail)
#   - SCAN_TIMEOUT defaults to 180s
#
# Format support: only npm. Other formats (oci, maven, pypi, cargo, helm)
# need format-specific fixture builders that do not exist yet. The earlier
# scaffold branches in this file were dead code -- the workflow matrix is
# restricted to [npm] (see the scan-completion-gate-scaffolds-pending
# sentinel job in release-gate.yml for visibility on deferred formats).
# FIXTURE_FORMAT is accepted only for forward compatibility with the
# matrix; an unsupported value fails the gate loudly rather than silently
# exiting 0.
#
# Why this lives in tests/release-gate/ rather than tests/security/:
#   - tests/security/ is picked up automatically by run-suite.sh --suite
#     security. The existing test-scan-completes.sh stays there for the
#     security suite. This wrapper exists specifically so the release-gate
#     workflow can call ONE script per matrix entry with the release-gate
#     env forced on regardless of the caller's env, without coupling to
#     run-suite.sh's directory layout.
#
# Environment:
#   BASE_URL              backend URL (default http://localhost:8080)
#   ADMIN_USER            admin username (default admin)
#   ADMIN_PASS            admin password
#   RUN_ID                resource-name suffix
#   FIXTURE_FORMAT        npm (default; only supported value today)
#   FIXTURE_LODASH_VERSION  override the lodash version baked into the
#                         fixture lockfile. Used by the self-test
#                         fixture B path to swap to a non-vulnerable
#                         version (4.17.21) and prove the gate's
#                         findings_count assertion bites. Default 4.17.4.
#   SCAN_TIMEOUT          max seconds to wait (default 180)
#   EXPECT_FAILURE        set to 1 by the meta-test workflow (#883 contract)
#   ALLOW_SCANNER_SKIP    forced to 0 here; release-gate must fail loud
#
# Exit codes (delegated to the embedded suite):
#   0 - all assertions passed (or EXPECT_FAILURE=1 and at least one failed)
#   1 - any assertion failed (or EXPECT_FAILURE=1 and every assertion passed,
#       which means the gate has been weakened -- self-test detected it)
#   2 - configuration error (unknown FIXTURE_FORMAT, etc.)
#   5 - EXPECT_FAILURE=1 and ALLOW_SCANNER_SKIP=1 (mutually exclusive)

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

if [ "$FIXTURE_FORMAT" != "npm" ]; then
  echo "ERROR: scan-completion-gate.sh: FIXTURE_FORMAT='${FIXTURE_FORMAT}' has no fixture builder yet." >&2
  echo "  Only 'npm' is supported. Deferred formats (oci, maven, pypi, cargo, helm)" >&2
  echo "  are tracked under artifact-keeper-test#62. When a fixture builder for a" >&2
  echo "  deferred format lands, add the case here AND add the format to the" >&2
  echo "  release-gate.yml workflow matrix in the same PR." >&2
  exit 2
fi

# Delegate to the lite primitive. It builds the lodash fixture
# (FIXTURE_LODASH_VERSION-controlled, default 4.17.4 / CVE-2019-10744),
# uploads via PUT to a generic repo, triggers a scan, polls, and asserts
# the load-bearing findings_count >= 1.
exec "$(dirname "$0")/../security/test-scan-completes.sh"
