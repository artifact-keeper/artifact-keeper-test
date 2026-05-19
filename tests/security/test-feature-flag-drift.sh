#!/usr/bin/env bash
# test-feature-flag-drift.sh -- Pin AK_FEATURES against the backend's
# self-reported version (issue #65 truth path).
#
# Why this test exists
# --------------------
# The branch-aware feature flag layer (tests/lib/feature-flags.sh)
# replaces the legacy backend-version probe with an env var the
# workflow sets per matrix job. That's a fast path. The risk is
# drift: the workflow says AK_BACKEND_BRANCH=release/1.1.x but the
# deployed backend is actually built from main (or vice versa). With
# the fast path, every feature-gated test would silently pass with
# the wrong assumption.
#
# This file is the truth path. It hits /health, parses the
# self-reported version, and asserts the version is consistent with
# AK_BACKEND_BRANCH. Drift becomes a single loud failure in ONE place,
# not silent skips/passes in dozens.
#
# Scope
# -----
# - When AK_BACKEND_BRANCH is unset (local dev), this test is a no-op.
# - When AK_BACKEND_BRANCH is set, the backend's reported version
#   MUST start with the major.minor the branch implies, or with
#   "main"/"dev"/"snapshot" markers for the main branch.
# - Drift in EITHER direction is a fail: a 1.2.x backend running
#   against a workflow that says 1.1.x is just as bad as the inverse.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "feature-flag-drift"

# No backend hint set -> nothing to assert against. Local dev path.
if [ -z "${AK_BACKEND_BRANCH:-}" ]; then
  begin_test "Drift check skipped (AK_BACKEND_BRANCH not set; local dev)"
  skip "no AK_BACKEND_BRANCH; nothing to drift-check"
  end_suite
  exit 0
fi

# Fetch /health. We bypass auth_admin because /health is unauth and
# the drift check runs before any other suite logic; if /health is
# broken we want a precise reason in the failure message.
#
# Use mktemp so two concurrent invocations of this script on the same
# runner pod cannot race on a shared /tmp path. The previous form
# (/tmp/.health-resp.$$) was unique per PID but not per concurrent
# invocation when run-suite.sh fans out (CLAUDE.md /tmp hygiene rule).
begin_test "Fetch /health"
health_resp=""
health_resp_file=$(mktemp -t health-resp.XXXXXXXX)
http_status=$(curl -s -o "${health_resp_file}" -w '%{http_code}' --max-time 5 \
    "${BASE_URL}/health" 2>/dev/null) || http_status="000"
if [ "$http_status" = "200" ]; then
  health_resp=$(cat "${health_resp_file}" 2>/dev/null || echo "")
  rm -f "${health_resp_file}"
  pass
else
  rm -f "${health_resp_file}"
  fail "GET ${BASE_URL}/health returned HTTP ${http_status}; cannot drift-check"
fi

# Parse version. Empty / missing is treated as "main-snapshot" for
# the main-branch mapping but a hard fail for any other branch (a
# release branch MUST report a real version; an empty version on a
# release branch is the kind of build-pipeline regression we want
# the gate to catch).
begin_test "Backend reports a version"
reported=$(echo "$health_resp" | jq -r '.version // empty' 2>/dev/null || echo "")
if [ -n "$reported" ]; then
  pass
else
  case "$AK_BACKEND_BRANCH" in
    main|master)
      # main builds sometimes ship with version="dev" or empty; let
      # the branch-name check below decide.
      pass
      ;;
    *)
      fail "/health has no .version field on a release branch (AK_BACKEND_BRANCH=${AK_BACKEND_BRANCH}); build pipeline regressed"
      ;;
  esac
fi

# Strip a leading v and any pre-release suffix for the comparison.
_strip() {
  local v="${1#v}"
  echo "${v%%-*}"
}

stripped=$(_strip "${reported:-0}")
major=$(echo "$stripped" | cut -d. -f1)
minor=$(echo "$stripped" | cut -d. -f2)

# Map AK_BACKEND_BRANCH to the expected (major, minor) tuple. We
# accept patch-version drift (1.1.5 vs 1.1.8 is fine on
# release/1.1.x); we do NOT accept minor-version drift.
expected_major=""
expected_minor=""
allow_main_markers=0

case "$AK_BACKEND_BRANCH" in
  main|master)
    # main branch: accept "main", "dev", or any version we haven't
    # tagged yet. We don't know the precise next-version major.minor
    # from this side, so the assertion is "reported version is
    # either an obvious main marker OR strictly newer than the
    # last-released minor we know about".
    allow_main_markers=1
    ;;
  release/1.1.x|release/1.1.*|v1.1.*|1.1.*)
    expected_major=1; expected_minor=1 ;;
  release/1.2.x|release/1.2.*|v1.2.*|1.2.*)
    expected_major=1; expected_minor=2 ;;
  *)
    # Already warned by feature_flags_init; let the assertion still
    # run, but expected_* are empty so the test will skip the strict
    # check.
    ;;
esac

begin_test "Backend version aligns with AK_BACKEND_BRANCH=${AK_BACKEND_BRANCH}"
if [ "$allow_main_markers" = "1" ]; then
  case "$reported" in
    main|dev|snapshot|""|*-dev|*-snapshot)
      pass
      ;;
    *)
      # On main we also accept a "real" version string (release
      # candidate cut from main but not yet retagged). The contract
      # is: it must NOT match a known release-branch minor we have
      # in the static map (otherwise the workflow is mis-pointed).
      if [ "$major" = "1" ] && { [ "$minor" = "1" ] || [ "$minor" = "0" ]; }; then
        fail "AK_BACKEND_BRANCH=main but backend reports ${reported}; gate is testing main feature flags against a back-versioned backend"
      else
        pass
      fi
      ;;
  esac
elif [ -z "$expected_major" ] || [ -z "$expected_minor" ]; then
  skip "AK_BACKEND_BRANCH=${AK_BACKEND_BRANCH} not in static branch map; cannot drift-check"
elif [ "$major" = "$expected_major" ] && [ "$minor" = "$expected_minor" ]; then
  pass
else
  fail "DRIFT: AK_BACKEND_BRANCH=${AK_BACKEND_BRANCH} expects major.minor=${expected_major}.${expected_minor}, backend /health reports ${reported} (parsed as ${major}.${minor}). The workflow is running the WRONG feature flag set for the deployed backend."
fi

# ---------------------------------------------------------------------------
# Sanity: AK_FEATURES is non-empty when AK_BACKEND_BRANCH is set
# (catches a bug where feature_flags_init is sourced but somehow
# fails to derive the flag set).
# ---------------------------------------------------------------------------

begin_test "AK_FEATURES is populated for AK_BACKEND_BRANCH=${AK_BACKEND_BRANCH}"
if [ -n "${AK_FEATURES:-}" ]; then
  echo "  AK_FEATURES=${AK_FEATURES}"
  pass
else
  fail "AK_BACKEND_BRANCH is set but AK_FEATURES is empty; feature_flags_init failed silently"
fi

end_suite
