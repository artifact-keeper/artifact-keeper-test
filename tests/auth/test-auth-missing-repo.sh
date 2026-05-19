#!/usr/bin/env bash
# test-auth-missing-repo.sh - Regression for artifact-keeper#874
#
# Bug summary
# -----------
# repo_visibility_middleware short-circuited when the repo lookup
# returned None: it called next.run(request) WITHOUT inserting
# Option<AuthExtension> into request extensions. Format handlers that
# declare Extension<Option<AuthExtension>> as an extractor (conan,
# generic, npm, pypi, others) then failed Axum extraction with
# HTTP 500 (MissingExtension) instead of letting the handler return
# its own 404.
#
# Original repro from the PR body (artifact-keeper#874, merged
# 2026-04-25, commit d7a60307):
#
#   PUT /conan/does-not-exist/v2/conans/.../files/conanfile.py
#   pre-fix:  500 (MissingExtension)
#   post-fix: 404 (from the handler, after it resolves the repo)
#
# Contract pinned by this test
# ----------------------------
# Any HTTP request through ANY format handler against a non-existent
# repo MUST return a clean 4xx refusal. NEVER 500.
#
# We test multiple format handlers because the bug affected every
# handler that takes Extension<Option<AuthExtension>>. Testing only
# one format would let a future refactor re-introduce the short-
# circuit on a different handler without this test catching it.
#
# We also run each case unauthenticated AND with admin auth: pre-fix,
# MissingExtension fired in Axum's extractor before the handler ran,
# so auth state was irrelevant -- the test must cover both paths to
# guard against a regression that only re-breaks one of them.
#
# Requires: curl (no upload, no repo creation)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-missing-repo"

# A repo key the backend has never seen. RUN_ID-suffixed to avoid any
# race against a parallel suite that transiently creates + deletes a
# repo by the same name (the LIKE-injection test in #1004 plants a
# real repo elsewhere in the same release-gate run).
MISSING_REPO="does-not-exist-${RUN_ID}"

# Cover format handlers from the original PR body ("conan, generic,
# others") plus two more (npm, pypi) that are common production
# entry points. Each is a real backend route; the response code is
# whatever the handler returns once it tries to resolve the repo --
# we do NOT pin to 404 specifically because some handlers may return
# 401 (e.g. if they require auth before repo lookup). The load-bearing
# assertion is "no 500".
#
# Format: "<METHOD>|<path>|<description>"
CASES=(
  "GET|/api/v1/conan/${MISSING_REPO}/v2/conans/foo/1.0/_/_/latest|conan v2 latest"
  "GET|/api/v1/generic/${MISSING_REPO}/some/path/file.txt|generic path-fetch"
  "GET|/api/v1/npm/${MISSING_REPO}/some-package|npm package metadata"
  "GET|/api/v1/pypi/${MISSING_REPO}/simple/somepkg/|pypi simple-index"
)

# auth_admin is best-effort. The bug fired regardless of auth state,
# so we want this suite to still surface the regression even if admin
# login is degraded on a given runner.
ADMIN_TOKEN=""
if auth_admin >/dev/null 2>&1; then
  ADMIN_TOKEN="$ACCESS_TOKEN"
fi

_check_status() {
  local status="$1"
  local desc="$2"
  case "$status" in
    500)
      fail "${desc} returned 500 (MissingExtension regression of #874); should be 4xx"
      ;;
    4*)
      pass
      ;;
    *)
      fail "${desc} returned ${status}, expected a 4xx refusal (or any non-5xx)"
      ;;
  esac
}

for case_spec in "${CASES[@]}"; do
  IFS='|' read -r method path desc <<< "$case_spec"
  url="${BASE_URL}${path}"

  begin_test "${desc} (no auth) -> non-500"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X "${method}" "${url}" 2>/dev/null) || status=000
  _check_status "$status" "${method} ${path} (no auth)"

  if [ -n "$ADMIN_TOKEN" ]; then
    begin_test "${desc} (admin auth) -> non-500"
    status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -X "${method}" "${url}" 2>/dev/null) || status=000
    _check_status "$status" "${method} ${path} (admin)"
  else
    # Don't silently skip the authed path; surface it as a skip so the
    # release-gate dashboard distinguishes "admin path not exercised"
    # from "admin path passed".
    begin_test "${desc} (admin auth) -> non-500"
    skip "admin login unavailable; covered the unauth path above"
  fi
done

end_suite
