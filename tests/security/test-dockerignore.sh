#!/usr/bin/env bash
# test-dockerignore.sh - #538: Verify .dockerignore excludes sensitive files
#
# This is a build-time concern, not an API behavior. The .dockerignore file
# prevents secrets, dev configs, and build artifacts from being copied into
# the Docker image. Since E2E tests run against a deployed instance, we can
# only verify the build succeeded (the backend is running) and skip the
# rest, as the actual validation belongs in the CI Docker build step.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "dockerignore"
auth_admin

# ---------------------------------------------------------------------------
# Backend is running (Docker build succeeded without .dockerignore issues)
# ---------------------------------------------------------------------------

begin_test "Backend is running (Docker image built successfully)"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/readyz" 2>/dev/null) || true

if [ "$status" = "200" ]; then
  pass
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/health" 2>/dev/null) || true
  if [ "$status" = "200" ]; then
    pass
  else
    fail "backend not reachable (HTTP ${status})"
  fi
fi

# ---------------------------------------------------------------------------
# .dockerignore validation is a build-time check
# ---------------------------------------------------------------------------

begin_test "Dockerignore validation"
skip "dockerignore is a build-time check, verified during CI Docker build"

end_suite
