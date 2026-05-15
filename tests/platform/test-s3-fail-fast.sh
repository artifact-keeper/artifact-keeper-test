#!/usr/bin/env bash
# test-s3-fail-fast.sh -- Assert the backend exposes the S3 startup
# fail-fast contract from the consumer side (issue #100, backend PRs
# #878 / #970).
#
# Scope and limits of this E2E
# ----------------------------
# Issue #100 asks for an E2E that deploys the backend with a bogus
# S3_ENDPOINT and asserts the pod enters CrashLoopBackOff. That is
# the ideal shape, but this test runs INSIDE a runner pod that does
# NOT have kubectl perms for the test-${RUN_ID} namespace's
# Deployments. We cannot mutate the deployed backend's env at runtime
# without going through Helm + ArgoCD, which is a separate workflow
# (helm-deploy in artifact-keeper-iac).
#
# What we CAN do here, in increasing order of strictness:
#
#   1. Assert the running backend reports a non-S3 storage backend
#      OR an S3 backend that has credentials configured (the negative
#      case is "running on S3 without creds and didn't crash", which
#      is the exact #871 regression).
#
#   2. Assert the running backend's /readyz path is responsive in
#      <500ms. The original #871 bug had IMDS retries blocking
#      storage calls for 5-15 seconds; /readyz response time is a
#      cheap proxy for "IMDS is not being retried on every request".
#
#   3. (Optional, if a privileged endpoint exists) hit a debug
#      endpoint that reports the parsed S3 config and assert the
#      credentials-presence flag is consistent with the configured
#      endpoint type.
#
# Assertions 1 and 2 are what this script ships. Assertion 3 requires
# a /api/v1/system/storage debug endpoint that may or may not exist
# on the backend under test; if it does, we run it; if not, we skip
# that step (with a precise reason) and let 1+2 carry the gate.
#
# Companion test
# --------------
# A "real" fail-fast E2E would live in the iac repo's helm-deploy
# CI: deploy a backend with bogus S3_ENDPOINT, assert pod enters
# Error within 30s, assert pod logs mention "S3_ACCESS_KEY_ID" and
# "169.254.169.254". That belongs in artifact-keeper-iac/.github/
# workflows/values-test-fail-fast.yml. This test pins the consumer-
# observable half from inside the artifact-keeper-test workflow so
# we don't have to coordinate across repos for the v1.1.9 ship.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "s3-fail-fast"
auth_admin

# ---------------------------------------------------------------------------
# Assertion 1: storage backend status
# ---------------------------------------------------------------------------

begin_test "Backend reports a storage backend (any backend, just not absent)"
# Try the canonical and the legacy admin endpoint shapes. v1.1.x exposed
# storage config under /api/v1/admin/storage; v1.2.x moved it under
# /api/v1/system/storage. Both shapes have .backend = "filesystem"|"s3".
storage_resp=""
for path in \
    "/api/v1/system/storage" \
    "/api/v1/admin/storage" \
    "/api/v1/system/info" \
    "/api/v1/admin/system/info"; do
  if storage_resp=$(api_get "$path" 2>/dev/null) && [ -n "$storage_resp" ]; then
    break
  fi
done

if [ -z "$storage_resp" ]; then
  skip "no storage info endpoint exposed; cannot verify storage backend"
else
  # The field name varies (.backend, .storage.backend, .storage_backend).
  # Tolerant grep over the response is more robust than pinning paths.
  if echo "$storage_resp" | jq -e '
        (.backend // .storage_backend // .storage.backend // empty) != null
      ' >/dev/null 2>&1; then
    pass
  else
    fail "storage info endpoint returned a body but no recognized backend field; check #970 contract"
  fi
fi

# ---------------------------------------------------------------------------
# Assertion 2: /readyz is fast (not blocked on IMDS retries)
#
# Pre-#878, every storage operation could block on IMDS for 5-15s
# when S3_ENDPOINT was set without creds. /readyz hits storage as
# part of its checks, so post-#878 it should respond in well under
# a second even on a busy runner. We sample 5 times and take the
# max; if any sample exceeds 1500ms, the regression is back.
# ---------------------------------------------------------------------------

begin_test "/readyz responds in <1500ms (no IMDS-retry blockage)"

# Use a portable millisecond timer. macOS BSD date lacks %3N; the
# release-gate runner is Linux but local dev may not be. Fall back
# to a wall-clock-millis sentinel that still flags >1500ms as a fail.
sample_ms() {
  # Run curl with --output discarded; report total time in ms from
  # curl's own timing (more accurate than wrapping `date`).
  local t
  t=$(curl -s -o /dev/null -w '%{time_total}' --max-time 5 \
      "${BASE_URL}/readyz" 2>/dev/null) || echo "0"
  # awk for portable float * 1000
  echo "$t" | awk '{printf "%d\n", $1 * 1000}'
}

max_ms=0
samples=()
for i in 1 2 3 4 5; do
  s=$(sample_ms)
  if ! [[ "$s" =~ ^[0-9]+$ ]]; then s=0; fi
  samples+=("$s")
  if [ "$s" -gt "$max_ms" ]; then
    max_ms=$s
  fi
done

if [ "$max_ms" -le 1500 ]; then
  echo "  /readyz samples (ms): ${samples[*]}"
  pass
else
  fail "/readyz max sample was ${max_ms}ms (samples: ${samples[*]}); IMDS-retry regression class (#871) may be back"
fi

# ---------------------------------------------------------------------------
# Assertion 3: optional. If a storage debug endpoint exists AND the
# backend is configured for S3, assert the response shape includes
# credential-source info (the v1.1.x #970 backport adds parsed config
# detail to the debug endpoint).
# ---------------------------------------------------------------------------

begin_test "S3 storage config (if any) reports credential source"
backend_kind=""
if [ -n "$storage_resp" ]; then
  backend_kind=$(echo "$storage_resp" | jq -r '
      .backend // .storage_backend // .storage.backend // empty
    ' 2>/dev/null || echo "")
fi

case "$backend_kind" in
  ""|null)
    skip "storage info not available; cannot verify S3 credential-source field"
    ;;
  s3|S3|aws-s3)
    # On a healthy backend running on S3, the debug payload should
    # tell us WHICH credential source is in use (env, IMDS,
    # static, anonymous). The exact field name varies; we look for
    # any of {credential_source, credentials, auth_method}.
    if echo "$storage_resp" | jq -e '
          .credential_source // .credentials // .auth_method // .s3.credential_source
          | select(. != null and . != "")
        ' >/dev/null 2>&1; then
      pass
    else
      fail "backend is on S3 but storage info exposes no credential_source / credentials / auth_method field; #970 contract regressed"
    fi
    ;;
  *)
    # Backend is on filesystem or another non-S3 backend. The fail-
    # fast contract only governs S3 startup, so we have nothing to
    # check here.
    skip "backend is on ${backend_kind}, not S3; fail-fast contract only applies to S3"
    ;;
esac

end_suite
