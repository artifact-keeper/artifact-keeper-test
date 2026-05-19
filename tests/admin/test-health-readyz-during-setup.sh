#!/usr/bin/env bash
# test-health-readyz-during-setup.sh - Regression for artifact-keeper#1099
#
# Bug summary
# -----------
# /readyz returned HTTP 503 when state.setup_required = true (the
# default admin password had not yet been changed). Kubernetes
# treated the pod as NotReady and eventually restarted it. The pod
# restart killed any `kubectl exec` session the operator was using
# to change the password, so the operator could never complete
# setup and the pod stayed in a restart loop.
#
# Fix (artifact-keeper#1099, merged 2026-05-08, commit 22b99a7):
#   - /readyz returns 200 once the database is reachable and
#     migrations have run, EVEN IF setup_required = true.
#   - The setup_complete field stays in the response body as
#     informational: "complete" or "incomplete". The HTTP status
#     code no longer gates on it.
#   - main.rs emits a tracing::warn!(event="setup_required") at
#     startup so log-based alerting can still detect un-bootstrapped
#     deployments.
#
# What this test pins
# -------------------
# /readyz returns 200 regardless of setup_complete state. The body
# carries the setup_complete signal for downstream tooling. Pre-fix,
# /readyz returned 503 when setup_required = true, so the regression
# we are guarding against is "200 reverts to 503 when setup is
# incomplete".
#
# Test surface in a release-gate context
# --------------------------------------
# The release-gate deploy fixtures complete admin setup before any
# test runs (the admin password is changed in deploy.yaml's bootstrap
# step), so by the time this script runs setup_complete is almost
# always "complete". The test still exercises three load-bearing
# invariants that DO regress under #1099-style breakage:
#
#   (a) /readyz returns HTTP 200 -- pinned unconditionally.
#   (b) /readyz body carries a setup_complete field. Pre-fix the
#       field name was `status: healthy|unhealthy` and the gate was
#       implicit; post-fix the gate is explicit and named.
#   (c) IF setup_complete is "incomplete", /readyz MUST still be 200
#       (the load-bearing assertion). IF "complete", we still
#       sanity-check that the field exists and the schema didn't
#       regress to the old shape.
#
# When (c) fires in a "complete" state it is a negative control --
# it pins the schema -- not the original-bug repro. The original
# repro requires a fresh deploy with the default admin password,
# which is an iac-side fixture (#179 follow-up tracks landing that).

source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-readyz-during-setup"

# ---------------------------------------------------------------------------
# Invariant (a): /readyz returns 200
# ---------------------------------------------------------------------------

begin_test "GET /readyz returns 200 (regardless of setup_complete state)"
body_file=$(mktemp -t readyz-body.XXXXXXXX)
status=$(curl -s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/readyz" 2>/dev/null) || status=000
body=$(cat "$body_file" 2>/dev/null || echo "")
rm -f "$body_file"

if [ "$status" = "200" ]; then
  pass
elif [ "$status" = "503" ]; then
  # Check the body to distinguish "DB or migrations down" (legitimate
  # 503) from "setup_required gating the response" (the #1099 bug).
  if echo "$body" | jq -e '.setup_complete == "incomplete"' >/dev/null 2>&1; then
    fail "/readyz returned 503 with setup_complete=incomplete: #1099 regression -- the fix that made /readyz return 200 even when setup_required=true has been reverted"
  else
    fail "/readyz returned 503 but body does not surface setup_complete; either the DB/migrations are actually down (separate issue) or the schema regressed below the fix's response-shape contract"
  fi
else
  fail "/readyz returned ${status}, expected 200 (or, if backend is genuinely degraded, a 503 with explanatory body)"
fi

# ---------------------------------------------------------------------------
# Invariant (b): setup_complete field is present in the body
# ---------------------------------------------------------------------------

begin_test "/readyz body carries a setup_complete field"
body_file=$(mktemp -t readyz-body.XXXXXXXX)
curl -sf -o "$body_file" $CURL_TIMEOUT "${BASE_URL}/readyz" 2>/dev/null || true
body=$(cat "$body_file" 2>/dev/null || echo "")
rm -f "$body_file"

if [ -z "$body" ]; then
  fail "/readyz returned empty body; cannot verify response shape"
else
  setup_value=$(echo "$body" | jq -r '.setup_complete // empty' 2>/dev/null || echo "")
  if [ -z "$setup_value" ]; then
    fail "/readyz body has no .setup_complete field: schema regressed below the #1099 contract. Body was: $(echo "$body" | head -c 200)"
  elif [ "$setup_value" = "complete" ] || [ "$setup_value" = "incomplete" ]; then
    pass
  else
    fail "/readyz .setup_complete = '${setup_value}'; expected 'complete' or 'incomplete' per #1099 contract"
  fi
fi

# ---------------------------------------------------------------------------
# Invariant (c): if setup_complete is "incomplete", /readyz MUST be 200.
#
# This is the load-bearing #1099 assertion. It only fires when the
# deployed backend happens to be in the un-bootstrapped state. In
# release-gate runs that always pre-bootstrap the admin password,
# this branch usually does not execute -- the previous test already
# pinned that setup_complete is reported. The branch IS the original
# bug class so we keep it: a future deploy fixture that runs this
# suite before bootstrapping (or a future #179 fresh-deploy harness)
# will exercise it for real.
# ---------------------------------------------------------------------------

begin_test "When setup_complete=incomplete, /readyz must still be 200 (#1099 contract)"
body_file=$(mktemp -t readyz-body.XXXXXXXX)
status=$(curl -s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/readyz" 2>/dev/null) || status=000
body=$(cat "$body_file" 2>/dev/null || echo "")
rm -f "$body_file"

setup_value=$(echo "$body" | jq -r '.setup_complete // empty' 2>/dev/null || echo "")
if [ "$setup_value" = "incomplete" ]; then
  if [ "$status" = "200" ]; then
    pass
  else
    fail "/readyz returned ${status} with setup_complete=incomplete; pre-#1099 behavior, MUST be 200"
  fi
elif [ "$setup_value" = "complete" ]; then
  # Negative control: backend is already bootstrapped on this runner.
  # Skip the unconditional 200 check (it would not exercise the bug
  # class) but pass the test so the suite stays green when the
  # release-gate deploy fixture has run admin bootstrap.
  skip "setup_complete=complete; bug class not reachable on this deployment (covered by #179 fresh-deploy fixture follow-up)"
else
  fail "could not determine setup_complete state; previous test should have caught this"
fi

end_suite
