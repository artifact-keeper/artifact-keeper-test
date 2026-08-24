#!/usr/bin/env bash
# test-metrics-auth.sh - Prometheus metrics endpoint is not publicly readable
#
# Ported from tests/security/redteam/test-15-metrics-auth.sh. That script
# sourced tests/security/redteam/lib.sh, whose fail() incremented a counter
# nothing read; the script ended in a literal `exit 0`, so run-suite.sh
# recorded PASS unconditionally and no JUnit XML was written. See
# tests/security/README-redteam-port.md for the full port record.
#
# What this pins
# --------------
# Metrics were once served unauthenticated at /metrics (11+ MB of operational
# data: request paths, status codes, upstream hosts). They now live behind
# admin auth at /api/v1/admin/metrics. Three assertions, in order, so the
# suite cannot pass by the endpoint simply disappearing:
#
#   1. GET /metrics without credentials must NOT return 200.
#   2. GET /api/v1/admin/metrics without credentials must return 401.
#   3. GET /api/v1/admin/metrics WITH an admin token must return 200 and serve
#      a real exposition. This is the positive control: without it, deleting
#      the metrics subsystem outright would satisfy 1 and 2 and report green.
#
# tests/platform/test-metrics-unmatched-cardinality.sh scrapes the same
# endpoint and its comment names this file as the owner of the "old
# unauthenticated path was removed" invariant.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "metrics-auth"
auth_admin

# ---------------------------------------------------------------------------
# 1. Legacy public path must not serve metrics anonymously
# ---------------------------------------------------------------------------

begin_test "GET /metrics without credentials does not return 200"
metrics_body=$(mktemp)
status=$(curl -s -o "$metrics_body" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  "${BASE_URL}/metrics" 2>/dev/null) || status="000"
body_size=$(wc -c < "$metrics_body" 2>/dev/null | tr -d '[:space:]') || body_size=0
body_snip=$(head -c 300 "$metrics_body" 2>/dev/null) || body_snip=""
rm -f "$metrics_body"

if [ "$status" = "000" ]; then
  fail "GET /metrics did not complete (curl status 000); the endpoint was not certified"
elif [ "$status" = "200" ]; then
  fail "GET /metrics is readable without authentication (HTTP 200, ${body_size} bytes)" \
    "The Prometheus scrape endpoint is public. It exposes request paths, status codes, upstream hosts and queue depths to any unauthenticated caller. Metrics must be served only from /api/v1/admin/metrics behind admin auth. Body starts: ${body_snip}"
else
  pass
fi

# ---------------------------------------------------------------------------
# 2. Admin path rejects anonymous callers
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/admin/metrics without credentials returns 401"
status=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null) || status="000"

if [ "$status" = "401" ]; then
  pass
else
  fail "expected HTTP 401 from unauthenticated GET /api/v1/admin/metrics, got ${status}" \
    "200 here is a metrics leak. 404 means the route moved, and assertion 3 below will say so. Anything else means the auth layer is not returning an authentication verdict on this route."
fi

# ---------------------------------------------------------------------------
# 3. Positive control: the endpoint still exists and still serves metrics
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/admin/metrics with an admin token returns metrics"
resp_file=$(mktemp)
status=$(curl -s -o "$resp_file" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null) || status="000"
body_size=$(wc -c < "$resp_file" 2>/dev/null | tr -d '[:space:]') || body_size=0
has_series=false
if grep -q '^ak_http_requests_total' "$resp_file" 2>/dev/null; then
  has_series=true
fi
head_snip=$(head -c 300 "$resp_file" 2>/dev/null) || head_snip=""
rm -f "$resp_file"

if [ "$status" != "200" ]; then
  fail "expected HTTP 200 from authenticated GET /api/v1/admin/metrics, got ${status}" \
    "Assertions 1 and 2 above are satisfied by an absent endpoint as well as by a protected one. This control tells the two apart. Body: ${head_snip}"
elif [ "$has_series" != true ]; then
  fail "authenticated metrics response carries no ak_http_requests_total series (${body_size} bytes)" \
    "The endpoint answered 200 but is not serving the Prometheus exposition tests/platform/test-metrics-unmatched-cardinality.sh scrapes. Body starts: ${head_snip}"
else
  pass
fi

end_suite
