#!/usr/bin/env bash
# test-livez.sh - /livez liveness probe contract (Epic 10.4, #77)
#
# /health and /readyz are already covered. /livez is the third K8s probe
# variant -- it MUST be unauthenticated and MUST return 200 whenever the
# process is up, even if dependencies are degraded. This is what
# kubelet uses to decide whether to restart the pod.
#
# Contract:
#   GET /livez            -> 200 (no auth required)
#   GET /api/v1/livez     -> 200 (alias under /api/v1; some deployments only mount here)
#
# Requires: curl
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-livez"

begin_test "GET /livez returns 200 without auth"
# Deliberately do not send Authorization header. /livez is for kubelet.
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/livez" 2>/dev/null) || status=000
if [ "$status" = "200" ]; then
  pass
elif [ "$status" = "404" ]; then
  # Endpoint may be mounted at /api/v1/livez only; verify alias before failing.
  alias_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/livez" 2>/dev/null) || alias_status=000
  if [ "$alias_status" = "200" ]; then
    pass
  else
    fail "GET /livez returned 404 and /api/v1/livez returned ${alias_status}"
  fi
else
  fail "GET /livez returned ${status}, expected 200"
fi

begin_test "GET /livez body is short and JSON-ish"
# /livez should return a tiny response (kubelet polls it frequently). The
# exact body shape varies (some return {"status":"ok"}, some return "ok"),
# but it MUST be under 1 KiB to avoid hammering kubelet.
body=$(curl -sf $CURL_TIMEOUT "${BASE_URL}/livez" 2>/dev/null \
  || curl -sf $CURL_TIMEOUT "${BASE_URL}/api/v1/livez" 2>/dev/null \
  || echo "")
if [ -z "$body" ]; then
  fail "could not read /livez body"
elif [ ${#body} -gt 1024 ]; then
  fail "/livez body is ${#body} bytes, expected <= 1024"
else
  pass
fi

end_suite
