#!/usr/bin/env bash
# test-events-sse-stream.sh - SSE event stream consumption smoke
#
# Epic 7 sub-task 7.15 (artifact-keeper-test#75). The backend exposes a
# server-sent-events stream at /api/v1/events/stream that bridges the
# in-process EventBus to external HTTP consumers. The platform suite
# already verifies the endpoint returns 200 but does not read any frames
# off the wire, so this test:
#
#   1. Opens a curl SSE connection in the background, writing frames to
#      a temp file with a hard 10s wall-clock cap (curl --max-time).
#   2. Triggers a domain event by creating a generic repository, which
#      should emit a repository_created event onto the bus.
#   3. Asserts an SSE-formatted frame appears in the log within 5s.
#
# Gating: SSE-bus frame emission depends on the same producer wire-up
# that powers webhook deliveries (webhook_event_producer, v1.2.0). On
# older backends the endpoint is live but the bus does not emit frames
# for domain events, so the assertion would fail for an unshipped
# feature. The suite is skipped at the suite level when the producer is
# unavailable; on supported backends, missing-frame is a HARD FAIL, not
# a silent skip. This replaces the previous behaviour where the assertion
# called skip on missing frames (false-green pattern).
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "events-sse-stream"
auth_admin
setup_workdir

# Suite-level gate. If the producer wire-up that powers SSE frames is
# absent (v1.1.x), skip the whole suite cleanly instead of leaving
# individual assertions to skip on missing frames.
backend_ver=$(get_backend_version)
if [ "$backend_ver" != "unknown" ]; then
  min_ver=$(_feature_min_version "webhook_event_producer")
  if ! version_ge "$backend_ver" "$min_ver"; then
    skip_suite "events SSE producer requires backend >= ${min_ver}, running ${backend_ver}"
  fi
fi

REPO_KEY="sse-trigger-${RUN_ID}"
SSE_LOG="${WORK_DIR}/sse-frames.log"
SSE_HDR="${WORK_DIR}/sse-headers.log"
SSE_PID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${SSE_PID}" ] && kill -0 "${SSE_PID}" 2>/dev/null; then
    # SIGTERM first, then SIGKILL after a brief grace, so a curl that
    # has already drained its connection exits cleanly while a wedged
    # one is force-killed. The bounded sleep means cleanup can't hang.
    kill "${SSE_PID}" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      kill -0 "${SSE_PID}" 2>/dev/null || break
      sleep 0.2
    done
    kill -9 "${SSE_PID}" 2>/dev/null || true
    # The wait builtin returns immediately when the child has exited;
    # it doesn't block on the curl --max-time window since we've already
    # signalled. Redirect any "Killed" message from the shell.
    wait "${SSE_PID}" 2>/dev/null || true
  fi
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
  exit "$code"
}
trap cleanup_and_finalize EXIT

# -------------------------------------------------------------------------
# Open SSE stream in background.
# -------------------------------------------------------------------------

begin_test "Open SSE stream against /api/v1/events/stream"
# --max-time bounds the listener. Use -N to disable curl buffering so frames
# land in the log as they arrive. -D writes response headers to SSE_HDR so we
# can assert content-type without parsing the streamed body.
curl -sN $CURL_TIMEOUT --max-time 10 \
  -H "$(auth_header)" \
  -H "Accept: text/event-stream" \
  -D "$SSE_HDR" \
  -o "$SSE_LOG" \
  "${BASE_URL}/api/v1/events/stream" &
SSE_PID=$!

# Give the connection a moment to land before we start emitting events.
sleep 1
if kill -0 "$SSE_PID" 2>/dev/null; then
  pass
else
  # The producer feature was gated above; reaching here with a dead
  # listener means the endpoint itself is not reachable on a backend
  # that claims to support the feature. Fail hard.
  fail "SSE listener died within 1s on a backend that claims webhook_event_producer support"
  end_suite
fi

# -------------------------------------------------------------------------
# Verify response headers look like an event stream.
# -------------------------------------------------------------------------

begin_test "Stream returns text/event-stream content-type"
# Wait briefly for response headers to flush to disk.
ct=""
for _ in $(seq 1 10); do
  if [ -s "$SSE_HDR" ]; then
    ct=$(grep -i '^content-type:' "$SSE_HDR" | head -1 | tr -d '\r')
    [ -n "$ct" ] && break
  fi
  sleep 0.3
done
if echo "$ct" | grep -qi 'text/event-stream'; then
  pass
elif [ -z "$ct" ]; then
  fail "no response headers captured within 3s; SSE endpoint may be unreachable on a producer-enabled backend"
  end_suite
else
  fail "endpoint returned non-SSE content-type: ${ct}"
  end_suite
fi

# -------------------------------------------------------------------------
# Trigger a domain event.
# -------------------------------------------------------------------------

begin_test "Trigger domain event by creating a repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create trigger repo"
  end_suite
fi

# -------------------------------------------------------------------------
# Wait for a frame. On a feature-enabled backend, missing-frame is a
# hard FAIL (not a skip): we are explicitly asserting the bus -> SSE
# bridge emits something when a domain event fires.
# -------------------------------------------------------------------------

begin_test "SSE log accumulates a 'data:' frame within 5s"
# Bound the wait against a wall-clock deadline so a wedged grep cannot
# exceed the expected budget. We compute the deadline once and break out
# as soon as a frame appears OR the deadline passes; 10 polls of 0.5s
# would total 5s but a slow grep run could drift past that, so the
# deadline guard is the load-bearing budget.
saw_frame=false
deadline=$(( $(date +%s) + 6 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if grep -qE '^data:|^event:|^id:' "$SSE_LOG" 2>/dev/null; then
    saw_frame=true
    break
  fi
  sleep 0.5
done
if [ "$saw_frame" = true ]; then
  pass
else
  fail "no SSE frame observed within 6s after firing repository_created on a producer-enabled backend"
fi

# -------------------------------------------------------------------------
# Frame shape sanity: if we saw a frame, it must be parseable as SSE.
# -------------------------------------------------------------------------

if [ "$saw_frame" = true ]; then
  begin_test "First data frame is non-empty and not HTML"
  first_data=$(grep '^data:' "$SSE_LOG" | head -1 | sed 's/^data: *//')
  if [ -n "$first_data" ] && ! echo "$first_data" | grep -qiE '<html|<!doctype'; then
    pass
  else
    fail "first data frame looks invalid: '${first_data:0:100}'"
  fi
fi

end_suite
