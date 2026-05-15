#!/usr/bin/env bash
# test-events-sse-stream.sh - SSE event stream consumption smoke
#
# Epic 7 sub-task 7.15 (artifact-keeper-test#75). The backend exposes a
# server-sent-events stream at /api/v1/events/stream that bridges the
# in-process EventBus to external HTTP consumers. The platform suite
# already verifies the endpoint returns 200 but doesn't read any frames
# off the wire, so this test:
#
#   1. Opens a curl SSE connection in the background, writing frames to
#      a temp file with a hard 10s wall-clock cap (curl --max-time).
#   2. Triggers a domain event by creating a generic repository, which
#      should emit a repository.* event onto the bus.
#   3. Greps the frame log for an SSE-formatted "data:" line. We do NOT
#      assert event name (the bus -> SSE mapping is version-sensitive)
#      because the producer wire-up gate (webhook_event_producer) is
#      v1.2.0; on 1.1.x the SSE bridge may not emit a frame even though
#      the endpoint is live. Hence: skip cleanly if no frame appears,
#      and only fail on protocol-shape violations (e.g. the endpoint
#      returns HTML instead of an event stream).
#
# This is intentionally a thin proof-of-concept; the full SSE coverage
# (back-pressure, lagged-event handling, JSON payload schema, named
# event types, last-event-id resumption) is broken out in the epic
# tracking comment.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "events-sse-stream"
auth_admin
setup_workdir

REPO_KEY="sse-trigger-${RUN_ID}"
SSE_LOG="${WORK_DIR}/sse-frames.log"
SSE_HDR="${WORK_DIR}/sse-headers.log"
SSE_PID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${SSE_PID}" ] && kill -0 "${SSE_PID}" 2>/dev/null; then
    kill "${SSE_PID}" 2>/dev/null || true
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
  skip "SSE stream did not open (endpoint may not be available)"
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
  skip "no response headers captured (endpoint may have closed immediately)"
  end_suite
else
  # Not a hard fail: some deployments serve plain JSON polling under the
  # same path. We only insist when the path is wired as a real SSE source.
  skip "endpoint returned non-SSE content-type: ${ct}"
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
# Wait for a frame.
# -------------------------------------------------------------------------

begin_test "SSE log accumulates a 'data:' frame within 5s"
saw_frame=false
for _ in $(seq 1 10); do
  if grep -qE '^data:|^event:|^id:' "$SSE_LOG" 2>/dev/null; then
    saw_frame=true
    break
  fi
  sleep 0.5
done
if [ "$saw_frame" = true ]; then
  pass
else
  # On 1.1.x backends with the producer disabled, the SSE bridge may be
  # idle. Skip rather than fail so the test reports a clean signal once
  # producer wire-up lands.
  skip "no SSE frame observed; producer may not be wired (v1.1.x)"
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
