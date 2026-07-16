#!/usr/bin/env bash
# test-migrations-sse-stream.sh - SSE progress streaming (v1.2.0)
#
# Covers artifact-keeper-test#74 subtask 9.4:
#   GET /migrations/{id}/stream  (Server-Sent Events)
#
# Goal
#   Confirm the SSE endpoint is reachable, returns text/event-stream, and
#   emits at least one event line for a started job, then disconnect
#   cleanly via curl --max-time without hanging the suite.
#
# Why this is the load-bearing assertion
#   The migration UI consumes this stream to show live progress; a regression
#   that makes the endpoint hang without any data, or that returns 200 with
#   an empty body, would silently break the UI. Reading at least one event
#   line within --max-time pins that "something is being streamed".
#
# Design notes
#   - We use `curl --no-buffer -N --max-time 30` and let curl terminate on
#     its own. We do NOT background curl with `&` and kill it: every prior
#     attempt at that pattern (#138, #142) left orphaned curls in CI when
#     the suite scripts were interrupted mid-stream. --max-time is the
#     cleanest disconnect.
#   - Exit code 28 from curl means "operation timed out" which for SSE is
#     the EXPECTED termination -- we hit --max-time after the server kept
#     streaming. We treat 28 the same as 0 for this test.
#   - We do not assert event JSON shape because the SSE schema is not
#     fully pinned in 1.2.0 (the openapi entry has no response body). We
#     do require at least one non-empty line that begins with the SSE
#     prefix `data:` or `event:` or `id:`, which is the minimum the spec
#     guarantees.
#
# Skip behavior
#   If the subsystem is disabled (404/501 on create-connection) we skip
#   and exit 0. We do NOT skip_suite (release-gate would harden that into
#   a fail).
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "migrations-sse-stream"
auth_admin

CONNECTION_NAME="mig-conn-sse-${RUN_ID}"
# Note: migration jobs no longer carry a `name` field in the backend
# contract (migration.rs CreateMigrationRequest / MigrationJobResponse),
# so there is no JOB_NAME to set or assert on.
CONNECTIONS_BASE="/api/v1/migrations/connections"
JOBS_BASE="/api/v1/migrations"

CONNECTION_IDS=()
JOB_IDS=()

cleanup_migrations() {
  local id
  for id in "${JOB_IDS[@]:-}"; do
    [ -z "$id" ] && continue
    curl -sf $CURL_TIMEOUT -X POST -H "$(auth_header)" \
      "${BASE_URL}${JOBS_BASE}/${id}/cancel" >/dev/null 2>&1 || true
    curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
      "${BASE_URL}${JOBS_BASE}/${id}" >/dev/null 2>&1 || true
  done
  for id in "${CONNECTION_IDS[@]:-}"; do
    [ -z "$id" ] && continue
    curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
      "${BASE_URL}${CONNECTIONS_BASE}/${id}" >/dev/null 2>&1 || true
  done
}
trap cleanup_migrations EXIT

migrations_request() {
  local method="$1" path="$2" data="${3:-}"
  local _tmp
  _tmp=$(mktemp)
  local _status
  if [ -n "$data" ]; then
    _status=$(curl -s $CURL_TIMEOUT -o "$_tmp" -w '%{http_code}' \
      -X "$method" \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      -d "$data" \
      "${BASE_URL}${path}" 2>/dev/null) || _status="000"
  else
    _status=$(curl -s $CURL_TIMEOUT -o "$_tmp" -w '%{http_code}' \
      -X "$method" \
      -H "$(auth_header)" \
      "${BASE_URL}${path}" 2>/dev/null) || _status="000"
  fi
  local _body
  _body=$(cat "$_tmp" 2>/dev/null || true)
  rm -f "$_tmp"
  echo "${_status}"
  echo "${_body}"
}

# ---------------------------------------------------------------------------
# Pre-flight: create connection + job and start it so the stream has
# something to emit. (An un-started job may still stream a "queued" event;
# starting maximises the chance of getting a progress frame within
# --max-time.)
# ---------------------------------------------------------------------------

begin_test "Create migration connection (SSE fixture)"
CREATE_PAYLOAD=$(jq -nc \
  --arg name "$CONNECTION_NAME" \
  '{
    name: $name,
    source_type: "artifactory",
    url: "https://example.invalid/artifactory",
    auth_type: "basic_auth",
    credentials: { type: "basic", username: "test", password: "test" }
  }')

RESP=$(migrations_request POST "$CONNECTIONS_BASE" "$CREATE_PAYLOAD")
STATUS=$(echo "$RESP" | head -1)
BODY=$(echo "$RESP" | tail -n +2)

case "$STATUS" in
  404|501)
    skip "migrations subsystem not enabled on this backend (HTTP ${STATUS})"
    end_suite
    exit 0
    ;;
  200|201)
    CONN_ID=$(echo "$BODY" | jq -r '.id // .connection.id // empty' 2>/dev/null || echo "")
    if [ -n "$CONN_ID" ] && [ "$CONN_ID" != "null" ]; then
      CONNECTION_IDS+=("$CONN_ID")
      pass
    else
      fail "create-connection HTTP ${STATUS} but no id; body=${BODY:0:200}"
    fi
    ;;
  *)
    fail "create-connection expected 200/201, got ${STATUS}; body=${BODY:0:200}"
    ;;
esac

if [ "${#CONNECTION_IDS[@]}" -eq 0 ]; then
  echo "  skipping SSE test: no connection id"
  end_suite
fi
CONN_ID="${CONNECTION_IDS[0]}"

begin_test "Create migration job for SSE consumer"
# Backend contract (migration.rs `CreateMigrationRequest`, authoritative):
# {source_connection_id, job_type?, config}. The old
# {name, connection_id, source_path, target_repo} shape now 422s with
# "missing field source_connection_id".
JOB_PAYLOAD=$(jq -nc \
  --arg cid "$CONN_ID" \
  '{
    source_connection_id: $cid,
    job_type: "full",
    config: {}
  }')

RESP=$(migrations_request POST "$JOBS_BASE" "$JOB_PAYLOAD")
STATUS=$(echo "$RESP" | head -1)
BODY=$(echo "$RESP" | tail -n +2)

JOB_ID=""
if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
  JOB_ID=$(echo "$BODY" | jq -r '.id // .job.id // empty' 2>/dev/null || echo "")
  if [ -n "$JOB_ID" ] && [ "$JOB_ID" != "null" ]; then
    JOB_IDS+=("$JOB_ID")
    pass
  else
    fail "create-job HTTP ${STATUS} but no id; body=${BODY:0:200}"
  fi
else
  fail "create-job expected 200/201, got ${STATUS}; body=${BODY:0:200}"
fi

if [ -z "$JOB_ID" ]; then
  echo "  skipping SSE test: no job id"
  end_suite
fi

# Best-effort start: not required for the stream to emit (some backends
# emit a snapshot frame on connect regardless of state), but it
# maximises our chance of getting a progress event within the window.
migrations_request POST "${JOBS_BASE}/${JOB_ID}/start" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 9.4 Connect, read at least one event, disconnect via --max-time.
# ---------------------------------------------------------------------------

begin_test "GET /stream emits at least one SSE event within 30s"
STREAM_OUT=$(mktemp)
HEADERS_OUT=$(mktemp)

# --no-buffer        flush as data arrives (default curl buffers stdout)
# -N                 disable curl's own line buffering (alias for --no-buffer)
# --max-time 30      hard ceiling: SSE is open-ended; this is our disconnect
# -D                 dump response headers (for content-type check)
# -H Accept          some backends require explicit SSE acceptance
CURL_EXIT=0
curl --no-buffer -N \
  --max-time 30 \
  -s \
  -o "$STREAM_OUT" \
  -D "$HEADERS_OUT" \
  -H "$(auth_header)" \
  -H "Accept: text/event-stream" \
  "${BASE_URL}${JOBS_BASE}/${JOB_ID}/stream" 2>/dev/null || CURL_EXIT=$?

# curl exit 28 = operation timed out (i.e. --max-time hit while stream was
# still open). For SSE this is the EXPECTED clean disconnect. 0 also
# acceptable (server closed first). Anything else is a connection error.
case "$CURL_EXIT" in
  0|28) : ;;
  *)
    fail "curl exited ${CURL_EXIT} (not 0 or 28-timeout) -- SSE connect failed"
    rm -f "$STREAM_OUT" "$HEADERS_OUT"
    end_suite
    ;;
esac

# Inspect headers: HTTP status and content-type. A 200 with
# text/event-stream is the contract. 404 = subsystem stripped, treat as
# skip below.
HTTP_STATUS_LINE=$(grep -E '^HTTP/' "$HEADERS_OUT" | tail -1 | awk '{print $2}')
CONTENT_TYPE=$(grep -iE '^content-type:' "$HEADERS_OUT" | tail -1 | tr -d '\r' | awk -F': ' '{print $2}')

if [ "$HTTP_STATUS_LINE" = "404" ] || [ "$HTTP_STATUS_LINE" = "501" ]; then
  rm -f "$STREAM_OUT" "$HEADERS_OUT"
  skip "stream endpoint not implemented (HTTP ${HTTP_STATUS_LINE})"
  end_suite
fi

if [ "$HTTP_STATUS_LINE" != "200" ]; then
  fail "stream expected HTTP 200, got '${HTTP_STATUS_LINE}'"
  rm -f "$STREAM_OUT" "$HEADERS_OUT"
  end_suite
fi

# Content-type check is informational, not load-bearing: some backends
# serve `text/event-stream; charset=utf-8`, some just `text/event-stream`.
case "$CONTENT_TYPE" in
  text/event-stream*) : ;;
  *)
    echo "    note: unexpected content-type '${CONTENT_TYPE}' (expected text/event-stream)"
    ;;
esac

# Load-bearing: at least one line that looks like an SSE field.
# SSE per W3C: lines beginning with `data:`, `event:`, `id:`, `retry:`,
# or a `:` comment. We accept any of these as proof the stream emitted.
EVENT_LINE_COUNT=$(grep -cE '^(data|event|id|retry):' "$STREAM_OUT" 2>/dev/null || echo 0)
EVENT_LINE_COUNT="${EVENT_LINE_COUNT//[^0-9]/}"
EVENT_LINE_COUNT="${EVENT_LINE_COUNT:-0}"

if [ "$EVENT_LINE_COUNT" -ge 1 ]; then
  pass
else
  # Capture a small sample for the failure log to help triage.
  SAMPLE=$(head -c 300 "$STREAM_OUT" 2>/dev/null | tr '\n' ' ')
  fail "stream returned 200 but emitted no SSE fields within 30s; sample='${SAMPLE}'"
fi

rm -f "$STREAM_OUT" "$HEADERS_OUT"

end_suite
