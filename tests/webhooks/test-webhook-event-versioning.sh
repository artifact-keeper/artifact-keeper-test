#!/usr/bin/env bash
# test-webhook-event-versioning.sh
#
# Webhooks v2 wire contract (artifact-keeper#919, E4): per-webhook
# event_schema_version. Defaults to "2026-04-01"; unsupported versions
# return 400 (AppError::Validation) at create time.
#
# Sub-checks:
#   1. POST /api/v1/webhooks with no event_schema_version field -> created;
#      GET returns "event_schema_version": "2026-04-01"; deliveries carry
#      X-ArtifactKeeper-Event-Version: 2026-04-01.
#   2. POST with explicit "event_schema_version": "2026-04-01" -> created;
#      header matches.
#   3. POST with "event_schema_version": "9999-99-99" -> 400, body
#      mentions "supported".
#
# Companion backend PR: artifact-keeper#1140.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-event-versioning"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18771}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-ver-${RUN_ID}.log}"
RECEIVER_PID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${RECEIVER_PID}" ] && kill -0 "${RECEIVER_PID}" 2>/dev/null; then
    kill "${RECEIVER_PID}" 2>/dev/null || true
    wait "${RECEIVER_PID}" 2>/dev/null || true
  fi
  rm -f "${WEBHOOK_RECEIVER_LOG}"
  exit "$code"
}
trap cleanup_and_finalize EXIT

auth_admin

# -------------------------------------------------------------------------
# Pre-flight + receiver.
# -------------------------------------------------------------------------

begin_test "python3 and jq available"
miss=""
command -v python3 >/dev/null 2>&1 || miss="${miss} python3"
command -v jq      >/dev/null 2>&1 || miss="${miss} jq"
if [ -n "$miss" ]; then
  skip "missing tools:${miss}"
  end_suite
fi
pass

begin_test "Start mock receiver"
WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
  WEBHOOK_FAIL_FIRST_N=0 \
  WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
  python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
  >/tmp/mock-webhook-receiver-ver-${RUN_ID}.stderr 2>&1 &
RECEIVER_PID=$!

ready=false
for _ in $(seq 1 25); do
  if curl -sf --max-time 1 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__health" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.2
done
if [ "$ready" = true ]; then
  pass
else
  fail "mock receiver did not come up on 127.0.0.1:${WEBHOOK_RECEIVER_PORT}"
fi

DEFAULT_VERSION="2026-04-01"

# Helper: POST a webhook with optional event_schema_version, return id or empty
create_webhook_status() {
  local payload="$1"
  local body_file
  body_file=$(mktemp)
  local status
  status=$(curl -s -o "$body_file" -w '%{http_code}' --max-time 10 \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/webhooks" 2>/dev/null) || status="000"
  echo "${status}"
  cat "$body_file"
  rm -f "$body_file"
}

# -------------------------------------------------------------------------
# Sub-check 1: omit event_schema_version -> defaults to 2026-04-01.
# -------------------------------------------------------------------------

DEFAULT_HOOK_ID=""

begin_test "Create webhook WITHOUT event_schema_version"
if [ "$ready" != "true" ]; then
  skip "receiver not running"
else
  PAYLOAD=$(jq -n \
    --arg name "ver-default-${RUN_ID}" \
    --arg url "$WEBHOOK_RECEIVER_URL" \
    '{name: $name, url: $url, events: ["artifact.uploaded"], enabled: true}')
  resp=$(create_webhook_status "$PAYLOAD")
  status=$(echo "$resp" | head -n 1)
  body=$(echo "$resp" | tail -n +2)
  if [ "$status" = "200" ] || [ "$status" = "201" ]; then
    DEFAULT_HOOK_ID=$(echo "$body" | jq -r '.id // empty')
    if [ -n "$DEFAULT_HOOK_ID" ] && [ "$DEFAULT_HOOK_ID" != "null" ]; then
      pass
    else
      fail "create returned no id (status ${status}, body: ${body:0:200})"
    fi
  else
    fail "expected 200/201 creating webhook without version, got ${status}: ${body:0:200}"
  fi
fi

begin_test "GET returns event_schema_version=${DEFAULT_VERSION}"
if [ -z "$DEFAULT_HOOK_ID" ]; then
  skip "no webhook id"
else
  if hook=$(api_get "/api/v1/webhooks/${DEFAULT_HOOK_ID}" 2>/dev/null); then
    ver=$(echo "$hook" | jq -r '.event_schema_version // empty')
    if [ "$ver" = "$DEFAULT_VERSION" ]; then
      pass
    else
      fail "expected event_schema_version='${DEFAULT_VERSION}', got '${ver}' (raw: ${hook:0:200})"
    fi
  else
    fail "could not GET webhook ${DEFAULT_HOOK_ID}"
  fi
fi

begin_test "Delivery carries X-ArtifactKeeper-Event-Version: ${DEFAULT_VERSION}"
if [ -z "$DEFAULT_HOOK_ID" ]; then
  skip "no webhook id"
else
  curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__reset" >/dev/null 2>&1 || true
  if api_post "/api/v1/webhooks/${DEFAULT_HOOK_ID}/test" "" >/dev/null 2>&1; then
    seen=0
    for _ in $(seq 1 20); do
      seen=$(curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__count" 2>/dev/null || echo 0)
      [ "$seen" -gt 0 ] && break
      sleep 0.5
    done
    if [ "$seen" -ge 1 ] && [ -s "$WEBHOOK_RECEIVER_LOG" ]; then
      headers=$(tail -n 1 "$WEBHOOK_RECEIVER_LOG" | jq -r '.headers')
      ver=$(echo "$headers" | jq -r '
        (.["X-ArtifactKeeper-Event-Version"] //
         .["x-artifactkeeper-event-version"] //
         .["X-ARTIFACTKEEPER-EVENT-VERSION"] // empty)
      ')
      if [ "$ver" = "$DEFAULT_VERSION" ]; then
        pass
      else
        fail "expected header version '${DEFAULT_VERSION}', got '${ver}'"
      fi
    else
      fail "no POST recorded at receiver after /test"
    fi
  else
    skip "/test endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# Sub-check 2: explicit "2026-04-01" works the same.
# -------------------------------------------------------------------------

EXPLICIT_HOOK_ID=""

begin_test "Create webhook WITH explicit event_schema_version=${DEFAULT_VERSION}"
if [ "$ready" != "true" ]; then
  skip "receiver not running"
else
  PAYLOAD=$(jq -n \
    --arg name "ver-explicit-${RUN_ID}" \
    --arg url "$WEBHOOK_RECEIVER_URL" \
    --arg ver "$DEFAULT_VERSION" \
    '{name: $name, url: $url, events: ["artifact.uploaded"], enabled: true, event_schema_version: $ver}')
  resp=$(create_webhook_status "$PAYLOAD")
  status=$(echo "$resp" | head -n 1)
  body=$(echo "$resp" | tail -n +2)
  if [ "$status" = "200" ] || [ "$status" = "201" ]; then
    EXPLICIT_HOOK_ID=$(echo "$body" | jq -r '.id // empty')
    if [ -n "$EXPLICIT_HOOK_ID" ] && [ "$EXPLICIT_HOOK_ID" != "null" ]; then
      pass
    else
      fail "create returned no id (status ${status}, body: ${body:0:200})"
    fi
  else
    fail "expected 200/201 creating webhook with explicit version, got ${status}: ${body:0:200}"
  fi
fi

begin_test "Explicit-version webhook delivery carries the same header"
if [ -z "$EXPLICIT_HOOK_ID" ]; then
  skip "no webhook id"
else
  curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__reset" >/dev/null 2>&1 || true
  if api_post "/api/v1/webhooks/${EXPLICIT_HOOK_ID}/test" "" >/dev/null 2>&1; then
    seen=0
    for _ in $(seq 1 20); do
      seen=$(curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__count" 2>/dev/null || echo 0)
      [ "$seen" -gt 0 ] && break
      sleep 0.5
    done
    if [ "$seen" -ge 1 ] && [ -s "$WEBHOOK_RECEIVER_LOG" ]; then
      headers=$(tail -n 1 "$WEBHOOK_RECEIVER_LOG" | jq -r '.headers')
      ver=$(echo "$headers" | jq -r '
        (.["X-ArtifactKeeper-Event-Version"] //
         .["x-artifactkeeper-event-version"] //
         .["X-ARTIFACTKEEPER-EVENT-VERSION"] // empty)
      ')
      if [ "$ver" = "$DEFAULT_VERSION" ]; then
        pass
      else
        fail "expected header version '${DEFAULT_VERSION}', got '${ver}'"
      fi
    else
      fail "no POST recorded at receiver after /test"
    fi
  else
    skip "/test endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# Sub-check 3: bogus version -> 400, body mentions "supported".
# -------------------------------------------------------------------------

begin_test "Create webhook with unsupported version returns 400"
PAYLOAD=$(jq -n \
  --arg name "ver-bad-${RUN_ID}" \
  --arg url "$WEBHOOK_RECEIVER_URL" \
  '{name: $name, url: $url, events: ["artifact.uploaded"], enabled: true, event_schema_version: "9999-99-99"}')
resp=$(create_webhook_status "$PAYLOAD")
status=$(echo "$resp" | head -n 1)
body=$(echo "$resp" | tail -n +2)
if [ "$status" = "400" ]; then
  pass
else
  fail "expected 400 for unsupported version, got ${status}: ${body:0:200}"
fi

begin_test "Unsupported-version error body mentions 'supported'"
# Reuse the response from the previous test by re-sending; resp variables
# above are local to that test's scope effectively (bash variables leak,
# but we re-issue to be defensive against retries).
resp=$(create_webhook_status "$PAYLOAD")
body=$(echo "$resp" | tail -n +2)
# Case-insensitive grep for "supported" so backends can word the message
# either as "unsupported version" or "supported versions: ...".
if echo "$body" | grep -qi 'supported'; then
  pass
else
  fail "error body did not mention 'supported': ${body:0:300}"
fi

# Cleanup
for hid in "$DEFAULT_HOOK_ID" "$EXPLICIT_HOOK_ID"; do
  if [ -n "$hid" ] && [ "$hid" != "null" ]; then
    api_delete "/api/v1/webhooks/${hid}" >/dev/null 2>&1 || true
  fi
done

end_suite
