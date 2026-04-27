#!/usr/bin/env bash
# test-webhook-hmac-signature.sh
#
# Epic 7 / sub-task 7.5 (artifact-keeper-test#73): verify HMAC signature
# generation and X-Webhook-Signature header injection.
#
# Contract (per the security review for v1.1.9):
#   - When a webhook is created with a `secret`, every delivery POST must
#     include an `X-Webhook-Signature` header.
#   - The header value must be `sha256=<hex>` where <hex> is
#     HMAC-SHA256(secret, body).
#
# Implementation note: in v1.1.x, the backend (api/handlers/webhooks.rs)
# emits a placeholder string ("test-signature" for /test, "hmac-signature"
# for retry deliveries) instead of a real HMAC. This test asserts the real
# contract; on v1.1.x it will FAIL the signature-match assertion and PASS
# the header-presence assertion. The signature-match failure is the
# tracked bug (#73 sub-task 7.5).
#
# Receiver discovery: WEBHOOK_RECEIVER_URL / WEBHOOK_RECEIVER_PORT, same as
# the sibling tests. EXPECT_FAILURE=1 inverts the script exit code.
#
# Requires: curl, jq, python3, openssl

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-hmac-signature"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18767}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-hmac-${RUN_ID}.log}"
WEBHOOK_SECRET="${WEBHOOK_SECRET:-s3cret-${RUN_ID}}"
RECEIVER_PID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${RECEIVER_PID}" ] && kill -0 "${RECEIVER_PID}" 2>/dev/null; then
    kill "${RECEIVER_PID}" 2>/dev/null || true
    wait "${RECEIVER_PID}" 2>/dev/null || true
  fi
  rm -f "${WEBHOOK_RECEIVER_LOG}"
  if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
    if [ "$code" -eq 0 ]; then
      echo "ERROR: EXPECT_FAILURE=1 but suite passed" >&2
      exit 4
    else
      echo "Self-test PASSED: suite exited ${code} as expected"
      exit 0
    fi
  fi
  exit "$code"
}
trap cleanup_and_finalize EXIT

auth_admin

# -------------------------------------------------------------------------
# Pre-flight: required tools.
# -------------------------------------------------------------------------

begin_test "openssl and python3 available"
miss=""
command -v openssl >/dev/null 2>&1 || miss="${miss} openssl"
command -v python3  >/dev/null 2>&1 || miss="${miss} python3"
if [ -n "$miss" ]; then
  skip "missing tools:${miss}"
  end_suite
fi
pass

# -------------------------------------------------------------------------
# Start the mock receiver in always-200 mode (no failure simulation; we
# care about the request, not the response).
# -------------------------------------------------------------------------

begin_test "Start mock receiver"
WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
  WEBHOOK_FAIL_FIRST_N=0 \
  WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
  python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
  >/tmp/mock-webhook-receiver-hmac-${RUN_ID}.stderr 2>&1 &
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

# -------------------------------------------------------------------------
# Create a webhook WITH a secret. The backend hashes the secret on create
# (Argon2 -- see auth_service::hash_password), so we cannot extract it
# back. We use the plaintext secret we sent on the way in to compute the
# expected HMAC locally.
# -------------------------------------------------------------------------

WEBHOOK_NAME="hmac-${RUN_ID}"
WEBHOOK_ID=""
SUITE_BLOCKED=false

begin_test "Create webhook with shared secret"
if [ "$ready" != "true" ]; then
  skip "receiver not running"
else
  PAYLOAD=$(jq -n \
    --arg name "$WEBHOOK_NAME" \
    --arg url "$WEBHOOK_RECEIVER_URL" \
    --arg secret "$WEBHOOK_SECRET" \
    '{name: $name, url: $url, secret: $secret, events: ["artifact.uploaded"], enabled: true}')
  if resp=$(api_post "/api/v1/webhooks" "$PAYLOAD" 2>/dev/null); then
    WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty')
    if [ -z "$WEBHOOK_ID" ] || [ "$WEBHOOK_ID" = "null" ]; then
      fail "create returned no id"
    else
      pass
    fi
  else
    SUITE_BLOCKED=true
    skip "webhook create rejected (URL '${WEBHOOK_RECEIVER_URL}' likely blocked by SSRF allow-list)"
  fi
fi

# -------------------------------------------------------------------------
# Trigger /test, then read the most recent receiver log entry.
# -------------------------------------------------------------------------

LATEST_HEADERS=""
LATEST_BODY=""

begin_test "Trigger /test and capture the latest receiver entry"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  if api_post "/api/v1/webhooks/${WEBHOOK_ID}/test" "" >/dev/null 2>&1; then
    seen=0
    for _ in $(seq 1 20); do
      seen=$(curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__count" 2>/dev/null || echo 0)
      [ "$seen" -gt 0 ] && break
      sleep 0.5
    done
    if [ "$seen" -lt 1 ] || [ ! -s "$WEBHOOK_RECEIVER_LOG" ]; then
      fail "no POST recorded at receiver after /test"
    else
      LATEST=$(tail -n 1 "$WEBHOOK_RECEIVER_LOG")
      LATEST_HEADERS=$(echo "$LATEST" | jq -r '.headers')
      LATEST_BODY=$(echo "$LATEST" | jq -r '.body')
      pass
    fi
  else
    skip "/test endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# Header presence: X-Webhook-Signature must be set.
# -------------------------------------------------------------------------

SIGNATURE_HEADER=""

begin_test "X-Webhook-Signature header is present on the delivery"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  # Header lookup is case-insensitive: try common spellings.
  SIGNATURE_HEADER=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-Webhook-Signature"] // .["x-webhook-signature"] // .["X-WEBHOOK-SIGNATURE"] // empty)
  ')
  if [ -n "$SIGNATURE_HEADER" ] && [ "$SIGNATURE_HEADER" != "null" ]; then
    pass
  else
    fail "X-Webhook-Signature header missing (headers: ${LATEST_HEADERS:0:300})"
  fi
fi

# -------------------------------------------------------------------------
# Signature value: must equal sha256=<hex> where hex = HMAC-SHA256(secret, body).
# -------------------------------------------------------------------------

begin_test "X-Webhook-Signature equals HMAC-SHA256(secret, body)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$SIGNATURE_HEADER" ] || [ -z "$LATEST_BODY" ]; then
  skip "no signature or body"
else
  expected_hex=$(printf '%s' "$LATEST_BODY" \
    | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" 2>/dev/null \
    | awk '{print $NF}')

  if [ -z "$expected_hex" ]; then
    fail "openssl produced empty HMAC"
  else
    expected="sha256=${expected_hex}"
    # Some implementations emit the raw hex without the "sha256=" prefix.
    if [ "$SIGNATURE_HEADER" = "$expected" ] || [ "$SIGNATURE_HEADER" = "$expected_hex" ]; then
      pass
    else
      fail "signature mismatch: header='${SIGNATURE_HEADER}' expected='${expected}' (or '${expected_hex}'). v1.1.x is known to emit a placeholder; this assertion tracks the real-HMAC contract for v1.1.9."
    fi
  fi
fi

# -------------------------------------------------------------------------
# Sanity: the body should be valid JSON that includes the event field.
# -------------------------------------------------------------------------

begin_test "Delivery body is JSON with an event field"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_BODY" ]; then
  skip "no body captured"
else
  evt=$(echo "$LATEST_BODY" | jq -r '.event // empty' 2>/dev/null) || evt=""
  if [ -n "$evt" ]; then
    pass
  else
    fail "delivery body has no .event: ${LATEST_BODY:0:200}"
  fi
fi

if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
  api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
fi

end_suite
