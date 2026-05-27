#!/usr/bin/env bash
# test-webhook-hmac-signature.sh
#
# Webhooks v2 wire contract (artifact-keeper#919, E2 / E4): assert that the
# backend emits the new X-ArtifactKeeper-Signature header AND keeps emitting
# the legacy X-Webhook-Signature header alongside it for one release window
# (legacy form is removed in v1.3.0).
#
# Contract under test:
#   X-ArtifactKeeper-Signature: t=<unix_secs>,v1=<hex_hmac_sha256>
#                               (multi-value during 24h rotation:
#                                t=...,v1=<new>,v1=<old>)
#   Signed bytes: "<unix_secs>.<raw_body>"
#
#   X-Webhook-Signature (legacy): sha256=<hex_hmac_sha256>
#                                 Signed bytes: <raw_body> (no timestamp)
#
# Plus the supporting headers:
#   X-ArtifactKeeper-Delivery       UUID
#   X-ArtifactKeeper-Event          event type
#   X-ArtifactKeeper-Event-Version  schema version (default 2026-04-01)
#
# The companion backend PR (artifact-keeper#1140) finalizes this contract.
# This test is meant to land AFTER that backend change. Do not enable in
# release-gate until #1140 is merged.
#
# Receiver discovery: WEBHOOK_RECEIVER_PORT (default in the 18000-19000
# range, matches the sibling tests). The mock receiver runs locally on the
# test runner and the backend POSTs to it directly.
#
# Requires: curl, jq, python3, openssl

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-hmac-signature"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18767}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://${WEBHOOK_RECEIVER_HOST:-127.0.0.1}:${WEBHOOK_RECEIVER_PORT}/hook}"
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
  exit "$code"
}
trap cleanup_and_finalize EXIT

auth_admin

# -------------------------------------------------------------------------
# Pre-flight: required tools.
# -------------------------------------------------------------------------

begin_test "openssl, python3, and jq available"
miss=""
command -v openssl >/dev/null 2>&1 || miss="${miss} openssl"
command -v python3  >/dev/null 2>&1 || miss="${miss} python3"
command -v jq       >/dev/null 2>&1 || miss="${miss} jq"
if [ -n "$miss" ]; then
  skip "missing tools:${miss}"
  end_suite
fi
pass

# -------------------------------------------------------------------------
# Start the mock receiver in always-200 mode.
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
# Create a webhook WITH a secret. We use the plaintext secret we sent on
# the way in to compute the expected HMAC locally; the backend hashes the
# secret on storage, so we cannot read it back.
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
# X-ArtifactKeeper-Signature: presence + shape (t=<int>,v1=<hex64>).
# -------------------------------------------------------------------------

NEW_SIG_HEADER=""
NEW_SIG_TS=""
NEW_SIG_V1=""

begin_test "X-ArtifactKeeper-Signature is present and well-formed"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  NEW_SIG_HEADER=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-ArtifactKeeper-Signature"] //
     .["x-artifactkeeper-signature"] //
     .["X-ARTIFACTKEEPER-SIGNATURE"] // empty)
  ')
  if [ -z "$NEW_SIG_HEADER" ] || [ "$NEW_SIG_HEADER" = "null" ]; then
    fail "X-ArtifactKeeper-Signature header missing (headers: ${LATEST_HEADERS:0:300})"
  else
    # Shape: t=<digits>(,v1=<64-hex>)+
    if echo "$NEW_SIG_HEADER" | grep -Eq '^t=[0-9]+(,v1=[0-9a-f]{64})+$'; then
      NEW_SIG_TS=$(echo "$NEW_SIG_HEADER" | sed -nE 's/^t=([0-9]+).*/\1/p')
      # Take the FIRST v1 token (current secret, per render_header order).
      NEW_SIG_V1=$(echo "$NEW_SIG_HEADER" | sed -nE 's/.*,v1=([0-9a-f]{64}).*/\1/p' | head -n 1)
      pass
    else
      fail "header value '${NEW_SIG_HEADER}' does not match t=<int>,v1=<64-hex>[,v1=<64-hex>]"
    fi
  fi
fi

# -------------------------------------------------------------------------
# X-ArtifactKeeper-Signature: HMAC equality. Recompute over
# "<t>.<raw_body>" with the known plaintext secret.
# -------------------------------------------------------------------------

begin_test "X-ArtifactKeeper-Signature v1 token equals HMAC-SHA256(secret, <t>.<body>)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$NEW_SIG_V1" ] || [ -z "$NEW_SIG_TS" ] || [ -z "$LATEST_BODY" ]; then
  skip "no signature components captured"
else
  expected=$(printf '%s.%s' "$NEW_SIG_TS" "$LATEST_BODY" \
    | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" 2>/dev/null \
    | awk '{print $NF}')
  if [ -z "$expected" ]; then
    fail "openssl produced empty HMAC"
  elif [ "$NEW_SIG_V1" = "$expected" ]; then
    pass
  else
    fail "HMAC mismatch: header v1='${NEW_SIG_V1}' expected='${expected}' (signed bytes: '${NEW_SIG_TS}.<body>')"
  fi
fi

# -------------------------------------------------------------------------
# Legacy X-Webhook-Signature header presence + value. The legacy form is
# `sha256=<hex>` over the raw body (no timestamp, secret-only). Removed in
# v1.3.0 per the deprecation plan; still emitted in v1.2.0.
# -------------------------------------------------------------------------

LEGACY_SIG_HEADER=""

begin_test "Legacy X-Webhook-Signature header is still emitted"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  LEGACY_SIG_HEADER=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-Webhook-Signature"] //
     .["x-webhook-signature"] //
     .["X-WEBHOOK-SIGNATURE"] // empty)
  ')
  if [ -n "$LEGACY_SIG_HEADER" ] && [ "$LEGACY_SIG_HEADER" != "null" ]; then
    pass
  else
    fail "X-Webhook-Signature legacy header missing (still required in v1.2.0; removed in v1.3.0)"
  fi
fi

begin_test "Legacy X-Webhook-Signature equals sha256=HMAC(secret, body)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LEGACY_SIG_HEADER" ] || [ -z "$LATEST_BODY" ]; then
  skip "no legacy signature or body"
else
  expected_hex=$(printf '%s' "$LATEST_BODY" \
    | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" 2>/dev/null \
    | awk '{print $NF}')
  expected="sha256=${expected_hex}"
  if [ -z "$expected_hex" ]; then
    fail "openssl produced empty legacy HMAC"
  elif [ "$LEGACY_SIG_HEADER" = "$expected" ]; then
    pass
  else
    fail "legacy signature mismatch: header='${LEGACY_SIG_HEADER}' expected='${expected}'"
  fi
fi

# -------------------------------------------------------------------------
# Supporting headers: delivery UUID, event type, event version.
# -------------------------------------------------------------------------

begin_test "X-ArtifactKeeper-Delivery is a UUID"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  delivery=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-ArtifactKeeper-Delivery"] //
     .["x-artifactkeeper-delivery"] //
     .["X-ARTIFACTKEEPER-DELIVERY"] // empty)
  ')
  if [ -z "$delivery" ] || [ "$delivery" = "null" ]; then
    fail "X-ArtifactKeeper-Delivery header missing"
  elif echo "$delivery" | grep -Eiq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
    pass
  else
    fail "delivery '${delivery}' is not a UUID"
  fi
fi

begin_test "X-ArtifactKeeper-Event is non-empty"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  evt=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-ArtifactKeeper-Event"] //
     .["x-artifactkeeper-event"] //
     .["X-ARTIFACTKEEPER-EVENT"] // empty)
  ')
  if [ -n "$evt" ] && [ "$evt" != "null" ]; then
    pass
  else
    fail "X-ArtifactKeeper-Event header missing"
  fi
fi

begin_test "X-ArtifactKeeper-Event-Version defaults to 2026-04-01"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  ver=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-ArtifactKeeper-Event-Version"] //
     .["x-artifactkeeper-event-version"] //
     .["X-ARTIFACTKEEPER-EVENT-VERSION"] // empty)
  ')
  if [ "$ver" = "2026-04-01" ]; then
    pass
  else
    fail "expected event-version '2026-04-01', got '${ver}'"
  fi
fi

# -------------------------------------------------------------------------
# Sanity: body is JSON with an event field.
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
