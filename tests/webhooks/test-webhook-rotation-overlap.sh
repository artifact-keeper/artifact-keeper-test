#!/usr/bin/env bash
# test-webhook-rotation-overlap.sh
#
# Webhooks v2 wire contract (artifact-keeper#919, E2): during the 24h secret
# rotation overlap window the X-ArtifactKeeper-Signature header carries TWO
# v1= tokens (current, previous) so receivers that have not yet rotated keys
# can still validate.
#
# Test plan:
#   1. Create webhook with secret S0.
#   2. POST /api/v1/webhooks/<id>/rotate-secret as an admin. The response
#      carries the new secret S1 exactly once, marked Cache-Control: no-store,
#      with a new secret_digest and the previous_secret_expires_at window
#      (artifact-keeper#5235). A later GET or LIST of the webhook must not
#      return S1 (GHSA-qcmj, artifact-keeper#2818). S1 is a secret: no message
#      in this suite prints the rotate response.
#   3. Fire /test (or wait for a producer-driven delivery) and capture the
#      receiver entry.
#   4. Assert the X-ArtifactKeeper-Signature header has exactly two v1=
#      tokens.
#   5. The first token equals HMAC(S1, t.body), the current secret, and the
#      second equals HMAC(S0, t.body), the previous secret.
#
# Companion backend PR: artifact-keeper#1140.
#
# Requires: curl, jq, python3, openssl

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-rotation-overlap"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18770}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://$(webhook_receiver_host):${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-rot-${RUN_ID}.log}"
INITIAL_SECRET="${WEBHOOK_SECRET:-rot-initial-${RUN_ID}}"
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
# Pre-flight.
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
# Start mock receiver.
# -------------------------------------------------------------------------

begin_test "Start mock receiver"
WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
  WEBHOOK_FAIL_FIRST_N=0 \
  WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
  python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
  >/tmp/mock-webhook-receiver-rot-${RUN_ID}.stderr 2>&1 &
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
# Create webhook with initial secret S0.
# -------------------------------------------------------------------------

WEBHOOK_NAME="rotation-${RUN_ID}"
WEBHOOK_ID=""
SUITE_BLOCKED=false

begin_test "Create webhook with initial secret"
if [ "$ready" != "true" ]; then
  skip "receiver not running"
else
  PAYLOAD=$(jq -n \
    --arg name "$WEBHOOK_NAME" \
    --arg url "$WEBHOOK_RECEIVER_URL" \
    --arg secret "$INITIAL_SECRET" \
    '{name: $name, url: $url, secret: $secret, events: ["artifact_uploaded"], enabled: true}')
  create_signing_webhook "$PAYLOAD"
fi

# -------------------------------------------------------------------------
# Rotate the secret. The response carries:
#   { id: "<uuid>", secret: "whsec_...", secret_digest: "whsec_...abcd",
#     previous_secret_expires_at: "<rfc3339>" }
# and is the only place the new secret ever appears (artifact-keeper#5235).
# Do not print the response body or headers from here on.
# -------------------------------------------------------------------------

ROTATED=false
PREV_EXPIRES_AT=""
ROTATED_SECRET=""

begin_test "POST /rotate-secret returns the new secret once, no-store, with a new digest + previous_secret_expires_at"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  OLD_DIGEST=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}" 2>/dev/null | jq -r '.secret_digest // empty')
  rot_body=$(mktemp)
  rot_headers=$(mktemp)
  rot_status=$(curl -s $CURL_TIMEOUT -o "$rot_body" -D "$rot_headers" -w '%{http_code}' -X POST \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/webhooks/${WEBHOOK_ID}/rotate-secret") || rot_status="000"
  case "$rot_status" in
    2*)
      ROTATED_SECRET=$(jq -r '.secret // empty' "$rot_body" 2>/dev/null)
      NEW_DIGEST=$(jq -r '.secret_digest // empty' "$rot_body" 2>/dev/null)
      PREV_EXPIRES_AT=$(jq -r '.previous_secret_expires_at // empty' "$rot_body" 2>/dev/null)
      rot_cache=$(tr -d '\r' < "$rot_headers" | sed -nE 's/^[Cc]ache-[Cc]ontrol:[[:space:]]*//p' | tail -n 1)
      if [ -z "$ROTATED_SECRET" ]; then
        fail "rotate-secret response carries no .secret, so a receiver cannot verify after the overlap ends (artifact-keeper#5235)"
      elif [ "$ROTATED_SECRET" = "$INITIAL_SECRET" ]; then
        fail "rotate-secret returned the previous secret, not a new one"
      elif [ "$rot_cache" != "no-store" ]; then
        fail "rotate-secret response must be Cache-Control: no-store, got '${rot_cache}'"
      elif [ -z "$NEW_DIGEST" ] || [ -z "$OLD_DIGEST" ] || [ "$NEW_DIGEST" = "$OLD_DIGEST" ]; then
        fail "secret_digest did not change across the rotation: before='${OLD_DIGEST}' after='${NEW_DIGEST}'"
      elif [ -z "$PREV_EXPIRES_AT" ]; then
        fail "rotate-secret response missing .previous_secret_expires_at"
      else
        ROTATED=true
        pass
      fi
      ;;
    *)
      SUITE_BLOCKED=true
      if [ "${RELEASE_GATE:-0}" = "1" ]; then
        fail "/rotate-secret returned HTTP ${rot_status}, so the overlap window cannot be checked"
      else
        skip "/rotate-secret endpoint unavailable (HTTP ${rot_status})"
      fi
      ;;
  esac
  rm -f "$rot_body" "$rot_headers"
fi

begin_test "GET and LIST of the webhook never return the rotated secret"
if [ "$ROTATED" != "true" ]; then
  skip "rotation not performed"
else
  read_one=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}" 2>/dev/null) || read_one=""
  read_all=$(api_get "/api/v1/webhooks?per_page=1000" 2>/dev/null) || read_all=""
  if [ -z "$read_one" ] || [ -z "$read_all" ]; then
    fail "could not read the webhook back"
  elif printf '%s%s' "$read_one" "$read_all" | grep -qF "$ROTATED_SECRET"; then
    fail "a webhook read returned the rotated secret (GHSA-qcmj)"
  elif [ "$(echo "$read_one" | jq -r '.secret // empty')" != "" ]; then
    fail "GET /webhooks/<id> carries a .secret field"
  else
    pass
  fi
fi

# -------------------------------------------------------------------------
# Capture a delivery during the overlap window. Truncate the receiver log
# first so we read the post-rotation entry.
# -------------------------------------------------------------------------

LATEST_HEADERS=""
LATEST_BODY=""
SIG_HEADER=""

begin_test "Capture a delivery during the overlap window"
if [ "$SUITE_BLOCKED" = "true" ] || [ "$ROTATED" != "true" ]; then
  skip "rotation not performed"
else
  # Reset the receiver counter + log so we read fresh entries.
  curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__reset" >/dev/null 2>&1 || true

  if api_post "/api/v1/webhooks/${WEBHOOK_ID}/test" "" >/dev/null 2>&1; then
    seen=0
    for _ in $(seq 1 20); do
      seen=$(curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__count" 2>/dev/null || echo 0)
      [ "$seen" -gt 0 ] && break
      sleep 0.5
    done
    if [ "$seen" -ge 1 ] && [ -s "$WEBHOOK_RECEIVER_LOG" ]; then
      LATEST=$(tail -n 1 "$WEBHOOK_RECEIVER_LOG")
      LATEST_HEADERS=$(echo "$LATEST" | jq -r '.headers')
      LATEST_BODY=$(echo "$LATEST" | jq -r '.body')
      SIG_HEADER=$(echo "$LATEST_HEADERS" | jq -r '
        (.["X-ArtifactKeeper-Signature"] //
         .["x-artifactkeeper-signature"] //
         .["X-ARTIFACTKEEPER-SIGNATURE"] // empty)
      ')
      if [ -n "$SIG_HEADER" ] && [ "$SIG_HEADER" != "null" ]; then
        pass
      else
        fail "captured delivery has no X-ArtifactKeeper-Signature header"
      fi
    else
      fail "no POST recorded after /test during overlap"
    fi
  else
    skip "/test endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# Assert TWO v1= tokens.
# -------------------------------------------------------------------------

V1_TOKENS=()
SIG_TS=""

begin_test "X-ArtifactKeeper-Signature carries exactly two v1= tokens"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$SIG_HEADER" ]; then
  skip "no captured signature"
else
  SIG_TS=$(echo "$SIG_HEADER" | sed -nE 's/^t=([0-9]+).*/\1/p')
  # Extract every v1=<64-hex> token.
  mapfile -t V1_TOKENS < <(echo "$SIG_HEADER" | grep -Eo 'v1=[0-9a-f]{64}' | sed 's/^v1=//')
  count="${#V1_TOKENS[@]}"
  if [ -z "$SIG_TS" ]; then
    fail "could not parse t= from header '${SIG_HEADER}'"
  elif [ "$count" -eq 2 ]; then
    pass
  else
    fail "expected 2 v1= tokens during overlap, got ${count} (header: ${SIG_HEADER})"
  fi
fi

# -------------------------------------------------------------------------
# The tokens are ordered current-first. Each must validate against its own
# secret: the first against the one the rotation returned, so a receiver that
# has rotated verifies, and the second against the previous one, so a receiver
# that has not yet rotated keeps verifying.
# -------------------------------------------------------------------------

begin_test "First v1= token validates against the current secret, second against the previous"
if [ "$SUITE_BLOCKED" = "true" ] || [ "${#V1_TOKENS[@]}" -ne 2 ] || [ -z "$SIG_TS" ] || [ -z "$ROTATED_SECRET" ]; then
  skip "no token pair to validate"
else
  expect_cur=$(printf '%s.%s' "$SIG_TS" "$LATEST_BODY" \
    | openssl dgst -sha256 -hmac "$ROTATED_SECRET" 2>/dev/null \
    | awk '{print $NF}')
  expect_prev=$(printf '%s.%s' "$SIG_TS" "$LATEST_BODY" \
    | openssl dgst -sha256 -hmac "$INITIAL_SECRET" 2>/dev/null \
    | awk '{print $NF}')

  if [ -z "$expect_cur" ] || [ -z "$expect_prev" ]; then
    fail "openssl produced an empty HMAC"
  elif [ "${V1_TOKENS[0]}" != "$expect_cur" ]; then
    fail "first token is not HMAC(current secret, t.body): tokens=${V1_TOKENS[*]} expect_cur=${expect_cur}"
  elif [ "${V1_TOKENS[1]}" != "$expect_prev" ]; then
    fail "second token is not HMAC(previous secret, t.body): tokens=${V1_TOKENS[*]} expect_prev=${expect_prev}"
  else
    pass
  fi
fi

if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
  api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
fi

end_suite
