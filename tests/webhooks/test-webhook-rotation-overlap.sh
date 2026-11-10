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
#   2. POST /api/v1/webhooks/<id>/rotate-secret. On 1.11.x the response
#      carries secret_digest and previous_secret_expires_at but never the
#      new plaintext secret S1 (GHSA-qcmj, artifact-keeper#2818). Returning
#      S1 once is artifact-keeper#5235, which ships in 1.12.0.
#   3. Fire /test (or wait for a producer-driven delivery) and capture the
#      receiver entry.
#   4. Assert the X-ArtifactKeeper-Signature header has exactly two v1=
#      tokens.
#   5. Recompute HMAC(S0, t.body); exactly one of the two tokens must match
#      it (in either order; the contract pins current-first but receivers
#      MUST tolerate either). S1 is not available on 1.11.x, so the
#      new-secret half of the check is skipped on this branch.
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
  require_or_fail "missing tools:${miss}"
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
  if api_post_capture "/api/v1/webhooks" "$PAYLOAD"; then
    WEBHOOK_ID=$(echo "$API_BODY" | jq -r '.id // empty')
    if [ -z "$WEBHOOK_ID" ] || [ "$WEBHOOK_ID" = "null" ]; then
      fail "create returned no id (HTTP ${API_STATUS})" "response body: ${API_BODY:0:1000}"
    else
      pass
    fi
  else
    SUITE_BLOCKED=true
    # The body says why. "webhook secret signing is not enabled on this
    # deployment" means the backend has no AK_WEBHOOK_SECRET_KEY
    # (artifact-keeper#5196); an SSRF rejection names the URL instead.
    require_or_fail "webhook create with a secret rejected: HTTP ${API_STATUS} for URL '${WEBHOOK_RECEIVER_URL}'" \
      "response body: ${API_BODY:0:1000}"
  fi
fi

# -------------------------------------------------------------------------
# Rotate the secret. On 1.11.x the response carries:
#   { id: "<uuid>", secret_digest: "<hex>",
#     previous_secret_expires_at: "<rfc3339>" }
# The new plaintext secret is deliberately withheld (GHSA-qcmj,
# artifact-keeper#2818). 1.12.0 returns it once as .secret
# (artifact-keeper#5235); release/1.11.x asserts the shipped 1.11 form.
# -------------------------------------------------------------------------

ROTATED=false
SECRET_DIGEST=""
PREV_EXPIRES_AT=""

begin_test "POST /rotate-secret returns secret_digest + previous_secret_expires_at"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  if api_post_capture "/api/v1/webhooks/${WEBHOOK_ID}/rotate-secret" ""; then
    rot_resp="$API_BODY"
    SECRET_DIGEST=$(echo "$rot_resp" | jq -r '.secret_digest // empty')
    PREV_EXPIRES_AT=$(echo "$rot_resp" | jq -r '.previous_secret_expires_at // empty')
    if [ -z "$SECRET_DIGEST" ] || [ "$SECRET_DIGEST" = "null" ]; then
      fail "rotate-secret response missing .secret_digest: ${rot_resp:0:200}"
    elif [ -z "$PREV_EXPIRES_AT" ] || [ "$PREV_EXPIRES_AT" = "null" ]; then
      fail "rotate-secret response missing .previous_secret_expires_at: ${rot_resp:0:200}"
    else
      ROTATED=true
      pass
    fi
  else
    SUITE_BLOCKED=true
    require_or_fail "POST /api/v1/webhooks/${WEBHOOK_ID}/rotate-secret failed: HTTP ${API_STATUS}" \
      "response body: ${API_BODY:0:1000}"
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

  if api_post_capture "/api/v1/webhooks/${WEBHOOK_ID}/test" ""; then
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
    require_or_fail "POST /api/v1/webhooks/${WEBHOOK_ID}/test failed: HTTP ${API_STATUS}" \
      "response body: ${API_BODY:0:1000}"
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
# Exactly one token must validate against the previous (initial) secret.
# The contract pins current-first, but tests accept either order. The other
# token is the new secret's HMAC; 1.11.x never hands the new raw secret back
# (artifact-keeper#5235 adds that in 1.12.0), so that half is not checked on
# this branch.
# -------------------------------------------------------------------------

begin_test "One v1= token validates against the previous secret"
if [ "$SUITE_BLOCKED" = "true" ] || [ "${#V1_TOKENS[@]}" -ne 2 ] || [ -z "$SIG_TS" ]; then
  skip "no token pair to validate"
else
  hmac_with() {
    printf '%s.%s' "$SIG_TS" "$LATEST_BODY" \
      | openssl dgst -sha256 -hmac "$1" 2>/dev/null \
      | awk '{print $NF}'
  }
  expect_prev=$(hmac_with "$INITIAL_SECRET")

  matched_prev=0
  for tok in "${V1_TOKENS[@]}"; do
    [ "$tok" = "$expect_prev" ] && matched_prev=$((matched_prev + 1))
  done

  if [ -z "$expect_prev" ]; then
    fail "openssl produced empty HMAC"
  elif [ "$matched_prev" -eq 1 ]; then
    pass
  else
    fail "expected exactly one token to match the previous secret, matched ${matched_prev} (tokens: ${V1_TOKENS[*]}, expect_prev=${expect_prev})"
  fi
fi

if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
  api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
fi

end_suite
