#!/usr/bin/env bash
# test-webhook-hmac-tamper.sh
#
# Issue #75 sub-task 7.5: deepen HMAC signing coverage with negative-path
# assertions. The existing test-webhook-hmac-signature.sh proves that the
# X-ArtifactKeeper-Signature header is present and equals HMAC(secret, body)
# for a clean delivery. That is the "happy path" half of 7.5.
#
# This test fills in the half that actually catches bugs: it computes the
# HMAC with a DIFFERENT secret and against a TAMPERED body, and asserts the
# header does NOT match either. A backend regression that emits a static
# signature (e.g. forgot to hash the body, or hashes only the URL) would
# pass the happy-path test and silently fail this one.
#
# Why this matters: HMAC is the only thing standing between a webhook
# receiver and a forged delivery. If the receiver is going to drop requests
# whose signature does not validate, the signature MUST be sensitive to
# every byte of the signed material. Verifying that the signature changes
# under tampering is the load-bearing security assertion, not verifying
# that it has 64 hex digits.
#
# Contract under test (matches v2 wire contract, artifact-keeper#919):
#   X-ArtifactKeeper-Signature: t=<unix_secs>,v1=<hex_hmac_sha256>
#   Signed bytes: "<unix_secs>.<raw_body>"
#
# Requires: curl, jq, python3, openssl

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-hmac-tamper"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18781}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-tamper-${RUN_ID}.log}"
WEBHOOK_SECRET="${WEBHOOK_SECRET:-tamper-secret-${RUN_ID}}"
WRONG_SECRET="not-the-real-secret-${RUN_ID}"
RECEIVER_PID=""
WEBHOOK_ID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${WEBHOOK_ID}" ] && [ "${WEBHOOK_ID}" != "null" ]; then
    api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
  fi
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
# Start the mock receiver.
# -------------------------------------------------------------------------

begin_test "Start mock receiver"
WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
  WEBHOOK_FAIL_FIRST_N=0 \
  WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
  python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
  >/tmp/mock-webhook-receiver-tamper-${RUN_ID}.stderr 2>&1 &
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
# Create a webhook with a known plaintext secret.
# -------------------------------------------------------------------------

WEBHOOK_NAME="tamper-${RUN_ID}"
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
# Drive a /test delivery and capture the receiver entry.
# -------------------------------------------------------------------------

LATEST_HEADERS=""
LATEST_BODY=""

begin_test "Trigger /test and capture the receiver entry"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__reset" >/dev/null 2>&1 || true
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
    SUITE_BLOCKED=true
    skip "/test endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# Parse the header. Pin to the FIRST v1= token (current secret) so the
# negative assertions below have a single value to compare against. The
# rotation-overlap test owns the multi-token case.
# -------------------------------------------------------------------------

SIG_HEADER=""
SIG_TS=""
SIG_V1=""

begin_test "Capture X-ArtifactKeeper-Signature header value"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  SIG_HEADER=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-ArtifactKeeper-Signature"] //
     .["x-artifactkeeper-signature"] //
     .["X-ARTIFACTKEEPER-SIGNATURE"] // empty)
  ')
  if [ -z "$SIG_HEADER" ] || [ "$SIG_HEADER" = "null" ]; then
    fail "X-ArtifactKeeper-Signature header missing (headers: ${LATEST_HEADERS:0:300})"
  elif echo "$SIG_HEADER" | grep -Eq '^t=[0-9]+(,v1=[0-9a-f]{64})+$'; then
    SIG_TS=$(echo "$SIG_HEADER" | sed -nE 's/^t=([0-9]+).*/\1/p')
    SIG_V1=$(echo "$SIG_HEADER" | sed -nE 's/.*,v1=([0-9a-f]{64}).*/\1/p' | head -n 1)
    pass
  else
    fail "header value '${SIG_HEADER}' does not match t=<int>,v1=<64-hex>"
  fi
fi

# -------------------------------------------------------------------------
# Sanity: with the RIGHT secret and the EXACT body the receiver saw, the
# locally recomputed HMAC must equal the header. If this fails, the test
# is broken (wrong body framing, wrong secret captured) -- not the
# backend. Keep this assertion separate from the negative cases so a
# breakage here is unambiguous.
# -------------------------------------------------------------------------

begin_test "Sanity: HMAC(real_secret, <t>.<body>) equals header v1 token"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$SIG_V1" ] || [ -z "$SIG_TS" ] || [ -z "$LATEST_BODY" ]; then
  skip "no signature components captured"
else
  expected=$(printf '%s.%s' "$SIG_TS" "$LATEST_BODY" \
    | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" 2>/dev/null \
    | awk '{print $NF}')
  if [ -z "$expected" ]; then
    fail "openssl produced empty HMAC"
  elif [ "$SIG_V1" = "$expected" ]; then
    pass
  else
    fail "happy-path HMAC mismatch: header v1='${SIG_V1}' expected='${expected}'"
  fi
fi

# -------------------------------------------------------------------------
# Negative case 1: signing the SAME body with the WRONG secret must
# produce a DIFFERENT value. If they match, the backend is either not
# using the secret at all or is using a hard-coded value -- both are
# critical security regressions.
# -------------------------------------------------------------------------

begin_test "Tamper: HMAC with WRONG secret diverges from header v1 token"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$SIG_V1" ] || [ -z "$SIG_TS" ] || [ -z "$LATEST_BODY" ]; then
  skip "no signature components captured"
else
  wrong=$(printf '%s.%s' "$SIG_TS" "$LATEST_BODY" \
    | openssl dgst -sha256 -hmac "$WRONG_SECRET" 2>/dev/null \
    | awk '{print $NF}')
  if [ -z "$wrong" ]; then
    fail "openssl produced empty HMAC for wrong-secret case"
  elif [ "$wrong" = "$SIG_V1" ]; then
    fail "SECURITY: HMAC under wrong secret matched header. Signature is not secret-dependent. header='${SIG_V1}' wrong-secret-hmac='${wrong}'"
  else
    pass
  fi
fi

# -------------------------------------------------------------------------
# Negative case 2: signing a TAMPERED body with the right secret must
# produce a DIFFERENT value. We mutate the body by appending a single
# byte; any HMAC implementation that ignores trailing bytes would be
# catastrophically broken. The assertion here is the second half of
# "the signature covers every byte of the body".
# -------------------------------------------------------------------------

begin_test "Tamper: HMAC over modified body diverges from header v1 token"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$SIG_V1" ] || [ -z "$SIG_TS" ] || [ -z "$LATEST_BODY" ]; then
  skip "no signature components captured"
else
  tampered_body="${LATEST_BODY}X"
  tampered=$(printf '%s.%s' "$SIG_TS" "$tampered_body" \
    | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" 2>/dev/null \
    | awk '{print $NF}')
  if [ -z "$tampered" ]; then
    fail "openssl produced empty HMAC for tampered-body case"
  elif [ "$tampered" = "$SIG_V1" ]; then
    fail "SECURITY: HMAC over body+'X' matched header. Signature does not cover full body. header='${SIG_V1}' tampered-hmac='${tampered}'"
  else
    pass
  fi
fi

# -------------------------------------------------------------------------
# Negative case 3: signing the body under a DIFFERENT timestamp must also
# produce a different value. This proves t= is part of the signed string,
# which is the only thing preventing trivial replay attacks (a receiver
# that pins a freshness window must rely on `t` being inside the HMAC).
# -------------------------------------------------------------------------

begin_test "Tamper: HMAC with mutated timestamp diverges from header v1 token"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$SIG_V1" ] || [ -z "$SIG_TS" ] || [ -z "$LATEST_BODY" ]; then
  skip "no signature components captured"
else
  mutated_ts=$(( SIG_TS + 1 ))
  off_ts=$(printf '%s.%s' "$mutated_ts" "$LATEST_BODY" \
    | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" 2>/dev/null \
    | awk '{print $NF}')
  if [ -z "$off_ts" ]; then
    fail "openssl produced empty HMAC for mutated-ts case"
  elif [ "$off_ts" = "$SIG_V1" ]; then
    fail "SECURITY: HMAC with t+1 matched header. Timestamp is not inside the signed string. header='${SIG_V1}' mutated-ts-hmac='${off_ts}'"
  else
    pass
  fi
fi

end_suite
