#!/usr/bin/env bash
# test-webhook-replay-window.sh
#
# Webhooks v2 wire contract (artifact-keeper#919, E2): receivers MUST reject
# deliveries whose timestamp falls outside the replay window (default 300s).
#
# Why this is structured as an offline-verifier test:
#   The backend always signs `t=now` at delivery time; we cannot push a
#   stale timestamp through the live producer path without backdating the
#   server clock, which is not a thing the harness can do safely. Instead
#   we capture a real signed delivery (header + body) into a file and then
#   run a small inline python3 verifier that mirrors the contract's sample
#   verification logic. The verifier returns 401 when |t - now| > window
#   even though the HMAC itself is valid.
#
# Receiver discovery: WEBHOOK_RECEIVER_PORT (default in 18000-19000 range).
#
# Companion backend PR: artifact-keeper#1140.
#
# Requires: curl, jq, python3, openssl

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-replay-window"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18769}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://${WEBHOOK_RECEIVER_HOST:-127.0.0.1}:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-replay-${RUN_ID}.log}"
WEBHOOK_SECRET="${WEBHOOK_SECRET:-replay-${RUN_ID}}"
REPLAY_WINDOW_SECS="${REPLAY_WINDOW_SECS:-300}"
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
# Capture a real delivery: spin up the mock receiver, create a webhook
# with a known plaintext secret, fire /test, and snapshot the request.
# -------------------------------------------------------------------------

begin_test "Start mock receiver"
WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
  WEBHOOK_FAIL_FIRST_N=0 \
  WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
  python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
  >/tmp/mock-webhook-receiver-replay-${RUN_ID}.stderr 2>&1 &
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

WEBHOOK_NAME="replay-${RUN_ID}"
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

LATEST_HEADERS=""
LATEST_BODY=""
SIG_HEADER=""

begin_test "Capture a real signed delivery"
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
        fail "no X-ArtifactKeeper-Signature header on captured delivery"
      fi
    else
      fail "no POST recorded at receiver after /test"
    fi
  else
    skip "/test endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# Verifier sub-tests. The python3 helper below mirrors the docs sample:
# parse the header, check |t - now| <= window, recompute HMAC, accept or
# reject.
# -------------------------------------------------------------------------

VERIFIER_PY=$(cat <<'PYEOF'
import hashlib
import hmac
import os
import sys
import time

secret = os.environ["VERIFY_SECRET"].encode()
window = int(os.environ.get("VERIFY_WINDOW", "300"))
now = int(os.environ.get("VERIFY_NOW", str(int(time.time()))))
sig_header = os.environ["VERIFY_SIG"]
body = os.environ["VERIFY_BODY"].encode()

ts = None
v1_tokens = []
for part in sig_header.split(","):
    part = part.strip()
    if part.startswith("t="):
        try:
            ts = int(part[2:])
        except ValueError:
            print("malformed t=", file=sys.stderr)
            sys.exit(1)
    elif part.startswith("v1="):
        v1_tokens.append(part[3:])

if ts is None or not v1_tokens:
    print("missing t= or v1=", file=sys.stderr)
    sys.exit(1)

if abs(now - ts) > window:
    print(f"replay rejected: |now-t|={abs(now-ts)} > window={window}", file=sys.stderr)
    sys.exit(2)

signed = f"{ts}.".encode() + body
expected = hmac.new(secret, signed, hashlib.sha256).hexdigest()
if any(hmac.compare_digest(expected, tok) for tok in v1_tokens):
    print("ok")
    sys.exit(0)

print("hmac mismatch", file=sys.stderr)
sys.exit(3)
PYEOF
)

# -------------------------------------------------------------------------
# Sub-test 1: replay the captured delivery as-is (now ~= t). Verifier must
# accept (exit 0). This proves the verifier itself works.
# -------------------------------------------------------------------------

begin_test "Verifier ACCEPTS a fresh delivery (within replay window)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$SIG_HEADER" ]; then
  skip "no captured signature"
else
  if VERIFY_SECRET="$WEBHOOK_SECRET" \
     VERIFY_WINDOW="$REPLAY_WINDOW_SECS" \
     VERIFY_SIG="$SIG_HEADER" \
     VERIFY_BODY="$LATEST_BODY" \
     python3 -c "$VERIFIER_PY" >/dev/null 2>/tmp/replay-verify-fresh-${RUN_ID}.err; then
    pass
  else
    err=$(cat /tmp/replay-verify-fresh-${RUN_ID}.err 2>/dev/null || true)
    fail "fresh delivery should verify but verifier rejected: ${err}"
  fi
  rm -f /tmp/replay-verify-fresh-${RUN_ID}.err
fi

# -------------------------------------------------------------------------
# Sub-test 2: simulate a stale delivery by passing VERIFY_NOW pushed ahead
# of the embedded t= by (window + 60) seconds. The HMAC remains valid for
# the original t but the timestamp window check must reject. Verifier exit
# code 2 = replay rejected.
# -------------------------------------------------------------------------

begin_test "Verifier REJECTS a delivery outside the replay window (exit 2)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$SIG_HEADER" ]; then
  skip "no captured signature"
else
  ts=$(echo "$SIG_HEADER" | sed -nE 's/^t=([0-9]+).*/\1/p')
  if [ -z "$ts" ]; then
    fail "could not parse t= from signature header '${SIG_HEADER}'"
  else
    fake_now=$(( ts + REPLAY_WINDOW_SECS + 60 ))
    set +e
    VERIFY_SECRET="$WEBHOOK_SECRET" \
      VERIFY_WINDOW="$REPLAY_WINDOW_SECS" \
      VERIFY_NOW="$fake_now" \
      VERIFY_SIG="$SIG_HEADER" \
      VERIFY_BODY="$LATEST_BODY" \
      python3 -c "$VERIFIER_PY" >/dev/null 2>/tmp/replay-verify-stale-${RUN_ID}.err
    rc=$?
    set -e
    if [ "$rc" = "2" ]; then
      pass
    else
      err=$(cat /tmp/replay-verify-stale-${RUN_ID}.err 2>/dev/null || true)
      fail "expected verifier exit 2 (replay rejected), got ${rc}: ${err}"
    fi
    rm -f /tmp/replay-verify-stale-${RUN_ID}.err
  fi
fi

# -------------------------------------------------------------------------
# Sub-test 3: tampered body must fail HMAC even within the window
# (verifier exit 3 = hmac mismatch). Sanity check that the verifier is
# not just rubber-stamping anything.
# -------------------------------------------------------------------------

begin_test "Verifier REJECTS a tampered body within the replay window (exit 3)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$SIG_HEADER" ]; then
  skip "no captured signature"
else
  tampered_body="${LATEST_BODY}<tampered>"
  set +e
  VERIFY_SECRET="$WEBHOOK_SECRET" \
    VERIFY_WINDOW="$REPLAY_WINDOW_SECS" \
    VERIFY_SIG="$SIG_HEADER" \
    VERIFY_BODY="$tampered_body" \
    python3 -c "$VERIFIER_PY" >/dev/null 2>/tmp/replay-verify-tamper-${RUN_ID}.err
  rc=$?
  set -e
  if [ "$rc" = "3" ]; then
    pass
  else
    err=$(cat /tmp/replay-verify-tamper-${RUN_ID}.err 2>/dev/null || true)
    fail "expected verifier exit 3 (hmac mismatch), got ${rc}: ${err}"
  fi
  rm -f /tmp/replay-verify-tamper-${RUN_ID}.err
fi

if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
  api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
fi

end_suite
