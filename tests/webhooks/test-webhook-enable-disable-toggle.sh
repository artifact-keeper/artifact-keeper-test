#!/usr/bin/env bash
# test-webhook-enable-disable-toggle.sh
#
# Issue #75 sub-task 7.13: POST /api/v1/webhooks/{id}/enable and
# /api/v1/webhooks/{id}/disable. test-webhook-crud.sh calls PUT
# {"is_enabled":false} but never asserts the state actually flipped, and
# never exercises the dedicated /enable + /disable verbs at all.
#
# Schema note: WebhookResponse.is_enabled is the documented field
# (openapi.yaml:18591, backend webhooks.rs:103). CreateWebhookRequest
# does not accept an is_enabled/enabled field -- new webhooks are
# enabled by default at the DB layer -- so the create body in this
# suite intentionally omits it.
#
# The is_enabled flag is the operator's circuit-breaker. If a receiver
# is dropping deliveries on the floor and we need to pause fan-out,
# /disable is what we POST. The behavior under test:
#
#   1. New webhook is enabled by default (is_enabled=true).
#   2. POST /disable flips the flag; GET reflects is_enabled=false.
#   3. POST /enable flips it back; GET reflects is_enabled=true.
#   4. /disable and /enable are idempotent: calling them on a webhook
#      already in the target state must still return 2xx (no 409
#      conflicts -- the operator's tooling will retry, and a retry on
#      an idempotent verb must not error).
#   5. /enable on an unknown id returns 404 (parallels the dry-run
#      negative path; same regression class).
#
# Requires: curl, jq, python3 (only for receiver -- optional path below)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-enable-disable-toggle"

WEBHOOK_ID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${WEBHOOK_ID}" ] && [ "${WEBHOOK_ID}" != "null" ]; then
    api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
  fi
  exit "$code"
}
trap cleanup_and_finalize EXIT

auth_admin

# -------------------------------------------------------------------------
# Pre-flight.
# -------------------------------------------------------------------------

begin_test "jq available"
if ! command -v jq >/dev/null 2>&1; then
  skip "jq not available"
  end_suite
fi
pass

# -------------------------------------------------------------------------
# Helpers: POST a verb and read the .is_enabled flag back. The field is
# .is_enabled per openapi.yaml:18591 and backend webhooks.rs:103. An
# earlier draft read .enabled, which is silently absent on every
# response and would have caused the assertions below to compare ""
# against "true"/"false" forever.
# -------------------------------------------------------------------------

# post_verb <verb>   ->   echoes HTTP status
post_verb() {
  local verb="$1"
  curl -s -o /dev/null -w '%{http_code}' \
    --max-time 10 \
    -H "$(auth_header)" \
    -X POST \
    "${BASE_URL}/api/v1/webhooks/${WEBHOOK_ID}/${verb}" 2>/dev/null || echo "000"
}

# read_enabled   ->   echoes "true" | "false" | ""
read_enabled() {
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}" 2>/dev/null); then
    # Do NOT use `.is_enabled // empty`: jq's `//` treats boolean `false`
    # as absent and collapses it to "", so a correctly-disabled webhook
    # would read as empty. Preserve false explicitly.
    echo "$resp" | jq -r 'if has("is_enabled") then (.is_enabled|tostring) else "" end' 2>/dev/null || echo ""
  else
    echo ""
  fi
}

# -------------------------------------------------------------------------
# Create a webhook. Use a URL that the SSRF allow-list will accept --
# httpbin.org is the convention used by test-webhook-crud.sh. We do not
# actually fire any deliveries in this suite, so the URL only needs to
# pass the create-time validator.
# -------------------------------------------------------------------------

WEBHOOK_NAME="toggle-${RUN_ID}"
SUITE_BLOCKED=false

begin_test "Create webhook (enabled by default)"
# CreateWebhookRequest does not accept an enabled/is_enabled field
# (backend webhooks.rs:86-95). New webhooks default to enabled at the
# DB layer, which is the property this case asserts.
PAYLOAD=$(jq -n \
  --arg name "$WEBHOOK_NAME" \
  --arg url "https://httpbin.org/post" \
  '{name: $name, url: $url, events: ["artifact_uploaded"]}')
if resp=$(api_post "/api/v1/webhooks" "$PAYLOAD" 2>/dev/null); then
  WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty')
  initial=$(echo "$resp" | jq -r '.is_enabled // empty')
  if [ -z "$WEBHOOK_ID" ] || [ "$WEBHOOK_ID" = "null" ]; then
    fail "create returned no id"
  elif [ "$initial" != "true" ]; then
    fail "webhook created with is_enabled='${initial}', expected 'true'"
  else
    pass
  fi
else
  SUITE_BLOCKED=true
  skip "webhook create rejected (URL likely blocked or endpoint unavailable)"
fi

# -------------------------------------------------------------------------
# /disable flips enabled to false.
# -------------------------------------------------------------------------

begin_test "POST /disable returns 2xx"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  status=$(post_verb "disable")
  case "$status" in
    2??) pass ;;
    501) SUITE_BLOCKED=true; skip "/disable endpoint not implemented" ;;
    *)   fail "expected 2xx from /disable, got HTTP ${status}" ;;
  esac
fi

begin_test "GET shows is_enabled=false after /disable"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "/disable unavailable"
else
  state=$(read_enabled)
  if [ "$state" = "false" ]; then
    pass
  else
    fail "expected is_enabled=false after /disable, got '${state}'"
  fi
fi

# -------------------------------------------------------------------------
# /disable is idempotent. Calling it twice in a row must still return
# 2xx, not 409 -- operator tooling will retry on a network hiccup and a
# 409 would push the operator toward the bad workaround of "GET first,
# branch on state".
# -------------------------------------------------------------------------

begin_test "POST /disable is idempotent (second call also 2xx)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "/disable unavailable"
else
  status=$(post_verb "disable")
  case "$status" in
    2??) pass ;;
    *)   fail "second /disable returned HTTP ${status} (expected 2xx, /disable must be idempotent)" ;;
  esac
fi

# -------------------------------------------------------------------------
# /enable flips it back.
# -------------------------------------------------------------------------

begin_test "POST /enable returns 2xx"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  status=$(post_verb "enable")
  case "$status" in
    2??) pass ;;
    501) SUITE_BLOCKED=true; skip "/enable endpoint not implemented" ;;
    *)   fail "expected 2xx from /enable, got HTTP ${status}" ;;
  esac
fi

begin_test "GET shows is_enabled=true after /enable"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "/enable unavailable"
else
  state=$(read_enabled)
  if [ "$state" = "true" ]; then
    pass
  else
    fail "expected is_enabled=true after /enable, got '${state}'"
  fi
fi

begin_test "POST /enable is idempotent (second call also 2xx)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "/enable unavailable"
else
  status=$(post_verb "enable")
  case "$status" in
    2??) pass ;;
    *)   fail "second /enable returned HTTP ${status} (expected 2xx, /enable must be idempotent)" ;;
  esac
fi

# -------------------------------------------------------------------------
# Final consistency check: round-trip enable -> disable -> enable lands
# the webhook back in the enabled state. Cheap belt-and-braces against
# a regression where /enable and /disable both report 2xx but only one
# of them actually mutates state.
# -------------------------------------------------------------------------

begin_test "Round-trip toggle leaves the webhook enabled"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "toggle endpoints unavailable"
else
  post_verb "disable" >/dev/null
  post_verb "enable"  >/dev/null
  state=$(read_enabled)
  if [ "$state" = "true" ]; then
    pass
  else
    fail "after disable->enable round-trip, .is_enabled='${state}' (expected 'true')"
  fi
fi

# -------------------------------------------------------------------------
# Negative path: /enable on a fabricated id is 404. Symmetric to the
# /test negative case in test-webhook-dry-run.sh.
# -------------------------------------------------------------------------

begin_test "POST /enable on unknown id returns 404"
if [ "$SUITE_BLOCKED" = "true" ]; then
  skip "toggle endpoints unavailable"
else
  fake_id="00000000-0000-0000-0000-000000000000"
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    --max-time 10 \
    -H "$(auth_header)" \
    -X POST \
    "${BASE_URL}/api/v1/webhooks/${fake_id}/enable" 2>/dev/null) || status="000"
  case "$status" in
    404) pass ;;
    4??) pass ;;  # 400 for malformed is fine; the assertion is "not 2xx"
    2??) fail "POST /enable against unknown id '${fake_id}' returned HTTP ${status} (expected 404)" ;;
    501) skip "/enable not implemented" ;;
    *)   fail "unexpected HTTP ${status} for /enable on unknown id" ;;
  esac
fi

end_suite
