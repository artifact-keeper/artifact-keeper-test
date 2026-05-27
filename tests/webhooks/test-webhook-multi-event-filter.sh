#!/usr/bin/env bash
# test-webhook-multi-event-filter.sh - Multi-event subscription routing
#
# Epic 7 sub-task 7.11 (artifact-keeper-test#75). Existing webhook tests
# only assert delivery of a single event type. The producer must also
# route every subscribed event independently: a webhook subscribed to
# "artifact.uploaded" must NOT receive a delivery for "repository.created"
# fired against an unrelated repo, and vice versa.
#
# Approach: create two webhooks pointing at the same mock receiver but
# subscribed to disjoint event sets, then drive REAL domain events
# (artifact upload + repository create), and assert via the per-webhook
# /deliveries endpoint that each webhook's row set contains only its own
# event. The previous revision of this test used POST /webhooks/{id}/test
# as a trigger and asserted total receiver count <= 3, which is a counting
# heuristic, not a routing check; that approach is replaced here.
#
# Gating: the producer that turns EventBus events into webhook_deliveries
# rows ships in v1.2.0 (webhook_event_producer feature flag). On older
# backends this whole suite is skipped at the suite level; partial
# assertions don't silently degrade.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-multi-event-filter"
auth_admin
setup_workdir

# Suite-level gate: producer wire-up landed in v1.2.0. Without it, real
# EventBus events do not enqueue webhook_deliveries rows, so the routing
# assertion below cannot run. Skipping at the suite level avoids the
# false-green pattern where individual assertions skip on missing rows.
backend_ver=$(get_backend_version)
if [ "$backend_ver" != "unknown" ]; then
  min_ver=$(_feature_min_version "webhook_event_producer")
  if ! version_ge "$backend_ver" "$min_ver"; then
    skip_suite "webhook_event_producer requires backend >= ${min_ver}, running ${backend_ver}"
  fi
fi

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18773}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://${WEBHOOK_RECEIVER_HOST:-127.0.0.1}:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WORK_DIR}/mock-webhook-receiver-multievt.log"
WEBHOOK_RECEIVER_STDERR="${WORK_DIR}/mock-webhook-receiver-multievt.stderr"
RECEIVER_PID=""
WEBHOOK_A_ID=""
WEBHOOK_B_ID=""
TRIGGER_REPO_KEY="multievt-trigger-${RUN_ID}"

cleanup_and_finalize() {
  local code=$?
  if [ -n "${RECEIVER_PID}" ] && kill -0 "${RECEIVER_PID}" 2>/dev/null; then
    kill "${RECEIVER_PID}" 2>/dev/null || true
    wait "${RECEIVER_PID}" 2>/dev/null || true
  fi
  for id in "${WEBHOOK_A_ID}" "${WEBHOOK_B_ID}"; do
    if [ -n "$id" ] && [ "$id" != "null" ]; then
      api_delete "/api/v1/webhooks/${id}" >/dev/null 2>&1 || true
    fi
  done
  api_delete "/api/v1/repositories/${TRIGGER_REPO_KEY}" >/dev/null 2>&1 || true
  # WORK_DIR (and the logs inside it) are cleaned by setup_workdir's
  # registered exit handler. No /tmp leakage.
  exit "$code"
}
trap cleanup_and_finalize EXIT

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

# Port-collision pre-flight: if something is already listening on
# WEBHOOK_RECEIVER_PORT, fail loudly with a clear message rather than
# silently attaching to a foreign receiver from another concurrent run.
begin_test "Receiver port ${WEBHOOK_RECEIVER_PORT} is free"
if curl -sf --max-time 1 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__health" >/dev/null 2>&1; then
  fail "127.0.0.1:${WEBHOOK_RECEIVER_PORT} already serves /__health (concurrent run? stale receiver?); set WEBHOOK_RECEIVER_PORT to a free port"
  end_suite
fi
pass

begin_test "Start mock receiver"
WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
  WEBHOOK_FAIL_FIRST_N=0 \
  WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
  python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
  >"$WEBHOOK_RECEIVER_STDERR" 2>&1 &
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
  end_suite
fi

# -------------------------------------------------------------------------
# Create two webhooks with disjoint event subscriptions.
#
# The wire event name uses underscores in the producer mapping
# (see test-webhook-delivery.sh): repository_created and
# artifact_uploaded. Some backend revisions accept the dot form as an
# alias on the way in; we use underscores since that matches what the
# producer emits onto the wire.
# -------------------------------------------------------------------------

WEBHOOK_A_NAME="multievt-a-${RUN_ID}"
WEBHOOK_B_NAME="multievt-b-${RUN_ID}"

begin_test "Create webhook A subscribed to artifact_uploaded only"
payload_a=$(jq -nc \
  --arg name "$WEBHOOK_A_NAME" \
  --arg url  "$WEBHOOK_RECEIVER_URL" \
  '{name: $name, url: $url, events: ["artifact_uploaded"], enabled: true}')
if resp=$(api_post "/api/v1/webhooks" "$payload_a" 2>/dev/null); then
  WEBHOOK_A_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$WEBHOOK_A_ID" ] && [ "$WEBHOOK_A_ID" != "null" ]; then
    pass
  else
    fail "webhook A create returned no id: ${resp:0:200}"
    end_suite
  fi
else
  fail "webhook A create request failed"
  end_suite
fi

begin_test "Create webhook B subscribed to repository_created only"
payload_b=$(jq -nc \
  --arg name "$WEBHOOK_B_NAME" \
  --arg url  "$WEBHOOK_RECEIVER_URL" \
  '{name: $name, url: $url, events: ["repository_created"], enabled: true}')
if resp=$(api_post "/api/v1/webhooks" "$payload_b" 2>/dev/null); then
  WEBHOOK_B_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$WEBHOOK_B_ID" ] && [ "$WEBHOOK_B_ID" != "null" ]; then
    pass
  else
    fail "webhook B create returned no id: ${resp:0:200}"
    end_suite
  fi
else
  fail "webhook B create request failed"
  end_suite
fi

# -------------------------------------------------------------------------
# Drive a real repository_created event by creating a repo. This must
# enqueue exactly one row on webhook B's delivery list and zero on A's.
# -------------------------------------------------------------------------

begin_test "Create repo to fire repository_created"
REPO_CREATE_PAYLOAD=$(jq -nc --arg k "$TRIGGER_REPO_KEY" \
  '{key:$k, name:$k, format:"generic", repo_type:"local", is_public:true}')
if api_post "/api/v1/repositories" "$REPO_CREATE_PAYLOAD" >/dev/null 2>&1; then
  pass
else
  fail "repo create failed; cannot fire repository_created"
  end_suite
fi

# -------------------------------------------------------------------------
# Drive a real artifact_uploaded event by uploading a file into the new
# repo. This must enqueue at least one row on webhook A's delivery list
# and zero on B's.
# -------------------------------------------------------------------------

begin_test "Upload artifact to fire artifact_uploaded"
echo "multievt-payload-${RUN_ID}" > "${WORK_DIR}/payload.txt"
if api_upload "/api/v1/repositories/${TRIGGER_REPO_KEY}/artifacts/payload/${RUN_ID}.txt" \
    "${WORK_DIR}/payload.txt" >/dev/null 2>&1; then
  pass
else
  fail "artifact upload failed; cannot fire artifact_uploaded"
  end_suite
fi

# -------------------------------------------------------------------------
# Poll the per-webhook /deliveries endpoint. This is the load-bearing
# contract: if it's not exposed, the routing assertion cannot be made,
# and the test MUST FAIL (not skip) so the gap is visible. The endpoint
# has shipped since the webhooks v2 wire contract landed; absence on a
# v1.2.0+ backend is a regression we want to catch.
# -------------------------------------------------------------------------

DELIVERIES_A=""
DELIVERIES_B=""

begin_test "Webhook A /deliveries reachable"
for _ in $(seq 1 15); do
  if DELIVERIES_A=$(api_get "/api/v1/webhooks/${WEBHOOK_A_ID}/deliveries" 2>/dev/null); then
    if [ -n "$DELIVERIES_A" ] && [ "$DELIVERIES_A" != "null" ]; then
      break
    fi
  fi
  sleep 2
done
if [ -n "$DELIVERIES_A" ] && [ "$DELIVERIES_A" != "null" ]; then
  pass
else
  fail "/api/v1/webhooks/${WEBHOOK_A_ID}/deliveries returned empty after 30s; routing cannot be asserted"
  end_suite
fi

begin_test "Webhook B /deliveries reachable"
for _ in $(seq 1 15); do
  if DELIVERIES_B=$(api_get "/api/v1/webhooks/${WEBHOOK_B_ID}/deliveries" 2>/dev/null); then
    if [ -n "$DELIVERIES_B" ] && [ "$DELIVERIES_B" != "null" ]; then
      break
    fi
  fi
  sleep 2
done
if [ -n "$DELIVERIES_B" ] && [ "$DELIVERIES_B" != "null" ]; then
  pass
else
  fail "/api/v1/webhooks/${WEBHOOK_B_ID}/deliveries returned empty after 30s; routing cannot be asserted"
  end_suite
fi

# Normalise the delivery payload to a flat array. Different backend
# revisions wrap rows in {items:[...]}, {deliveries:[...]}, or return a
# bare array; the jq filter handles all three.
_normalize() {
  echo "$1" | jq -c '
    if type == "array" then .
    elif .items then .items
    elif .deliveries then .deliveries
    else [] end' 2>/dev/null || echo '[]'
}

DELIVERIES_A_ARR=$(_normalize "$DELIVERIES_A")
DELIVERIES_B_ARR=$(_normalize "$DELIVERIES_B")

# -------------------------------------------------------------------------
# Cross-routing assertion: webhook A (subscribed only to artifact_uploaded)
# must have ZERO rows whose event is repository_created. This is the real
# routing check, replacing the old "<=3 total deliveries" heuristic.
# -------------------------------------------------------------------------

begin_test "Webhook A has zero repository_created rows"
bad_a=$(echo "$DELIVERIES_A_ARR" | jq '
  map(select(
    (.event == "repository_created") or
    (.event == "repository.created") or
    (.event_name == "repository_created") or
    (.event_name == "repository.created")
  )) | length' 2>/dev/null || echo 0)
if [ "$bad_a" = "0" ]; then
  pass
else
  fail "webhook A leaked ${bad_a} repository_created rows (cross-subscription routing failure)"
fi

# -------------------------------------------------------------------------
# Mirror assertion: webhook B (subscribed only to repository_created) must
# have ZERO rows whose event is artifact_uploaded.
# -------------------------------------------------------------------------

begin_test "Webhook B has zero artifact_uploaded rows"
bad_b=$(echo "$DELIVERIES_B_ARR" | jq '
  map(select(
    (.event == "artifact_uploaded") or
    (.event == "artifact.uploaded") or
    (.event_name == "artifact_uploaded") or
    (.event_name == "artifact.uploaded")
  )) | length' 2>/dev/null || echo 0)
if [ "$bad_b" = "0" ]; then
  pass
else
  fail "webhook B leaked ${bad_b} artifact_uploaded rows (cross-subscription routing failure)"
fi

# -------------------------------------------------------------------------
# Positive-side sanity: at least one of the two webhooks should have a
# matching row for its subscribed event. If both are empty, the producer
# isn't running and the cross-leak assertions above were vacuously true;
# that's a regression we still want to surface.
# -------------------------------------------------------------------------

begin_test "At least one webhook recorded its own subscribed event"
ok_a=$(echo "$DELIVERIES_A_ARR" | jq '
  map(select(
    (.event == "artifact_uploaded") or
    (.event == "artifact.uploaded") or
    (.event_name == "artifact_uploaded") or
    (.event_name == "artifact.uploaded")
  )) | length' 2>/dev/null || echo 0)
ok_b=$(echo "$DELIVERIES_B_ARR" | jq '
  map(select(
    (.event == "repository_created") or
    (.event == "repository.created") or
    (.event_name == "repository_created") or
    (.event_name == "repository.created")
  )) | length' 2>/dev/null || echo 0)
if [ "$ok_a" -gt 0 ] || [ "$ok_b" -gt 0 ]; then
  pass
else
  fail "neither webhook recorded its subscribed event (A=${ok_a} artifact_uploaded, B=${ok_b} repository_created); producer may not be enqueuing rows"
fi

end_suite
