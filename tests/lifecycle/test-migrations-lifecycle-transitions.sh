#!/usr/bin/env bash
# test-migrations-lifecycle-transitions.sh - Full migration state machine (v1.2.0)
#
# Covers artifact-keeper-test#74 subtask 9.3 followup:
#   POST /migrations/{id}/start
#   POST /migrations/{id}/pause
#   POST /migrations/{id}/resume
#
# The starter PR (#156) pinned cancel as the fail-safe transition from
# queued -> cancelled. This script extends 9.3 to the positive path of the
# state machine:
#
#   queued -> started   (POST /start)        running/started
#   started -> paused   (POST /pause)        paused
#   paused  -> resumed  (POST /resume)       running/started
#   running -> cancelled (POST /cancel)      terminal cleanup
#
# Design notes
#   - We deliberately do not assert which exact state label the backend
#     uses (running vs started vs in_progress) -- different release lines
#     have used different vocabulary. The load-bearing assertion is that
#     each transition is OBSERVABLE: the POST returns 2xx AND the
#     subsequent GET reports a state distinct from the prior one in a
#     direction consistent with the transition. A transition that returns
#     2xx but leaves the state unchanged would be silent-success
#     (#870/#871/#888 class) and we fail it loudly.
#   - The job points at an unreachable source so we don't depend on any
#     real artifact transfer happening. The state machine itself is the
#     contract under test, not the transfer.
#   - Some transitions can race: a started job against an unreachable
#     source can flip to a failed/errored terminal state before we get
#     to pause it. We accept that as a valid (non-silent) outcome and
#     skip the rest of the chain with a clear reason rather than
#     forcing a transition the backend has already refused.
#
# Skip behavior
#   Mirrors the starter: if POST /migrations/connections returns 404 or
#   501 the subsystem is disabled and we skip cleanly. We do NOT
#   skip_suite (RELEASE_GATE=1 would turn it into a hard fail); we mark
#   the first test skipped and exit 0 via end_suite.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "migrations-lifecycle-transitions"
auth_admin

CONNECTION_NAME="mig-conn-tx-${RUN_ID}"
JOB_NAME="mig-job-tx-${RUN_ID}"
CONNECTIONS_BASE="/api/v1/migrations/connections"
JOBS_BASE="/api/v1/migrations"

CONNECTION_IDS=()
JOB_IDS=()

cleanup_migrations() {
  local id
  for id in "${JOB_IDS[@]:-}"; do
    [ -z "$id" ] && continue
    # Best-effort cancel-then-delete: a running job needs to be cancelled
    # before delete on some backends.
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

# Read the current job state. Returns empty string if not retrievable.
get_job_state() {
  local job_id="$1"
  local resp
  resp=$(migrations_request GET "${JOBS_BASE}/${job_id}")
  local status
  status=$(echo "$resp" | head -1)
  local body
  body=$(echo "$resp" | tail -n +2)
  if [ "$status" = "200" ]; then
    echo "$body" | jq -r '.status // .state // .job.status // .job.state // empty' 2>/dev/null
  fi
}

# ---------------------------------------------------------------------------
# Pre-flight: create connection + job. If the subsystem is disabled, skip.
# ---------------------------------------------------------------------------

begin_test "Create migration connection (unreachable source for state machine fixture)"
CREATE_PAYLOAD=$(jq -nc \
  --arg name "$CONNECTION_NAME" \
  '{
    name: $name,
    source_type: "artifactory",
    url: "https://example.invalid/artifactory",
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
  echo "  skipping remaining transition tests: no connection id"
  end_suite
fi
CONN_ID="${CONNECTION_IDS[0]}"

begin_test "Create migration job for state-machine chain"
JOB_PAYLOAD=$(jq -nc \
  --arg name "$JOB_NAME" \
  --arg cid "$CONN_ID" \
  '{
    name: $name,
    connection_id: $cid,
    source_path: "example-repo",
    target_repo: "migration-target"
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
  echo "  skipping remaining transitions: no job id"
  end_suite
fi

# Capture the initial queued/pending state for the silent-success guard.
INITIAL_STATE=$(get_job_state "$JOB_ID")

# ---------------------------------------------------------------------------
# 9.3.a queued -> started
# ---------------------------------------------------------------------------

begin_test "POST /start transitions job out of the initial state"
RESP=$(migrations_request POST "${JOBS_BASE}/${JOB_ID}/start")
STATUS=$(echo "$RESP" | head -1)
BODY=$(echo "$RESP" | tail -n +2)

STARTED_OK=0
if [[ "$STATUS" =~ ^2 ]]; then
  AFTER_START_STATE=$(get_job_state "$JOB_ID")
  # Either the state changed (good) OR the response body itself names a
  # running-ish state. We treat "state unchanged from queued/pending" as
  # silent success and fail loudly.
  case "$AFTER_START_STATE" in
    running|started|in_progress|active)
      STARTED_OK=1
      pass
      ;;
    failed|error|errored)
      # Acceptable: unreachable source caused the worker to fast-fail.
      # The transition is observable, just terminal.
      pass
      ;;
    "")
      fail "/start returned 2xx but GET state was empty"
      ;;
    *)
      if [ -n "$INITIAL_STATE" ] && [ "$AFTER_START_STATE" = "$INITIAL_STATE" ]; then
        fail "/start returned 2xx but state is unchanged ('${AFTER_START_STATE}') -- silent success"
      else
        # State moved to something we don't recognise; that's still an
        # observable transition, so pass but warn in the log.
        echo "    note: post-start state is '${AFTER_START_STATE}' (not in known set)"
        STARTED_OK=1
        pass
      fi
      ;;
  esac
else
  fail "/start expected 2xx, got ${STATUS}; body=${BODY:0:200}"
fi

# If start did not land us in a running-ish state, the rest of the chain
# (pause/resume) is not exercisable. Don't fail it; record clear skips.
if [ "$STARTED_OK" -ne 1 ]; then
  begin_test "POST /pause (skipped: job did not reach running state)"
  skip "pre-condition not met: start landed in '${AFTER_START_STATE:-unknown}'"
  begin_test "POST /resume (skipped: job did not reach running state)"
  skip "pre-condition not met: start landed in '${AFTER_START_STATE:-unknown}'"
  end_suite
fi

# ---------------------------------------------------------------------------
# 9.3.b started -> paused
# ---------------------------------------------------------------------------

begin_test "POST /pause moves a running job to paused"
RESP=$(migrations_request POST "${JOBS_BASE}/${JOB_ID}/pause")
STATUS=$(echo "$RESP" | head -1)
BODY=$(echo "$RESP" | tail -n +2)

PAUSE_OK=0
if [[ "$STATUS" =~ ^2 ]]; then
  AFTER_PAUSE_STATE=$(get_job_state "$JOB_ID")
  case "$AFTER_PAUSE_STATE" in
    paused|pausing)
      PAUSE_OK=1
      pass
      ;;
    failed|error|errored|cancelled|canceled|completed)
      # Job raced to a terminal state before we could pause. Acceptable;
      # surface it so the chain skip below is explicit.
      echo "    note: job reached terminal state '${AFTER_PAUSE_STATE}' before pause"
      pass
      ;;
    "")
      fail "/pause returned 2xx but GET state was empty"
      ;;
    *)
      fail "/pause returned 2xx but state is '${AFTER_PAUSE_STATE}', expected paused"
      ;;
  esac
elif [ "$STATUS" = "409" ]; then
  # Backend refused because the job already moved past running (terminal
  # race). That's a non-silent, well-shaped failure -- pass.
  echo "    note: /pause returned 409 (job no longer pausable)"
  pass
else
  fail "/pause expected 2xx or 409, got ${STATUS}; body=${BODY:0:200}"
fi

if [ "$PAUSE_OK" -ne 1 ]; then
  begin_test "POST /resume (skipped: job did not pause)"
  skip "pre-condition not met: pause landed in '${AFTER_PAUSE_STATE:-unknown}'"
  end_suite
fi

# ---------------------------------------------------------------------------
# 9.3.c paused -> resumed
# ---------------------------------------------------------------------------

begin_test "POST /resume moves a paused job back to running"
RESP=$(migrations_request POST "${JOBS_BASE}/${JOB_ID}/resume")
STATUS=$(echo "$RESP" | head -1)
BODY=$(echo "$RESP" | tail -n +2)

if [[ "$STATUS" =~ ^2 ]]; then
  AFTER_RESUME_STATE=$(get_job_state "$JOB_ID")
  case "$AFTER_RESUME_STATE" in
    running|started|in_progress|active|resuming)
      pass
      ;;
    failed|error|errored|completed)
      echo "    note: job reached terminal state '${AFTER_RESUME_STATE}' after resume"
      pass
      ;;
    paused)
      fail "/resume returned 2xx but state is still 'paused' -- silent success"
      ;;
    "")
      fail "/resume returned 2xx but GET state was empty"
      ;;
    *)
      echo "    note: post-resume state is '${AFTER_RESUME_STATE}' (not in known set)"
      pass
      ;;
  esac
else
  fail "/resume expected 2xx, got ${STATUS}; body=${BODY:0:200}"
fi

end_suite
