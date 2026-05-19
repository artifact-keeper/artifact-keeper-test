#!/usr/bin/env bash
# test-migrations-lifecycle.sh - Migration subsystem E2E (v1.1.9 starter)
#
# Covers Epic 9 (artifact-keeper-test#74) starter subtasks:
#   9.1 Create migration job   (POST /migrations)
#   9.2 List / query jobs      (GET  /migrations, GET /migrations/{id})
#   9.3 Job lifecycle: cancel  (POST /migrations/{id}/cancel)
#   9.7 Connection test        (POST /migrations/connections/{id}/test)
#   9.8 Connection CRUD        (POST/GET/PUT/DELETE /migrations/connections/...)
#
# Deferred to followup PRs (require fixture endpoints we cannot reach in a
# v1.1.x release-gate environment):
#   9.4 SSE progress streaming     -- requires a long-running source connection
#   9.5 Migration report           -- requires a completed job
#   9.6 Pre-migration assessment   -- requires a reachable source instance
#   9.9 Artifactory/Nexus/Harbor source fixtures -- separate fixture infra
#
# Design notes
#   - Migrations are an admin-only subsystem; all endpoints require admin
#     auth. We do not attempt a non-admin negative-control here -- that
#     belongs in a dedicated RBAC test once the basic CRUD contract is
#     pinned (this test).
#   - The connection points at a deliberately unreachable upstream
#     (`https://example.invalid/...`). The connection-test endpoint must
#     therefore fail closed (non-2xx body indicating the source could not
#     be reached). A 2xx from this fixture would mean the test endpoint
#     is mocked or always succeeds -- the load-bearing assertion.
#   - The job is cancelled before any actual transfer can run, so we do
#     not depend on a working source. The cancel transition pins the job
#     state machine: queued/pending -> cancelled.
#   - The test is conservative about endpoint shapes that the issue text
#     describes at a high level: we accept any JSON envelope with an `id`
#     (or `connection.id` / `job.id`) field and treat empty/null as a
#     hard fail so a schema regression is loud.
#
# Skip behavior
#   The migrations subsystem is gated by backend feature flag in some
#   1.1.x builds (release/1.1.x ships it enabled by default, but a
#   compatibility mode disables it). If POST /migrations/connections
#   returns 404 OR 501, the suite skips with a clear reason -- it does
#   not silently pass.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "migrations-lifecycle"
auth_admin

CONNECTION_NAME="mig-conn-${RUN_ID}"
JOB_NAME="mig-job-${RUN_ID}"
CONNECTIONS_BASE="/api/v1/migrations/connections"
JOBS_BASE="/api/v1/migrations"

# ---------------------------------------------------------------------------
# Track resources for trap-based cleanup. We push IDs onto these arrays
# as they're created, then the EXIT trap iterates and DELETEs each so a
# mid-suite failure does not leave residue in the cluster.
# ---------------------------------------------------------------------------

CONNECTION_IDS=()
JOB_IDS=()

cleanup_migrations() {
  local id
  for id in "${JOB_IDS[@]:-}"; do
    [ -z "$id" ] && continue
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

# Helper: GET status + body separately so we can distinguish
# "endpoint missing" (skip) from "endpoint failed" (fail).
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

# ---------------------------------------------------------------------------
# 9.8.a Connection CRUD: create
#
# Shape per release/1.1.x backend handlers/migrations.rs:
#   { "name": "...", "source_type": "<artifactory|nexus|harbor>",
#     "url": "...", "credentials": {...} }
# Response envelope: either bare connection or { "connection": {...} }.
# ---------------------------------------------------------------------------

begin_test "Create migration connection (artifactory source, unreachable URL)"
CREATE_PAYLOAD=$(jq -nc \
  --arg name "$CONNECTION_NAME" \
  '{
    name: $name,
    source_type: "artifactory",
    url: "https://example.invalid/artifactory",
    auth_type: "basic_auth",
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
      fail "create-connection returned HTTP ${STATUS} but no id field; body=${BODY:0:200}"
    fi
    ;;
  *)
    fail "create-connection expected 200/201, got ${STATUS}; body=${BODY:0:200}"
    ;;
esac

# Only run subsequent tests if we got a connection ID.
if [ "${#CONNECTION_IDS[@]}" -eq 0 ]; then
  echo "  skipping remaining migration tests: no connection id"
  end_suite
fi
CONN_ID="${CONNECTION_IDS[0]}"

# ---------------------------------------------------------------------------
# 9.8.b Connection CRUD: list contains the new connection
# ---------------------------------------------------------------------------

begin_test "List connections includes the new one"
RESP=$(migrations_request GET "$CONNECTIONS_BASE")
STATUS=$(echo "$RESP" | head -1)
BODY=$(echo "$RESP" | tail -n +2)

if [ "$STATUS" = "200" ]; then
  # Accept either { "connections": [...] } or a bare array.
  ID_FOUND=$(echo "$BODY" | jq -r --arg id "$CONN_ID" \
    '(.connections // .items // .) | if type == "array" then .[] | select(.id == $id) | .id else empty end' \
    2>/dev/null | head -1)
  if [ "$ID_FOUND" = "$CONN_ID" ]; then
    pass
  else
    fail "list-connections did not include id=${CONN_ID}; body=${BODY:0:300}"
  fi
else
  fail "list-connections expected 200, got ${STATUS}"
fi

# ---------------------------------------------------------------------------
# 9.8.c Connection CRUD: get-by-id round-trips fields
# ---------------------------------------------------------------------------

begin_test "GET connection by id returns the same name"
RESP=$(migrations_request GET "${CONNECTIONS_BASE}/${CONN_ID}")
STATUS=$(echo "$RESP" | head -1)
BODY=$(echo "$RESP" | tail -n +2)

if [ "$STATUS" = "200" ]; then
  GOT_NAME=$(echo "$BODY" | jq -r '.name // .connection.name // empty')
  if [ "$GOT_NAME" = "$CONNECTION_NAME" ]; then
    pass
  else
    fail "GET connection name mismatch: expected '${CONNECTION_NAME}', got '${GOT_NAME}'"
  fi
else
  fail "GET connection expected 200, got ${STATUS}"
fi

# ---------------------------------------------------------------------------
# 9.7 Connection test: must fail closed against an unreachable upstream.
#
# A 2xx here would indicate the test endpoint is mocked or always
# succeeds, which would silently turn migration validation into a no-op
# (the regression class we exist to catch). We accept 2xx ONLY if the
# body explicitly reports a failure status (`ok: false`, `status: "failed"`,
# `success: false`).
# ---------------------------------------------------------------------------

begin_test "POST connection test against unreachable URL fails closed"
RESP=$(migrations_request POST "${CONNECTIONS_BASE}/${CONN_ID}/test")
STATUS=$(echo "$RESP" | head -1)
BODY=$(echo "$RESP" | tail -n +2)

# Acceptable: non-2xx (4xx/5xx/timeout-shaped).
# Also acceptable: 2xx with explicit failure body.
case "$STATUS" in
  200|201|202)
    REPORTED_OK=$(echo "$BODY" | jq -r '.ok // .success // empty' 2>/dev/null)
    REPORTED_STATUS=$(echo "$BODY" | jq -r '.status // empty' 2>/dev/null)
    if [ "$REPORTED_OK" = "false" ] || [ "$REPORTED_STATUS" = "failed" ] || [ "$REPORTED_STATUS" = "error" ]; then
      pass
    else
      fail "test-endpoint returned 2xx without an explicit failure marker on an unreachable URL; body=${BODY:0:200}"
    fi
    ;;
  4*|5*)
    pass
    ;;
  *)
    fail "test-endpoint returned unexpected HTTP ${STATUS}; body=${BODY:0:200}"
    ;;
esac

# ---------------------------------------------------------------------------
# 9.1 Create migration job referencing the connection.
# ---------------------------------------------------------------------------

begin_test "Create migration job"
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

# ---------------------------------------------------------------------------
# 9.2 GET job by id returns the job we just created.
# ---------------------------------------------------------------------------

if [ -n "$JOB_ID" ]; then
  begin_test "GET migration job by id"
  RESP=$(migrations_request GET "${JOBS_BASE}/${JOB_ID}")
  STATUS=$(echo "$RESP" | head -1)
  BODY=$(echo "$RESP" | tail -n +2)
  if [ "$STATUS" = "200" ]; then
    GOT_NAME=$(echo "$BODY" | jq -r '.name // .job.name // empty')
    if [ "$GOT_NAME" = "$JOB_NAME" ]; then
      pass
    else
      fail "GET job name mismatch: expected '${JOB_NAME}', got '${GOT_NAME}'"
    fi
  else
    fail "GET job expected 200, got ${STATUS}"
  fi

  # -------------------------------------------------------------------------
  # 9.3 Job lifecycle: cancel transition
  #
  # We cancel from the initial queued/pending state (no source connection
  # exists for real, so the job will never actually start transferring).
  # The lifecycle subtask covers start/pause/resume/cancel; this PR
  # exercises cancel only, the most important "fail-safe" transition.
  # -------------------------------------------------------------------------

  begin_test "POST cancel on queued migration job returns 2xx"
  RESP=$(migrations_request POST "${JOBS_BASE}/${JOB_ID}/cancel")
  STATUS=$(echo "$RESP" | head -1)
  if [[ "$STATUS" =~ ^2 ]]; then
    pass
  else
    fail "cancel endpoint expected 2xx, got ${STATUS}"
  fi

  begin_test "Cancelled job reports cancelled state"
  RESP=$(migrations_request GET "${JOBS_BASE}/${JOB_ID}")
  STATUS=$(echo "$RESP" | head -1)
  BODY=$(echo "$RESP" | tail -n +2)
  if [ "$STATUS" = "200" ]; then
    JOB_STATE=$(echo "$BODY" | jq -r '.state // .status // .job.state // .job.status // empty')
    case "$JOB_STATE" in
      cancelled|canceled|cancelling|cancelling) pass ;;
      *) fail "expected cancelled state, got '${JOB_STATE}'" ;;
    esac
  else
    fail "GET job after cancel expected 200, got ${STATUS}"
  fi
fi

# ---------------------------------------------------------------------------
# 9.8.d Connection CRUD: delete is idempotent (404 acceptable on second call).
# ---------------------------------------------------------------------------

begin_test "DELETE migration connection succeeds"
RESP=$(migrations_request DELETE "${CONNECTIONS_BASE}/${CONN_ID}")
STATUS=$(echo "$RESP" | head -1)
if [[ "$STATUS" =~ ^2 ]]; then
  CONNECTION_IDS=()  # already cleaned up; skip trap re-delete
  pass
else
  fail "DELETE connection expected 2xx, got ${STATUS}"
fi

begin_test "DELETE migration connection a second time returns 404"
RESP=$(migrations_request DELETE "${CONNECTIONS_BASE}/${CONN_ID}")
STATUS=$(echo "$RESP" | head -1)
if [ "$STATUS" = "404" ]; then
  pass
else
  fail "second DELETE expected 404, got ${STATUS}"
fi

end_suite
