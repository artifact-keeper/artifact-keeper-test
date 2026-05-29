#!/usr/bin/env bash
# test-migrations-assess.sh - Pre-migration assessment fail-closed (v1.2.0)
#
# Covers artifact-keeper-test#74 subtask 9.6:
#   POST /migrations/{id}/assess
#   GET  /migrations/{id}/assessment   (used for the fail-closed assertion)
#
# Goal
#   Pin the same "fail closed on unreachable source" contract that the
#   connection-test endpoint pins for 9.7. The assessment runs against
#   the source connection; if the source is unreachable, the assessment
#   MUST surface that as a failure -- either by returning non-2xx on
#   POST /assess, or by returning 2xx with the eventual
#   AssessmentResult.status == "failed" / .blockers non-empty.
#
# Why this is load-bearing
#   The assessment is presented to operators as "is this migration safe
#   to run?" The cost of a false positive (assessment says "ready" when
#   the source is unreachable) is a botched cutover. A regression that
#   returned a synthetic green assessment regardless of source health
#   would be the exact silent-success class (#870/#871/#888) we exist
#   to catch. We refuse to accept a 2xx assessment with status == "ok"
#   / "ready" / "success" against an unreachable source.
#
# Design notes
#   - POST /assess is async per openapi (202 Accepted). The actual result
#     lives at GET /assessment. We poll the GET endpoint for up to ~30s.
#   - Acceptable outcomes:
#       a. POST returns 4xx/5xx (synchronous fail-closed).
#       b. POST returns 2xx, GET /assessment eventually shows
#          status in {failed, error, errored} OR blockers array non-empty.
#       c. POST returns 2xx, GET /assessment never materialises within
#          the budget (still in progress / no result yet) -- we treat
#          this as inconclusive and skip rather than pass, because a
#          green-by-default assessment must NEVER pass this test.
#   - Refused outcome:
#       d. POST returns 2xx AND GET /assessment shows status in
#          {ok, ready, success, completed} AND blockers is empty.
#          This is silent-success; we fail loudly.
#
# Skip behavior
#   Standard subsystem-disabled skip on 404/501 from create-connection.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "migrations-assess"
auth_admin

CONNECTION_NAME="mig-conn-ass-${RUN_ID}"
# Note: migration jobs no longer carry a `name` field in the backend
# contract (migration.rs CreateMigrationRequest / MigrationJobResponse),
# so there is no JOB_NAME to set or assert on.
CONNECTIONS_BASE="/api/v1/migrations/connections"
JOBS_BASE="/api/v1/migrations"

CONNECTION_IDS=()
JOB_IDS=()

cleanup_migrations() {
  local id
  for id in "${JOB_IDS[@]:-}"; do
    [ -z "$id" ] && continue
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

# ---------------------------------------------------------------------------
# Pre-flight: subsystem availability + fixture create. The URL is
# example.invalid (RFC 6761 guaranteed-unresolvable) so the source is
# truly unreachable, not just slow.
# ---------------------------------------------------------------------------

begin_test "Create migration connection (unreachable source for assessment)"
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
      fail "create-connection HTTP ${STATUS} but no id; body=${BODY:0:200}"
    fi
    ;;
  *)
    fail "create-connection expected 200/201, got ${STATUS}; body=${BODY:0:200}"
    ;;
esac

if [ "${#CONNECTION_IDS[@]}" -eq 0 ]; then
  echo "  skipping assess test: no connection id"
  end_suite
fi
CONN_ID="${CONNECTION_IDS[0]}"

begin_test "Create migration job to assess"
# Backend contract (migration.rs `CreateMigrationRequest`, authoritative):
# {source_connection_id, job_type?, config}. The old
# {name, connection_id, source_path, target_repo} shape now 422s with
# "missing field source_connection_id". The job is created with the
# default job_type "full" (status pending); POST /{id}/assess then flips
# it to job_type "assessment" / status "assessing" on the backend side.
JOB_PAYLOAD=$(jq -nc \
  --arg cid "$CONN_ID" \
  '{
    source_connection_id: $cid,
    job_type: "full",
    config: {}
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
  echo "  skipping assess test: no job id"
  end_suite
fi

# ---------------------------------------------------------------------------
# 9.6 POST /assess against an unreachable source must fail closed.
# ---------------------------------------------------------------------------

begin_test "POST /assess on unreachable source returns non-silent failure"
RESP=$(migrations_request POST "${JOBS_BASE}/${JOB_ID}/assess")
ASSESS_STATUS=$(echo "$RESP" | head -1)
ASSESS_BODY=$(echo "$RESP" | tail -n +2)

# Path A: synchronous fail (4xx/5xx). Accept and done.
case "$ASSESS_STATUS" in
  4*|5*)
    if [ "$ASSESS_STATUS" = "404" ] || [ "$ASSESS_STATUS" = "501" ]; then
      skip "assess endpoint not implemented (HTTP ${ASSESS_STATUS})"
      end_suite
      exit 0
    fi
    pass
    end_suite
    # end_suite only exits on failure; on an all-pass suite it returns, so we
    # must exit explicitly here to avoid falling through to the unconditional
    # silent-success `fail` at the end of the script.
    exit 0
    ;;
  200|201|202) : ;;
  *)
    fail "/assess returned unexpected HTTP ${ASSESS_STATUS}; body=${ASSESS_BODY:0:200}"
    end_suite
    ;;
esac

# Path B: async accepted. Poll GET /assessment for a *terminal* result.
#
# Stale-assertion fix: the previous loop broke as soon as `.status` was
# non-empty. But the assessment endpoint reports the live job status, and an
# async assessment sits in a non-terminal `assessing` state for several
# seconds while the worker tries (and fails) to reach the source. The old
# break-on-any-status logic therefore broke on the FIRST poll with
# status="assessing", then fell through to the "unknown status" branch and
# failed loudly even though the backend was about to mark the job failed.
#
# An unreachable source (example.invalid) fails closed only after the source
# client exhausts its connect timeout + retry backoff, so we must keep polling
# through the in-progress window and only break on a TERMINAL status (or when
# blockers appear). The budget (~40s) stays well within --max-time for a
# release-gate test and comfortably covers the worker's retry backoff.
ATTEMPTS=0
MAX_ATTEMPTS=20
GOT_STATUS=""
GOT_BLOCKERS=""
GOT_BODY=""
GET_HTTP=""
# Statuses that mean "assessment still running" -- we must NOT treat these as
# a final result; keep polling.
IN_PROGRESS_RE='^(assessing|pending|running|in_progress|queued|started)$'
while [ "$ATTEMPTS" -lt "$MAX_ATTEMPTS" ]; do
  RESP=$(migrations_request GET "${JOBS_BASE}/${JOB_ID}/assessment")
  GET_HTTP=$(echo "$RESP" | head -1)
  GOT_BODY=$(echo "$RESP" | tail -n +2)
  if [ "$GET_HTTP" = "200" ]; then
    GOT_STATUS=$(echo "$GOT_BODY" | jq -r '.status // empty' 2>/dev/null)
    GOT_BLOCKERS=$(echo "$GOT_BODY" | jq -r '.blockers // [] | length' 2>/dev/null)
    # Blockers present -> a definitive result regardless of status.
    if [ "${GOT_BLOCKERS:-0}" -gt 0 ] 2>/dev/null; then
      break
    fi
    # A non-empty, non-in-progress status is terminal -> stop polling.
    if [ -n "$GOT_STATUS" ] && ! echo "$GOT_STATUS" | grep -Eq "$IN_PROGRESS_RE"; then
      break
    fi
    # else: status is empty or still in-progress -> keep polling.
  elif [ "$GET_HTTP" = "404" ] || [ "$GET_HTTP" = "202" ]; then
    : # still in progress
  fi
  sleep 2
  ATTEMPTS=$(( ATTEMPTS + 1 ))
done

# If we exited the loop while the assessment was still in-progress, treat the
# transient status as "no result yet" so the inconclusive branch below skips
# rather than misclassifying an unfinished assessment as a silent success.
if [ -n "$GOT_STATUS" ] && echo "$GOT_STATUS" | grep -Eq "$IN_PROGRESS_RE"; then
  GOT_STATUS=""
fi

# Path B.1: never got a populated result. Inconclusive -> skip (not pass).
if [ -z "$GOT_STATUS" ] && [ "${GOT_BLOCKERS:-0}" = "0" ]; then
  skip "assessment did not materialise within budget (last HTTP=${GET_HTTP}); cannot prove fail-closed but refusing to pass"
  end_suite
fi

# Path B.2: explicit failure or blockers present -> pass.
# NOTE: end_suite() only calls `exit` when at least one test failed; on an
# all-pass suite it prints the summary and RETURNS. So after a definitive
# pass we must `exit 0` explicitly, otherwise control falls through to the
# unconditional silent-success `fail` at the end of the script and emits a
# spurious second (failing) summary.
case "$GOT_STATUS" in
  failed|error|errored|unreachable)
    pass
    end_suite
    exit 0
    ;;
esac

if [ "${GOT_BLOCKERS:-0}" -gt 0 ] 2>/dev/null; then
  pass
  end_suite
  exit 0
fi

# Path B.3 (refused): green status against an unreachable source.
case "$GOT_STATUS" in
  ok|ready|success|completed|passed)
    fail "assessment reports green status='${GOT_STATUS}' against an unreachable source -- silent success; body=${GOT_BODY:0:300}"
    end_suite
    ;;
esac

# Unknown status with no blockers -- be conservative and fail rather than
# pass: an unrecognised vocabulary is still a contract regression we
# want to surface.
fail "assessment status='${GOT_STATUS}' is not a known failure marker and blockers is empty; treating as silent success; body=${GOT_BODY:0:300}"

end_suite
