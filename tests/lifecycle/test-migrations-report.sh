#!/usr/bin/env bash
# test-migrations-report.sh - Migration report fetch + schema (v1.2.0)
#
# Covers artifact-keeper-test#74 subtask 9.5:
#   GET /migrations/{id}/report
#
# Goal
#   Drive a migration job to a terminal state (cancelled is sufficient
#   for report generation), fetch the report, and assert the documented
#   fields are present per openapi.yaml MigrationReportResponse:
#     - id, job_id, generated_at, summary, warnings, errors, recommendations
#
# Why this is the load-bearing assertion
#   The report endpoint is the audit artifact for compliance: a regression
#   that returns 200 with a stripped-down body (e.g. missing `errors` or
#   `recommendations`) would silently break downstream compliance tooling.
#   We require every documented top-level field to be present and not
#   null.
#
# Design notes
#   - We do not run a real transfer. We cancel the job immediately and
#     poll for report availability up to ~20s. Some backends generate the
#     report eagerly on terminal transition; others lazily on first GET.
#     We accept either.
#   - The backend may return 404 until the report is materialised. We
#     poll on 404 with a short sleep, not on 500.
#   - The summary/warnings/errors/recommendations fields are typed as
#     `object` (not array) in the openapi schema; we only assert
#     presence (`!= null`), not shape, to stay forward-compatible.
#
# Skip behavior
#   Standard subsystem-disabled skip on 404/501 from create-connection.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "migrations-report"
auth_admin

CONNECTION_NAME="mig-conn-rep-${RUN_ID}"
JOB_NAME="mig-job-rep-${RUN_ID}"
CONNECTIONS_BASE="/api/v1/migrations/connections"
JOBS_BASE="/api/v1/migrations"

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
# Pre-flight: subsystem availability + fixture create
# ---------------------------------------------------------------------------

begin_test "Create migration connection (report fixture)"
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
  echo "  skipping report test: no connection id"
  end_suite
fi
CONN_ID="${CONNECTION_IDS[0]}"

begin_test "Create migration job (will be driven to terminal state)"
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
  echo "  skipping report test: no job id"
  end_suite
fi

# ---------------------------------------------------------------------------
# Drive to terminal: cancel is the cheapest way to reach a state from
# which the backend will generate a report. We don't care whether the
# job actually transferred anything -- the report contract is about the
# audit envelope, not the transfer payload.
# ---------------------------------------------------------------------------

begin_test "Cancel job to make report available"
RESP=$(migrations_request POST "${JOBS_BASE}/${JOB_ID}/cancel")
STATUS=$(echo "$RESP" | head -1)
if [[ "$STATUS" =~ ^2 ]]; then
  pass
else
  fail "cancel expected 2xx, got ${STATUS}"
  end_suite
fi

# ---------------------------------------------------------------------------
# 9.5 Poll for report, then assert required fields.
# ---------------------------------------------------------------------------

begin_test "GET /report returns 200 with documented fields"
ATTEMPTS=0
MAX_ATTEMPTS=10
REPORT_STATUS=""
REPORT_BODY=""
while [ "$ATTEMPTS" -lt "$MAX_ATTEMPTS" ]; do
  RESP=$(migrations_request GET "${JOBS_BASE}/${JOB_ID}/report")
  REPORT_STATUS=$(echo "$RESP" | head -1)
  REPORT_BODY=$(echo "$RESP" | tail -n +2)
  case "$REPORT_STATUS" in
    200) break ;;
    404)
      # Not yet materialised; wait and retry.
      sleep 2
      ;;
    501)
      skip "report endpoint not implemented (HTTP 501)"
      end_suite
      ;;
    *)
      # Unexpected; bail (don't burn the full budget on 5xx).
      break
      ;;
  esac
  ATTEMPTS=$(( ATTEMPTS + 1 ))
done

if [ "$REPORT_STATUS" != "200" ]; then
  fail "GET /report expected 200 within ${MAX_ATTEMPTS} attempts, last status='${REPORT_STATUS}'; body=${REPORT_BODY:0:200}"
  end_suite
fi

# Per openapi.yaml MigrationReportResponse, required:
#   id, job_id, generated_at, summary, warnings, errors, recommendations
MISSING=()
for field in id job_id generated_at summary warnings errors recommendations; do
  PRESENT=$(echo "$REPORT_BODY" | jq -r --arg f "$field" 'if (has($f) and (.[$f] != null)) then "yes" else "no" end' 2>/dev/null)
  if [ "$PRESENT" != "yes" ]; then
    MISSING+=("$field")
  fi
done

if [ "${#MISSING[@]}" -eq 0 ]; then
  pass
else
  fail "report missing required fields: ${MISSING[*]}; body=${REPORT_BODY:0:300}"
  end_suite
fi

# Additional load-bearing assertion: report.job_id must equal the job we drove.
begin_test "Report.job_id matches the migration job id"
REPORT_JOB_ID=$(echo "$REPORT_BODY" | jq -r '.job_id // empty')
if [ "$REPORT_JOB_ID" = "$JOB_ID" ]; then
  pass
else
  fail "report.job_id='${REPORT_JOB_ID}' does not match driver job_id='${JOB_ID}'"
fi

end_suite
