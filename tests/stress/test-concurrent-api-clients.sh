#!/usr/bin/env bash
# test-concurrent-api-clients.sh - Simulate N parallel API clients
#
# Simulates what happens during the release-gate: N independent clients
# each authenticate, create a repo, upload an artifact, and read it back.
# Measures how many can complete successfully as N increases.
#
# This directly tests the scenario that causes flaky format-test failures:
# many parallel test suites all hitting the backend at once.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "concurrent-api-clients"
auth_admin
setup_workdir

CLIENTS_DIR="${WORK_DIR}/clients"
mkdir -p "$CLIENTS_DIR"

# ---------------------------------------------------------------------------
# Helper: run a single simulated test client
# ---------------------------------------------------------------------------

# Every step gets the same retry budget. Previously only `auth` retried, so a
# transient hiccup at step 2 or later (postgres CPU starvation, pod restart,
# network blip) was always recorded as a failure of THAT step rather than a
# transient. That produced the misleading '100% of failures concentrated on
# POST /repositories' signal investigated in artifact-keeper#1088 (the
# diagnosis doc on artifact-keeper#1176 / artifact-keeper-test#141).
#
# Retries only fire on transient-class statuses. tests/lib/common.sh's
# create_repo() helper draws the line at 401/429/503/000 (network/timeout);
# we match that allowlist here plus 5xx (any 500-class server error is by
# definition retryable in a stress run). 4xx other than 401/429 is a client
# bug we should not paper over with retries.
#
# Knobs (override via env):
#   STEP_MAX_RETRIES  - attempts per step (default 3, same as the old auth budget)
#   STEP_RETRY_DELAY  - seconds between attempts (default 1)
#
# Each client's failure file now also captures the per-step retry counts so an
# operator can tell "create-repo really fails N% of the time" from "create-repo
# eats the retries because earlier steps already burned them".
STEP_MAX_RETRIES="${STEP_MAX_RETRIES:-3}"
STEP_RETRY_DELAY="${STEP_RETRY_DELAY:-1}"

# _is_transient_status - 0 if the given HTTP code is retry-worthy.
#
# Matches the allowlist used by create_repo() in tests/lib/common.sh:
#   - 000 (curl timeout / connection refused)
#   - 401 (race with auth-token-refresh, see artifact-keeper#697/#995)
#   - 429 (rate-limit, should not hit with admin-exempt but defensive)
#   - 503 (service unavailable, e.g. backend in-flight pod restart)
#   - 5xx generally (backend / db / search 500s during saturation burst)
# Returns 1 for any 2xx/3xx (caller handles success) and any 4xx other
# than 401/429 (genuine client error, do not mask with retries).
_is_transient_status() {
  case "$1" in
    000|401|429|503) return 0 ;;
    5*) return 0 ;;
    *) return 1 ;;
  esac
}

run_client() {
  local client_id="$1"
  local wave_id="${2:-0}"
  local client_dir="${CLIENTS_DIR}/${client_id}"
  mkdir -p "$client_dir"

  local result="fail"
  local step="start"
  local start_ms end_ms http_code
  # Per-step retry counters (number of attempts made for each step). Written
  # to <client_dir>/retries on completion regardless of pass/fail.
  local auth_attempts=0
  local create_attempts=0
  local upload_attempts=0
  local read_attempts=0

  # Step 1: authenticate
  step="auth"
  local token=""
  local _retry
  for _retry in $(seq 1 "$STEP_MAX_RETRIES"); do
    auth_attempts=$_retry
    start_ms=$(date +%s%3N 2>/dev/null || date +%s)
    # curl with -w to capture the HTTP status, -o to a body file so we can
    # distinguish "transient 503" from "permanent 401-with-bad-creds" and
    # avoid retrying the latter (Fresh-Eyes #4).
    local _body_file
    _body_file=$(mktemp)
    local _code
    _code=$(curl -s -o "$_body_file" -w '%{http_code}' --max-time 10 \
        -X POST "${BASE_URL}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null) || _code="000"
    end_ms=$(date +%s%3N 2>/dev/null || date +%s)
    log_request "POST" "/api/v1/auth/login" "${_code}" "$(( end_ms - start_ms ))"
    if [ "$_code" -ge 200 ] 2>/dev/null && [ "$_code" -lt 300 ] 2>/dev/null; then
      token=$(jq -r '.access_token // .token // empty' < "$_body_file" 2>/dev/null) || true
      rm -f "$_body_file"
      [ -n "$token" ] && break
    else
      rm -f "$_body_file"
      # Stop retrying on non-transient (e.g. 400/403): a credential or
      # request-shape regression should fail loudly, not burn the budget.
      if ! _is_transient_status "$_code"; then
        break
      fi
    fi
    sleep "$STEP_RETRY_DELAY"
  done
  if [ -z "$token" ]; then
    printf 'auth=%d create-repo=%d upload=%d read=%d\n' \
      "$auth_attempts" "$create_attempts" "$upload_attempts" "$read_attempts" \
      > "${client_dir}/retries"
    echo "${step}" > "${client_dir}/failed"; return
  fi

  # Step 2: create repo
  step="create-repo"
  # Include the wave_id in the key so two clients with the same client_id
  # across waves cannot collide on the server side, masking a real "second
  # wave failed to create" as a 409-treated-as-success (Fresh-Eyes #5).
  local repo_key="stress-client-w${wave_id}-${client_id}-${RUN_ID}"
  http_code="000"
  # 409 is only safe to treat as success if a prior attempt for THIS
  # client+wave saw a transient failure. A first-attempt 409 indicates an
  # external collision (a concurrent suite re-used our RUN_ID, or the
  # server side has stale state), which is worth surfacing rather than
  # masking. We accept 409 as success only when create_attempts >= 2.
  local create_succeeded=0
  for _retry in $(seq 1 "$STEP_MAX_RETRIES"); do
    create_attempts=$_retry
    start_ms=$(date +%s%3N 2>/dev/null || date +%s)
    http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "{\"key\":\"${repo_key}\",\"name\":\"${repo_key}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" \
        "${BASE_URL}/api/v1/repositories" 2>/dev/null) || http_code="000"
    end_ms=$(date +%s%3N 2>/dev/null || date +%s)
    log_request "POST" "/api/v1/repositories" "${http_code}" "$(( end_ms - start_ms ))"
    if [ "$http_code" -ge 200 ] 2>/dev/null && [ "$http_code" -lt 300 ] 2>/dev/null; then
      create_succeeded=1
      break
    fi
    if [ "$http_code" = "409" ] && [ "$create_attempts" -ge 2 ]; then
      create_succeeded=1
      break
    fi
    # Non-transient (other 4xx including first-attempt 409, 400/403/422):
    # stop retrying. The post-loop check will record this as a failure.
    if ! _is_transient_status "$http_code"; then
      break
    fi
    sleep "$STEP_RETRY_DELAY"
  done
  if [ "$create_succeeded" -ne 1 ]; then
    printf 'auth=%d create-repo=%d upload=%d read=%d\n' \
      "$auth_attempts" "$create_attempts" "$upload_attempts" "$read_attempts" \
      > "${client_dir}/retries"
    echo "${step}" > "${client_dir}/failed"; return
  fi

  # Step 3: upload artifact
  step="upload"
  local upload_path="/api/v1/repositories/${repo_key}/artifacts/test/payload.bin"
  echo "client-${client_id}-payload-${RUN_ID}" > "${client_dir}/payload.bin"
  http_code="000"
  for _retry in $(seq 1 "$STEP_MAX_RETRIES"); do
    upload_attempts=$_retry
    start_ms=$(date +%s%3N 2>/dev/null || date +%s)
    http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X PUT \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@${client_dir}/payload.bin" \
        "${BASE_URL}${upload_path}" 2>/dev/null) || http_code="000"
    end_ms=$(date +%s%3N 2>/dev/null || date +%s)
    log_request "PUT" "${upload_path}" "${http_code}" "$(( end_ms - start_ms ))"
    if [ "$http_code" -ge 200 ] 2>/dev/null && [ "$http_code" -lt 300 ] 2>/dev/null; then
      break
    fi
    if ! _is_transient_status "$http_code"; then
      break
    fi
    sleep "$STEP_RETRY_DELAY"
  done
  if [ "$http_code" -lt 200 ] 2>/dev/null || [ "$http_code" -ge 300 ] 2>/dev/null; then
    printf 'auth=%d create-repo=%d upload=%d read=%d\n' \
      "$auth_attempts" "$create_attempts" "$upload_attempts" "$read_attempts" \
      > "${client_dir}/retries"
    echo "${step}" > "${client_dir}/failed"; return
  fi

  # Step 4: read back
  step="read"
  sleep 1
  local list_path="/api/v1/repositories/${repo_key}/artifacts"
  http_code="000"
  for _retry in $(seq 1 "$STEP_MAX_RETRIES"); do
    read_attempts=$_retry
    start_ms=$(date +%s%3N 2>/dev/null || date +%s)
    http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        -H "Authorization: Bearer ${token}" \
        "${BASE_URL}${list_path}" 2>/dev/null) || http_code="000"
    end_ms=$(date +%s%3N 2>/dev/null || date +%s)
    log_request "GET" "${list_path}" "${http_code}" "$(( end_ms - start_ms ))"
    if [ "$http_code" -ge 200 ] 2>/dev/null && [ "$http_code" -lt 300 ] 2>/dev/null; then
      break
    fi
    if ! _is_transient_status "$http_code"; then
      break
    fi
    sleep "$STEP_RETRY_DELAY"
  done
  if [ "$http_code" -lt 200 ] 2>/dev/null || [ "$http_code" -ge 300 ] 2>/dev/null; then
    printf 'auth=%d create-repo=%d upload=%d read=%d\n' \
      "$auth_attempts" "$create_attempts" "$upload_attempts" "$read_attempts" \
      > "${client_dir}/retries"
    echo "${step}" > "${client_dir}/failed"; return
  fi

  result="pass"
  printf 'auth=%d create-repo=%d upload=%d read=%d\n' \
    "$auth_attempts" "$create_attempts" "$upload_attempts" "$read_attempts" \
    > "${client_dir}/retries"
  echo "${result}" > "${client_dir}/result"
}

# ---------------------------------------------------------------------------
# Helper: launch N clients and count results
# ---------------------------------------------------------------------------

run_wave() {
  local count="$1"
  local wave_id="${2:-0}"
  rm -rf "${CLIENTS_DIR:?}"/*

  for i in $(seq 1 "$count"); do
    run_client "$i" "$wave_id" &
  done
  wait

  local passed=0
  local failed=0
  local fail_step_counts=""
  # Per-step retry-attempt totals across this wave. Reported alongside the
  # pass/fail counts so an operator can see whether failures concentrate at
  # a particular step or distribute evenly (the difference between a real
  # endpoint regression and a runner-capacity issue).
  local auth_total=0 create_total=0 upload_total=0 read_total=0
  for d in "${CLIENTS_DIR}"/*/; do
    [ -d "$d" ] || continue
    if [ -f "${d}result" ]; then
      passed=$(( passed + 1 ))
    elif [ -f "${d}failed" ]; then
      failed=$(( failed + 1 ))
      fail_step_counts="${fail_step_counts} $(cat "${d}failed")"
    else
      failed=$(( failed + 1 ))
    fi
    if [ -f "${d}retries" ]; then
      # Parse the four counters out of the retry-summary file.
      local row a c u r
      row=$(cat "${d}retries")
      a=$(echo "$row" | tr ' ' '\n' | awk -F= '$1=="auth"{print $2}')
      c=$(echo "$row" | tr ' ' '\n' | awk -F= '$1=="create-repo"{print $2}')
      u=$(echo "$row" | tr ' ' '\n' | awk -F= '$1=="upload"{print $2}')
      r=$(echo "$row" | tr ' ' '\n' | awk -F= '$1=="read"{print $2}')
      auth_total=$(( auth_total + ${a:-0} ))
      create_total=$(( create_total + ${c:-0} ))
      upload_total=$(( upload_total + ${u:-0} ))
      read_total=$(( read_total + ${r:-0} ))
    fi
  done

  echo "${passed} ${failed} ${auth_total} ${create_total} ${upload_total} ${read_total} ${fail_step_counts}"
}

# ---------------------------------------------------------------------------
# 5 parallel clients (should be fine)
# ---------------------------------------------------------------------------

begin_test "5 parallel API clients complete full workflow"
read passed failed auth_t create_t upload_t read_t steps <<< "$(run_wave 5 1)"
echo "  5 clients: ${passed} passed, ${failed} failed [${steps}]"
echo "  retry attempts: auth=${auth_t} create-repo=${create_t} upload=${upload_t} read=${read_t}"
if [ "$passed" -ge 4 ]; then
  pass
else
  fail "only ${passed}/5 clients completed (failures at: ${steps}; attempts a=${auth_t} c=${create_t} u=${upload_t} r=${read_t})"
fi

sleep 3

# ---------------------------------------------------------------------------
# 10 parallel clients
# ---------------------------------------------------------------------------

begin_test "10 parallel API clients complete full workflow"
read passed failed auth_t create_t upload_t read_t steps <<< "$(run_wave 10 2)"
echo "  10 clients: ${passed} passed, ${failed} failed [${steps}]"
echo "  retry attempts: auth=${auth_t} create-repo=${create_t} upload=${upload_t} read=${read_t}"
if [ "$passed" -ge 5 ]; then
  pass
else
  fail "only ${passed}/10 clients completed (failures at: ${steps}; attempts a=${auth_t} c=${create_t} u=${upload_t} r=${read_t})"
fi

sleep 3

# ---------------------------------------------------------------------------
# 20 parallel clients (capacity characterization)
# ---------------------------------------------------------------------------

begin_test "20 parallel API clients (capacity characterization)"
read passed failed auth_t create_t upload_t read_t steps <<< "$(run_wave 20 3)"
echo "  20 clients: ${passed} passed, ${failed} failed [${steps}]"
echo "  retry attempts: auth=${auth_t} create-repo=${create_t} upload=${upload_t} read=${read_t}"
# On a 1-core pod, bcrypt serialization limits throughput. Report results
# but only fail if fewer than half complete (catastrophic degradation).
if [ "$passed" -ge 10 ]; then
  pass
else
  fail "only ${passed}/20 clients completed (failures at: ${steps}; attempts a=${auth_t} c=${create_t} u=${upload_t} r=${read_t})"
fi

sleep 5

# ---------------------------------------------------------------------------
# Recovery after heavy load
# ---------------------------------------------------------------------------

begin_test "Backend responds to single request after 20-client burst"
if resp=$(curl -sf --max-time 10 -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null); then
  pass
else
  fail "backend unresponsive after load test"
fi

end_suite
