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
# Knobs (override via env):
#   STEP_MAX_RETRIES  - attempts per step (default 3, same as the old auth budget)
#   STEP_RETRY_DELAY  - seconds between attempts (default 1)
#
# Each client's failure file now also captures the per-step retry counts so an
# operator can tell "create-repo really fails N% of the time" from "create-repo
# eats the retries because earlier steps already burned them".
STEP_MAX_RETRIES="${STEP_MAX_RETRIES:-3}"
STEP_RETRY_DELAY="${STEP_RETRY_DELAY:-1}"

run_client() {
  local client_id="$1"
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
    if resp=$(curl -sf --max-time 10 -X POST "${BASE_URL}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null); then
      end_ms=$(date +%s%3N 2>/dev/null || date +%s)
      log_request "POST" "/api/v1/auth/login" "200" "$(( end_ms - start_ms ))"
      token=$(echo "$resp" | jq -r '.access_token // .token // empty') || true
      [ -n "$token" ] && break
    else
      end_ms=$(date +%s%3N 2>/dev/null || date +%s)
      log_request "POST" "/api/v1/auth/login" "000" "$(( end_ms - start_ms ))"
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
  local repo_key="stress-client-${client_id}-${RUN_ID}"
  http_code="000"
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
      break
    fi
    # 409 means the repo already exists from a previous attempt that
    # succeeded server-side after we timed out. Treat as success and move on.
    if [ "$http_code" = "409" ]; then
      break
    fi
    sleep "$STEP_RETRY_DELAY"
  done
  if [ "$http_code" -lt 200 ] 2>/dev/null || { [ "$http_code" -ge 300 ] 2>/dev/null && [ "$http_code" != "409" ]; }; then
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
  rm -rf "${CLIENTS_DIR:?}"/*

  for i in $(seq 1 "$count"); do
    run_client "$i" &
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
read passed failed auth_t create_t upload_t read_t steps <<< "$(run_wave 5)"
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
read passed failed auth_t create_t upload_t read_t steps <<< "$(run_wave 10)"
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
read passed failed auth_t create_t upload_t read_t steps <<< "$(run_wave 20)"
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
