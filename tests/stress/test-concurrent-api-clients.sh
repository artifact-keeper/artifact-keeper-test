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

run_client() {
  local client_id="$1"
  local client_dir="${CLIENTS_DIR}/${client_id}"
  mkdir -p "$client_dir"

  local result="fail"
  local step="start"
  local start_ms end_ms http_code

  # Step 1: authenticate
  step="auth"
  local token=""
  for _retry in 1 2 3; do
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
    sleep 1
  done
  [ -z "$token" ] && { echo "${step}" > "${client_dir}/failed"; return; }

  # Step 2: create repo
  step="create-repo"
  local repo_key="stress-client-${client_id}-${RUN_ID}"
  start_ms=$(date +%s%3N 2>/dev/null || date +%s)
  http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json" \
      -d "{\"key\":\"${repo_key}\",\"name\":\"${repo_key}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" \
      "${BASE_URL}/api/v1/repositories" 2>/dev/null) || http_code="000"
  end_ms=$(date +%s%3N 2>/dev/null || date +%s)
  log_request "POST" "/api/v1/repositories" "${http_code}" "$(( end_ms - start_ms ))"
  if [ "$http_code" -lt 200 ] 2>/dev/null || [ "$http_code" -ge 300 ] 2>/dev/null; then
    echo "${step}" > "${client_dir}/failed"; return
  fi

  # Step 3: upload artifact
  step="upload"
  local upload_path="/api/v1/repositories/${repo_key}/artifacts/test/payload.bin"
  echo "client-${client_id}-payload-${RUN_ID}" > "${client_dir}/payload.bin"
  start_ms=$(date +%s%3N 2>/dev/null || date +%s)
  http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X PUT \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@${client_dir}/payload.bin" \
      "${BASE_URL}${upload_path}" 2>/dev/null) || http_code="000"
  end_ms=$(date +%s%3N 2>/dev/null || date +%s)
  log_request "PUT" "${upload_path}" "${http_code}" "$(( end_ms - start_ms ))"
  if [ "$http_code" -lt 200 ] 2>/dev/null || [ "$http_code" -ge 300 ] 2>/dev/null; then
    echo "${step}" > "${client_dir}/failed"; return
  fi

  # Step 4: read back
  step="read"
  sleep 1
  local list_path="/api/v1/repositories/${repo_key}/artifacts"
  start_ms=$(date +%s%3N 2>/dev/null || date +%s)
  http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer ${token}" \
      "${BASE_URL}${list_path}" 2>/dev/null) || http_code="000"
  end_ms=$(date +%s%3N 2>/dev/null || date +%s)
  log_request "GET" "${list_path}" "${http_code}" "$(( end_ms - start_ms ))"
  if [ "$http_code" -lt 200 ] 2>/dev/null || [ "$http_code" -ge 300 ] 2>/dev/null; then
    echo "${step}" > "${client_dir}/failed"; return
  fi

  result="pass"
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
  done

  echo "${passed} ${failed} ${fail_step_counts}"
}

# ---------------------------------------------------------------------------
# 5 parallel clients (should be fine)
# ---------------------------------------------------------------------------

begin_test "5 parallel API clients complete full workflow"
read passed failed steps <<< "$(run_wave 5)"
echo "  5 clients: ${passed} passed, ${failed} failed [${steps}]"
if [ "$passed" -ge 4 ]; then
  pass
else
  fail "only ${passed}/5 clients completed (failures at: ${steps})"
fi

sleep 3

# ---------------------------------------------------------------------------
# 10 parallel clients
# ---------------------------------------------------------------------------

begin_test "10 parallel API clients complete full workflow"
read passed failed steps <<< "$(run_wave 10)"
echo "  10 clients: ${passed} passed, ${failed} failed [${steps}]"
if [ "$passed" -ge 5 ]; then
  pass
else
  fail "only ${passed}/10 clients completed (failures at: ${steps})"
fi

sleep 3

# ---------------------------------------------------------------------------
# 20 parallel clients (capacity characterization)
# ---------------------------------------------------------------------------

begin_test "20 parallel API clients (capacity characterization)"
read passed failed steps <<< "$(run_wave 20)"
echo "  20 clients: ${passed} passed, ${failed} failed [${steps}]"
# On a 1-core pod, bcrypt serialization limits throughput. Report results
# but only fail if fewer than half complete (catastrophic degradation).
if [ "$passed" -ge 10 ]; then
  pass
else
  fail "only ${passed}/20 clients completed (failures at: ${steps})"
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
