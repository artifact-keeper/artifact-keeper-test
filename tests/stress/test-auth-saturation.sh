#!/usr/bin/env bash
# test-auth-saturation.sh - Auth endpoint saturation stress test
#
# Measures how the auth endpoint degrades under increasing concurrent load.
# Sends parallel login requests in waves (5, 10, 20, 40) and records
# success rate and p95 response time at each level. Fails if the backend
# returns a genuine server fault (500/502/504) or stops responding entirely.
#
# 503 Service Unavailable is NOT a failure here: per backend #1437 it is the
# intended saturation/overload response. When the bcrypt-permit concurrency
# cap is saturated, the auth path sheds load with 503 (correct backpressure)
# instead of running the request and crashing. 429 (rate-limit) and 503
# (saturation) are both treated as the backend correctly protecting itself.
#
# This test characterizes backend capacity, not correctness. It answers:
# "How many concurrent auth requests can the backend handle?"
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-saturation"
auth_admin
setup_workdir

RESULTS_DIR="${WORK_DIR}/auth-results"
mkdir -p "$RESULTS_DIR"

# ---------------------------------------------------------------------------
# Helper: fire N parallel login requests, collect status codes + timings
# ---------------------------------------------------------------------------

fire_auth_wave() {
  local count="$1"
  local wave_dir="${RESULTS_DIR}/wave-${count}"
  mkdir -p "$wave_dir"

  for i in $(seq 1 "$count"); do
    (
      start_ms=$(date +%s%3N 2>/dev/null || date +%s)
      http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
        -X POST "${BASE_URL}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null) || http_code="000"
      end_ms=$(date +%s%3N 2>/dev/null || date +%s)
      elapsed=$(( end_ms - start_ms ))
      echo "${http_code} ${elapsed}" > "${wave_dir}/${i}.txt"
      log_request "POST" "/api/v1/auth/login?wave=${count}" "${http_code}" "${elapsed}"
    ) &
  done
  wait
}

# ---------------------------------------------------------------------------
# Helper: summarize a wave's results
# ---------------------------------------------------------------------------

summarize_wave() {
  local wave_dir="$1"
  local total=0
  local success=0
  local rate_limited=0
  local saturated=0
  local server_error=0
  local timeout=0
  local max_ms=0

  for f in "${wave_dir}"/*.txt; do
    [ -f "$f" ] || continue
    total=$(( total + 1 ))
    code=$(awk '{print $1}' "$f")
    ms=$(awk '{print $2}' "$f")
    [ "$ms" -gt "$max_ms" ] 2>/dev/null && max_ms="$ms"

    if [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 300 ] 2>/dev/null; then
      success=$(( success + 1 ))
    elif [ "$code" = "429" ]; then
      rate_limited=$(( rate_limited + 1 ))
    elif [ "$code" = "503" ]; then
      # 503 is the INTENDED overload/saturation response (backend #1437):
      # when the bcrypt concurrency permit cap is saturated, the auth path
      # sheds load with 503 Service Unavailable rather than crashing. This
      # is correct backpressure, so 503 is counted separately from a genuine
      # server fault (500/502/504), which still indicates the backend broke.
      saturated=$(( saturated + 1 ))
    elif [ "$code" -ge 500 ] 2>/dev/null; then
      server_error=$(( server_error + 1 ))
    elif [ "$code" = "000" ]; then
      timeout=$(( timeout + 1 ))
    fi
  done

  echo "${total} ${success} ${rate_limited} ${saturated} ${server_error} ${timeout} ${max_ms}"
}

# ---------------------------------------------------------------------------
# Wave 1: 5 concurrent auth requests (baseline)
# ---------------------------------------------------------------------------

begin_test "Auth under 5 concurrent requests"
fire_auth_wave 5
read total success rate_limited saturated server_error timeout max_ms <<< "$(summarize_wave "${RESULTS_DIR}/wave-5")"
echo "  5 concurrent: ${success}/${total} success, ${rate_limited} rate-limited, ${saturated} 503-saturation, ${server_error} 5xx-fault, ${timeout} timeout, max ${max_ms}ms"
if [ "$success" -ge 4 ]; then
  pass
else
  fail "expected >= 4/5 success at concurrency 5, got ${success}"
fi

# ---------------------------------------------------------------------------
# Wave 2: 10 concurrent auth requests
# ---------------------------------------------------------------------------

sleep 2

begin_test "Auth under 10 concurrent requests"
fire_auth_wave 10
read total success rate_limited saturated server_error timeout max_ms <<< "$(summarize_wave "${RESULTS_DIR}/wave-10")"
echo "  10 concurrent: ${success}/${total} success, ${rate_limited} rate-limited, ${saturated} 503-saturation, ${server_error} 5xx-fault, ${timeout} timeout, max ${max_ms}ms"
if [ "$success" -ge 7 ]; then
  pass
elif [ "$(( success + rate_limited + saturated ))" -ge 8 ]; then
  pass  # 429 rate-limit and 503 saturation are acceptable: backend protecting itself
else
  fail "expected >= 7/10 success (or 429/503 backpressure) at concurrency 10, got ${success} success + ${rate_limited} rate-limited + ${saturated} saturated"
fi

# ---------------------------------------------------------------------------
# Wave 3: 20 concurrent auth requests
# ---------------------------------------------------------------------------

sleep 3

begin_test "Auth under 20 concurrent requests"
fire_auth_wave 20
read total success rate_limited saturated server_error timeout max_ms <<< "$(summarize_wave "${RESULTS_DIR}/wave-20")"
echo "  20 concurrent: ${success}/${total} success, ${rate_limited} rate-limited, ${saturated} 503-saturation, ${server_error} 5xx-fault, ${timeout} timeout, max ${max_ms}ms"
# At 20 concurrent, we expect some degradation. Key metric: no genuine server
# faults (500/502/504) or total timeouts. 503 saturation is acceptable
# backpressure (backend #1437) and is NOT counted as a server fault here.
if [ "$server_error" -le 2 ] && [ "$timeout" -le 2 ]; then
  pass
else
  fail "backend returned ${server_error} 5xx faults (excl. 503) and ${timeout} timeouts at concurrency 20"
fi

# ---------------------------------------------------------------------------
# Wave 4: 40 concurrent auth requests (beyond expected capacity)
# ---------------------------------------------------------------------------

sleep 5

begin_test "Auth under 40 concurrent requests (capacity limit)"
fire_auth_wave 40
read total success rate_limited saturated server_error timeout max_ms <<< "$(summarize_wave "${RESULTS_DIR}/wave-40")"
echo "  40 concurrent: ${success}/${total} success, ${rate_limited} rate-limited, ${saturated} 503-saturation, ${server_error} 5xx-fault, ${timeout} timeout, max ${max_ms}ms"
# At 40 concurrent bcrypt on a 1-core pod, the backend sheds load. Per backend
# #1437, the INTENDED saturation response is 503 Service Unavailable: when the
# bcrypt-permit cap is saturated, the auth path returns 503 (correct
# backpressure) rather than running the request and crashing. So 503 is a
# valid, expected response under this load and is NOT a failure.
#
# The key assertion is still that the backend does not break: zero genuine
# server faults (500 Internal Server Error / 502 Bad Gateway / 504 Gateway
# Timeout). Those indicate a crash, panic, or upstream failure, which 503 does
# not. Timeouts (client-side, code 000) remain acceptable here (CPU saturation).
if [ "$server_error" -eq 0 ]; then
  if [ "$saturated" -gt 0 ]; then
    echo "  ${saturated}/${total} requests returned 503 (intended saturation backpressure per backend #1437)"
  fi
  pass
else
  fail "backend returned ${server_error} genuine 5xx faults (500/502/504) at concurrency 40; 503 saturation and client timeouts are acceptable, a server fault is not (${saturated} requests were 503)"
fi

# ---------------------------------------------------------------------------
# Recovery: verify backend recovers after load
# ---------------------------------------------------------------------------

sleep 10

begin_test "Backend recovers after auth saturation"
recovered=false
for _try in 1 2 3 4 5; do
  if resp=$(curl -sf --max-time 10 -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null); then
    token=$(echo "$resp" | jq -r '.access_token // .token // empty') || true
    if [ -n "$token" ]; then
      recovered=true
      break
    fi
  fi
  sleep 3
done
if $recovered; then
  pass
else
  fail "backend did not recover after 25s cool-down"
fi

end_suite
