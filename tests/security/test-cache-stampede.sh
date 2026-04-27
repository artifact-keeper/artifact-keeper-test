#!/usr/bin/env bash
# test-cache-stampede.sh - T2-12: Cache stampede / thundering-herd prevention
#
# When N concurrent clients ask the proxy for the same uncached artifact, a
# correctly-sized backend bounds peak upstream concurrency at
# `proxy_max_concurrent_fetches` (default 20). A broken backend forwards all
# N requests upstream simultaneously and either drowns the upstream, blows
# its memory budget, or both. Customer pain #1
# (https://github.com/orgs/artifact-keeper/discussions/872) was triggered by
# this exact failure mode in v1.1.7.
#
# This suite verifies two assertions, in order of importance:
#
#   1. Peak upstream in-flight count <= proxy_max_concurrent_fetches.
#      Measured by the mock upstream's own per-handler counter.
#
#   2. When the queue saturates and queue_timeout fires, the backend rejects
#      with 503 (queue full) -- it does NOT silently dispatch every request.
#      We can only assert this if PROXY_QUEUE_TIMEOUT_SECS was set short
#      enough relative to the per-request mock delay; tests pass-through if
#      the env wasn't tuned.
#
# Hard constraint (issue artifact-keeper-test#67): this test must FAIL when
# the backend is broken. To self-verify, run against a backend image with
# the semaphore disabled and confirm the assertion at line ~155 fails with
# "peak in-flight ${peak} exceeded limit ${LIMIT}".

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cache-stampede"

if ! command -v python3 >/dev/null 2>&1; then
  skip_suite "python3 not available; cache-stampede needs the mock upstream fixture"
fi

if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip_suite "MOCK_UPSTREAM_HOSTNAME unset; CI must set this to a name the backend can resolve to the test runner pod"
fi

auth_admin
setup_workdir

# Knobs. Tests honor PROXY_MAX_CONCURRENT_FETCHES if CI passed it through so
# we know what limit to assert against; otherwise we use the documented
# default of 20 and just verify peak <= 20 with N strictly greater.
LIMIT="${PROXY_MAX_CONCURRENT_FETCHES:-20}"
N="${STAMPEDE_CONCURRENCY:-$(( LIMIT * 2 + 5 ))}"
UPSTREAM_DELAY_MS="${STAMPEDE_UPSTREAM_DELAY_MS:-2000}"
QUEUE_TIMEOUT_SECS="${PROXY_QUEUE_TIMEOUT_SECS:-30}"

MOCK_PORT="${MOCK_UPSTREAM_PORT:-18080}"
MOCK_STATE_DIR="${WORK_DIR}/mock-upstream"
MOCK_BASE_URL="http://${MOCK_UPSTREAM_HOSTNAME}:${MOCK_PORT}"
REMOTE_KEY="sec-stampede-${RUN_ID}"

mkdir -p "${MOCK_STATE_DIR}/files"
ARTIFACT_PATH="herd/v1/payload.bin"
mkdir -p "${MOCK_STATE_DIR}/files/$(dirname "$ARTIFACT_PATH")"
# Distinct payload per run so prior cache state from a flaky prior run can't
# satisfy the stampede locally and silently zero out the assertion.
PAYLOAD="stampede-payload-${RUN_ID}"
printf '%s\n' "$PAYLOAD" > "${MOCK_STATE_DIR}/files/${ARTIFACT_PATH}"
printf '%s\n' "$UPSTREAM_DELAY_MS" > "${MOCK_STATE_DIR}/delay-ms"

# ---------------------------------------------------------------------------
# Boot the mock upstream
# ---------------------------------------------------------------------------

MOCK_PID=""
start_mock() {
  MOCK_STATE_DIR="$MOCK_STATE_DIR" MOCK_PORT="$MOCK_PORT" \
    python3 "$(dirname "$0")/../lib/mock-upstream.py" \
    > "${WORK_DIR}/mock.out" 2> "${WORK_DIR}/mock.err" &
  MOCK_PID=$!
  for _ in $(seq 1 20); do
    # Probe with a path the mock has zero-delay handling for: it doesn't,
    # so we just wait on TCP readiness.
    if curl -sf --max-time 2 -o /dev/null "http://127.0.0.1:${MOCK_PORT}/__readyz" 2>/dev/null; then
      return 0
    fi
    # 404 also means "server up". Accept any response that isn't connect-refused.
    code=$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${MOCK_PORT}/__readyz" 2>/dev/null) || code="000"
    if [ "$code" != "000" ]; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

stop_mock() {
  if [ -n "$MOCK_PID" ] && kill -0 "$MOCK_PID" 2>/dev/null; then
    kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
  fi
}
trap 'stop_mock; rm -rf "$WORK_DIR"' EXIT

begin_test "Mock upstream starts"
if start_mock; then
  pass
else
  fail "mock upstream did not become reachable on 127.0.0.1:${MOCK_PORT}"
  end_suite
fi

# ---------------------------------------------------------------------------
# Create the remote repo. We deliberately do NOT prime the cache: the test
# is about what happens when N concurrent clients all hit a cold cache key.
# ---------------------------------------------------------------------------

begin_test "Create remote repo pointing at slow mock upstream"
if create_remote_repo "$REMOTE_KEY" "generic" "$MOCK_BASE_URL"; then
  pass
else
  fail "could not create remote repo for upstream ${MOCK_BASE_URL}"
  end_suite
fi

# ---------------------------------------------------------------------------
# Fire N concurrent GETs at the cold cache. Capture each request's HTTP
# status so we can classify outcomes.
# ---------------------------------------------------------------------------

begin_test "Fire ${N} concurrent GETs against cold proxy cache (limit=${LIMIT}, delay=${UPSTREAM_DELAY_MS}ms)"
mkdir -p "${WORK_DIR}/results"

START_TS=$(date +%s)
for i in $(seq 1 "$N"); do
  (
    status=$(curl -s -o /dev/null -w '%{http_code}' \
      --max-time $(( QUEUE_TIMEOUT_SECS + UPSTREAM_DELAY_MS / 1000 + 30 )) \
      --connect-timeout 10 \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}") || status="000"
    echo "$status" > "${WORK_DIR}/results/req-${i}.status"
  ) &
done
wait
END_TS=$(date +%s)
echo "  elapsed: $(( END_TS - START_TS ))s"
pass

# ---------------------------------------------------------------------------
# Classify outcomes.
# ---------------------------------------------------------------------------

success_count=0
queue_full_count=0
other_count=0
for i in $(seq 1 "$N"); do
  s=$(cat "${WORK_DIR}/results/req-${i}.status" 2>/dev/null || echo "000")
  if [ "$s" -ge 200 ] 2>/dev/null && [ "$s" -lt 300 ] 2>/dev/null; then
    success_count=$(( success_count + 1 ))
  elif [ "$s" = "503" ]; then
    queue_full_count=$(( queue_full_count + 1 ))
  else
    other_count=$(( other_count + 1 ))
    echo "  req-${i}: HTTP ${s}"
  fi
done
echo "  outcomes: success=${success_count} queue_full=${queue_full_count} other=${other_count}"

# ---------------------------------------------------------------------------
# Read mock counters: peak concurrent in-flight upstream fetches and the
# total number of upstream GETs the backend issued for this artifact.
# ---------------------------------------------------------------------------

# Mock writes peak-inflight and request-count.* during request handling.
# Allow a brief flush window since file writes are async w.r.t. our wait.
sleep 1

peak=$(cat "${MOCK_STATE_DIR}/peak-inflight" 2>/dev/null || echo 0)
upstream_count_key=$(echo "$ARTIFACT_PATH" | tr '/' '_')
upstream_count=$(cat "${MOCK_STATE_DIR}/request-count.${upstream_count_key}" 2>/dev/null || echo 0)
echo "  upstream peak in-flight: ${peak}"
echo "  upstream total fetches:  ${upstream_count}"

# ---------------------------------------------------------------------------
# Load-bearing assertion #1: peak upstream concurrency must not exceed the
# configured semaphore limit. This is THE assertion that fails on a broken
# backend (semaphore disabled / limit raised / fetch path bypassed).
# ---------------------------------------------------------------------------

begin_test "Peak upstream in-flight does not exceed proxy_max_concurrent_fetches (${LIMIT})"
if [ "$peak" -le "$LIMIT" ]; then
  if [ "$peak" -gt 0 ]; then
    pass
  else
    fail "mock recorded zero upstream traffic; either backend served from a stale cache, the proxy never dialed the mock, or the mock-upstream hostname is unreachable from the backend pod"
  fi
else
  fail "peak upstream in-flight ${peak} exceeded configured limit ${LIMIT}: stampede protection is off"
fi

# ---------------------------------------------------------------------------
# Assertion #2: at least one request was served. With a working semaphore
# and a non-trivial delay, the first wave succeeds; the rest either queue
# (and succeed once a permit frees up) or 503 if queue_timeout fires.
# ---------------------------------------------------------------------------

begin_test "At least one client receives a successful proxy response"
if [ "$success_count" -ge 1 ]; then
  pass
else
  fail "no client got a 2xx response (success=${success_count} queue_full=${queue_full_count} other=${other_count}): proxy is wedged"
fi

# ---------------------------------------------------------------------------
# Assertion #3: if N exceeds limit AND queue_timeout was tuned short, we
# expect SOME 503s. This is informational on default settings (queue
# timeout of 30s usually long enough that everyone eventually gets in) so
# we treat it as a soft assertion: skip when N <= LIMIT or the timeout is
# generous.
# ---------------------------------------------------------------------------

begin_test "When N > limit and queue_timeout is short, queue-full responses appear"
expected_queueing=0
# Heuristic: if N > LIMIT and the per-request delay times the overflow exceeds
# queue_timeout, requests should hit the timeout path.
overflow=$(( N - LIMIT ))
projected_wait_secs=$(( overflow * UPSTREAM_DELAY_MS / 1000 / LIMIT ))
if [ "$overflow" -gt 0 ] && [ "$projected_wait_secs" -gt "$QUEUE_TIMEOUT_SECS" ]; then
  expected_queueing=1
fi

if [ "$expected_queueing" -eq 1 ]; then
  if [ "$queue_full_count" -ge 1 ]; then
    pass
  else
    fail "expected at least one 503 (overflow=${overflow}, projected_wait=${projected_wait_secs}s, queue_timeout=${QUEUE_TIMEOUT_SECS}s) but saw none: queue_timeout enforcement may be broken"
  fi
else
  skip "queueing not expected with N=${N}, LIMIT=${LIMIT}, delay=${UPSTREAM_DELAY_MS}ms, queue_timeout=${QUEUE_TIMEOUT_SECS}s; tune PROXY_QUEUE_TIMEOUT_SECS or STAMPEDE_UPSTREAM_DELAY_MS to exercise this branch"
fi

# ---------------------------------------------------------------------------
# Assertion #4: a follow-up fetch hits the cache. Coalescing (single-flight)
# is not implemented in v1.1.x, so upstream_count >= 1 is acceptable; what
# matters is that ONCE the cache is warm, no additional upstream traffic
# is generated.
# ---------------------------------------------------------------------------

begin_test "Post-stampede fetch is served from cache (no additional upstream traffic)"
pre_count="$upstream_count"
followup_status=$(curl -s -o "${WORK_DIR}/followup.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}") || true
sleep 1
post_count=$(cat "${MOCK_STATE_DIR}/request-count.${upstream_count_key}" 2>/dev/null || echo 0)

if assert_http_2xx "$followup_status" "follow-up fetch should hit cache and return 2xx"; then
  if [ "$post_count" = "$pre_count" ]; then
    pass
  else
    fail "follow-up fetch generated extra upstream traffic (pre=${pre_count} post=${post_count}): cache write/read path is broken"
  fi
fi

end_suite
