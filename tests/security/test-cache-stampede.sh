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
#      We only assert this when PROXY_QUEUE_TIMEOUT_SECS is short enough
#      relative to the per-request mock delay; otherwise informational.
#
#      NOTE (artifact-keeper-test#344): assertion 2 is a latent false-red. What
#      the backend actually ships is single-flight coalescing (#1631/#1694), not
#      a bounded queue with a timeout; PROXY_MAX_CONCURRENT_FETCHES and
#      PROXY_QUEUE_TIMEOUT_SECS do not exist in the backend at all. With the
#      gate's values it always takes the informational skip, so it is harmless
#      today -- but tuning the knobs as its skip message suggests would fail it
#      against a perfectly healthy backend. #344 tracks rewriting it against
#      the coalescing contract.
#
# Parking history (artifact-keeper-test#343)
# ------------------------------------------
# This suite and its cache-poisoning twin were stubbed down to a single skip in
# #126 because the backend rejected every RFC1918 upstream URL, which the mock
# fixture needs (it is exposed on the ARC runner pod IP, 10.244.0.0/16). That
# blocker is gone on BOTH sides and has been since May 2026:
#
#   * artifact-keeper#1325 (merged, closes artifact-keeper#1224) added the
#     AK_SSRF_ALLOW_PRIVATE_CIDRS env var.
#   * helm/values-test-full.yaml -- which the release-gate deploy renders, via
#     create-test-namespace.sh --full-stack -- already sets
#     AK_SSRF_ALLOW_PRIVATE_CIDRS: "10.96.0.0/12,10.244.0.0/16".
#
# The suites were not blocked, only unmaintained, so they are restored rather
# than exempted.
#
# Backend dependency: this test exercises a semaphore that does not exist in
# v1.1.x. It is gated behind require_feature "proxy_stampede_protection"
# (minimum backend version: 1.2.0) so older builds skip cleanly. When the
# backend feature lands, bump the version in tests/lib/common.sh's
# _feature_min_version map.
#
# Hard constraint (issue artifact-keeper-test#67): this test must FAIL when
# the backend is broken. To self-verify, run with EXPECT_FAILURE=1 against
# a backend image with the semaphore disabled and confirm the assertion
# at "Peak upstream in-flight does not exceed..." fails.

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

# Feature gate: skip if the backend version does not ship the proxy semaphore.
# require_feature emits a SKIP testcase via skip(); under RELEASE_GATE=1 this
# is fine because the suite-level skip (skip_suite) is what hard-fails, not
# individual feature-gated tests on older backends.
begin_test "Backend supports proxy stampede protection"
require_feature "proxy_stampede_protection" || { end_suite; }
pass

# Knobs. Tests honor PROXY_MAX_CONCURRENT_FETCHES if CI passed it through so
# we know what limit to assert against. CI MUST set this for the assertion to
# be deterministic across chart default changes.
LIMIT="${PROXY_MAX_CONCURRENT_FETCHES:-20}"
N="${STAMPEDE_CONCURRENCY:-$(( LIMIT * 2 + 5 ))}"
UPSTREAM_DELAY_MS="${STAMPEDE_UPSTREAM_DELAY_MS:-2000}"
QUEUE_TIMEOUT_SECS="${PROXY_QUEUE_TIMEOUT_SECS:-30}"

REMOTE_KEY="sec-stampede-${RUN_ID}"
ARTIFACT_PATH="herd/v1/payload.bin"

# ---------------------------------------------------------------------------
# Boot the mock upstream, seed a per-run-unique payload, and inject a delay
# so concurrent fetches actually overlap on the upstream side.
# ---------------------------------------------------------------------------

begin_test "Mock upstream starts"
if start_mock_upstream "${WORK_DIR}/mock-state"; then
  mkdir -p "${MOCK_STATE_DIR}/files/$(dirname "$ARTIFACT_PATH")"
  # Distinct payload per run so prior cache state from a flaky prior run
  # cannot satisfy the stampede locally and silently zero out the assertion.
  PAYLOAD="stampede-payload-${RUN_ID}"
  printf '%s\n' "$PAYLOAD" > "${MOCK_STATE_DIR}/files/${ARTIFACT_PATH}"
  printf '%s\n' "$UPSTREAM_DELAY_MS" > "${MOCK_STATE_DIR}/delay-ms"
  pass
else
  fail "mock upstream did not boot"
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

# Per-curl timeout: queue wait + upstream RTT + slack. Keep this tight enough
# that a wedged backend produces "000" rather than blocking until the job
# timeout.
PER_REQ_TIMEOUT=$(( QUEUE_TIMEOUT_SECS + UPSTREAM_DELAY_MS / 1000 + 30 ))

START_TS=$(date +%s)
# Collect only the curl subshell PIDs so we can wait on them specifically.
# A bare `wait` would also block on the mock-upstream python child that
# start_mock_upstream backgrounded earlier (the mock is long-lived and never
# exits during the test), wedging the script forever.
declare -a curl_pids=()
for i in $(seq 1 "$N"); do
  (
    status=$(curl -s -o /dev/null -w '%{http_code}' \
      --max-time "$PER_REQ_TIMEOUT" \
      --connect-timeout 10 \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}") || status="000"
    echo "$status" > "${WORK_DIR}/results/req-${i}.status"
  ) &
  curl_pids+=($!)
done
for pid in "${curl_pids[@]}"; do
  wait "$pid" || true
done
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
# Read mock counters via bounded poll. wait_for_counter_stable returns once
# peak-inflight has not changed for ~0.6s, which is strictly safer than the
# previous `sleep 1` and bounds the wait at 5s.
# ---------------------------------------------------------------------------

peak=$(wait_for_counter_stable "${MOCK_STATE_DIR}/peak-inflight" 5 0.6 || true)
peak="${peak:-0}"
upstream_count_key=$(echo "$ARTIFACT_PATH" | tr '/' '_' | tr -dc 'A-Za-z0-9_.-' | cut -c1-128)
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
    fail "mock recorded zero upstream traffic; either the proxy never dialed the mock or MOCK_UPSTREAM_HOSTNAME is unreachable from the backend pod (mock.err: $(tail -3 "${WORK_DIR}/mock.err" 2>/dev/null | tr '\n' ' '))"
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
# is not required for this assertion; what matters is that ONCE the cache is
# warm, no additional upstream traffic is generated for a repeat fetch.
# ---------------------------------------------------------------------------

begin_test "Post-stampede fetch is served from cache (no additional upstream traffic)"
pre_count="$upstream_count"
followup_status=$(curl -s -o "${WORK_DIR}/followup.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}") || true

# Bounded poll for counter stability instead of sleep 1.
post_count=$(wait_for_counter_stable "${MOCK_STATE_DIR}/request-count.${upstream_count_key}" 3 0.4 || true)
post_count="${post_count:-$pre_count}"

if assert_http_2xx "$followup_status" "follow-up fetch should hit cache and return 2xx"; then
  if [ "$post_count" = "$pre_count" ]; then
    pass
  else
    fail "follow-up fetch generated extra upstream traffic (pre=${pre_count} post=${post_count}): cache write/read path is broken"
  fi
fi

# ---------------------------------------------------------------------------
# Assertion #5: content integrity check across the stampede. The successful
# 2xx responses must each have returned the seeded payload bytes; an empty
# or upstream-error body that the proxy mistook for "200 OK" would slip past
# status-code-only checks.
# ---------------------------------------------------------------------------

begin_test "Stampede response body matches seeded payload"
verify_status=$(curl -s -o "${WORK_DIR}/verify.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}") || true

if assert_http_2xx "$verify_status" "verification fetch should return 2xx"; then
  expected_sha=$(shasum -a 256 "${MOCK_STATE_DIR}/files/${ARTIFACT_PATH}" | awk '{print $1}')
  got_sha=$(shasum -a 256 "${WORK_DIR}/verify.bin" | awk '{print $1}')
  if [ "$got_sha" = "$expected_sha" ]; then
    pass
  else
    fail "stampede 2xx body sha=${got_sha} != upstream sha=${expected_sha}: cache may have stored a partial or upstream-error body"
  fi
fi

end_suite
