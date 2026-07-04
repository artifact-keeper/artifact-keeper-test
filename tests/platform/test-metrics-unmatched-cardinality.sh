#!/usr/bin/env bash
# test-metrics-unmatched-cardinality.sh - Unmatched request paths must collapse
# to a single path="unmatched" metrics series.
#
# Release gate for:
#   artifact-keeper#2217 - metrics path-label cardinality DoS
#
# The HTTP metrics middleware labels ak_http_requests_total with the matched
# route pattern (e.g. /api/v1/repositories/:key). Before #2217, a request that
# matched NO route fell back to the raw (normalized) request path, so an
# attacker spraying distinct junk paths (/.env, /.git/config, /wp-admin, ...)
# minted one new time-series per path -- an unbounded-cardinality DoS on the
# metrics registry / scrape pipeline. The v1.3.0 fix collapses every unmatched
# request to a single path="unmatched" series while matched routes keep their
# real (low-cardinality) route pattern.
#
# This gate probes several distinct junk paths and asserts:
#   1. No metrics series carries any of the literal junk path labels.
#   2. A single path="unmatched" series exists with a count >= the number of
#      junk probes we issued.
#   3. A genuinely matched route (/health) still keeps its real path label
#      (the fix must not collapse legitimate routes).
#
# Feature-gated on `metrics_unmatched_path` so it auto-skips on a 1.2.x
# backend (which emits per-path series) instead of hard-failing.
#
# Requires: curl, grep, awk

source "$(dirname "$0")/../lib/common.sh"

begin_suite "metrics-unmatched-cardinality"
auth_admin
setup_workdir

# Feature gate: skip on backends without the unmatched-path collapse.
# Must come before any probing so a gated skip exits fast.
begin_test "Backend supports metrics_unmatched_path (v1.3.0)"
if require_feature "metrics_unmatched_path"; then
  pass
else
  end_suite
  exit 0
fi

# Junk paths that match no route. Two classes:
#   - real-world scanner probes (#2217's motivating vectors)
#   - RUN_ID-unique paths that could ONLY appear as a metrics label if the
#     per-path cardinality bug were present (nothing else probes them).
JUNK_PATHS=(
  "/.env"
  "/.git/config"
  "/wp-admin"
  "/nonexistent-${RUN_ID}-alpha"
  "/nonexistent-${RUN_ID}-beta"
  "/nonexistent-${RUN_ID}-gamma"
)
NUM_PROBES=${#JUNK_PATHS[@]}

# Fetch /metrics text (public endpoint; no auth needed).
fetch_metrics() {
  curl -sf --max-time 15 "${BASE_URL}/metrics" 2>/dev/null
}

# Sum ak_http_requests_total across every series whose label set contains
# path="unmatched". There may be several (one per method/status combo), so we
# sum the trailing value column. Prints an integer (0 if none).
sum_unmatched_total() {
  local metrics="$1"
  echo "$metrics" \
    | grep '^ak_http_requests_total{' \
    | grep 'path="unmatched"' \
    | awk '{sum += $NF} END {printf "%.0f\n", sum+0}'
}

# =========================================================================
# Section 1: metrics endpoint reachable
# =========================================================================

begin_test "Metrics endpoint is available"
if fetch_metrics > /dev/null 2>&1; then
  pass
else
  fail "GET /metrics returned error"
fi

# =========================================================================
# Section 2: probe junk paths + one matched route, then scrape
# =========================================================================

begin_test "Probe unmatched junk paths and a matched route"
for p in "${JUNK_PATHS[@]}"; do
  curl -s -o /dev/null --max-time 10 "${BASE_URL}${p}" > /dev/null 2>&1 || true
done
# Hit a genuinely matched route a few times so its real-path series is present.
for _i in $(seq 1 3); do
  curl -s -o /dev/null --max-time 10 "${BASE_URL}/health" > /dev/null 2>&1 || true
done
# Give the registry a moment to record the completed requests.
sleep 2
METRICS="$(fetch_metrics || true)"
if [ -n "$METRICS" ]; then
  pass
else
  fail "GET /metrics returned an empty body after probing"
fi

# =========================================================================
# Section 3: no per-junk-path series exist (cardinality is collapsed)
# =========================================================================

begin_test "No metrics series carries a literal junk path label"
leaked=""
for p in "${JUNK_PATHS[@]}"; do
  # Only consider the request metrics with an explicit path="<junk>" label.
  if echo "$METRICS" | grep -q "path=\"${p}\""; then
    leaked="${leaked} ${p}"
  fi
done
if [ -z "$leaked" ]; then
  pass
else
  fail "metrics leaked per-path series for unmatched paths:${leaked}" \
    "$(echo "$METRICS" | grep '^ak_http_requests_total{' | grep 'nonexistent\|\.env\|\.git\|wp-admin' | head -20)"
fi

# =========================================================================
# Section 4: a single unmatched series exists with count >= probes
# =========================================================================

begin_test "A path=\"unmatched\" series exists with count >= ${NUM_PROBES}"
if ! echo "$METRICS" | grep '^ak_http_requests_total{' | grep -q 'path="unmatched"'; then
  fail "no ak_http_requests_total series with path=\"unmatched\" found" \
    "$(echo "$METRICS" | grep '^ak_http_requests_total{' | head -20)"
else
  UNMATCHED_TOTAL=$(sum_unmatched_total "$METRICS")
  if [ "$UNMATCHED_TOTAL" -ge "$NUM_PROBES" ] 2>/dev/null; then
    pass
  else
    fail "unmatched total ${UNMATCHED_TOTAL} < probes ${NUM_PROBES} (probes not attributed to the unmatched series)"
  fi
fi

# =========================================================================
# Section 5: matched routes keep their real path label
# =========================================================================

begin_test "Matched route /health keeps its real path label"
if echo "$METRICS" | grep '^ak_http_requests_total{' | grep -q 'path="/health"'; then
  pass
else
  fail "matched route /health has no path=\"/health\" series (fix over-collapsed a real route)" \
    "$(echo "$METRICS" | grep '^ak_http_requests_total{' | head -20)"
fi

end_suite
