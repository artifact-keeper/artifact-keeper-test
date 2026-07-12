#!/usr/bin/env bash
# common.sh - Shared test helpers for artifact-keeper-test
#
# Source this at the top of every test script:
#   source "$(dirname "$0")/../lib/common.sh"
#
# Provides: configuration defaults, auth, HTTP helpers, repository helpers,
# test framework (begin_suite/begin_test/pass/fail/end_suite with JUnit XML),
# assertions, and utility functions.
#
# Stress-test knobs (consumed by tests/stress/*.sh, documented here so that
# `grep -nE 'STEP_|SUSTAINED_' tests/lib/common.sh` is enough to find them):
#
#   STEP_MAX_RETRIES                attempts per step in test-concurrent-api-clients
#                                   (default 3); retries only fire on transient-class
#                                   HTTP statuses (000/401/429/503/5xx)
#   STEP_RETRY_DELAY                seconds between attempts (default 1)
#   SUSTAINED_DURATION              sustained-load workload duration in seconds
#                                   (default 60)
#   SUSTAINED_AUTH_USER             credential used by test-sustained-load.sh
#                                   (default: $ADMIN_USER, falling back to "admin").
#                                   Must be in the backend's
#                                   RATE_LIMIT_EXEMPT_USERNAMES list for the
#                                   default 55% threshold to apply.
#   SUSTAINED_AUTH_PASS             password for SUSTAINED_AUTH_USER
#                                   (default: $ADMIN_PASS)
#   SUSTAINED_ERROR_PCT_THRESHOLD   pass/fail ceiling for sustained-load error rate
#                                   (default 55; TODO #153 makes this baseline-relative)
#
# Other knobs already in common.sh: BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID,
# TEST_TIMEOUT, JUNIT_OUTPUT_DIR, STRESS_LOG_DIR, CREATE_REPO_MAX_ATTEMPTS,
# CREATE_REPO_RETRY_DELAY.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

export BASE_URL="${BASE_URL:-http://localhost:8080}"
export ADMIN_USER="${ADMIN_USER:-admin}"
export ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
export RUN_ID="${RUN_ID:-local-$(date +%s)}"
export TEST_TIMEOUT="${TEST_TIMEOUT:-120}"
export JUNIT_OUTPUT_DIR="${JUNIT_OUTPUT_DIR:-/tmp/test-results}"

# STRESS_LOG_DIR is the deterministic path where stress-test scripts append
# per-request HTTP status code rows. The release-gate workflow uploads this
# directory as an artifact so a failed run can be debugged endpoint-by-endpoint
# (see artifact-keeper-test#138, artifact-keeper#1088). Each row is space-
# separated: <epoch_ms> <suite> <method> <endpoint> <http_code> <elapsed_ms>.
export STRESS_LOG_DIR="${STRESS_LOG_DIR:-/tmp/stress-logs}"

mkdir -p "$JUNIT_OUTPUT_DIR"
mkdir -p "$STRESS_LOG_DIR"

# log_request - Append one per-request row to the stress log for this suite.
#
# Usage:
#   log_request <method> <endpoint> <http_code> <elapsed_ms>
#
# The suite name comes from $_SUITE_NAME (set by begin_suite). If begin_suite
# has not been called yet (e.g. logging from a worker that runs before the
# suite is named) the suite column falls back to "unknown".
log_request() {
  local method="${1:-?}"
  local endpoint="${2:-?}"
  local code="${3:-000}"
  local elapsed_ms="${4:-0}"
  local suite="${_SUITE_NAME:-unknown}"
  local ts_ms
  ts_ms=$(date +%s%3N 2>/dev/null || true)
  # macOS / BSD date doesn't understand %3N and returns "<seconds>N". Fall
  # back to seconds-with-zero-millis in that case so the log row stays a
  # pure integer in the timestamp column. Linux ARC runners (the actual
  # release-gate environment) emit the millisecond form natively.
  if [ -z "$ts_ms" ] || ! [[ "$ts_ms" =~ ^[0-9]+$ ]]; then
    ts_ms="$(date +%s)000"
  fi
  # Strip the BASE_URL prefix so the log is portable across runs.
  # Defensive: BASE_URL is set at top of file but ${VAR:-} guards against
  # any caller that `unset BASE_URL` before sourcing this helper.
  endpoint="${endpoint#"${BASE_URL:-}"}"
  # Strip query strings before logging: defense against future callers that
  # accidentally log URLs containing `?token=...`, `?api_key=...`, or signed
  # share-link / pre-signed-S3 URLs. The artifact is retained 90 days; keeping
  # secrets out by construction is cheaper than scrubbing later.
  endpoint="${endpoint%%\?*}"
  # Replace any whitespace in the endpoint with %20 so the row stays single-
  # field-per-column when grep/awk-ed later.
  endpoint="${endpoint// /%20}"
  printf '%s %s %s %s %s %s\n' \
    "$ts_ms" "$suite" "$method" "$endpoint" "$code" "$elapsed_ms" \
    >> "${STRESS_LOG_DIR}/${suite}.log"
}

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

_SUITE_NAME=""
_SUITE_START=0
_TEST_NAME=""
_TEST_START=0
_PASS_COUNT=0
_FAIL_COUNT=0
_SKIP_COUNT=0
_JUNIT_CASES=""

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

ADMIN_TOKEN=""

# AUTH_ADMIN_MAX_ATTEMPTS / AUTH_ADMIN_RETRY_DELAY can be overridden by callers
# that need a different retry budget. Defaults give ~60s of total wait time,
# which is enough to absorb short backend hiccups (rate-limiter window resets,
# OpenSearch JVM warmup, GC pauses, brief pod readiness flaps) that happen
# when many test suites run concurrently against a single namespace. The
# previous 5x3s = 15s budget was too tight: it would tip over during parallel
# release-gate runs and leave the very next suite to recover, which manifested
# as "first script in suite fails, rest pass" (release-gate run 24934467423).
AUTH_ADMIN_MAX_ATTEMPTS="${AUTH_ADMIN_MAX_ATTEMPTS:-12}"
AUTH_ADMIN_RETRY_DELAY="${AUTH_ADMIN_RETRY_DELAY:-5}"

# ---------------------------------------------------------------------------
# Backend feature detection
# ---------------------------------------------------------------------------
#
# Tests should never assume the backend supports every feature in the suite.
# When a test exercises a feature that only ships in a specific minor (or
# later), call `require_feature "<name>"` at the start. If the backend is
# older than the version that introduced the feature, the helper records the
# current test as `skip` with a precise reason and returns 1; the caller
# should `return` immediately. If supported, the helper returns 0 and the
# test runs as normal.
#
# The feature -> minimum-version map below is the single source of truth for
# the gate suite. When a feature ships in a release, add an entry here in
# the SAME PR that ships the feature.
#
# This pattern lets one main branch of the test repo run cleanly against
# any backend version. v1.2.0 backend auto-skips v1.3.0 features; v1.3.0
# backend runs them automatically.

# Cached result of `GET /health` so we only hit the backend once per suite.
BACKEND_VERSION=""

# Source the branch-aware feature flag layer (issue #65). This must run
# before the first require_feature call. The file is small and exports
# AK_FEATURES via feature_flags_init; if the file is missing for any
# reason (e.g. an old checkout), require_feature gracefully falls back
# to the legacy backend-probe path because feature_enabled_via_env will
# not be defined.
# shellcheck source=feature-flags.sh
if [ -f "$(dirname "${BASH_SOURCE[0]}")/feature-flags.sh" ]; then
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/feature-flags.sh"
fi

# Strip a leading 'v' if present and return the cleaned version string.
_strip_v_prefix() {
  local v="$1"
  echo "${v#v}"
}

# Compare two semver strings. Returns 0 if $1 >= $2, 1 otherwise.
# Pre-release suffixes (-rc.N) are stripped before comparison so a release
# candidate validates the same feature set as its target release. We only ship
# -rc.N suffixes, never -alpha/-beta, so dropping the suffix is safe.
version_ge() {
  local a_core b_core
  a_core=$(_strip_v_prefix "$1")
  b_core=$(_strip_v_prefix "$2")
  a_core="${a_core%%-*}"
  b_core="${b_core%%-*}"
  if [ "$a_core" = "$b_core" ]; then
    return 0
  fi
  local lower
  lower=$(printf '%s\n%s\n' "$a_core" "$b_core" | sort -V | head -n1)
  [ "$lower" = "$b_core" ]
}

# Read the backend version from /health, cache it, return it on stdout.
get_backend_version() {
  if [ -z "$BACKEND_VERSION" ]; then
    BACKEND_VERSION=$(curl -sf --max-time 5 "${BASE_URL}/health" 2>/dev/null | jq -r '.version // empty' 2>/dev/null)
    if [ -z "$BACKEND_VERSION" ]; then
      BACKEND_VERSION="unknown"
    fi
  fi
  echo "$BACKEND_VERSION"
}

# Map of feature flag -> minimum backend version that ships it.
# Add entries here in the same PR that ships the feature.
_feature_min_version() {
  case "$1" in
    # quality_checks_admin_list: the admin quality-checks list-all endpoint
    # GET /api/v1/admin/quality-checks (#2419) — a repository-scoped (or
    # unscoped) paginated `{items,total,page,per_page}` view that backs the web
    # admin quality-checks page. The artifact-scoped GET /api/v1/quality/checks
    # keeps its #2334 contract (400 without artifact_id). Pre-1.6.0 backends
    # have no list-all endpoint (the page 400s), so the gate skips there.
    "quality_checks_admin_list")      echo "1.6.0" ;;
    "conan_remote_search_forward")    echo "1.3.0" ;;
    "conan_virtual_search_aggregate") echo "1.3.0" ;;
    # v1.3.0 release-gate additions (see rig FixSpec v130-test-gates-plan.md).
    # metrics_unmatched_path: the metrics middleware collapses requests that
    # match no route to a single path="unmatched" series instead of echoing
    # the raw request path, closing the per-path label-cardinality DoS
    # (artifact-keeper#2217). Pre-1.3.0 backends emit one series per junk path.
    "metrics_unmatched_path")         echo "1.3.0" ;;
    # streaming_large_artifact: artifacts larger than the 16 MiB in-memory
    # buffer cap are streamed to/from storage rather than buffered, so a
    # >16 MiB upload/download returns 2xx instead of 502/OOM (the #1608
    # streaming-invariant trilogy). Pre-1.3.0 backends buffer and 502/OOM.
    "streaming_large_artifact")       echo "1.3.0" ;;
    # composer_dist_cache: a warm composer dist fetch is served from the
    # pull-through cache without re-dialing upstream (artifact-keeper#2204).
    # Pre-1.3.0 backends re-fetch upstream on every dist request.
    "composer_dist_cache")            echo "1.3.0" ;;
    # npm_packument_swr: npm packument responses are served stale-while-
    # revalidate from cache within the TTL window (no upstream re-hit) and
    # refreshed after a new version lands (artifact-keeper#2166).
    "npm_packument_swr")              echo "1.3.0" ;;
    # oci_gc_two_phase: the OCI/storage GC sweep reclaims a genuinely
    # unreferenced blob (manifest deleted, grace elapsed) and leaves no
    # dangling manifest reference behind (artifact-keeper#1660). Pre-1.3.0
    # backends do not maintain the manifest->blob reference table the sweep
    # needs, so the reclaim assertion cannot be driven there.
    "oci_gc_two_phase")               echo "1.3.0" ;;
    # recipe_latest / recipe_revisions filter by user/channel rather than
    # collapsing variants to _/_/latest. Backported via artifact-keeper#869.
    # v1.1.x backend lacks this scoping; tracked for v1.1.10 backport in #986.
    "conan_user_channel_scoping")     echo "1.2.0" ;;
    # Virtual-repo recipe_latest fans out across non-Remote members. Landed
    # via artifact-keeper#875. v1.1.x backend lacks this; tracked in #986.
    "conan_virtual_recipe_fanout")    echo "1.2.0" ;;
    "maven_virtual_snapshot")         echo "1.2.0" ;;
    "guest_access_toggle")            echo "1.2.0" ;;
    "opensearch_indexing")            echo "1.2.0" ;;
    # sbom_declared_dependencies: SBOM generation merges the artifact's own
    # declared dependencies (Maven POM, npm package.json, Helm Chart.yaml) with
    # scanner output, so an artifact a scanner cannot enumerate (a bare Maven
    # jar with no lockfile) no longer produces an authoritative empty SBOM, and
    # the document carries a completeness signal (complete/declared/partial/
    # none). artifact-keeper#870, lands in v1.2.0. Pre-1.2.0 backends return an
    # empty SBOM for the declared-only case, so the gate skips there.
    "sbom_declared_dependencies")     echo "1.2.0" ;;
    # proxy_stampede_protection: ProxyService gains a per-(repo,path) semaphore
    # capping concurrent upstream fetches at proxy_max_concurrent_fetches and
    # emitting 503 when proxy_queue_timeout_secs fires. Tracked by backend
    # work to land in v1.2.0 (companion to discussion #872 customer pain).
    "proxy_stampede_protection")      echo "1.2.0" ;;
    # Strict-contract assertions on virtual repository member endpoints
    # (PUT /:key/members, DELETE /:key/members/:member_key, PUT /:key/cache-ttl).
    # The endpoints themselves exist in 1.1.x. This flag gates the v1.2.0
    # follow-on tests (response-shape assertions, DELETE idempotency,
    # malformed-JSON 400 contract, 401/403 auth-failure paths) so they
    # only run against a 1.2.0+ backend and stay out of the in-flight
    # 1.1.9 release-gate. Tracks artifact-keeper-test#92, #93, #94, #95.
    "virtual_member_strict_contract") echo "1.2.0" ;;
    # Auth/Epic-11 features. Targeted for v1.1.9 because security-flavoured
    # work (rotation + token revocation on deactivate) is likely to land on
    # the release/1.1.x maintenance branch as a backport rather than wait
    # for the next minor. If a backport ships earlier than 1.1.9, drop the
    # min-version here; if any of these slip past 1.1.9 to 1.2.0, raise it.
    # Tracked: artifact-keeper#929, #930, #931 (milestone v1.1.9).
    "refresh_token_rotation")         echo "1.1.9" ;;
    "download_ticket_consumer")       echo "1.1.9" ;;
    "user_deactivation_token_flush")  echo "1.1.9" ;;
    # Conan error-path correctness work. v1.1.x conan handler lacks repo
    # existence checks before format dispatch (uploads to non-existent repos
    # return 500 instead of 404), the /v2/ping endpoint short-circuits before
    # repo lookup (returns 200 for any repo path), and the file-upload handler
    # panics on >255-char path segments instead of returning a structured
    # error. These are correctness gaps that pre-date v1.1.x rather than
    # regressions, so they're slated for v1.1.10 / v1.2.0. Tracked in
    # artifact-keeper#990.
    "conan_error_correctness")        echo "1.1.10" ;;
    # webhook_event_producer: the in-process EventBus -> webhook_deliveries
    # producer task. Subscribes to domain events and enqueues delivery rows
    # for the existing retry scheduler. v1.1.x ships the wire contract
    # (webhook CRUD, /test, signing, retry scheduler) but not the producer:
    # rows only appear in webhook_deliveries when /test is hit synchronously.
    # Real EventBus events do not produce rows on 1.1.x. Producer wire-up is
    # epic artifact-keeper#919 (E3) for v1.2.0. Until then, tests that assert
    # "delivery row appears after a domain event" must skip on 1.1.x backends
    # to avoid hard-failing on the absence of an unshipped feature.
    "webhook_event_producer")         echo "1.2.0" ;;
    # proxy_ttl_eviction_correctness: the proxy correctly serves the
    # cached upstream response within the configured cache_ttl_seconds
    # window and only refetches after the TTL expires. v1.1.x backends
    # have a latent bug where the within-TTL fetch already shows
    # upstream's new content, indicating a missing or wrong cache-
    # validity check in the proxy fetch path. Tracked for v1.2.0; the
    # eviction E2E test gates against this feature so 1.1.x releases
    # do not block on a known-broken behaviour.
    "proxy_ttl_eviction_correctness") echo "1.2.0" ;;
    *) return 1 ;;
  esac
}

# Skip the current test if the backend doesn't support the named feature.
# Usage:
#   begin_test "Search through remote proxy"
#   require_feature "conan_remote_search_forward" || return
#   ... rest of the test ...
require_feature() {
  local feature="$1"

  # Fast path: branch-aware AK_FEATURES env (issue #65). The release-gate
  # workflow sets AK_BACKEND_BRANCH once per matrix job; feature_flags_init
  # (sourced below) derives AK_FEATURES from that. If we got an explicit
  # answer here we use it and skip the backend probe entirely. Probe-only
  # fallback runs when AK_FEATURES is unset (local dev path).
  if declare -F feature_enabled_via_env >/dev/null 2>&1; then
    feature_enabled_via_env "$feature"
    case $? in
      0)
        # Env says enabled. No HTTP needed.
        return 0
        ;;
      1)
        # Env says explicitly disabled. Skip with a precise reason so a
        # stale workflow mapping shows up loudly (not as a silent skip).
        skip "feature '${feature}' not enabled on backend branch '${AK_BACKEND_BRANCH:-?}' (AK_FEATURES=${AK_FEATURES:-})"
        return 1
        ;;
      2)
        # No env hint. Fall through to backend probe (legacy path).
        ;;
    esac
  fi

  local min_ver
  min_ver=$(_feature_min_version "$feature") || {
    fail "require_feature: unknown feature '$feature' (add to _feature_min_version map in tests/lib/common.sh)"
    return 1
  }
  local backend_ver
  backend_ver=$(get_backend_version)
  if [ "$backend_ver" = "unknown" ]; then
    skip "could not determine backend version, skipping ${feature}"
    return 1
  fi
  if version_ge "$backend_ver" "$min_ver"; then
    return 0
  else
    skip "feature '${feature}' requires backend >= ${min_ver}, running ${backend_ver}"
    return 1
  fi
}

auth_admin() {
  # Wait for backend readiness (handles parallel suite load bursts)
  local _ready=false
  for _i in $(seq 1 15); do
    if curl -sf --max-time 5 "${BASE_URL}/readyz" >/dev/null 2>&1 || \
       curl -sf --max-time 5 "${BASE_URL}/health" >/dev/null 2>&1; then
      _ready=true
      break
    fi
    sleep 2
  done
  if ! $_ready; then
    echo "FATAL: backend not ready at ${BASE_URL} after 30s"
    exit 1
  fi

  local resp=""
  local _attempt
  local _http_status=""
  local _body=""
  local _max="$AUTH_ADMIN_MAX_ATTEMPTS"
  local _delay="$AUTH_ADMIN_RETRY_DELAY"
  for _attempt in $(seq 1 "$_max"); do
    # Capture status + body separately so a 429 / 503 / 401 surfaces in logs.
    # We deliberately drop -f here (it suppresses the body on >=400) so we can
    # report what actually came back instead of an opaque "auth failed".
    local _tmp
    _tmp=$(mktemp)
    _http_status=$(curl -s --max-time 10 -o "$_tmp" -w '%{http_code}' \
      -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null) || _http_status="000"
    _body=$(cat "$_tmp" 2>/dev/null || true)
    rm -f "$_tmp"

    if [ "$_http_status" = "200" ] && [ -n "$_body" ]; then
      resp="$_body"
      break
    fi

    # Truncate body for log output to avoid spamming on large error pages.
    local _body_snip="${_body:0:200}"
    echo "  auth attempt ${_attempt}/${_max} failed (HTTP ${_http_status}, body: ${_body_snip:-<empty>}), retrying in ${_delay}s..."

    # If we got a 429, honor Retry-After when present by waiting a bit longer.
    if [ "$_http_status" = "429" ]; then
      sleep "$(( _delay * 2 ))"
    else
      sleep "$_delay"
    fi
  done
  if [ -z "$resp" ]; then
    echo "FATAL: failed to authenticate as ${ADMIN_USER} at ${BASE_URL} after ${_max} attempts (last HTTP ${_http_status})"
    exit 1
  fi

  ADMIN_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty')
  if [ -z "$ADMIN_TOKEN" ]; then
    echo "FATAL: auth response did not contain a token"
    echo "Response: ${resp}"
    exit 1
  fi
  export ADMIN_TOKEN
}

auth_header() {
  echo "Authorization: Bearer ${ADMIN_TOKEN}"
}

# Format-native endpoints (e.g. /conan/, /vscode/, /lfs/, /huggingface/) have
# their own auth middleware that only accepts Basic auth.  Use this header for
# any call that hits a format-native route.
format_auth_header() {
  echo "Authorization: Basic $(printf '%s:%s' "$ADMIN_USER" "$ADMIN_PASS" | base64)"
}

# PUT a file to a format-native endpoint with retry on transient auth/rate-limit
# failures. Echoes the final HTTP status on stdout.
#
# The 1.1.x backend reauthenticates Basic credentials on every format-native
# request via bcrypt(cost=12) inside spawn_blocking. Under back-to-back PUT
# bursts within the same suite (and parallel suites sharing the same admin
# user), the spawn_blocking pool can transiently drop a verify task, surfacing
# as HTTP 401 even though credentials are valid. The 1.2.x backend grew
# RATE_LIMIT_EXEMPT_USERNAMES (#697) to take the admin user off the auth
# bucket, but that exemption was never backported to release/1.1.x, so the
# release-gate (which targets 1.1.6) needs test-side resilience.
#
# Retries on HTTP 401, 429, 503, and network errors. Returns the final status
# so callers can assert success.
#
# Usage:
#   status=$(format_put_with_retry "$URL" "$DATA_FILE" [extra_curl_args...])
format_put_with_retry() {
  local url="$1"
  local data_file="$2"
  shift 2
  local _max="${FORMAT_PUT_MAX_ATTEMPTS:-4}"
  local _delay="${FORMAT_PUT_RETRY_DELAY:-2}"
  local _attempt _status="000"
  for _attempt in $(seq 1 "$_max"); do
    _status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
      -H "$(format_auth_header)" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@${data_file}" \
      "$@" \
      "$url" 2>/dev/null) || _status="000"

    # Success
    if [ "$_status" -ge 200 ] 2>/dev/null && [ "$_status" -lt 300 ] 2>/dev/null; then
      echo "$_status"
      return 0
    fi

    # Non-transient failure: stop retrying
    if [ "$_status" != "401" ] && [ "$_status" != "429" ] && \
       [ "$_status" != "503" ] && [ "$_status" != "000" ]; then
      break
    fi

    if [ "$_attempt" -lt "$_max" ]; then
      sleep "$_delay"
    fi
  done
  echo "$_status"
  return 1
}

# GET from a format-native endpoint with retry on transient auth/rate-limit
# failures. Writes body to OUT_FILE (-) and echoes the final HTTP status.
# Same retry rationale as format_put_with_retry.
#
# Usage:
#   status=$(format_get_with_retry "$URL" "$OUT_FILE")
format_get_with_retry() {
  local url="$1"
  local out_file="${2:-/dev/null}"
  local _max="${FORMAT_PUT_MAX_ATTEMPTS:-4}"
  local _delay="${FORMAT_PUT_RETRY_DELAY:-2}"
  local _attempt _status="000"
  for _attempt in $(seq 1 "$_max"); do
    _status=$(curl -s -o "$out_file" -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "$url" 2>/dev/null) || _status="000"

    if [ "$_status" -ge 200 ] 2>/dev/null && [ "$_status" -lt 300 ] 2>/dev/null; then
      echo "$_status"
      return 0
    fi

    if [ "$_status" != "401" ] && [ "$_status" != "429" ] && \
       [ "$_status" != "503" ] && [ "$_status" != "000" ]; then
      break
    fi

    if [ "$_attempt" -lt "$_max" ]; then
      sleep "$_delay"
    fi
  done
  echo "$_status"
  return 1
}

# ---------------------------------------------------------------------------
# HTTP helpers
#
# All helpers use the admin Bearer token. They pass through curl's -sf flags
# so callers get a non-zero exit code on HTTP errors, which works well with
# set -euo pipefail. Wrap calls in `if` or `|| true` when a non-2xx response
# is expected.
# ---------------------------------------------------------------------------

# All curl calls use --max-time to prevent indefinite hangs in CI.
CURL_TIMEOUT="--max-time 60 --connect-timeout 10"

api_get() {
  local path="$1"; shift
  curl -sf $CURL_TIMEOUT -H "$(auth_header)" "$@" "${BASE_URL}${path}"
}

# api_get_with_retry - GET an idempotent management-API endpoint with a bounded
# retry-with-backoff on TRANSIENT failures only. On success it echoes the
# response body on stdout and returns 0, so it is a drop-in replacement for
# `api_get` in `if resp=$(...); then`-style call sites.
#
# Why this exists (the test-sbt.sh "List artifacts" flake, ak-test):
#   The plain `api_get` uses `curl -sf`, which exits non-zero on ANY >=400 and
#   discards the response body. When ~25 format suites run in parallel in the
#   `format-tests (jvm)` gate job they saturate the backend's tokio runtime
#   (the known worker-starvation / availability issue: uncapped CPU work such
#   as bcrypt(cost=12) on basic-auth format calls bypasses the auth semaphore).
#   A GET that races peak saturation can transiently come back 503/502 (pool
#   exhausted / shed) or 000 (request exceeded its time budget) even though the
#   data is fine -- the very next attempt succeeds. With bare `api_get` that one
#   transient blip hard-fails the suite ("GET .../artifacts returned error"),
#   which is a retry-hope flake, not a real defect: the GET is idempotent and
#   SHOULD be retried, exactly as format_get_with_retry / create_repo / login_as
#   already do for their transient classes.
#
# Retry policy (deliberately narrow so we never mask a real bug):
#   - Retry ONLY on transient-class statuses: 000 (network/timeout) and the 5xx
#     range (500-599: 502/503/504 plus any residual 5xx).
#   - DO NOT retry on 2xx (success) or 4xx (real client/auth/not-found errors):
#     those are deterministic and a retry would just hide a genuine failure. A
#     404/403/wrong-content surfaces immediately.
#   - On a non-2xx final outcome, return 1 AND emit a precise diagnostic to
#     stderr (final HTTP status + body snippet) so the failure is never opaque
#     the way bare `curl -sf` made it.
#
# Knobs: API_GET_MAX_ATTEMPTS (default 4), API_GET_RETRY_DELAY (default 2s,
# applied with linear backoff: delay * attempt).
#
# Usage:
#   if resp=$(api_get_with_retry "/api/v1/repositories/${KEY}/artifacts"); then
#     assert_contains "$resp" "$MODULE_NAME" "..."
#   else
#     fail "GET .../artifacts returned error"
#   fi
api_get_with_retry() {
  local path="$1"; shift
  local _max="${API_GET_MAX_ATTEMPTS:-4}"
  local _delay="${API_GET_RETRY_DELAY:-2}"
  local _attempt _status="000" _body_file _body=""
  _body_file=$(mktemp)
  for _attempt in $(seq 1 "$_max"); do
    _status=$(curl -s $CURL_TIMEOUT -o "$_body_file" -w '%{http_code}' \
      -H "$(auth_header)" "$@" "${BASE_URL}${path}" 2>/dev/null) || _status="000"

    # Success: 2xx -> emit body, return 0.
    if [ "$_status" -ge 200 ] 2>/dev/null && [ "$_status" -lt 300 ] 2>/dev/null; then
      cat "$_body_file"
      rm -f "$_body_file"
      return 0
    fi

    # Transient class -> retry. Everything else (4xx, other non-5xx) is a real,
    # deterministic failure: stop immediately so we don't mask a bug.
    local _transient=false
    if [ "$_status" = "000" ] || \
       { [ "$_status" -ge 500 ] 2>/dev/null && [ "$_status" -le 599 ] 2>/dev/null; }; then
      _transient=true
    fi
    if [ "$_transient" != true ]; then
      break
    fi

    if [ "$_attempt" -lt "$_max" ]; then
      sleep "$(( _delay * _attempt ))"
    fi
  done

  _body=$(head -c 400 "$_body_file" 2>/dev/null || true)
  rm -f "$_body_file"
  # _attempt holds the loop index of the last attempt made. A deterministic
  # (non-transient) status breaks the loop early, so this reports the real
  # number of requests issued rather than the configured ceiling.
  echo "api_get_with_retry ${path} failed after ${_attempt} attempt(s) (max ${_max}): HTTP ${_status} body=${_body}" >&2
  return 1
}

# Create a test user (admin auth) and echo the new user's UUID on stdout.
# On failure, echoes empty string and the response body to stderr.
#
# Usage:
#   USER_ID=$(create_test_user "$USERNAME" "$PASSWORD" "$EMAIL")
create_test_user() {
  local username="$1"
  local password="$2"
  local email="$3"
  local resp
  resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${username}\",\"password\":\"${password}\",\"email\":\"${email}\"}" 2>/dev/null) || true
  local uid
  uid=$(echo "$resp" | jq -r '.user.id // .id // empty')
  if [ -z "$uid" ] || [ "$uid" = "null" ]; then
    echo "create_test_user failed: ${resp:0:200}" >&2
    echo ""
    return 1
  fi
  echo "$uid"
}

# Create a test user (admin auth) with bounded retry-on-transient, echoing
# the new user's UUID on stdout. Returns 0 on success, 1 after retries.
#
# Why this exists (release-gate flake #1):
#   Several security suites create a throwaway user as a SETUP step
#   (token-revocation, lockout, force-password-change). User creation hashes
#   the password with bcrypt in spawn_blocking. Under fleet-concurrent load
#   the backend's blocking pool / worker runtime can be momentarily starved
#   (the known availability worker-starvation issue: uncapped CPU-bound auth
#   work on the tokio runtime), so an otherwise-valid admin POST
#   /api/v1/users can transiently return 5xx or drop the connection
#   (curl exit -> 000). The plain api_post helper uses `curl -sf`, which
#   collapses any non-2xx into a bare non-zero exit with no body and NO
#   retry, so a single transient blip fails the whole suite at setup time
#   ("could not create force-password-change test user").
#
#   This helper retries ONLY the transient class (HTTP 5xx and network 000).
#   Real client errors (400 invalid payload, 409 username taken, 401/403
#   auth) are returned immediately and NOT masked -- a duplicate-username or
#   a malformed request is a genuine test bug, not a flake.
#
# Accepts EITHER the 3-arg short form (username password email) or a 4th arg
# giving a full JSON body (so callers that also set display_name reuse the
# same retry logic). The body, if given, must be a complete JSON object.
#
# Tunables (shared budget feel with create_repo / login_as):
#   CREATE_USER_MAX_ATTEMPTS  default 4
#   CREATE_USER_RETRY_DELAY   default 1 (seconds; doubled each attempt)
#
# Usage:
#   USER_ID=$(create_test_user_with_retry "$USER" "$PASS" "$EMAIL") || fail ...
#   USER_ID=$(create_test_user_with_retry "$USER" "$PASS" "$EMAIL" "$JSON") || fail ...
create_test_user_with_retry() {
  local username="$1"
  local password="$2"
  local email="$3"
  local body="${4:-}"
  if [ -z "$body" ]; then
    body="{\"username\":\"${username}\",\"password\":\"${password}\",\"email\":\"${email}\"}"
  fi
  local _max="${CREATE_USER_MAX_ATTEMPTS:-4}"
  local _delay="${CREATE_USER_RETRY_DELAY:-1}"
  local _attempt _status _tmp _resp uid=""
  for _attempt in $(seq 1 "$_max"); do
    _tmp=$(mktemp)
    _status=$(curl -s $CURL_TIMEOUT -o "$_tmp" -w '%{http_code}' \
      -X POST -H "$(auth_header)" -H 'Content-Type: application/json' \
      -d "$body" "${BASE_URL}/api/v1/users" 2>/dev/null) || _status="000"
    _resp=$(cat "$_tmp" 2>/dev/null || true)
    rm -f "$_tmp"

    if [ "$_status" -ge 200 ] 2>/dev/null && [ "$_status" -lt 300 ] 2>/dev/null; then
      uid=$(echo "$_resp" | jq -r '.user.id // .id // .user_id // empty' 2>/dev/null) || uid=""
      if [ -n "$uid" ] && [ "$uid" != "null" ]; then
        echo "$uid"
        return 0
      fi
      # 2xx but no id: a contract break, not a transient blip. Don't retry.
      echo "create_test_user_with_retry: ${username} got HTTP ${_status} but no id: ${_resp:0:200}" >&2
      echo ""
      return 1
    fi

    # Retry ONLY transient class: network 000 or any 5xx. Everything else
    # (4xx) is a real failure surfaced immediately.
    if [ "$_status" != "000" ] && { [ "$_status" -lt 500 ] 2>/dev/null || [ "$_status" -ge 600 ] 2>/dev/null; }; then
      echo "create_test_user_with_retry: ${username} non-transient HTTP ${_status}: ${_resp:0:200}" >&2
      echo ""
      return 1
    fi

    if [ "$_attempt" -lt "$_max" ]; then
      echo "  create-user ${username} attempt ${_attempt}/${_max} transient HTTP ${_status}, retrying in ${_delay}s..." >&2
      sleep "$_delay"
      _delay=$(( _delay * 2 ))
    fi
  done
  echo "create_test_user_with_retry: ${username} failed after ${_max} attempts (last HTTP ${_status})" >&2
  echo ""
  return 1
}

# ---------------------------------------------------------------------------
# create_dedicated_admin / cleanup_dedicated_admin
#
# Release-gate flake fix (shared-admin credential poisoning):
#   The gate runs ~25 suites in parallel, ALL authenticating as the same
#   global admin (ADMIN_USER/ADMIN_PASS). Any suite that mutates the shared
#   admin's own auth state -- changes its password, flips its roles,
#   deactivates it, or revokes its tokens -- trips the backend's credential
#   invalidation (services/auth/credential_invalidations.rs). That
#   invalidates the admin's JWT process-wide, so EVERY other concurrently
#   running suite's ADMIN_TOKEN starts returning "401 Invalid or expired
#   token" -> non-deterministic 401 cascades across the whole gate.
#
#   A suite that needs to exercise admin-self mutations (password recovery,
#   role flip, self-deactivation) must do so on a THROWAWAY admin identity,
#   never on the shared one. create_dedicated_admin mints such a user using
#   the global admin token (which it does NOT mutate), and echoes the new
#   admin's UUID on stdout. The throwaway admin is created with
#   is_admin:true so it has the same admin authority as the shared admin and
#   can hit admin-only routes / be used wherever the shared admin was.
#
#   The caller's global ADMIN_TOKEN is unaffected throughout: we only POST
#   /users (create) and never touch /users/{global_admin_id}.
#
# Output / contract (mirrors create_test_user_with_retry):
#   - echoes the new admin's UUID on stdout, returns 0 on success
#   - echoes "" and a diagnostic to stderr, returns 1 on failure
#   - retries ONLY the transient class (network 000 / HTTP 5xx); real 4xx
#     (e.g. 409 duplicate, 403 authz) are surfaced immediately
#
# The username/password/email are derived from RUN_ID + $$ so they are
# unique per suite invocation and cannot collide across parallel suites.
#
# Usage:
#   ADMIN2_USER="e2e-dedadmin-${RUN_ID}-$$"
#   ADMIN2_PASS="DedAdmin_${RUN_ID:0:8}_Aa1!"
#   ADMIN2_ID=$(create_dedicated_admin "$ADMIN2_USER" "$ADMIN2_PASS") || fail ...
#   add_exit_handler "cleanup_dedicated_admin $ADMIN2_ID"
#
# Or let it generate the credentials for you and read them back via the
# convenience globals it exports (DEDICATED_ADMIN_USER / _PASS / _ID):
#   create_dedicated_admin >/dev/null || fail "could not create dedicated admin"
#   add_exit_handler "cleanup_dedicated_admin ${DEDICATED_ADMIN_ID}"
create_dedicated_admin() {
  # Generate unique, policy-compliant credentials when not supplied. The
  # backend password policy wants >=12 chars + mixed case + digit + symbol;
  # the suffix guarantees all four classes regardless of RUN_ID contents.
  local label="${3:-dedadmin}"
  local username="${1:-e2e-${label}-${RUN_ID}-$$}"
  local password="${2:-Ded_${RUN_ID:0:8}_$$_Aa1!}"
  local email="${username}@e2e.local"

  # Export the resolved identity so callers that did not pass explicit args
  # can still recover the credentials (and so the cleanup handler can be
  # registered without recomputing them).
  DEDICATED_ADMIN_USER="$username"
  DEDICATED_ADMIN_PASS="$password"
  export DEDICATED_ADMIN_USER DEDICATED_ADMIN_PASS

  local body
  body="{\"username\":\"${username}\",\"password\":\"${password}\",\"email\":\"${email}\",\"display_name\":\"E2E Dedicated Admin\",\"is_admin\":true}"

  local _max="${CREATE_USER_MAX_ATTEMPTS:-4}"
  local _delay="${CREATE_USER_RETRY_DELAY:-1}"
  local _attempt _status _tmp _resp uid=""
  for _attempt in $(seq 1 "$_max"); do
    _tmp=$(mktemp)
    # Uses the GLOBAL admin token via auth_header(); creating a user does not
    # mutate the global admin, so its JWT stays valid for concurrent suites.
    _status=$(curl -s $CURL_TIMEOUT -o "$_tmp" -w '%{http_code}' \
      -X POST -H "$(auth_header)" -H 'Content-Type: application/json' \
      -d "$body" "${BASE_URL}/api/v1/users" 2>/dev/null) || _status="000"
    _resp=$(cat "$_tmp" 2>/dev/null || true)
    rm -f "$_tmp"

    if [ "$_status" -ge 200 ] 2>/dev/null && [ "$_status" -lt 300 ] 2>/dev/null; then
      uid=$(echo "$_resp" | jq -r '.user.id // .id // .user_id // empty' 2>/dev/null) || uid=""
      if [ -n "$uid" ] && [ "$uid" != "null" ]; then
        DEDICATED_ADMIN_ID="$uid"
        export DEDICATED_ADMIN_ID
        echo "$uid"
        return 0
      fi
      echo "create_dedicated_admin: ${username} got HTTP ${_status} but no id: ${_resp:0:200}" >&2
      echo ""
      return 1
    fi

    # Retry ONLY transient class: network 000 or any 5xx.
    if [ "$_status" != "000" ] && { [ "$_status" -lt 500 ] 2>/dev/null || [ "$_status" -ge 600 ] 2>/dev/null; }; then
      echo "create_dedicated_admin: ${username} non-transient HTTP ${_status}: ${_resp:0:200}" >&2
      echo ""
      return 1
    fi

    if [ "$_attempt" -lt "$_max" ]; then
      echo "  create-dedicated-admin ${username} attempt ${_attempt}/${_max} transient HTTP ${_status}, retrying in ${_delay}s..." >&2
      sleep "$_delay"
      _delay=$(( _delay * 2 ))
    fi
  done
  echo "create_dedicated_admin: ${username} failed after ${_max} attempts (last HTTP ${_status})" >&2
  echo ""
  return 1
}

# Delete a throwaway admin created by create_dedicated_admin. Best-effort:
# re-authenticates as the global admin first (in case the suite rotated its
# own ADMIN_TOKEN while testing), then DELETEs the user. Safe to call with an
# empty/invalid id (no-op). Intended for use with add_exit_handler so an
# interrupted run leaves no dangling admin users.
#
# Usage:
#   add_exit_handler "cleanup_dedicated_admin $ADMIN2_ID"
cleanup_dedicated_admin() {
  local uid="${1:-${DEDICATED_ADMIN_ID:-}}"
  if [ -z "$uid" ] || [ "$uid" = "null" ]; then
    return 0
  fi
  auth_admin > /dev/null 2>&1 || true
  api_delete "/api/v1/users/${uid}" > /dev/null 2>&1 || true
}

# Log in as the named user and echo the access_token on stdout.
# On failure, echoes empty string and the response body to stderr.
#
# Retries on HTTP 429 (auth rate-limit) because non-admin users are not in
# RATE_LIMIT_EXEMPT_USERNAMES. When parallel suites burst-call /auth/login
# (e.g. test-idor creates two users + logs one in, all in <1s), the bucket
# can momentarily refuse the login that immediately follows. Same retry
# budget as auth_admin: 5x3s = 15s. 429s honor a doubled delay.
#
# Usage:
#   USER_TOKEN=$(login_as "$USERNAME" "$PASSWORD")
login_as() {
  local username="$1"
  local password="$2"
  local _max="${LOGIN_AS_MAX_ATTEMPTS:-5}"
  local _delay="${LOGIN_AS_RETRY_DELAY:-3}"
  local _attempt _http_status _body _tmp tok=""
  for _attempt in $(seq 1 "$_max"); do
    _tmp=$(mktemp)
    _http_status=$(curl -s $CURL_TIMEOUT -o "$_tmp" -w '%{http_code}' \
      -X POST -H "Content-Type: application/json" \
      -d "{\"username\":\"${username}\",\"password\":\"${password}\"}" \
      "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || _http_status="000"
    _body=$(cat "$_tmp" 2>/dev/null || true)
    rm -f "$_tmp"

    if [ "$_http_status" = "200" ] && [ -n "$_body" ]; then
      tok=$(echo "$_body" | jq -r '.access_token // .token // empty')
      if [ -n "$tok" ] && [ "$tok" != "null" ]; then
        echo "$tok"
        return 0
      fi
    fi

    # Only retry on transient 429 / 503 / network. 401/400 are real failures.
    if [ "$_http_status" != "429" ] && [ "$_http_status" != "503" ] && [ "$_http_status" != "000" ]; then
      break
    fi
    if [ "$_attempt" -lt "$_max" ]; then
      if [ "$_http_status" = "429" ]; then
        sleep "$(( _delay * 2 ))"
      else
        sleep "$_delay"
      fi
    fi
  done
  echo "login_as failed for ${username} after ${_max} attempts (last HTTP ${_http_status}): ${_body:0:200}" >&2
  echo ""
  return 1
}

api_post() {
  local path="$1"
  local data="${2:-}"
  shift; shift 2>/dev/null || true
  if [ -n "$data" ]; then
    curl -sf $CURL_TIMEOUT -X POST \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      -d "$data" "$@" "${BASE_URL}${path}"
  else
    curl -sf $CURL_TIMEOUT -X POST \
      -H "$(auth_header)" "$@" "${BASE_URL}${path}"
  fi
}

api_put() {
  local path="$1"
  local data="${2:-}"
  shift; shift 2>/dev/null || true
  if [ -n "$data" ]; then
    curl -sf $CURL_TIMEOUT -X PUT \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      -d "$data" "$@" "${BASE_URL}${path}"
  else
    curl -sf $CURL_TIMEOUT -X PUT \
      -H "$(auth_header)" "$@" "${BASE_URL}${path}"
  fi
}

api_delete() {
  local path="$1"; shift
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" "$@" "${BASE_URL}${path}"
}

api_upload() {
  local path="$1"
  local file="$2"
  local content_type="${3:-application/octet-stream}"
  curl -sf $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: ${content_type}" \
    --data-binary "@${file}" \
    "${BASE_URL}${path}"
}

# ---------------------------------------------------------------------------
# Repository helpers
# ---------------------------------------------------------------------------

# create_repo KEY FORMAT [REPO_TYPE] [UPSTREAM_URL]
#
# Creates a repository via POST /api/v1/repositories. The previous version
# called `api_post ... > /dev/null` which used `curl -sf`: any non-2xx
# returned non-zero with the body discarded, so callers (`fail "could not
# create local OCI repo"`) had no signal about WHY the call failed.
#
# This rewrite adds two things:
#   1. Visibility: on failure, print "create_repo <key> (format=... type=...)
#      failed: HTTP <status> body=<body-snippet>" to stderr so the test
#      log shows what the server actually said.
#   2. Resilience: retry on the same transient class as
#      format_put_with_retry (HTTP 401, 429, 503, network 000). The
#      release/1.1.x admin path bcrypt-reauths every basic-auth call in
#      spawn_blocking and can transiently drop a verify task under burst
#      load. The 1.2.x backend grew RATE_LIMIT_EXEMPT_USERNAMES (#697) to
#      take the admin user off the auth bucket, but that exemption was
#      never backported to release/1.1.x. We saw this exact failure mode
#      on v1.1.9-rc.5's release-gate run #25466619896: an identical
#      create_local_repo "...." "docker" call PASSED in test-oci.sh and
#      then FAILED 4 seconds later in test-oci-remote.sh against the same
#      backend pod, with no distinguishing payload difference.
#
# Returns 0 on success, 1 on final failure (after retries exhausted).
create_repo() {
  local key="$1"
  local format="$2"
  local repo_type="${3:-local}"
  local upstream_url="${4:-}"

  local payload
  payload="{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"${format}\",\"repo_type\":\"${repo_type}\",\"is_public\":true"
  if [ -n "$upstream_url" ]; then
    payload="${payload},\"upstream_url\":\"${upstream_url}\""
  fi
  payload="${payload}}"

  local _max="${CREATE_REPO_MAX_ATTEMPTS:-4}"
  local _delay="${CREATE_REPO_RETRY_DELAY:-2}"
  local _attempt _status="000" _body_file _body=""
  _body_file=$(mktemp)
  for _attempt in $(seq 1 "$_max"); do
    _status=$(curl -s -o "$_body_file" -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      -d "$payload" \
      "${BASE_URL}/api/v1/repositories" 2>/dev/null) || _status="000"

    # Success: 2xx
    if [ "$_status" -ge 200 ] 2>/dev/null && [ "$_status" -lt 300 ] 2>/dev/null; then
      rm -f "$_body_file"
      return 0
    fi

    # Non-transient failure: stop retrying.
    if [ "$_status" != "401" ] && [ "$_status" != "429" ] && \
       [ "$_status" != "503" ] && [ "$_status" != "000" ]; then
      break
    fi

    if [ "$_attempt" -lt "$_max" ]; then
      sleep "$_delay"
    fi
  done

  _body=$(head -c 400 "$_body_file" 2>/dev/null || true)
  rm -f "$_body_file"
  echo "create_repo ${key} (format=${format} type=${repo_type}) failed: HTTP ${_status} body=${_body}" >&2
  return 1
}

create_local_repo() {
  create_repo "$1" "$2" "local"
}

# ---------------------------------------------------------------------------
# User / group helpers
#
# The backend's group membership endpoints expect user UUIDs, not usernames:
#   POST   /api/v1/groups/{id}/members   { "user_ids": ["<uuid>", ...] }
#   DELETE /api/v1/groups/{id}/members   { "user_ids": ["<uuid>", ...] }
# Tests typically know the username (because they just created the user),
# so these helpers resolve the username to a UUID and send the correct shape.
# ---------------------------------------------------------------------------

# resolve_user_id_by_username USERNAME
# Looks up a user by exact username via /api/v1/users?search=<name> and prints
# the matching user's UUID on stdout. Returns 1 if no exact match is found.
resolve_user_id_by_username() {
  local username="$1"
  local resp
  if ! resp=$(api_get "/api/v1/users?search=${username}&per_page=100" 2>/dev/null); then
    return 1
  fi
  local id
  id=$(echo "$resp" | jq -r --arg u "$username" '.items[]? | select(.username == $u) | .id' | head -n1)
  if [ -z "$id" ] || [ "$id" = "null" ]; then
    return 1
  fi
  echo "$id"
}

# add_group_members GROUP_ID USERNAME [USERNAME ...]
# Resolves each username to a UUID and POSTs the user_ids array to the
# group's members endpoint. Returns non-zero if any username cannot be
# resolved or the API call fails.
add_group_members() {
  local group_id="$1"
  shift
  local ids=()
  local username
  for username in "$@"; do
    local uid
    if ! uid=$(resolve_user_id_by_username "$username"); then
      echo "  resolve_user_id_by_username: no user found for '${username}'"
      return 1
    fi
    ids+=("$uid")
  done
  local payload
  payload=$(printf '%s\n' "${ids[@]}" | jq -R . | jq -s '{user_ids: .}')
  api_post "/api/v1/groups/${group_id}/members" "$payload"
}

# remove_group_members GROUP_ID USERNAME [USERNAME ...]
# Resolves usernames to UUIDs and DELETEs the user_ids array from the
# group's members endpoint. The backend expects a JSON body on DELETE,
# which is why we cannot simply use api_delete with a path suffix.
remove_group_members() {
  local group_id="$1"
  shift
  local ids=()
  local username
  for username in "$@"; do
    local uid
    if ! uid=$(resolve_user_id_by_username "$username"); then
      echo "  resolve_user_id_by_username: no user found for '${username}'"
      return 1
    fi
    ids+=("$uid")
  done
  local payload
  payload=$(printf '%s\n' "${ids[@]}" | jq -R . | jq -s '{user_ids: .}')
  curl -sf $CURL_TIMEOUT -X DELETE \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/groups/${group_id}/members"
}

# ---------------------------------------------------------------------------
# Test framework
#
# Usage pattern:
#   begin_suite "my-format"
#   begin_test "Upload package"
#   <do stuff, call pass or fail>
#   begin_test "Download package"
#   <do stuff, call pass or fail>
#   end_suite   # exits non-zero if any failures
#
# IMPORTANT: fail() does NOT exit. It records the failure and the suite
# continues. This lets a single suite run many tests even if some fail.
# If you run commands that might fail, guard them with `if` or `|| true`
# so set -euo pipefail does not abort the script before you call fail().
# ---------------------------------------------------------------------------

begin_suite() {
  _SUITE_NAME="$1"
  _SUITE_START=$(date +%s)
  _PASS_COUNT=0
  _FAIL_COUNT=0
  _SKIP_COUNT=0
  _JUNIT_CASES=""
  echo "========================================"
  echo "  Suite: ${_SUITE_NAME}"
  echo "  Run ID: ${RUN_ID}"
  echo "  Target: ${BASE_URL}"
  echo "========================================"
}

begin_test() {
  _TEST_NAME="$1"
  _TEST_START=$(date +%s)
  echo ""
  echo "--- ${_TEST_NAME} ---"
}

pass() {
  local duration=$(( $(date +%s) - _TEST_START ))
  _PASS_COUNT=$(( _PASS_COUNT + 1 ))
  local xml_name
  xml_name=$(_xml_escape "$_TEST_NAME")
  local xml_suite
  xml_suite=$(_xml_escape "$_SUITE_NAME")
  _JUNIT_CASES="${_JUNIT_CASES}  <testcase name=\"${xml_name}\" classname=\"${xml_suite}\" time=\"${duration}\"/>
"
  echo "  PASS (${duration}s)"
}

fail() {
  # Usage: fail <msg> [body]
  #
  # The optional <body> emits as a CDATA section inside the JUnit
  # <failure> element so dashboards (Jenkins, ReportPortal, GitHub
  # test reporter) render multi-line diagnostic context instead of
  # truncating the message attribute at ~120 chars. Use it for
  # response snippets, scan ids, kubectl commands, anything an
  # operator needs to triage without re-running the gate.
  local msg="${1:-assertion failed}"
  local body="${2:-}"
  local duration=$(( $(date +%s) - _TEST_START ))
  _FAIL_COUNT=$(( _FAIL_COUNT + 1 ))
  local xml_name
  xml_name=$(_xml_escape "$_TEST_NAME")
  local xml_suite
  xml_suite=$(_xml_escape "$_SUITE_NAME")
  local xml_msg
  xml_msg=$(_xml_escape "$msg")
  if [ -n "$body" ]; then
    # Defuse any embedded "]]>" so the CDATA terminator cannot be
    # injected via a response snippet that happens to contain it.
    local safe_body="${body//]]>/]]]]><![CDATA[>}"
    _JUNIT_CASES="${_JUNIT_CASES}  <testcase name=\"${xml_name}\" classname=\"${xml_suite}\" time=\"${duration}\">
    <failure message=\"${xml_msg}\"><![CDATA[${safe_body}]]></failure>
  </testcase>
"
  else
    _JUNIT_CASES="${_JUNIT_CASES}  <testcase name=\"${xml_name}\" classname=\"${xml_suite}\" time=\"${duration}\">
    <failure message=\"${xml_msg}\"/>
  </testcase>
"
  fi
  echo "  FAIL: ${msg} (${duration}s)"
  if [ -n "$body" ]; then
    echo "$body" | sed 's/^/    /'
  fi
  # NOTE: does NOT exit. end_suite handles the final exit code.
}

skip() {
  local reason="${1:-skipped}"
  local duration=$(( $(date +%s) - _TEST_START ))
  _SKIP_COUNT=$(( _SKIP_COUNT + 1 ))
  local xml_name
  xml_name=$(_xml_escape "$_TEST_NAME")
  local xml_suite
  xml_suite=$(_xml_escape "$_SUITE_NAME")
  local xml_reason
  xml_reason=$(_xml_escape "$reason")
  _JUNIT_CASES="${_JUNIT_CASES}  <testcase name=\"${xml_name}\" classname=\"${xml_suite}\" time=\"${duration}\">
    <skipped message=\"${xml_reason}\"/>
  </testcase>
"
  echo "  SKIP: ${reason} (${duration}s)"
}

## ---------------------------------------------------------------------------
## Capability-exemption allowlist (RELEASE_GATE only)
## ---------------------------------------------------------------------------
##
## `skip_suite` under RELEASE_GATE=1 is a HARD FAIL by design: a silently
## skipped suite is the silent-success class (#870/#871/#888) we want to
## catch loudly. That default stays in force for everything NOT listed here.
##
## A handful of suites, however, skip because a capability is genuinely NOT
## provisioned / NOT shipped in the gate deploy. That is an environment fact,
## not a backend defect, so hard-failing the gate on it is wrong. Each entry
## below is a capability that has been verified to be a not-provisioned /
## not-shipped condition (NOT a real bug), with the tracking issue that owns
## the provisioning (or shipping) work.
##
## Format of each row: "<capability_key>|<match_substring>|<tracking_issue>"
##   - capability_key:  stable identifier emitted in the EXEMPT line and logs
##   - match_substring: matched (substring, case-sensitive) against the exact
##                      skip_suite REASON the suite passes. Keep it distinctive
##                      enough that it cannot accidentally match an unrelated
##                      skip that might hide a real bug.
##   - tracking_issue:  the GitHub issue (this repo) tracking the exemption /
##                      provisioning. #211 owns the allowlist itself.
##
## CRITICAL: only add a row here for a capability that is genuinely
## not-provisioned or not-shipped. Never add a row to silence a skip that
## could mask a real backend bug. When in doubt, leave it hard-failing.
##
## Deliberately NOT exempted:
##   - formats/test-pypi-native-client.sh twine 401: the test already sends
##     valid Basic credentials (byte-identical to the curl -u upload that
##     PASSES in the same gate run). A 401 there is not a not-provisioned
##     capability, so it stays a hard failure pending backend triage.
_CAPABILITY_EXEMPTIONS=(
  # security: per-repo scan-config (auto-scan-on-upload) endpoint not shipped
  "scan_config_autoscan|scan-config endpoint not mounted (HTTP 404); auto-scan-on-upload feature not shipped|211"
  # security: scan-schedules (scheduled-scan) endpoint not shipped
  "scan_schedules|scan-schedules endpoint not mounted (HTTP 404); scheduled-scan feature not shipped|211"
  # security: Dependency-Track not deployed in gate namespace (see #200)
  "dependency_track|DEPENDENCY_TRACK_API_KEY and/or DEPENDENCY_TRACK_URL not set|200"
  "dependency_track|/api/v1/integrations/dependency-track not mounted (HTTP 404); backend pre-dates DTrack wiring|200"
  # security: OpenSCAP sidecar not provisioned in gate deploy
  "openscap|openscap service not configured|211"
  # platform: no WASM plugin fixture loaded against the gate backend
  "wasm_plugin_fixture|plugin list is empty; no plugin loaded against this backend deploy|211"
  "wasm_plugin_fixture|no plugin list endpoint responded; backend deploy may not include the plugin overlay|211"
  # mesh: run-now sync trigger endpoint not shipped (sync worker, TODO #78.4)
  "mesh_run_now|sync run-now endpoint not shipped (HTTP 404)|211"
)

## _match_capability_exemption REASON
##
## If REASON matches an allowlisted capability, echo "<key> <issue>" and
## return 0. Otherwise return 1. Matching is a plain substring test against
## the exact reason string, so the match_substring must appear verbatim.
_match_capability_exemption() {
  local reason="$1"
  local row key sub issue
  for row in "${_CAPABILITY_EXEMPTIONS[@]}"; do
    key="${row%%|*}"
    sub="${row#*|}"; sub="${sub%|*}"
    issue="${row##*|}"
    case "$reason" in
      *"$sub"*)
        echo "${key} ${issue}"
        return 0
        ;;
    esac
  done
  return 1
}

## skip_suite REASON
##
## Emit a JUnit testcase with <skipped/> for the SUITE itself, then exit
## the script. Use this for pre-flight skips that fire BEFORE any
## begin_test (e.g. "tool not installed"). Without this helper, a bare
## `exit 0` after a pre-flight check writes nothing to JUnit and the
## dashboard shows "no testcases" instead of an explicit skip reason.
##
## In release-gate context, if RELEASE_GATE=1 is set, skip_suite turns
## into a hard FAIL: a skipped gate is a silent-success class
## (#870/#871/#888) we want to catch loudly. Local-dev runs that don't
## set RELEASE_GATE keep the graceful skip.
##
## Exception: if the reason matches the documented capability-exemption
## allowlist (_CAPABILITY_EXEMPTIONS above), the suite is a known
## not-provisioned/not-shipped capability rather than a code defect. It is
## reported as EXEMPT (a JUnit <skipped/>, exit 0) instead of hard-failing.
## Any reason that does NOT match the allowlist still hard-fails, preserving
## the silent-success protection.
skip_suite() {
  local reason="${1:-suite skipped}"
  local duration=0
  if [ -n "${_SUITE_START:-}" ]; then
    duration=$(( $(date +%s) - _SUITE_START ))
  fi

  if [ "${RELEASE_GATE:-0}" = "1" ]; then
    local _exempt_match
    if _exempt_match=$(_match_capability_exemption "$reason"); then
      local cap="${_exempt_match%% *}"
      local issue="${_exempt_match##* }"
      echo "  EXEMPT: ${cap} (tracked by #${issue})"
      echo "          capability not provisioned/shipped in gate deploy; not a backend defect (reason: ${reason})"
      local xml_name
      xml_name=$(_xml_escape "preflight")
      local xml_suite
      xml_suite=$(_xml_escape "$_SUITE_NAME")
      local xml_reason
      xml_reason=$(_xml_escape "EXEMPT ${cap} (tracked by #${issue}): ${reason}")
      cat > "${JUNIT_OUTPUT_DIR}/${_SUITE_NAME}.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="${xml_suite}" tests="1" failures="0" skipped="1" time="${duration}">
  <testcase name="${xml_name}" classname="${xml_suite}" time="${duration}">
    <skipped message="${xml_reason}"/>
  </testcase>
</testsuite>
EOF
      exit 0
    fi

    echo "  FAIL: skip_suite called with RELEASE_GATE=1 (reason: ${reason})"
    echo "        a skipped suite in release-gate is silent-success; failing the gate"
    local xml_name
    xml_name=$(_xml_escape "preflight")
    local xml_suite
    xml_suite=$(_xml_escape "$_SUITE_NAME")
    local xml_reason
    xml_reason=$(_xml_escape "skip in release-gate context: ${reason}")
    cat > "${JUNIT_OUTPUT_DIR}/${_SUITE_NAME}.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="${xml_suite}" tests="1" failures="1" skipped="0" time="${duration}">
  <testcase name="${xml_name}" classname="${xml_suite}" time="${duration}">
    <failure message="${xml_reason}"/>
  </testcase>
</testsuite>
EOF
    exit 1
  fi

  echo "  SKIP_SUITE: ${reason} (${duration}s)"
  local xml_name
  xml_name=$(_xml_escape "preflight")
  local xml_suite
  xml_suite=$(_xml_escape "$_SUITE_NAME")
  local xml_reason
  xml_reason=$(_xml_escape "$reason")
  cat > "${JUNIT_OUTPUT_DIR}/${_SUITE_NAME}.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="${xml_suite}" tests="1" failures="0" skipped="1" time="${duration}">
  <testcase name="${xml_name}" classname="${xml_suite}" time="${duration}">
    <skipped message="${xml_reason}"/>
  </testcase>
</testsuite>
EOF
  exit 0
}

## assert_http_2xx STATUS [MSG]
##
## Assert that STATUS is in the 200-299 range. Returns non-zero if not.
## Replaces the inlined `[ -ge 200 -lt 300 ] 2>/dev/null` pattern that
## was duplicated across native-client tests; the `2>/dev/null` masked
## arithmetic failures (e.g. when STATUS was the literal string "000")
## and made debugging painful.
assert_http_2xx() {
  local status="${1:-}"
  local msg="${2:-HTTP status not in 2xx}"
  if [[ "$status" =~ ^[0-9]+$ ]] && [ "$status" -ge 200 ] && [ "$status" -lt 300 ]; then
    return 0
  fi
  fail "$msg (got status='$status')"
  return 1
}

end_suite() {
  local total_duration=$(( $(date +%s) - _SUITE_START ))
  local total=$(( _PASS_COUNT + _FAIL_COUNT + _SKIP_COUNT ))

  echo ""
  echo "========================================"
  echo "  Results: ${_PASS_COUNT} passed, ${_FAIL_COUNT} failed, ${_SKIP_COUNT} skipped (${total} total, ${total_duration}s)"
  echo "========================================"

  # Write JUnit XML
  local xml_file="${JUNIT_OUTPUT_DIR}/${_SUITE_NAME}.xml"
  local xml_suite
  xml_suite=$(_xml_escape "$_SUITE_NAME")
  cat > "$xml_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="${xml_suite}" tests="${total}" failures="${_FAIL_COUNT}" skipped="${_SKIP_COUNT}" time="${total_duration}">
${_JUNIT_CASES}</testsuite>
EOF

  # EXPECT_FAILURE self-test mode: inverts the exit code so an author can
  # point the suite at a known-broken backend (e.g. semaphore disabled) and
  # confirm the load-bearing assertion actually catches it. See the
  # "EXPECT_FAILURE self-test mode" block above for full semantics.
  if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
    if [ "$_FAIL_COUNT" -gt 0 ]; then
      echo "EXPECT_FAILURE=1: at least one test failed as expected; exiting 0"
      exit 0
    fi
    echo "EXPECT_FAILURE=1: every test passed but a failure was expected; exiting 1"
    exit 1
  fi

  if [ "$_FAIL_COUNT" -gt 0 ]; then
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Assertions
#
# Each assertion calls fail() on mismatch and returns 1 so callers can use
# them in conditionals. On success they return 0 silently.
#
# HTTP Status Code Guide (use exact codes, never OR them together):
#   401 = Unauthenticated - no valid credentials provided (missing/expired/invalid token)
#   403 = Forbidden - authenticated but insufficient permissions (wrong role/scope)
#   404 = Not Found - resource does not exist (or hidden from this user)
#   409 = Conflict - resource already exists or state conflict
#   422 = Unprocessable - request valid but semantically wrong
# When writing assertions, pick the EXACT code for the scenario.
# Checking "401 or 403" masks whether auth or authz is broken.
# ---------------------------------------------------------------------------

assert_eq() {
  local actual="$1"
  local expected="$2"
  local msg="${3:-expected '${expected}' but got '${actual}'}"
  if [ "$actual" != "$expected" ]; then
    fail "$msg"
    return 1
  fi
  return 0
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="${3:-expected output to contain '${needle}'}"
  if [[ "$haystack" != *"$needle"* ]]; then
    fail "$msg"
    return 1
  fi
  return 0
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="${3:-expected output not to contain '${needle}'}"
  if [[ "$haystack" == *"$needle"* ]]; then
    fail "$msg"
    return 1
  fi
  return 0
}

assert_http_ok() {
  local path="$1"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' -H "$(auth_header)" "${BASE_URL}${path}") || true
  if [ "$status" -lt 200 ] 2>/dev/null || [ "$status" -ge 300 ] 2>/dev/null; then
    fail "expected 2xx from ${path}, got ${status}"
    return 1
  fi
  return 0
}

assert_http_status() {
  local path="$1"
  local expected="$2"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' -H "$(auth_header)" "${BASE_URL}${path}") || true
  if [ "$status" != "$expected" ]; then
    fail "expected HTTP ${expected} from ${path}, got ${status}"
    return 1
  fi
  return 0
}

# assert_count JSON EXPECTED
# Handles three common response shapes:
#   - JSON array:         counts array length
#   - Object with .items: counts items array length
#   - Object with .total: uses the total field
assert_count() {
  local json="$1"
  local expected="$2"
  local actual
  actual=$(echo "$json" | jq '
    if type == "array" then length
    elif .items then (.items | length)
    elif .total != null then .total
    else 0
    end
  ')
  if [ "$actual" != "$expected" ]; then
    fail "expected count ${expected}, got ${actual}"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Prerequisite check
# ---------------------------------------------------------------------------

# require_cmd CMD
# Skips the entire suite (exit 0) if CMD is not on PATH.
require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" &>/dev/null; then
    echo "SKIP: ${cmd} not found, skipping suite ${_SUITE_NAME:-unknown}"
    exit 0
  fi
}

# ---------------------------------------------------------------------------
# Composable EXIT trap (LIFO)
# ---------------------------------------------------------------------------
#
# Bash only supports one EXIT trap per shell, so multiple `trap '...' EXIT`
# calls clobber each other. Tests that boot fixtures (mock upstreams, sidecar
# processes) need to chain cleanups onto whatever setup_workdir already
# registered.
#
# Usage:
#   add_exit_handler 'stop_mock_upstream'
#   add_exit_handler 'rm -rf "$STATE_DIR"'
# Handlers run in LIFO order (last-added first), each in a subshell-safe form
# so a failing handler does not block subsequent cleanups.

_EXIT_HANDLERS=()
_EXIT_HANDLERS_INSTALLED=0

_run_exit_handlers() {
  local rc=$?
  local i
  for (( i=${#_EXIT_HANDLERS[@]}-1; i>=0; i-- )); do
    eval "${_EXIT_HANDLERS[$i]}" || true
  done
  return $rc
}

add_exit_handler() {
  local cmd="$1"
  _EXIT_HANDLERS+=("$cmd")
  if [ "$_EXIT_HANDLERS_INSTALLED" -eq 0 ]; then
    trap _run_exit_handlers EXIT
    _EXIT_HANDLERS_INSTALLED=1
  fi
}

# ---------------------------------------------------------------------------
# TOTP helper
#
# Compute the current 6-digit TOTP code for a base32 secret using Python's
# stdlib (hmac/base64). Replaces oathtool so we do not have to extend the
# ARC runner image.
#
# Usage:
#   CODE=$(totp_code "$TOTP_SECRET")        # current window
#   CODE=$(totp_code "$TOTP_SECRET" wait)   # wait to next window if the
#                                           # last call returned the same
#                                           # code (avoids replay rejection
#                                           # when calling /enable then
#                                           # /disable back-to-back)
# ---------------------------------------------------------------------------

_totp_state_file() {
  # Shared state across $() subshells so 'wait' mode can detect a repeat
  # call. WORK_DIR is per-suite (set by setup_workdir), so this file is
  # naturally scoped to a single test script.
  echo "${WORK_DIR:-/tmp}/.totp_last_window_${PPID:-$$}"
}

_totp_compute() {
  python3 - "$1" <<'PY'
import base64, hmac, hashlib, struct, sys, time
secret = sys.argv[1].strip().upper().replace(" ", "")
pad = (-len(secret)) % 8
key = base64.b32decode(secret + ("=" * pad))
counter = int(time.time() // 30)
msg = struct.pack(">Q", counter)
digest = hmac.new(key, msg, hashlib.sha1).digest()
offset = digest[-1] & 0x0F
code = (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7FFFFFFF) % 1000000
print(f"{code:06d} {counter}")
PY
}

totp_code() {
  local secret="$1"
  local mode="${2:-now}"
  if [ -z "$secret" ]; then
    echo "totp_code: empty secret" >&2
    return 1
  fi
  local out code window
  if [ "$mode" = "wait" ]; then
    local state_file last_window
    state_file=$(_totp_state_file)
    last_window=$(cat "$state_file" 2>/dev/null || echo 0)
    out=$(_totp_compute "$secret") || return 1
    code="${out%% *}"; window="${out##* }"
    if [ "$window" -le "$last_window" ]; then
      local now_sec sleep_for
      now_sec=$(date +%s)
      sleep_for=$(( 30 - (now_sec % 30) + 1 ))
      sleep "$sleep_for"
      out=$(_totp_compute "$secret") || return 1
      code="${out%% *}"; window="${out##* }"
    fi
    echo "$window" > "$state_file" 2>/dev/null || true
  else
    out=$(_totp_compute "$secret") || return 1
    code="${out%% *}"; window="${out##* }"
    local state_file
    state_file=$(_totp_state_file)
    echo "$window" > "$state_file" 2>/dev/null || true
  fi
  echo "$code"
}

# ---------------------------------------------------------------------------
# Temp directory with automatic cleanup
# ---------------------------------------------------------------------------

WORK_DIR=""

_workdir_cleanup() {
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}

setup_workdir() {
  WORK_DIR="$(mktemp -d)"
  add_exit_handler "rm -rf \"$WORK_DIR\""
}

# enable_expect_failure_trap: deprecated no-op shim.
#
# Earlier auth tests (PR #98) called this helper expecting it to install an
# EXIT trap that inverts the exit code under EXPECT_FAILURE=1. That logic now
# lives centrally in end_suite() (see "EXPECT_FAILURE self-test mode" above).
# Calling both would double-invert and break the self-test signal, so this
# shim is intentionally empty -- it preserves the test interface during
# rebase without altering behavior.
enable_expect_failure_trap() {
  : # no-op; end_suite handles EXPECT_FAILURE inversion centrally
}

# ---------------------------------------------------------------------------
# Mock HTTP upstream fixture
# ---------------------------------------------------------------------------
#
# Boots tests/lib/mock-upstream.py as a controllable HTTP upstream the backend
# can dial. Used by proxy/cache tests (cache-poisoning, cache-stampede, ETag,
# stale-on-error, etc.) to seed bytes, swap content mid-flight, and read
# per-request counters.
#
# Globals set on success:
#   MOCK_PID            background server PID
#   MOCK_PORT           bound port (random by default; honors MOCK_PORT env)
#   MOCK_STATE_DIR      state directory the mock reads from / writes to
#   MOCK_BASE_URL       URL the *backend pod* should use (uses MOCK_UPSTREAM_HOSTNAME)
#   MOCK_LOCAL_URL      URL the test runner should use (127.0.0.1)
#
# Auto-cleanup is registered via add_exit_handler so callers don't have to
# manage trap stacks. Honors skip_teardown (env: SKIP_TEARDOWN=1) for debugging.
#
# Usage:
#   setup_workdir
#   start_mock_upstream "${WORK_DIR}/mock-state" || skip_suite "mock did not boot"
#   echo "payload" > "${MOCK_STATE_DIR}/files/pkg/v1/payload.bin"

# shellcheck disable=SC2034 # consumed by tests that source this file
MOCK_PID=""
# shellcheck disable=SC2034
MOCK_PORT=""
# shellcheck disable=SC2034
MOCK_STATE_DIR=""
# shellcheck disable=SC2034
MOCK_BASE_URL=""
# shellcheck disable=SC2034
MOCK_LOCAL_URL=""

# Pick an unused TCP port. Honors MOCK_PORT env (CI can pin); otherwise asks
# the kernel for a free port via getsockname(). Avoids the 18080 collision
# class when multiple suites run on the same runner pod.
_pick_mock_port() {
  if [ -n "${MOCK_PORT_OVERRIDE:-}" ]; then
    echo "$MOCK_PORT_OVERRIDE"
    return 0
  fi
  python3 -c '
import socket
s = socket.socket()
s.bind(("0.0.0.0", 0))
print(s.getsockname()[1])
s.close()
'
}

# start_mock_upstream STATE_DIR
# Boots the mock, waits up to 10s for /__readyz, registers an EXIT handler.
# Returns 0 on success; non-zero (and prints diagnostics) on failure.
start_mock_upstream() {
  local state_dir="$1"
  MOCK_STATE_DIR="$state_dir"
  mkdir -p "${MOCK_STATE_DIR}/files"
  MOCK_PORT="$(_pick_mock_port)"

  local mock_script
  mock_script="$(dirname "${BASH_SOURCE[0]}")/mock-upstream.py"
  if [ ! -f "$mock_script" ]; then
    echo "start_mock_upstream: mock-upstream.py not found at $mock_script" >&2
    return 1
  fi

  MOCK_STATE_DIR="$MOCK_STATE_DIR" MOCK_PORT="$MOCK_PORT" \
    python3 "$mock_script" \
    > "${WORK_DIR:-/tmp}/mock.out" 2> "${WORK_DIR:-/tmp}/mock.err" &
  MOCK_PID=$!
  # Disown so a bare `wait` in the caller (e.g. fan-out concurrency loops)
  # does not block on the long-lived mock process. Cleanup is still handled
  # via add_exit_handler -> stop_mock_upstream.
  disown "$MOCK_PID" 2>/dev/null || true

  MOCK_LOCAL_URL="http://127.0.0.1:${MOCK_PORT}"
  if [ -n "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
    MOCK_BASE_URL="http://${MOCK_UPSTREAM_HOSTNAME}:${MOCK_PORT}"
  else
    # shellcheck disable=SC2034 # consumed by sourcing test scripts
    MOCK_BASE_URL="$MOCK_LOCAL_URL"
  fi

  add_exit_handler "stop_mock_upstream"

  # Readiness probe: __readyz bypasses logging/counters/delay so the wait
  # itself doesn't pollute mock state.
  local code
  for _ in $(seq 1 20); do
    if ! kill -0 "$MOCK_PID" 2>/dev/null; then
      echo "start_mock_upstream: mock died during boot" >&2
      [ -f "${WORK_DIR:-/tmp}/mock.err" ] && cat "${WORK_DIR:-/tmp}/mock.err" >&2 || true
      return 1
    fi
    code=$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' "${MOCK_LOCAL_URL}/__readyz" 2>/dev/null) || code="000"
    if [ "$code" = "200" ]; then
      return 0
    fi
    sleep 0.5
  done
  echo "start_mock_upstream: not ready on ${MOCK_LOCAL_URL} after 10s" >&2
  return 1
}

stop_mock_upstream() {
  if [ -n "${MOCK_PID:-}" ] && kill -0 "$MOCK_PID" 2>/dev/null; then
    kill "$MOCK_PID" 2>/dev/null || true
    # SIGTERM, then escalate after 2s if the handler is mid-sleep (stampede
    # tests can have requests blocked in time.sleep at shutdown).
    local i
    for i in 1 2 3 4; do
      kill -0 "$MOCK_PID" 2>/dev/null || break
      sleep 0.5
    done
    if kill -0 "$MOCK_PID" 2>/dev/null; then
      kill -9 "$MOCK_PID" 2>/dev/null || true
    fi
    wait "$MOCK_PID" 2>/dev/null || true
  fi
  MOCK_PID=""
}

# wait_for_file_value FILE EXPECTED_REGEX TIMEOUT_SECS
# Polls FILE every 0.2s until its content matches EXPECTED_REGEX or the
# timeout fires. Replaces ad-hoc `sleep N` waits for fixture state changes.
# Returns 0 on match, 1 on timeout.
wait_for_file_value() {
  local file="$1"
  local pattern="$2"
  local timeout="${3:-5}"
  local elapsed=0
  local step=0.2
  local steps
  steps=$(awk -v t="$timeout" -v s="$step" 'BEGIN{print int(t/s)}')
  for _ in $(seq 1 "$steps"); do
    if [ -f "$file" ] && grep -qE "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    sleep "$step"
    elapsed=$((elapsed + 1))
  done
  return 1
}

# wait_for_counter_stable FILE TIMEOUT_SECS [STABLE_WINDOW_SECS]
# Polls a numeric counter file (e.g. mock peak-inflight) until its value has
# not changed for STABLE_WINDOW_SECS (default 0.6s) or TIMEOUT_SECS fires.
# Use this in place of `sleep 1` when reading mock-upstream peak counters.
# Echoes the final value on stdout. Returns 0 if stable; 1 on timeout.
wait_for_counter_stable() {
  local file="$1"
  local timeout="${2:-5}"
  local stable_window="${3:-0.6}"
  local last="" cur=""
  local stable_for=0
  local elapsed=0
  local steps
  steps=$(awk -v t="$timeout" 'BEGIN{print int(t/0.2)}')
  local stable_steps
  stable_steps=$(awk -v t="$stable_window" 'BEGIN{print int(t/0.2)}')
  for _ in $(seq 1 "$steps"); do
    cur=$(cat "$file" 2>/dev/null || echo "")
    if [ -n "$cur" ] && [ "$cur" = "$last" ]; then
      stable_for=$((stable_for + 1))
      if [ "$stable_for" -ge "$stable_steps" ]; then
        echo "$cur"
        return 0
      fi
    else
      stable_for=0
      last="$cur"
    fi
    sleep 0.2
    elapsed=$((elapsed + 1))
  done
  echo "$last"
  return 1
}

# ---------------------------------------------------------------------------
# EXPECT_FAILURE self-test mode
# ---------------------------------------------------------------------------
#
# When EXPECT_FAILURE=1 is set, the *suite-level* exit code is inverted at
# end_suite: a passing suite returns non-zero and a failing suite returns 0.
# Use this to verify that a load-bearing assertion actually catches a known
# breakage (e.g. point the test at a backend image with the semaphore
# disabled and confirm EXIT=0 with the inversion). Without this, "the test
# passed" is indistinguishable from "the test could never fail".
#
# This only inverts the exit code; it does NOT silence per-test failure
# output, so logs still tell you which assertion fired.

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Escape special XML characters in attribute values.
_xml_escape() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  s="${s//\"/&quot;}"
  s="${s//\'/&apos;}"
  echo "$s"
}

# ---------------------------------------------------------------------------
# Remote / Virtual repository helpers
# ---------------------------------------------------------------------------

# create_remote_repo KEY FORMAT UPSTREAM_URL [DESCRIPTION]
# Creates a remote (proxy) repository that caches artifacts from an upstream.
create_remote_repo() {
  local key="$1"
  local format="$2"
  local upstream_url="$3"
  local description="${4:-Remote proxy for ${format}}"

  local payload
  payload=$(jq -n \
    --arg key "$key" \
    --arg name "$key" \
    --arg format "$format" \
    --arg upstream_url "$upstream_url" \
    --arg description "$description" \
    '{key: $key, name: $name, format: $format, repo_type: "remote", upstream_url: $upstream_url, description: $description, is_public: true}')

  api_post "/api/v1/repositories" "$payload" > /dev/null
}

# create_virtual_repo KEY FORMAT [MEMBER_KEYS] [DESCRIPTION]
# Creates a virtual repository that aggregates multiple backing repos.
# MEMBER_KEYS is a comma-separated list of repository keys (e.g. "local-npm,remote-npm").
# If omitted, the virtual repo is created with no members (add them later via the API).
create_virtual_repo() {
  local key="$1"
  local format="$2"
  local member_keys="${3:-}"
  local description="${4:-Virtual repo for ${format}}"

  local payload
  payload=$(jq -n \
    --arg key "$key" \
    --arg name "$key" \
    --arg format "$format" \
    --arg description "$description" \
    '{key: $key, name: $name, format: $format, repo_type: "virtual", description: $description, is_public: true}')

  api_post "/api/v1/repositories" "$payload" > /dev/null

  # Add each member repository (if any specified). Use a subshell tr to split
  # on commas so we don't leak `IFS=','` into downstream `api_post` calls -- the
  # earlier in-place `local IFS=','` form caused `$CURL_TIMEOUT` to splat as a
  # single arg rather than multiple flags, producing
  # `curl: option --max-time 60 --connect-timeout 10: is unknown`.
  if [ -n "$member_keys" ]; then
    local member
    for member in $(printf '%s\n' "$member_keys" | tr ',' '\n'); do
      local member_payload
      member_payload=$(jq -n --arg key "$member" '{member_key: $key}')
      api_post "/api/v1/repositories/${key}/members" "$member_payload" > /dev/null
    done
  fi
}

# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------

# wait_for_scan REPO_KEY ARTIFACT_PATH [TIMEOUT_SECS]
# Polls the scan endpoint until the status is no longer "pending" or "scanning".
# Returns the final scan status on stdout.
wait_for_scan() {
  local repo_key="$1"
  local artifact_path="$2"
  local timeout="${3:-60}"

  local elapsed=0
  local status=""
  while [ "$elapsed" -lt "$timeout" ]; do
    local resp
    resp=$(api_get "/api/v1/repositories/${repo_key}/artifacts/${artifact_path}/security/scan" 2>/dev/null) || true
    if [ -n "$resp" ]; then
      status=$(echo "$resp" | jq -r '.scan_status // .status // "unknown"')
      if [ "$status" != "pending" ] && [ "$status" != "scanning" ]; then
        echo "$status"
        return 0
      fi
    fi
    sleep 3
    elapsed=$(( elapsed + 3 ))
  done

  echo "${status:-timeout}"
  return 1
}

# assert_scan_completed REPO_KEY ARTIFACT_PATH
# Waits for the scan to finish and asserts the status is "completed" or "clean".
assert_scan_completed() {
  local repo_key="$1"
  local artifact_path="$2"

  local status
  if ! status=$(wait_for_scan "$repo_key" "$artifact_path" 60); then
    fail "scan did not complete within 60s for ${repo_key}/${artifact_path} (status: ${status})"
    return 1
  fi

  if [ "$status" != "completed" ] && [ "$status" != "clean" ]; then
    fail "expected scan status 'completed' or 'clean', got '${status}' for ${repo_key}/${artifact_path}"
    return 1
  fi
  return 0
}

# assert_scan_has_findings REPO_KEY ARTIFACT_PATH
# Waits for the scan and verifies the findings array is non-empty.
assert_scan_has_findings() {
  local repo_key="$1"
  local artifact_path="$2"

  wait_for_scan "$repo_key" "$artifact_path" 60 > /dev/null || true

  local resp
  resp=$(api_get "/api/v1/repositories/${repo_key}/artifacts/${artifact_path}/security/scan") || {
    fail "failed to fetch scan results for ${repo_key}/${artifact_path}"
    return 1
  }

  local count
  count=$(echo "$resp" | jq '.findings | length // 0')
  if [ "$count" -eq 0 ]; then
    fail "expected scan findings for ${repo_key}/${artifact_path}, got none"
    return 1
  fi
  return 0
}

# trigger_and_wait_scan ARTIFACT_ID [TIMEOUT_SECS] [SCAN_TYPE]
#
# Triggers POST /api/v1/security/scan for the given artifact_id and polls
# GET /api/v1/security/scans?artifact_id=X until the most-recent matching row
# (optionally filtered by scan_type=SCAN_TYPE) reaches a terminal state, then
# echoes its scan_id on stdout.
#
# Return codes:
#   0 -- scan reached a terminal state (completed|failed|error|cancelled);
#        scan_id echoed on stdout
#   2 -- scanner not available: HTTP 501/502/503/504 from trigger, or HTTP 500
#        with body matching /scanner.*not.*configured/. Caller should skip.
#   3 -- trigger succeeded but the scan did not reach a terminal state within
#        timeout (stuck running/pending). Caller should fail with a timeout
#        message rather than skip — this is the exact bug class the suite
#        exists to catch.
#   1 -- any other non-2xx trigger response. Caller should fail.
#
# WORK_DIR must be set (callers should invoke setup_workdir first); response
# bodies are written under WORK_DIR/ for diagnostic capture. artifact_id is
# sanitized into the filename so a backend-returned id containing path
# separators cannot escape WORK_DIR.
trigger_and_wait_scan() {
  local artifact_id="$1"
  local timeout="${2:-180}"
  local scan_type="${3:-}"
  local trigger_status final_status="" scan_id="" elapsed=0
  local safe_id="${artifact_id//[^a-zA-Z0-9._-]/_}"
  local trig_body="${WORK_DIR}/trig-${safe_id}.json"

  trigger_status=$(curl -s -o "$trig_body" -w '%{http_code}' \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"artifact_id\":\"${artifact_id}\"}" \
    "${BASE_URL}/api/v1/security/scan") || trigger_status="000"

  case "$trigger_status" in
    501|502|503|504) return 2 ;;
    500)
      if grep -qi "scanner.*not.*configured" "$trig_body" 2>/dev/null; then
        return 2
      fi
      echo "POST /security/scan returned HTTP 500" >&2
      return 1
      ;;
  esac
  if [[ ! "$trigger_status" =~ ^2[0-9][0-9]$ ]]; then
    echo "POST /security/scan returned HTTP ${trigger_status}" >&2
    return 1
  fi

  # jq selector: optionally filter items by scan_type before picking the first row.
  # Accept both envelope shapes ({items:[...]} and bare array) since the
  # backend's response shape differs between the per-artifact and the global
  # scans endpoint.
  local jq_pick
  if [ -n "$scan_type" ]; then
    jq_pick="[(.items // .)[]? | select(.scan_type==\"${scan_type}\")] | .[0]"
  else
    jq_pick="(.items // .)[0]"
  fi

  while [ "$elapsed" -lt "$timeout" ]; do
    local scans_resp
    scans_resp=$(api_get "/api/v1/security/scans?artifact_id=${artifact_id}&per_page=20" 2>/dev/null) || true
    if [ -n "$scans_resp" ]; then
      scan_id=$(echo "$scans_resp" | jq -r "${jq_pick}.id // empty" 2>/dev/null || echo "")
      final_status=$(echo "$scans_resp" | jq -r "${jq_pick}.status // empty" 2>/dev/null || echo "")
      case "$final_status" in
        completed|failed|error|cancelled) break ;;
      esac
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done

  echo "$scan_id"
  case "$final_status" in
    completed|failed|error|cancelled) return 0 ;;
  esac
  # Did not reach a terminal state. Distinguish "no row at all" (likely skip-
  # worthy; backend never accepted the scan) from "stuck running" (must fail).
  if [ -z "$scan_id" ]; then return 2; fi
  return 3
}

# ---------------------------------------------------------------------------
# SBOM helpers
# ---------------------------------------------------------------------------

# get_sbom REPO_KEY ARTIFACT_NAME ARTIFACT_VERSION
# Fetches the SBOM for a specific artifact version. Outputs the JSON response.
get_sbom() {
  local repo_key="$1"
  local artifact_name="$2"
  local artifact_version="$3"

  api_get "/api/v1/repositories/${repo_key}/artifacts/${artifact_name}/${artifact_version}/sbom"
}

# assert_sbom_has_components REPO_KEY ARTIFACT_NAME ARTIFACT_VERSION [MIN_COUNT]
# Fetches the SBOM and asserts the components array has at least MIN_COUNT entries.
assert_sbom_has_components() {
  local repo_key="$1"
  local artifact_name="$2"
  local artifact_version="$3"
  local min_count="${4:-1}"

  local resp
  resp=$(get_sbom "$repo_key" "$artifact_name" "$artifact_version") || {
    fail "failed to fetch SBOM for ${repo_key}/${artifact_name}@${artifact_version}"
    return 1
  }

  local count
  count=$(echo "$resp" | jq '.components | length // 0')
  if [ "$count" -lt "$min_count" ]; then
    fail "expected >= ${min_count} SBOM components for ${repo_key}/${artifact_name}@${artifact_version}, got ${count}"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

# assert_artifact_cached REPO_KEY ARTIFACT_PATH
# Verifies that an artifact exists in the repository's artifact list.
assert_artifact_cached() {
  local repo_key="$1"
  local artifact_path="$2"

  local resp
  resp=$(api_get "/api/v1/repositories/${repo_key}/artifacts") || {
    fail "failed to list artifacts for ${repo_key}"
    return 1
  }

  local found
  found=$(echo "$resp" | jq --arg path "$artifact_path" '
    if type == "array" then map(select(.path == $path or .name == $path)) | length
    elif .items then [.items[] | select(.path == $path or .name == $path)] | length
    else 0
    end
  ')
  if [ "$found" -eq 0 ]; then
    fail "artifact '${artifact_path}' not found in cached artifacts for ${repo_key}"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Proxy helpers
# ---------------------------------------------------------------------------

# proxy_and_verify REPO_KEY FORMAT PACKAGE_NAME PACKAGE_VERSION
# Pulls an artifact through the remote proxy using the format-native endpoint,
# then verifies it was cached locally.
proxy_and_verify() {
  local repo_key="$1"
  local format="$2"
  local package_name="$3"
  local package_version="$4"

  local pull_path=""
  case "$format" in
    npm)
      pull_path="/${repo_key}/${package_name}/-/${package_name}-${package_version}.tgz"
      ;;
    pypi)
      pull_path="/api/v1/pypi/${repo_key}/packages/${package_name}/${package_version}/${package_name}-${package_version}.tar.gz"
      ;;
    maven)
      # Expects package_name as "group/artifact" (e.g. "org/example/mylib")
      pull_path="/${repo_key}/${package_name}/${package_version}/${package_name##*/}-${package_version}.jar"
      ;;
    cargo)
      pull_path="/api/v1/crates/${repo_key}/${package_name}/${package_version}/download"
      ;;
    nuget)
      pull_path="/api/v1/nuget/${repo_key}/package/${package_name}/${package_version}/${package_name}.${package_version}.nupkg"
      ;;
    go)
      pull_path="/${repo_key}/${package_name}/@v/${package_version}.zip"
      ;;
    docker|oci)
      # For OCI/Docker, pull the manifest to trigger caching
      pull_path="/v2/${repo_key}/${package_name}/manifests/${package_version}"
      ;;
    *)
      pull_path="/api/v1/repositories/${repo_key}/artifacts/${package_name}/${package_version}"
      ;;
  esac

  local http_status
  http_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}${pull_path}") || true

  if [ "$http_status" -lt 200 ] 2>/dev/null || [ "$http_status" -ge 300 ] 2>/dev/null; then
    fail "proxy pull failed for ${format}/${package_name}@${package_version}: HTTP ${http_status}"
    return 1
  fi

  # Verify the artifact was cached
  assert_artifact_cached "$repo_key" "${package_name}" || return 1
  return 0
}
