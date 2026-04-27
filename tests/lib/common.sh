#!/usr/bin/env bash
# common.sh - Shared test helpers for artifact-keeper-test
#
# Source this at the top of every test script:
#   source "$(dirname "$0")/../lib/common.sh"
#
# Provides: configuration defaults, auth, HTTP helpers, repository helpers,
# test framework (begin_suite/begin_test/pass/fail/end_suite with JUnit XML),
# assertions, and utility functions.

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

mkdir -p "$JUNIT_OUTPUT_DIR"

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
    "conan_remote_search_forward")  echo "1.3.0" ;;
    "conan_virtual_search_aggregate") echo "1.3.0" ;;
    "maven_virtual_snapshot")       echo "1.2.0" ;;
    "guest_access_toggle")          echo "1.2.0" ;;
    "opensearch_indexing")          echo "1.2.0" ;;
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

  api_post "/api/v1/repositories" "$payload" > /dev/null
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
  local msg="${1:-assertion failed}"
  local duration=$(( $(date +%s) - _TEST_START ))
  _FAIL_COUNT=$(( _FAIL_COUNT + 1 ))
  local xml_name
  xml_name=$(_xml_escape "$_TEST_NAME")
  local xml_suite
  xml_suite=$(_xml_escape "$_SUITE_NAME")
  local xml_msg
  xml_msg=$(_xml_escape "$msg")
  _JUNIT_CASES="${_JUNIT_CASES}  <testcase name=\"${xml_name}\" classname=\"${xml_suite}\" time=\"${duration}\">
    <failure message=\"${xml_msg}\"/>
  </testcase>
"
  echo "  FAIL: ${msg} (${duration}s)"
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
skip_suite() {
  local reason="${1:-suite skipped}"
  local duration=0
  if [ -n "${_SUITE_START:-}" ]; then
    duration=$(( $(date +%s) - _SUITE_START ))
  fi

  if [ "${RELEASE_GATE:-0}" = "1" ]; then
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
  echo "ASSERTION FAILED: ${msg} (got status='${status}')" >&2
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
# Temp directory with automatic cleanup
# ---------------------------------------------------------------------------

WORK_DIR=""

setup_workdir() {
  WORK_DIR="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf \"$WORK_DIR\"" EXIT
}

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
  # on commas so we don't leak `IFS=','` into downstream `api_post` calls — the
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
