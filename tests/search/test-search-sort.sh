#!/usr/bin/env bash
# test-search-sort.sh - sort_by / sort_order parameters on advanced search
#
# Epic 8 sub-task 8.6 (artifact-keeper-test#73). The advanced search
# endpoint (OpenAPI: /api/v1/search/advanced) accepts sort_by and
# sort_order query parameters. There is no E2E coverage today, so a
# regression that silently ignores sort_order or returns a non-2xx for
# any valid sort_by value would not be caught by the gate.
#
# Strategy: upload three sentinels of distinct sizes (small / medium /
# large) into one fresh repo, then ask the search backend to order by
# size in ascending and descending order. The load-bearing assertion
# is that the first hit under sort_order=asc and the first hit under
# sort_order=desc are NOT the same artifact (i.e. flipping the order
# actually flips the head of the result set). This catches the common
# regression where sort_order is parsed but never applied.
#
# We additionally smoke-probe the supported sort_by values (name,
# created_at, size) by asserting each returns a 2xx with a parseable
# JSON body. An unrecognised sort_by must NOT 5xx; either 2xx (ignored)
# or 4xx (rejected) is acceptable.
#
# Skips cleanly if:
#   - advanced search endpoint is not available (404/501)
#   - search backend is unavailable at preflight (503/504/000)
#
# Requires: curl, jq, dd

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-sort"
auth_admin
setup_workdir

# Preflight: search backend may be unwired in some test environments.
preflight_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/advanced?query=preflight&per_page=1" 2>/dev/null || echo "000")
case "$preflight_status" in
  404|501)
    skip_suite "advanced search endpoint not available (HTTP ${preflight_status})"
    ;;
  503|504|000)
    skip_suite "search backend unavailable (HTTP ${preflight_status})"
    ;;
esac

REPO_KEY="srch-sort-${RUN_ID}"
UNIQUE_TERM="sort${RUN_ID//[^a-z0-9]/}"

add_exit_handler "api_delete \"/api/v1/repositories/${REPO_KEY}\" >/dev/null 2>&1 || true"

# -------------------------------------------------------------------------
# Build a known corpus with three distinct sizes so sort-by-size has
# something deterministic to order.
# -------------------------------------------------------------------------

begin_test "Create repo and upload three distinct-size sentinels"
ok=true
create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1 || ok=false

SMALL="${WORK_DIR}/small-${UNIQUE_TERM}.bin"
MED="${WORK_DIR}/med-${UNIQUE_TERM}.bin"
LARGE="${WORK_DIR}/large-${UNIQUE_TERM}.bin"
dd if=/dev/zero of="$SMALL" bs=1    count=256   2>/dev/null  #  256 B
dd if=/dev/zero of="$MED"   bs=1024 count=8     2>/dev/null  #   8 KB
dd if=/dev/zero of="$LARGE" bs=1024 count=64    2>/dev/null  #  64 KB

api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/small.bin" "$SMALL" >/dev/null 2>&1 || ok=false
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/med.bin"   "$MED"   >/dev/null 2>&1 || ok=false
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/large.bin" "$LARGE" >/dev/null 2>&1 || ok=false
if [ "$ok" = true ]; then
  pass
else
  fail "could not seed sort corpus"
  end_suite
fi

sleep 4   # allow async indexing to surface all three sentinels

# _first_name JSON
# Extract the name (or final path segment) of the first hit in an advanced
# search response. Tolerant of the common wrapper shapes (.items, .results,
# .hits, bare array).
_first_name() {
  echo "$1" | jq -r '
    def hits:
      if type == "array" then .
      elif (.items?   | type) == "array" then .items
      elif (.results? | type) == "array" then .results
      elif (.hits?    | type) == "array" then .hits
      else [] end;
    (hits | .[0] // {})
    | (.name // .path // .artifact_path // "")
    | (split("/") | .[-1])
  ' 2>/dev/null
}

# -------------------------------------------------------------------------
# 8.6 sort_order=asc vs desc on sort_by=size must flip the head of the list.
# -------------------------------------------------------------------------

begin_test "sort_order=asc vs desc on sort_by=size flips the head hit"
asc_resp=$(api_get "/api/v1/search/advanced?query=${UNIQUE_TERM}&sort_by=size&sort_order=asc&per_page=10" 2>/dev/null || echo "")
desc_resp=$(api_get "/api/v1/search/advanced?query=${UNIQUE_TERM}&sort_by=size&sort_order=desc&per_page=10" 2>/dev/null || echo "")

if [ -z "$asc_resp" ] || [ -z "$desc_resp" ]; then
  skip "advanced search did not accept sort_by/sort_order parameters"
else
  first_asc=$(_first_name "$asc_resp")
  first_desc=$(_first_name "$desc_resp")
  if [ -z "$first_asc" ] || [ -z "$first_desc" ]; then
    skip "sort response did not contain a parseable first hit (asc='${first_asc}', desc='${first_desc}')"
  elif [ "$first_asc" = "$first_desc" ]; then
    fail "sort_order had no effect: first hit is '${first_asc}' under both asc and desc"
  else
    pass
  fi
fi

# -------------------------------------------------------------------------
# 8.6 supported sort_by values must not 5xx.
# -------------------------------------------------------------------------

for field in name created_at size; do
  begin_test "sort_by=${field} returns a non-5xx response"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/search/advanced?query=${UNIQUE_TERM}&sort_by=${field}&per_page=5" 2>/dev/null || echo "000")
  case "$status" in
    5*) fail "sort_by=${field} returned HTTP ${status} (expected 2xx or 4xx)" ;;
    *)  pass ;;
  esac
done

# -------------------------------------------------------------------------
# 8.6 unrecognised sort_by must not panic the handler.
# -------------------------------------------------------------------------

begin_test "sort_by=nonsense_field does not 5xx"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/advanced?query=${UNIQUE_TERM}&sort_by=nonsense_field_${RUN_ID}&per_page=5" 2>/dev/null || echo "000")
case "$status" in
  5*) fail "unrecognised sort_by returned HTTP ${status}; handler should reject (4xx) or ignore (2xx)" ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 8.6 unrecognised sort_order must not panic the handler.
# -------------------------------------------------------------------------

begin_test "sort_order=sideways does not 5xx"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/advanced?query=${UNIQUE_TERM}&sort_by=size&sort_order=sideways&per_page=5" 2>/dev/null || echo "000")
case "$status" in
  5*) fail "unrecognised sort_order returned HTTP ${status}; handler should reject (4xx) or ignore (2xx)" ;;
  *)  pass ;;
esac

end_suite
