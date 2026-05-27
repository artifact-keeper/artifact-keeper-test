#!/usr/bin/env bash
# test-json-validation-400-1368.sh -- Malformed JSON returns 400 VALIDATION_ERROR
#
# Reproducer / regression test for artifact-keeper#1368.
#
# Background
#   Axum's stock Json<T> extractor rejects malformed request bodies with HTTP
#   422 and an opaque text/plain message. Our public API contract is:
#     "any client error returns 400 with {code: 'VALIDATION_ERROR', message: ...}"
#   This is what every other 400 in the codebase emits (AppError::Validation
#   maps to (BAD_REQUEST, "VALIDATION_ERROR") in backend/src/error.rs).
#
#   PR #1381 introduced `crate::api::extractors::Json<T>`, a drop-in wrapper
#   around axum::Json that converts any JsonRejection into AppError::Validation
#   so the response envelope is consistent. The repositories handlers were
#   swapped to the new extractor.
#
# What this script catches
#   - A regression that re-imports `axum::Json` in a handler that previously
#     used the wrapper -- the symptom is 422 returning instead of 400.
#   - A regression that breaks the AppError::Validation -> 400 mapping --
#     the symptom is 422 OR a body without the VALIDATION_ERROR code.
#   - A wrapper-internal regression that drops the JSON error envelope --
#     the symptom is 400 but the body no longer contains
#     {"code": "VALIDATION_ERROR"}.
#
#   The release-gate's existing `virtual-repo-malformed-input` test only
#   asserts the status code. This script tightens the assertion to include
#   the response body's `code` field, which is what the issue #1368 customer
#   was missing on the SDK side.
#
# Sibling test: tests/repos/test-virtual-repo-malformed-input.sh runs a wider
# set of malformed-body shapes but does not assert on the body envelope.
# That test catches "status changed from 400"; this one catches "envelope
# changed from VALIDATION_ERROR".
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "json-validation-400-1368"
auth_admin

LOCAL_A="test-jv-a-${RUN_ID}"
LOCAL_B="test-jv-b-${RUN_ID}"
VIRTUAL_KEY="test-jv-virt-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup -- real backing repos so a 4xx on the malformed PUT is a body /
# envelope reject, never a 404 / 400 from the path resolution layer.
# -------------------------------------------------------------------------

begin_test "Setup: create local repo A"
if create_local_repo "$LOCAL_A" "generic"; then
  pass
else
  fail "could not create local repo A"
fi

begin_test "Setup: create local repo B"
if create_local_repo "$LOCAL_B" "generic"; then
  pass
else
  fail "could not create local repo B"
fi

begin_test "Setup: create virtual repo with members A,B"
if create_virtual_repo "$VIRTUAL_KEY" "generic" "${LOCAL_A},${LOCAL_B}"; then
  pass
else
  fail "could not create virtual repo with members"
fi

# Settle until both members are visible so the malformed PUT below is fired
# at a fully-realised path.
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "2" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

MEMBERS_PATH="/api/v1/repositories/${VIRTUAL_KEY}/members"

# -------------------------------------------------------------------------
# Helper: PUT a literal body, capture both status and body. Echo
#   "<status>\t<body>"
# so callers can split deterministically. Use --data-binary so payloads
# stay byte-exact (no curl-injected newlines on JSON-unfriendly input).
# -------------------------------------------------------------------------

put_with_body() {
  local path="$1"
  local body="$2"
  local out
  out=$(mktemp)
  local args=(-s -o "$out" -w '%{http_code}' --max-time 60 --connect-timeout 10
              -X PUT
              -H "$(auth_header)"
              -H "Content-Type: application/json")
  if [ -n "$body" ]; then
    args+=(--data-binary "$body")
  fi
  args+=("${BASE_URL}${path}")
  local code
  code=$(curl "${args[@]}") || code="000"
  local resp
  resp=$(cat "$out" 2>/dev/null || echo "")
  rm -f "$out"
  printf '%s\t%s\n' "$code" "$resp"
}

# assert_400_validation_error <status> <body> <label>
#   - status must be exactly 400 (not 422, the pre-fix shape).
#   - body must parse as JSON.
#   - body.code must equal "VALIDATION_ERROR".
#
# These three predicates are the load-bearing #1368 contract; verifying only
# the status (the existing virtual-repo-malformed-input does that) lets a
# regression sneak through where the body envelope changes to something an
# SDK can't deserialise.
assert_400_validation_error() {
  local status="$1"
  local body="$2"
  local label="$3"

  if [ "$status" != "400" ]; then
    fail "${label}: expected status 400 (VALIDATION_ERROR contract), got ${status}" \
"response body (first 300 bytes): ${body:0:300}
note: HTTP 422 here is the pre-#1381 regression shape (axum's default JsonRejection mapping)."
    return 1
  fi

  if ! echo "$body" | jq -e . >/dev/null 2>&1; then
    fail "${label}: status was 400 but body is not JSON" \
"response body (first 300 bytes): ${body:0:300}
note: even error responses must be JSON so SDK clients can deserialise the envelope."
    return 1
  fi

  local code
  code=$(echo "$body" | jq -r '.code // empty' 2>/dev/null || echo "")
  if [ "$code" != "VALIDATION_ERROR" ]; then
    fail "${label}: body missing code='VALIDATION_ERROR' envelope" \
"actual code: '${code}'
response body (first 300 bytes): ${body:0:300}
contract: AppError::Validation maps to {status: 400, code: 'VALIDATION_ERROR'} in backend/src/error.rs"
    return 1
  fi

  return 0
}

# -------------------------------------------------------------------------
# Case 1: PUT /members with member array element missing required member_key.
#
# This is the exact shape called out in #1368: the array element has a
# priority but no member_key. axum's stock extractor rejects this with 422;
# the wrapper from #1381 must convert it to 400 + VALIDATION_ERROR.
# -------------------------------------------------------------------------

begin_test "PUT /members missing member_key returns 400 with code=VALIDATION_ERROR"
PAYLOAD='{"members":[{"priority":1}]}'
result=$(put_with_body "$MEMBERS_PATH" "$PAYLOAD")
status="${result%%$'\t'*}"
body="${result#*$'\t'}"
assert_400_validation_error "$status" "$body" "PUT ${MEMBERS_PATH} missing member_key" && pass

# -------------------------------------------------------------------------
# Case 2: PUT /members with priority sent as a JSON string. This is the
# type-mismatch path of the JsonRejection class -- a different code path
# inside axum than the missing-field case above. The wrapper must coerce
# this branch too.
# -------------------------------------------------------------------------

begin_test "PUT /members priority=string returns 400 with code=VALIDATION_ERROR"
PAYLOAD_TYPE_MISMATCH=$(jq -n \
  --arg a "$LOCAL_A" \
  '{members: [{member_key: $a, priority: "high"}]}')
result=$(put_with_body "$MEMBERS_PATH" "$PAYLOAD_TYPE_MISMATCH")
status="${result%%$'\t'*}"
body="${result#*$'\t'}"
assert_400_validation_error "$status" "$body" "PUT ${MEMBERS_PATH} priority as string" && pass

# -------------------------------------------------------------------------
# Case 3: syntactically malformed JSON. This is the third major JsonRejection
# branch (serde_json::Error rather than missing-field / type-mismatch).
# Important to assert it explicitly because the wrapper has to forward
# parser errors with the same envelope.
# -------------------------------------------------------------------------

begin_test "PUT /members with malformed JSON returns 400 with code=VALIDATION_ERROR"
result=$(put_with_body "$MEMBERS_PATH" '{')
status="${result%%$'\t'*}"
body="${result#*$'\t'}"
assert_400_validation_error "$status" "$body" "PUT ${MEMBERS_PATH} malformed JSON" && pass

# -------------------------------------------------------------------------
# Case 4: empty body. axum's default rejection class for "missing Content"
# is yet another arm of JsonRejection; verify the wrapper catches it too so
# the envelope is consistent across all four major rejection arms.
# -------------------------------------------------------------------------

begin_test "PUT /members with empty body returns 400 with code=VALIDATION_ERROR"
result=$(put_with_body "$MEMBERS_PATH" "")
status="${result%%$'\t'*}"
body="${result#*$'\t'}"
assert_400_validation_error "$status" "$body" "PUT ${MEMBERS_PATH} empty body" && pass

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_B}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_A}" > /dev/null 2>&1 || true

end_suite
