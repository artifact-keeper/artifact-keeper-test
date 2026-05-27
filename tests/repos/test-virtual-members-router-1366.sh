#!/usr/bin/env bash
# test-virtual-members-router-1366.sh -- Virtual repo /members sub-router shape
#
# Reproducer / regression test for artifact-keeper#1366.
#
# Background
#   Release-gate Full Suite for v1.2.0-rc.2 reported 22 failures all rooted at
#   HTTP 404 on /api/v1/repositories/{key}/members and the sibling /cache-ttl
#   route. The hypothesis was that #1281 (reject virtual-repo create with no
#   members at 400) had unmounted the /members sub-router as a side effect.
#
#   Investigation on the same source commit could not reproduce the 404 -- the
#   handlers were still wired and the OpenAPI doc still listed the four
#   expected paths. The merged PR #1387 therefore lands regression-only tests
#   that pin the sub-router shape: GET / POST / PUT / DELETE on
#   /api/v1/repositories/{key}/members must all be reachable (2xx, never 404)
#   against a freshly-created virtual repo.
#
#   This script is the E2E side of those regression tests: it talks to a real
#   backend, creates a virtual repo with two members, then walks each HTTP
#   verb on the /members sub-router and asserts none of them returns 404
#   "route not found". Bodies are valid so a 4xx that does fire indicates a
#   real handler problem rather than a payload issue.
#
# What this script catches
#   - Sub-router fully unmounted (every verb -> 404) -- the #1366 hypothesis.
#   - Sub-router partially unmounted (one verb -> 404 while others work).
#   - Path-spec regression where the {key} parameter no longer resolves and
#     all verbs collapse onto a different route that returns 405 / 404.
#
# What this script does NOT catch
#   - Payload-shape regressions (covered by test-virtual-repo-malformed-input
#     for the 400 + VALIDATION_ERROR envelope).
#   - Member-priority semantics (covered by test-virtual-repo-member-bulk-update).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-members-router-1366"
auth_admin

LOCAL_A="test-vmr-a-${RUN_ID}"
LOCAL_B="test-vmr-b-${RUN_ID}"
VIRTUAL_KEY="test-vmr-virt-${RUN_ID}"

# Echo "<METHOD> <PATH> [body]" -> HTTP status. Captures the body to a temp
# file so a failing assertion can surface a snippet via fail()'s CDATA arg.
verb_status() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local out
  out=$(mktemp)
  local args=(-s -o "$out" -w '%{http_code}' --max-time 60 --connect-timeout 10
              -X "$method"
              -H "$(auth_header)"
              -H "Content-Type: application/json")
  if [ -n "$body" ]; then
    args+=(--data-binary "$body")
  fi
  args+=("${BASE_URL}${path}")
  local code
  code=$(curl "${args[@]}") || code="000"
  # Caller can read the body via $RESP_BODY_FILE; expose deterministically.
  RESP_BODY_FILE="$out"
  echo "$code"
}

# Assert that STATUS is anything but 404. Captures the response body so the
# failure message names the actual code. Used to pin "the route exists" --
# the load-bearing assertion against #1366.
assert_not_404() {
  local status="$1"
  local label="$2"
  if [ "$status" = "404" ]; then
    local snippet="<empty>"
    if [ -n "${RESP_BODY_FILE:-}" ] && [ -f "$RESP_BODY_FILE" ]; then
      snippet=$(head -c 300 "$RESP_BODY_FILE" 2>/dev/null || echo "")
    fi
    fail "${label}: route returned 404 (sub-router unmounted -- #1366 reproducing)" \
"endpoint: ${label}
response body (first 300 bytes): ${snippet}"
    return 1
  fi
  return 0
}

# -------------------------------------------------------------------------
# Setup
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

# Settle: wait for both members to appear so the verb walk below runs against
# a fully-realised virtual repo (avoids racing the POST helper inside
# create_virtual_repo).
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "2" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

MEMBERS_PATH="/api/v1/repositories/${VIRTUAL_KEY}/members"

# -------------------------------------------------------------------------
# GET /members -- must be 2xx, never 404. This is the read path that the
# release-gate Full Suite for v1.2.0-rc.2 saw collapse to 404.
# -------------------------------------------------------------------------

begin_test "GET /members returns 2xx (route mounted)"
status=$(verb_status GET "$MEMBERS_PATH")
if assert_not_404 "$status" "GET ${MEMBERS_PATH}"; then
  assert_http_2xx "$status" "expected 2xx on GET /members, got ${status}" && pass
fi
rm -f "${RESP_BODY_FILE:-}"

# -------------------------------------------------------------------------
# POST /members -- add a third member (we reuse A; the handler is idempotent
# enough that a duplicate add either succeeds, returns 409 Conflict, or 400
# Validation; any of those means the route exists. The load-bearing
# assertion is "not 404".)
# -------------------------------------------------------------------------

begin_test "POST /members returns non-404 (route mounted)"
POST_PAYLOAD=$(jq -n --arg k "$LOCAL_A" '{member_key: $k, priority: 99}')
status=$(verb_status POST "$MEMBERS_PATH" "$POST_PAYLOAD")
if assert_not_404 "$status" "POST ${MEMBERS_PATH}"; then
  # Accept 2xx (added) or 4xx other than 404 (duplicate / validation). The
  # bug we care about is route-level 404; a payload-level 4xx is fine.
  if [[ "$status" =~ ^[24][0-9][0-9]$ ]]; then
    pass
  else
    fail "POST /members returned unexpected ${status} (route exists but handler errored)"
  fi
fi
rm -f "${RESP_BODY_FILE:-}"

# -------------------------------------------------------------------------
# PUT /members -- bulk priority swap. Valid payload so a non-2xx response
# would be a handler regression rather than a payload issue.
# -------------------------------------------------------------------------

begin_test "PUT /members returns non-404 (route mounted)"
PUT_PAYLOAD=$(jq -n \
  --arg a "$LOCAL_A" \
  --arg b "$LOCAL_B" \
  '{members: [
     {member_key: $a, priority: 1},
     {member_key: $b, priority: 2}
   ]}')
status=$(verb_status PUT "$MEMBERS_PATH" "$PUT_PAYLOAD")
if assert_not_404 "$status" "PUT ${MEMBERS_PATH}"; then
  assert_http_2xx "$status" "expected 2xx on PUT /members with valid payload, got ${status}" && pass
fi
rm -f "${RESP_BODY_FILE:-}"

# -------------------------------------------------------------------------
# DELETE /members/{member_key} -- remove member B. The leaf-path variant is
# the documented removal verb; pin both that path and the parent /members
# path are reachable. Per #1387 the bug claim was specifically about the
# sub-router so both flavours are tested.
# -------------------------------------------------------------------------

begin_test "DELETE /members/{member_key} returns non-404 (route mounted)"
status=$(verb_status DELETE "${MEMBERS_PATH}/${LOCAL_B}")
if assert_not_404 "$status" "DELETE ${MEMBERS_PATH}/${LOCAL_B}"; then
  assert_http_2xx "$status" "expected 2xx on DELETE /members/${LOCAL_B}, got ${status}" && pass
fi
rm -f "${RESP_BODY_FILE:-}"

# Verify the remaining member is exactly A (single survivor) -- this also
# re-exercises GET /members after a mutation, which would catch a sub-router
# that 404s only after the first write call.
begin_test "GET /members after DELETE still returns 2xx and reflects removal"
status=$(verb_status GET "$MEMBERS_PATH")
if assert_not_404 "$status" "GET ${MEMBERS_PATH} (post-DELETE)"; then
  if assert_http_2xx "$status" "expected 2xx on GET /members after DELETE, got ${status}"; then
    count=$(jq '.members | length // 0' < "$RESP_BODY_FILE" 2>/dev/null || echo 0)
    remaining=$(jq -r '.members[0].member_repo_key // empty' < "$RESP_BODY_FILE" 2>/dev/null || echo "")
    if [ "$count" = "1" ] && [ "$remaining" = "$LOCAL_A" ]; then
      pass
    else
      fail "GET /members after DELETE: expected 1 member (${LOCAL_A}); got count=${count} first='${remaining}'"
    fi
  fi
fi
rm -f "${RESP_BODY_FILE:-}"

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_B}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_A}" > /dev/null 2>&1 || true

end_suite
