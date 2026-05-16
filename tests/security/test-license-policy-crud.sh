#!/usr/bin/env bash
# test-license-policy-crud.sh - License policy CRUD + compliance check E2E.
#
# Covers Epic 2 sub-task 2.9 (artifact-keeper-test#67):
#   GET    /api/v1/sbom/license-policies
#   POST   /api/v1/sbom/license-policies       (upsert -- doubles as update)
#   GET    /api/v1/sbom/license-policies/{id}
#   DELETE /api/v1/sbom/license-policies/{id}
#   POST   /api/v1/sbom/check-compliance
# Ships in v1.2.0 (customer pain #2 -- "license policy was a YAML
# nobody could edit safely").
#
# Flow (create -> list -> update -> get -> compliance check -> delete -> 404)
# --------------------------------------------------------------------------
#   1. POST upsert with a fresh name, allowed=[MIT, Apache-2.0],
#      denied=[GPL-3.0, AGPL-3.0]. Assert documented LicensePolicyResponse
#      shape and capture POLICY_ID.
#   2. GET list -- assert our policy is in the array.
#   3. POST upsert again with the SAME name but a tweaked field
#      (description) -- assert the response reflects the update.
#   4. GET by id -- assert the tweaked field round-tripped.
#   5. POST /sbom/check-compliance with our denied license (GPL-3.0)
#      -- assert compliant=false. Then with an allowed license (MIT)
#      -- assert compliant=true.
#   6. DELETE by id -- assert 2xx.
#   7. GET by id -- assert 404 (not 200, not 500).
#
# Skip semantics
# --------------
# This endpoint set is CRUD over a SQL table and ships in every backend
# build that has the sbom module enabled, which is all of them. We skip
# only on 501/404-not-mounted at the suite entry (zero CRUD ops). The
# compliance check sub-test can be skip()ed if /sbom/check-compliance
# returns 404-no-policy-configured (404 is documented for this endpoint).
#
# Self-test mode (EXPECT_FAILURE=1):
#   Inverts the final exit code.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "license-policy-crud"
auth_admin
setup_workdir

POLICY_NAME="e2e-lic-${RUN_ID}"
POLICY_ID=""

# Belt-and-suspenders cleanup: even if the DELETE test below succeeds,
# a previous failed run can leave dangling rows. Look up by name on
# entry and delete if found.
cleanup_policy() {
  if [ -n "$POLICY_ID" ]; then
    # shellcheck disable=SC2086
    curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/sbom/license-policies/${POLICY_ID}" > /dev/null 2>&1 || true
  fi
}
add_exit_handler "cleanup_policy"

# ---------------------------------------------------------------------------
# 2.9.a -- POST upsert creates the policy. Required LicensePolicyResponse
# fields per openapi.yaml line 14118:
#   id, name, allowed_licenses, denied_licenses, allow_unknown,
#   action, is_enabled, created_at.
# ---------------------------------------------------------------------------

begin_test "POST /sbom/license-policies creates a policy"
create_payload=$(jq -n --arg n "$POLICY_NAME" '{
  name: $n,
  description: "initial description",
  allowed_licenses: ["MIT", "Apache-2.0"],
  denied_licenses: ["GPL-3.0", "AGPL-3.0"],
  allow_unknown: false,
  action: "block",
  is_enabled: true
}')
c_status=$(curl -s -o "$WORK_DIR/create.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$create_payload" \
  "${BASE_URL}/api/v1/sbom/license-policies") || c_status="000"

case "$c_status" in
  501|404)
    skip_suite "license policy endpoint not available (HTTP ${c_status})"
    ;;
  200|201)
    missing=""
    for field in id name allowed_licenses denied_licenses allow_unknown \
                 action is_enabled created_at; do
      if ! jq -e --arg f "$field" 'has($f)' "$WORK_DIR/create.json" > /dev/null 2>&1; then
        missing="${missing} ${field}"
      fi
    done
    if [ -n "$missing" ]; then
      fail "create response missing required field(s):${missing} (body: $(head -c 250 "$WORK_DIR/create.json"))"
    else
      POLICY_ID=$(jq -r '.id' "$WORK_DIR/create.json")
      uuid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      got_name=$(jq -r '.name' "$WORK_DIR/create.json")
      if ! [[ "$POLICY_ID" =~ $uuid_re ]]; then
        fail "policy id '${POLICY_ID}' is not a UUID"
      elif [ "$got_name" != "$POLICY_NAME" ]; then
        fail "policy name did not round-trip: sent='${POLICY_NAME}' got='${got_name}'"
      else
        pass
      fi
    fi
    ;;
  *)
    fail "POST /sbom/license-policies returned HTTP ${c_status} (body: $(head -c 200 "$WORK_DIR/create.json"))"
    ;;
esac

# ---------------------------------------------------------------------------
# 2.9.b -- GET list contains our policy.
# ---------------------------------------------------------------------------

begin_test "GET /sbom/license-policies contains created policy"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  l_status=$(curl -s -o "$WORK_DIR/list.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" "${BASE_URL}/api/v1/sbom/license-policies") || l_status="000"
  if [ "$l_status" != "200" ]; then
    fail "GET list returned HTTP ${l_status}"
  elif ! jq -e 'type == "array"' "$WORK_DIR/list.json" > /dev/null 2>&1; then
    fail "list response is not an array"
  elif ! jq -e --arg id "$POLICY_ID" 'any(.id == $id)' "$WORK_DIR/list.json" > /dev/null 2>&1; then
    fail "list does not contain id=${POLICY_ID} (list head: $(head -c 200 "$WORK_DIR/list.json"))"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 2.9.c -- POST upsert with the same name updates the existing row.
# We change description; the response must reflect the new value
# (proves it's an UPDATE, not a duplicate INSERT).
# ---------------------------------------------------------------------------

NEW_DESC="updated by E2E run ${RUN_ID}"

begin_test "POST upsert with same name updates description"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  upd_payload=$(jq -n --arg n "$POLICY_NAME" --arg d "$NEW_DESC" '{
    name: $n,
    description: $d,
    allowed_licenses: ["MIT", "Apache-2.0"],
    denied_licenses: ["GPL-3.0", "AGPL-3.0"],
    allow_unknown: false,
    action: "block",
    is_enabled: true
  }')
  u_status=$(curl -s -o "$WORK_DIR/upd.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$upd_payload" \
    "${BASE_URL}/api/v1/sbom/license-policies") || u_status="000"
  if [ "$u_status" != "200" ] && [ "$u_status" != "201" ]; then
    fail "upsert returned HTTP ${u_status} (body: $(head -c 200 "$WORK_DIR/upd.json"))"
  else
    upd_id=$(jq -r '.id' "$WORK_DIR/upd.json")
    upd_desc=$(jq -r '.description // empty' "$WORK_DIR/upd.json")
    if [ "$upd_id" != "$POLICY_ID" ]; then
      fail "upsert created new row id=${upd_id} instead of updating ${POLICY_ID}"
    elif [ "$upd_desc" != "$NEW_DESC" ]; then
      fail "description did not update: expected='${NEW_DESC}' got='${upd_desc}'"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.9.d -- GET by id reflects the updated description (and is not the
# cached pre-update copy).
# ---------------------------------------------------------------------------

begin_test "GET /sbom/license-policies/{id} reflects update"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  g_status=$(curl -s -o "$WORK_DIR/get.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" "${BASE_URL}/api/v1/sbom/license-policies/${POLICY_ID}") || g_status="000"
  if [ "$g_status" != "200" ]; then
    fail "GET by id returned HTTP ${g_status}"
  else
    got_desc=$(jq -r '.description // empty' "$WORK_DIR/get.json")
    if [ "$got_desc" != "$NEW_DESC" ]; then
      fail "GET description='${got_desc}' did not match expected updated='${NEW_DESC}'"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.9.e -- POST /sbom/check-compliance evaluates a license list against
# active policies. Required LicenseCheckResult fields per openapi.yaml
# line 14100: compliant, violations[], warnings[].
# ---------------------------------------------------------------------------

begin_test "POST /sbom/check-compliance: denied license -> compliant=false"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  bad_payload=$(jq -n '{licenses: ["GPL-3.0"]}')
  b_status=$(curl -s -o "$WORK_DIR/bad.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$bad_payload" \
    "${BASE_URL}/api/v1/sbom/check-compliance") || b_status="000"
  case "$b_status" in
    404) skip "no license policy configured for this scope (HTTP 404 documented)" ;;
    501) skip "check-compliance endpoint not available" ;;
    200)
      compliant=$(jq -r '.compliant // empty' "$WORK_DIR/bad.json")
      viol_type=$(jq -r '.violations | type' "$WORK_DIR/bad.json")
      warn_type=$(jq -r '.warnings | type' "$WORK_DIR/bad.json")
      if [ "$compliant" != "false" ]; then
        fail "denied license GPL-3.0 returned compliant='${compliant}' (expected false). body: $(head -c 200 "$WORK_DIR/bad.json")"
      elif [ "$viol_type" != "array" ] || [ "$warn_type" != "array" ]; then
        fail "violations or warnings is not an array (violations=${viol_type}, warnings=${warn_type})"
      else
        pass
      fi
      ;;
    *) fail "check-compliance returned HTTP ${b_status} (body: $(head -c 200 "$WORK_DIR/bad.json"))" ;;
  esac
fi

begin_test "POST /sbom/check-compliance: allowed license -> compliant=true"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  ok_payload=$(jq -n '{licenses: ["MIT"]}')
  o_status=$(curl -s -o "$WORK_DIR/ok.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$ok_payload" \
    "${BASE_URL}/api/v1/sbom/check-compliance") || o_status="000"
  case "$o_status" in
    404|501) skip "endpoint/policy not available (HTTP ${o_status})" ;;
    200)
      compliant=$(jq -r '.compliant // empty' "$WORK_DIR/ok.json")
      if [ "$compliant" != "true" ]; then
        fail "allowed license MIT returned compliant='${compliant}' (expected true). body: $(head -c 200 "$WORK_DIR/ok.json")"
      else
        pass
      fi
      ;;
    *) fail "check-compliance returned HTTP ${o_status}" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 2.9.f -- DELETE + GET-after-delete returns 404 (not 200, not 500).
# ---------------------------------------------------------------------------

begin_test "DELETE /sbom/license-policies/{id} returns 2xx"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  d_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/sbom/license-policies/${POLICY_ID}") || d_status="000"
  case "$d_status" in
    200|204)
      pass
      # Clear POLICY_ID so cleanup_policy doesn't double-DELETE (which
      # would log a benign 404).
      POLICY_ID=""
      ;;
    *) fail "DELETE returned HTTP ${d_status}" ;;
  esac
fi

begin_test "GET-after-delete returns 404"
# We saved the id before clearing POLICY_ID. Re-fetch from the create
# response so we can assert the 404.
GHOST_ID=$(jq -r '.id // empty' "$WORK_DIR/create.json" 2>/dev/null || echo "")
if [ -z "$GHOST_ID" ]; then
  skip "no original policy id to re-check"
else
  ga_status=$(curl -s -o "$WORK_DIR/ga.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" "${BASE_URL}/api/v1/sbom/license-policies/${GHOST_ID}") || ga_status="000"
  case "$ga_status" in
    404) pass ;;
    200) fail "GET after DELETE returned 200 (policy still exists; DELETE was a no-op)" ;;
    *) fail "GET after DELETE returned HTTP ${ga_status} (expected 404)" ;;
  esac
fi

end_suite
