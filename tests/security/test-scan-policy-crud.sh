#!/usr/bin/env bash
# test-scan-policy-crud.sh - Scan (security) policy CRUD E2E test.
#
# Covers Epic 2 sub-task 2.10 part 1 (artifact-keeper-test#67):
#   GET    /api/v1/security/policies
#   POST   /api/v1/security/policies
#   GET    /api/v1/security/policies/{id}
#   PUT    /api/v1/security/policies/{id}
#   DELETE /api/v1/security/policies/{id}
# Ships in v1.2.0 (customer pain #2 -- "security policy CRUD existed in
# code but was never E2E-asserted; we found two regressions where PUT
# silently lost min_staging_hours / max_artifact_age_days").
#
# The companion "policy actually blocks upload on violation" sub-task is
# tracked separately under test-quality-gate-enforcement.sh + future work;
# this script is the CRUD half so a release gate that breaks DELETE or
# PUT fails loudly here rather than waiting for a customer to file
# a bug.
#
# Flow (create -> list -> get -> update -> get -> delete -> 404)
# --------------------------------------------------------------
#   1. POST with CreatePolicyRequest. Capture POLICY_ID.
#      Required PolicyResponse fields per openapi.yaml line 15542:
#        id, name, max_severity, block_unscanned, block_on_fail,
#        is_enabled, require_signature, created_at, updated_at.
#   2. GET list -- assert array contains our id.
#   3. GET by id -- assert returns our policy.
#   4. PUT with UpdatePolicyRequest changing max_severity from "high"
#      to "critical" + is_enabled from true to false. Assert the
#      response reflects BOTH changes. (Regression guard: an earlier
#      PUT impl only updated the first field.)
#   5. GET by id -- assert update persisted.
#   6. DELETE -- assert 2xx.
#   7. GET by id -- assert 404.
#
# Skip semantics
# --------------
# Hard-fail on 5xx or shape mismatches. skip_suite if the endpoint set
# itself is not mounted (501/404 on the LIST). No scanner dependency.
#
# Self-test mode (EXPECT_FAILURE=1):
#   Inverts the final exit code.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-policy-crud"
auth_admin
setup_workdir

POLICY_NAME="e2e-scan-policy-${RUN_ID}"
POLICY_ID=""

cleanup_policy() {
  if [ -n "$POLICY_ID" ]; then
    # shellcheck disable=SC2086
    curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/security/policies/${POLICY_ID}" > /dev/null 2>&1 || true
  fi
}
add_exit_handler "cleanup_policy"

# ---------------------------------------------------------------------------
# Pre-flight: confirm the endpoint set is mounted. We pick LIST (cheap,
# read-only, no body) and gracefully skip_suite if it's 501/404.
# ---------------------------------------------------------------------------

begin_test "Pre-flight: GET /security/policies is mounted"
pf_status=$(curl -s -o "$WORK_DIR/pf.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" "${BASE_URL}/api/v1/security/policies") || pf_status="000"
case "$pf_status" in
  200) pass ;;
  501|404) skip_suite "security policies endpoint not available (HTTP ${pf_status})" ;;
  *) fail "pre-flight LIST returned HTTP ${pf_status} (body: $(head -c 200 "$WORK_DIR/pf.json"))" ;;
esac

# ---------------------------------------------------------------------------
# 2.10.a -- POST creates a policy.
# ---------------------------------------------------------------------------

begin_test "POST /security/policies creates a policy"
create_payload=$(jq -n --arg n "$POLICY_NAME" '{
  name: $n,
  max_severity: "high",
  block_unscanned: true,
  block_on_fail: true,
  max_artifact_age_days: 30,
  min_staging_hours: 24,
  require_signature: false
}')
c_status=$(curl -s -o "$WORK_DIR/create.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$create_payload" \
  "${BASE_URL}/api/v1/security/policies") || c_status="000"
case "$c_status" in
  200|201)
    POLICY_ID=$(jq -r '.id // empty' "$WORK_DIR/create.json")
    uuid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    missing=""
    for field in id name max_severity block_unscanned block_on_fail \
                 is_enabled require_signature created_at updated_at; do
      if ! jq -e --arg f "$field" 'has($f)' "$WORK_DIR/create.json" > /dev/null 2>&1; then
        missing="${missing} ${field}"
      fi
    done
    if [ -n "$missing" ]; then
      fail "create response missing required field(s):${missing} (body: $(head -c 250 "$WORK_DIR/create.json"))"
    elif ! [[ "$POLICY_ID" =~ $uuid_re ]]; then
      fail "policy id '${POLICY_ID}' is not a UUID"
    else
      pass
    fi
    ;;
  *)
    fail "POST returned HTTP ${c_status} (body: $(head -c 250 "$WORK_DIR/create.json"))"
    ;;
esac

# ---------------------------------------------------------------------------
# 2.10.b -- GET list contains our policy.
# ---------------------------------------------------------------------------

begin_test "GET /security/policies contains created policy"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  l_status=$(curl -s -o "$WORK_DIR/list.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" "${BASE_URL}/api/v1/security/policies") || l_status="000"
  if [ "$l_status" != "200" ]; then
    fail "list returned HTTP ${l_status}"
  elif ! jq -e --arg id "$POLICY_ID" 'any(.id == $id)' "$WORK_DIR/list.json" > /dev/null 2>&1; then
    fail "list does not contain id=${POLICY_ID}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 2.10.c -- GET by id returns the policy we created.
# ---------------------------------------------------------------------------

begin_test "GET /security/policies/{id} returns created policy"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  g_status=$(curl -s -o "$WORK_DIR/get.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" "${BASE_URL}/api/v1/security/policies/${POLICY_ID}") || g_status="000"
  if [ "$g_status" != "200" ]; then
    fail "GET returned HTTP ${g_status}"
  else
    got_id=$(jq -r '.id // empty' "$WORK_DIR/get.json")
    got_sev=$(jq -r '.max_severity // empty' "$WORK_DIR/get.json")
    got_stag=$(jq -r '.min_staging_hours // empty' "$WORK_DIR/get.json")
    got_age=$(jq -r '.max_artifact_age_days // empty' "$WORK_DIR/get.json")
    if [ "$got_id" != "$POLICY_ID" ]; then
      fail "id mismatch: expected '${POLICY_ID}' got '${got_id}'"
    elif [ "$got_sev" != "high" ]; then
      fail "max_severity did not round-trip on create: expected 'high' got '${got_sev}'"
    elif [ "$got_stag" != "24" ]; then
      fail "min_staging_hours did not round-trip: expected 24 got '${got_stag}'"
    elif [ "$got_age" != "30" ]; then
      fail "max_artifact_age_days did not round-trip: expected 30 got '${got_age}'"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.10.d -- PUT updates multiple fields in one request. Regression
# guard: we change BOTH max_severity AND is_enabled; older PUT impl
# only persisted the first field.
# ---------------------------------------------------------------------------

begin_test "PUT /security/policies/{id} updates max_severity AND is_enabled"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  # Regression guard for the file-header bug class: PUT silently dropped
  # min_staging_hours / max_artifact_age_days. If we re-send the same
  # values used at create, a buggy PUT that ignores those columns would
  # still pass the GET-after-PUT check (the row already has those
  # values). Send DIFFERENT values so a regression fails loudly here.
  upd_payload=$(jq -n --arg n "$POLICY_NAME" '{
    name: $n,
    max_severity: "critical",
    block_unscanned: true,
    block_on_fail: true,
    is_enabled: false,
    max_artifact_age_days: 60,
    min_staging_hours: 48,
    require_signature: false
  }')
  u_status=$(curl -s -o "$WORK_DIR/upd.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$upd_payload" \
    "${BASE_URL}/api/v1/security/policies/${POLICY_ID}") || u_status="000"
  if [ "$u_status" != "200" ]; then
    fail "PUT returned HTTP ${u_status} (body: $(head -c 200 "$WORK_DIR/upd.json"))"
  else
    upd_sev=$(jq -r '.max_severity // empty' "$WORK_DIR/upd.json")
    upd_en=$(jq -r '.is_enabled // empty' "$WORK_DIR/upd.json")
    upd_stag=$(jq -r '.min_staging_hours // empty' "$WORK_DIR/upd.json")
    upd_age=$(jq -r '.max_artifact_age_days // empty' "$WORK_DIR/upd.json")
    if [ "$upd_sev" != "critical" ]; then
      fail "max_severity did not update: expected 'critical' got '${upd_sev}'"
    elif [ "$upd_en" != "false" ]; then
      fail "is_enabled did not update: expected false got '${upd_en}' (regression: PUT dropped 2nd-and-later fields)"
    elif [ "$upd_stag" != "48" ]; then
      fail "min_staging_hours did not update: expected 48 got '${upd_stag}' (regression: PUT silently dropped this column)"
    elif [ "$upd_age" != "60" ]; then
      fail "max_artifact_age_days did not update: expected 60 got '${upd_age}' (regression: PUT silently dropped this column)"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.10.e -- GET-after-PUT confirms the update was actually persisted
# (not just returned in the PUT response from a cached object).
# ---------------------------------------------------------------------------

begin_test "GET-after-PUT confirms persistence"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  g2_status=$(curl -s -o "$WORK_DIR/g2.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" "${BASE_URL}/api/v1/security/policies/${POLICY_ID}") || g2_status="000"
  if [ "$g2_status" != "200" ]; then
    fail "GET-after-PUT returned HTTP ${g2_status}"
  else
    sev=$(jq -r '.max_severity // empty' "$WORK_DIR/g2.json")
    en=$(jq -r '.is_enabled // empty' "$WORK_DIR/g2.json")
    stag=$(jq -r '.min_staging_hours // empty' "$WORK_DIR/g2.json")
    age=$(jq -r '.max_artifact_age_days // empty' "$WORK_DIR/g2.json")
    # Assert the NEW values from PUT, not the create-row values: the
    # whole point of the changed-values regression guard above is that
    # a buggy PUT that silently drops min_staging_hours /
    # max_artifact_age_days must fail loudly here.
    if [ "$sev" != "critical" ] || [ "$en" != "false" ]; then
      fail "post-PUT GET shows stale data: max_severity='${sev}' is_enabled='${en}' (expected 'critical', false)"
    elif [ "$stag" != "48" ]; then
      fail "post-PUT GET min_staging_hours='${stag}' (expected 48 -- PUT silently dropped this column)"
    elif [ "$age" != "60" ]; then
      fail "post-PUT GET max_artifact_age_days='${age}' (expected 60 -- PUT silently dropped this column)"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.10.f -- DELETE returns 2xx; GET-after-DELETE returns 404.
# ---------------------------------------------------------------------------

begin_test "DELETE /security/policies/{id} returns 2xx"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  d_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/policies/${POLICY_ID}") || d_status="000"
  case "$d_status" in
    200|204)
      pass
      GHOST_ID="$POLICY_ID"
      POLICY_ID=""
      ;;
    *) fail "DELETE returned HTTP ${d_status}" ;;
  esac
fi

begin_test "GET-after-DELETE returns 404"
if [ -z "${GHOST_ID:-}" ]; then
  skip "no deleted policy id to re-check"
else
  ga_status=$(curl -s -o "$WORK_DIR/ga.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" "${BASE_URL}/api/v1/security/policies/${GHOST_ID}") || ga_status="000"
  case "$ga_status" in
    404) pass ;;
    200) fail "GET after DELETE returned 200 (DELETE was a no-op)" ;;
    *) fail "GET after DELETE returned HTTP ${ga_status} (expected 404)" ;;
  esac
fi

end_suite
