#!/usr/bin/env bash
# test-quality-gate-enforcement.sh - Quality gate policy E2E test
#
# Creates a quality gate that blocks artifacts with critical issues, associates
# it with a repository, and verifies gate status and evaluation endpoints.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "quality-gate"
auth_admin
setup_workdir

REPO_KEY="test-qgate-${RUN_ID}"
GATE_NAME="no-critical-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create quality gate
# ---------------------------------------------------------------------------

begin_test "Create quality gate"
gate_payload="{\"name\":\"${GATE_NAME}\",\"description\":\"Block artifacts with critical issues\",\"max_critical_issues\":0}"
gate_resp=""
if gate_resp=$(api_post "/api/v1/quality-gates" "$gate_payload"); then
  GATE_ID=$(echo "$gate_resp" | jq -r '.id // .gate_id // empty')
  if [ -n "$GATE_ID" ]; then
    pass
  else
    fail "quality gate created but response did not contain an id"
  fi
else
  fail "POST /api/v1/quality-gates returned error"
fi

# ---------------------------------------------------------------------------
# Verify quality gate was created
# ---------------------------------------------------------------------------

begin_test "Verify quality gate exists"
if [ -z "${GATE_ID:-}" ]; then
  skip "no gate ID from previous step"
else
  if get_resp=$(api_get "/api/v1/quality-gates/${GATE_ID}"); then
    if assert_contains "$get_resp" "$GATE_NAME" "gate response should contain gate name"; then
      pass
    fi
  else
    fail "GET /api/v1/quality-gates/${GATE_ID} returned error"
  fi
fi

# ---------------------------------------------------------------------------
# Create a generic repository
# ---------------------------------------------------------------------------

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

# ---------------------------------------------------------------------------
# Upload a test artifact
# ---------------------------------------------------------------------------

begin_test "Upload test artifact"
echo "quality-gate-test-content-${RUN_ID}" > "${WORK_DIR}/test-artifact.bin"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/pkg/v1/test-artifact.bin" \
    "${WORK_DIR}/test-artifact.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "artifact upload failed"
fi

# ---------------------------------------------------------------------------
# Associate quality gate with repository
# ---------------------------------------------------------------------------

begin_test "Associate quality gate with repository"
if [ -z "${GATE_ID:-}" ]; then
  skip "no gate ID from previous step"
else
  assoc_payload="{\"gate_id\":\"${GATE_ID}\"}"
  if api_post "/api/v1/repositories/${REPO_KEY}/quality-gates" "$assoc_payload" > /dev/null; then
    pass
  else
    fail "POST /api/v1/repositories/${REPO_KEY}/quality-gates returned error"
  fi
fi

# ---------------------------------------------------------------------------
# Verify quality gate status on repository
# ---------------------------------------------------------------------------

begin_test "Verify quality gate status on repository"
if [ -z "${GATE_ID:-}" ]; then
  skip "no gate ID from previous step"
else
  if status_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/quality-gates"); then
    if assert_contains "$status_resp" "$GATE_ID" "repo quality gates should reference gate id"; then
      pass
    fi
  else
    fail "GET /api/v1/repositories/${REPO_KEY}/quality-gates returned error"
  fi
fi

# ---------------------------------------------------------------------------
# Evaluate quality gate
# ---------------------------------------------------------------------------

begin_test "Evaluate quality gate"
if [ -z "${GATE_ID:-}" ]; then
  skip "no gate ID from previous step"
else
  if eval_resp=$(api_get "/api/v1/quality-gates/${GATE_ID}/evaluate"); then
    # The evaluation should return some status indicating pass/fail
    if assert_contains "$eval_resp" "status" "evaluation response should contain status field" \
       || assert_contains "$eval_resp" "result" "evaluation response should contain result field" \
       || assert_contains "$eval_resp" "passed" "evaluation response should contain passed field"; then
      pass
    fi
  else
    # Evaluate might also be a POST
    if eval_resp=$(api_post "/api/v1/quality-gates/${GATE_ID}/evaluate" "" 2>/dev/null); then
      pass
    else
      fail "quality gate evaluation endpoint returned error"
    fi
  fi
fi

end_suite
