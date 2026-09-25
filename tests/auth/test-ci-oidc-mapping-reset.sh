#!/usr/bin/env bash
# test-ci-oidc-mapping-reset.sh - CI OIDC identity mapping can be reset to
# all repositories (#4198)
#
# Verifies:
#   1. A mapping created with an allowed_repo_ids restriction reports it
#   2. PUT with an explicit "allowed_repo_ids": null clears the restriction
#      (the PUT response itself shows allowed_repo_ids: null)
#   3. A subsequent GET confirms the mapping is unrestricted
#   4. PUT with the field omitted leaves a restriction unchanged (control)
#
# On the unfixed backend serde collapsed an explicit null into "field
# absent", so step 2's PUT kept the stored restriction and both step 2 and
# step 3 fail. Against the fix (tri-state Option<Option<Vec<Uuid>>>), null
# means "clear" and the assertions pass.
#
# Backend reference:
#   - POST /api/v1/admin/ci-oidc                  (create provider)
#   - POST /api/v1/admin/ci-oidc/{id}/mappings    (create mapping)
#   - PUT  /api/v1/admin/ci-oidc/{id}/mappings/{mid}
#   - GET  /api/v1/admin/ci-oidc/{id}/mappings/{mid}
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-ci-oidc-mapping-reset"
auth_admin

PROVIDER_ID=""
MAPPING_ID=""
# A random UUID standing in for a repository the mapping is restricted to;
# the mapping store does not FK allowed_repo_ids to repositories.
REPO_UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"

# -------------------------------------------------------------------------
# Feature probe: CI OIDC admin endpoints exist on this backend
# -------------------------------------------------------------------------

begin_test "CI OIDC admin API is available"
if api_get "/api/v1/admin/ci-oidc" > /dev/null 2>&1; then
  pass "CI OIDC admin API reachable"
else
  skip "CI OIDC admin API not available on this backend"
  end_suite
  exit 0
fi

# -------------------------------------------------------------------------
# Create a provider and a restricted identity mapping
# -------------------------------------------------------------------------

begin_test "Create CI OIDC provider"
resp=$(api_post "/api/v1/admin/ci-oidc" \
  "{\"name\":\"e2e-reset-${RUN_ID}\",\"provider_type\":\"gitlab\",\"issuer_url\":\"https://gitlab.example.com\",\"audience\":\"artifact-keeper\"}" \
  2>/dev/null) || resp=""
PROVIDER_ID=$(echo "$resp" | jq -r '.id // empty')
if [ -n "$PROVIDER_ID" ] && [ "$PROVIDER_ID" != "null" ]; then
  pass "Provider created (${PROVIDER_ID})"
else
  fail "Could not create CI OIDC provider" "$resp"
fi

begin_test "Create identity mapping restricted to one repository"
if [ -z "${PROVIDER_ID:-}" ]; then
  fail "No provider id from previous step"
else
  resp=$(api_post "/api/v1/admin/ci-oidc/${PROVIDER_ID}/mappings" \
    "{\"name\":\"e2e-reset-${RUN_ID}\",\"claim_filters\":{\"project_path\":\"group/app\"},\"allowed_repo_ids\":[\"${REPO_UUID}\"]}" \
    2>/dev/null) || resp=""
  MAPPING_ID=$(echo "$resp" | jq -r '.id // empty')
  scope=$(echo "$resp" | jq -c '.allowed_repo_ids // empty')
  if [ -n "$MAPPING_ID" ] && [ "$MAPPING_ID" != "null" ] && [ "$scope" = "[\"${REPO_UUID}\"]" ]; then
    pass "Restricted mapping created (${MAPPING_ID}, scope=${scope})"
  else
    fail "Restricted mapping not created as expected" "$resp"
  fi
fi

# -------------------------------------------------------------------------
# The bug: PUT with explicit null must clear the restriction (#4198)
# -------------------------------------------------------------------------

begin_test "PUT with explicit null clears the repository restriction"
if [ -z "${MAPPING_ID:-}" ]; then
  fail "No mapping id from previous step"
else
  resp=$(api_put "/api/v1/admin/ci-oidc/${PROVIDER_ID}/mappings/${MAPPING_ID}" \
    '{"allowed_repo_ids":null}' 2>/dev/null) || resp=""
  # `null` must come back as JSON null, i.e. jq type "null". On the unfixed
  # backend the stored restriction survives and this is "array".
  scope_type=$(echo "$resp" | jq -r '.allowed_repo_ids | type')
  if [ "$scope_type" = "null" ]; then
    pass "PUT response shows the mapping is unrestricted"
  else
    fail "Explicit null did not clear the restriction (allowed_repo_ids is ${scope_type})" "$resp"
  fi
fi

begin_test "Subsequent GET confirms the mapping is unrestricted"
if [ -z "${MAPPING_ID:-}" ]; then
  fail "No mapping id from previous step"
else
  resp=$(api_get "/api/v1/admin/ci-oidc/${PROVIDER_ID}/mappings/${MAPPING_ID}" 2>/dev/null) || resp=""
  scope_type=$(echo "$resp" | jq -r '.allowed_repo_ids | type')
  if [ "$scope_type" = "null" ]; then
    pass "GET shows allowed_repo_ids: null (all repositories)"
  else
    fail "GET still shows a restriction after the null reset (allowed_repo_ids is ${scope_type})" "$resp"
  fi
fi

# -------------------------------------------------------------------------
# Control: omitting the field leaves a restriction unchanged
# -------------------------------------------------------------------------

begin_test "PUT omitting allowed_repo_ids leaves a restriction unchanged"
if [ -z "${MAPPING_ID:-}" ]; then
  fail "No mapping id from previous step"
else
  api_put "/api/v1/admin/ci-oidc/${PROVIDER_ID}/mappings/${MAPPING_ID}" \
    "{\"allowed_repo_ids\":[\"${REPO_UUID}\"]}" > /dev/null 2>&1 || true
  resp=$(api_put "/api/v1/admin/ci-oidc/${PROVIDER_ID}/mappings/${MAPPING_ID}" \
    '{"name":"e2e-reset-renamed"}' 2>/dev/null) || resp=""
  scope=$(echo "$resp" | jq -c '.allowed_repo_ids // empty')
  if [ "$scope" = "[\"${REPO_UUID}\"]" ]; then
    pass "Omitted field preserves the restriction"
  else
    fail "Omitting allowed_repo_ids changed the restriction" "$resp"
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

if [ -n "${PROVIDER_ID:-}" ] && [ "$PROVIDER_ID" != "null" ]; then
  # Deleting the provider cascades to its mappings and deactivates the
  # mapping's service account.
  api_delete "/api/v1/admin/ci-oidc/${PROVIDER_ID}" > /dev/null 2>&1 || true
fi

# EXPECT_FAILURE=1 inverts the suite's exit code so this script can be used
# as a fixture to validate the gate (a "broken" gate is a passing self-test).
enable_expect_failure_trap

end_suite
