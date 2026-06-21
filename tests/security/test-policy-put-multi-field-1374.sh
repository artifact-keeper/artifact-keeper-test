#!/usr/bin/env bash
# test-policy-put-multi-field-1374.sh -- Security policy PUT persists every field
#
# Reproducer / regression test for artifact-keeper#1374.
#
# Background
#   PUT /api/v1/security/policies/{id} previously persisted only the first
#   changed field in a multi-field patch. A request with
#   {max_severity, is_enabled} updated max_severity but is_enabled came back
#   as empty / unchanged on a follow-up GET because the update handler
#   applied only the first non-None field from the patch DTO.
#
#   PR #1386 switches the update path to a read-modify-write pattern: load
#   the existing row, apply the patch struct fully, write the merged row
#   back. The response shape is now consistent: is_enabled is always
#   returned as a JSON boolean, never absent / empty-string.
#
# What this script catches
#   - The exact #1374 symptom: PUT with {max_severity, is_enabled} where the
#     GET-after-PUT shows the original is_enabled value (the second field
#     was silently dropped on the write).
#   - A regression that drops the boolean from the PUT response body (the
#     "empty string" form the release-gate observed in bash).
#   - A regression on the inverse direction: PUT with is_enabled only must
#     also persist (separate code path in the service layer).
#
# What this script does NOT cover
#   - The full matrix of single-field PUTs (covered in the backend's
#     security.rs unit tests).
#   - Validation envelope on malformed PUT bodies (covered by
#     test-json-validation-400 for the broader API contract).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "policy-put-multi-field-1374"
auth_admin

POLICY_NAME="test-1374-policy-${RUN_ID}"

# -------------------------------------------------------------------------
# Create a policy with known initial values. We do NOT bind it to a
# repository so the test is decoupled from repo lifecycle.
#
# Initial state:
#   max_severity   = "high"
#   block_unscanned = false
#   block_on_fail  = false
#   is_enabled     = true   (default per backend after create)
#
# We then PUT {max_severity: "critical", is_enabled: false} and assert the
# GET-after-PUT shows BOTH fields persisted (the bug was that only the
# first listed field stuck).
# -------------------------------------------------------------------------

begin_test "Create initial policy"
CREATE_PAYLOAD=$(jq -n --arg name "$POLICY_NAME" '{
  name: $name,
  max_severity: "high",
  block_unscanned: false,
  block_on_fail: false,
  min_staging_hours: null,
  max_artifact_age_days: null
}')
if create_resp=$(api_post "/api/v1/security/policies" "$CREATE_PAYLOAD" 2>/dev/null); then
  POLICY_ID=$(echo "$create_resp" | jq -r '.id // empty')
  if [ -n "$POLICY_ID" ] && [ "$POLICY_ID" != "null" ]; then
    pass
  else
    fail "policy created but response lacked id" "response: ${create_resp:0:300}"
  fi
else
  fail "could not create policy" "endpoint: POST /api/v1/security/policies"
fi

# Capture initial state. is_enabled defaults to true on create per the
# service layer; pin it so we know what value the PUT is flipping.
begin_test "Read initial policy state"
if [ -z "${POLICY_ID:-}" ]; then
  skip "no policy ID from previous step"
else
  if initial_resp=$(api_get "/api/v1/security/policies/${POLICY_ID}" 2>/dev/null); then
    initial_max_severity=$(echo "$initial_resp" | jq -r '.max_severity // empty')
    initial_is_enabled=$(echo "$initial_resp" | jq -r 'if .is_enabled == null then "" else (.is_enabled|tostring) end')
    # is_enabled must be a real JSON boolean -- not absent, not "" -- in the
    # GET response. Pin the contract here so a regression on the *response*
    # shape fails loudly rather than silently breaking the assertion below.
    if [ "$initial_max_severity" = "high" ] && \
       { [ "$initial_is_enabled" = "true" ] || [ "$initial_is_enabled" = "false" ]; }; then
      pass
    else
      fail "initial GET shape unexpected" \
"max_severity='${initial_max_severity}' is_enabled='${initial_is_enabled}' (expected high + true/false)
response: ${initial_resp:0:300}"
    fi
  else
    fail "could not GET initial policy state"
  fi
fi

# -------------------------------------------------------------------------
# PUT a two-field patch. This is the exact #1374 trigger shape: a patch
# with max_severity AND is_enabled where the bug would persist only the
# first of the two.
#
# We flip is_enabled to the OPPOSITE of its initial value so a "silent drop"
# regression is observable from the bash side (initial false stays false,
# initial true stays true).
# -------------------------------------------------------------------------

begin_test "PUT {max_severity, is_enabled} returns 2xx"
if [ -z "${POLICY_ID:-}" ]; then
  skip "no policy ID"
else
  # Flip is_enabled. If initial was true -> patch to false, and vice versa.
  if [ "$initial_is_enabled" = "true" ]; then
    target_is_enabled="false"
  else
    target_is_enabled="true"
  fi

  PUT_PAYLOAD=$(jq -n --arg sev "critical" --argjson en "$target_is_enabled" '{
    max_severity: $sev,
    is_enabled: $en
  }')
  put_status=$(curl -s -o "/tmp/put-resp-${RUN_ID}.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$PUT_PAYLOAD" \
    "${BASE_URL}/api/v1/security/policies/${POLICY_ID}") || put_status="000"

  if [[ "$put_status" =~ ^2[0-9][0-9]$ ]]; then
    pass
  else
    body=$(head -c 300 "/tmp/put-resp-${RUN_ID}.json" 2>/dev/null || echo "<empty>")
    fail "PUT returned HTTP ${put_status} (expected 2xx)" "body: ${body}"
  fi
fi

# -------------------------------------------------------------------------
# Load-bearing assertion: GET-after-PUT shows BOTH fields persisted.
#
# This is the regression boundary. Before #1386 the bug would leave one of:
#   - is_enabled at its initial value (the field was silently dropped)
#   - is_enabled as empty string / absent (the "bash sees empty" symptom)
# Both of those forms must fail the assertion below.
# -------------------------------------------------------------------------

begin_test "GET after PUT shows BOTH max_severity AND is_enabled persisted (#1374)"
if [ -z "${POLICY_ID:-}" ] || [ -z "${target_is_enabled:-}" ]; then
  skip "no policy ID or PUT step skipped"
else
  if after_resp=$(api_get "/api/v1/security/policies/${POLICY_ID}" 2>/dev/null); then
    after_max_severity=$(echo "$after_resp" | jq -r '.max_severity // empty')
    after_is_enabled=$(echo "$after_resp" | jq -r 'if .is_enabled == null then "" else (.is_enabled|tostring) end')

    # Two predicates must both hold:
    #   (a) max_severity is "critical" (the first patched field).
    #   (b) is_enabled equals target_is_enabled (the second patched field --
    #       the one the bug used to drop).
    max_severity_ok=0
    is_enabled_ok=0
    is_enabled_concrete=0

    [ "$after_max_severity" = "critical" ] && max_severity_ok=1
    [ "$after_is_enabled" = "$target_is_enabled" ] && is_enabled_ok=1
    # Per #1386 the response must always emit is_enabled as a JSON boolean;
    # an empty string or absent field is itself a contract regression. We
    # check that "true" or "false" appears (jq -r serialises real booleans
    # as those literals).
    if [ "$after_is_enabled" = "true" ] || [ "$after_is_enabled" = "false" ]; then
      is_enabled_concrete=1
    fi

    if [ "$max_severity_ok" = "1" ] && \
       [ "$is_enabled_ok" = "1" ] && \
       [ "$is_enabled_concrete" = "1" ]; then
      pass
    else
      fail "GET-after-PUT missing or stale field(s)" \
"max_severity (expected 'critical', got '${after_max_severity}') ok=${max_severity_ok}
is_enabled  (expected '${target_is_enabled}',   got '${after_is_enabled}')  ok=${is_enabled_ok} concrete=${is_enabled_concrete}
This is the #1374 symptom: the second field in a multi-field PUT was
silently dropped, or returned as empty/absent in the response envelope.
response: ${after_resp:0:300}"
    fi
  else
    fail "could not GET policy after PUT"
  fi
fi

# -------------------------------------------------------------------------
# Inverse direction: PUT only is_enabled (no max_severity in body). The
# fix path uses a read-modify-write so a single-field PUT must leave the
# other fields untouched while still persisting the bool. This catches a
# regression that breaks the COALESCE on the SQL side.
# -------------------------------------------------------------------------

begin_test "PUT {is_enabled} alone persists without disturbing max_severity"
if [ -z "${POLICY_ID:-}" ] || [ -z "${target_is_enabled:-}" ]; then
  skip "no policy ID or prior step skipped"
else
  # Flip back to the original value, this time alone.
  if [ "$target_is_enabled" = "true" ]; then
    second_target="false"
  else
    second_target="true"
  fi
  SECOND_PAYLOAD=$(jq -n --argjson en "$second_target" '{is_enabled: $en}')
  second_status=$(curl -s -o "/tmp/put-resp2-${RUN_ID}.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$SECOND_PAYLOAD" \
    "${BASE_URL}/api/v1/security/policies/${POLICY_ID}") || second_status="000"
  if [[ "$second_status" =~ ^2[0-9][0-9]$ ]]; then
    if final_resp=$(api_get "/api/v1/security/policies/${POLICY_ID}" 2>/dev/null); then
      final_max_severity=$(echo "$final_resp" | jq -r '.max_severity // empty')
      final_is_enabled=$(echo "$final_resp" | jq -r 'if .is_enabled == null then "" else (.is_enabled|tostring) end')
      if [ "$final_max_severity" = "critical" ] && \
         [ "$final_is_enabled" = "$second_target" ]; then
        pass
      else
        fail "single-field PUT either disturbed max_severity or failed to persist is_enabled" \
"expected max_severity='critical' is_enabled='${second_target}'
got      max_severity='${final_max_severity}' is_enabled='${final_is_enabled}'"
      fi
    else
      fail "could not GET policy after single-field PUT"
    fi
  else
    body=$(head -c 300 "/tmp/put-resp2-${RUN_ID}.json" 2>/dev/null || echo "<empty>")
    fail "single-field PUT returned HTTP ${second_status}" "body: ${body}"
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

if [ -n "${POLICY_ID:-}" ]; then
  api_delete "/api/v1/security/policies/${POLICY_ID}" > /dev/null 2>&1 || true
fi
rm -f "/tmp/put-resp-${RUN_ID}.json" "/tmp/put-resp2-${RUN_ID}.json" 2>/dev/null || true

end_suite
