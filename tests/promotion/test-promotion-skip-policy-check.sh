#!/usr/bin/env bash
# test-promotion-skip-policy-check.sh -- skip_policy_check is an admin-only
# override (#4203).
#
# The promotion endpoints' skip_policy_check flag switches off the quality
# gate, the CVE/licence policy and the promotion rules in one boolean. Before
# the fix, ANY caller holding the grantable `promote:artifacts` scope could set
# it — a standing policy bypass for every scoped CI token. After the fix a
# non-admin caller passing the flag gets 403 naming the flag, and an admin's
# override is recorded in promotion_history as policy_check_skipped.
#
# Fails against the unfixed backend: the scoped-token promote with the flag
# returns 200 and copies the rule-blocked artifact (and the admin override
# leaves no audit marker).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "promotion-skip-policy-check"
auth_admin
setup_workdir

STAGING_KEY="spc-staging-${RUN_ID}"
RELEASE_KEY="spc-release-${RUN_ID}"
SA_NAME="spc-sa-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup: staging + release repos, one artifact, one rule it violates
# -------------------------------------------------------------------------

begin_test "Create staging and release repos"
if create_repo "$STAGING_KEY" "generic" "staging" && \
   create_repo "$RELEASE_KEY" "generic" "local"; then
  pass
else
  fail "could not create repos"
fi

begin_test "Upload artifact to staging"
echo "skip-policy-${RUN_ID}" > "${WORK_DIR}/app.bin"
if api_upload "/api/v1/repositories/${STAGING_KEY}/artifacts/com/app/app.bin" \
    "${WORK_DIR}/app.bin"; then
  pass
else
  fail "upload to staging failed"
fi

SOURCE_ID=""
TARGET_ID=""
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${STAGING_KEY}" 2>/dev/null); then
  SOURCE_ID=$(echo "$resp" | jq -r '.id // empty') || true
fi
if resp=$(api_get "/api/v1/repositories/${RELEASE_KEY}" 2>/dev/null); then
  TARGET_ID=$(echo "$resp" | jq -r '.id // empty') || true
fi
if resp=$(api_get "/api/v1/repositories/${STAGING_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // .[0].artifact_id // empty
    elif .items then .items[0].id // .items[0].artifact_id // empty
    else .id // .artifact_id // empty
    end' 2>/dev/null) || true
fi

begin_test "Create promotion rule the fresh artifact violates (min_staging_hours=720)"
RULE_PAYLOAD=$(jq -n \
  --arg name "spc-rule-${RUN_ID}" \
  --arg src "$SOURCE_ID" \
  --arg tgt "$TARGET_ID" \
  '{name: $name, source_repo_id: $src, target_repo_id: $tgt, is_enabled: true, min_staging_hours: 720}')
if api_post "/api/v1/promotion-rules" "$RULE_PAYLOAD" > /dev/null 2>&1; then
  pass
else
  fail "could not create promotion rule"
fi

# -------------------------------------------------------------------------
# A non-admin service-account token carrying promote:artifacts
# -------------------------------------------------------------------------

begin_test "Create service account with a promote:artifacts token"
SA_TOKEN=""
if resp=$(api_post "/api/v1/service-accounts" \
    "{\"name\":\"${SA_NAME}\",\"description\":\"#4203 E2E\"}" 2>/dev/null); then
  SA_ID=$(echo "$resp" | jq -r '.id // empty') || true
  if [ -n "${SA_ID:-}" ]; then
    if resp=$(api_post "/api/v1/service-accounts/${SA_ID}/tokens" \
        "{\"name\":\"spc-${RUN_ID}\",\"scopes\":[\"promote:artifacts\"]}" 2>/dev/null); then
      SA_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // empty') || true
    fi
  fi
fi
if [ -n "$SA_TOKEN" ] && [ "$SA_TOKEN" != "null" ]; then
  pass
else
  # No token -> every assertion below is impossible; stop here.
  fail "could not mint a promote:artifacts service-account token"
  end_suite
  exit $?
fi

# promote_as TOKEN PAYLOAD -> "STATUS<TAB>BODY"
promote_as() {
  local token="$1" payload="$2"
  curl -s $CURL_TIMEOUT -w $'\t%{http_code}' -X POST \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/promotion/repositories/${STAGING_KEY}/artifacts/${ARTIFACT_ID}/promote" \
    2>/dev/null
}

# -------------------------------------------------------------------------
# THE BUG: scoped token + skip_policy_check=true must be refused 403
# -------------------------------------------------------------------------

begin_test "Scoped token + skip_policy_check is refused and names the flag"
out=$(promote_as "$SA_TOKEN" \
  "{\"target_repository\":\"${RELEASE_KEY}\",\"skip_policy_check\":true}") || true
status=$(echo "$out" | awk -F'\t' '{print $NF}')
body=$(echo "$out" | sed 's/\t[0-9]*$//')
if [ "$status" = "403" ] && echo "$body" | grep -q "skip_policy_check"; then
  pass
else
  fail "expected 403 naming skip_policy_check for a non-admin override, got HTTP ${status}" "$body"
fi

begin_test "The refused override did not copy the artifact"
sleep 1
if resp=$(api_get "/api/v1/repositories/${RELEASE_KEY}/artifacts" 2>/dev/null); then
  if echo "$resp" | grep -q "app.bin"; then
    fail "the rule-blocked artifact was promoted by a non-admin skip_policy_check" "$resp"
  else
    pass
  fi
else
  fail "could not list release repo artifacts"
fi

# -------------------------------------------------------------------------
# Control: the same token WITHOUT the flag gets a normal policy refusal
# (200 + promoted:false), proving the token can reach the gate at all
# -------------------------------------------------------------------------

begin_test "Scoped token without the flag gets the normal policy refusal"
out=$(promote_as "$SA_TOKEN" "{\"target_repository\":\"${RELEASE_KEY}\"}") || true
status=$(echo "$out" | awk -F'\t' '{print $NF}')
body=$(echo "$out" | sed 's/\t[0-9]*$//')
if [ "$status" = "200" ] && [ "$(echo "$body" | jq -r '.promoted // empty')" = "false" ]; then
  pass
else
  fail "expected 200 + promoted:false for a rule-blocked promote, got HTTP ${status}" "$body"
fi

# -------------------------------------------------------------------------
# Control: admin break-glass still works AND is recorded in the audit trail
# -------------------------------------------------------------------------

begin_test "Admin skip_policy_check override still promotes"
# auth_admin already minted the admin JWT ($ADMIN_TOKEN).
if [ -z "${ADMIN_TOKEN:-}" ]; then
  skip "no admin JWT"
else
  out=$(promote_as "$ADMIN_TOKEN" \
    "{\"target_repository\":\"${RELEASE_KEY}\",\"skip_policy_check\":true}") || true
  status=$(echo "$out" | awk -F'\t' '{print $NF}')
  body=$(echo "$out" | sed 's/\t[0-9]*$//')
  if [ "$status" = "200" ] && [ "$(echo "$body" | jq -r '.promoted // empty')" = "true" ]; then
    pass
  else
    fail "admin break-glass override must still promote, got HTTP ${status}" "$body"
  fi
fi

begin_test "The admin override is recorded in promotion_history"
if resp=$(api_get "/api/v1/promotion/repositories/${STAGING_KEY}/promotion-history" 2>/dev/null); then
  if echo "$resp" | jq -e '[.. | objects | select(.policy_check_skipped? == true)] | length > 0' \
      > /dev/null 2>&1; then
    pass
  else
    fail "no promotion_history row carries the policy_check_skipped marker" "$resp"
  fi
else
  fail "could not read promotion history"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${STAGING_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${RELEASE_KEY}" > /dev/null 2>&1 || true
if [ -n "${SA_ID:-}" ]; then
  api_delete "/api/v1/service-accounts/${SA_ID}" > /dev/null 2>&1 || true
fi

end_suite
