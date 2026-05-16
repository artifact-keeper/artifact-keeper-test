#!/usr/bin/env bash
# test-ghsa-vvc3-deferred-handlers.sh - GHSA-vvc3-h39c-mrq5 deferred handlers
#
# Companion to test-ghsa-vvc3-scope-checks.sh.
#
# Background:
#   PR #1219 fixed the SA-token scope bypass on npm, pypi, and oci, but
#   explicitly reverted the same fix on 8 other handlers to satisfy the
#   jscpd duplication gate (see CHANGELOG entry "remain affected by the
#   advisory"). Those 8 handlers are:
#
#       ansible, chef, cocoapods, jetbrains, pub_registry, puppet, sbt, vscode
#
#   A read-scope SA token TODAY still gets accepted on the write paths of
#   those 8 formats. That is a known bug, scheduled to be fixed in a
#   follow-up PR once the duplication gate is addressed.
#
# What this test does:
#   It pins the EXPECTED-CURRENT-BEHAVIOR: each of the 8 deferred handlers
#   accepts a read-scope SA token on its publish path today (status is
#   anything in {200, 201, 202, 400, 404, 409, 415, 422, 500} but NOT 403).
#   We deliberately do NOT assert a specific success status: payload-parsing
#   errors (400/415/422/500) are acceptable as long as the scope check did
#   not fire. The contract is: "scope check should fire here later, today
#   it does not".
#
#   The moment the backend fix lands and any of the 8 handlers starts
#   returning 403 with the canonical "Token does not have required scope:
#   write" message, this test will fail loudly with a message instructing
#   the engineer to flip that handler from the deferred list to the
#   protected list in test-ghsa-vvc3-scope-checks.sh.
#
# Pairs with: artifact-keeper PR #1219, GHSA-vvc3-h39c-mrq5
# Issue: artifact-keeper-test#76 (Epic 11)
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "ghsa-vvc3-deferred-handlers"
auth_admin
setup_workdir

SA_READ_NAME="ghsa-def-sa-read-${RUN_ID}"
SA_READ_ID=""
SA_READ_TOKEN=""
SCOPE_ERROR_MSG="Token does not have required scope: write"

# Format -> repo_format mapping for create_local_repo. The "format" value
# must match what backend/src/repositories::RepositoryFormat accepts.
# pub_registry is created as "pub" because backend's repo-create endpoint
# normalizes the format to its short name.
declare -a DEFERRED_FORMATS=(ansible chef cocoapods jetbrains pub puppet sbt vscode)

declare -A REPO_KEY_BY_FORMAT=()

# -------------------------------------------------------------------------
# Setup: create one repo per deferred format. Failures here are precondition
# failures, not skips: a missing repo invalidates the regression assertion
# for that format.
# -------------------------------------------------------------------------

for fmt in "${DEFERRED_FORMATS[@]}"; do
  REPO_KEY_BY_FORMAT[$fmt]="ghsa-def-${fmt}-${RUN_ID}"
  begin_test "Create ${fmt} repo"
  if create_local_repo "${REPO_KEY_BY_FORMAT[$fmt]}" "$fmt"; then
    pass
  else
    fail "could not create ${fmt} repo"
  fi
done

# -------------------------------------------------------------------------
# Mint a read-scope SA token.
# -------------------------------------------------------------------------

begin_test "Create read-scope service account"
if resp=$(api_post "/api/v1/service-accounts" \
    "{\"name\":\"${SA_READ_NAME}\",\"description\":\"GHSA deferred read-scope SA\"}" 2>/dev/null); then
  SA_READ_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$SA_READ_ID" ] && [ "$SA_READ_ID" != "null" ]; then
    pass
  else
    fail "SA created but no ID: ${resp:0:200}"
  fi
else
  fail "could not create read-scope SA"
fi

begin_test "Mint read-only token on read-scope SA"
if [ -z "${SA_READ_ID:-}" ] || [ "$SA_READ_ID" = "null" ]; then
  fail "read SA missing -- token mint is a precondition, not optional"
else
  if resp=$(api_post "/api/v1/service-accounts/${SA_READ_ID}/tokens" \
      "{\"name\":\"ghsa-def-read-tok-${RUN_ID}\",\"scopes\":[\"read\"]}" 2>/dev/null); then
    SA_READ_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // empty')
    if [ -n "$SA_READ_TOKEN" ] && [ "$SA_READ_TOKEN" != "null" ]; then
      pass
    else
      fail "no token in response: ${resp:0:200}"
    fi
  else
    fail "could not mint read token"
  fi
fi

# Hard precondition: if SA token creation failed there is no point running
# the deferred-handler assertions. Fail loudly so an operator sees that the
# regression test did not actually exercise the surface it claims to.
if [ -z "${SA_READ_TOKEN:-}" ]; then
  begin_test "Precondition: SA read token available"
  fail "SA read token unavailable -- deferred-handler assertions cannot run"
  end_suite
fi

# -------------------------------------------------------------------------
# Helper: call a publish path with the read-scope SA token, capture status
# AND body. Returns status on stdout.
# -------------------------------------------------------------------------

call_publish() {
  local method="$1"
  local path="$2"
  local content_type="${3:-application/octet-stream}"
  local body_file="${WORK_DIR}/last-body"
  # shellcheck disable=SC2206 # CURL_TIMEOUT is intentionally word-split
  local args=(-s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT
    -X "$method"
    -H "Authorization: Bearer ${SA_READ_TOKEN}"
    -H "Content-Type: ${content_type}"
    --data-binary "@/dev/null"
    "${BASE_URL}${path}")
  curl "${args[@]}" 2>/dev/null || echo "000"
}

# assert_NOT_blocked_by_scope LABEL STATUS
#
# The deferred handler is currently vulnerable. We expect ANYTHING except
# a 403 with the scope error message. If we see the canonical scope-error
# 403, the bug has been fixed for that handler. Fail loudly with a
# remediation hint.
assert_NOT_blocked_by_scope() {
  local label="$1"
  local status="$2"
  local body_file="${WORK_DIR}/last-body"

  if [ "$status" = "403" ] && grep -q "$SCOPE_ERROR_MSG" "$body_file" 2>/dev/null; then
    fail "${label}: backend now returns 403 + scope-error -- handler is FIXED. Move this format from the deferred list in test-ghsa-vvc3-deferred-handlers.sh into the protected list in test-ghsa-vvc3-scope-checks.sh."
    return 1
  fi
  # Any other outcome (including auth/parse errors) is consistent with
  # the unfixed-but-not-this-bug state. Pinning the contract on "anything
  # but a scope-error 403" is the loosest sound assertion: a 401 (e.g. SA
  # tokens disabled in this build), a 400/415/422 (payload rejected), a
  # 404 (route not mounted), or a 2xx (accepted) are all current-real-world
  # outcomes for the 8 deferred handlers depending on the format's payload
  # parser. None of those indicate the scope-check fix has been applied.
  pass
}

# -------------------------------------------------------------------------
# Per-format publish surfaces. Each format has a representative write path.
# These are canonical paths -- no fallbacks. If a path 404s the test still
# passes (the scope check didn't fire); a routing regression on the path
# itself is owned by the per-format conformance suite, not by this test.
# -------------------------------------------------------------------------

begin_test "ansible publish path is NOT blocked by scope (current bug)"
status=$(call_publish POST \
  "/ansible/${REPO_KEY_BY_FORMAT[ansible]}/api/v3/artifacts/collections/" \
  "application/x-tar")
assert_NOT_blocked_by_scope "ansible POST collections" "$status"

begin_test "chef publish path is NOT blocked by scope (current bug)"
status=$(call_publish POST \
  "/chef/${REPO_KEY_BY_FORMAT[chef]}/api/v1/cookbooks" \
  "multipart/form-data")
assert_NOT_blocked_by_scope "chef POST cookbooks" "$status"

begin_test "cocoapods publish path is NOT blocked by scope (current bug)"
status=$(call_publish POST \
  "/cocoapods/${REPO_KEY_BY_FORMAT[cocoapods]}/api/v1/pods" \
  "application/json")
assert_NOT_blocked_by_scope "cocoapods POST pods" "$status"

begin_test "jetbrains publish path is NOT blocked by scope (current bug)"
status=$(call_publish POST \
  "/jetbrains/${REPO_KEY_BY_FORMAT[jetbrains]}/api/plugin" \
  "multipart/form-data")
assert_NOT_blocked_by_scope "jetbrains POST plugin" "$status"

begin_test "pub_registry publish path is NOT blocked by scope (current bug)"
status=$(call_publish POST \
  "/pub/${REPO_KEY_BY_FORMAT[pub]}/api/packages/versions/newUpload" \
  "application/json")
assert_NOT_blocked_by_scope "pub_registry POST newUpload" "$status"

begin_test "puppet publish path is NOT blocked by scope (current bug)"
status=$(call_publish POST \
  "/puppet/${REPO_KEY_BY_FORMAT[puppet]}/v3/releases" \
  "multipart/form-data")
assert_NOT_blocked_by_scope "puppet POST releases" "$status"

begin_test "sbt publish path is NOT blocked by scope (current bug)"
status=$(call_publish PUT \
  "/sbt/${REPO_KEY_BY_FORMAT[sbt]}/com/example/test_2.13/1.0.0/test_2.13-1.0.0.jar" \
  "application/java-archive")
assert_NOT_blocked_by_scope "sbt PUT artifact" "$status"

begin_test "vscode publish path is NOT blocked by scope (current bug)"
status=$(call_publish POST \
  "/vscode/${REPO_KEY_BY_FORMAT[vscode]}/_apis/public/gallery/publishers/test/vsextensions/test/1.0.0/extensionPackage" \
  "application/octet-stream")
assert_NOT_blocked_by_scope "vscode POST extensionPackage" "$status"

# -------------------------------------------------------------------------
# Cleanup. Best-effort.
# -------------------------------------------------------------------------

auth_admin
if [ -n "${SA_READ_ID:-}" ] && [ "$SA_READ_ID" != "null" ]; then
  api_delete "/api/v1/service-accounts/${SA_READ_ID}" > /dev/null 2>&1 || true
fi
for fmt in "${DEFERRED_FORMATS[@]}"; do
  api_delete "/api/v1/repositories/${REPO_KEY_BY_FORMAT[$fmt]}" > /dev/null 2>&1 || true
done

end_suite
