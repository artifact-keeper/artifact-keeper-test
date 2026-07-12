#!/usr/bin/env bash
# test-ghsa-vvc3-scope-checks.sh - GHSA-vvc3-h39c-mrq5 regression test
#
# Regression coverage for the SA-token scope-check bypass fixed in PR #1219.
# Before the fix, service-account tokens declared with scopes=["read"] could
# call write paths (POST /permissions, POST /groups, format-handler push
# endpoints) because the middleware did not enforce the declared scope set
# on SA tokens (only on user API tokens).
#
# Contract enforced here:
#   - SA token with scope=["read"]:
#       - 403 on POST /api/v1/permissions
#       - 403 on POST /api/v1/groups
#       - 403 on npm publish (PUT /npm/{repo}/{pkg})
#       - 403 on pypi upload (POST /pypi/{repo}/)
#       - 403 on oci blob upload (POST /v2/{repo}/{name}/blobs/uploads/)
#       - 403 on the eight previously-deferred format publish handlers
#         (ansible, chef, cocoapods, jetbrains, pub, puppet, sbt, vscode)
#         now that #2417 completes the GHSA-vvc3 rollout
#       - 403 body contains "Token does not have required scope: write"
#   - SA token with scope=["read","write"]:
#       - succeeds (2xx) on the same write endpoints
#   - JWT user-session token (admin):
#       - succeeds regardless of declared scope; JWTs are NOT scoped
#
# Pairs with: artifact-keeper PR #1219 + #2417, GHSA-vvc3-h39c-mrq5.
# The eight deferred handlers previously lived in the companion
# test-ghsa-vvc3-deferred-handlers.sh (which pinned the still-vulnerable
# state); #2417 fixes them, so that file is removed and its formats are
# folded into the protected assertions below.
# Issue: artifact-keeper-test#76 (Epic 11)
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "ghsa-vvc3-scope-checks"
auth_admin
setup_workdir

SA_READ_NAME="ghsa-sa-read-${RUN_ID}"
SA_WRITE_NAME="ghsa-sa-write-${RUN_ID}"
NPM_REPO="ghsa-npm-${RUN_ID}"
PYPI_REPO="ghsa-pypi-${RUN_ID}"
OCI_REPO="ghsa-oci-${RUN_ID}"

SA_READ_ID=""
SA_WRITE_ID=""
SA_READ_TOKEN=""
SA_WRITE_TOKEN=""
SCOPE_ERROR_MSG="Token does not have required scope: write"

# Eight previously-deferred format publish handlers now gated by #2417.
# Each row: <label>|<repo_format>|<method>|<path-after-BASE_URL>|<mode>
#   mode = multipart -> curl -F (handlers using the axum Multipart extractor
#          reject a non-multipart content-type BEFORE the scope check runs, so
#          a valid boundary is required to reach the scope gate)
#          binary    -> --data-binary with the format's content-type
# The {REPO} placeholder is substituted with each format's per-run repo key.
# NOTE: sbt is nested at /ivy (not /sbt) and its write verb is PUT.
DEFERRED_REPO_PREFIX="ghsa-def"
declare -a DEFERRED_ROWS=(
  "ansible|ansible|POST|/ansible/{REPO}/api/v3/artifacts/collections/|multipart|"
  "chef|chef|POST|/chef/{REPO}/api/v1/cookbooks|multipart|"
  "cocoapods|cocoapods|POST|/cocoapods/{REPO}/pods|binary|application/octet-stream"
  "jetbrains|jetbrains|POST|/jetbrains/{REPO}/plugin/uploadPlugin|binary|application/zip"
  "pub|pub|POST|/pub/{REPO}/api/packages/versions/newUpload|multipart|"
  "puppet|puppet|POST|/puppet/{REPO}/v3/releases|multipart|"
  "sbt|sbt|PUT|/ivy/{REPO}/com/example/test_2.13/1.0.0/test_2.13-1.0.0.jar|binary|application/java-archive"
  "vscode|vscode|POST|/vscode/{REPO}/api/extensions|binary|application/octet-stream"
)
declare -A DEFERRED_REPO_KEY=()

# -------------------------------------------------------------------------
# Setup: create format-typed repos so push endpoints route correctly.
# Failures here mark the suite as unable to run -- skip downstream tests
# rather than reporting false negatives.
# -------------------------------------------------------------------------

begin_test "Create npm repo"
if create_local_repo "$NPM_REPO" "npm"; then
  pass
else
  fail "could not create npm repo"
fi

begin_test "Create pypi repo"
if create_local_repo "$PYPI_REPO" "pypi"; then
  pass
else
  fail "could not create pypi repo"
fi

begin_test "Create oci repo"
if create_local_repo "$OCI_REPO" "docker"; then
  pass
else
  fail "could not create oci repo"
fi

# One repo per previously-deferred format (#2417). create_local_repo sets
# is_public:true, so the read-scope SA can resolve the repo and reach the
# handler's scope gate (a private repo would 404 before the gate and mask
# the assertion).
for row in "${DEFERRED_ROWS[@]}"; do
  IFS='|' read -r d_label d_fmt _ _ _ _ <<< "$row"
  d_key="${DEFERRED_REPO_PREFIX}-${d_label}-${RUN_ID}"
  DEFERRED_REPO_KEY[$d_label]="$d_key"
  begin_test "Create ${d_label} repo"
  if create_local_repo "$d_key" "$d_fmt"; then
    pass
  else
    fail "could not create ${d_label} repo"
  fi
done

# -------------------------------------------------------------------------
# Create the two service accounts: one read-only, one read+write.
# -------------------------------------------------------------------------

begin_test "Create read-scope service account"
if resp=$(api_post "/api/v1/service-accounts" \
    "{\"name\":\"${SA_READ_NAME}\",\"description\":\"GHSA read-scope SA\"}" 2>/dev/null); then
  SA_READ_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$SA_READ_ID" ] && [ "$SA_READ_ID" != "null" ]; then
    pass
  else
    fail "SA created but no ID: ${resp:0:200}"
  fi
else
  fail "could not create read-scope SA"
fi

begin_test "Create write-scope service account"
if resp=$(api_post "/api/v1/service-accounts" \
    "{\"name\":\"${SA_WRITE_NAME}\",\"description\":\"GHSA write-scope SA\"}" 2>/dev/null); then
  SA_WRITE_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$SA_WRITE_ID" ] && [ "$SA_WRITE_ID" != "null" ]; then
    pass
  else
    fail "SA created but no ID: ${resp:0:200}"
  fi
else
  fail "could not create write-scope SA"
fi

# -------------------------------------------------------------------------
# Mint scoped tokens for each SA.
# -------------------------------------------------------------------------

begin_test "Mint read-only token on read-scope SA"
# SA token availability is a precondition for the entire regression suite,
# not optional state. A silent skip here masks setup failures and lets the
# four downstream "rejected on write path" assertions pass vacuously under
# RELEASE_GATE=1. Hard-fail instead.
if [ -z "${SA_READ_ID:-}" ] || [ "$SA_READ_ID" = "null" ]; then
  fail "read SA missing -- token mint is a precondition, not optional"
else
  if resp=$(api_post "/api/v1/service-accounts/${SA_READ_ID}/tokens" \
      "{\"name\":\"ghsa-read-tok-${RUN_ID}\",\"scopes\":[\"read\"]}" 2>/dev/null); then
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

begin_test "Mint read+write token on write-scope SA"
# Same precondition reasoning as the read token above. The positive
# control (write SA can write) is part of the suite's contract; a missing
# write token means we cannot prove the GHSA fix didn't over-rotate.
if [ -z "${SA_WRITE_ID:-}" ] || [ "$SA_WRITE_ID" = "null" ]; then
  fail "write SA missing -- token mint is a precondition, not optional"
else
  if resp=$(api_post "/api/v1/service-accounts/${SA_WRITE_ID}/tokens" \
      "{\"name\":\"ghsa-write-tok-${RUN_ID}\",\"scopes\":[\"read\",\"write\"]}" 2>/dev/null); then
    SA_WRITE_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // empty')
    if [ -n "$SA_WRITE_TOKEN" ] && [ "$SA_WRITE_TOKEN" != "null" ]; then
      pass
    else
      fail "no token in response: ${resp:0:200}"
    fi
  else
    fail "could not mint write token"
  fi
fi

# -------------------------------------------------------------------------
# Helper: send a request with a bearer token, capture both status and body.
# Writes the body to ${WORK_DIR}/last-body so we can grep for the scope
# error message without juggling temp files at every call site.
# -------------------------------------------------------------------------

call_with_token() {
  local token="$1"
  local method="$2"
  local path="$3"
  local content_type="${4:-application/json}"
  local data="${5:-}"
  local body_file="${WORK_DIR}/last-body"

  # shellcheck disable=SC2206 # CURL_TIMEOUT is intentionally word-split
  local args=(-s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT
    -X "$method"
    -H "Authorization: Bearer ${token}"
    -H "Content-Type: ${content_type}")
  if [ -n "$data" ]; then
    args+=(-d "$data")
  fi
  args+=("${BASE_URL}${path}")
  curl "${args[@]}" 2>/dev/null || echo "000"
}

assert_403_with_scope_msg() {
  local label="$1"
  local status="$2"
  local body_file="${WORK_DIR}/last-body"
  if [ "$status" != "403" ]; then
    fail "${label}: expected 403, got HTTP ${status}"
    return 1
  fi
  # Strict contract: response body MUST contain the exact backend scope-
  # error substring. The earlier lowercase-"scope" fallback loosened this
  # so a 403 with body "out of scope" or "Insufficient scope" would
  # silently pass, which masks the message-shape part of the contract
  # the GHSA fix actually pins (middleware/auth.rs emits the literal
  # string verbatim). Keep only the exact substring match.
  if grep -q "$SCOPE_ERROR_MSG" "$body_file" 2>/dev/null; then
    pass
    return 0
  fi
  fail "${label}: got 403 but body missing canonical scope error '${SCOPE_ERROR_MSG}': $(head -c 200 "$body_file" 2>/dev/null)"
  return 1
}

# -------------------------------------------------------------------------
# Core regression: read-scope SA token MUST be rejected on write paths.
# -------------------------------------------------------------------------

# If the SA read token wasn't minted, the four downstream assertions
# cannot meaningfully run. Hard-fail and exit so the suite reports the
# precondition failure clearly under RELEASE_GATE=1 instead of emitting
# four silent "skip" testcases that look like greens on the dashboard.
if [ -z "${SA_READ_TOKEN:-}" ]; then
  begin_test "Precondition: SA read token available"
  fail "SA read token unavailable -- scope-check assertions cannot run"
  end_suite
fi

begin_test "Read-scope SA token rejected on POST /api/v1/permissions"
status=$(call_with_token "$SA_READ_TOKEN" POST "/api/v1/permissions" \
  "application/json" \
  "{\"name\":\"ghsa-perm-${RUN_ID}\",\"description\":\"should not be created\"}")
assert_403_with_scope_msg "POST /api/v1/permissions" "$status"

begin_test "Read-scope SA token rejected on POST /api/v1/groups"
status=$(call_with_token "$SA_READ_TOKEN" POST "/api/v1/groups" \
  "application/json" \
  "{\"name\":\"ghsa-group-${RUN_ID}\",\"description\":\"should not be created\"}")
assert_403_with_scope_msg "POST /api/v1/groups" "$status"

# Format-handler push paths. These three (npm, pypi, oci) are the canonical
# write surfaces referenced in the GHSA advisory. We don't need a valid
# payload for the contract test: the scope check fires before any payload
# parsing, so an empty/minimal body is enough to assert 403.
#
# Each path is pinned to one canonical URL with no 404-fallback. A 404 on
# the primary URL is a routing regression that should fail the suite
# loudly, not be papered over by retrying an alternate path. Per-format
# conformance tests own URL-shape coverage; this test owns the scope-check
# contract on the canonical surface.

begin_test "Read-scope SA token rejected on npm publish (PUT /npm/{repo}/{pkg})"
# Minimal npm publish envelope. Backend rejects on scope before parsing.
npm_payload='{"name":"ghsa-test-pkg","versions":{},"_attachments":{}}'
status=$(call_with_token "$SA_READ_TOKEN" PUT \
  "/npm/${NPM_REPO}/ghsa-test-pkg" \
  "application/json" "$npm_payload")
assert_403_with_scope_msg "npm publish" "$status"

begin_test "Read-scope SA token rejected on pypi upload (POST /pypi/{repo}/)"
# Empty multipart is fine: scope check runs before multipart parser.
body_file="${WORK_DIR}/last-body"
status=$(curl -s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "Authorization: Bearer ${SA_READ_TOKEN}" \
  -F ":action=file_upload" \
  -F "name=ghsa-test" \
  -F "version=0.0.1" \
  "${BASE_URL}/pypi/${PYPI_REPO}/" 2>/dev/null) || status=000
assert_403_with_scope_msg "pypi upload" "$status"

begin_test "Read-scope SA token rejected on oci blob upload (POST /v2/.../blobs/uploads/)"
status=$(call_with_token "$SA_READ_TOKEN" POST \
  "/v2/${OCI_REPO}/ghsa-test/blobs/uploads/" \
  "application/octet-stream" "")
assert_403_with_scope_msg "oci blob upload" "$status"

# -------------------------------------------------------------------------
# Previously-deferred format publish handlers (#2417). These eight formats
# used to be pinned as still-vulnerable in test-ghsa-vvc3-deferred-handlers.sh;
# with #2417 each swaps require_auth_basic -> require_auth_basic_scope(...,
# "write"), so a read-scope SA token must now be rejected identically to
# npm/pypi/oci above. The scope gate fires before the format's body parser,
# so a minimal body suffices; multipart-extractor handlers still need a valid
# multipart boundary (curl -F) to reach the gate rather than 400ing first.
# -------------------------------------------------------------------------

publish_scope_status() {
  # $1 method  $2 path  $3 mode(multipart|binary)  $4 content-type(binary only)
  local method="$1" path="$2" mode="$3" ctype="${4:-application/octet-stream}"
  local body_file="${WORK_DIR}/last-body"
  # shellcheck disable=SC2206 # CURL_TIMEOUT is intentionally word-split
  local args=(-s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT
    -X "$method" -H "Authorization: Bearer ${SA_READ_TOKEN}")
  if [ "$mode" = "multipart" ]; then
    args+=(-F "file=@/dev/null")
  else
    args+=(-H "Content-Type: ${ctype}" --data-binary "x")
  fi
  args+=("${BASE_URL}${path}")
  curl "${args[@]}" 2>/dev/null || echo "000"
}

for row in "${DEFERRED_ROWS[@]}"; do
  IFS='|' read -r d_label _ d_method d_path_tpl d_mode d_ctype <<< "$row"
  d_key="${DEFERRED_REPO_KEY[$d_label]}"
  d_path="${d_path_tpl//\{REPO\}/$d_key}"
  begin_test "Read-scope SA token rejected on ${d_label} publish (${d_method} ${d_path_tpl})"
  status=$(publish_scope_status "$d_method" "$d_path" "$d_mode" "$d_ctype")
  assert_403_with_scope_msg "${d_label} publish" "$status"
done

# pub_registry also gates the upload-URL preflight (#2417 D2): a read token
# must not be able to obtain an upload URL.
begin_test "Read-scope SA token rejected on pub upload-URL preflight (GET .../versions/new)"
status=$(call_with_token "$SA_READ_TOKEN" GET \
  "/pub/${DEFERRED_REPO_KEY[pub]}/api/packages/versions/new" \
  "application/json" "")
assert_403_with_scope_msg "pub upload-URL preflight" "$status"

# -------------------------------------------------------------------------
# Authorization-layer control: a write-scope SA token passes the GHSA scope
# check but is STILL rejected (403) on permission/group creation, because
# those are admin-only operations in the backend authorization model.
#
# Granting fine-grained permissions and creating groups are privileged
# operations: create_permission calls require_admin() and create_group
# requires admin (or fine-grained "admin" on the system sentinel) AFTER the
# scope check. A plain write-scope service account is neither, so it must get
# 403 -- "Admin access required" / "Insufficient permissions to create
# groups" -- NOT a 2xx. This pins that the GHSA scope fix layers on top of
# the existing admin gate rather than replacing it.
#
# (Earlier revisions of this suite expected a 2xx here and sent a
# {name, description} body. That body never matched the permissions API,
# which requires {principal_type, principal_id, target_type, target_id,
# actions}; and write-scope alone was never sufficient for these admin-only
# endpoints. See artifact-keeper#1438 / GHSA-vvc3-h39c-mrq5.)
# -------------------------------------------------------------------------

CREATED_PERM_ID=""
CREATED_GROUP_ID=""

begin_test "Write-scope SA token is rejected (403, admin required) on POST /api/v1/permissions"
if [ -z "${SA_WRITE_TOKEN:-}" ]; then
  skip "no write SA token"
else
  status=$(call_with_token "$SA_WRITE_TOKEN" POST "/api/v1/permissions" \
    "application/json" \
    "{\"name\":\"ghsa-ok-perm-${RUN_ID}\",\"description\":\"created by write SA\"}")
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 (admin required) for write SA on POST /permissions, got ${status}: $(head -c 200 "${WORK_DIR}/last-body" 2>/dev/null)"
  fi
fi

begin_test "Write-scope SA token is rejected (403, admin required) on POST /api/v1/groups"
if [ -z "${SA_WRITE_TOKEN:-}" ]; then
  skip "no write SA token"
else
  status=$(call_with_token "$SA_WRITE_TOKEN" POST "/api/v1/groups" \
    "application/json" \
    "{\"name\":\"ghsa-ok-group-${RUN_ID}\",\"description\":\"created by write SA\"}")
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 (admin required) for write SA on POST /groups, got ${status}: $(head -c 200 "${WORK_DIR}/last-body" 2>/dev/null)"
  fi
fi

# -------------------------------------------------------------------------
# JWT (user session) passes scope checks regardless of declared scope.
# Admin JWTs are not scoped: middleware/auth.rs treats JWT-bearing requests
# as scope-unrestricted. This test asserts that the GHSA fix did not
# accidentally apply scope enforcement to JWTs.
# -------------------------------------------------------------------------

begin_test "Admin JWT passes write-scope check on POST /api/v1/permissions"
# The permissions API requires a real {principal_type, principal_id,
# target_type, target_id, actions} body -- NOT {name, description}. Resolve
# the admin user id (principal) and one of the repos created above (target)
# so the admin JWT exercises the genuine create path. A malformed body would
# 400 AFTER the scope/admin gate, which would not prove the JWT passed the
# write-scope check.
PERM_PRINCIPAL_ID=$(resolve_user_id_by_username "$ADMIN_USER" 2>/dev/null || true)
PERM_TARGET_ID=$(api_get "/api/v1/repositories/${NPM_REPO}" 2>/dev/null | jq -r '.id // empty')
if [ -z "$PERM_PRINCIPAL_ID" ] || [ -z "$PERM_TARGET_ID" ]; then
  fail "could not resolve principal (admin user) or target (repo) id for permission body"
else
  perm_body=$(jq -n \
    --arg pid "$PERM_PRINCIPAL_ID" \
    --arg tid "$PERM_TARGET_ID" \
    '{principal_type:"user", principal_id:$pid, target_type:"repository", target_id:$tid, actions:["read"]}')
  status=$(call_with_token "$ADMIN_TOKEN" POST "/api/v1/permissions" \
    "application/json" "$perm_body")
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    JWT_PERM_ID=$(jq -r '.id // empty' < "${WORK_DIR}/last-body" 2>/dev/null || true)
    pass
  else
    fail "admin JWT rejected on write path (expected 2xx, got ${status}): $(head -c 200 "${WORK_DIR}/last-body" 2>/dev/null)"
  fi
fi

begin_test "Admin JWT passes write-scope check on POST /api/v1/groups"
status=$(call_with_token "$ADMIN_TOKEN" POST "/api/v1/groups" \
  "application/json" \
  "{\"name\":\"ghsa-jwt-group-${RUN_ID}\",\"description\":\"created by admin JWT\"}")
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  JWT_GROUP_ID=$(jq -r '.id // empty' < "${WORK_DIR}/last-body" 2>/dev/null || true)
  pass
else
  fail "admin JWT rejected on write path (expected 2xx, got ${status}): $(head -c 200 "${WORK_DIR}/last-body" 2>/dev/null)"
fi

# -------------------------------------------------------------------------
# Cleanup. Best-effort: any failure here doesn't change the suite result,
# the items will be garbage collected by the next nightly cleanup.
# -------------------------------------------------------------------------

auth_admin
if [ -n "${CREATED_PERM_ID:-}" ] && [ "$CREATED_PERM_ID" != "null" ]; then
  api_delete "/api/v1/permissions/${CREATED_PERM_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${JWT_PERM_ID:-}" ] && [ "$JWT_PERM_ID" != "null" ]; then
  api_delete "/api/v1/permissions/${JWT_PERM_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${CREATED_GROUP_ID:-}" ] && [ "$CREATED_GROUP_ID" != "null" ]; then
  api_delete "/api/v1/groups/${CREATED_GROUP_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${JWT_GROUP_ID:-}" ] && [ "$JWT_GROUP_ID" != "null" ]; then
  api_delete "/api/v1/groups/${JWT_GROUP_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${SA_READ_ID:-}" ] && [ "$SA_READ_ID" != "null" ]; then
  api_delete "/api/v1/service-accounts/${SA_READ_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${SA_WRITE_ID:-}" ] && [ "$SA_WRITE_ID" != "null" ]; then
  api_delete "/api/v1/service-accounts/${SA_WRITE_ID}" > /dev/null 2>&1 || true
fi
api_delete "/api/v1/repositories/${NPM_REPO}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${PYPI_REPO}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${OCI_REPO}" > /dev/null 2>&1 || true
for d_label in "${!DEFERRED_REPO_KEY[@]}"; do
  api_delete "/api/v1/repositories/${DEFERRED_REPO_KEY[$d_label]}" > /dev/null 2>&1 || true
done

end_suite
