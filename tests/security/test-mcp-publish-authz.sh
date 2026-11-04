#!/usr/bin/env bash
# test-mcp-publish-authz.sh - who may publish to, change the status of, and
# read an MCP registry repository (artifact-keeper#5253, docs/mcp-registry.md
# "Authentication and publishing").
#
# Contract under test:
#   - publishing and status changes need repository `write` and, for an API
#     token, the `write:artifacts` scope; any AK credential is the bearer.
#   - an anonymous write is 401 application/problem+json (no-store) and keeps
#     the shared middleware's WWW-Authenticate challenge.
#   - reads follow repository visibility: a public repository is readable by
#     anyone (a user with no grant included), a private one answers an
#     anonymous read with the same 401 challenge every format route gives.
#
# Pinned from the backend (the docs do not spell these out):
#   - a user with no grant reading a PRIVATE mcp repository gets the plain
#     unknown-name 404 (MCP_NOT_FOUND_BODY), byte-identical to a repository
#     key that does not exist: existence is hidden, not 403.
#   - a repository-scoped API token (repo_selector naming another repository)
#     publishing here is 403 mcp_forbidden. The detail tells the two token
#     refusals apart: "This token does not carry the write:artifacts scope"
#     for a missing scope, "This token is not scoped to this repository" for
#     a token scoped elsewhere.
#   - POST /mcp/<non-mcp repo key>/v0.1/publish is the plain 404.
#   - a deactivated user's API token and session JWT are both 401.
#
# Every request is a direct curl so the status code is the backend's own.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-publish-authz"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
mcp_require_registry

KEY="sec-mcpauthz-${RUN_ID}"
KEY2="sec-mcpauthz2-${RUN_ID}"
PRIV_KEY="sec-mcpauthzp-${RUN_ID}"
NPM_KEY="sec-mcpauthz-npm-${RUN_ID}"
NS="com.authz-${RUN_ID}"
REMOTE='[{"type":"streamable-http","url":"https://mcp.example.invalid/mcp"}]'

# remote_doc NAME VERSION: write a remotes-only server.json (no backing
# package needed under own-repos) and echo its path.
_doc_seq=0
remote_doc() {
  _doc_seq=$(( _doc_seq + 1 ))
  local f="${WORK_DIR}/doc-${_doc_seq}.json"
  mcp_server_json "$1" "$2" "" "$REMOTE" > "$f"
  echo "$f"
}

# expect_problem STATUS CODE WHAT: pass or fail on the last mcp_* answer.
expect_problem() {
  local why
  if why=$(mcp_check_problem "$1" "$2"); then
    pass
  else
    fail "$3: ${why}"
  fi
}

# expect_status STATUS WHAT: the last answer is exactly STATUS.
expect_status() {
  if [ "$MCP_STATUS" = "$1" ]; then
    pass
  else
    fail "$2: expected HTTP $1, got ${MCP_STATUS}: $(mcp_snip)"
  fi
}

# new_user NAME: create a user, set NEW_TOKEN and NEW_ID (no subshell, so
# mcp_make_user's MCP_USER_ID survives).
new_user() {
  NEW_TOKEN=""
  NEW_ID=""
  if mcp_make_user "$1" > "${WORK_DIR}/token-$1"; then
    NEW_TOKEN=$(cat "${WORK_DIR}/token-$1")
    NEW_ID="$MCP_USER_ID"
  fi
  [ -n "$NEW_TOKEN" ] && [ -n "$NEW_ID" ]
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

begin_test "Create the MCP repositories (public, second public, private) and an npm repository"
if mcp_create_repo "$KEY" && mcp_create_repo "$KEY2" && mcp_create_repo "$PRIV_KEY" '{}' false \
  && create_local_repo "$NPM_KEY" npm; then
  mcp_delete_repo_on_exit "$NPM_KEY"
  pass
else
  fail_fatal "fixture repositories could not be created: ${MCP_CREATE_ERROR:-npm create failed}"
fi

begin_test "Create users: no grant, read grant, write grant, to-be-deactivated"
users_ok=true
new_user "mcpaz-none-${RUN_ID}" || users_ok=false
TOK_NONE="$NEW_TOKEN"
new_user "mcpaz-read-${RUN_ID}" || users_ok=false
TOK_READ="$NEW_TOKEN"; ID_READ="$NEW_ID"
new_user "mcpaz-write-${RUN_ID}" || users_ok=false
TOK_WRITE="$NEW_TOKEN"; ID_WRITE="$NEW_ID"
new_user "mcpaz-deact-${RUN_ID}" || users_ok=false
TOK_DEACT="$NEW_TOKEN"; ID_DEACT="$NEW_ID"
if $users_ok \
  && mcp_grant "$ID_READ" "$KEY" '["read"]' \
  && mcp_grant "$ID_READ" "$PRIV_KEY" '["read"]' \
  && mcp_grant "$ID_WRITE" "$KEY" '["read","write"]' \
  && mcp_grant "$ID_WRITE" "$KEY2" '["read","write"]' \
  && mcp_grant "$ID_DEACT" "$KEY" '["read","write"]'; then
  pass
else
  fail_fatal "user or grant setup failed (last grant HTTP ${MCP_STATUS:-?}): $(mcp_snip)"
fi

# Seed one version so the status routes have a target that exists.
SEED="${NS}/seed"
begin_test "Admin publishes the seed version"
mcp_publish "$KEY" "$(remote_doc "$SEED" 1.0.0)"
expect_status 200 "admin publish of the seed version"

# ---------------------------------------------------------------------------
# Anonymous writes
# ---------------------------------------------------------------------------

for api in v0.1 v0; do
  begin_test "Anonymous POST /${api}/publish is 401 problem+json with WWW-Authenticate"
  mcp_req POST "${BASE_URL}/mcp/${KEY}/${api}/publish" anon \
    -H "Content-Type: application/json" --data-binary "@$(remote_doc "${NS}/anon-${api}" 1.0.0)"
  if why=$(mcp_check_problem 401 mcp_unauthorized); then
    if [ -n "$(mcp_header www-authenticate)" ]; then
      pass
    else
      fail "anonymous publish 401 lost its WWW-Authenticate challenge" \
        "docs/mcp-registry.md: middleware refusals on /mcp/ keep WWW-Authenticate. Headers: $(tr -d '\r' < "$MCP_HDRS" | head -20)"
    fi
  else
    fail "anonymous publish on /${api}: ${why}"
  fi
done

begin_test "Anonymous PATCH .../versions/1.0.0/status is 401"
mcp_patch_status "$KEY" "$SEED" 1.0.0 deprecated "" anon
expect_problem 401 mcp_unauthorized "anonymous version status PATCH"

begin_test "Anonymous PATCH .../servers/<name>/status (all versions) is 401"
mcp_patch_status "$KEY" "$SEED" "" deprecated "" anon
expect_problem 401 mcp_unauthorized "anonymous all-versions status PATCH"

begin_test "The anonymous status PATCHes changed nothing (seed still active)"
mcp_get "$KEY" "$(mcp_version_path "$SEED" 1.0.0)"
st=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status // empty')
if [ "$MCP_STATUS" = "200" ] && [ "$st" = "active" ]; then
  pass
else
  fail "seed version after anonymous PATCHes: HTTP ${MCP_STATUS}, status '${st}' (expected 200, active)"
fi

# ---------------------------------------------------------------------------
# Users and grants
# ---------------------------------------------------------------------------

begin_test "A user with no grant cannot publish to a public repository (403)"
mcp_publish "$KEY" "$(remote_doc "${NS}/nogrant" 1.0.0)" "$TOK_NONE"
expect_problem 403 mcp_forbidden "no-grant publish"

begin_test "The same no-grant user can read the public repository (200)"
mcp_get "$KEY" "servers" "$TOK_NONE"
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '[.servers[]?.server.name] | index("'"$SEED"'") != null')" = "true" ]; then
  pass
else
  fail "no-grant read of a public repository: HTTP ${MCP_STATUS}, seed listed: $(mcp_json '[.servers[]?.server.name]|tostring')"
fi

begin_test "The no-grant user cannot change a status either (403)"
mcp_patch_status "$KEY" "$SEED" 1.0.0 deprecated "" "$TOK_NONE"
expect_problem 403 mcp_forbidden "no-grant status PATCH"

begin_test "A user with a read-only grant cannot publish (403)"
mcp_publish "$KEY" "$(remote_doc "${NS}/readgrant" 1.0.0)" "$TOK_READ"
expect_problem 403 mcp_forbidden "read-grant publish"

begin_test "A user with a write grant can publish (200)"
mcp_publish "$KEY" "$(remote_doc "${NS}/writegrant" 1.0.0)" "$TOK_WRITE"
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.name')" = "${NS}/writegrant" ]; then
  pass
else
  fail "write-grant publish: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "A user with a write grant can change a status (200)"
mcp_patch_status "$KEY" "${NS}/writegrant" 1.0.0 deprecated "" "$TOK_WRITE"
expect_status 200 "write-grant status PATCH"

# ---------------------------------------------------------------------------
# API token scopes
# ---------------------------------------------------------------------------

begin_test "Mint API tokens for the write user (read:artifacts, write:artifacts, repo-scoped)"
TOK_RSCOPE=$(mcp_mint_token "$TOK_WRITE" "mcpaz-r-${RUN_ID}" '["read:artifacts"]')
TOK_WSCOPE=$(mcp_mint_token "$TOK_WRITE" "mcpaz-w-${RUN_ID}" '["write:artifacts"]')
KEY2_ID=$(mcp_repo_id "$KEY2")
TOK_OTHER=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -X POST -H "Authorization: Bearer ${TOK_WRITE}" \
  -H "Content-Type: application/json" \
  -d "$(jq -cn --arg n "mcpaz-s-${RUN_ID}" --arg r "$KEY2_ID" '{name:$n,scopes:["write:artifacts"],repo_selector:{match_repos:[$r]}}')" \
  "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null | jq -r '.token // empty' 2>/dev/null) || TOK_OTHER=""
TOK_DEACT_API=$(mcp_mint_token "$TOK_DEACT" "mcpaz-d-${RUN_ID}" '["write:artifacts"]')
if [ -n "$TOK_RSCOPE" ] && [ -n "$TOK_WSCOPE" ] && [ -n "$TOK_OTHER" ] && [ -n "$TOK_DEACT_API" ]; then
  pass
else
  fail_fatal "token minting failed (read:'${TOK_RSCOPE:0:4}' write:'${TOK_WSCOPE:0:4}' scoped:'${TOK_OTHER:0:4}' deact:'${TOK_DEACT_API:0:4}')"
fi

SCOPE_DETAIL="This token does not carry the write:artifacts scope"
REPO_SCOPE_DETAIL="This token is not scoped to this repository"

# expect_forbidden_detail DETAIL WHAT: 403 mcp_forbidden with that detail.
expect_forbidden_detail() {
  local why
  if ! why=$(mcp_check_problem 403 mcp_forbidden); then
    fail "$2: ${why}"
  elif [ "$(mcp_json '.detail // empty')" != "$1" ]; then
    fail "$2: detail '$(mcp_json '.detail // empty')', want '$1'"
  else
    pass
  fi
}

begin_test "An API token with only read:artifacts cannot publish (403, names the missing scope)"
mcp_publish "$KEY" "$(remote_doc "${NS}/readscope" 1.0.0)" "$TOK_RSCOPE"
expect_forbidden_detail "$SCOPE_DETAIL" "read:artifacts token publish"

begin_test "An API token with write:artifacts can publish (200)"
mcp_publish "$KEY" "$(remote_doc "${NS}/writescope" 1.0.0)" "$TOK_WSCOPE"
expect_status 200 "write:artifacts token publish"

begin_test "A token scoped to another repository cannot publish here (403, says so)"
mcp_publish "$KEY" "$(remote_doc "${NS}/otherscope" 1.0.0)" "$TOK_OTHER"
expect_forbidden_detail "$REPO_SCOPE_DETAIL" "repo-scoped token publishing outside its scope"

begin_test "Control: the same scoped token publishes to the repository it names (200)"
mcp_publish "$KEY2" "$(remote_doc "${NS}/otherscope" 1.0.0)" "$TOK_OTHER"
expect_status 200 "repo-scoped token publishing inside its scope"

# ---------------------------------------------------------------------------
# Deactivated user
# ---------------------------------------------------------------------------

begin_test "Control: the to-be-deactivated user's token publishes (200)"
mcp_publish "$KEY" "$(remote_doc "${NS}/deact" 1.0.0)" "$TOK_DEACT_API"
expect_status 200 "pre-deactivation publish"

begin_test "Deactivate the user (PATCH /api/v1/users/{id} is_active=false)"
st=$(curl -s -o "${WORK_DIR}/deact.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PATCH \
  -H "$(auth_header)" -H "Content-Type: application/json" -d '{"is_active":false}' \
  "${BASE_URL}/api/v1/users/${ID_DEACT}" 2>/dev/null) || st="000"
if [ "${st:0:1}" = "2" ]; then
  pass
else
  fail_fatal "deactivation returned HTTP ${st}: $(head -c 300 "${WORK_DIR}/deact.json" 2>/dev/null)"
fi

begin_test "A deactivated user's API token cannot publish (401)"
ok=false
for _ in 1 2 3 4 5; do
  mcp_publish "$KEY" "$(remote_doc "${NS}/deact" 1.0.1)" "$TOK_DEACT_API"
  [ "$MCP_STATUS" = "401" ] && { ok=true; break; }
  sleep 1
done
if $ok; then
  expect_problem 401 mcp_unauthorized "deactivated token publish"
else
  fail "deactivated user's API token publish answered ${MCP_STATUS} (expected 401): $(mcp_snip)"
fi

begin_test "A deactivated user's session JWT cannot publish (401)"
mcp_publish "$KEY" "$(remote_doc "${NS}/deact" 1.0.2)" "$TOK_DEACT"
expect_problem 401 mcp_unauthorized "deactivated JWT publish"

# ---------------------------------------------------------------------------
# Wrong repository kind
# ---------------------------------------------------------------------------

begin_test "Publish under /mcp/<npm repo key>/ is the plain 404 problem"
mcp_publish "$NPM_KEY" "$(remote_doc "${NS}/wrongkind" 1.0.0)"
if why=$(mcp_check_plain_404); then
  pass
else
  fail "publish to a non-mcp repository key: ${why}"
fi

# ---------------------------------------------------------------------------
# Private repository
# ---------------------------------------------------------------------------

PRIV_NAME="${NS}/private"
begin_test "Admin publishes into the private repository"
mcp_publish "$PRIV_KEY" "$(remote_doc "$PRIV_NAME" 1.0.0)"
expect_status 200 "private repository publish"

PRIV_ENC=$(mcp_encode_name "$PRIV_NAME")
PRIV_TAILS=("servers" "servers?search=com.authz" "servers/${PRIV_ENC}/versions" "servers/${PRIV_ENC}/versions/1.0.0" "servers/${PRIV_ENC}/versions/latest")

for tail in "${PRIV_TAILS[@]}"; do
  begin_test "Private repository, anonymous GET ${tail}: 401 with the challenge"
  mcp_get "$PRIV_KEY" "$tail" anon
  if why=$(mcp_check_problem 401 mcp_unauthorized); then
    if [ -n "$(mcp_header www-authenticate)" ]; then
      pass
    else
      fail "anonymous private read 401 has no WWW-Authenticate (docs: the same challenge every format route gives)"
    fi
  else
    fail "anonymous private read of ${tail}: ${why}"
  fi
done

# What a no-grant user gets for a private repository: pin it against the
# answer for a repository key that does not exist at all.
mcp_get "sec-mcpauthz-absent-${RUN_ID}" "servers" "$TOK_NONE"
ABSENT_STATUS="$MCP_STATUS"
ABSENT_BODY=$(cat "$MCP_BODY")
for tail in "${PRIV_TAILS[@]}"; do
  begin_test "Private repository, no-grant user GET ${tail}: plain 404 (existence hidden)"
  mcp_get "$PRIV_KEY" "$tail" "$TOK_NONE"
  if ! why=$(mcp_check_plain_404); then
    fail "no-grant read of a private repository (${tail}): ${why}"
  elif [ "$ABSENT_STATUS" != "404" ] || [ "$(cat "$MCP_BODY")" != "$ABSENT_BODY" ]; then
    fail "no-grant private read differs from a missing repository key (missing: ${ABSENT_STATUS} ${ABSENT_BODY})"
  else
    pass
  fi
done

begin_test "Control: a read grant on the private repository reads it (200, server listed)"
mcp_get "$PRIV_KEY" "servers/${PRIV_ENC}/versions/1.0.0" "$TOK_READ"
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.name')" = "$PRIV_NAME" ]; then
  pass
else
  fail "read-grant read of the private repository: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

end_suite
