#!/usr/bin/env bash
# test-mint-scope-validation.sh - Token mint-path scope validation (#2996)
#
# Verifies the three mint-path controls added by #2996 on top of the #2993
# broad-covers-specific parent rule in scopes_grant_access:
#
#   1. VOCABULARY BACKSTOP (mint primitive): scopes outside ALLOWED_SCOPES are
#      rejected with 400 at every mint endpoint. Bare action parents
#      (`delete` / `write` / `read`) are NOT vocabulary — this matters because
#      a held bare parent covers every colon-form child under the parent rule,
#      so a persisted bare `delete` would satisfy the admin-only
#      `delete:artifacts`. Pre-fix: bare-scope mints returned 200 and
#      persisted (RED); post-fix: 400 (GREEN).
#   2. DELEGATION CEILING: a non-admin presenting a scoped API token cannot
#      mint a token with scopes beyond its own — e.g. a `read:artifacts`
#      token minting `write:artifacts` (read->write laundering). Pre-fix: 200
#      (RED); post-fix: 403 (GREEN). Interactive sessions are unaffected.
#      The ceiling must be UNIFORM across all four mint handlers, including
#      the repo-scoped path, whose older repo-ACTION check (#2603 G3) ignores
#      the read family and so let a write:repositories-only token mint a
#      read:users token it never held.
#   3. PROFILE DEFAULT: POST /profile/access-tokens with no `scopes` persists
#      `read:artifacts` (canonical) instead of the legacy non-vocabulary bare
#      `read`.
#
# Unchanged behavior pinned: admin-only scopes (`admin`, `*`) still 403 for
# non-admins; the routine CI scope `write:artifacts` still mints on an
# interactive session.
#
# Backend reference:
#   - AuthService::generate_api_token vocabulary backstop (auth_service.rs)
#   - AuthExtension::enforce_mint_ceiling (api/middleware/auth.rs)
#   - POST /api/v1/auth/tokens, POST /api/v1/profile/access-tokens
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-mint-scope-validation"
auth_admin
setup_workdir

NONADMIN_USER="e2e-mintval-${RUN_ID}"
NONADMIN_PASS="MintVal_Pass123!"
NONADMIN_EMAIL="e2e-mintval-${RUN_ID}@test.local"
USER_ID=""
USER_TOKEN=""
READ_API_TOKEN=""
READ_API_TOKEN_ID=""

mint_status() { # <bearer> <json-body> -> echoes HTTP status
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer $1" \
    -H "Content-Type: application/json" \
    -d "$2" \
    "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null || echo 000
}

# -------------------------------------------------------------------------
# Setup: non-admin user + interactive session
# -------------------------------------------------------------------------

begin_test "Create non-admin test user"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${NONADMIN_USER}\",\"password\":\"${NONADMIN_PASS}\",\"email\":\"${NONADMIN_EMAIL}\",\"display_name\":\"Mint Val\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.user.id // .id // empty')
  if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID in response: ${resp:0:200}"
  fi
else
  fail "could not create non-admin user"
fi

begin_test "Login as non-admin user (interactive session)"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user ID from creation"
else
  USER_TOKEN=$(login_as "${NONADMIN_USER}" "${NONADMIN_PASS}") || true
  if [ -n "$USER_TOKEN" ]; then
    pass
  else
    fail "non-admin login returned no token"
  fi
fi

# -------------------------------------------------------------------------
# Control 1: vocabulary backstop — bare parents / unknown scopes 400
# -------------------------------------------------------------------------

for bad_scope in "delete" "write" "read" "hack:system"; do
  begin_test "Mint with non-vocabulary scope '${bad_scope}' is rejected (400)"
  if [ -z "${USER_TOKEN:-}" ]; then
    skip "no user JWT"
  else
    status=$(mint_status "$USER_TOKEN" "{\"name\":\"e2e-bad-${bad_scope//:/-}\",\"scopes\":[\"${bad_scope}\"]}")
    if [ "$status" = "400" ]; then
      pass
    else
      fail "expected 400 for scope '${bad_scope}', got HTTP ${status} (pre-#2996 this persisted a token whose bare parent covers admin-only colon children under the #2993 parent rule)"
    fi
  fi
done

# -------------------------------------------------------------------------
# Unchanged: admin-only scopes still 403; CI scope still mints
# -------------------------------------------------------------------------

for admin_scope in "admin" "*"; do
  begin_test "Non-admin mint with admin-only scope '${admin_scope}' is 403"
  if [ -z "${USER_TOKEN:-}" ]; then
    skip "no user JWT"
  else
    status=$(mint_status "$USER_TOKEN" "{\"name\":\"e2e-adminonly\",\"scopes\":[\"${admin_scope}\"]}")
    if [ "$status" = "403" ]; then
      pass
    else
      fail "expected 403 for admin-only scope '${admin_scope}', got HTTP ${status}"
    fi
  fi
done

begin_test "Interactive non-admin still mints write:artifacts (200)"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user JWT"
else
  status=$(mint_status "$USER_TOKEN" '{"name":"e2e-ci-scope","scopes":["write:artifacts"]}')
  if [ "$status" = "200" ]; then
    pass
  else
    fail "expected 200 for interactive write:artifacts mint, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Control 2: delegation ceiling — read:artifacts token cannot mint
# write:artifacts (the read->write laundering closed by #2996)
# -------------------------------------------------------------------------

begin_test "Interactive non-admin mints a read:artifacts API token"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user JWT"
else
  resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"name":"e2e-mintval-read","scopes":["read:artifacts"]}' \
    "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null) || true
  READ_API_TOKEN=$(echo "$resp" | jq -r '.token // empty')
  READ_API_TOKEN_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$READ_API_TOKEN" ] && [ "$READ_API_TOKEN" != "null" ]; then
    pass
  else
    fail "read:artifacts token creation failed: ${resp:0:200}"
  fi
fi

begin_test "read:artifacts token minting write:artifacts is 403 (ceiling)"
if [ -z "${READ_API_TOKEN:-}" ] || [ "$READ_API_TOKEN" = "null" ]; then
  skip "no read:artifacts API token"
else
  status=$(mint_status "$READ_API_TOKEN" '{"name":"e2e-launder","scopes":["write:artifacts"]}')
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 (delegation ceiling), got HTTP ${status} — a read-scoped credential minted beyond itself"
  fi
fi

begin_test "read:artifacts token re-minting read:artifacts is 200 (within ceiling)"
if [ -z "${READ_API_TOKEN:-}" ] || [ "$READ_API_TOKEN" = "null" ]; then
  skip "no read:artifacts API token"
else
  status=$(mint_status "$READ_API_TOKEN" '{"name":"e2e-within-ceiling","scopes":["read:artifacts"]}')
  if [ "$status" = "200" ]; then
    pass
  else
    fail "expected 200 for re-mint within ceiling, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Control 2b: the ceiling is UNIFORM across all four mint handlers.
#
# The repo-scoped mint path (POST /repositories/{key}/tokens) has its own
# older repo-ACTION delegation check (#2603 G3), but that check maps the read
# family to "no repository mutation required" and so never consults the
# presenting credential's own scope set. Without the ceiling here, a
# write:repositories-only token could mint a read:users token it never held —
# while the identical request was already 403 on /auth and /profile.
# -------------------------------------------------------------------------

REPO_KEY="e2e-mintval-repo-${RUN_ID}"
WR_TOKEN=""

begin_test "Create repo for the repo-scoped mint path"
if resp=$(api_post "/api/v1/repositories" \
    "{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" 2>/dev/null); then
  pass
else
  fail "could not create repo ${REPO_KEY}"
fi

begin_test "Interactive non-admin mints a write:repositories-only API token"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user JWT"
else
  resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"name":"e2e-mintval-wr","scopes":["write:repositories"]}' \
    "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null) || true
  WR_TOKEN=$(echo "$resp" | jq -r '.token // empty')
  if [ -n "$WR_TOKEN" ] && [ "$WR_TOKEN" != "null" ]; then
    pass
  else
    fail "write:repositories token creation failed: ${resp:0:200}"
  fi
fi

repo_mint_status() { # <bearer> <scopes-json-array> -> echoes HTTP status
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer $1" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"e2e-repo-mint-$RANDOM\",\"scopes\":$2,\"expires_in_days\":30}" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/tokens" 2>/dev/null || echo 000
}

for unheld in '["read:users"]' '["read:artifacts"]' '["read:repositories"]'; do
  begin_test "Repo-path mint of unheld scope ${unheld} is 403 (uniform ceiling)"
  if [ -z "${WR_TOKEN:-}" ] || [ "$WR_TOKEN" = "null" ]; then
    skip "no write:repositories token"
  else
    status=$(repo_mint_status "$WR_TOKEN" "$unheld")
    if [ "$status" = "403" ]; then
      pass
    else
      fail "expected 403 on the repo mint path for unheld scope ${unheld}, got HTTP ${status} — the repo handler skipped the scope ceiling that /auth and /profile enforce"
    fi
  fi
done

begin_test "Repo-path mint WITHIN the presenting token's scopes is 200"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user JWT"
else
  held=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"name":"e2e-mintval-wr-read","scopes":["write:repositories","read:artifacts"]}' \
    "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null | jq -r '.token // empty') || true
  if [ -z "$held" ] || [ "$held" = "null" ]; then
    fail "could not mint the write:repositories+read:artifacts token"
  else
    status=$(repo_mint_status "$held" '["read:artifacts"]')
    if [ "$status" = "200" ]; then
      pass
    else
      fail "expected 200 minting a HELD scope via the repo path, got HTTP ${status} (over-restriction)"
    fi
  fi
fi

begin_test "Repo-path mint on an interactive session is 200 (ceiling short-circuits)"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user JWT"
else
  status=$(repo_mint_status "$USER_TOKEN" '["read:artifacts"]')
  if [ "$status" = "200" ]; then
    pass
  else
    fail "expected 200 for interactive repo-token mint, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Control 3: profile default — omitted scopes persist read:artifacts
# -------------------------------------------------------------------------

begin_test "Profile mint with no scopes returns 200 and persists read:artifacts"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user JWT"
else
  resp=$(curl -s $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"name":"e2e-default-scopes"}' \
    "${BASE_URL}/api/v1/profile/access-tokens" 2>/dev/null) || true
  tok_id=$(echo "$resp" | jq -r '.id // empty')
  if [ -z "$tok_id" ] || [ "$tok_id" = "null" ]; then
    fail "no-scopes profile mint did not return a token: ${resp:0:200}"
  else
    persisted=$(curl -sf $CURL_TIMEOUT \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      "${BASE_URL}/api/v1/profile/access-tokens" 2>/dev/null \
      | jq -r --arg id "$tok_id" '.items[] | select(.id == $id) | .scopes | join(",")') || true
    if [ "$persisted" = "read:artifacts" ]; then
      pass
    else
      fail "expected persisted scopes 'read:artifacts', got '${persisted}' (legacy default was non-vocabulary bare 'read')"
    fi
    curl -sf $CURL_TIMEOUT -X DELETE \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      "${BASE_URL}/api/v1/profile/access-tokens/${tok_id}" >/dev/null 2>&1 || true
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

if [ -n "${READ_API_TOKEN_ID:-}" ] && [ "$READ_API_TOKEN_ID" != "null" ] && [ -n "${USER_TOKEN:-}" ]; then
  curl -sf $CURL_TIMEOUT -X DELETE \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/tokens/${READ_API_TOKEN_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${REPO_KEY:-}" ]; then
  api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
fi
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

# EXPECT_FAILURE=1 inverts the suite's exit code so this script can be used
# as a fixture to validate the gate (a "broken" gate is a passing self-test).
enable_expect_failure_trap

end_suite
