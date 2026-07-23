#!/usr/bin/env bash
# =============================================================================
# tiers/vvc3-scoped-admin/oracle.sh — token-inherits-owner-admin bypass (GHSA-vvc3)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP flow against the live backend.
#
# The defect (GHSA-vvc3): an API token authenticates AS its owner and inherits
# the owner's `is_admin` flag with NO regard to the token's own scopes. The admin
# gate (`admin_middleware`) checks only `is_admin`. So a READ-scoped PAT minted by
# an admin passes every admin route — a full privilege escalation hiding behind a
# "read-only" token. The fix holds an API token to its minted scope ceiling:
# admin routes demand an admin-class scope (`admin`/`*`); interactive/CI JWTs
# (scopes = None) stay unrestricted.
#
# Discriminating gates, ALL must hold (RELEASE_GATE=1):
#   (A) BOUNDARY  read-scoped admin token on POST /api/v1/users + GET /api/v1/users
#                 -> 403, and no user row is created. Baseline: 2xx + row (RED).
#   (B) POSITIVE  admin-scoped (`*`) token -> 2xx; interactive admin JWT -> 2xx.
#   (C) NEGATIVE  plain non-admin JWT -> 403 (the admin gate is intact).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
NA_USER="vvc3-na-${DTF_SLOT:-x}-${SUF}"
NA_PASS="Vvc3Na_${SUF}_Aa1!"
# Distinct target usernames per admission attempt so each probe is unambiguous
# and a DB row is attributable to exactly one caller/route.
U_BOUND_POST="vvc3-x-ropost-${DTF_SLOT:-x}-${SUF}"   # read-token POST (must NOT exist on fix)
U_POS_SCOPED="vvc3-y-scoped-${DTF_SLOT:-x}-${SUF}"   # admin-scoped token POST (must exist)
U_POS_JWT="vvc3-y-jwt-${DTF_SLOT:-x}-${SUF}"         # admin JWT POST (must exist)
U_NEG_NA="vvc3-z-na-${DTF_SLOT:-x}-${SUF}"           # non-admin POST (must NOT exist)

# --- curl helpers (always return 0; echo the numeric status) ----------------
req_code() { # METHOD URL BEARER [JSON_BODY]
  local m="$1" url="$2" tok="$3" body="${4:-}"
  if [ -n "$body" ]; then
    curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$m" \
      -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' \
      -d "$body" "$url" 2>/dev/null || echo 000
  else
    curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$m" \
      -H "Authorization: Bearer ${tok}" "$url" 2>/dev/null || echo 000
  fi
}
mint_token() { # BEARER SCOPES_JSON_ARRAY  -> echoes the raw token or empty
  local tok="$1" scopes="$2"
  curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/tokens" \
    -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' \
    -d "{\"name\":\"vvc3-${scopes//[^a-z]/}-${SUF}\",\"scopes\":${scopes}}" 2>/dev/null \
    | jq -r '.token // empty' 2>/dev/null || true
}
user_rows() { # USERNAME -> count of matching user rows (DB truth)
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) FROM users WHERE username='${1}';" 2>/dev/null | tr -d '[:space:]' || echo "?"
}
newuser_body() { echo "{\"username\":\"${1}\",\"password\":\"Vvc3Tgt_${SUF}_Aa1!\",\"email\":\"${1}@t.test\"}"; }

begin_suite "vvc3-scoped-admin-authz"

# --- setup: admin session, read-scoped + admin-scoped tokens, a non-admin ----
auth_admin   # sets ADMIN_TOKEN from ADMIN_USER/ADMIN_PASS

READ_TOKEN="$(mint_token "$ADMIN_TOKEN" '["read:artifacts"]')"
ADMIN_SCOPED_TOKEN="$(mint_token "$ADMIN_TOKEN" '["*"]')"
if [ -z "$READ_TOKEN" ] || [ -z "$ADMIN_SCOPED_TOKEN" ]; then
  begin_test "setup: mint read-scoped + admin-scoped API tokens owned by the admin"
  fail "could not mint owner API tokens (read='${READ_TOKEN:0:6}…' adminScoped='${ADMIN_SCOPED_TOKEN:0:6}…')"
  end_suite
fi

NA_ID="$(create_test_user_with_retry "$NA_USER" "$NA_PASS" "${NA_USER}@t.test")" || true
NA_TOKEN=""
[ -n "$NA_ID" ] && [ "$NA_ID" != "null" ] && NA_TOKEN="$(login_as "$NA_USER" "$NA_PASS")" || true
if [ -z "$NA_TOKEN" ]; then
  begin_test "setup: create + login a plain non-admin user"
  fail "could not provision the non-admin control principal ${NA_USER}"
  end_suite
fi

# ---------------------------------------------------------------------------
# (A) BOUNDARY — the load-bearing security gate. A READ-scoped token owned by
#     an admin must NOT be honoured as admin. Proven on a mutating route
#     (POST /api/v1/users, with a DB no-write assertion) AND a read admin route
#     (GET /api/v1/users) so it cannot pass on a single-route quirk.
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: read-scoped admin token -> POST /api/v1/users -> 403 (GHSA-vvc3: token must not inherit owner admin)"
RC="$(req_code POST "${BASE_URL}/api/v1/users" "$READ_TOKEN" "$(newuser_body "$U_BOUND_POST")")"
if [ "$RC" = "403" ]; then
  pass
else
  fail "PRIVILEGE-ESCALATION BYPASS: read-scoped (read:artifacts) admin-owned token created a user via POST /api/v1/users -> ${RC}, expected 403. The token inherited its owner's is_admin without carrying an admin scope (GHSA-vvc3)." \
       "status=${RC} route=POST /api/v1/users scopes=[read:artifacts]"
fi

begin_test "BOUNDARY(DB): the read-scoped token's POST /api/v1/users did NOT create the user row"
ROWS="$(user_rows "$U_BOUND_POST")"
if [ "$ROWS" = "0" ]; then
  pass
else
  fail "read-scoped admin token PERSISTED a user (${U_BOUND_POST} rows=${ROWS}); the admin-only mutation went through (GHSA-vvc3 bypass, RED)" \
       "username=${U_BOUND_POST} matching_rows=${ROWS} expected=0"
fi

begin_test "BOUNDARY: read-scoped admin token -> GET /api/v1/users (admin list) -> 403"
RC="$(req_code GET "${BASE_URL}/api/v1/users" "$READ_TOKEN")"
if [ "$RC" = "403" ]; then
  pass
else
  fail "read-scoped admin-owned token reached the admin user-list GET /api/v1/users -> ${RC}, expected 403 (GHSA-vvc3 bypass on a second admin route)" \
       "status=${RC} route=GET /api/v1/users scopes=[read:artifacts]"
fi

# ---------------------------------------------------------------------------
# (B) POSITIVE — the fix is scope-aware, not an "API tokens are never admin"
#     hammer. An admin-SCOPED token and an interactive admin JWT both still
#     work, proving the pipeline grants real admin.
# ---------------------------------------------------------------------------
begin_test "POSITIVE: admin-scoped (*) token owned by the admin -> POST /api/v1/users -> 2xx (admin automation still works)"
RC="$(req_code POST "${BASE_URL}/api/v1/users" "$ADMIN_SCOPED_TOKEN" "$(newuser_body "$U_POS_SCOPED")")"
if [ "$RC" = "200" ] || [ "$RC" = "201" ]; then
  pass
else
  fail "admin-scoped (*) token was refused on POST /api/v1/users -> ${RC}, expected 2xx; the fix must not break legitimate admin automation" \
       "status=${RC} scopes=[*]"
fi

begin_test "POSITIVE: interactive admin Bearer JWT -> POST /api/v1/users -> 2xx"
RC="$(req_code POST "${BASE_URL}/api/v1/users" "$ADMIN_TOKEN" "$(newuser_body "$U_POS_JWT")")"
if [ "$RC" = "200" ] || [ "$RC" = "201" ]; then
  pass
else
  fail "interactive admin JWT was refused on POST /api/v1/users -> ${RC}, expected 2xx (the admin gate must still admit real admins)" \
       "status=${RC} principal=admin-jwt"
fi

# ---------------------------------------------------------------------------
# (C) NEGATIVE — the admin gate itself is intact: a plain non-admin is 403.
# ---------------------------------------------------------------------------
begin_test "NEGATIVE: plain non-admin JWT -> POST /api/v1/users -> 403 (admin gate intact)"
RC="$(req_code POST "${BASE_URL}/api/v1/users" "$NA_TOKEN" "$(newuser_body "$U_NEG_NA")")"
if [ "$RC" = "403" ]; then
  pass
else
  fail "non-admin was not refused on POST /api/v1/users -> ${RC}, expected 403 (the admin gate is broken independent of GHSA-vvc3)" \
       "status=${RC} principal=non-admin-jwt"
fi

end_suite
