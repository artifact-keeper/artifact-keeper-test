#!/usr/bin/env bash
# =============================================================================
# tiers/ci-token-basic/oracle.sh — API-token-as-Basic-password asymmetry (#2786)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP flow against the live backend.
#
# The feature (#2786): a package-manager client that cannot send a Bearer header
# may present an API token as the HTTP Basic *password* (any username) on FORMAT
# endpoints. The request authenticates AS THE TOKEN OWNER. The security boundary:
# that same Basic-with-token fallback is refused on the JSON management API
# `/api/v1/*` (token accepted only as `Bearer`). See the manifest header.
#
# Three discriminating gates, ALL must hold:
#   (A) POSITIVE  token-as-Basic (bogus username) PUT/GET on a PRIVATE maven repo
#                 -> 2xx + DB-attributed to the token owner (uploaded_by=owner).
#   (B) CONTROL   token as Bearer on /api/v1/auth/me -> 200 (owner).
#   (C) BOUNDARY  token as Basic password on /api/v1/* -> 401 (garbage Basic 401
#                 too; Bearer still 200). This is the load-bearing security gate.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="ci-tok-mvn-${DTF_SLOT:-x}-${SUF}"
OWNER="ci-tok-owner-${DTF_SLOT:-x}-${SUF}"
OWNER_PASS="CiTok_${SUF}_Aa1!"
BOGUS_BASIC_USER="netrc-ignored-${SUF}"
COORD="com/ci/tok/1.0-${SUF}/tok-1.0-${SUF}.jar"
BYTES="CI-TOKEN-BASIC-BYTES-${SUF}"

# curl helpers ---------------------------------------------------------------
# basic_code / basic_body: present $1 as the Basic PASSWORD with the bogus
# username (the netrc/Artifactory convention: username is ignored).
b64_basic() { printf '%s:%s' "$1" "$2" | base64 | tr -d '\n'; }
http_code() { # METHOD URL HEADER [BODY]
  local m="$1" url="$2" hdr="$3" body="${4:-}"
  if [ -n "$body" ]; then
    curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$m" -H "$hdr" \
      -H 'Content-Type: application/octet-stream' --data-binary "$body" "$url" 2>/dev/null || echo 000
  else
    curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$m" -H "$hdr" "$url" 2>/dev/null || echo 000
  fi
}
http_body() { curl -s $CURL_TIMEOUT -X "${1}" -H "$3" "$2" 2>/dev/null || true; }

begin_suite "ci-token-basic-auth-asymmetry-2786"

# --- setup: admin, a plain user, an API token owned by that user ------------
auth_admin   # sets ADMIN_TOKEN from ADMIN_USER/ADMIN_PASS

OWNER_ID="$(create_test_user_with_retry "$OWNER" "$OWNER_PASS" "${OWNER}@t.test")" || true
if [ -z "$OWNER_ID" ] || [ "$OWNER_ID" = "null" ]; then
  begin_test "setup: create token-owner user"
  infra_fail "could not create owner user ${OWNER}"
  end_suite
fi

OWNER_TOKEN="$(login_as "$OWNER" "$OWNER_PASS")" || true
if [ -z "$OWNER_TOKEN" ]; then
  begin_test "setup: login token-owner user"
  infra_fail "could not log in as ${OWNER}"
  end_suite
fi

# Mint an API token for the owner (read+write scopes; non-admin-safe).
# Colon-form vocabulary (#2989/#2996): the bare "read"/"write" parents were
# removed from the backend's ALLOWED_SCOPES, so minting them 400s
# VALIDATION_ERROR and this setup would silently die with an empty token.
TOKEN_RESP="$(curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/tokens" \
  -H "Authorization: Bearer ${OWNER_TOKEN}" -H 'Content-Type: application/json' \
  -d '{"name":"ci-token-basic-probe","scopes":["read:artifacts","write:artifacts"]}' 2>/dev/null || true)"
API_TOKEN="$(echo "$TOKEN_RESP" | jq -r '.token // empty' 2>/dev/null || true)"
if [ -z "$API_TOKEN" ]; then
  begin_test "setup: mint owner API token"
  infra_fail "POST /api/v1/auth/tokens did not return a token; the tier never probed a format endpoint" "${TOKEN_RESP:0:300}"
  end_suite
fi

# A PRIVATE maven repo (is_public:false) so BOTH read and write require auth.
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null 2>&1; then
  begin_test "setup: create private maven repo"
  infra_fail "could not create private repo ${REPO}"
  end_suite
fi
# Grant the owner developer(write) on the repo so the token carries write there.
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='${OWNER}' AND r.name='developer' AND repo.key='${REPO}'
  ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true

BASIC_TOKEN_HDR="Authorization: Basic $(b64_basic "$BOGUS_BASIC_USER" "$API_TOKEN")"
BASIC_GARBAGE_HDR="Authorization: Basic $(b64_basic "$BOGUS_BASIC_USER" "not-a-real-token-${SUF}")"
BEARER_HDR="Authorization: Bearer ${API_TOKEN}"

# ---------------------------------------------------------------------------
# (A) POSITIVE — token-as-Basic-password works on a FORMAT endpoint, attributed
#     to the token OWNER (not the ignored Basic username).
# ---------------------------------------------------------------------------
begin_test "POSITIVE: API token as Basic password (bogus username) PUTs to a private /maven endpoint -> 201"
PUT_CODE="$(http_code PUT "${BASE_URL}/maven/${REPO}/${COORD}" "$BASIC_TOKEN_HDR" "$BYTES")"
if [ "$PUT_CODE" = "200" ] || [ "$PUT_CODE" = "201" ]; then
  pass
else
  fail "token-as-Basic PUT to /maven/${REPO} returned ${PUT_CODE}, expected 201 (pre-#2786 this 401s)"
fi

begin_test "POSITIVE: the token-as-Basic upload is attributed to the TOKEN OWNER (DB uploaded_by), not the Basic username"
ATTR="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  SELECT a.uploaded_by FROM artifacts a JOIN repositories r ON r.id=a.repository_id
  WHERE r.key='${REPO}' AND a.path='${COORD}' AND a.is_deleted=false LIMIT 1;" 2>/dev/null | tr -d '[:space:]' || true)"
if [ -z "$ATTR" ]; then
  fail "no artifact row for ${REPO}/${COORD} — upload not persisted"
elif [ "$ATTR" = "$OWNER_ID" ]; then
  pass
else
  fail "artifact attributed to '${ATTR}', expected token owner '${OWNER_ID}' (${OWNER}); the ignored Basic username must not become the actor" \
       "uploaded_by=${ATTR} owner_id=${OWNER_ID}"
fi

begin_test "POSITIVE: token-as-Basic GET reads the private artifact back with matching bytes"
GET_CODE="$(http_code GET "${BASE_URL}/maven/${REPO}/${COORD}" "$BASIC_TOKEN_HDR")"
GOT="$(http_body GET "${BASE_URL}/maven/${REPO}/${COORD}" "$BASIC_TOKEN_HDR")"
if [ "$GET_CODE" = "200" ] && [ "$GOT" = "$BYTES" ]; then
  pass
else
  fail "token-as-Basic GET returned code=${GET_CODE} body='${GOT}', expected 200 + '${BYTES}'"
fi

# ---------------------------------------------------------------------------
# (B) CONTROL — the token IS valid on /api/v1/* the canonical way (Bearer).
# ---------------------------------------------------------------------------
begin_test "CONTROL: the SAME token as 'Bearer' on /api/v1/auth/me -> 200 and reports the owner"
ME_CODE="$(http_code GET "${BASE_URL}/api/v1/auth/me" "$BEARER_HDR")"
ME_USER="$(http_body GET "${BASE_URL}/api/v1/auth/me" "$BEARER_HDR" | jq -r '.username // .user.username // empty' 2>/dev/null || true)"
if [ "$ME_CODE" = "200" ] && [ "$ME_USER" = "$OWNER" ]; then
  pass
else
  fail "Bearer /api/v1/auth/me returned code=${ME_CODE} user='${ME_USER}', expected 200 + '${OWNER}'"
fi

# ---------------------------------------------------------------------------
# (C) BOUNDARY — the Basic-with-token fallback must NOT bleed into /api/v1/*.
#     This is the load-bearing SECURITY gate. Verified across the hard-auth
#     (auth_middleware) AND optional-auth (optional_auth_middleware) /api/v1
#     surfaces so it cannot pass on a single whoami exemption and so it proves
#     the COMPLETE boundary (#2806): the shared resolver refuses token-as-Basic
#     on the management API too, not just the auth_middleware routes. A garbage
#     Basic password 401s (sanity: the route DOES authenticate the Basic creds)
#     while the valid-token Basic password must ALSO 401 (the token is not
#     honoured as a Basic carrier on the management API). The Bearer control
#     accepts 200 OR 403 — both prove the route authenticated the token (403 is
#     authz-denied, still not anonymous); only a token-as-Basic 401 passes the
#     boundary, and a 403 there would itself be a violation (auth succeeded).
# ---------------------------------------------------------------------------
for MEP in "/api/v1/auth/me" "/api/v1/users/me" "/api/v1/repositories"; do
  begin_test "BOUNDARY: API token as Basic password on ${MEP} -> 401 (documented AUTH_ERROR asymmetry)"
  TB_CODE="$(http_code GET "${BASE_URL}${MEP}" "$BASIC_TOKEN_HDR")"
  GB_CODE="$(http_code GET "${BASE_URL}${MEP}" "$BASIC_GARBAGE_HDR")"
  BR_CODE="$(http_code GET "${BASE_URL}${MEP}" "$BEARER_HDR")"
  if [ "$GB_CODE" != "401" ]; then
    fail "sanity failed: garbage Basic password on ${MEP} returned ${GB_CODE}, expected 401 (route must authenticate Basic)" \
         "tokenBasic=${TB_CODE} garbageBasic=${GB_CODE} Bearer=${BR_CODE}"
  elif [ "$BR_CODE" != "200" ] && [ "$BR_CODE" != "403" ]; then
    fail "control failed: Bearer token on ${MEP} returned ${BR_CODE}, expected 200 or 403 (authenticated)" \
         "tokenBasic=${TB_CODE} garbageBasic=${GB_CODE} Bearer=${BR_CODE}"
  elif [ "$TB_CODE" = "401" ]; then
    pass
  else
    fail "SECURITY BOUNDARY VIOLATION: API token as Basic password on ${MEP} returned ${TB_CODE}, expected 401. The #2786 Basic-with-token fallback must be format-only, never on /api/v1/* (OpenAPI documents 401 AUTH_ERROR here)." \
         "tokenBasic=${TB_CODE} garbageBasic=${GB_CODE} Bearer=${BR_CODE} owner=${OWNER}"
  fi
done

end_suite
