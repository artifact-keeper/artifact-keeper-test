#!/usr/bin/env bash
# =============================================================================
# tiers/auth-db-outage/oracle.sh — a database outage during a credential check
#                                  answers a retryable 503, not a 401
#                                  (artifact-keeper#4750 / #4751)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# THE BUG. When PostgreSQL could not answer while a presented credential was
# being checked, the backend said 401 ("your credential is wrong") instead of
# 503 ("try again"). Only a pool-acquire timeout was mapped to 503 (#2125).
# Clients abort on 401 and retry on 503, so a DB restart failed CI outright.
#
# THE PRIMITIVE. A real outage: this oracle stops its OWN slot's Postgres
# (`docker stop "$DB_CONTAINER"` = ak-dtf<slot>-db; every slot is a separate
# compose project, so nothing else is touched), probes, and starts it again.
# An EXIT trap restarts the container if the oracle dies mid-outage.
#
# Gates (see the manifest for the full prose):
#   (CONTROL) before / during / after the outage, true on BOTH images.
#   (FIX)     each presented credential gets 503 during the outage, never 401
#             and never 2xx. RED on 1.11.1 (401).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"

USR="dbout-user-${SLOT}-${SUF}"
USR_PASS="Dbout_${SUF}_Aa1!"
REPO="dbout-maven-${SLOT}-${SUF}"
COORD="com/example/dbout/1.0.0/dbout-1.0.0.txt"
BYTES="auth-db-outage-${SUF}"

# Bound every outage wait. The backend's pool acquire timeout is 5s by default
# (DATABASE_ACQUIRE_TIMEOUT_SECS), so a probe answers within ~5-10s.
NOTREADY_TIMEOUT=60
READY_TIMEOUT=120

WORK="$(mktemp -d -t dtf-dbout-XXXXXX)"
DB_STOPPED=0
cleanup() {
  # Never leave the slot's database stopped: run.sh teardown and --keep both
  # expect a whole stack.
  if [ "$DB_STOPPED" = "1" ]; then
    docker start "$DB_CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- curl helpers -----------------------------------------------------------
b64_basic() { printf '%s:%s' "$1" "$2" | base64 | tr -d '\n'; }

# req METHOD URL [CURL ARGS...] -> prints the status; the body lands in
# $WORK/body and the response headers in $WORK/hdr for the caller to inspect.
req() {
  local m="$1" url="$2"; shift 2
  : > "${WORK}/body"; : > "${WORK}/hdr"
  # shellcheck disable=SC2086
  curl -s $CURL_TIMEOUT -X "$m" -D "${WORK}/hdr" -o "${WORK}/body" -w '%{http_code}' "$@" "$url" 2>/dev/null || echo 000
}
body() { head -c 300 "${WORK}/body" 2>/dev/null; }
retry_after() { grep -i '^retry-after:' "${WORK}/hdr" 2>/dev/null | head -1 | cut -d: -f2 | tr -d '[:space:]'; }
evidence() { printf 'HTTP %s  Retry-After=%s\nbody: %s\n' "$1" "$(retry_after)" "$(body)"; }

readyz_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 "${BASE_URL}/readyz" 2>/dev/null || echo 000; }
readyz_not_ready() { [ "$(readyz_code)" = "503" ]; }
readyz_ready() { [ "$(readyz_code)" = "200" ]; }

login_code() { # USER PASS
  req POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')"
}

# expect_503 LABEL CODE [require-retry-after] [require-oci-unavailable]
# The FIX assertion: 503, and specifically NOT the 1.11.1 401.
expect_503() {
  local label="$1" code="$2" want_ra="${3:-}" want_oci="${4:-}"
  local ev; ev="$(evidence "$code")"
  if [ "$code" != "503" ]; then
    fail "${label}: HTTP ${code}, expected 503 (1.11.1 answered 401: an outage reported as a bad credential)" "$ev"
    return
  fi
  if [ -n "$want_ra" ] && [ "$(retry_after)" != "1" ]; then
    fail "${label}: 503 without Retry-After: 1" "$ev"
    return
  fi
  if [ -n "$want_oci" ] && [ "$(jq -r '.errors[0].code // empty' "${WORK}/body" 2>/dev/null)" != "UNAVAILABLE" ]; then
    fail "${label}: 503 without the OCI error code UNAVAILABLE" "$ev"
    return
  fi
  pass
}

begin_suite "auth-db-outage"

# =============================================================================
# SETUP (infra_fail on any failure: nothing about the candidate is learned yet)
# =============================================================================
begin_test "setup: admin login, user, API token, private maven repo + artifact"
auth_admin
USER_ID="$(create_test_user_with_retry "$USR" "$USR_PASS" "${USR}@dtf.invalid")" || USER_ID=""
if [ -z "$USER_ID" ]; then infra_fail "could not create user ${USR}"; end_suite; fi
USER_JWT="$(login_as "$USR" "$USR_PASS")" || USER_JWT=""
if [ -z "$USER_JWT" ]; then infra_fail "could not log in as ${USR}"; end_suite; fi
# shellcheck disable=SC2086  # CURL_TIMEOUT is a flag list by design
TOKEN_RESP="$(curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/tokens" \
  -H "Authorization: Bearer ${USER_JWT}" -H 'Content-Type: application/json' \
  -d '{"name":"auth-db-outage","scopes":["read:artifacts"]}' 2>/dev/null || true)"
API_TOKEN="$(echo "$TOKEN_RESP" | jq -r '.token // empty' 2>/dev/null || true)"
if [ -z "$API_TOKEN" ]; then infra_fail "POST /api/v1/auth/tokens returned no token" "${TOKEN_RESP:0:300}"; end_suite; fi
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null 2>&1; then
  infra_fail "could not create private maven repo ${REPO}"; end_suite
fi
PUT_CODE="$(req PUT "${BASE_URL}/maven/${REPO}/${COORD}" -H "Authorization: Basic $(b64_basic "$ADMIN_USER" "$ADMIN_PASS")" --data-binary "$BYTES")"
case "$PUT_CODE" in 200|201) ;; *) infra_fail "admin Basic PUT of the fixture artifact returned ${PUT_CODE}" "$(body)"; end_suite ;; esac
# Read access for the user on the private repo, so the user's Basic GET is a
# real authenticated read (the same grant ci-token-basic uses).
GRANT="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='${USR}' AND r.name='developer' AND repo.key='${REPO}'
  ON CONFLICT DO NOTHING RETURNING 1;" 2>&1 || true)"
if [ "$(echo "$GRANT" | head -1)" != "1" ]; then infra_fail "could not grant ${USR} developer on ${REPO}" "$GRANT"; end_suite; fi
pass

BEARER_JWT="Authorization: Bearer ${USER_JWT}"
BEARER_API="Authorization: Bearer ${API_TOKEN}"
BASIC_PASS="Authorization: Basic $(b64_basic "$USR" "$USR_PASS")"
BASIC_JWT="Authorization: Basic $(b64_basic "$USR" "$USER_JWT")"
BASIC_WRONG="Authorization: Basic $(b64_basic "$USR" "not-the-password-${SUF}")"
BASIC_ADMIN="Authorization: Basic $(b64_basic "$ADMIN_USER" "$ADMIN_PASS")"
ART_URL="${BASE_URL}/maven/${REPO}/${COORD}"

me_is_user() { # HEADER -> 0 when /api/v1/auth/me answers 200 for $USR
  local c; c="$(req GET "${BASE_URL}/api/v1/auth/me" -H "$1")"
  [ "$c" = "200" ] && [ "$(jq -r '.username // empty' "${WORK}/body" 2>/dev/null)" = "$USR" ]
}
art_ok() { # HEADER -> 0 when the private artifact reads back byte-identical
  local c; c="$(req GET "$ART_URL" -H "$1")"
  [ "$c" = "200" ] && [ "$(cat "${WORK}/body")" = "$BYTES" ]
}

# =============================================================================
# BEFORE THE OUTAGE (CONTROL, both images)
# =============================================================================
begin_test "CONTROL before: /readyz is ready"
C="$(req GET "${BASE_URL}/readyz")"
if [ "$C" = "200" ]; then pass; else fail "/readyz returned ${C} before the outage" "$(body)"; fi

begin_test "CONTROL before: Bearer JWT on /api/v1/auth/me -> 200 as the user"
if me_is_user "$BEARER_JWT"; then pass; else fail "Bearer JWT /me did not answer 200 for ${USR}" "$(body)"; fi

begin_test "CONTROL before: Bearer API token on /api/v1/auth/me -> 200 as the user"
if me_is_user "$BEARER_API"; then pass; else fail "Bearer API token /me did not answer 200 for ${USR}" "$(body)"; fi

begin_test "CONTROL before: Basic user:password GET on the private /maven artifact -> 200 + bytes"
if art_ok "$BASIC_PASS"; then pass; else fail "Basic password GET did not read the artifact back" "$(body)"; fi

begin_test "CONTROL before: Basic user:<JWT> GET on the private /maven artifact -> 200 + bytes"
if art_ok "$BASIC_JWT"; then pass; else fail "JWT-as-Basic-password GET did not read the artifact back" "$(body)"; fi

begin_test "CONTROL before: wrong Basic password on /maven -> 401"
C="$(req GET "$ART_URL" -H "$BASIC_WRONG")"
if [ "$C" = "401" ]; then pass; else fail "wrong Basic password returned ${C}, expected 401" "$(evidence "$C")"; fi

begin_test "CONTROL before: /v2/ with Basic -> 200"
C="$(req GET "${BASE_URL}/v2/" -H "$BASIC_ADMIN")"
if [ "$C" = "200" ]; then pass; else fail "/v2/ Basic returned ${C}" "$(body)"; fi

# =============================================================================
# THE OUTAGE: stop this slot's own Postgres
# =============================================================================
begin_test "CONTROL outage: stop ${DB_CONTAINER}; /readyz goes not-ready (503, database unhealthy)"
if ! docker stop -t 10 "$DB_CONTAINER" >/dev/null 2>&1; then
  infra_fail "docker stop ${DB_CONTAINER} failed"; end_suite
fi
DB_STOPPED=1
OUTAGE_T0="$(date +%s)"
if wait_until "/readyz reports not-ready" "$NOTREADY_TIMEOUT" readyz_not_ready; then
  C="$(req GET "${BASE_URL}/readyz")"
  if [ "$C" = "503" ] && [ "$(jq -r '.checks.database.status // empty' "${WORK}/body" 2>/dev/null)" = "unhealthy" ]; then
    pass
  else
    fail "/readyz answered ${C} without database=unhealthy" "$(body)"
  fi
else
  fail "/readyz never went not-ready within ${NOTREADY_TIMEOUT}s of stopping the database" "$(curl -s --max-time 15 "${BASE_URL}/readyz" | head -c 300)"
fi

begin_test "FIX outage: Bearer JWT on /api/v1/auth/me -> 503 + Retry-After: 1 (not 401)"
C="$(req GET "${BASE_URL}/api/v1/auth/me" -H "$BEARER_JWT")"
expect_503 "Bearer JWT /api/v1/auth/me" "$C" ra

begin_test "FIX outage: Basic user:password GET on /maven -> 503 + Retry-After: 1 (not 401)"
C="$(req GET "$ART_URL" -H "$BASIC_PASS")"
expect_503 "Basic password /maven" "$C" ra

begin_test "FIX outage: Basic user:<JWT> GET on /maven -> 503 + Retry-After: 1 (not 401)"
C="$(req GET "$ART_URL" -H "$BASIC_JWT")"
expect_503 "JWT-as-Basic-password /maven" "$C" ra

begin_test "FIX outage: WRONG Basic password on /maven -> 503, never 2xx (the check cannot run: cannot decide)"
C="$(req GET "$ART_URL" -H "$BASIC_WRONG")"
expect_503 "wrong Basic password /maven" "$C" ra

begin_test "FIX outage: /v2/ with Bearer JWT -> 503 UNAVAILABLE + Retry-After: 1 (not 401)"
C="$(req GET "${BASE_URL}/v2/" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
expect_503 "/v2/ Bearer JWT" "$C" ra oci

begin_test "FIX outage: /v2/ with Basic -> 503 UNAVAILABLE + Retry-After: 1 (not 401)"
C="$(req GET "${BASE_URL}/v2/" -H "$BASIC_ADMIN")"
expect_503 "/v2/ Basic" "$C" ra oci

begin_test "FIX outage: /v2/token with Basic -> 503 UNAVAILABLE + Retry-After: 1 (not 401)"
C="$(req GET "${BASE_URL}/v2/token?service=artifact-keeper&scope=repository:${REPO}/img:pull" -H "$BASIC_ADMIN")"
expect_503 "/v2/token Basic" "$C" ra oci

begin_test "CONTROL outage: a credential rejected before the DB is consulted (too-short X-API-Key) is still 401"
C="$(req GET "$ART_URL" -H "X-API-Key: short")"
if [ "$C" = "401" ]; then pass; else fail "too-short X-API-Key during the outage returned ${C}, expected 401" "$(evidence "$C")"; fi

begin_test "CONTROL outage: POST /api/v1/auth/login with the CORRECT password is never 401 and never mints a token"
C="$(login_code "$USR" "$USR_PASS")"
case "$C" in
  401) fail "login with the correct password answered 401 during a DB outage" "$(evidence "$C")" ;;
  2*)  fail "login answered ${C} with the database stopped" "$(evidence "$C")" ;;
  *)   echo "  login during the outage: $(evidence "$C" | head -1)"; pass ;;
esac

OUTAGE_SECS=$(( $(date +%s) - OUTAGE_T0 ))
echo "  outage window so far: ${OUTAGE_SECS}s"

# =============================================================================
# RECOVERY (CONTROL, both images)
# =============================================================================
begin_test "CONTROL recovery: start ${DB_CONTAINER}; /readyz returns to ready (the pool reconnects)"
if ! docker start "$DB_CONTAINER" >/dev/null 2>&1; then
  infra_fail "docker start ${DB_CONTAINER} failed"; end_suite
fi
DB_STOPPED=0
if wait_until "/readyz reports ready again" "$READY_TIMEOUT" readyz_ready; then
  pass
else
  fail_fatal "/readyz did not return to ready within ${READY_TIMEOUT}s of restarting the database" "$(curl -s --max-time 15 "${BASE_URL}/readyz" | head -c 300)"
fi

begin_test "CONTROL recovery: login with the correct password -> 200 + token"
C="$(login_code "$USR" "$USR_PASS")"
if [ "$C" = "200" ] && [ -n "$(jq -r '.access_token // .token // empty' "${WORK}/body" 2>/dev/null)" ]; then
  pass
else
  fail "login after recovery returned ${C}" "$(body)"
fi

begin_test "CONTROL recovery: the SAME pre-outage JWT is still valid on /api/v1/auth/me"
if me_is_user "$BEARER_JWT"; then pass; else fail "pre-outage JWT rejected after recovery" "$(body)"; fi

begin_test "CONTROL recovery: the SAME pre-outage API token is still valid on /api/v1/auth/me"
if me_is_user "$BEARER_API"; then pass; else fail "pre-outage API token rejected after recovery" "$(body)"; fi

begin_test "CONTROL recovery: Basic user:password GET on /maven -> 200 + bytes"
if art_ok "$BASIC_PASS"; then pass; else fail "Basic password GET failed after recovery" "$(body)"; fi

begin_test "CONTROL recovery: wrong Basic password is 401 again (the 503 was outage-only)"
C="$(req GET "$ART_URL" -H "$BASIC_WRONG")"
if [ "$C" = "401" ]; then pass; else fail "wrong Basic password after recovery returned ${C}, expected 401" "$(evidence "$C")"; fi

end_suite
