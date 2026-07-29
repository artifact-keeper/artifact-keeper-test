#!/usr/bin/env bash
# =============================================================================
# tiers/migration-authz/oracle.sh — migration surface authorization gap (#2603 G2)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the
# assertion + JUnit harness, then drive the real HTTP flow against the backend.
#
# The bug (#2603 G2): the /api/v1/migrations/* nest had authentication
# (auth_middleware) but no admin gate and no target-repo write authz — only
# per-user ownership of the SOURCE connection. Any authenticated non-admin could
# register a source, stage a migration job whose config NAMES ARBITRARY TARGET
# REPOSITORIES, and start it, bulk-writing into repos they cannot write. The fix
# moves the whole nest under `admin_middleware` -> non-admin 403 before handler.
#
# Discriminating gates, ALL must hold on the FIXED image:
#   (BOUNDARY) a NON-admin token on each migration route -> 403. On the
#              vulnerable baseline the request reaches the handler (201/200/404,
#              never 403) = the authz bypass. 403 == GREEN, anything else == RED.
#              The create_migration probe carries a config NAMING a target repo
#              the caller cannot write: the cross-repo-write case.
#   (CONTROL)  admin on the same routes -> NOT 403 (201, authz passes);
#              admin GET /migrations -> 200 (legit operator path intact);
#              anon on a mutating route -> 401.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
USER="mig-user-${DTF_SLOT:-x}-${SUF}"
USER_PASS="Mig_${SUF}_Aa1!"
# The target repository the migration job config NAMES. It need not exist: on
# the vulnerable baseline `create_migration` stores the caller-controlled config
# verbatim, which is exactly the "point a job at an arbitrary repo" gap.
TARGET_REPO="victim-repo-${SUF}"

# Synthetic fallbacks — the fix denies at the nest before the handler body, so
# connection/job existence is irrelevant to the boundary.
SYN_CONN="$(cat /proc/sys/kernel/random/uuid)"
SYN_JOB="$(cat /proc/sys/kernel/random/uuid)"

# --- curl helpers -----------------------------------------------------------
# http_code METHOD URL AUTH_HEADER [JSON_BODY]  -> echoes status code only
http_code() {
  local m="$1" url="$2" hdr="$3" body="${4:-}"
  local args=(-s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$m")
  [ -n "$hdr" ] && args+=(-H "$hdr")
  if [ -n "$body" ]; then
    args+=(-H 'Content-Type: application/json' --data-binary "$body")
  fi
  curl "${args[@]}" "$url" 2>/dev/null || echo 000
}

# http_capture OUTVAR METHOD URL AUTH_HEADER [JSON_BODY] -> echoes code, writes
# response body to the file named by $BODY_FILE (for id extraction on baseline).
BODY_FILE="$(mktemp)"

# body_id -> the `.id` of the captured body, or empty. common.sh runs the oracle
# under `set -e`, and a DENIED response body is plain text ("Forbidden"), not
# JSON — jq exits 5 on that, which would abort the suite mid-probe on exactly
# the FIXED image this tier is meant to prove green. Swallow it: absent id is a
# legitimate outcome here, the assertions read the status code.
body_id() { jq -r '.id // empty' "$BODY_FILE" 2>/dev/null || true; }
http_capture() {
  local m="$1" url="$2" hdr="$3" body="${4:-}"
  local args=(-s -o "$BODY_FILE" -w '%{http_code}' $CURL_TIMEOUT -X "$m")
  [ -n "$hdr" ] && args+=(-H "$hdr")
  if [ -n "$body" ]; then
    args+=(-H 'Content-Type: application/json' --data-binary "$body")
  fi
  curl "${args[@]}" "$url" 2>/dev/null || echo 000
}

begin_suite "migration-surface-admin-authz"

# --- setup: admin token, one plain non-admin user + token -------------------
auth_admin   # sets ADMIN_TOKEN

USER_ID="$(create_test_user_with_retry "$USER" "$USER_PASS" "${USER}@t.test")" || true
if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
  begin_test "setup: create non-admin user"
  fail "could not create non-admin user ${USER}"
  end_suite
fi

USER_TOKEN="$(login_as "$USER" "$USER_PASS")" || true
if [ -z "$USER_TOKEN" ]; then
  begin_test "setup: login non-admin user"
  fail "could not log in as ${USER}"
  end_suite
fi

NONADMIN_HDR="Authorization: Bearer ${USER_TOKEN}"
ADMIN_HDR="Authorization: Bearer ${ADMIN_TOKEN}"

CONN_URL="${BASE_URL}/api/v1/migrations/connections"
CONN_BODY="{\"name\":\"src-${SUF}\",\"url\":\"http://192.0.2.10:8081\",\"auth_type\":\"api_token\",\"credentials\":{\"token\":\"x\"},\"source_type\":\"artifactory\"}"
MIG_URL="${BASE_URL}/api/v1/migrations"

# ---------------------------------------------------------------------------
# (BOUNDARY 1) non-admin registers a SOURCE connection -> 403 (GREEN).
# On the baseline this returns 201 and yields a real owned connection id, which
# the next probe uses to fully stage a cross-repo-write job.
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: non-admin POST /migrations/connections -> 403 (admin gate denies before handler)"
CONN_CODE="$(http_capture POST "$CONN_URL" "$NONADMIN_HDR" "$CONN_BODY")"
NA_CONN_ID="$(body_id)"
if [ "$CONN_CODE" = "403" ]; then
  pass
elif [ "$CONN_CODE" = "401" ]; then
  fail "non-admin create-connection returned 401 (unauthenticated) — the token should authenticate; expected 403 authz-denied" \
       "code=${CONN_CODE}"
else
  fail "AUTHZ BYPASS (#2603 G2): non-admin POST /migrations/connections returned ${CONN_CODE}, expected 403. A non-admin registered a migration SOURCE connection (baseline nest had no admin gate)." \
       "code=${CONN_CODE} user=${USER}"
fi

# Use the baseline-created owned connection id when present, else a synthetic id
# (the fix denies at the nest before ownership is ever consulted).
CONN_ID="${NA_CONN_ID:-$SYN_CONN}"
[ -z "$CONN_ID" ] && CONN_ID="$SYN_CONN"

# ---------------------------------------------------------------------------
# (BOUNDARY 2) THE CROSS-REPO-WRITE CASE: non-admin stages a migration JOB whose
# config NAMES a target repo it cannot write -> 403 (GREEN). On the baseline the
# non-admin owns CONN_ID, so the job is stored (201) pointed at TARGET_REPO.
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: non-admin POST /migrations (job config names target repo it can't write) -> 403"
MIG_BODY="{\"source_connection_id\":\"${CONN_ID}\",\"config\":{\"include_repos\":[\"${TARGET_REPO}\"],\"include_users\":true,\"include_groups\":true,\"include_permissions\":true}}"
MIG_CODE="$(http_capture POST "$MIG_URL" "$NONADMIN_HDR" "$MIG_BODY")"
NA_JOB_ID="$(body_id)"
if [ "$MIG_CODE" = "403" ]; then
  pass
elif [ "$MIG_CODE" = "401" ]; then
  fail "non-admin create-migration returned 401 — the token should authenticate; expected 403" "code=${MIG_CODE}"
else
  fail "CROSS-REPO WRITE (#2603 G2): non-admin POST /migrations returned ${MIG_CODE}, expected 403. A non-admin staged a migration job naming target repo '${TARGET_REPO}' with NO target-repo write authz (baseline)." \
       "code=${MIG_CODE} target=${TARGET_REPO}"
fi

JOB_ID="${NA_JOB_ID:-$SYN_JOB}"
[ -z "$JOB_ID" ] && JOB_ID="$SYN_JOB"

# ---------------------------------------------------------------------------
# (BOUNDARY 3) non-admin STARTS the import -> 403 (GREEN). Baseline: 200 (the
# bulk import into the named target repo is kicked off).
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: non-admin POST /migrations/:id/start -> 403 (import not startable by non-admin)"
START_CODE="$(http_code POST "${MIG_URL}/${JOB_ID}/start" "$NONADMIN_HDR" "")"
if [ "$START_CODE" = "403" ]; then
  pass
elif [ "$START_CODE" = "401" ]; then
  fail "non-admin start returned 401 — the token should authenticate; expected 403" "code=${START_CODE}"
else
  fail "AUTHZ BYPASS (#2603 G2): non-admin POST /migrations/:id/start returned ${START_CODE}, expected 403. A non-admin started a migration import (baseline had no admin gate)." \
       "code=${START_CODE} job=${JOB_ID}"
fi

# ---------------------------------------------------------------------------
# (BOUNDARY 4) the whole nest is admin-only: non-admin GET /migrations -> 403
# (GREEN). Baseline: 200 (list readable by any authenticated user).
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: non-admin GET /migrations -> 403 (whole migration nest is admin-only)"
LIST_CODE="$(http_code GET "$MIG_URL" "$NONADMIN_HDR" "")"
if [ "$LIST_CODE" = "403" ]; then
  pass
else
  fail "AUTHZ BYPASS (#2603 G2): non-admin GET /migrations returned ${LIST_CODE}, expected 403 (the migration nest must be admin-only)." \
       "code=${LIST_CODE}"
fi

# ---------------------------------------------------------------------------
# (CONTROL) admin on the mutating routes -> NOT 403 (authz passes). The legit
# operator migration path must keep working: admin creates a source connection
# and a migration job into any target repo.
# ---------------------------------------------------------------------------
begin_test "CONTROL: admin POST /migrations/connections -> passes authz (201, not 403)"
ADMIN_CONN_CODE="$(http_capture POST "$CONN_URL" "$ADMIN_HDR" "$CONN_BODY")"
ADMIN_CONN_ID="$(body_id)"
if [ "$ADMIN_CONN_CODE" = "403" ]; then
  fail "admin create-connection returned 403 — the admin gate must let admins through; over-restriction regression" \
       "code=${ADMIN_CONN_CODE}"
elif [ "$ADMIN_CONN_CODE" = "201" ] || [ "$ADMIN_CONN_CODE" = "200" ]; then
  pass
else
  fail "admin create-connection returned ${ADMIN_CONN_CODE}, expected 201 (legit operator path)" "code=${ADMIN_CONN_CODE}"
fi

begin_test "CONTROL: admin POST /migrations (job into target repo) -> passes authz (201, not 403)"
ADMIN_CONN_ID="${ADMIN_CONN_ID:-$SYN_CONN}"
ADMIN_MIG_BODY="{\"source_connection_id\":\"${ADMIN_CONN_ID}\",\"config\":{\"include_repos\":[\"${TARGET_REPO}\"]}}"
ADMIN_MIG_CODE="$(http_code POST "$MIG_URL" "$ADMIN_HDR" "$ADMIN_MIG_BODY")"
if [ "$ADMIN_MIG_CODE" = "403" ]; then
  fail "admin create-migration returned 403 — over-restriction regression of the legit operator path" "code=${ADMIN_MIG_CODE}"
elif [ "$ADMIN_MIG_CODE" = "201" ] || [ "$ADMIN_MIG_CODE" = "200" ]; then
  pass
else
  fail "admin create-migration returned ${ADMIN_MIG_CODE}, expected 201 (legit operator path)" "code=${ADMIN_MIG_CODE}"
fi

begin_test "CONTROL: admin GET /migrations -> 200 (legit operator read path intact)"
ADMIN_LIST_CODE="$(http_code GET "$MIG_URL" "$ADMIN_HDR" "")"
if [ "$ADMIN_LIST_CODE" = "200" ]; then
  pass
else
  fail "admin GET /migrations returned ${ADMIN_LIST_CODE}, expected 200 (admins must retain migration access)" "code=${ADMIN_LIST_CODE}"
fi

# ---------------------------------------------------------------------------
# (CONTROL) anonymous on a mutating route -> 401 (admin_middleware authenticates
# before it authorizes; authz sits on top of authn, not instead).
# ---------------------------------------------------------------------------
begin_test "CONTROL: anonymous POST /migrations/connections -> 401 (admin_middleware authenticates first)"
ANON_CODE="$(http_code POST "$CONN_URL" "" "$CONN_BODY")"
if [ "$ANON_CODE" = "401" ]; then
  pass
else
  fail "anonymous create-connection returned ${ANON_CODE}, expected 401 (admin_middleware must reject anon)" "code=${ANON_CODE}"
fi

rm -f "$BODY_FILE" 2>/dev/null || true
end_suite
