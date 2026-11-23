#!/usr/bin/env bash
# =============================================================================
# tiers/rolling-deploy-migrations/oracle.sh: a backend restarted on a ledger a
#                                            newer release migrated
#                                            (expand-only) starts and serves,
#                                            and refuses a newer contract
#                                            (artifact-keeper#5920)
# =============================================================================
# run.sh has stood up `storage.filesystem migrations.ignore-missing` with
# MIGRATIONS_IGNORE_MISSING=true, and exported BASE_URL, DB_CONTAINER,
# ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# Only this slot's own Postgres and backend container are touched, and an EXIT
# trap removes the simulated rows and column again.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
REPO="rolling-generic-${SLOT}-${SUF}"
ART="pkgs/rolling-1.0.0.tgz"
BYTES="rolling-deploy-${SUF}"
COL="dtf_rolling_note"

WORK="$(mktemp -d -t dtf-rolling-XXXXXX)"
psql_db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -Atc "$1" 2>&1; }
EXPAND_V=""; CONTRACT_V=""
undo_simulation() {
  [ -z "$EXPAND_V" ] || psql_db "DELETE FROM _sqlx_migrations WHERE version IN (${EXPAND_V}${CONTRACT_V:+,${CONTRACT_V}})" >/dev/null
  psql_db "ALTER TABLE repositories DROP COLUMN IF EXISTS ${COL}" >/dev/null
}
cleanup() {
  undo_simulation
  # Leave a serving backend behind if the oracle died with it stopped.
  if ! curl -sf --max-time 3 "${BASE_URL}/readyz" >/dev/null 2>&1; then
    docker restart "$BACKEND_CTR" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

req() {
  local m="$1" url="$2"; shift 2
  : > "${WORK}/body"
  curl -s --max-time 20 --connect-timeout 10 -X "$m" -o "${WORK}/body" -w '%{http_code}' "$@" "$url" 2>/dev/null || echo "000"
}
# restart_backend <seconds>: restart the container; prints "serving" once
# /readyz answers 200, or "exited <code>" / "not-ready" when it does not.
restart_backend() {
  local deadline=$(( $(date +%s) + $1 )) state
  docker restart -t 10 "$BACKEND_CTR" >/dev/null 2>&1
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -sf --max-time 3 "${BASE_URL}/readyz" >/dev/null 2>&1; then echo serving; return; fi
    state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$BACKEND_CTR" 2>/dev/null)"
    case "$state" in exited*|dead*) echo "exited ${state#* }"; return ;; esac
    sleep 2
  done
  echo not-ready
}
startup_log() { docker logs --since "$1" "$BACKEND_CTR" 2>&1 | { grep -E "VersionMissing|refusing to start|schema newer than this binary|was previously applied" || true; } | head -3 | cut -c1-300; }

DL_URL="${BASE_URL}/api/v1/repositories/${REPO}/download/${ART}"

begin_suite "rolling-deploy-migrations"

begin_test "setup: admin login, public generic repo + artifact"
auth_admin
BEARER="Authorization: Bearer ${ADMIN_TOKEN}"
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" >/dev/null 2>&1; then
  infra_fail "could not create public generic repo ${REPO}"; end_suite
fi
C="$(req PUT "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/${ART}" -H "$BEARER" -H 'Content-Type: application/octet-stream' --data-binary "$BYTES")"
case "$C" in 200|201) pass ;; *) infra_fail "PUT of the fixture artifact returned ${C}" "$(head -c 300 "${WORK}/body")"; end_suite ;; esac

begin_test "CONTROL before: /readyz 200 and the public download 200 + bytes"
C1="$(req GET "${BASE_URL}/readyz")"; C2="$(req GET "$DL_URL")"; B2="$(cat "${WORK}/body")"
if [ "$C1" = "200" ] && [ "$C2" = "200" ] && [ "$B2" = "$BYTES" ]; then pass; else fail "/readyz ${C1}, download ${C2}"; fi

begin_test "setup: release N+1 expands the schema (a nullable column) and records its migration"
MAXV="$(psql_db "SELECT max(version) FROM _sqlx_migrations")"
if ! [[ "$MAXV" =~ ^[0-9]+$ ]]; then infra_fail "could not read the migration ledger: ${MAXV}"; end_suite; fi
EXPAND_V=$(( MAXV + 500 ))
OUT="$(psql_db "BEGIN;
  ALTER TABLE repositories ADD COLUMN ${COL} TEXT;
  INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
    VALUES (${EXPAND_V}, 'dtf rolling add note column', true, '\\x00'::bytea, 1);
  COMMIT;")"
if [ "$(psql_db "SELECT count(*) FROM _sqlx_migrations WHERE version = ${EXPAND_V}")" = "1" ]; then
  echo "  ledger: binary's newest ${MAXV}, recorded ${EXPAND_V} (expand)"; pass
else EXPAND_V=""; infra_fail "could not record the simulated migration" "$OUT"; end_suite; fi

begin_test "FIX #5920: restarted on the newer expand-only ledger, the backend serves (readyz, download, upload)"
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ST="$(restart_backend 120)"
if [ "$ST" = "serving" ]; then
  auth_admin >/dev/null 2>&1; BEARER="Authorization: Bearer ${ADMIN_TOKEN}"
  C1="$(req GET "$DL_URL")"; B1="$(cat "${WORK}/body")"
  C2="$(req PUT "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/pkgs/rolling-1.0.1.tgz" -H "$BEARER" \
    -H 'Content-Type: application/octet-stream' --data-binary "${BYTES}-2")"
  if [ "$C1" = "200" ] && [ "$B1" = "$BYTES" ] && { [ "$C2" = "201" ] || [ "$C2" = "200" ]; }; then
    echo "  $(startup_log "$T0" | head -1)"
    pass
  else fail "serving, but download ${C1} / upload ${C2} (want 200 + bytes / 201)"; fi
else
  fail "the backend did not come back on a ledger a newer release migrated (${ST}): an older pod restarted mid-rollout crash-loops" "$(startup_log "$T0")"
fi

begin_test "setup: release N+1 also contracts an expand this binary has (contract of ${MAXV})"
COVERED_V=$(( EXPAND_V + 1 ))
OUT="$(psql_db "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
    VALUES (${COVERED_V}, 'contract of ${MAXV} dtf rolling drop superseded index', true, '\\x00'::bytea, 1)")"
if [ "$(psql_db "SELECT count(*) FROM _sqlx_migrations WHERE version = ${COVERED_V}")" = "1" ]; then CONTRACT_V="$COVERED_V"; pass
else infra_fail "could not record the simulated contract migration" "$OUT"; end_suite; fi

begin_test "FIX #5920: restarted with a newer contract of an expand it has, the backend serves"
T2="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ST="$(restart_backend 120)"
C1="$(req GET "$DL_URL")"
if [ "$ST" = "serving" ] && [ "$C1" = "200" ]; then pass
else fail "restart ${ST}, download ${C1}: a pod already past the expand must survive its contract" "$(startup_log "$T2")"; fi

begin_test "setup: release N+1 also records a contract of its own expand (${EXPAND_V})"
UNCOVERED_V=$(( EXPAND_V + 2 ))
OUT="$(psql_db "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
    VALUES (${UNCOVERED_V}, 'contract of ${EXPAND_V} dtf rolling drop old column', true, '\\x00'::bytea, 1)")"
if [ "$(psql_db "SELECT count(*) FROM _sqlx_migrations WHERE version = ${UNCOVERED_V}")" = "1" ]; then CONTRACT_V="${COVERED_V},${UNCOVERED_V}"; pass
else infra_fail "could not record the simulated contract migration" "$OUT"; end_suite; fi

begin_test "CONTROL: restarted on a ledger with a newer contract of an expand it lacks, the backend never serves"
T1="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ST="$(restart_backend 60)"
LOG="$(startup_log "$T1")"
if [ "$ST" != "serving" ]; then echo "  ${ST}"; pass
else fail "the backend served on a schema with an unknown contract migration" "$LOG"; fi

begin_test "FIX #5920: the refusal names that contract migration"
if printf '%s' "$LOG" | grep -q "refusing to start" && printf '%s' "$LOG" | grep -q "${UNCOVERED_V}"; then pass
else fail "startup log does not refuse the contract migration ${UNCOVERED_V} by name" "$LOG"; fi

begin_test "CONTROL after: with the simulated migrations removed the backend restarts and serves"
undo_simulation; EXPAND_V=""; CONTRACT_V=""
ST="$(restart_backend 120)"
C1="$(req GET "$DL_URL")"
if [ "$ST" = "serving" ] && [ "$C1" = "200" ]; then pass; else fail "restart ${ST}, download ${C1}"; fi

end_suite
