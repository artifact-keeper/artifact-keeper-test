#!/usr/bin/env bash
# =============================================================================
# tiers/admin-collision-2875/oracle.sh -- #2875 admin-collision discriminating oracle
# =============================================================================
# run.sh has stood up filesystem/single and exported BASE_URL, DB_CONTAINER,
# ADMIN_USER/ADMIN_PASS, RELEASE_GATE=1, COMMON_SH, JUNIT_OUTPUT_DIR, DTF_SLOT.
#
# THREAT: startup provision_admin_user (backend/src/main.rs) keys the built-in
# admin on username='admin' with no guard that the row is a LOCAL, non-federated
# account. A federated (SSO) user holding username='admin' therefore gets
# hijacked on the next backend restart -- auth_provider flipped to 'local', the
# built-in admin password stamped onto it -- merging the SSO identity with the
# built-in admin. This oracle reproduces that exact code path (a real container
# restart) and asserts the federated row is left untouched.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"
SUF="${RUN_ID##*-}-${DTF_SLOT:-x}-$$"
FED_SUB="oidc-2875-${SUF}"
FED_EMAIL="collide-victim-${SUF}@sso.test"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

wait_health() { # wait up to ~60s for the backend to come back after restart
  local i
  for i in $(seq 1 60); do
    curl -sf --max-time 3 "${BASE_URL}/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

begin_suite "admin-collision-2875"

# --- setup: make the ONLY 'admin' row a FEDERATED principal -------------------
# Free the username: remove the built-in local admin (this stack is disposable
# and torn down after the tier). Then seed a federated 'admin' exactly as an
# OIDC login would leave it: auth_provider='oidc', external_id set, is_admin,
# and no local password.
begin_test "setup: seed a federated (oidc) user named 'admin' as the sole admin"
psql_q "DELETE FROM users WHERE username='admin' AND auth_provider='local';" >/dev/null
psql_q "INSERT INTO users (username, email, auth_provider, external_id, is_admin, password_hash)
        VALUES ('admin', '${FED_EMAIL}', 'oidc', '${FED_SUB}', true, NULL);" >/dev/null
FED_ID="$(psql_q "SELECT id FROM users WHERE username='admin';")"
provider_before="$(psql_q "SELECT auth_provider FROM users WHERE username='admin';")"
extid_before="$(psql_q "SELECT external_id FROM users WHERE username='admin';")"
if [ -z "$FED_ID" ] || [ "$provider_before" != "oidc" ] || [ "$extid_before" != "$FED_SUB" ]; then
  fail "could not seed the federated 'admin' principal (id='${FED_ID}' provider='${provider_before}' ext='${extid_before}')"
  end_suite
fi
pass "federated 'admin' seeded (id=${FED_ID}, auth_provider=oidc, external_id=${FED_SUB})"

# --- trigger: restart the backend -> runs provision_admin_user ---------------
begin_test "restart backend to run startup admin provisioning"
if ! docker restart "$BACKEND_CONTAINER" >/dev/null 2>&1; then
  fail "could not restart backend container '${BACKEND_CONTAINER}'"
  end_suite
fi
if ! wait_health; then
  fail "backend did not return healthy within 60s after restart"
  end_suite
fi
pass "backend restarted and healthy"

# --- assertions: the federated identity must be intact (DB truth) ------------
provider_after="$(psql_q "SELECT auth_provider FROM users WHERE username='admin';")"
extid_after="$(psql_q "SELECT external_id FROM users WHERE username='admin';")"
pwnull_after="$(psql_q "SELECT (password_hash IS NULL) FROM users WHERE username='admin';")"
id_after="$(psql_q "SELECT id FROM users WHERE username='admin';")"

begin_test "federated 'admin' auth_provider is NOT flipped to local (#2875 hijack)"
# RED on a pre-fix image: provision_admin_user flips it to 'local'.
assert_eq "$provider_after" "oidc" \
  "auth_provider after restart is '${provider_after}' (want oidc; a pre-fix image flips it to local)" \
  && pass "auth_provider preserved as oidc"

begin_test "federated 'admin' external_id is preserved"
assert_eq "$extid_after" "$FED_SUB" \
  "external_id after restart is '${extid_after}' (want ${FED_SUB})" \
  && pass "external_id preserved"

begin_test "built-in admin password is NOT stamped onto the federated 'admin'"
# RED on a pre-fix image: the ON CONFLICT upsert writes a local password_hash.
assert_eq "$pwnull_after" "t" \
  "password_hash IS NULL is '${pwnull_after}' after restart (want t; a pre-fix image stamps a local password)" \
  && pass "no local password stamped onto the federated identity"

begin_test "the 'admin' row identity (id) is unchanged"
assert_eq "$id_after" "$FED_ID" \
  "row id after restart is '${id_after}' (want ${FED_ID})" \
  && pass "row id unchanged"

end_suite
