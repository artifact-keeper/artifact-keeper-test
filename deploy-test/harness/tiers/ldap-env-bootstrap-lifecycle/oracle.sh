#!/usr/bin/env bash
# =============================================================================
# tiers/ldap-env-bootstrap-lifecycle/oracle.sh
#   #4857  an env-seeded LDAP provider is disabled once LDAP_* is removed
# See the manifest for the boots and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${RUN_ID:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh enables `set -e`; every probe below judges its own result.
set +e

BASE="$BASE_URL"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
PROJECT="ak-dtf${DTF_SLOT}"
FX="${HERE}/fixtures"
BASEF=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml")
ENV_NAME="dtf-env-ldap"
ADMIN_NAME="dtf-admin-ldap"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# boot <env|none|stock>: recreate only the backend and wait for /health.
# Prints "up" or the failure.
boot(){
  local files=("${BASEF[@]}")
  [ "$1" = "stock" ] || files+=(-f "${FX}/ldap.$1.yml")
  if docker compose -p "$PROJECT" "${files[@]}" up -d --no-deps --force-recreate --wait backend \
       >"${W}/boot-$1.log" 2>&1; then
    echo "up"
  else
    echo "failed: $(tail -3 "${W}/boot-$1.log" | tr '\n' ' ' | head -c 300)"
  fi
}
backend_logs(){ docker logs "$BACKEND_CTR" 2>&1 || true; }
ldap_env_count(){ docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND_CTR" 2>/dev/null | grep -c '^LDAP_' || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
admin_token(){
  curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u admin --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" 2>/dev/null \
    | jqr '.access_token // empty'
}
# provider_listed <name>: exit 0 when /auth/sso/providers lists it as ldap.
provider_listed(){
  curl -s --max-time 15 "${BASE}/api/v1/auth/sso/providers" 2>/dev/null \
    | jq -e --arg n "$1" 'any(.[]?; .name == $n and .provider_type == "ldap")' >/dev/null 2>&1
}
local_login_enabled(){
  curl -s --max-time 15 "${BASE}/api/v1/system/config" 2>/dev/null | jqr '.auth.local_login_enabled'
}
# row_state <name> -> "<is_enabled>|<env_owned_fields or NULL>"
row_state(){
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT is_enabled::text || '|' || COALESCE(env_owned_fields::text, 'NULL') FROM ldap_configs WHERE name = '$1'" \
    2>/dev/null | tr -d '[:space:]'
}

begin_suite "ldap-env-bootstrap-lifecycle"

# =============================================================================
begin_test "CONTROL: a boot with LDAP_URL / LDAP_BASE_DN seeds an enabled, env-owned LDAP provider that hides the local form, and admin password login still works"
reset_case
ST="$(boot env)"
note "boot 1 (LDAP_* set): ${ST}; LDAP_ vars in the container: $(ldap_env_count)"
if [ "$ST" != "up" ]; then
  infra_fail "the backend did not come up with LDAP_* set: ${ST}"; end_suite
fi
provider_listed "$ENV_NAME" || fail_g "/auth/sso/providers does not list ${ENV_NAME}"
R="$(row_state "$ENV_NAME")"; note "ldap_configs ${ENV_NAME}: ${R}"
case "$R" in true\|\{*[a-z]*\}) ;; *) fail_g "${ENV_NAME} is not an enabled row with an env ownership record (${R:-missing})" ;; esac
L="$(local_login_enabled)"; note "auth.local_login_enabled=${L}"
[ "$L" = "false" ] || fail_g "local_login_enabled=${L} with an enabled LDAP provider, expected false"
TOK="$(admin_token)"
[ -n "$TOK" ] || fail_g "admin password login failed with the LDAP provider enabled"
ENV_ID="$(psql_q "SELECT id FROM ldap_configs WHERE name = '${ENV_NAME}'")"
finish_case "the LDAP_* bootstrap did not seed the expected provider"

# =============================================================================
begin_test "FIX #4857: a boot without LDAP_* disables the env-seeded provider (row kept), stops listing it, re-offers the local login form and logs the provider it disabled"
reset_case
ST="$(boot none)"
note "boot 2 (LDAP_* removed): ${ST}; LDAP_ vars in the container: $(ldap_env_count)"
if [ "$ST" != "up" ]; then
  fail_g "the backend did not come up without LDAP_*: ${ST}"
else
  [ "$(ldap_env_count)" = "0" ] || fail_g "LDAP_* is still in the container environment"
  R="$(row_state "$ENV_NAME")"; note "ldap_configs ${ENV_NAME}: ${R}"
  case "$R" in
    false\|*) ;;
    '') fail_g "the ${ENV_NAME} row was deleted; it must only be disabled" ;;
    *) fail_g "${ENV_NAME} is still enabled after LDAP_* was removed (${R})" ;;
  esac
  provider_listed "$ENV_NAME" && fail_g "/auth/sso/providers still lists ${ENV_NAME}"
  L="$(local_login_enabled)"; note "auth.local_login_enabled=${L}"
  [ "$L" = "true" ] || fail_g "local_login_enabled=${L} with no enabled provider left, expected true"
  LOGS="$(backend_logs)"
  grep -q "Disabled LDAP provider '${ENV_NAME}'" <<<"$LOGS" \
    || fail_g "the backend log does not name the provider it disabled"
fi
finish_case "#4857: the env-seeded LDAP provider outlives its LDAP_* variables"

# =============================================================================
begin_test "FIX #4857: an admin who re-enables the env-seeded provider takes ownership of it, so the next boot without LDAP_* leaves it enabled; an admin-created provider is never touched"
reset_case
TOK="$(admin_token)"
if [ -z "$TOK" ] || [ -z "$ENV_ID" ]; then
  fail_g "no admin session (${TOK:+ok}) or no ${ENV_NAME} id (${ENV_ID})"
else
  c="$(curl -s -o "${W}/toggle.json" -w '%{http_code}' --max-time 15 -X PATCH \
        "${BASE}/api/v1/admin/sso/ldap/${ENV_ID}/toggle" -H "Authorization: Bearer ${TOK}" \
        -H 'Content-Type: application/json' -d '{"enabled":true}')"
  [ "$c" = "200" ] || fail_g "toggle ${ENV_NAME} on answered ${c}: $(head -c 200 "${W}/toggle.json")"
  c="$(curl -s -o "${W}/create.json" -w '%{http_code}' --max-time 15 -X POST \
        "${BASE}/api/v1/admin/sso/ldap" -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg n "$ADMIN_NAME" '{name:$n,server_url:"ldap://ldap-admin.dtf.invalid:389",user_base_dn:"ou=people,dc=dtf,dc=invalid"}')")"
  case "$c" in 200|201) ;; *) fail_g "creating ${ADMIN_NAME} answered ${c}: $(head -c 200 "${W}/create.json")" ;; esac
  note "after the admin API: ${ENV_NAME} $(row_state "$ENV_NAME"), ${ADMIN_NAME} $(row_state "$ADMIN_NAME")"
  ST="$(boot none)"
  note "boot 3 (LDAP_* still removed): ${ST}"
  if [ "$ST" != "up" ]; then
    fail_g "the backend did not come up: ${ST}"
  else
    R="$(row_state "$ENV_NAME")"; note "ldap_configs ${ENV_NAME}: ${R}"
    [ "$R" = "true|NULL" ] || fail_g "${ENV_NAME} re-enabled through the admin API is '${R}', expected enabled with no env ownership record (true|NULL)"
    provider_listed "$ENV_NAME" || fail_g "/auth/sso/providers does not list the re-enabled ${ENV_NAME}"
  fi
fi
finish_case "#4857: an admin re-enable does not take ownership from the env bootstrap"

begin_test "CONTROL: an LDAP provider created through the admin API stays enabled across a boot without LDAP_*"
reset_case
R="$(row_state "$ADMIN_NAME")"; note "ldap_configs ${ADMIN_NAME}: ${R}"
[ "$R" = "true|NULL" ] || fail_g "${ADMIN_NAME} is '${R:-missing}', expected enabled with no env ownership record"
provider_listed "$ADMIN_NAME" || fail_g "/auth/sso/providers does not list ${ADMIN_NAME}"
finish_case "a boot without LDAP_* touched an admin-created LDAP provider"

# =============================================================================
begin_test "CONTROL: the stock environment boots and admin logs in"
reset_case
ST="$(boot stock)"
note "final boot: ${ST}"
[ "$ST" = "up" ] || fail_g "the stock environment did not come up: ${ST}"
[ -n "$(admin_token)" ] || fail_g "admin login failed on the stock environment"
finish_case "the stock environment does not boot"

end_suite
