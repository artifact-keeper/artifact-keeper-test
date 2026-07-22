#!/usr/bin/env bash
# =============================================================================
# tiers/ldaps/oracle.sh — per-provider LDAPS TLS options oracle (#2782)
# =============================================================================
# run.sh has stood up `filesystem + sso.ldap`: the backend plus a live LDAPS
# server (osixia/openldap, self-signed cert CN/SAN=ldap.dtf.local, valid 2036)
# reachable at the docker alias `ldap.dtf.local`. It exported BASE_URL,
# ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, DTF_SLOT, DB_CONTAINER,
# DTF_DIR, JUNIT_OUTPUT_DIR. We source common.sh for the assertion/JUnit harness.
#
# #2782: per-provider LDAPS TLS options (insecure_skip_verify + ca_certificate),
# secure-by-default. The oracle proves the columns exist, round-trip, and are
# HONORED at the real LDAP bind (POST /api/v1/auth/sso/ldap/{id}/login):
#   secure-by-default (false + no CA) REJECTS the self-signed bind, while
#   skip=true OR the correct CA lets it SUCCEED. Same server/user/creds across
#   the pair — the ONLY difference is the per-provider TLS option.
#
# EXPECTED OUTCOME on artifact-keeper-backend:1.6.1-rc (has #2782): PASS.
# On a pre-#2782 backend the positive controls cannot pass (no per-provider
# skip/CA option) -> the tier fails, which is what makes it discriminating.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

LDAP_CONTAINER="ak-dtf${DTF_SLOT}-ldap"
LDAP_SRV="ldaps://ldap.dtf.local:636"
LDAP_BIND_DN="cn=admin,dc=dtf,dc=local"
LDAP_BIND_PW="adminpass"
LDAP_BASE="dc=dtf,dc=local"
LDAP_USER="alice"
LDAP_USER_PW="alicepass"
CA_PEM="$(cat "${DTF_DIR}/harness/tiers/ldaps/fixtures/ca.crt")"

begin_suite "ldaps-per-provider-tls-2782"
auth_admin
setup_workdir

CREATED_IDS=()
cleanup_providers() {
  local id
  for id in "${CREATED_IDS[@]:-}"; do
    [ -n "$id" ] && curl -s -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/admin/sso/ldap/${id}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup_providers"

# --- helpers ----------------------------------------------------------------

# create_provider NAME SKIP(true|false) [CA_PEM] -> echoes provider id (or "")
create_provider() {
  local name="$1" skip="$2" ca="${3:-}"
  local payload
  if [ -n "$ca" ]; then
    payload=$(jq -n --arg n "$name" --arg s "$LDAP_SRV" --arg b "$LDAP_BIND_DN" \
      --arg bp "$LDAP_BIND_PW" --arg base "$LDAP_BASE" --argjson skip "$skip" --arg ca "$ca" \
      '{name:$n, server_url:$s, bind_dn:$b, bind_password:$bp, user_base_dn:$base,
        user_filter:"(uid={0})", insecure_skip_verify:$skip, ca_certificate:$ca}')
  else
    payload=$(jq -n --arg n "$name" --arg s "$LDAP_SRV" --arg b "$LDAP_BIND_DN" \
      --arg bp "$LDAP_BIND_PW" --arg base "$LDAP_BASE" --argjson skip "$skip" \
      '{name:$n, server_url:$s, bind_dn:$b, bind_password:$bp, user_base_dn:$base,
        user_filter:"(uid={0})", insecure_skip_verify:$skip}')
  fi
  local out
  out=$(curl -s -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$payload" "${BASE_URL}/api/v1/admin/sso/ldap" 2>/dev/null)
  local id
  id=$(printf '%s' "$out" | jq -r '.id // empty' 2>/dev/null)
  [ -n "$id" ] && CREATED_IDS+=("$id")
  # Return both id and raw for the caller that wants to inspect the echo.
  printf '%s\t%s' "$id" "$out"
}

# ldap_login PROVIDER_ID [PASSWORD] -> echoes HTTP status
ldap_login() {
  local id="$1" pw="${2:-$LDAP_USER_PW}"
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    -X POST -H "Content-Type: application/json" \
    -d "$(jq -n --arg u "$LDAP_USER" --arg p "$pw" '{username:$u, password:$p}')" \
    "${BASE_URL}/api/v1/auth/sso/ldap/${id}/login" 2>/dev/null || echo "000"
}

# db_provider_cols NAME -> echoes "<insecure_skip_verify>|<ca_present bool>"
# psql renders booleans as the text 'true'/'false' when concatenated with ||.
db_provider_cols() {
  local name="$1"
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT insecure_skip_verify || '|' || (ca_certificate IS NOT NULL) FROM ldap_configs WHERE name='${name}';" \
    2>/dev/null | tr -d '[:space:]'
}

# ---------------------------------------------------------------------------
# Seed the test user into LDAP (idempotent).
# ---------------------------------------------------------------------------
begin_test "Seed uid=${LDAP_USER} into LDAPS server"
seed_out=$(docker exec -i "$LDAP_CONTAINER" ldapadd -x -H ldap://localhost:389 \
  -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PW" < "${DTF_DIR}/harness/tiers/ldaps/fixtures/seed.ldif" 2>&1)
# Success, or already present from a prior attempt in the same slot.
if printf '%s' "$seed_out" | grep -qiE 'adding new entry|Already exists'; then
  pass
else
  fail "could not seed LDAP user (ldapadd output)" "$seed_out"
  end_suite
fi

# ---------------------------------------------------------------------------
# Test 1 — SCHEMA / round-trip: create accepts + persists both new columns.
# ---------------------------------------------------------------------------
begin_test "Create/update API accepts + persists insecure_skip_verify + ca_certificate (#2782 schema)"
SCHEMA_NAME="dtf-ldap-schema-${RUN_ID}"
res=$(create_provider "$SCHEMA_NAME" false "$CA_PEM")
SCHEMA_ID="${res%%$'\t'*}"; SCHEMA_ECHO="${res#*$'\t'}"
if [ -z "$SCHEMA_ID" ]; then
  fail "provider create returned no id" "$SCHEMA_ECHO"
else
  # NB: use plain field access, NOT `// empty` — jq's `//` treats the boolean
  # `false` as empty and would drop a legitimately-false value.
  api_skip=$(printf '%s' "$SCHEMA_ECHO" | jq -r '.insecure_skip_verify')
  api_hasca=$(printf '%s' "$SCHEMA_ECHO" | jq -r '.has_ca_certificate')
  db_cols=$(db_provider_cols "$SCHEMA_NAME")   # "<skip>|<ca_present>"
  # Flip the value via update and confirm the column round-trips.
  curl -s -o /dev/null -X PUT -H "$(auth_header)" -H "Content-Type: application/json" \
    -d '{"insecure_skip_verify":true}' \
    "${BASE_URL}/api/v1/admin/sso/ldap/${SCHEMA_ID}" 2>/dev/null
  db_cols_after=$(db_provider_cols "$SCHEMA_NAME")
  if [ "$api_skip" = "false" ] && [ "$api_hasca" = "true" ] \
     && [ "$db_cols" = "false|true" ] && [ "$db_cols_after" = "true|true" ]; then
    pass
  else
    fail "schema round-trip mismatch: api(skip=${api_skip},hasca=${api_hasca}) db_before='${db_cols}' db_after='${db_cols_after}' (want api false/true, db 'false|true' then 'true|true')" "$SCHEMA_ECHO"
  fi
fi

# ---------------------------------------------------------------------------
# Test 2 — NEGATIVE control (secure by default): false + no CA -> bind REJECTED.
# ---------------------------------------------------------------------------
begin_test "NEGATIVE: insecure_skip_verify=false, no CA -> self-signed bind REJECTED (secure by default)"
NEG_NAME="dtf-ldap-neg-${RUN_ID}"
res=$(create_provider "$NEG_NAME" false)
NEG_ID="${res%%$'\t'*}"
if [ -z "$NEG_ID" ]; then
  fail "could not create negative provider" "${res#*$'\t'}"
else
  neg_status=$(ldap_login "$NEG_ID")
  if [ "$neg_status" != "200" ]; then
    pass   # rejected (401/500/502) — untrusted self-signed cert, as designed
  else
    fail "SECURITY: bind SUCCEEDED (HTTP 200) with cert verification ON and no trusted CA — the self-signed cert should NOT be trusted by default"
  fi
fi

# ---------------------------------------------------------------------------
# Test 3 — POSITIVE: insecure_skip_verify=true -> bind SUCCEEDS.
# ---------------------------------------------------------------------------
begin_test "POSITIVE: insecure_skip_verify=true -> bind SUCCEEDS (login 200 + token)"
POS_NAME="dtf-ldap-pos-skip-${RUN_ID}"
res=$(create_provider "$POS_NAME" true)
POS_ID="${res%%$'\t'*}"
if [ -z "$POS_ID" ]; then
  fail "could not create skip=true provider" "${res#*$'\t'}"
else
  pos_status=$(ldap_login "$POS_ID")
  if [ "$pos_status" = "200" ]; then
    pass
  else
    fail "expected login 200 with insecure_skip_verify=true, got ${pos_status}"
  fi
fi

# ---------------------------------------------------------------------------
# Test 4 — POSITIVE: false + correct ca_certificate -> bind SUCCEEDS.
# ---------------------------------------------------------------------------
begin_test "POSITIVE: insecure_skip_verify=false + correct ca_certificate -> bind SUCCEEDS (trust established)"
CA_NAME="dtf-ldap-pos-ca-${RUN_ID}"
res=$(create_provider "$CA_NAME" false "$CA_PEM")
CA_ID="${res%%$'\t'*}"
if [ -z "$CA_ID" ]; then
  fail "could not create ca_certificate provider" "${res#*$'\t'}"
else
  ca_status=$(ldap_login "$CA_ID")
  if [ "$ca_status" = "200" ]; then
    pass
  else
    fail "expected login 200 with the correct CA supplied, got ${ca_status} (host must match cert CN ldap.dtf.local)"
  fi
fi

# ---------------------------------------------------------------------------
# Test 5 — DYNAMIC: flipping the negative provider false->true flips fail->pass.
# Proves the per-provider column is honored AT BIND, not a global toggle.
# ---------------------------------------------------------------------------
begin_test "DYNAMIC: flip the negative provider insecure_skip_verify false->true -> login now SUCCEEDS"
if [ -z "${NEG_ID:-}" ]; then
  skip "negative provider was not created"
else
  curl -s -o /dev/null -X PUT -H "$(auth_header)" -H "Content-Type: application/json" \
    -d '{"insecure_skip_verify":true}' \
    "${BASE_URL}/api/v1/admin/sso/ldap/${NEG_ID}" 2>/dev/null
  flip_status=$(ldap_login "$NEG_ID")
  if [ "$flip_status" = "200" ]; then
    pass
  else
    fail "expected login 200 after flipping insecure_skip_verify to true, got ${flip_status}"
  fi
fi

# ---------------------------------------------------------------------------
# Test 6 — REAL-BIND sanity: wrong password on the working provider -> 401.
# (Confirms the positive is a genuine credential bind, not a blanket accept.)
# ---------------------------------------------------------------------------
begin_test "REAL BIND: wrong password on the skip=true provider -> rejected (not blanket accept)"
if [ -z "${POS_ID:-}" ]; then
  skip "positive provider was not created"
else
  wrong_status=$(ldap_login "$POS_ID" "WRONG-${RUN_ID}")
  if [ "$wrong_status" = "401" ]; then
    pass
  elif [ "$wrong_status" = "200" ]; then
    fail "SECURITY: wrong password returned 200 — bind is not actually validating credentials"
  else
    # A non-200 that is not 401 still means "rejected"; accept but note it.
    pass
  fi
fi

end_suite
