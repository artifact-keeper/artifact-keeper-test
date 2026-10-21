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
# Appended cases (see the manifest): #4648, #4638 (1.11.2), #3505, #4475 and
# #3904 (1.11.0) against the same LDAP server, a SAML provider created through
# the API, and the LDAP_* env-bootstrapped provider dtf-env-ldap.
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

# =============================================================================
# 1.11.x SSO fixes (artifact-keeper #3904, #3505, #4475: 1.11.0; #4648,
# #4638: 1.11.2). profiles/sso.ldap-lifecycle.yml adds the LDAP_* env
# bootstrap of a provider named dtf-env-ldap (plain ldap:// on 389).
# Each case below records its gates instead of aborting the suite.
# =============================================================================
set +e
FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }
jqr(){ jq -r "$@" 2>/dev/null || true; }
W="$WORK_DIR"
# areq <METHOD> <PATH> [JSON]: admin call, sets CODE and BODY.
areq(){
  local -a ca=(-s -o "${W}/abody" -w '%{http_code}' --max-time 30 -X "$1" -H "$(auth_header)")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' -d "$3")
  : >"${W}/abody"
  CODE="$(curl "${ca[@]}" "${BASE_URL}$2" 2>/dev/null)"
  BODY="$(cat "${W}/abody" 2>/dev/null || true)"
}
ldap_log(){ docker logs "$LDAP_CONTAINER" 2>&1; }

begin_test "#4648: LDAP login reports expires_in and sizes the access cookie to the token lifetime"
reset_case
if [ -z "${POS_ID:-}" ]; then
  fail_g "the skip=true provider was not created"
else
  : >"${W}/lh"
  code="$(curl -s -D "${W}/lh" -o "${W}/lb" -w '%{http_code}' --max-time 30 -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$LDAP_USER" --arg p "$LDAP_USER_PW" '{username:$u,password:$p}')" \
    "${BASE_URL}/api/v1/auth/sso/ldap/${POS_ID}/login")"
  exp="$(jqr '.expires_in // empty' "${W}/lb")"
  age="$(grep -i '^set-cookie: ak_access_token=' "${W}/lh" | grep -io 'max-age=[0-9]*' | head -1 | cut -d= -f2)"
  note "login ${code}: expires_in=${exp:-absent} token_type=$(jqr '.token_type // empty' "${W}/lb"); access cookie Max-Age=${age:-absent}"
  [ "$code" = "200" ] || fail_g "LDAP login answered ${code}"
  # JWT_ACCESS_TOKEN_EXPIRY_MINUTES is unset: the default 30 minutes.
  [ "$exp" = "1800" ] || fail_g "expires_in is ${exp:-absent}, expected 1800 (the 30-minute default access-token lifetime)"
  [ "$age" = "1800" ] || fail_g "access cookie Max-Age is ${age:-absent}, expected 1800 (was a fixed 3600)"
fi
finish_case "LDAP login does not report its real session lifetime"

begin_test "#4638: an LDAP server on a CGNAT address is refused naming AK_SSRF_ALLOW_PRIVATE_CIDRS on save and on /test; a metadata address names nothing"
reset_case
mk_ldap_json(){ jq -nc --arg n "$1" --arg s "$2" --arg b "$LDAP_BIND_DN" '{name:$n,server_url:$s,bind_dn:$b,bind_password:"x",user_base_dn:"ou=people,dc=dtf,dc=local",user_filter:"(uid={0})"}'; }
areq POST /api/v1/admin/sso/ldap "$(mk_ldap_json "dtf-cgnat-${RUN_ID}" "ldap://100.64.1.1:389")"
note "ldap://100.64.1.1:389 -> ${CODE}: $(jqr '.message // empty' <<<"$BODY")"
[ "$CODE" = "400" ] || fail_g "the CGNAT LDAP server was not refused (${CODE})"
grep -q 'AK_SSRF_ALLOW_PRIVATE_CIDRS=100.64.1.1' <<<"$BODY" || fail_g "the refusal does not name AK_SSRF_ALLOW_PRIVATE_CIDRS with the refused address"
areq POST /api/v1/admin/sso/ldap "$(mk_ldap_json "dtf-meta-${RUN_ID}" "ldap://169.254.169.254:389")"
note "ldap://169.254.169.254:389 -> ${CODE}: $(jqr '.message // empty' <<<"$BODY")"
[ "$CODE" = "400" ] || fail_g "the metadata address was not refused (${CODE})"
grep -q 'AK_SSRF_ALLOW_PRIVATE_CIDRS' <<<"$BODY" && fail_g "the metadata refusal offers an allowlist"
# The connection test guards the address again at probe time. A provider
# saved while its host was admitted (here: written straight to the row, as if
# the allowlist had since been narrowed) must be refused there with the same
# wording.
areq POST /api/v1/admin/sso/ldap "$(mk_ldap_json "dtf-probe-${RUN_ID}" "ldap://ldap.dtf.local:389")"
PROBE_ID="$(jqr '.id // empty' <<<"$BODY")"
if [ -z "$PROBE_ID" ]; then
  fail_g "could not create the provider for the /test probe (${CODE})"
else
  CREATED_IDS+=("$PROBE_ID")
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "UPDATE ldap_configs SET server_url = 'ldap://100.64.1.1:389' WHERE id = '${PROBE_ID}'" >/dev/null 2>&1
  areq POST "/api/v1/admin/sso/ldap/${PROBE_ID}/test"
  note "/test on a stored ldap://100.64.1.1:389 -> ${CODE}: $(jqr -c '{success, message}' <<<"$BODY")"
  [ "$(jqr '.success' <<<"$BODY")" != "true" ] || fail_g "/test reported success for a refused address"
  grep -q 'AK_SSRF_ALLOW_PRIVATE_CIDRS' <<<"$BODY" || fail_g "the /test refusal does not name AK_SSRF_ALLOW_PRIVATE_CIDRS"
fi
finish_case "the private-network refusal does not name the setting that admits it"

begin_test "#3505: a username the directory does not have pays a decoy bind, like a wrong password does"
reset_case
if [ -z "${POS_ID:-}" ]; then
  fail_g "the skip=true provider was not created"
else
  ghost="ghost${RANDOM}${RANDOM}"
  miss_code="$(curl -s -o "${W}/miss" -w '%{http_code}' --max-time 30 -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$ghost" '{username:$u,password:"Wrong-pass-1"}')" "${BASE_URL}/api/v1/auth/sso/ldap/${POS_ID}/login")"
  wrong_code="$(curl -s -o "${W}/wrong" -w '%{http_code}' --max-time 30 -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$LDAP_USER" '{username:$u,password:"Wrong-pass-1"}')" "${BASE_URL}/api/v1/auth/sso/ldap/${POS_ID}/login")"
  sleep 1
  ldap_log > "${W}/slapd.log"
  # The connection that searched for the ghost, then any BIND after it.
  conn="$(grep -F "filter=\"(uid=${ghost})\"" "${W}/slapd.log" | head -1 | grep -o 'conn=[0-9]*' | cut -d= -f2)"
  decoy="$(awk -v c="${conn:-0}" '$0 ~ ("conn=" c " ") && /SRCH/ {seen=1} seen && / BIND dn="/ {print; exit}' "${W}/slapd.log" | sed -n 's/.*BIND dn="\([^"]*\)".*/\1/p')"
  [ -n "$decoy" ] || decoy="$(awk -v c="${conn:-0}" 'index($0, "conn=" c " ") && /SRCH/ {seen=1; next} seen && / BIND dn="/ && !/cn=admin,/ {print; exit}' "${W}/slapd.log" | sed -n 's/.*BIND dn="\([^"]*\)".*/\1/p')"
  note "miss ${miss_code} $(head -c 120 "${W}/miss"); wrong password ${wrong_code} $(head -c 120 "${W}/wrong")"
  note "search for uid=${ghost} on conn=${conn:-none}; first non-service bind after it: ${decoy:-none}"
  [ "$miss_code" = "401" ] && [ "$wrong_code" = "401" ] || fail_g "miss/wrong-password answered ${miss_code}/${wrong_code}, expected 401/401"
  cmp -s "${W}/miss" "${W}/wrong" || fail_g "the miss and the wrong password return different bodies"
  [ -n "$conn" ] || fail_g "slapd never logged the search for uid=${ghost}"
  case "$decoy" in
    cn=ak-login-decoy-*,ou=people,dc=dtf,dc=local|cn=ak-login-decoy-*,dc=dtf,dc=local) : ;;
    *) fail_g "no decoy bind followed the search miss (the miss returned without a second directory round-trip)";;
  esac
  case "$decoy" in *"$ghost"*) fail_g "the decoy DN carries the submitted username";; esac
fi
finish_case "a search miss is distinguishable from a wrong password by its directory operations"

begin_test "#4475: the SAML HTTP-Redirect AuthnRequest is raw DEFLATE, not bare XML"
reset_case
areq POST /api/v1/admin/sso/saml "$(jq -nc --arg c "$CA_PEM" --arg n "dtf-saml-${RUN_ID}" '{name:$n,entity_id:"https://idp.example.test/entity",sso_url:"https://idp.example.test/sso",certificate:$c}')"
SAML_ID="$(jqr '.id // empty' <<<"$BODY")"
note "SAML provider create: ${CODE} id=${SAML_ID:-none}"
if [ -z "$SAML_ID" ]; then
  fail_g "could not create the SAML provider: ${BODY:0:200}"
else
  loc="$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 30 "${BASE_URL}/api/v1/auth/sso/saml/${SAML_ID}/login")"
  dec="$(python3 -I - "$loc" <<'PY'
import base64, sys, urllib.parse as up, zlib
q = up.parse_qs(up.urlsplit(sys.argv[1]).query).get("SAMLRequest", [""])[0]
raw = base64.b64decode(q) if q else b""
kind = "bare-xml" if raw.lstrip().startswith(b"<") else "binary"
try:
    xml = zlib.decompress(raw, -15)
    print("deflate", kind, b"AuthnRequest" in xml)
except Exception:
    print("not-deflate", kind, b"AuthnRequest" in raw)
PY
)"
  note "redirect to ${loc%%\?*}; SAMLRequest decodes as: ${dec:-nothing}"
  case "$loc" in https://idp.example.test/sso\?*) : ;; *) fail_g "login did not redirect to the IdP SSO URL";; esac
  [ "$dec" = "deflate binary True" ] || fail_g "SAMLRequest is not base64(raw DEFLATE(AuthnRequest)) (${dec:-empty})"
fi
finish_case "the SAML AuthnRequest violates the HTTP-Redirect binding"

begin_test "#3904: admin-API changes to the env-managed LDAP provider survive a restart; env-owned fields are re-applied"
reset_case
areq GET /api/v1/admin/sso/ldap
ENV_ID="$(jqr '.[]? | select(.name == "dtf-env-ldap") | .id' <<<"$BODY")"
note "env-managed provider dtf-env-ldap: ${ENV_ID:-absent} $(jqr -c '.[]? | select(.name == "dtf-env-ldap") | {is_enabled,priority,server_url}' <<<"$BODY")"
if [ -z "$ENV_ID" ]; then
  fail_g "the LDAP_* bootstrap did not create dtf-env-ldap"
else
  areq PUT "/api/v1/admin/sso/ldap/${ENV_ID}" '{"is_enabled":false,"priority":7,"user_filter":"(cn={0})","server_url":"ldap://ldap.dtf.local:3389"}'
  note "admin PUT is_enabled=false priority=7 user_filter=(cn={0}) server_url=:3389 -> ${CODE}"
  is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
  is_2xx "$CODE" || fail_g "the admin update answered ${CODE}"
  docker restart "ak-dtf${DTF_SLOT}-backend" >/dev/null 2>&1
  up=0
  for _i in $(seq 1 90); do curl -sf --max-time 3 "${BASE_URL}/health" >/dev/null 2>&1 && { up=1; break; }; sleep 1; done
  [ "$up" = "1" ] || fail_g "the backend did not come back after the restart"
  auth_admin >/dev/null 2>&1 || true
  areq GET "/api/v1/admin/sso/ldap/${ENV_ID}"
  note "after restart: $(jqr -c '{is_enabled,priority,user_filter,server_url}' <<<"$BODY")"
  # CONTROL half: LDAP_URL owns server_url, so the boot re-applies it on every image.
  [ "$(jqr .server_url <<<"$BODY")" = "ldap://ldap.dtf.local:389" ] || fail_g "the env-owned server_url was not re-applied ($(jqr .server_url <<<"$BODY"))"
  [ "$(jqr .is_enabled <<<"$BODY")" = "false" ] || fail_g "is_enabled reverted to $(jqr .is_enabled <<<"$BODY")"
  [ "$(jqr .priority <<<"$BODY")" = "7" ] || fail_g "priority reverted to $(jqr .priority <<<"$BODY")"
  [ "$(jqr .user_filter <<<"$BODY")" = "(cn={0})" ] || fail_g "user_filter (not set by the environment) reverted to $(jqr .user_filter <<<"$BODY")"
fi
finish_case "the LDAP env bootstrap reverts admin-API changes on restart"

end_suite
