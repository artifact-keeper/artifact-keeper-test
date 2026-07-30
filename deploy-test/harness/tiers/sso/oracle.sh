#!/usr/bin/env bash
# =============================================================================
# tiers/sso/oracle.sh — SAML XSW / SSO discriminating oracle (#2449 CRITICAL)
# =============================================================================
# run.sh has stood up filesystem/single + sso=saml (Keycloak) and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER/ADMIN_PASS, RELEASE_GATE=1, COMMON_SH,
# JUNIT_OUTPUT_DIR, HTTP_PORT/PG_PORT/TRIVY_PORT, DTF_DIR/DTF_SLOT.
#
# The defect class (#2449, v1.5.4 subtree-scope fix): SAML XML Signature
# Wrapping. An attacker wraps an unsigned attacker-controlled assertion (or a
# `groups` attribute) around/alongside a validly-signed one so a whole-doc,
# last-wins parser consumes attacker claims OUTSIDE the cryptographically-signed
# subtree and escalates to admin. The fix scopes claim extraction to the
# VERIFIED signed subtree and rejects multi-assertion responses at parse time.
#
# How this oracle is DISCRIMINATING (asserts identity/role, not just HTTP code):
#   * positive controls prove the pipeline REALLY authenticates: a single signed
#     assertion with a non-admin group -> 307 + is_admin=false; the SAME admin
#     group carried by a single SIGNED assertion -> 307 + is_admin=TRUE. So the
#     backend genuinely can mint an admin from that group.
#   * the XSW cases then present the IDENTICAL admin group but in an UNSIGNED
#     wrapper: they MUST be rejected (401, no admin user) or authenticate as a
#     NON-admin. Signed-admin -> admin vs unsigned-wrapped-admin -> rejected, on
#     one live backend, is the escalation guarantee.
#
# The base assertions are signed with bergshamra (the exact crate the backend
# verifies with) via a stateless Rust payload generator (probe/), whose
# ephemeral self-signed cert is registered as the provider certificate. This
# mirrors backend/tests/sso_saml_acs_e2e_tests.rs + rig/harness/pool_xsw_probe.rs.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$COMMON_SH"

ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"
ADMIN_GROUP="ak-admins"
SP_ENTITY_ID="artifact-keeper"
SUF="$(date +%s)-${DTF_SLOT:-x}"
KC_PORT="${TRIVY_PORT:-}"   # Keycloak host port (slot spare), see sso.saml.yml

# --- locate (do NOT build) the payload generator ----------------------------
# The probe is PROVISIONED, not built here. The release gate's required tiers
# must depend only on the candidate image plus local containers — no external
# network — and building this crate pulls ~195 transitive crates from
# crates.io. On the dind runner pool (no Rust toolchain, no registry egress)
# that build simply fails, which is how this tier false-failed the 1.7.0-rc.2
# gate as a "SAML regression" while the candidate's XSW protection was intact.
#
# The static musl binary is now built by the `build-dtf-probes` job in
# .github/workflows/release-gate.yml and downloaded into
# probe/target/release/ before the tier runs, so build_probe is a no-op in CI.
# Locally, an existing target/release build or a DTF_SAML_XSW_PROBE override is
# used as-is, and a cargo build is only ever attempted OUTSIDE the gate, when a
# toolchain is actually present. The probe SOURCE stays the signer of record —
# only the moment of compilation moved. (artifact-keeper-test#323)
PROBE_DIR="${HERE}/probe"
PROBE_BIN="${DTF_SAML_XSW_PROBE:-${PROBE_DIR}/target/release/dtf-saml-xsw-probe}"
build_probe() {
  if [ -x "$PROBE_BIN" ]; then
    echo ">> using prebuilt SAML XSW payload generator: ${PROBE_BIN}"
    file "$PROBE_BIN" 2>/dev/null | sed 's/^/>>   /' || true
    return 0
  fi
  if [ "${RELEASE_GATE:-0}" = "1" ]; then
    # Invariant guard: never reach the network from a required tier. A missing
    # prebuilt binary in the gate is a provisioning failure to be fixed in the
    # workflow, not something to paper over with a crates.io build.
    echo "!! no prebuilt probe at ${PROBE_BIN} and RELEASE_GATE=1:" >&2
    echo "!! refusing to cargo-build inside a required tier (no-external-network invariant)." >&2
    return 1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    echo "!! no prebuilt probe at ${PROBE_BIN} and no cargo toolchain on PATH" >&2
    return 1
  fi
  echo ">> building SAML XSW payload generator (local cargo release, non-gate run)..."
  ( cd "$PROBE_DIR" && cargo build --release ) || return 1
  [ -x "$PROBE_BIN" ]
}

# --- HTTP + DB helpers (curl/psql, prove.sh style) --------------------------
login() {
  curl -s -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jq -r '.access_token // empty'
}

# create_provider <cert_pem_file> -> prints provider UUID
create_provider() {
  local cert_file="$1" body resp
  body=$(jq -n \
    --arg name  "dtf-xsw-${SUF}" \
    --arg eid   "https://idp.dtf-xsw.test/${SUF}" \
    --arg sso   "https://idp.dtf-xsw.test/sso" \
    --arg cert  "$(cat "$cert_file")" \
    --arg spid  "$SP_ENTITY_ID" \
    --arg admg  "$ADMIN_GROUP" \
    '{name:$name, entity_id:$eid, sso_url:$sso, certificate:$cert,
      sp_entity_id:$spid, sign_requests:false, require_signed_assertions:true,
      admin_group:$admg, is_enabled:true}')
  resp=$(curl -s -X POST "${BASE_URL}/api/v1/admin/sso/saml" \
    -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
    -d "$body")
  echo "$resp" | jq -r '.id // empty'
}

# request_id <provider_id> -> the AuthnRequest ID persisted as the pending
# single-use SSO session (must be echoed as InResponseTo).
request_id() {
  local pid="$1" loc
  loc=$(curl -s -o /dev/null -w '%{redirect_url}' \
    "${BASE_URL}/api/v1/auth/sso/saml/${pid}/login")
  python3 - "$loc" <<'PY'
import sys, urllib.parse, base64, re
u = sys.argv[1]
q = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
xml = base64.b64decode(q['SAMLRequest'][0]).decode('utf-8', 'replace')
m = re.search(r'ID="([^"]+)"', xml)
print(m.group(1) if m else "")
PY
}

# post_acs <provider_id> <b64payload> -> HTTP status code
post_acs() {
  local pid="$1" payload="$2"
  curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "SAMLResponse=${payload}" \
    "${BASE_URL}/api/v1/auth/sso/saml/${pid}/acs"
}

# db_saml_isadmin <external_id> -> "t" | "f" | "" (no such user)
db_saml_isadmin() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT is_admin FROM users WHERE external_id='$1' AND auth_provider='saml'" 2>/dev/null | tr -d '[:space:]'
}

craft() { # craft <case> <name_id> <extra args...>
  local case="$1" nid="$2"; shift 2
  "$PROBE_BIN" craft --key "$KEYDIR/idp_key.pem" \
    --issuer "$IDP_ENTITY" --audience "$SP_ENTITY_ID" \
    --request-id "$(request_id "$PROVIDER")" --name-id "$nid" --case "$case" "$@"
}

# =============================================================================
begin_suite "sso-saml-xsw-2449"

# ---- bootstrap -------------------------------------------------------------
if ! build_probe; then
  # INFRA, not a verdict: with no payload generator the oracle cannot craft a
  # single SAML assertion, so it never exercises the XSW protection at all.
  # Reporting this as a regression is how a clean candidate got a RED "SAML
  # break" on the 1.7.0-rc.2 gate (#323).
  begin_test "provision SAML XSW payload generator (bergshamra signer)"
  infra_fail "no usable SAML XSW probe binary; the tier crafted no assertions and evaluated nothing" \
             "expected: ${PROBE_BIN}
provisioned by: the 'build-dtf-probes' job in .github/workflows/release-gate.yml
                (static musl build, downloaded into probe/target/release/)
override with:  DTF_SAML_XSW_PROBE=/path/to/dtf-saml-xsw-probe"
  end_suite
fi

TOK="$(login "${ADMIN_USER:-admin}" "$ADMPASS")"
if [ -z "$TOK" ]; then
  begin_test "admin login"
  infra_fail "admin login to ${BASE_URL} failed (no access_token); the SAML flow was never driven"
  end_suite
fi

KEYDIR="$(mktemp -d)"
"$PROBE_BIN" keygen "$KEYDIR" >/dev/null
PROVIDER="$(create_provider "${KEYDIR}/idp_cert.pem")"
# The provider entity_id we registered (must match the assertion Issuer).
IDP_ENTITY="https://idp.dtf-xsw.test/${SUF}"

begin_test "provision SAML provider (ephemeral IdP cert, require_signed_assertions=true, admin_group=${ADMIN_GROUP})"
if [ -n "$PROVIDER" ] && [ "$PROVIDER" != "null" ]; then
  pass
else
  infra_fail "could not create SAML provider via /api/v1/admin/sso/saml; no XSW variant was ever presented"
  end_suite
fi

# ---------------------------------------------------------------------------
# POSITIVE CONTROLS — the pipeline must really authenticate.
# ---------------------------------------------------------------------------
begin_test "POSITIVE single validly-signed assertion (non-admin group) yields 307 and is_admin=false"
NID="dtf-legit-nonadmin-${SUF}"
ST=$(post_acs "$PROVIDER" "$(craft positive "$NID" --groups Developers)")
ADM=$(db_saml_isadmin "$NID")
if [ "$ST" = "307" ] && [ "$ADM" = "f" ]; then
  pass
else
  fail "legit non-admin login must 307 + is_admin=false (got status=$ST is_admin='$ADM')"
fi

begin_test "POSITIVE single validly-signed assertion carrying admin group yields 307 and is_admin=true (not over-blocked)"
NID="dtf-legit-admin-${SUF}"
ST=$(post_acs "$PROVIDER" "$(craft positive "$NID" --groups "${ADMIN_GROUP},Developers")")
ADM=$(db_saml_isadmin "$NID")
if [ "$ST" = "307" ] && [ "$ADM" = "t" ]; then
  pass
else
  fail "legit admin-group login must 307 + is_admin=true (got status=$ST is_admin='$ADM')" \
       "This is the baseline the XSW cases contrast against: the SAME group, when SIGNED, must mint an admin."
fi

# ---------------------------------------------------------------------------
# XSW ATTACKS — identical admin claim, but UNSIGNED / outside the signed subtree.
# Every one MUST fail to escalate.
# ---------------------------------------------------------------------------
begin_test "XSW 1 dual-assertion (signed benign plus appended UNSIGNED admin assertion) REJECTED 401, no admin user (2449 core)"
VIC="dtf-xsw-victim-${SUF}"; ATT="dtf-xsw-attacker-${SUF}"
ST=$(post_acs "$PROVIDER" "$(craft xsw_dual "$VIC" --groups Developers --attacker-name-id "$ATT" --admin-group "$ADMIN_GROUP")")
AA=$(db_saml_isadmin "$ATT"); AV=$(db_saml_isadmin "$VIC")
if [ "$ST" = "401" ] && [ -z "$AA" ] && [ -z "$AV" ]; then
  pass
else
  fail "XSW dual-assertion must be 401 with NO user provisioned (got status=$ST attacker_is_admin='$AA' victim='$AV')" \
       "Pre-#2449 a last-wins parser consumed the UNSIGNED admin assertion -> 307 + admin escalation. This is the CRITICAL bug."
fi

begin_test "XSW 2 duplicate-ID wrap (unsigned admin assertion reuses the signed assertion ID) REJECTED 401, no admin user"
VIC="dtf-xswdup-victim-${SUF}"; ATT="dtf-xswdup-attacker-${SUF}"
ST=$(post_acs "$PROVIDER" "$(craft xsw_dup_id "$VIC" --groups Developers --attacker-name-id "$ATT" --admin-group "$ADMIN_GROUP")")
AA=$(db_saml_isadmin "$ATT"); AV=$(db_saml_isadmin "$VIC")
if [ "$ST" = "401" ] && [ -z "$AA" ] && [ -z "$AV" ]; then
  pass
else
  fail "duplicate-ID XSW must be 401 with no user provisioned (got status=$ST attacker='$AA' victim='$AV')"
fi

begin_test "XSW 3 groups attribute spliced BEFORE the signed assertion authenticates NON-admin"
NID="dtf-attrxsw-before-${SUF}"
ST=$(post_acs "$PROVIDER" "$(craft xsw_attr_before "$NID" --groups '' --admin-group "$ADMIN_GROUP")")
ADM=$(db_saml_isadmin "$NID")
if [ "$ST" = "307" ] && [ "$ADM" = "f" ]; then
  pass
else
  fail "groups attr spliced BEFORE the signed assertion must NOT grant admin (got status=$ST is_admin='$ADM')"
fi

begin_test "XSW 4 groups attribute spliced AFTER the signed assertion authenticates NON-admin"
NID="dtf-attrxsw-after-${SUF}"
ST=$(post_acs "$PROVIDER" "$(craft xsw_attr_after "$NID" --groups '' --admin-group "$ADMIN_GROUP")")
ADM=$(db_saml_isadmin "$NID")
if [ "$ST" = "307" ] && [ "$ADM" = "f" ]; then
  pass
else
  fail "groups attr spliced AFTER the signed assertion must NOT grant admin (got status=$ST is_admin='$ADM')"
fi

begin_test "XSW 5 in-signature ds:Object groups injection authenticates NON-admin"
NID="dtf-dsobjxsw-${SUF}"
ST=$(post_acs "$PROVIDER" "$(craft xsw_ds_object "$NID" --groups '' --admin-group "$ADMIN_GROUP")")
ADM=$(db_saml_isadmin "$NID")
if [ "$ST" = "307" ] && [ "$ADM" = "f" ]; then
  pass
else
  fail "groups in a <ds:Object> inside the enveloped signature must NOT grant admin (got status=$ST is_admin='$ADM')"
fi

begin_test "XSW 6 comment-truncation NameID provisioned under the FULL signed NameID, not the trailing segment"
NID="dtf-xswcomment-prefix-suffix-${SUF}"
ST=$(post_acs "$PROVIDER" "$(craft xsw_nameid_comment "$NID" --groups Developers)")
FULL=$(db_saml_isadmin "$NID")
TRUNC=$(db_saml_isadmin "suffix-${SUF}")
if [ "$ST" = "307" ] && [ -n "$FULL" ] && [ -z "$TRUNC" ]; then
  pass
else
  fail "comment-split NameID must provision the FULL value, not the trailing segment (got status=$ST full='$FULL' truncated='$TRUNC')"
fi

begin_test "CONTROL fully-UNSIGNED forged admin assertion (no signature) REJECTED 401, no user"
NID="dtf-forged-${SUF}"
ST=$(post_acs "$PROVIDER" "$(craft forged_unsigned "$NID" --groups "$ADMIN_GROUP")")
ADM=$(db_saml_isadmin "$NID")
if [ "$ST" = "401" ] && [ -z "$ADM" ]; then
  pass
else
  fail "an unsigned forged assertion must be rejected when require_signed_assertions=true (got status=$ST is_admin='$ADM')"
fi

# ---------------------------------------------------------------------------
# REAL-IdP INTEROP (Keycloak in-compose) — the design's "real IdP" requirement.
# ---------------------------------------------------------------------------
begin_test "REAL IdP Keycloak serves the realm SAML descriptor with a signing X509Certificate"
if [ -z "$KC_PORT" ]; then
  fail "TRIVY_PORT (Keycloak host port) not exported by run.sh"
else
  DESC=$(curl -s "http://127.0.0.1:${KC_PORT}/realms/dtf/protocol/saml/descriptor")
  if echo "$DESC" | grep -q 'EntityDescriptor' && echo "$DESC" | grep -q 'X509Certificate'; then
    pass
  else
    fail "Keycloak SAML descriptor missing EntityDescriptor/X509Certificate on :${KC_PORT}" \
         "$(echo "$DESC" | head -c 400)"
  fi
fi

begin_test "REAL IdP AK federates to live Keycloak (provider from Keycloak descriptor, login 307s to Keycloak SSO URL)"
KC_ENTITY="http://127.0.0.1:${KC_PORT}/realms/dtf"
KC_SSO="http://127.0.0.1:${KC_PORT}/realms/dtf/protocol/saml"
# Extract Keycloak's real signing cert from its descriptor and register a provider.
KC_CERT_B64=$(curl -s "http://127.0.0.1:${KC_PORT}/realms/dtf/protocol/saml/descriptor" \
  | python3 -c "import sys,re; d=sys.stdin.read(); m=re.search(r'<[^>]*X509Certificate>([^<]+)<', d); print(m.group(1).strip() if m else '')" 2>/dev/null)
if [ -n "$KC_CERT_B64" ]; then
  KC_CERT_FILE="${KEYDIR}/kc_cert.pem"
  { echo "-----BEGIN CERTIFICATE-----"; echo "$KC_CERT_B64" | fold -w64; echo "-----END CERTIFICATE-----"; } > "$KC_CERT_FILE"
  KC_BODY=$(jq -n --arg name "dtf-keycloak-${SUF}" --arg eid "$KC_ENTITY" --arg sso "$KC_SSO" \
      --arg cert "$(cat "$KC_CERT_FILE")" --arg spid "$SP_ENTITY_ID" \
      '{name:$name, entity_id:$eid, sso_url:$sso, certificate:$cert, sp_entity_id:$spid,
        sign_requests:false, require_signed_assertions:true, is_enabled:true}')
  KC_PROVIDER=$(curl -s -X POST "${BASE_URL}/api/v1/admin/sso/saml" \
      -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' -d "$KC_BODY" | jq -r '.id // empty')
  REDIR=$(curl -s -o /dev/null -w '%{redirect_url}' "${BASE_URL}/api/v1/auth/sso/saml/${KC_PROVIDER}/login")
  if [ -n "$KC_PROVIDER" ] && echo "$REDIR" | grep -q "${KC_SSO}"; then
    pass
  else
    fail "AK SAML login must 307-redirect to the live Keycloak SSO URL (provider=$KC_PROVIDER redirect='$REDIR')"
  fi
else
  fail "could not extract Keycloak signing cert from its SAML descriptor"
fi

# ---- discrimination summary (printed, not a gate) --------------------------
echo ""
echo "=== DISCRIMINATION SUMMARY (why this tier catches #2449) ==="
echo "  Same admin group '${ADMIN_GROUP}', one live backend:"
echo "    - carried by a SINGLE SIGNED assertion   -> 307 + is_admin=TRUE   (POSITIVE #2)"
echo "    - carried by an UNSIGNED WRAPPED assertion -> 401 + NO user        (XSW #1)"
echo "  A whole-doc last-wins parser (pre-#2449) would have consumed the unsigned"
echo "  admin assertion and returned 307 + admin. The subtree-scoped fix rejects it."

rm -rf "$KEYDIR" 2>/dev/null || true
end_suite
