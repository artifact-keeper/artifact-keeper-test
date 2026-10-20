#!/usr/bin/env bash
# =============================================================================
# tiers/signing-trust-attestations/oracle.sh
#   #4282 / #4274 an external OpenPGP issuer key can attest an AK signing key:
#   GET  /api/v1/signing/keys/{id}/trust-attestation/challenge  (server payload)
#   POST /api/v1/signing/keys/{id}/trust-attestation/verify     (admin only)
#   GET  /api/v1/signing/keys/{id}/trust-attestation            (stored record)
#   stored in signing_key_trust_attestations (migration 291), audited as
#   SIGNING_KEY_TRUST_ATTESTED.
# See the manifest for the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"

setup_workdir
W="$WORK_DIR"
# A throwaway keyring for the external issuers (short path: gpg-agent socket).
GNUPGHOME="$(mktemp -d "${TMPDIR:-/tmp}/dtf-sta-gpg.XXXXXX")"
chmod 700 "$GNUPGHOME"
add_exit_handler "gpgconf --homedir \"$GNUPGHOME\" --kill all >/dev/null 2>&1; rm -rf \"$GNUPGHOME\""
export GNUPGHOME

# common.sh runs under `set -e`: every probe swallows its own failure and the
# assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
psql_raw(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# call <token> <METHOD> <path> <outfile> [json-body-file] -> http code
call(){
  local tok="$1" m="$2" p="$3" out="$4" body="${5:-}" code
  rm -f "$out"
  if [ -n "$body" ]; then
    code="$(curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$m" -H "Authorization: Bearer ${tok}" \
      -H 'Content-Type: application/json' --data-binary "@${body}" "${BASE}${p}" 2>/dev/null)" || true
  else
    code="$(curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$m" -H "Authorization: Bearer ${tok}" \
      "${BASE}${p}" 2>/dev/null)" || true
  fi
  [ -f "$out" ] || : > "$out"
  echo "${code:-000}"
}

login(){
  curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'
}

# new_key <name> -> echoes the id of a fresh gpg signing key
new_key(){
  printf '{"name":"%s","key_type":"gpg","algorithm":"rsa2048","uid_name":"DTF STA","uid_email":"sta@dtf.invalid"}' "$1" > "$W/nk.json"
  call "$TOK" POST /api/v1/signing/keys "$W/nk.out" "$W/nk.json" >/dev/null
  jqr '.id // empty' < "$W/nk.out"
}

# expected_payload <key_id> -> the attestation payload rebuilt from the key's
# public fields (signing_service::signing_key_attestation_payload).
expected_payload(){
  local k="$1" pub_sha created
  call "$TOK" GET "/api/v1/signing/keys/${k}" "$W/ep.key" >/dev/null
  call "$TOK" GET "/api/v1/signing/keys/${k}/public" "$W/ep.pub" >/dev/null
  pub_sha="$(sha256sum "$W/ep.pub" | awk '{print $1}')"
  created="$(jqr '.created_at' < "$W/ep.key" | sed 's/Z$/+00:00/')"
  printf 'AK-SIGNING-ATTESTATION-V1\nsigning_key_id:%s\nfingerprint:%s\nkey_id:%s\nkey_type:%s\nalgorithm:%s\npublic_key_sha256:%s\ncreated_at:%s\n' \
    "$k" "$(jqr '.fingerprint' < "$W/ep.key")" "$(jqr '.key_id' < "$W/ep.key")" \
    "$(jqr '.key_type' < "$W/ep.key")" "$(jqr '.algorithm' < "$W/ep.key")" "$pub_sha" "$created"
}

# sign_payload <issuer-email> <payload-file> <out.asc> [extra gpg args...]
sign_payload(){
  local who="$1" in="$2" out="$3"
  shift 3
  gpg --batch --yes --armor --local-user "$who" "$@" --detach-sign --output "$out" "$in" >/dev/null 2>&1 || true
}

# req_json <issuer_name> <issuer-pubkey.asc> <sig.asc> <out.json>
req_json(){
  jq -n --arg n "$1" --rawfile k "$2" --rawfile s "$3" \
    '{issuer_name:$n,issuer_public_key_armored:$k,signature_armored:$s}' > "$4" 2>/dev/null || true
}

rows_for(){ psql_q "SELECT count(*) FROM signing_key_trust_attestations WHERE signing_key_id='$1'"; }
table_exists(){ [ "$(psql_q "SELECT to_regclass('public.signing_key_trust_attestations') IS NOT NULL")" = "t" ]; }
is_denied(){ case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }

# =============================================================================
begin_suite "signing-trust-attestations"

begin_test "setup: admin login, a non-admin user, two throwaway Ed25519 issuer keys and one RSA-3072 issuer"
TOK="$(login admin "$ADMIN_PASS")"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
for c in gpg jq; do command -v "$c" >/dev/null 2>&1 || { infra_fail "$c missing on the harness host"; end_suite; }; done
SUF="${RUN_ID##*-}"
NA_USER="sta-user-${DTF_SLOT}-${SUF}"
NA_PASS="StaUser_${SUF}_Aa1!"
printf '{"username":"%s","password":"%s","email":"%s@dtf.invalid"}' "$NA_USER" "$NA_PASS" "$NA_USER" > "$W/u.json"
call "$TOK" POST /api/v1/users "$W/u.out" "$W/u.json" >/dev/null
UTOK="$(login "$NA_USER" "$NA_PASS")"
ADMIN_ID="$(psql_q "SELECT id FROM users WHERE username='admin'")"
ISS_A="issuer-a-${SUF}@dtf.invalid"; ISS_B="issuer-b-${SUF}@dtf.invalid"; ISS_C="issuer-c-${SUF}@dtf.invalid"
gpg --batch --passphrase '' --quick-gen-key "DTF Issuer A <${ISS_A}>" ed25519 sign 2d >/dev/null 2>&1 || true
gpg --batch --passphrase '' --quick-gen-key "DTF Issuer B <${ISS_B}>" ed25519 sign 2d >/dev/null 2>&1 || true
gpg --batch --passphrase '' --quick-gen-key "DTF Issuer C <${ISS_C}>" rsa3072 sign 2d >/dev/null 2>&1 || true
for i in A B C; do
  v="ISS_${i}"
  gpg --batch --armor --export "${!v}" > "$W/issuer-${i}.asc" 2>/dev/null || true
done
FPR_A="$(gpg --batch --with-colons --fingerprint "$ISS_A" 2>/dev/null | awk -F: '$1=="fpr"{print tolower($10); exit}')" || true
FPR_B="$(gpg --batch --with-colons --fingerprint "$ISS_B" 2>/dev/null | awk -F: '$1=="fpr"{print tolower($10); exit}')" || true
if [ -z "$UTOK" ] || [ -z "$ADMIN_ID" ] || [ -z "$FPR_A" ] || [ -z "$FPR_B" ] || ! grep -q 'BEGIN PGP PUBLIC KEY' "$W/issuer-C.asc"; then
  infra_fail "setup incomplete: non-admin token=${UTOK:+yes} admin id=${ADMIN_ID} issuer A=${FPR_A} B=${FPR_B}"
  end_suite
fi
echo "-- non-admin ${NA_USER}; issuer A ${FPR_A}; issuer B ${FPR_B}"
pass

# =============================================================================
# CONTROL (both images): the pre-existing signing-key surface.
# =============================================================================
begin_test "CONTROL: gpg key create, get, list, public key (gpg-importable, same fingerprint), artifact sign, revoke"
reset_case
K_CTL="$(new_key "sta-ctl-${SUF}")"
note "created key ${K_CTL:-<none>}"
[ -n "$K_CTL" ] || fail_g "POST /api/v1/signing/keys did not return an id"
c="$(call "$TOK" GET "/api/v1/signing/keys/${K_CTL}" "$W/ctl.key")"
[ "$c" = "200" ] && [ "$(jqr '.key_type' < "$W/ctl.key")" = "gpg" ] && [ "$(jqr '.is_active' < "$W/ctl.key")" = "true" ] \
  || fail_g "GET key HTTP ${c}: $(head -c 200 "$W/ctl.key")"
c="$(call "$TOK" GET "/api/v1/signing/keys" "$W/ctl.list")"
jq -e --arg k "$K_CTL" '(if type=="array" then . else (.keys // .items // []) end) | any(.id == $k)' < "$W/ctl.list" >/dev/null 2>&1 \
  || fail_g "GET /keys (HTTP ${c}) does not list ${K_CTL}"
call "$TOK" GET "/api/v1/signing/keys/${K_CTL}/public" "$W/ctl.pub" >/dev/null
CTL_HOME="$(mktemp -d "${TMPDIR:-/tmp}/dtf-sta-ctl.XXXXXX")"; chmod 700 "$CTL_HOME"
gpg --homedir "$CTL_HOME" --batch --import "$W/ctl.pub" >/dev/null 2>&1 || true
got_fpr="$(gpg --homedir "$CTL_HOME" --batch --with-colons --fingerprint 2>/dev/null | awk -F: '$1=="fpr"{print tolower($10); exit}')" || true
gpgconf --homedir "$CTL_HOME" --kill all >/dev/null 2>&1 || true; rm -rf "$CTL_HOME"
note "public key fingerprint (gpg) ${got_fpr:-<none>} vs API $(jqr '.fingerprint' < "$W/ctl.key")"
[ -n "$got_fpr" ] && [ "$got_fpr" = "$(jqr '.fingerprint' < "$W/ctl.key" | tr 'A-F' 'a-f')" ] \
  || fail_g "the served public key does not import with the fingerprint the API reports"
# Sign an artifact with the key through the admin sign route.
R_GEN="sta-gen-${DTF_SLOT}-${SUF}"
printf '{"key":"%s","name":"%s","format":"generic","repo_type":"local","is_public":false}' "$R_GEN" "$R_GEN" > "$W/r.json"
call "$TOK" POST /api/v1/repositories "$W/r.out" "$W/r.json" >/dev/null
RID="$(jqr '.id // empty' < "$W/r.out")"
printf 'dtf signing control %s\n' "$SUF" > "$W/art.txt"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer $TOK" --data-binary "@$W/art.txt" \
  "${BASE}/api/v1/repositories/${R_GEN}/artifacts/ctl/art.txt" 2>/dev/null || true
AID="$(psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${R_GEN}' AND a.is_deleted=false LIMIT 1")"
printf '{"signing_key_id":"%s","sign_metadata":true,"sign_packages":true,"require_signatures":false}' "$K_CTL" > "$W/cfg.json"
c_cfg="$(call "$TOK" POST "/api/v1/signing/repositories/${RID}/config" "$W/cfg.out" "$W/cfg.json")"
c="$(call "$TOK" POST "/api/v1/signing/artifacts/${AID}/sign" "$W/sign.out")"
note "repo ${R_GEN} id ${RID:-?} artifact ${AID:-?}; config HTTP ${c_cfg}; sign HTTP ${c}: $(head -c 200 "$W/sign.out")"
[ "$c" = "200" ] && [ -n "$(jqr '.signature_sha256 // empty' < "$W/sign.out")" ] || fail_g "artifact sign with the key failed (HTTP ${c})"
c="$(call "$TOK" POST "/api/v1/signing/keys/${K_CTL}/revoke" "$W/rev.out")"
call "$TOK" GET "/api/v1/signing/keys/${K_CTL}" "$W/ctl.key2" >/dev/null
[ "$c" = "200" ] && [ "$(jqr '.is_active' < "$W/ctl.key2")" = "false" ] || fail_g "revoke HTTP ${c}, is_active=$(jqr '.is_active' < "$W/ctl.key2")"
finish_case "the existing signing-key routes regressed"

# =============================================================================
# FIX (#4282): challenge payload.
# =============================================================================
begin_test "FIX #4282: migration 291 table exists; the challenge payload is the deterministic key-bound document"
reset_case
table_exists || fail_g "table signing_key_trust_attestations does not exist (migration 291 absent)"
K1="$(new_key "sta-k1-${SUF}")"
c="$(call "$TOK" GET "/api/v1/signing/keys/${K1}/trust-attestation/challenge" "$W/ch1")"
jq -j '.payload // empty' < "$W/ch1" > "$W/payload1" 2>/dev/null || : > "$W/payload1"
expected_payload "$K1" > "$W/payload1.expected"
FPR_K1="$(jqr '.fingerprint' < "$W/ep.key")"
note "challenge HTTP ${c}; payload:"; note "$(cat "$W/payload1")"
[ "$c" = "200" ] || fail_g "challenge HTTP ${c}"
cmp -s "$W/payload1" "$W/payload1.expected" || fail_g "payload != the document rebuilt from the key (id, fingerprint, key_id, type, algorithm, sha256(public key), created_at): expected
$(cat "$W/payload1.expected")"
[ -n "$FPR_K1" ] && [ "$(jqr '.key_fingerprint' < "$W/ch1")" = "$FPR_K1" ] || fail_g "challenge key_fingerprint != key fingerprint"
c2="$(call "$TOK" GET "/api/v1/signing/keys/${K1}/trust-attestation/challenge" "$W/ch1b")"
[ "$c2" = "200" ] && [ "$(jq -j '.payload' < "$W/ch1b" 2>/dev/null)" = "$(cat "$W/payload1")" ] || fail_g "a second challenge differs (not deterministic)"
finish_case "the trust-attestation challenge is missing or not bound to the key (#4282)"

# =============================================================================
# FIX (#4282): admin-only verify and store.
# =============================================================================
begin_test "FIX #4282: a non-admin is refused; an admin's valid issuer signature is stored bound to the key"
reset_case
sign_payload "$ISS_A" "$W/payload1" "$W/sig-a1.asc"
req_json "DTF Issuer A" "$W/issuer-A.asc" "$W/sig-a1.asc" "$W/req-a1.json"
c="$(call "$UTOK" POST "/api/v1/signing/keys/${K1}/trust-attestation/verify" "$W/na.out" "$W/req-a1.json")"
note "non-admin verify: HTTP ${c} $(head -c 160 "$W/na.out")"
is_denied "$c" || fail_g "non-admin verify answered HTTP ${c}, expected 403/404"
[ "$(rows_for "$K1")" = "1" ] && fail_g "a non-admin request stored an attestation"
c="$(call "$TOK" POST "/api/v1/signing/keys/${K1}/trust-attestation/verify" "$W/a1.out" "$W/req-a1.json")"
note "admin verify: HTTP ${c} $(jq -c 'del(.issuer_public_key_armored,.signature_armored,.payload)' < "$W/a1.out" 2>/dev/null | head -c 400)"
[ "$c" = "200" ] || fail_g "admin verify HTTP ${c}: $(head -c 300 "$W/a1.out")"
[ "$(jqr '.verification_status' < "$W/a1.out")" = "signature_valid" ] || fail_g "verification_status != signature_valid"
[ "$(jqr '.issuer_fingerprint' < "$W/a1.out")" = "$FPR_A" ] || fail_g "issuer_fingerprint != issuer A ${FPR_A}"
[ "$(jqr '.signing_key_id' < "$W/a1.out")" = "$K1" ] || fail_g "signing_key_id != ${K1}"
row="$(psql_raw "SELECT signing_key_id||'|'||issuer_fingerprint||'|'||verification_status||'|'||coalesce(created_by::text,'') FROM signing_key_trust_attestations WHERE signing_key_id='${K1}'" | tr -d '[:space:]')"
note "DB row: ${row}"
[ "$row" = "${K1}|${FPR_A}|signature_valid|${ADMIN_ID}" ] || fail_g "DB row != ${K1}|${FPR_A}|signature_valid|${ADMIN_ID}"
psql_raw "SELECT payload FROM signing_key_trust_attestations WHERE signing_key_id='${K1}'" > "$W/row.payload"
grep -q "^fingerprint:${FPR_K1}\$" "$W/row.payload" 2>/dev/null \
  || fail_g "stored payload does not carry the key fingerprint line"
c="$(call "$TOK" GET "/api/v1/signing/keys/${K1}/trust-attestation" "$W/get1")"
[ "$c" = "200" ] && [ "$(jqr '.issuer_fingerprint' < "$W/get1")" = "$FPR_A" ] || fail_g "GET trust-attestation HTTP ${c}: $(head -c 200 "$W/get1")"
finish_case "trust attestation verify/store is missing or not admin-only (#4282)"

begin_test "FIX #4282: the same issuer re-verifies idempotently; a DIFFERENT issuer is refused with 409 and the row is unchanged"
reset_case
sign_payload "$ISS_A" "$W/payload1" "$W/sig-a2.asc"
req_json "DTF Issuer A renamed" "$W/issuer-A.asc" "$W/sig-a2.asc" "$W/req-a2.json"
id_before="$(psql_q "SELECT id FROM signing_key_trust_attestations WHERE signing_key_id='${K1}'")"
c="$(call "$TOK" POST "/api/v1/signing/keys/${K1}/trust-attestation/verify" "$W/a2.out" "$W/req-a2.json")"
note "same issuer again: HTTP ${c}"
[ "$c" = "200" ] || fail_g "same-issuer re-verify HTTP ${c}"
[ "$(rows_for "$K1")" = "1" ] && [ "$(psql_q "SELECT id FROM signing_key_trust_attestations WHERE signing_key_id='${K1}'")" = "$id_before" ] \
  || fail_g "same-issuer re-verify did not update the one existing row in place"
sign_payload "$ISS_B" "$W/payload1" "$W/sig-b1.asc"
req_json "DTF Issuer B" "$W/issuer-B.asc" "$W/sig-b1.asc" "$W/req-b1.json"
c="$(call "$TOK" POST "/api/v1/signing/keys/${K1}/trust-attestation/verify" "$W/b1.out" "$W/req-b1.json")"
note "different issuer: HTTP ${c} $(head -c 200 "$W/b1.out")"
[ "$c" = "409" ] || fail_g "a different issuer answered HTTP ${c}, expected 409"
[ "$(psql_q "SELECT issuer_fingerprint FROM signing_key_trust_attestations WHERE signing_key_id='${K1}'")" = "$FPR_A" ] \
  || fail_g "the stored issuer changed after a different issuer's attestation"
finish_case "issuer replacement is not refused (#4282)"

begin_test "FIX #4282: bad, weak and text-mode signatures and an over-long issuer_name are 400 VALIDATION_ERROR (never 500), nothing stored"
reset_case
K2="$(new_key "sta-k2-${SUF}")"
call "$TOK" GET "/api/v1/signing/keys/${K2}/trust-attestation/challenge" "$W/ch2" >/dev/null
jq -j '.payload // empty' < "$W/ch2" > "$W/payload2" 2>/dev/null || : > "$W/payload2"
expected_payload "$K2" > "$W/payload2.expected"
cp "$W/payload2.expected" "$W/payload2.sign"
sed 's/^algorithm:.*/algorithm:rsa4096/' "$W/payload2.expected" > "$W/payload2.tampered"
sign_payload "$ISS_A" "$W/payload2.tampered" "$W/sig-bad.asc"
sign_payload "$ISS_C" "$W/payload2.sign" "$W/sig-sha1.asc" --digest-algo SHA1
sign_payload "$ISS_A" "$W/payload2.sign" "$W/sig-text.asc" --textmode
sign_payload "$ISS_A" "$W/payload2.sign" "$W/sig-good2.asc"
long_name="$(printf 'n%.0s' $(seq 1 256))"
req_json "bad" "$W/issuer-A.asc" "$W/sig-bad.asc" "$W/req-bad.json"
req_json "sha1" "$W/issuer-C.asc" "$W/sig-sha1.asc" "$W/req-sha1.json"
req_json "text" "$W/issuer-A.asc" "$W/sig-text.asc" "$W/req-text.json"
req_json "$long_name" "$W/issuer-A.asc" "$W/sig-good2.asc" "$W/req-long.json"
for spec in "signature over a different payload|req-bad|does not match" \
            "SHA-1 digest (RSA issuer)|req-sha1|SHA1" \
            "text-mode (0x01) signature|req-text|binary" \
            "issuer_name of 256 characters|req-long|issuer_name"; do
  IFS='|' read -r label rq needle <<<"$spec"
  c="$(call "$TOK" POST "/api/v1/signing/keys/${K2}/trust-attestation/verify" "$W/${rq}.out" "$W/${rq}.json")"
  note "${label}: HTTP ${c} $(head -c 200 "$W/${rq}.out")"
  [ "$c" = "400" ] || fail_g "${label}: HTTP ${c}, expected 400"
  [ "$(jqr '.code' < "$W/${rq}.out")" = "VALIDATION_ERROR" ] || fail_g "${label}: code is not VALIDATION_ERROR"
  grep -qi -- "$needle" "$W/${rq}.out" || fail_g "${label}: message does not mention '${needle}'"
done
[ "$(rows_for "$K2")" = "0" ] || fail_g "a rejected attestation was stored for ${K2}"
# The same key accepts a good signature right after (the rejections were about the input).
req_json "DTF Issuer A" "$W/issuer-A.asc" "$W/sig-good2.asc" "$W/req-good2.json"
c="$(call "$TOK" POST "/api/v1/signing/keys/${K2}/trust-attestation/verify" "$W/good2.out" "$W/req-good2.json")"
[ "$c" = "200" ] && [ "$(rows_for "$K2")" = "1" ] || fail_g "a valid attestation on ${K2} after the rejections answered HTTP ${c}"
finish_case "invalid attestations are not cleanly rejected (#4282)"

begin_test "FIX #4282: a revoked signing key cannot be attested"
reset_case
K3="$(new_key "sta-k3-${SUF}")"
call "$TOK" GET "/api/v1/signing/keys/${K3}/trust-attestation/challenge" "$W/ch3" >/dev/null
jq -j '.payload // empty' < "$W/ch3" > "$W/payload3" 2>/dev/null || : > "$W/payload3"
[ -s "$W/payload3" ] || expected_payload "$K3" > "$W/payload3"
c_rev="$(call "$TOK" POST "/api/v1/signing/keys/${K3}/revoke" "$W/rev3")"
sign_payload "$ISS_A" "$W/payload3" "$W/sig-k3.asc"
req_json "DTF Issuer A" "$W/issuer-A.asc" "$W/sig-k3.asc" "$W/req-k3.json"
c="$(call "$TOK" POST "/api/v1/signing/keys/${K3}/trust-attestation/verify" "$W/k3.out" "$W/req-k3.json")"
note "revoke HTTP ${c_rev}; verify on the revoked key: HTTP ${c} $(head -c 200 "$W/k3.out")"
[ "$c" = "400" ] || fail_g "verify on a revoked key answered HTTP ${c}, expected 400"
grep -qi 'revoked or inactive' "$W/k3.out" || fail_g "the refusal does not say the key is revoked/inactive"
table_exists && [ "$(rows_for "$K3")" != "0" ] && fail_g "an attestation was stored for a revoked key"
finish_case "a revoked key can be attested (#4282)"

begin_test "FIX #4282: audit_log has SIGNING_KEY_TRUST_ATTESTED for the key, by the admin, naming the issuer; signing_key_audit has the verify"
reset_case
n="$(psql_q "SELECT count(*) FROM audit_log WHERE action='SIGNING_KEY_TRUST_ATTESTED' AND resource_id='${K1}'")"
det="$(psql_raw "SELECT user_id::text||' '||resource_type||' '||(details->>'issuer_fingerprint')||' '||(details->>'fingerprint') FROM audit_log WHERE action='SIGNING_KEY_TRUST_ATTESTED' AND resource_id='${K1}' ORDER BY created_at LIMIT 1" | head -1)"
note "audit_log rows for ${K1}: ${n:-?}; first: ${det}"
[ "$n" = "2" ] || fail_g "expected 2 SIGNING_KEY_TRUST_ATTESTED rows for ${K1} (first verify + same-issuer re-verify), got ${n:-none}"
read -r a_user a_type a_iss a_fpr <<<"$det"
[ "${a_user:-}" = "$ADMIN_ID" ] || fail_g "audit actor ${a_user:-?} != admin ${ADMIN_ID}"
[ "${a_type:-}" = "signing_key" ] || fail_g "audit resource_type ${a_type:-?} != signing_key"
[ "${a_iss:-}" = "$FPR_A" ] || fail_g "audit details.issuer_fingerprint ${a_iss:-?} != ${FPR_A}"
[ -n "${a_fpr:-}" ] && [ "${a_fpr:-}" = "$FPR_K1" ] || fail_g "audit details.fingerprint ${a_fpr:-?} != key fingerprint ${FPR_K1}"
[ "$(psql_q "SELECT count(*) FROM audit_log WHERE action='SIGNING_KEY_TRUST_ATTESTED' AND resource_id IN ('${K3}')")" = "0" ] \
  || fail_g "a refused attestation (revoked key) was audited as attested"
m="$(psql_q "SELECT count(*) FROM signing_key_audit WHERE signing_key_id='${K1}' AND action='trust_attestation_verified'" )"
note "signing_key_audit trust_attestation_verified rows for ${K1}: ${m:-?}"
[ "$m" = "2" ] || fail_g "expected 2 signing_key_audit trust_attestation_verified rows for ${K1}, got ${m:-none}"
finish_case "trust attestations are not audited (#4282)"

end_suite
