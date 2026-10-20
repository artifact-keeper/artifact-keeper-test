#!/usr/bin/env bash
# =============================================================================
# tiers/conda-attestation-trust/oracle.sh - key-based CEP-27 attestations:
#   trust policy, verification record, CEP-50 sidecars, policy and promotion
#   gates, audit rows and metrics, the fail-closed opt-out
#   (artifact-keeper#4556, #4155, #4058, #4709, #4711)
# =============================================================================
# run.sh has stood up `storage.filesystem` with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH and the slot's ports.
#
# The oracle generates two P-256 key pairs in its scratch directory:
#   KA  trusted: recreated backend gets CONDA_ATTESTATION_PUBLIC_KEYS=dtf-ci=<KA pub>
#       (plus `broken=<missing file>`, which must be dropped, not trusted)
#   KB  never trusted
# and signs DSSE in-toto Statements with openssl (fixtures/sign_bundle.py), the
# bundle shape `cosign attest-blob --key` produces.
#
# Topology (keys suffixed per run):
#   H   hosted conda: dtfatt-signed 1.0 (attested with KA), dtfatt-plain 1.0
#       (never attested); scan policy predicates.conda.min_attestation_state
#       = verified (added after the sidecar cases)
#   ST  staging conda -> RL local conda: dtfatt-promo 1.0 (attested with KA),
#       dtfatt-bare 1.0 (not attested); policy require_signature +
#       min_attestation_state = verified
#   O   hosted conda for the CONDA_ATTESTATION_REQUIRE_VERIFIED=false leg
#
# Gates (RED on 1.10.0 unless noted; every CONTROL holds on both images):
#   #4556  /api/v1/attestations/policy lists exactly the dtf-ci key by its
#          SPKI fingerprint, never the key bytes; the KA bundle verifies
#          (method sigstore-key, key_fingerprint); refusals name the failed
#          check; `.sigs` / `.sigs.<sha>` serve the stored bundles whose sha256
#          repodata advertises, append-only and de-duplicated; promotion
#          gate_results list require-signature and policy-predicate passes
#          naming the key.
#   #4058  the download gate admits the verified package and refuses the
#          unattested sibling under min_attestation_state=verified.
#   #4155  opt-out: the KB bundle is stored with a `failed` record (201).
#   #4709/#4711 (RED on 1.11.1)  one ATTESTATION_VERIFIED row per accepted PUT
#          carrying method + key fingerprint; ak_conda_attestation_total
#          outcome=verified and, under the opt-out, outcome=failed plus an
#          ATTESTATION_REJECTED row with stored=true.
#   CONTROL  KB-signed, foreign-signature and wrong-digest bundles are all
#          refused (400) and leave no sidecar; the unattested package downloads
#          with no policy; the bare package is never promoted.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below must survive a non-2xx or a
# non-JSON body (a baseline image answers both), so evaluate them explicitly.
set +e

SUF="${RUN_ID##*-}-$$"
PROJECT="ak-dtf${DTF_SLOT}"
FX="${HERE}/fixtures"

H="cat-host-${SUF}"
ST="cat-stage-${SUF}"
RL="cat-rel-${SUF}"
O="cat-optout-${SUF}"

SIGNED="dtfatt-signed-1.0-0.tar.bz2"
PLAIN="dtfatt-plain-1.0-0.tar.bz2"
PROMO="dtfatt-promo-1.0-0.tar.bz2"
BARE="dtfatt-bare-1.0-0.tar.bz2"
OPTPKG="dtfatt-optout-1.0-0.tar.bz2"

WORK="$(mktemp -d -t dtf-cat-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

AUDIT_WAIT=30

# --- helpers ------------------------------------------------------------------

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null
}
audit_rows() { psql_q "SELECT count(*) FROM audit_log WHERE action = '$1' AND ($2)"; }
audit_rows_at_least() { [ "$(audit_rows "$2" "$3")" -ge "$1" ] 2>/dev/null; }

# hget <path> <outfile> [extra curl args] -> HTTP status (anonymous)
hget() {
  local p="$1" o="$2"; shift 2
  curl -s --max-time 60 -o "$o" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}

conda_put() {  # conda_put <repo> <file> <filename> -> status
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$2" \
    "${BASE_URL}/conda/$1/noarch/$3" 2>/dev/null || echo 000
}

# att_put <repo> <pkg filename> <bundle file> <out> -> status
att_put() {
  curl -s --max-time 60 -o "$4" -w '%{http_code}' -X PUT -H "$(auth_header)" \
    -H 'Content-Type: application/json' --data-binary "@$3" \
    "${BASE_URL}/conda/$1/noarch/$2/attestation" 2>/dev/null || echo 000
}

# sign <priv> <hint pub> <pkg filename> <sha256> <out>
sign() {
  python3 -I "${FX}/sign_bundle.py" --key "$1" --hint-pub "$2" --name "$3" \
    --sha256 "$4" --out "$5" >/dev/null 2>"$WORK/sign.err"
}

sha_of() { sha256sum "$1" | awk '{print $1}'; }

METRICS="$WORK/metrics.txt"
scrape_metrics() {
  curl -s --max-time 30 -o "$METRICS" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000
}
metric_value() {
  local name="$1"; shift
  python3 -I - "$METRICS" "$name" "$@" <<'PY'
import re, sys
path, name, wanted = sys.argv[1], sys.argv[2], sys.argv[3:]
want = dict(w.split("=", 1) for w in wanted)
for line in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r'^([A-Za-z_:][\w:]*)\{(.*)\}\s+(\S+)', line)
    if not m or m.group(1) != name:
        continue
    labels = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', m.group(2)))
    if all(labels.get(k) == v for k, v in want.items()):
        print(m.group(3))
        break
PY
}
metric_ge() {
  local min="$1"; shift
  local v; v="$(metric_value "$@")"
  [ -n "$v" ] && python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)' "$v" "$min"
}
_rescrape_ge() { scrape_metrics >/dev/null; metric_ge "$@"; }
metric_eventually() { wait_until "$2 >= $1" 15 _rescrape_ge "$@"; }

# recreate_backend: recreate only the backend with the trust-policy override
# (postgres and the data volume stay), wait for health, log in again.
recreate_backend() {
  docker compose -p "$PROJECT" -f "${DTF_DIR}/compose.base.yml" \
    -f "${DTF_DIR}/profiles/storage.filesystem.yml" -f "${FX}/attestation-keys.yml" \
    up -d --no-deps --force-recreate --wait backend >"$WORK/recreate.log" 2>&1
  local rc=$?
  ADMIN_TOKEN=""
  [ "$rc" -eq 0 ] && auth_admin >/dev/null 2>&1
  [ -n "${ADMIN_TOKEN:-}" ]
}

repo_id() { api_get "/api/v1/repositories/$1" 2>/dev/null | jq -r '.id // empty'; }
artifact_id_of() {  # artifact_id_of <repo id> <filename>
  psql_q "SELECT id FROM artifacts WHERE repository_id = '$1' AND path LIKE '%/$2' AND NOT is_deleted LIMIT 1"
}

begin_suite "conda-attestation-trust (#4556 #4155 #4058 #4709 #4711)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: generated keys, trust policy, repositories, uploads"
setup_err=""
for k in KA KB; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/${k}.key" 2>/dev/null \
    && openssl pkey -in "$WORK/${k}.key" -pubout -out "$WORK/${k}.pub" 2>/dev/null \
    || setup_err+="generate ${k}; "
done
FP_A="$(openssl pkey -pubin -in "$WORK/KA.pub" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
# One line of the PEM body: must never appear in the policy response.
PEM_LINE="$(sed -n 2p "$WORK/KA.pub")"
DTF_CAT_KEYS="dtf-ci=$(cat "$WORK/KA.pub"),broken=/nonexistent/dtf-missing-key.pem"
DTF_CAT_REQUIRE_VERIFIED="true"
export DTF_CAT_KEYS DTF_CAT_REQUIRE_VERIFIED
if [ -z "$setup_err" ] && ! recreate_backend; then
  setup_err+="recreate backend with the trust policy: $(tail -5 "$WORK/recreate.log" | tr '\n' ' '); "
fi

if [ -z "$setup_err" ]; then
  create_repo "$H" conda local || setup_err+="create ${H}; "
  create_repo "$ST" conda staging || setup_err+="create ${ST}; "
  create_repo "$RL" conda local || setup_err+="create ${RL}; "
  create_repo "$O" conda local || setup_err+="create ${O}; "
  BUILD="${DTF_DIR}/fixtures/conda/build.sh"
  for n in dtfatt-signed dtfatt-plain dtfatt-promo dtfatt-bare dtfatt-optout; do
    bash "$BUILD" "$WORK" "$n" 1.0 0 noarch "DTF-ATT-${n}-${SUF}" >/dev/null 2>&1 || setup_err+="build ${n}; "
  done
  for spec in "$H $SIGNED" "$H $PLAIN" "$ST $PROMO" "$ST $BARE" "$O $OPTPKG"; do
    # shellcheck disable=SC2086
    set -- $spec
    st="$(conda_put "$1" "$WORK/$2" "$2")"
    { [ "$st" = "201" ] || [ "$st" = "200" ]; } \
      || setup_err+="upload $2 to $1 -> HTTP ${st} $(head -c 200 "$WORK/put.out"); "
  done
  H_ID="$(repo_id "$H")"; ST_ID="$(repo_id "$ST")"
  [ -n "$H_ID" ] && [ -n "$ST_ID" ] || setup_err+="resolve repository ids; "
  SHA_SIGNED="$(sha_of "$WORK/$SIGNED")"
  SHA_PLAIN="$(sha_of "$WORK/$PLAIN")"
  SHA_PROMO="$(sha_of "$WORK/$PROMO")"
  SHA_OPT="$(sha_of "$WORK/$OPTPKG")"
  sign "$WORK/KA.key" "$WORK/KA.pub" "$SIGNED" "$SHA_SIGNED" "$WORK/good1.json" || setup_err+="sign good1: $(cat "$WORK/sign.err"); "
  sign "$WORK/KA.key" "$WORK/KA.pub" "$SIGNED" "$SHA_SIGNED" "$WORK/good2.json" || setup_err+="sign good2; "
  sign "$WORK/KB.key" "$WORK/KB.pub" "$SIGNED" "$SHA_SIGNED" "$WORK/untrusted.json" || setup_err+="sign untrusted; "
  sign "$WORK/KB.key" "$WORK/KA.pub" "$SIGNED" "$SHA_SIGNED" "$WORK/forged.json" || setup_err+="sign forged; "
  sign "$WORK/KA.key" "$WORK/KA.pub" "$SIGNED" "$SHA_PLAIN" "$WORK/wrongdigest.json" || setup_err+="sign wrongdigest; "
  sign "$WORK/KA.key" "$WORK/KA.pub" "$PROMO" "$SHA_PROMO" "$WORK/promo.json" || setup_err+="sign promo; "
  sign "$WORK/KB.key" "$WORK/KB.pub" "$OPTPKG" "$SHA_OPT" "$WORK/optout.json" || setup_err+="sign optout; "
  if cmp -s "$WORK/good1.json" "$WORK/good2.json"; then
    setup_err+="two signatures over one statement came out identical (ECDSA nonce reuse?); "
  fi
fi
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# #4556 - the trust policy endpoint
# =============================================================================
begin_test "#4556: /api/v1/attestations/policy lists the configured key by fingerprint, drops the unloadable entry, never returns key bytes"
pst="$(curl -s --max-time 30 -o "$WORK/policy.json" -w '%{http_code}' -H "$(auth_header)" \
  "${BASE_URL}/api/v1/attestations/policy" 2>/dev/null || echo 000)"
if [ "$pst" = "200" ] \
   && jq -e --arg fp "$FP_A" '
        .require_verified == true
        and (.keys | length) == 1
        and .keys[0].name == "dtf-ci"
        and .keys[0].fingerprint == $fp
        and .keys[0].id == $fp[0:16]
        and .keys[0].algorithm == "ecdsa-p256-sha256"
        and (.issuers | length) >= 1' "$WORK/policy.json" >/dev/null 2>&1 \
   && ! grep -qF -- "$PEM_LINE" "$WORK/policy.json" \
   && ! grep -q 'BEGIN\|nonexistent' "$WORK/policy.json"; then
  pass
else
  fail "attestation trust policy not reported as configured" \
    "HTTP ${pst}: $(head -c 600 "$WORK/policy.json") (want one key dtf-ci fingerprint ${FP_A})"
fi

# =============================================================================
# CONTROL - bundles that must never verify (refused on both images)
# =============================================================================
begin_test "CONTROL: untrusted-key, forged-signature and wrong-digest bundles are refused and leave no sidecar"
s_unt="$(att_put "$H" "$SIGNED" "$WORK/untrusted.json" "$WORK/r_unt")"
s_for="$(att_put "$H" "$SIGNED" "$WORK/forged.json" "$WORK/r_for")"
s_dig="$(att_put "$H" "$SIGNED" "$WORK/wrongdigest.json" "$WORK/r_dig")"
s_sig="$(hget "/conda/${H}/noarch/${SIGNED}.sigs" "$WORK/sigs_before")"
stored="$(psql_q "SELECT count(*) FROM artifact_metadata am JOIN artifacts a ON a.id = am.artifact_id WHERE a.repository_id = '${H_ID}' AND a.path LIKE '%/${SIGNED}' AND am.metadata ? 'attestation'")"
if [ "$s_unt" = "400" ] && [ "$s_for" = "400" ] && [ "$s_dig" = "400" ] \
   && [ "$s_sig" = "404" ] && [ "${stored:-x}" = "0" ]; then
  pass
else
  fail "a bundle that must not verify was accepted or left a trace" \
    "untrusted HTTP ${s_unt}; forged HTTP ${s_for}; wrong-digest HTTP ${s_dig}; .sigs HTTP ${s_sig}; stored attestation rows=${stored}"
fi

begin_test "#4556: each refusal names the check that failed (unknown key hint, signature, subject digest)"
if grep -q "not a configured trusted key" "$WORK/r_unt" \
   && grep -q "does not verify under any configured trusted key" "$WORK/r_for" \
   && grep -q "does not match package sha256" "$WORK/r_dig"; then
  pass
else
  fail "refusal reasons do not name the key-based checks" \
    "untrusted: $(head -c 250 "$WORK/r_unt") | forged: $(head -c 250 "$WORK/r_for") | wrong digest: $(head -c 250 "$WORK/r_dig")"
fi

# =============================================================================
# #4556 - a key-signed bundle verifies
# =============================================================================
begin_test "#4556: a bundle signed by the configured key verifies (method sigstore-key, key fingerprint) and is persisted"
s_g1="$(att_put "$H" "$SIGNED" "$WORK/good1.json" "$WORK/r_g1")"
SC_SHA1="$(jq -r '.attestations_sha256 // empty' "$WORK/r_g1" 2>/dev/null)"
db_method="$(psql_q "SELECT am.metadata->'attestation_verification'->>'method' || '|' || (am.metadata->'attestation_verification'->>'key_fingerprint') FROM artifact_metadata am JOIN artifacts a ON a.id = am.artifact_id WHERE a.repository_id = '${H_ID}' AND a.path LIKE '%/${SIGNED}'")"
if [ "$s_g1" = "201" ] \
   && jq -e --arg fp "$FP_A" '
        .verification.state == "verified"
        and .verification.method == "sigstore-key"
        and .verification.key_fingerprint == $fp
        and .verification.identity == "dtf-ci"
        and .verification.issuer == ("key:" + $fp[0:16])
        and .attestation_count == 1' "$WORK/r_g1" >/dev/null 2>&1 \
   && [ "$db_method" = "sigstore-key|${FP_A}" ]; then
  pass
else
  fail "key-based bundle did not verify" "HTTP ${s_g1}: $(head -c 600 "$WORK/r_g1"); db=${db_method}"
fi

# =============================================================================
# #4556 - CEP-50 sidecars and attestations_sha256
# =============================================================================
begin_test "#4556: anonymous <file>.sigs serves the stored bundle; its sha256 is the attestations_sha256 repodata advertises"
s1="$(hget "/conda/${H}/noarch/${SIGNED}.sigs" "$WORK/sigs1")"
s2="$(hget "/conda/${H}/noarch/${SIGNED}.sigs.${SC_SHA1}" "$WORK/sigs1ca" -D "$WORK/sigs1ca.h")"
s3="$(hget "/conda/${H}/noarch/repodata.json" "$WORK/rd1.json")"
s4="$(hget "/conda/${H}/noarch/${PLAIN}.sigs" "$WORK/sigs_plain")"
got_sha="$(sha_of "$WORK/sigs1" 2>/dev/null)"
if [ "$s1" = "200" ] && [ -n "$SC_SHA1" ] && [ "$got_sha" = "$SC_SHA1" ] \
   && jq -e --slurpfile b "$WORK/good1.json" 'length == 1 and .[0] == $b[0]' "$WORK/sigs1" >/dev/null 2>&1 \
   && [ "$s2" = "200" ] && cmp -s "$WORK/sigs1" "$WORK/sigs1ca" \
   && grep -qi '^cache-control:.*immutable' "$WORK/sigs1ca.h" \
   && [ "$s3" = "200" ] \
   && jq -e --arg f "$SIGNED" --arg p "$PLAIN" --arg s "$SC_SHA1" '
        .packages[$f].attestations_sha256 == $s
        and (.packages[$p] | has("attestations_sha256") | not)' "$WORK/rd1.json" >/dev/null 2>&1 \
   && [ "$s4" = "404" ]; then
  pass
else
  fail "CEP-50 sidecar / attestations_sha256 contract broken" \
    ".sigs HTTP ${s1} sha=${got_sha} want=${SC_SHA1}; .sigs.<sha> HTTP ${s2}; repodata HTTP ${s3} record=$(jq -c --arg f "$SIGNED" '.packages[$f]' "$WORK/rd1.json" 2>/dev/null | head -c 300); unattested .sigs HTTP ${s4}"
fi

begin_test "#4556: sidecars are append-only: an identical bundle is not duplicated, a new one is appended and re-advertised"
s_dup="$(att_put "$H" "$SIGNED" "$WORK/good1.json" "$WORK/r_dup")"
s_g2="$(att_put "$H" "$SIGNED" "$WORK/good2.json" "$WORK/r_g2")"
SC_SHA2="$(jq -r '.attestations_sha256 // empty' "$WORK/r_g2" 2>/dev/null)"
s5="$(hget "/conda/${H}/noarch/${SIGNED}.sigs" "$WORK/sigs2")"
hget "/conda/${H}/noarch/repodata.json" "$WORK/rd2.json" >/dev/null
if [ "$s_dup" = "200" ] \
   && jq -e --arg s "$SC_SHA1" '.attestation_count == 1 and .attestations_sha256 == $s and .status == "attestation already stored"' "$WORK/r_dup" >/dev/null 2>&1 \
   && [ "$s_g2" = "201" ] && [ -n "$SC_SHA2" ] && [ "$SC_SHA2" != "$SC_SHA1" ] \
   && jq -e '.attestation_count == 2' "$WORK/r_g2" >/dev/null 2>&1 \
   && [ "$s5" = "200" ] && [ "$(sha_of "$WORK/sigs2")" = "$SC_SHA2" ] \
   && jq -e --slurpfile a "$WORK/good1.json" --slurpfile b "$WORK/good2.json" '. == [$a[0], $b[0]]' "$WORK/sigs2" >/dev/null 2>&1 \
   && jq -e --arg f "$SIGNED" --arg s "$SC_SHA2" '.packages[$f].attestations_sha256 == $s' "$WORK/rd2.json" >/dev/null 2>&1; then
  pass
else
  fail "attestation append semantics broken" \
    "duplicate HTTP ${s_dup}: $(head -c 300 "$WORK/r_dup"); second HTTP ${s_g2}: $(head -c 300 "$WORK/r_g2"); .sigs HTTP ${s5} entries=$(jq 'length' "$WORK/sigs2" 2>/dev/null)"
fi

# =============================================================================
# #4709 / #4711 (1.11.2) - verified outcome is audited and counted
# =============================================================================
begin_test "#4709: one ATTESTATION_VERIFIED row per accepted PUT, carrying method and key fingerprint"
pred="details->>'repository' = '${H}' AND details->'package'->>'filename' = '${SIGNED}' AND details->>'method' = 'sigstore-key' AND details->>'key_fingerprint' = '${FP_A}' AND details->>'stored' = 'true'"
if wait_until "ATTESTATION_VERIFIED x3" "$AUDIT_WAIT" audit_rows_at_least 3 ATTESTATION_VERIFIED "$pred"; then
  n="$(audit_rows ATTESTATION_VERIFIED "$pred")"
  assert_eq "$n" "3" "want exactly 3 ATTESTATION_VERIFIED rows (two appends + one duplicate), got ${n}" && pass
else
  fail "verified attestations not audited" \
    "rows=$(audit_rows ATTESTATION_VERIFIED "$pred"); latest: $(psql_q "SELECT action, details FROM audit_log WHERE action LIKE 'ATTESTATION%' ORDER BY created_at DESC LIMIT 2" | head -c 600)"
fi

begin_test "#4711: ak_conda_attestation_total counts outcome=verified (3) and outcome=rejected (3) for the hosted channel"
scrape_metrics >/dev/null
if metric_eventually 3 ak_conda_attestation_total "repository=${H}" "outcome=verified" \
   && metric_ge 3 ak_conda_attestation_total "repository=${H}" "outcome=rejected"; then
  pass
else
  fail "ak_conda_attestation_total verified/rejected not counted" \
    "verified=$(metric_value ak_conda_attestation_total "repository=${H}" "outcome=verified") rejected=$(metric_value ak_conda_attestation_total "repository=${H}" "outcome=rejected")"
fi

# =============================================================================
# #4058 / #4556 - the download gate honours min_attestation_state
# =============================================================================
begin_test "CONTROL: with no scan policy both hosted packages download"
d1="$(hget "/conda/${H}/noarch/${SIGNED}" "$WORK/dl_signed0")"
d2="$(hget "/conda/${H}/noarch/${PLAIN}" "$WORK/dl_plain0")"
if [ "$d1" = "200" ] && [ "$d2" = "200" ] && cmp -s "$WORK/dl_signed0" "$WORK/$SIGNED" && cmp -s "$WORK/dl_plain0" "$WORK/$PLAIN"; then
  pass
else
  fail "hosted conda downloads broken before any policy" "signed HTTP ${d1}; plain HTTP ${d2}"
fi

begin_test "#4058: under min_attestation_state=verified the key-verified package downloads and the unattested one is refused"
pol_body="$(jq -nc --arg n "cat-dl-${SUF}" --arg r "$H_ID" \
  '{name:$n, repository_id:$r, max_severity:"critical", block_unscanned:false, block_on_fail:false,
    predicates:{conda:{min_attestation_state:"verified"}}}')"
pol_st="$(curl -s --max-time 30 -o "$WORK/pol1" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d "$pol_body" "${BASE_URL}/api/v1/security/policies" 2>/dev/null || echo 000)"
d1="$(hget "/conda/${H}/noarch/${SIGNED}" "$WORK/dl_signed1")"
d2="$(hget "/conda/${H}/noarch/${PLAIN}" "$WORK/dl_plain1")"
if [ "$pol_st" != "200" ] && [ "$pol_st" != "201" ]; then
  infra_fail "could not create the scan policy" "HTTP ${pol_st}: $(head -c 300 "$WORK/pol1")"
elif [ "$d1" = "200" ] && cmp -s "$WORK/dl_signed1" "$WORK/$SIGNED" \
     && { [ "$d2" = "403" ] || [ "$d2" = "404" ]; } && ! cmp -s "$WORK/dl_plain1" "$WORK/$PLAIN"; then
  pass
else
  fail "min_attestation_state=verified not enforced on download" \
    "verified pkg HTTP ${d1}; unattested pkg HTTP ${d2}: $(head -c 200 "$WORK/dl_plain1")"
fi

# =============================================================================
# #4556 - promotion: require_signature satisfied by the key-verified bundle
# =============================================================================
begin_test "#4556: promotion under require_signature + min_attestation_state passes for the key-verified package, gate_results name the key"
s_pa="$(att_put "$ST" "$PROMO" "$WORK/promo.json" "$WORK/r_promo")"
pol_body="$(jq -nc --arg n "cat-promo-${SUF}" --arg r "$ST_ID" \
  '{name:$n, repository_id:$r, max_severity:"critical", block_unscanned:false, block_on_fail:false,
    require_signature:true, predicates:{conda:{min_attestation_state:"verified"}}}')"
pol_st="$(curl -s --max-time 30 -o "$WORK/pol2" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d "$pol_body" "${BASE_URL}/api/v1/security/policies" 2>/dev/null || echo 000)"
PROMO_ID="$(artifact_id_of "$ST_ID" "$PROMO")"
pr_st="$(curl -s --max-time 60 -o "$WORK/promote.json" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d "{\"target_repository\":\"${RL}\"}" \
  "${BASE_URL}/api/v1/promotion/repositories/${ST}/artifacts/${PROMO_ID}/promote" 2>/dev/null || echo 000)"
if [ "$pol_st" != "200" ] && [ "$pol_st" != "201" ]; then
  infra_fail "could not create the staging policy" "HTTP ${pol_st}: $(head -c 300 "$WORK/pol2")"
elif [ "$pr_st" = "200" ] \
   && jq -e '
        .promoted == true
        and any(.gate_results[]; .rule == "require-signature" and .passed
                and (.reason | contains("sigstore-key")) and (.reason | contains("dtf-ci")))
        and any(.gate_results[]; .rule == "policy-predicate" and .passed
                and (.reason | contains("[conda.attestation]")))' "$WORK/promote.json" >/dev/null 2>&1; then
  pass
else
  fail "verified attestation did not carry the promotion" \
    "attestation PUT HTTP ${s_pa}; promote HTTP ${pr_st}: $(head -c 700 "$WORK/promote.json")"
fi

begin_test "CONTROL: the unattested staging package is not promoted under require_signature"
BARE_ID="$(artifact_id_of "$ST_ID" "$BARE")"
pr_st="$(curl -s --max-time 60 -o "$WORK/promote_bare.json" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d "{\"target_repository\":\"${RL}\"}" \
  "${BASE_URL}/api/v1/promotion/repositories/${ST}/artifacts/${BARE_ID}/promote" 2>/dev/null || echo 000)"
if { [ "$pr_st" = "200" ] && jq -e '.promoted == false' "$WORK/promote_bare.json" >/dev/null 2>&1; } \
   || [ "$pr_st" = "403" ] || [ "$pr_st" = "409" ] || [ "$pr_st" = "422" ]; then
  pass
else
  fail "an unattested package was promoted past require_signature" "HTTP ${pr_st}: $(head -c 400 "$WORK/promote_bare.json")"
fi

# =============================================================================
# #4155 / #4709 / #4711 - the explicit opt-out stores a failed record
# =============================================================================
begin_test "#4155: with CONDA_ATTESTATION_REQUIRE_VERIFIED=false an untrusted bundle is stored with a failed record"
DTF_CAT_REQUIRE_VERIFIED="false"
export DTF_CAT_REQUIRE_VERIFIED
if ! recreate_backend; then
  infra_fail "recreate backend with the opt-out" "$(tail -5 "$WORK/recreate.log" | tr '\n' ' ')"
  end_suite
fi
s_opt="$(att_put "$O" "$OPTPKG" "$WORK/optout.json" "$WORK/r_opt")"
s_os="$(hget "/conda/${O}/noarch/${OPTPKG}.sigs" "$WORK/sigs_opt")"
if [ "$s_opt" = "201" ] \
   && jq -e '.verification.state == "failed" and (.verification.error | test("trusted key"))' "$WORK/r_opt" >/dev/null 2>&1 \
   && [ "$s_os" = "200" ]; then
  pass
else
  fail "opt-out did not store the unverified bundle with its failed record" \
    "PUT HTTP ${s_opt}: $(head -c 400 "$WORK/r_opt"); .sigs HTTP ${s_os}"
fi

begin_test "#4709/#4711: the opt-out store is audited as ATTESTATION_REJECTED stored=true and counted outcome=failed"
pred="details->>'repository' = '${O}' AND details->'package'->>'filename' = '${OPTPKG}' AND details->>'stored' = 'true'"
if wait_until "ATTESTATION_REJECTED stored=true" "$AUDIT_WAIT" audit_rows_at_least 1 ATTESTATION_REJECTED "$pred" \
   && [ "$(audit_rows ATTESTATION_REJECTED "$pred")" = "1" ] \
   && metric_eventually 1 ak_conda_attestation_total "repository=${O}" "outcome=failed"; then
  pass
else
  fail "opt-out outcome not audited/counted" \
    "rows=$(audit_rows ATTESTATION_REJECTED "$pred") failed=$(metric_value ak_conda_attestation_total "repository=${O}" "outcome=failed")"
fi

end_suite
