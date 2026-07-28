#!/usr/bin/env bash
# =============================================================================
# tiers/curation-global-publisher-trust/oracle.sh — global publisher_trust
# typed curation rule, end-to-end at the catalog re-evaluate seam (#2948/#2947)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP + catalog flow against the backend.
#
# The enforcement seam under test is POST /curation/packages/re-evaluate, which
# runs evaluate_typed_rules over each pending package's SEEDED metadata blob and
# writes the resulting decision to curation_packages.status / .rule_id. We drive
# packages through it and assert the catalog DECISION — NOT an inline proxy pull
# (the PEP 503 proxy gate is pattern-only and skips typed rules by design).
#
# Gates (one global rule, four seeded packages):
#   (RULE)    create global publisher_trust rule -> 201 + rule_type echoed.
#   (ATTEST)  attested-trusted NumFOCUS pypi pkg -> REVIEW, rule_id=<rule>.
#             Attestation envelopes are not cryptographically verified yet
#             (#2955), so structural presence of a provenance blob (which is
#             forgeable) must yield review — never approved (presence is not
#             trust) and never a blanket block of legit attested packages.
#   (SPOOF)   self-asserted "NumFOCUS" (no attestation) -> blocked (spoof
#             resistant), rule_id=<rule>.  <-- primary discriminator.
#   (UNKNOWN) applicable format, no publisher -> review, rule_id=<rule>.
#   (NA)      raw format -> NotApplicable pass-through: default allow ->
#             approved with rule_id NULL (the rule never judged it).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="cpt-staging-${DTF_SLOT:-x}-${SUF}"
PSQL=(docker exec -i "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1)
PSQLQ=(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc)

begin_suite "curation-global-publisher-trust-2948"

auth_admin   # sets ADMIN_TOKEN

api_call() { # METHOD PATH [BODY] -> sets API_STATUS + API_BODY (no subshell)
  local method="$1" path="$2" body="${3:-}" tmp
  tmp=$(mktemp)
  if [ -n "$body" ]; then
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "$(auth_header)" -H 'Content-Type: application/json' \
      -d "$body" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  else
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "$(auth_header)" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  fi
  API_BODY="$(cat "$tmp")"; rm -f "$tmp"
}

# Seed one pending curation_packages row with a metadata blob (publisher_trust
# reads the publisher out of this blob; no external fetch). JSON carries only
# double quotes, so single-quoting it in SQL is safe.
seed_pkg() { # NAME FORMAT METADATA_JSON
  local name="$1" fmt="$2" meta="$3"
  "${PSQL[@]}" >/dev/null <<SQL
INSERT INTO curation_packages
  (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path, status, metadata)
VALUES
  ('${STAGING_ID}', '${STAGING_ID}', '${fmt}', '${name}', '1.0.0', '/${name}', 'pending', '${meta}'::jsonb);
SQL
}
pkg_status()  { "${PSQLQ[@]}" "SELECT status FROM curation_packages WHERE staging_repo_id='${STAGING_ID}' AND package_name='$1'"; }
pkg_ruleid()  { "${PSQLQ[@]}" "SELECT COALESCE(rule_id::text,'NULL') FROM curation_packages WHERE staging_repo_id='${STAGING_ID}' AND package_name='$1'"; }
pkg_reason()  { "${PSQLQ[@]}" "SELECT COALESCE(evaluation_reason,'') FROM curation_packages WHERE staging_repo_id='${STAGING_ID}' AND package_name='$1'"; }

# --- (RULE) create the global publisher_trust rule ---------------------------
begin_test "RULE: create global publisher_trust rule -> 201 + rule_type echoed"
RBODY='{"action":"block","reason":"cpt-2948 global publisher trust","rule_type":"publisher_trust","scope":"global","priority":40,"config":{"trusted_publishers":["NumFOCUS"],"match":"attestation","action":"block"}}'
api_call POST /api/v1/curation/rules "$RBODY"; RESP="$API_BODY"
RULE_ID="$(echo "$RESP" | jq -r '.id // empty' 2>/dev/null || true)"
R_TYPE="$(echo "$RESP" | jq -r '.rule_type // empty' 2>/dev/null || true)"
R_SCOPE="$(echo "$RESP" | jq -r '.scope // empty' 2>/dev/null || true)"
if [ "$API_STATUS" = "201" ] && [ "$R_TYPE" = "publisher_trust" ] && [ "$R_SCOPE" = "global" ] && [ -n "$RULE_ID" ]; then
  pass
else
  fail "global publisher_trust rule did not round-trip: status=${API_STATUS} rule_type='${R_TYPE}' scope='${R_SCOPE}' (pre-#2947 drops rule_type/config/scope -> not a typed rule)" \
       "resp=${RESP}"
fi

# --- stage a repo + seed four packages ---------------------------------------
create_repo "$REPO" "pypi" "local"
STAGING_ID="$("${PSQLQ[@]}" "SELECT id FROM repositories WHERE key='${REPO}'")"

# attested-trusted: merged PyPI integrity-API provenance for the NumFOCUS org.
seed_pkg "cpt-attested" "pypi" '{"info":{"name":"cpt-attested","author":"NumPy Developers"},"provenance":{"attestation_bundles":[{"publisher":{"kind":"GitHub","repository":"NumFOCUS/numpy","workflow":"wheels.yml"},"attestations":[{"envelope":{}}]}]}}'
# spoof: self-asserted author "NumFOCUS", NO attestation (dependency-confusion).
seed_pkg "cpt-spoof" "pypi" '{"info":{"name":"cpt-spoof","author":"NumFOCUS","author_email":"attacker@example.com"}}'
# applicable format, no extractable publisher.
seed_pkg "cpt-nopublisher" "pypi" '{"info":{"name":"cpt-nopublisher"}}'
# non-applicable format: raw artifact has no publisher concept.
seed_pkg "cpt-rawblob" "raw" '{}'

# --- drive the catalog decision seam -----------------------------------------
begin_test "SEAM: POST /curation/packages/re-evaluate (default allow) -> 200 over 4 pending"
api_call POST /api/v1/curation/packages/re-evaluate "{\"staging_repo_id\":\"${STAGING_ID}\",\"default_action\":\"allow\"}"
RECOUNT="$API_BODY"
if [ "$API_STATUS" = "200" ]; then
  pass
else
  fail "re-evaluate seam did not run: status=${API_STATUS}" "resp=${RECOUNT}"
fi

# --- (ATTEST) present-but-unverified provenance -> review (never trust) ------
begin_test "ATTEST: attested-but-unverified NumFOCUS pypi pkg -> REVIEW (presence != trust, #2955)"
S="$(pkg_status cpt-attested)"; RID="$(pkg_ruleid cpt-attested)"; RSN="$(pkg_reason cpt-attested)"
if [ "$S" = "review" ] && [ "$RID" = "$RULE_ID" ] && echo "$RSN" | grep -qi "not cryptographically verified"; then
  pass
else
  fail "attested-but-unverified package not routed to review: status='${S}' rule_id='${RID}' (expected review by rule ${RULE_ID}; the attestation-theater bug trusts a forgeable provenance blob and yields approved)" \
       "reason=${RSN}"
fi

# --- (SPOOF) self-asserted name is NOT trusted -> blocked (primary) ----------
begin_test "SPOOF: self-asserted 'NumFOCUS' (no attestation) -> BLOCKED (spoof-resistant)"
S="$(pkg_status cpt-spoof)"; RID="$(pkg_ruleid cpt-spoof)"; RSN="$(pkg_reason cpt-spoof)"
if [ "$S" = "blocked" ] && [ "$RID" = "$RULE_ID" ] && echo "$RSN" | grep -qi "registry-verified provenance"; then
  pass
else
  fail "spoofed self-asserted publisher was not blocked: status='${S}' rule_id='${RID}' (expected blocked by rule ${RULE_ID}; pre-feature the typed rule is not enforced so the spoof stays UNBLOCKED)" \
       "reason=${RSN}"
fi

# --- (UNKNOWN) applicable format, no publisher -> review ----------------------
begin_test "UNKNOWN: applicable pypi pkg with no publisher -> review (never trust silence)"
S="$(pkg_status cpt-nopublisher)"; RID="$(pkg_ruleid cpt-nopublisher)"; RSN="$(pkg_reason cpt-nopublisher)"
if [ "$S" = "review" ] && [ "$RID" = "$RULE_ID" ] && echo "$RSN" | grep -qi "publisher unknown"; then
  pass
else
  fail "no-publisher package not routed to review: status='${S}' rule_id='${RID}' (expected review by rule ${RULE_ID})" \
       "reason=${RSN}"
fi

# --- (NA) non-applicable format -> NotApplicable pass-through -----------------
begin_test "NA: raw format -> NotApplicable pass-through (default decides, rule_id NULL)"
S="$(pkg_status cpt-rawblob)"; RID="$(pkg_ruleid cpt-rawblob)"
if [ "$S" = "approved" ] && [ "$RID" = "NULL" ]; then
  pass
else
  fail "raw artifact was not passed through untouched: status='${S}' rule_id='${RID}' (expected approved via default_action=allow with rule_id NULL; the global rule must not judge a non-publisher format)" \
       "reason=$(pkg_reason cpt-rawblob)"
fi

# --- cleanup -----------------------------------------------------------------
[ -n "${RULE_ID:-}" ] && api_call DELETE "/api/v1/curation/rules/${RULE_ID}"
"${PSQLQ[@]}" "DELETE FROM curation_packages WHERE staging_repo_id='${STAGING_ID}'" >/dev/null 2>&1
api_call DELETE "/api/v1/repositories/${REPO}" 2>/dev/null

end_suite
