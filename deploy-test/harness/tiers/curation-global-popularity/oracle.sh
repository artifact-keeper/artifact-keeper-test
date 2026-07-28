#!/usr/bin/env bash
# =============================================================================
# tiers/curation-global-popularity/oracle.sh — global popularity typed curation
# rule (download threshold + typo-squat), at the catalog re-evaluate seam
# (#2949/#2947)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP + catalog flow against the backend.
#
# The enforcement seam under test is POST /curation/packages/re-evaluate, which
# runs evaluate_typed_rules over each pending package and writes the resulting
# decision to curation_packages.status / .rule_id. We assert the catalog
# DECISION — NOT an inline proxy pull (the PEP 503 proxy gate is pattern-only
# and skips typed rules by design).
#
# NO-EGRESS SCOPE: the pool stack has no external egress, so the live download-
# count source degrades to PopularityResult::Unknown for every lookup. We assert
# the egress-free deterministic behaviors: typo-squat detection and the
# fail-open Unknown->review mapping. The count-THRESHOLD arm needs a Known count
# (reachable/mocked source) and is OUT OF SCOPE here (see manifest).
#
# Gates (one global rule, three seeded packages):
#   (RULE)      create global popularity rule -> 201 + rule_type echoed.
#   (TYPOSQUAT) 'reqeusts' (D-L 1 of 'requests') -> review, reason names
#               'requests' + typo-squat, rule_id=<rule>.
#   (UNKNOWN)   distinct name, Unknown source -> review ("popularity unknown"),
#               fail-OPEN (NOT blocked), rule_id=<rule>.
#   (NA)        raw format -> NotApplicable pass-through: default allow ->
#               approved with rule_id NULL.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="cpop-staging-${DTF_SLOT:-x}-${SUF}"
PSQL=(docker exec -i "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1)
PSQLQ=(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc)

begin_suite "curation-global-popularity-2949"

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

seed_pkg() { # NAME FORMAT
  local name="$1" fmt="$2"
  "${PSQL[@]}" >/dev/null <<SQL
INSERT INTO curation_packages
  (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path, status, metadata)
VALUES
  ('${STAGING_ID}', '${STAGING_ID}', '${fmt}', '${name}', '1.0.0', '/${name}', 'pending', '{}'::jsonb);
SQL
}
pkg_status() { "${PSQLQ[@]}" "SELECT status FROM curation_packages WHERE staging_repo_id='${STAGING_ID}' AND package_name='$1'"; }
pkg_ruleid() { "${PSQLQ[@]}" "SELECT COALESCE(rule_id::text,'NULL') FROM curation_packages WHERE staging_repo_id='${STAGING_ID}' AND package_name='$1'"; }
pkg_reason() { "${PSQLQ[@]}" "SELECT COALESCE(evaluation_reason,'') FROM curation_packages WHERE staging_repo_id='${STAGING_ID}' AND package_name='$1'"; }

# --- (RULE) create the global popularity rule --------------------------------
begin_test "RULE: create global popularity rule -> 201 + rule_type echoed"
# Top-level action must satisfy the curation_rules action CHECK (allow|block);
# the popularity *decision* action lives in config.action ("flag").
RBODY='{"action":"allow","reason":"cpop-2949 global popularity","rule_type":"popularity","scope":"global","priority":41,"config":{"min_downloads":10000,"typosquat_check":true,"max_distance":2,"action":"flag"}}'
api_call POST /api/v1/curation/rules "$RBODY"; RESP="$API_BODY"
RULE_ID="$(echo "$RESP" | jq -r '.id // empty' 2>/dev/null || true)"
R_TYPE="$(echo "$RESP" | jq -r '.rule_type // empty' 2>/dev/null || true)"
R_SCOPE="$(echo "$RESP" | jq -r '.scope // empty' 2>/dev/null || true)"
if [ "$API_STATUS" = "201" ] && [ "$R_TYPE" = "popularity" ] && [ "$R_SCOPE" = "global" ] && [ -n "$RULE_ID" ]; then
  pass
else
  fail "global popularity rule did not round-trip: status=${API_STATUS} rule_type='${R_TYPE}' scope='${R_SCOPE}' (pre-#2947 drops rule_type/config/scope -> not a typed rule)" \
       "resp=${RESP}"
fi

# --- stage a repo + seed three packages --------------------------------------
create_repo "$REPO" "pypi" "local"
STAGING_ID="$("${PSQLQ[@]}" "SELECT id FROM repositories WHERE key='${REPO}'")"

seed_pkg "reqeusts" "pypi"            # typo-squat of the seed-list 'requests'
seed_pkg "acme-internal-xyz" "pypi"   # distinct name, no lexical neighbor
seed_pkg "cpop-rawblob" "raw"         # non-applicable format

# --- drive the catalog decision seam -----------------------------------------
begin_test "SEAM: POST /curation/packages/re-evaluate (default allow) -> 200 over 3 pending"
api_call POST /api/v1/curation/packages/re-evaluate "{\"staging_repo_id\":\"${STAGING_ID}\",\"default_action\":\"allow\"}"
RECOUNT="$API_BODY"
if [ "$API_STATUS" = "200" ]; then
  pass
else
  fail "re-evaluate seam did not run: status=${API_STATUS}" "resp=${RECOUNT}"
fi

# --- (TYPOSQUAT) 'reqeusts' flagged, names 'requests' ------------------------
begin_test "TYPOSQUAT: 'reqeusts' -> review, reason names 'requests' + typo-squat"
S="$(pkg_status reqeusts)"; RID="$(pkg_ruleid reqeusts)"; RSN="$(pkg_reason reqeusts)"
if [ "$S" = "review" ] && [ "$RID" = "$RULE_ID" ] && \
   echo "$RSN" | grep -qi "requests" && echo "$RSN" | grep -qi "typo-squat"; then
  pass
else
  fail "typo-squat name not flagged for review by the rule: status='${S}' rule_id='${RID}' (expected review by rule ${RULE_ID} naming 'requests'; pre-feature the typed rule is not enforced -> approved)" \
       "reason=${RSN}"
fi

# --- (UNKNOWN) fail-open: Unknown source -> review, NOT blocked --------------
begin_test "UNKNOWN: Unknown download source -> review (fail-open), never blocked"
S="$(pkg_status acme-internal-xyz)"; RID="$(pkg_ruleid acme-internal-xyz)"; RSN="$(pkg_reason acme-internal-xyz)"
if [ "$S" = "review" ] && [ "$S" != "blocked" ] && [ "$RID" = "$RULE_ID" ] && \
   echo "$RSN" | grep -qi "popularity unknown"; then
  pass
else
  fail "unknown-source package not fail-open flagged: status='${S}' rule_id='${RID}' (expected review 'popularity unknown' by rule ${RULE_ID}, NEVER blocked; pre-feature -> approved)" \
       "reason=${RSN}"
fi

# --- (NA) non-applicable format -> NotApplicable pass-through -----------------
begin_test "NA: raw format -> NotApplicable pass-through (default decides, rule_id NULL)"
S="$(pkg_status cpop-rawblob)"; RID="$(pkg_ruleid cpop-rawblob)"
if [ "$S" = "approved" ] && [ "$RID" = "NULL" ]; then
  pass
else
  fail "raw artifact was not passed through untouched: status='${S}' rule_id='${RID}' (expected approved via default_action=allow with rule_id NULL; the popularity rule must not judge a non-ecosystem format)" \
       "reason=$(pkg_reason cpop-rawblob)"
fi

# --- cleanup -----------------------------------------------------------------
[ -n "${RULE_ID:-}" ] && api_call DELETE "/api/v1/curation/rules/${RULE_ID}"
"${PSQLQ[@]}" "DELETE FROM curation_packages WHERE staging_repo_id='${STAGING_ID}'" >/dev/null 2>&1
api_call DELETE "/api/v1/repositories/${REPO}" 2>/dev/null

end_suite
