#!/usr/bin/env bash
# =============================================================================
# tiers/popularity-homoglyph-affix/oracle.sh — Unicode-confusable (homoglyph)
# + affix reputation-riding detection in the typed popularity rule (#2956)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP + catalog flow against the backend.
#
# Seam under test: POST /curation/packages/re-evaluate ->
# curation_packages.status/.rule_id/.evaluation_reason (same seam as
# curation-global-popularity; #2956 adds signals, no new enforcement path).
#
# NO-EGRESS NOTE: every download count is Unknown -> every pypi package lands
# in `review` with "popularity unknown" on baseline AND fix, so the
# discriminator is the REASON CONTENT, not the status:
#   (HOMOGLYPH) 'rеquеѕts' (Cyrillic е/е/ѕ, D-L 3 > max_distance 2) -> reason
#               names 'requests' with a homoglyph justification.
#   (AFFIX)     'python-requests' (prefix, D-L 7, Unknown own count)
#               -> reason cites reputation-riding of 'requests'.
#   (GEN-AFFIX) 'data-numpy' (NON-allowlisted affix token) -> reason cites
#               reputation-riding of 'numpy' (#3005 red-team finding 1).
#   (HOMO-AFFIX)'nｕmpy-x' (fullwidth homoglyph + arbitrary affix) -> reason
#               cites reputation-riding of 'numpy' (#3005 finding 3).
#   (LEGIT-FP)  'python-dateutil' (on the popular seed list) -> reason has NO
#               lexical-squat signal at all (false-positive guard; green on
#               baseline and fix both).
#   (MIXED-FP)  'py中文tools' (multi-script, resembles nothing popular) ->
#               reason has NO mixed-script/lexical-squat signal (#3005
#               finding 2: proximity-gated mixed-script).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="phga-staging-${DTF_SLOT:-x}-${SUF}"
PSQL=(docker exec -i "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1)
PSQLQ=(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc)

# Homoglyph squat of 'requests': r е(е) q u е(е) ѕ(ѕ) t s —
# three confusable swaps, Damerau-Levenshtein distance 3 (beyond max_distance
# 2), pixel-identical to the real name.
HOMO_NAME="$(printf 'rеquеѕts')"

begin_suite "popularity-homoglyph-affix-2956"

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
begin_test "RULE: create global popularity rule (defaults enable #2956 checks) -> 201"
RBODY='{"action":"allow","reason":"phga-2956 global popularity","rule_type":"popularity","scope":"global","priority":42,"config":{"min_downloads":10000,"typosquat_check":true,"max_distance":2,"action":"flag"}}'
api_call POST /api/v1/curation/rules "$RBODY"; RESP="$API_BODY"
RULE_ID="$(echo "$RESP" | jq -r '.id // empty' 2>/dev/null || true)"
R_TYPE="$(echo "$RESP" | jq -r '.rule_type // empty' 2>/dev/null || true)"
if [ "$API_STATUS" = "201" ] && [ "$R_TYPE" = "popularity" ] && [ -n "$RULE_ID" ]; then
  pass
else
  fail "global popularity rule did not round-trip: status=${API_STATUS} rule_type='${R_TYPE}'" \
       "resp=${RESP}"
fi

# --- stage a repo + seed three packages --------------------------------------
create_repo "$REPO" "pypi" "local"
STAGING_ID="$("${PSQLQ[@]}" "SELECT id FROM repositories WHERE key='${REPO}'")"

HOMOAFFIX_NAME="$(printf 'nｕmpy-x')"   # fullwidth ｕ + arbitrary affix
MIXEDFP_NAME="py中文tools"                   # benign multi-script, no popular neighbor

seed_pkg "$HOMO_NAME" "pypi"        # homoglyph squat of 'requests' (D-L 3)
seed_pkg "python-requests" "pypi"   # affix squat of 'requests' (D-L 7)
seed_pkg "data-numpy" "pypi"        # NON-allowlisted affix token (gen. affix)
seed_pkg "$HOMOAFFIX_NAME" "pypi"   # homoglyph + unlisted affix combo
seed_pkg "python-dateutil" "pypi"   # LEGIT: on the popular seed list
seed_pkg "$MIXEDFP_NAME" "pypi"     # LEGIT: multi-script, resembles nothing

# --- drive the catalog decision seam -----------------------------------------
begin_test "SEAM: POST /curation/packages/re-evaluate (default allow) -> 200 over 6 pending"
api_call POST /api/v1/curation/packages/re-evaluate "{\"staging_repo_id\":\"${STAGING_ID}\",\"default_action\":\"allow\"}"
if [ "$API_STATUS" = "200" ]; then
  pass
else
  fail "re-evaluate seam did not run: status=${API_STATUS}" "resp=${API_BODY}"
fi

# --- (HOMOGLYPH) Cyrillic lookalike beyond edit distance ---------------------
begin_test "HOMOGLYPH: '${HOMO_NAME}' (D-L 3 of 'requests') -> review, reason cites homoglyph + 'requests'"
S="$(pkg_status "$HOMO_NAME")"; RID="$(pkg_ruleid "$HOMO_NAME")"; RSN="$(pkg_reason "$HOMO_NAME")"
if [ "$S" = "review" ] && [ "$RID" = "$RULE_ID" ] && \
   echo "$RSN" | grep -qi "homoglyph" && echo "$RSN" | grep -qi "requests"; then
  pass
else
  fail "homoglyph squat not identified: status='${S}' rule_id='${RID}' (pre-#2956 the 3-swap Cyrillic name exceeds max_distance 2, so the reason is 'popularity unknown' only)" \
       "reason=${RSN}"
fi

# --- (AFFIX) reputation-riding prefix beyond edit distance -------------------
begin_test "AFFIX: 'python-requests' (Unknown own count) -> review, reason cites reputation-riding of 'requests'"
S="$(pkg_status python-requests)"; RID="$(pkg_ruleid python-requests)"; RSN="$(pkg_reason python-requests)"
if [ "$S" = "review" ] && [ "$RID" = "$RULE_ID" ] && \
   echo "$RSN" | grep -qi "reputation-riding" && echo "$RSN" | grep -q "'requests'"; then
  pass
else
  fail "affix squat not identified: status='${S}' rule_id='${RID}' (pre-#2956 'python-requests' is distance 7 from 'requests', so the reason is 'popularity unknown' only)" \
       "reason=${RSN}"
fi

# --- (GEN-AFFIX) non-allowlisted affix token (#3005 finding 1) ---------------
begin_test "GEN-AFFIX: 'data-numpy' (unlisted affix token) -> review, reason cites reputation-riding of 'numpy'"
S="$(pkg_status data-numpy)"; RID="$(pkg_ruleid data-numpy)"; RSN="$(pkg_reason data-numpy)"
if [ "$S" = "review" ] && [ "$RID" = "$RULE_ID" ] && \
   echo "$RSN" | grep -qi "reputation-riding" && echo "$RSN" | grep -q "'numpy'"; then
  pass
else
  fail "generalized affix squat not identified: status='${S}' rule_id='${RID}' (a bounded affix allowlist has no 'data' token -> no signal; #3005 finding 1)" \
       "reason=${RSN}"
fi

# --- (HOMO-AFFIX) homoglyph + unlisted affix (#3005 finding 3) ---------------
begin_test "HOMO-AFFIX: '${HOMOAFFIX_NAME}' (fullwidth homoglyph + arbitrary affix) -> review, reputation-riding of 'numpy'"
S="$(pkg_status "$HOMOAFFIX_NAME")"; RID="$(pkg_ruleid "$HOMOAFFIX_NAME")"; RSN="$(pkg_reason "$HOMOAFFIX_NAME")"
if [ "$S" = "review" ] && [ "$RID" = "$RULE_ID" ] && \
   echo "$RSN" | grep -qi "reputation-riding" && echo "$RSN" | grep -q "'numpy'"; then
  pass
else
  fail "homoglyph-in-affix squat not identified: status='${S}' rule_id='${RID}' (raw-byte affix match + whole-name skeleton + mixed-script all miss this; #3005 finding 3)" \
       "reason=${RSN}"
fi

# --- (LEGIT-FP) popular affixed name must carry NO lexical-squat signal ------
begin_test "LEGIT-FP: 'python-dateutil' reason has NO typo-squat/homoglyph/affix signal"
RSN="$(pkg_reason python-dateutil)"
if echo "$RSN" | grep -qiE "typo-squat|homoglyph|mixes Unicode scripts|reputation-riding"; then
  fail "false positive: legitimately popular affixed name got a lexical-squat reason" \
       "reason=${RSN}"
else
  pass
fi

# --- (MIXED-FP) benign multi-script name must NOT be lexically flagged -------
begin_test "MIXED-FP: '${MIXEDFP_NAME}' (multi-script, no popular neighbor) has NO mixed-script/squat signal"
RSN="$(pkg_reason "$MIXEDFP_NAME")"
if echo "$RSN" | grep -qiE "typo-squat|homoglyph|mixes Unicode scripts|reputation-riding"; then
  fail "benign internationalized name got a lexical-squat reason (mixed-script must be proximity-gated; #3005 finding 2)" \
       "reason=${RSN}"
else
  pass
fi

# --- cleanup -----------------------------------------------------------------
[ -n "${RULE_ID:-}" ] && api_call DELETE "/api/v1/curation/rules/${RULE_ID}"
"${PSQLQ[@]}" "DELETE FROM curation_packages WHERE staging_repo_id='${STAGING_ID}'" >/dev/null 2>&1
api_call DELETE "/api/v1/repositories/${REPO}" 2>/dev/null

end_suite
