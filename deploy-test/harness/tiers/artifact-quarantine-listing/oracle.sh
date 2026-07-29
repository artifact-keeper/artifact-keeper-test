#!/usr/bin/env bash
# =============================================================================
# tiers/artifact-quarantine-listing/oracle.sh — per-artifact quarantine state
# surfaced in the repository artifacts listing (#2940)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_DIR,
# DTF_SLOT, HTTP_PORT/..., BACKEND_IMAGE, RELEASE_GATE=1, JUNIT_OUTPUT_DIR. We
# source common.sh for the assertion + JUnit harness.
#
# The gap (#2940): the repository artifacts listing returned artifacts with no
# quarantine state, so an operator/UI could not tell which listed artifacts are
# held for security review. The fix adds an always-present `quarantine_status`
# (+ `quarantine_until`) to each listing item, populated from the same
# `artifacts` row the listing query already selects (no join, no N+1).
#
# Discriminating gates, ALL must hold (RELEASE_GATE=1):
#   (A) DISCRIMINATOR  a quarantined artifact's listing item ->
#                      quarantine_status == "quarantined". Baseline: field
#                      absent -> RED.
#   (B) CONTROL        an un-held artifact's listing item ->
#                      quarantine_status == "not_quarantined" (not a hollow
#                      always-quarantined). Baseline: field absent -> RED.
#   (C) GROUNDED       DB row reads 'quarantined' AND GET /quarantine/{id}
#                      is_blocked=true (the listing reflects a real control).
#   (D) NON-DISCLOSURE anonymous public listing surfaces the state but NO
#                      quarantine_reason field (preserves #2912).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="q2940-repo-${DTF_SLOT}-${SUF}"
HELD_PATH="held/pkg-1.0.0.bin"
CLEAN_PATH="clean/pkg-1.0.0.bin"

# --- helpers ----------------------------------------------------------------
# Admin PUT of raw bytes to a repo artifact path; echoes the response body.
put_artifact() { # PATH BYTES  -> upload response JSON
  curl -s $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" \
    --data-binary "$2" \
    "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/${1}" 2>/dev/null || true
}
admin_get() { # PATH -> body (admin bearer)
  curl -s $CURL_TIMEOUT -H "$(auth_header)" "${BASE_URL}${1}" 2>/dev/null || true
}
anon_get() { # PATH -> body (no auth)
  curl -s $CURL_TIMEOUT "${BASE_URL}${1}" 2>/dev/null || true
}
# quarantine_status for a given path from a listing body.
# jq's `// empty` collapses BOTH a missing key and an explicit null to empty,
# so a pre-fix listing (no such key) reports "" and the discriminator fails RED.
status_for() { # LISTING_JSON PATH
  echo "$1" | jq -r --arg p "$2" '.items[] | select(.path==$p) | .quarantine_status // empty' 2>/dev/null || true
}
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || echo "?"; }

begin_suite "artifact-quarantine-listing"

# --- setup: admin session, a public hosted repo, two artifacts --------------
auth_admin   # sets ADMIN_TOKEN

begin_test "setup: create a public hosted generic repository"
if create_repo "$REPO" "generic" "local" >/dev/null 2>&1; then
  pass
else
  fail "could not create repo ${REPO}"
  end_suite
fi

begin_test "setup: upload two artifacts (one to be quarantined, one left clean)"
HELD_BODY="$(put_artifact "$HELD_PATH" "held-artifact-bytes-${SUF}")"
CLEAN_BODY="$(put_artifact "$CLEAN_PATH" "clean-artifact-bytes-${SUF}")"
HELD_ID="$(echo "$HELD_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
CLEAN_ID="$(echo "$CLEAN_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
if [ -n "$HELD_ID" ] && [ "$HELD_ID" != "null" ] && [ -n "$CLEAN_ID" ] && [ "$CLEAN_ID" != "null" ]; then
  pass
else
  fail "could not upload both artifacts (held='${HELD_ID}' clean='${CLEAN_ID}')" \
       "held_body=$(echo "$HELD_BODY" | head -c 300)"
  end_suite
fi

begin_test "setup: admin quarantines the held artifact (POST /quarantine/:id/quarantine)"
Q_RC="$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d '{"reason":"DTF #2940: flagged for security review"}' \
  "${BASE_URL}/api/v1/quarantine/${HELD_ID}/quarantine" 2>/dev/null || echo 000)"
if [ "$Q_RC" = "200" ]; then
  pass
else
  fail "admin quarantine call did not return 200 -> ${Q_RC}" "artifact=${HELD_ID}"
  end_suite
fi

# ---------------------------------------------------------------------------
# (A) DISCRIMINATOR — the held artifact must appear in the listing WITH its
#     quarantine state. Pre-fix the listing item has no quarantine_status key
#     (status_for -> "") so this fails RED.
# ---------------------------------------------------------------------------
LISTING="$(admin_get "/api/v1/repositories/${REPO}/artifacts")"

begin_test "DISCRIMINATOR: quarantined artifact lists with quarantine_status='quarantined' (#2940)"
HELD_ST="$(status_for "$LISTING" "$HELD_PATH")"
if [ "$HELD_ST" = "quarantined" ]; then
  pass
else
  fail "the artifacts listing does not surface per-artifact quarantine state: held artifact reports quarantine_status='${HELD_ST:-<absent>}', expected 'quarantined'. Operators cannot see which artifacts are held (#2940)." \
       "held_path=${HELD_PATH} quarantine_status=${HELD_ST:-<absent>} listing=$(echo "$LISTING" | head -c 400)"
fi

# ---------------------------------------------------------------------------
# (B) CONTROL — an un-held artifact must report the explicit not-quarantined
#     state, proving the field is populated per-row and not a hollow constant.
# ---------------------------------------------------------------------------
begin_test "CONTROL: un-held artifact lists with quarantine_status='not_quarantined' (#2940)"
CLEAN_ST="$(status_for "$LISTING" "$CLEAN_PATH")"
if [ "$CLEAN_ST" = "not_quarantined" ]; then
  pass
else
  fail "un-held artifact reports quarantine_status='${CLEAN_ST:-<absent>}', expected 'not_quarantined' (the listing must report a clear not-quarantined state for the default case, and must not be a hollow always-quarantined string)." \
       "clean_path=${CLEAN_PATH} quarantine_status=${CLEAN_ST:-<absent>}"
fi

# ---------------------------------------------------------------------------
# (C) GROUNDED — the listing string reflects a real control, not a label: the
#     DB row is really 'quarantined' and GET /quarantine/{id} reports blocked.
# ---------------------------------------------------------------------------
begin_test "GROUNDED: DB row + quarantine endpoint confirm the held artifact is really blocked"
DB_ST="$(db "SELECT quarantine_status FROM artifacts WHERE id='${HELD_ID}';")"
Q_BLOCKED="$(admin_get "/api/v1/quarantine/${HELD_ID}" | jq -r '.is_blocked // empty' 2>/dev/null || true)"
if [ "$DB_ST" = "quarantined" ] && [ "$Q_BLOCKED" = "true" ]; then
  pass
else
  fail "listing state is not grounded in the real control: db quarantine_status='${DB_ST}', GET /quarantine is_blocked='${Q_BLOCKED}' (expected 'quarantined' + 'true')" \
       "db_status=${DB_ST} is_blocked=${Q_BLOCKED}"
fi

# ---------------------------------------------------------------------------
# (D) NON-DISCLOSURE — the anonymous public listing surfaces the STATE but not
#     the reason (#2912): the reason stays behind the authenticated
#     GET /quarantine/{id} even though the state is now visible here.
# ---------------------------------------------------------------------------
begin_test "NON-DISCLOSURE: anonymous public listing shows quarantine state but NO reason (#2912 preserved)"
ANON_LISTING="$(anon_get "/api/v1/repositories/${REPO}/artifacts")"
ANON_ST="$(status_for "$ANON_LISTING" "$HELD_PATH")"
HAS_REASON="$(echo "$ANON_LISTING" | jq -r '[.items[] | has("quarantine_reason")] | any' 2>/dev/null || echo unknown)"
if [ "$ANON_ST" = "quarantined" ] && [ "$HAS_REASON" = "false" ]; then
  pass
else
  fail "anonymous listing disclosure mismatch: state='${ANON_ST:-<absent>}' (expected 'quarantined'), any item exposes quarantine_reason='${HAS_REASON}' (expected 'false' — the reason must stay behind the authenticated quarantine endpoint, #2912)" \
       "anon_status=${ANON_ST:-<absent>} has_reason=${HAS_REASON}"
fi

end_suite
