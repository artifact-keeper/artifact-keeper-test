#!/usr/bin/env bash
# =============================================================================
# tiers/qxxr-refresh-race/oracle.sh — refresh-token rotation replay race (GHSA-qxxr)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, DTF_SLOT. We source common.sh for the
# assertion + JUnit harness, then drive the real HTTP + concurrency flow against
# the live backend.
#
# The bug (GHSA-qxxr): POST /api/v1/auth/refresh marks the presented refresh
# token single-use with
#     UPDATE refresh_token_jti SET consumed_at = NOW()
#     WHERE jti = $1 AND consumed_at IS NULL
# but never checked `rows_affected`. Two concurrent refreshes of the SAME token
# both read `consumed_at IS NULL`, both run the UPDATE (the loser's affects zero
# rows), and BOTH proceed to mint a fresh successor family -> one login = two
# live token families (lost-update / replay). The fix makes consume-and-rotate
# atomic: exactly one winner claims the row (rows_affected == 1) and the losers
# 401, with a benign-double-submit carve-out that does NOT revoke the family on a
# concurrent duplicate submit.
#
# Three discriminating gates, ALL must hold on the fixed image:
#   (A) RACE INVARIANT  — N concurrent refreshes of one token, R rounds (fresh
#       login each round): EXACTLY ONE 200 per round, the rest 401. RED baseline
#       yields >= 2 200s (multiple successor families). Load-bearing gate.
#   (B) NON-REVOCATION  — the concurrent winner's new refresh token still works
#       once (single refresh -> 200). A benign double-submit must not revoke the
#       family.
#   (C) GENUINE-REPLAY  — legit rotate T0->T1, consume T1->T2, then replay the
#       ORIGINAL T0 -> 401 AND the family is revoked (T1 now 401; the DB shows
#       zero non-revoked refresh_token_jti rows for the family). Real replay must
#       still nuke the family.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
USER_NAME="qxxr-user-${DTF_SLOT:-x}-${SUF}"
USER_PASS="Qxxr_${SUF}_Aa1!"

# Concurrency knobs. A single origin firing this many refreshes of one token
# reliably reproduces the lost-update race on the baseline image; the fixed
# image collapses each burst to exactly one winner regardless of fan-out.
CONC="${QXXR_CONCURRENCY:-8}"
ROUNDS="${QXXR_ROUNDS:-5}"

PSQL() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

# raw_login: POST /api/v1/auth/login, echo the raw JSON body (has access_token +
# refresh_token). Retries transient throttling/unready.
raw_login() {
  local u="$1" p="$2" i tmp code body
  for i in $(seq 1 6); do
    tmp=$(mktemp)
    code=$(curl -s $CURL_TIMEOUT -o "$tmp" -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' \
      -d "{\"username\":\"${u}\",\"password\":\"${p}\"}" \
      "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || code=000
    body=$(cat "$tmp" 2>/dev/null || true); rm -f "$tmp"
    if [ "$code" = "200" ]; then printf '%s' "$body"; return 0; fi
    [ "$code" != "429" ] && [ "$code" != "503" ] && [ "$code" != "000" ] && break
    sleep 2
  done
  printf ''; return 1
}

login_refresh_token() { raw_login "$1" "$2" | jq -r '.refresh_token // empty' 2>/dev/null; }

# refresh_once: single POST /api/v1/auth/refresh with the given token.
# Sets globals REFRESH_CODE (http status) and REFRESH_BODY (json).
refresh_once() {
  local tok="$1" tmp
  tmp=$(mktemp)
  REFRESH_CODE=$(curl -s $CURL_TIMEOUT -o "$tmp" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d "{\"refresh_token\":\"${tok}\"}" \
    "${BASE_URL}/api/v1/auth/refresh" 2>/dev/null) || REFRESH_CODE=000
  REFRESH_BODY=$(cat "$tmp" 2>/dev/null || true); rm -f "$tmp"
}

# fire_concurrent: launch CONC refreshes of the SAME token with minimal skew.
# Sets WINNERS (count of 200s), CODES (space-joined status codes) and
# WINNER_REFRESH (the .refresh_token minted by one 200 winner, if any).
fire_concurrent() {
  local tok="$1" n="$CONC" i c d
  d="$(mktemp -d)"
  printf '{"refresh_token":"%s"}' "$tok" > "${d}/payload.json"
  # Prime the connection so the burst races on the consume path, not TCP setup.
  curl -s -o /dev/null $CURL_TIMEOUT "${BASE_URL}/readyz" 2>/dev/null || true
  for i in $(seq 1 "$n"); do
    (
      code=$(curl -s -o "${d}/body.${i}" -w '%{http_code}' $CURL_TIMEOUT \
        -X POST -H 'Content-Type: application/json' \
        --data-binary @"${d}/payload.json" \
        "${BASE_URL}/api/v1/auth/refresh" 2>/dev/null) || code=000
      printf '%s' "$code" > "${d}/code.${i}"
    ) &
  done
  wait
  WINNERS=0; CODES=""; WINNER_REFRESH=""
  for i in $(seq 1 "$n"); do
    c=$(cat "${d}/code.${i}" 2>/dev/null || echo 000)
    CODES="${CODES}${c} "
    if [ "$c" = "200" ]; then
      WINNERS=$((WINNERS+1))
      WINNER_REFRESH="$(jq -r '.refresh_token // empty' "${d}/body.${i}" 2>/dev/null || true)"
    fi
  done
  CODES="${CODES% }"
  rm -rf "$d"
}

# jwt_family_id: extract the family_id claim from a refresh JWT (base64url payload).
jwt_family_id() {
  local p pad
  p="$(printf '%s' "$1" | cut -d. -f2)"
  pad=$(( ${#p} % 4 )); [ "$pad" -ne 0 ] && p="${p}$(printf '=%.0s' $(seq 1 $((4-pad))))"
  printf '%s' "$p" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r '.family_id // empty' 2>/dev/null
}

begin_suite "qxxr-refresh-token-rotation-race"

# --- setup: admin readiness + a dedicated user ------------------------------
auth_admin

USER_ID="$(create_test_user_with_retry "$USER_NAME" "$USER_PASS" "${USER_NAME}@t.test")" || true
if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
  begin_test "setup: create refresh-race test user"
  fail "could not create user ${USER_NAME}"
  end_suite
fi

# Sanity: login returns a refresh token at all.
begin_test "setup: login returns a refresh token"
T_SANITY="$(login_refresh_token "$USER_NAME" "$USER_PASS")"
if [ -n "$T_SANITY" ] && [ "$T_SANITY" != "null" ]; then
  pass
else
  fail "POST /api/v1/auth/login did not return a refresh_token for ${USER_NAME}"
  end_suite
fi

# ---------------------------------------------------------------------------
# (A) RACE INVARIANT — the load-bearing gate.
#     Each round: fresh login -> T0 (a pristine, unconsumed refresh token), then
#     fire CONC concurrent refreshes of that SAME T0. On the fixed image exactly
#     one wins (200) and the rest 401. On the baseline TWO OR MORE win (each a
#     new successor family). winners != 1 in ANY round fails the gate.
# ---------------------------------------------------------------------------
begin_test "RACE INVARIANT: ${CONC} concurrent refreshes of one token yield EXACTLY ONE 200 (x${ROUNDS} rounds); baseline mints >=2"
RACE_FAIL=""; ROUND_SUMMARY=""; LAST_WINNER_REFRESH=""
for r in $(seq 1 "$ROUNDS"); do
  T0="$(login_refresh_token "$USER_NAME" "$USER_PASS")"
  if [ -z "$T0" ] || [ "$T0" = "null" ]; then
    RACE_FAIL="round ${r}: fresh login failed (no refresh token)"; break
  fi
  # Retry a round that produced ZERO winners (pure transient/flake, not the
  # race) a couple times before trusting it; >=2 winners is the RED signal and
  # is never retried away.
  attempt=0
  while :; do
    fire_concurrent "$T0"
    if [ "$WINNERS" -ge 1 ] || [ "$attempt" -ge 2 ]; then break; fi
    attempt=$((attempt+1))
    T0="$(login_refresh_token "$USER_NAME" "$USER_PASS")"
    [ -z "$T0" ] && break
  done
  ROUND_SUMMARY="${ROUND_SUMMARY}round ${r}: winners=${WINNERS} codes=[${CODES}]
"
  if [ "$WINNERS" -gt 1 ]; then
    RACE_FAIL="round ${r}: ${WINNERS} concurrent refreshes returned 200 (>1 successor family minted) — GHSA-qxxr race present"; break
  elif [ "$WINNERS" -lt 1 ]; then
    RACE_FAIL="round ${r}: zero winners after retries (codes=[${CODES}]) — backend/concurrency broken, cannot assert invariant"; break
  fi
  [ -n "$WINNER_REFRESH" ] && LAST_WINNER_REFRESH="$WINNER_REFRESH"
done
if [ -z "$RACE_FAIL" ]; then
  pass
else
  fail "$RACE_FAIL" "concurrency=${CONC} rounds=${ROUNDS}
${ROUND_SUMMARY}"
fi

# ---------------------------------------------------------------------------
# (B) NON-REVOCATION control — a benign concurrent double-submit must NOT revoke
#     the family: the winner's freshly minted refresh token still works once.
#     Uses a dedicated fresh login so it is independent of (A)'s last round.
# ---------------------------------------------------------------------------
begin_test "NON-REVOCATION: the concurrent winner's new refresh token still refreshes once (200) — benign double-submit did not revoke the family"
T0_B="$(login_refresh_token "$USER_NAME" "$USER_PASS")"
if [ -z "$T0_B" ] || [ "$T0_B" = "null" ]; then
  fail "control setup: fresh login failed"
else
  fire_concurrent "$T0_B"
  if [ "$WINNERS" -ne 1 ]; then
    fail "control precondition failed: expected exactly one concurrent winner, got ${WINNERS} (codes=[${CODES}])"
  elif [ -z "$WINNER_REFRESH" ]; then
    fail "control precondition failed: winning 200 response carried no refresh_token"
  else
    refresh_once "$WINNER_REFRESH"
    if [ "$REFRESH_CODE" = "200" ]; then
      pass
    else
      fail "winner's new refresh token was rejected (HTTP ${REFRESH_CODE}); a benign concurrent double-submit must not revoke the family" \
           "winner_refresh follow-up code=${REFRESH_CODE} body=${REFRESH_BODY:0:200}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# (C) GENUINE-REPLAY control — real single-use replay must still nuke the whole
#     family. Legit rotate T0->T1, consume T1->T2, then replay the ORIGINAL T0.
#     Expect: T0 replay -> 401, family revoked (T1 -> 401), and the DB shows zero
#     non-revoked refresh_token_jti rows for the family.
# ---------------------------------------------------------------------------
begin_test "GENUINE-REPLAY: replaying a consumed refresh token -> 401 and revokes the family (sibling token 401 + DB shows zero non-revoked rows)"
LOGIN_JSON="$(raw_login "$USER_NAME" "$USER_PASS")"
T0_C="$(printf '%s' "$LOGIN_JSON" | jq -r '.refresh_token // empty' 2>/dev/null)"
FAM="$(jwt_family_id "$T0_C")"
if [ -z "$T0_C" ] || [ "$T0_C" = "null" ]; then
  fail "control setup: fresh login failed"
elif [ -z "$FAM" ]; then
  fail "control setup: could not extract family_id from the refresh JWT" "token_prefix=${T0_C:0:24}"
else
  # Legit rotation T0 -> T1.
  refresh_once "$T0_C"; C_ROT1="$REFRESH_CODE"; T1_C="$(printf '%s' "$REFRESH_BODY" | jq -r '.refresh_token // empty' 2>/dev/null)"
  # Consume T1 -> T2.
  refresh_once "$T1_C"; C_ROT2="$REFRESH_CODE"
  # Replay the ORIGINAL, now-consumed T0.
  refresh_once "$T0_C"; C_REPLAY="$REFRESH_CODE"
  # Sibling token from the same family must now be rejected too.
  refresh_once "$T1_C"; C_SIBLING="$REFRESH_CODE"
  NON_REVOKED="$(PSQL "SELECT count(*) FROM refresh_token_jti WHERE family_id='${FAM}' AND revoked_at IS NULL;")"

  if [ "$C_ROT1" != "200" ] || [ "$C_ROT2" != "200" ]; then
    fail "control precondition failed: legitimate rotation did not both 200 (T0->T1=${C_ROT1}, T1->T2=${C_ROT2})" \
         "family=${FAM} rot1=${C_ROT1} rot2=${C_ROT2}"
  elif [ "$C_REPLAY" != "401" ]; then
    fail "replay of consumed T0 returned ${C_REPLAY}, expected 401 (genuine replay must be rejected)" \
         "family=${FAM} replayT0=${C_REPLAY} siblingT1=${C_SIBLING} nonRevokedRows=${NON_REVOKED}"
  elif [ "$C_SIBLING" != "401" ]; then
    fail "sibling token T1 returned ${C_SIBLING} after replay, expected 401 (family must be revoked)" \
         "family=${FAM} replayT0=${C_REPLAY} siblingT1=${C_SIBLING} nonRevokedRows=${NON_REVOKED}"
  elif [ "$NON_REVOKED" != "0" ]; then
    fail "family still has ${NON_REVOKED} non-revoked refresh_token_jti rows after replay, expected 0 (whole family must be revoked)" \
         "family=${FAM} replayT0=${C_REPLAY} siblingT1=${C_SIBLING} nonRevokedRows=${NON_REVOKED}"
  else
    pass
  fi
fi

end_suite
