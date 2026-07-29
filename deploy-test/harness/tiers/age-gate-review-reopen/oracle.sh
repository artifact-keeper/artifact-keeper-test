#!/usr/bin/env bash
# =============================================================================
# tiers/age-gate-review-reopen/oracle.sh — reopen/re-decide age-gate reviews (#2939)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP flow against the backend.
#
# Gates:
#   (REOPEN-ROUTE) POST /api/v1/admin/age-gate/reviews/{id}/reopen on an approved
#                  review -> 200 and status flips to `pending`. Pre-#2939 the
#                  route is absent -> empty-body 404 -> RED.
#   (ENFORCE)      the served npm packument flips with the decision: approved ->
#                  version SERVED; after reopen -> BLOCKED; after reject ->
#                  BLOCKED; after re-approve (re-decide the rejected review) ->
#                  SERVED. Pre-#2939 the review is terminal so it never flips.
#   (AUTHZ)        anonymous reopen -> 401.
#
# Egress: the age gate only holds versions it can prove are "young", which means
# fetching the real upstream packument. This tier needs egress to
# registry.npmjs.org, like the other proxy tiers. `is-odd` is a frozen package
# whose newest releases are well under the 3650-day (max) threshold, so at least
# one version is always held; the target version is picked dynamically from the
# pending queue so the tier survives version aging.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="agr-npm-${DTF_SLOT:-x}-${SUF}"
PKG="is-odd"

begin_suite "age-gate-review-reopen-2939"

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

# Is version $1 present in the (freshly proxied) packument? echoes SERVED|BLOCKED.
served_state() { # VERSION
  local ver="$1" tmp state
  tmp=$(mktemp)
  curl -s -o "$tmp" -H "$(auth_header)" "${BASE_URL}/npm/${REPO}/${PKG}" 2>/dev/null
  if jq -e --arg v "$ver" '.versions[$v]' "$tmp" >/dev/null 2>&1; then
    state="SERVED"
  else
    state="BLOCKED"
  fi
  rm -f "$tmp"; echo "$state"
}

# --- setup: remote npm repo with the age gate turned all the way up ----------
create_repo "$REPO" "npm" "remote" "https://registry.npmjs.org"
api_call PUT "/api/v1/repositories/${REPO}/age-gate" '{"enabled":true,"min_age_days":3650}'

# Prime the gate: proxying the packument enqueues reviews for held versions.
served_state "0.0.0" >/dev/null   # discard; this pull populates the review queue

# --- pick a held version dynamically -----------------------------------------
begin_test "SETUP: age gate holds >=1 young version and enqueues a pending review"
api_call GET "/api/v1/admin/age-gate/reviews?repository_key=${REPO}&status=pending&per_page=100"
RID="$(echo "$API_BODY" | jq -r '.items[0].id // empty' 2>/dev/null || true)"
VER="$(echo "$API_BODY" | jq -r '.items[0].package_version // empty' 2>/dev/null || true)"
if [ "$API_STATUS" = "200" ] && [ -n "$RID" ] && [ -n "$VER" ]; then
  pass
else
  fail "no pending age-gate review was created for ${PKG} (status=${API_STATUS}); the gate did not engage — check upstream egress or bump min_age_days if every version has aged past the threshold" \
       "reviews=$(echo "$API_BODY" | head -c 400)"
  end_suite
fi

begin_test "BLOCKED baseline: held version ${VER} is withheld from the packument"
[ "$(served_state "$VER")" = "BLOCKED" ] && pass || \
  fail "held version ${VER} was served even though its review is pending"

# --- approve so we have a genuinely terminal review to reopen ----------------
begin_test "SETUP: approve ${VER} -> proxy now serves it"
api_call POST "/api/v1/admin/age-gate/reviews/${RID}/approve" '{"reason":"agr setup approve"}'
if [ "$API_STATUS" = "200" ] && [ "$(served_state "$VER")" = "SERVED" ]; then
  pass
else
  fail "approve did not unblock ${VER}: status=${API_STATUS}" "resp=${API_BODY}"
fi

# --- (REOPEN-ROUTE) the #2939 discriminator ----------------------------------
begin_test "REOPEN: POST .../reopen on an approved review -> 200 + status=pending"
api_call POST "/api/v1/admin/age-gate/reviews/${RID}/reopen" '{"reason":"agr turned out bad"}'
RSTATUS="$(echo "$API_BODY" | jq -r '.status // empty' 2>/dev/null || true)"
if [ "$API_STATUS" = "200" ] && [ "$RSTATUS" = "pending" ]; then
  pass
else
  fail "reopen did not move the review back to pending: http=${API_STATUS} status='${RSTATUS}' (pre-#2939 the route is absent -> empty-body 404)" \
       "resp=$(echo "$API_BODY" | head -c 300)"
fi

begin_test "ENFORCE: reopening re-blocks ${VER} on the next pull"
[ "$(served_state "$VER")" = "BLOCKED" ] && pass || \
  fail "reopened (pending) version ${VER} is still being served; enforcement did not flip"

# --- (ENFORCE) re-decide: reject re-blocks, then re-approve unblocks ----------
begin_test "REJECT: reject the reopened review -> 200 + ${VER} stays blocked"
api_call POST "/api/v1/admin/age-gate/reviews/${RID}/reject" '{"reason":"agr confirmed bad"}'
if [ "$API_STATUS" = "200" ] && [ "$(served_state "$VER")" = "BLOCKED" ]; then
  pass
else
  fail "reject did not keep ${VER} blocked: status=${API_STATUS}" "resp=${API_BODY}"
fi

begin_test "RE-DECIDE: approve a REJECTED review -> 200 + ${VER} served again"
api_call POST "/api/v1/admin/age-gate/reviews/${RID}/approve" '{"reason":"agr now fine"}'
ASTATUS="$(echo "$API_BODY" | jq -r '.status // empty' 2>/dev/null || true)"
if [ "$API_STATUS" = "200" ] && [ "$ASTATUS" = "approved" ] && [ "$(served_state "$VER")" = "SERVED" ]; then
  pass
else
  fail "re-approving a rejected review failed: http=${API_STATUS} status='${ASTATUS}' (pre-#2939 approve requires pending -> 400)" \
       "resp=$(echo "$API_BODY" | head -c 300)"
fi

# --- (AUTHZ) anonymous reopen is refused -------------------------------------
begin_test "AUTHZ: anonymous reopen -> 401"
ANON=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -d '{"reason":"x"}' \
  "${BASE_URL}/api/v1/admin/age-gate/reviews/${RID}/reopen" 2>/dev/null) || ANON=000
[ "$ANON" = "401" ] && pass || fail "anonymous reopen returned ${ANON}, expected 401"

# --- cleanup -----------------------------------------------------------------
api_call DELETE "/api/v1/repositories/${REPO}" 2>/dev/null || true

end_suite
