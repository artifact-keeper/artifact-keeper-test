#!/usr/bin/env bash
# =============================================================================
# tiers/audit-admin-denial-full-path/oracle.sh  (artifact-keeper#5603 / #5831)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR and COMMON_SH.
#
# A non-admin is refused on two admin-only routes; the PERMISSION_DENIED audit
# row each refusal writes must name the FULL request path, not the remainder
# after the `/api/v1/admin` nest. See the manifest for the bug.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SUF="${RUN_ID##*-}-$$"
NA_USER="aud-deny-${DTF_SLOT:-x}-${SUF}"
# Generated per run; nothing credential-shaped is committed.
NA_PASS="Dtf-$(openssl rand -hex 12)-Aa1"

# code METHOD PATH TOKEN -> echoes the HTTP status, body in $WORK/body
code() {
  curl -s $CURL_TIMEOUT -o "${WORK}/body" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer $3" "${BASE_URL}$2" 2>/dev/null || echo 000
}

begin_suite "audit-admin-denial-full-path"

auth_admin

NA_ID="$(create_test_user_with_retry "$NA_USER" "$NA_PASS" "${NA_USER}@t.test")" || true
if [ -z "$NA_ID" ] || [ "$NA_ID" = "null" ]; then
  begin_test "setup: create non-admin user"
  fail "could not create non-admin user ${NA_USER}"
  end_suite
fi
NA_TOKEN="$(login_as "$NA_USER" "$NA_PASS")" || true
if [ -z "$NA_TOKEN" ]; then
  begin_test "setup: log in as the non-admin user"
  fail "could not log in as ${NA_USER}"
  end_suite
fi

# denied_rows -> JSON array of this user's PERMISSION_DENIED rows (admin read)
denied_rows() {
  local c
  c="$(code GET "/api/v1/admin/audit?action=PERMISSION_DENIED&resource_id=${NA_ID}&per_page=50" "$ADMIN_TOKEN")"
  if [ "$c" = "200" ]; then jq -c '.items' "${WORK}/body" 2>/dev/null || echo '[]'; else echo '[]'; fi
}

# wait_denied N -> polls (audit writes are fire-and-forget) until the user has
# at least N PERMISSION_DENIED rows or ~15 s pass; echoes the rows.
wait_denied() {
  local want="$1" rows n i
  for i in $(seq 1 30); do
    rows="$(denied_rows)"
    n="$(printf '%s' "$rows" | jq 'length' 2>/dev/null || echo 0)"
    [ "$n" -ge "$want" ] && break
    sleep 0.5
  done
  printf '%s' "$rows"
}

# --- CONTROL: the admin passes the gate on both routes -----------------------
for p in /api/v1/admin/settings /api/v1/admin/audit; do
  begin_test "CONTROL: admin GET ${p} -> 200"
  c="$(code GET "$p" "$ADMIN_TOKEN")"
  if [ "$c" = "200" ]; then pass; else fail "admin GET ${p} returned ${c}, want 200" "$(head -c 300 "${WORK}/body")"; fi
done

# --- the two refusals --------------------------------------------------------
begin_test "CONTROL: non-admin GET /api/v1/admin/settings -> 403"
c="$(code GET /api/v1/admin/settings "$NA_TOKEN")"
if [ "$c" = "403" ]; then pass; else fail "non-admin GET /api/v1/admin/settings returned ${c}, want 403"; fi

ROWS="$(wait_denied 1)"
begin_test "CONTROL: the settings refusal wrote exactly one PERMISSION_DENIED row for the user"
n="$(printf '%s' "$ROWS" | jq 'length')"
if [ "$n" = "1" ]; then pass; else fail "PERMISSION_DENIED rows for ${NA_ID}: ${n}, want 1" "$ROWS"; fi
SETTINGS_ROW="$(printf '%s' "$ROWS" | jq -c '.[0] // {}')"

begin_test "CONTROL: the row is attributed to the user, method GET, reason admin_privileges_required"
if printf '%s' "$SETTINGS_ROW" | jq -e --arg u "$NA_ID" \
     '.user_id == $u and .resource_id == $u and .details.method == "GET"
      and .details.reason == "admin_privileges_required"' >/dev/null 2>&1; then
  pass
else
  fail "PERMISSION_DENIED row does not carry the expected actor/method/reason" "$SETTINGS_ROW"
fi

begin_test "FIX #5603: the settings refusal records details.path /api/v1/admin/settings"
got="$(printf '%s' "$SETTINGS_ROW" | jq -r '.details.path // "<none>"')"
if [ "$got" = "/api/v1/admin/settings" ]; then
  pass
else
  fail "details.path = '${got}', want '/api/v1/admin/settings' (the nest-relative remainder was recorded)" "$SETTINGS_ROW"
fi

begin_test "CONTROL: non-admin GET /api/v1/admin/audit -> 403"
c="$(code GET /api/v1/admin/audit "$NA_TOKEN")"
if [ "$c" = "403" ]; then pass; else fail "non-admin GET /api/v1/admin/audit returned ${c}, want 403"; fi

ROWS="$(wait_denied 2)"
begin_test "CONTROL: the audit refusal wrote a second PERMISSION_DENIED row for the user"
n="$(printf '%s' "$ROWS" | jq 'length')"
if [ "$n" = "2" ]; then pass; else fail "PERMISSION_DENIED rows for ${NA_ID}: ${n}, want 2" "$ROWS"; fi

begin_test "FIX #5603: the audit refusal records details.path /api/v1/admin/audit"
# Newest first; pick the row that is not the settings row.
AUDIT_ROW="$(printf '%s' "$ROWS" | jq -c --arg sid "$(printf '%s' "$SETTINGS_ROW" | jq -r '.id')" \
  '[.[] | select(.id != $sid)][0] // {}')"
got="$(printf '%s' "$AUDIT_ROW" | jq -r '.details.path // "<none>"')"
gotm="$(printf '%s' "$AUDIT_ROW" | jq -r '.details.method // "<none>"')"
if [ "$got" = "/api/v1/admin/audit" ] && [ "$gotm" = "GET" ]; then
  pass
else
  fail "details.path = '${got}' method = '${gotm}', want '/api/v1/admin/audit' GET" "$AUDIT_ROW"
fi

end_suite
