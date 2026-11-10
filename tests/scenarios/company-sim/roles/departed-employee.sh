#!/usr/bin/env bash
# roles/departed-employee.sh - Leo Varga, web engineer at Halcyon Robotics,
# on his last morning.
#
# Leo does ordinary npm work with every credential a developer accumulates:
# a session JWT, two refresh tokens, the personal token the founder minted
# (HAL_WEB_DEV_TOKEN), a laptop token he mints himself, his password, an OCI
# registry token, and two download tickets. He signals "leo-worked". The
# platform-admin role deactivates him, takes him out of HAL-web and revokes
# his tokens, then signals "leo-offboarded". After that every credential he
# held must answer 401 on REST, native-format and OCI routes. A presented but
# dead credential must never be served as an anonymous caller (#1371).
#
# Spec: ROLES.md "## departed-employee". Barriers: signals leo-worked, waits
# leo-offboarded (CS_BARRIER_TIMEOUT, default 600 s), signals leo-verified
# after the admin read-back (web deletes Leo's package only after it).
#
# Objects this role creates and cannot delete itself (Leo has no delete
# grant, and after offboarding no access at all):
#   - npm package ${HAL}-web-leo-widget in HAL-web-npm-local (web #12 deletes
#     it after leo-verified; on a replay with the package already there,
#     the morning publishes a run-unique prerelease instead of 1.0.0);
#   - personal token ${HAL}-leo-laptop (platform-admin #5 revokes it; the
#     next run revokes and re-mints it by name).
#
# Run alone: bash tests/scenarios/company-sim/run-roles.sh --only departed-employee
# (the leo-offboarded barrier then times out unless platform-admin runs too).

source "$(dirname "$0")/../lib.sh"

cs_begin departed-employee
# Barriers this role signals: released as "failed" if it exits early.
cs_signals leo-worked leo-verified
# The bootstrap admin is used only for read-backs after offboarding (Leo's
# account state, and that his post-offboarding publish wrote nothing).
auth_admin

BARRIER_TIMEOUT="${CS_BARRIER_TIMEOUT:-600}"
PKG="${HAL}-web-leo-widget"
VIRT="$HAL_REPO_WEB_NPM"
LOCAL="$HAL_REPO_WEB_NPM_LOCAL"
NOW=$(date +%s)

# ---------------------------------------------------------------------------
# Morning 1-2: sign in, keep the JWT and the refresh token
# ---------------------------------------------------------------------------
LEO_REFRESH=""
if cs_login WEB_DEV; then
  LEO_REFRESH=$(cs_json '.refresh_token // empty')
  cs_record "Leo signs in (POST /api/v1/auth/login)" PASS "HTTP 200, JWT issued"
else
  cs_record "Leo signs in (POST /api/v1/auth/login)" FAIL \
    "login HTTP ${CS_STATUS}; Leo is inactive or his password changed, so platform-admin offboarded him in an earlier run and 00-found-company.sh has not re-activated him since" \
    "${CS_BODY:0:300}"
fi
# shellcheck disable=SC2034  # read through cs_http token:LEO_JWT
LEO_JWT="${CS_JWT[WEB_DEV]:-}"
if [ -n "$LEO_REFRESH" ]; then
  cs_record "login body carries a refresh_token" PASS "kept for the post-offboarding check"
else
  cs_record "login body carries a refresh_token" FAIL "no refresh_token in the login answer" "${CS_BODY:0:300}"
fi

# A second session whose refresh token Leo uses this morning: proves the
# refresh grant works for him while he is active, and the rotated token it
# returns is one more credential that must die with the account.
LEO_REFRESH2=""
cs_http POST /api/v1/auth/login none -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$HAL_WEB_DEV_USER" --arg p "$HAL_WEB_DEV_PASS" '{username:$u,password:$p}')"
r0=$(cs_json '.refresh_token // empty')
if [ -n "$r0" ]; then
  cs_http POST /api/v1/auth/refresh none -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg t "$r0" '{refresh_token:$t}')"
  cs_expect "refresh grant works while Leo is active (POST /api/v1/auth/refresh)" 200
  LEO_REFRESH2=$(cs_json '.refresh_token // empty')
else
  cs_record "refresh grant works while Leo is active (POST /api/v1/auth/refresh)" FAIL \
    "second login HTTP ${CS_STATUS} gave no refresh_token" "${CS_BODY:0:300}"
fi

# ---------------------------------------------------------------------------
# Morning: Leo mints a token for his laptop (self-service)
# ---------------------------------------------------------------------------
# shellcheck disable=SC2034  # read through cs_http token:/basictoken: specs
LEO_LAPTOP_TOKEN=""
if cs_mint_user_token WEB_DEV "${HAL}-leo-laptop" '["read:artifacts","write:artifacts"]'; then
  # shellcheck disable=SC2034
  LEO_LAPTOP_TOKEN="$CS_TOKEN"
  cs_record "Leo mints personal token ${HAL}-leo-laptop (POST /api/v1/users/me/tokens)" PASS "HTTP ${CS_STATUS}"
else
  cs_record "Leo mints personal token ${HAL}-leo-laptop (POST /api/v1/users/me/tokens)" FAIL \
    "HTTP ${CS_STATUS}, no token in the answer" "${CS_BODY:0:300}"
fi

# ---------------------------------------------------------------------------
# Morning 3: publish ${HAL}-web-leo-widget with the founder-minted token as
# npm Basic. Replay-safe: Leo cannot delete, so if an earlier run's 1.0.0 is
# still there he publishes a run-unique prerelease. The post-offboarding
# version is picked the same way so "absent" is never satisfied by accident.
# ---------------------------------------------------------------------------
cs_http GET "/npm/${LOCAL}/${PKG}" jwt:WEB_DEV
have_versions=$(cs_json '.versions // {} | keys | join(" ")')
MORNING_VER="1.0.0"; POST_VER="1.0.1"
case " $have_versions " in *" 1.0.0 "*) MORNING_VER="1.0.0-r${NOW}" ;; esac
case " $have_versions " in *" 1.0.1 "*) POST_VER="1.0.1-r${NOW}" ;; esac

cs_publish_npm "$LOCAL" "$PKG" "$MORNING_VER" basictoken:WEB_DEV:HAL_WEB_DEV_TOKEN
if [ "$CS_STATUS" = "200" ]; then
  cs_record "Leo publishes ${PKG}@${MORNING_VER} with his personal token as npm Basic" PASS "HTTP ${CS_STATUS}"
else
  cs_record "Leo publishes ${PKG}@${MORNING_VER} with his personal token as npm Basic" FAIL \
    "expected 200, got ${CS_STATUS} (${CS_LAST_REQ}); A:1487-1508 accepts Basic user:<api_token> on native routes" \
    "${CS_BODY:0:600}"
fi

# Morning 4: read it back through the virtual with the JWT.
cs_http GET "/npm/${VIRT}/${PKG}" jwt:WEB_DEV
if cs_expect "Leo reads ${PKG} through the virtual ${VIRT} with his JWT" 200; then
  cs_expect_body "virtual packument lists ${MORNING_VER}" "\"${MORNING_VER}\""
fi

# ---------------------------------------------------------------------------
# Morning baselines: every credential works now, so each 401 later is caused
# by the offboarding and not by a wrong route or form.
# ---------------------------------------------------------------------------
cs_http GET /api/v1/users/me jwt:WEB_DEV
cs_expect "baseline: JWT on REST /users/me" 200
cs_http GET "/api/v1/repositories/${LOCAL}" token:HAL_WEB_DEV_TOKEN
cs_expect "baseline: personal token (Bearer) on REST repository detail" 200
cs_http GET "/api/v1/repositories/${LOCAL}" token:LEO_LAPTOP_TOKEN
cs_expect "baseline: laptop token (Bearer) on REST repository detail" 200
cs_http GET "/npm/${VIRT}/${PKG}" basic:WEB_DEV
cs_expect "baseline: Basic password on native npm read" 200
cs_http GET "/npm/${VIRT}/${PKG}" basictoken:WEB_DEV:LEO_LAPTOP_TOKEN
cs_expect "baseline: laptop token as npm Basic on native read" 200
cs_http GET "/v2/token" basictoken:WEB_DEV:HAL_WEB_DEV_TOKEN
cs_expect "baseline: docker login (/v2/token) with Basic user:token" 200
cs_http GET "/v2/token" jwt:WEB_DEV
cs_expect "baseline: /v2/token Bearer JWT swap" 200
# /v2/ (version_check, H/oci_v2.rs:5971-6024) takes a Bearer JWT or Basic
# (password, API token, JWT); a Bearer API token is not one of them.
cs_http GET "/v2/" basictoken:WEB_DEV:HAL_WEB_DEV_TOKEN
cs_expect "baseline: OCI /v2/ with Basic user:token" 200
cs_http GET "/v2/" token:LEO_JWT
cs_expect "baseline: OCI /v2/ with the JWT (Bearer)" 200
# An OCI content route with the personal token as Bearer (H/oci_v2.rs:460-494).
# Leo has no grant on the ops registry, so a live Leo is told NAME_UNKNOWN.
OCI_PROBE="/v2/${HAL_REPO_OPS_DOCKER}/leo-probe/tags/list"
cs_http GET "$OCI_PROBE" token:HAL_WEB_DEV_TOKEN
if cs_expect "baseline: OCI tags/list on a repo Leo cannot read (personal token Bearer)" 404; then
  cs_expect_body "baseline: OCI refusal is NAME_UNKNOWN (H/oci_v2.rs:834-907)" "NAME_UNKNOWN"
fi

# Download tickets (POST /api/v1/auth/ticket, H/auth.rs:1112, 30 s TTL,
# single use). T1 proves a ticket reads the package now; T2 is minted last,
# right before the barrier, and redeemed first after it.
mint_ticket() {
  cs_http POST /api/v1/auth/ticket jwt:WEB_DEV -H 'Content-Type: application/json' -d '{"purpose":"download"}'
  CS_TICKET=$(cs_json '.ticket // empty')
}
mint_ticket
T1="$CS_TICKET"
if [ -n "$T1" ]; then
  cs_record "Leo mints a download ticket (POST /api/v1/auth/ticket)" PASS "HTTP ${CS_STATUS}"
  cs_http GET "/npm/${VIRT}/${PKG}?ticket=${T1}" none
  cs_expect "baseline: download ticket reads ${PKG} through the virtual" 200
else
  cs_record "Leo mints a download ticket (POST /api/v1/auth/ticket)" FAIL "HTTP ${CS_STATUS}, no ticket" "${CS_BODY:0:300}"
fi

# ---------------------------------------------------------------------------
# Morning 5: signal leo-worked, wait for leo-offboarded
# ---------------------------------------------------------------------------
mint_ticket
T2="$CS_TICKET"; T2_AT=$(date +%s)
[ -n "$T2" ] || cs_record "Leo mints a second download ticket to hold over the offboarding" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:300}"

cs_signal leo-worked
if ! cs_wait leo-offboarded "$BARRIER_TIMEOUT"; then
  cs_record "waited for leo-offboarded" FAIL "${CS_WAIT_WHY}; every post-offboarding check skipped"
  cs_record "post-offboarding credential checks" SKIP "depend on leo-offboarded"
  cs_end
fi

# ---------------------------------------------------------------------------
# 13 (VERIFY): the ticket minted before he left. Redeemed first because of
# its 30 s TTL. try_resolve_ticket_auth loads the owner with
# "WHERE id = $1 AND is_active = true" (A:1661), so a live ticket of a
# deactivated user authenticates nothing; on a private repo the request is
# then anonymous, which is 401 (A:3231-3250).
# ---------------------------------------------------------------------------
if [ -n "$T2" ]; then
  cs_http GET "/npm/${VIRT}/${PKG}?ticket=${T2}" none
  age=$(( $(date +%s) - T2_AT ))
  cs_expect "13 pre-offboarding download ticket on native read" 401 "ticket ${age}s old; A:1661 requires is_active"
  if [ "$age" -lt 30 ]; then
    cs_record "13 ticket refusal is the deactivation check, not the TTL" PASS \
      "ticket was ${age}s old (< 30 s TTL, H/auth.rs:1141), so the is_active filter refused it"
  else
    cs_record "13 ticket refusal is the deactivation check, not the TTL" SKIP \
      "ticket was ${age}s old (>= 30 s TTL): the offboarding took longer than a ticket lives, so expiry and deactivation cannot be told apart"
  fi
fi

# Read-back (admin): the account really is inactive. Context for every 401.
cs_http GET "/api/v1/users/${HAL_WEB_DEV_ID}" admin
if [ "$(cs_json '.is_active')" = "false" ]; then
  cs_record "read-back: Leo is_active=false" PASS "HTTP ${CS_STATUS}"
else
  cs_record "read-back: Leo is_active=false" FAIL \
    "leo-offboarded was signalled but GET /api/v1/users/{id} as admin shows is_active=$(cs_json '.is_active') (HTTP ${CS_STATUS})" "${CS_BODY:0:300}"
fi

# check_401 WHAT : the last answer is 401 and carries no data. The body test
# catches an anonymous downgrade that kept the status but leaked content.
check_401() {
  local what="$1" note="${2:-}"
  if cs_expect "$what" 401 "$note"; then
    if printf '%s' "$CS_BODY" | grep -qF -- "$PKG"; then
      cs_record "${what}: no package data in the 401" FAIL "401 body names ${PKG}" "${CS_BODY:0:300}"
    fi
  fi
}

# ---------------------------------------------------------------------------
# 6-7: the old JWT
# ---------------------------------------------------------------------------
cs_http GET /api/v1/users/me "token:LEO_JWT"
check_401 "6 old JWT on REST /users/me" "S/auth_service.rs:990-1015"
cs_http GET "/npm/${VIRT}/${PKG}" "token:LEO_JWT"
check_401 "7 old JWT on native npm read (not an anonymous 404, #1371)" "A:3203-3207"
cs_http GET "/api/v1/repositories?per_page=100" "token:LEO_JWT"
check_401 "old JWT on optional-auth REST list (not the anonymous public list, #1371)" "A:1807-1817"
cs_http GET "/api/v1/repositories/${HAL_REPO_HANDBOOK}" "token:LEO_JWT"
check_401 "old JWT on the internal handbook (REST)" "VIS: internal needs a resolved principal"
cs_http GET "/v2/token" "token:LEO_JWT"
check_401 "old JWT on /v2/token Bearer swap" "H/oci_v2.rs:5603-5628"

# ---------------------------------------------------------------------------
# 8-9: personal tokens (founder-minted and self-minted), every form
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories/${LOCAL}" token:HAL_WEB_DEV_TOKEN
check_401 "8 personal token Bearer on REST repository detail" "S/auth_service.rs:1039"
cs_http GET "/api/v1/repositories/${LOCAL}" none -H "X-API-Key: ${HAL_WEB_DEV_TOKEN}"
check_401 "personal token as X-API-Key on REST repository detail" "S/auth_service.rs:1039"
cs_http GET "/api/v1/repositories?per_page=100" token:HAL_WEB_DEV_TOKEN
check_401 "personal token on optional-auth REST list (not the anonymous list, #1371)" "A:1807-1817"
cs_http GET "/api/v1/repositories/${LOCAL}" token:LEO_LAPTOP_TOKEN
check_401 "laptop token Bearer on REST repository detail" "S/auth_service.rs:1039"
cs_http GET "/npm/${VIRT}/${PKG}" basictoken:WEB_DEV:HAL_WEB_DEV_TOKEN
check_401 "personal token as npm Basic on native read" "A:3203-3207"
cs_http GET "/npm/${VIRT}/${PKG}" token:LEO_LAPTOP_TOKEN
check_401 "laptop token Bearer on native read" "A:3203-3207"

cs_publish_npm "$LOCAL" "$PKG" "$POST_VER" basictoken:WEB_DEV:HAL_WEB_DEV_TOKEN
check_401 "9 publish ${PKG}@${POST_VER} with the personal token as npm Basic" "A:3203-3207"
cs_publish_npm "$LOCAL" "$PKG" "$POST_VER" token:LEO_LAPTOP_TOKEN
check_401 "publish ${PKG}@${POST_VER} with the laptop token as Bearer" "A:3203-3207"
_cs_work
printf 'leo was here\n' > "${CS_WORK}/leo-note.txt"
cs_put_generic "$LOCAL" "leo-after/${NOW}.txt" "${CS_WORK}/leo-note.txt" token:HAL_WEB_DEV_TOKEN
check_401 "REST PUT .../artifacts with the personal token" "A:1807-1817"

# ---------------------------------------------------------------------------
# Password (Basic) on REST and native, and 10: re-login
# ---------------------------------------------------------------------------
cs_http GET /api/v1/users/me basic:WEB_DEV
check_401 "Basic user:password on REST /users/me" "S/auth_service.rs:1759 (is_active)"
cs_http GET "/npm/${VIRT}/${PKG}" basic:WEB_DEV
check_401 "Basic user:password on native npm read" "A:3203-3207"

cs_http POST /api/v1/auth/login none -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$HAL_WEB_DEV_USER" --arg p "$HAL_WEB_DEV_PASS" '{username:$u,password:$p}')"
leo_login_status="$CS_STATUS"; leo_login_body="$CS_BODY"
check_401 "10 Leo password login" "S/auth_service.rs:1396, 1683, 1759"
code=$(cs_json '.code'); msg=$(cs_json '.message')
if [ "$code" = "AUTH_ERROR" ] && [ "$msg" = "Invalid username or password" ]; then
  cs_record "10 login refusal body is the generic AUTH_ERROR" PASS "code=${code}"
else
  cs_record "10 login refusal body is the generic AUTH_ERROR" FAIL \
    "expected {code:AUTH_ERROR,message:Invalid username or password}, got code=${code} message=${msg}" "${leo_login_body:0:300}"
fi
# Same answer as a wrong password for a live colleague (Jun). A correct login
# right after resets Jun's failed-attempt counter, so repeated replays never
# reach the lockout threshold (S/auth_service.rs:1892-1900).
cs_http POST /api/v1/auth/login none -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$HAL_WEB_LEAD_USER" '{username:$u,password:"definitely-not-the-password"}')"
if [ "$CS_STATUS" = "$leo_login_status" ] && [ "$CS_BODY" = "$leo_login_body" ]; then
  cs_record "10 deactivated login is indistinguishable from a wrong password" PASS "both HTTP ${CS_STATUS}, identical body"
else
  cs_record "10 deactivated login is indistinguishable from a wrong password" FAIL \
    "Leo: HTTP ${leo_login_status} ${leo_login_body:0:120}; wrong password for ${HAL_WEB_LEAD_USER}: HTTP ${CS_STATUS} ${CS_BODY:0:120}"
fi
cs_http POST /api/v1/auth/login none -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$HAL_WEB_LEAD_USER" --arg p "$HAL_WEB_LEAD_PASS" '{username:$u,password:$p}')"

# ---------------------------------------------------------------------------
# 11: refresh tokens (families revoked on deactivation, H/users.rs:564-574)
# ---------------------------------------------------------------------------
if [ -n "$LEO_REFRESH" ]; then
  cs_http POST /api/v1/auth/refresh none -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg t "$LEO_REFRESH" '{refresh_token:$t}')"
  check_401 "11 unused refresh token from the morning login" "H/users.rs:564-574"
fi
if [ -n "$LEO_REFRESH2" ]; then
  cs_http POST /api/v1/auth/refresh none -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg t "$LEO_REFRESH2" '{refresh_token:$t}')"
  check_401 "rotated refresh token from the morning refresh" "H/users.rs:564-574"
fi

# ---------------------------------------------------------------------------
# 12: docker login and OCI content route
# ---------------------------------------------------------------------------
cs_http GET "/v2/token" basictoken:WEB_DEV:HAL_WEB_DEV_TOKEN
check_401 "12 docker login (/v2/token) with Basic user:token" "H/oci_v2.rs:5603-5628"
if [ "$(cs_json '.errors[0].code')" != "UNAUTHORIZED" ]; then
  cs_record "12 /v2/token refusal code is UNAUTHORIZED" FAIL "errors[0].code=$(cs_json '.errors[0].code')" "${CS_BODY:0:300}"
else
  cs_record "12 /v2/token refusal code is UNAUTHORIZED" PASS "no anonymous pull token issued"
fi
cs_http GET "/v2/token" basic:WEB_DEV
check_401 "docker login (/v2/token) with Basic user:password" "H/oci_v2.rs:5563-5781"
cs_http POST "/v2/token" none -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=password" --data-urlencode "username=${HAL_WEB_DEV_USER}" \
  --data-urlencode "password=${HAL_WEB_DEV_PASS}"
check_401 "docker OAuth2 password grant (POST /v2/token form)" "H/oci_v2.rs:5563-5781 (#894)"
cs_http GET "/v2/" basictoken:WEB_DEV:HAL_WEB_DEV_TOKEN
check_401 "OCI /v2/ with Basic user:token" "H/oci_v2.rs:5971-6024"
cs_http GET "/v2/" token:LEO_JWT
check_401 "OCI /v2/ with the old JWT (Bearer)" "H/oci_v2.rs:271-284"
cs_http GET "$OCI_PROBE" token:HAL_WEB_DEV_TOKEN
check_401 "OCI tags/list with the personal token: 401, no longer NAME_UNKNOWN" "H/oci_v2.rs:460-494"
cs_http GET "$OCI_PROBE" token:LEO_JWT
check_401 "OCI tags/list with the old JWT" "H/oci_v2.rs:449-453"

# ---------------------------------------------------------------------------
# Read-back (admin): nothing Leo tried after offboarding was written.
# ---------------------------------------------------------------------------
cs_http GET "/npm/${LOCAL}/${PKG}" admin
if [ "$CS_STATUS" = "200" ]; then
  cs_expect_no_body "read-back: ${PKG}@${POST_VER} is absent from ${LOCAL}" "\"${POST_VER}\""
  cs_expect_body "read-back: ${PKG}@${MORNING_VER} is still served (deactivation removes access, not content)" "\"${MORNING_VER}\""
else
  cs_record "read-back: ${PKG}@${POST_VER} is absent from ${LOCAL}" FAIL "admin packument read HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
fi
cs_http GET "/api/v1/repositories/${LOCAL}/artifacts/leo-after/${NOW}.txt" admin
cs_expect "read-back: REST artifact leo-after/${NOW}.txt was not written" 404

# Leo's package has been read back; web #11-12 may now read and delete it.
cs_signal leo-verified

cs_end
