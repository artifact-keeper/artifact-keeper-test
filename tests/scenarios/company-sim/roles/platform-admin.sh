#!/usr/bin/env bash
# roles/platform-admin.sh - Priya Raman, platform admin (instance admin) at
# Halcyon Robotics. Spec: ROLES.md "## platform-admin".
#
# Priya reviews the org, offboards Leo (web engineer) once he has finished
# his last morning, ends the contractor's engagement once Nina is done, runs
# a short-lived incident repository, and checks the limits of her own admin
# power (deprecated roles endpoint, admin-scoped tokens, self-delete).
#
# Barriers: waits leo-worked, nina-done; signals leo-offboarded,
# nina-offboarded. Timeout per barrier: CS_BARRIER_TIMEOUT (default 600 s).
#
# Changes to shared state this role owns (ROLES.md): Leo is deactivated,
# removed from the web group and his tokens revoked; Nina's repository rule
# is deleted. 00-found-company.sh restores both on a re-run.
#
# Objects it creates and removes again: user ${HAL}-padmin-probe, token
# ${HAL}-padmin-script, token ${HAL}-padmin-narrow, repository
# ${HAL}-ops-incident-<epoch>. Left behind: audit rows, and the incident
# repository's delete job (the repository itself is gone).
#
# The deprecated-role check needs the id of the built-in `developer` role.
# No API lists roles (only GET /api/v1/users/{id}/roles, per user), so it is
# looked up from HAL_DEVELOPER_ROLE_ID, then from any user's role list, then
# read-only from the database when AK_PG_URL and psql are available.

# shellcheck disable=SC2034  # token and PROBE vars are read indirectly by cs_http (token:VAR, jwt:PROBE)
source "$(dirname "$0")/../lib.sh"

cs_begin platform-admin
# Barriers this role signals: released as "failed" if it exits early.
cs_signals leo-offboarded nina-offboarded

BARRIER_TIMEOUT="${CS_BARRIER_TIMEOUT:-600}"
P=PADMIN
J="jwt:${P}"
JSON=(-H 'Content-Type: application/json')

# jq filter: RFC 3339 timestamp -> epoch seconds (fraction dropped).
jq_epoch='sub("\\.[0-9]+";"") | sub("\\+00:00$";"Z") | fromdateiso8601'

# ---------------------------------------------------------------------------
# 1. Sign in, confirm admin
# Expected: 200, is_admin true (H/users.rs get_current_user_record)
# ---------------------------------------------------------------------------
if ! cs_login "$P"; then
  cs_record "Priya signs in" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
  cs_end
fi
cs_http GET /api/v1/users/me "$J"
if cs_expect "1 Priya reads her own record (users/me)" 200; then
  if [ "$(cs_json '.is_admin')" = "true" ] && [ "$(cs_json '.username')" = "$HAL_PADMIN_USER" ]; then
    cs_record "1 Priya is an instance admin" PASS "is_admin true, username ${HAL_PADMIN_USER}"
  else
    cs_record "1 Priya is an instance admin" FAIL "is_admin=$(cs_json '.is_admin') username=$(cs_json '.username')" "${CS_BODY:0:300}"
  fi
fi

# ---------------------------------------------------------------------------
# 2. Review the org: list Halcyon users
# Expected: 200, exactly the 12 founded users plus the CI service account,
# the SA flagged is_service_account (H/users.rs:255-263, #3634). A
# throwaway user another role creates (${HAL}-<role>-...) is tolerated and
# named in the note.
# ---------------------------------------------------------------------------
PERSONAS=(PADMIN FW_LEAD FW_DEV WEB_LEAD WEB_DEV DATA_LEAD DATA_DEV OPS_LEAD SEC_LEAD SEC_ANALYST CONTRACTOR AUDITOR)
want_humans=$(for k in "${PERSONAS[@]}"; do cs_user "$k"; echo; done | jq -R . | jq -sc 'map(select(.!=""))|sort')
cs_http GET "/api/v1/users?search=${HAL}&per_page=100" "$J"
if cs_expect "2 Priya lists the ${HAL} users" 200; then
  # search=${HAL} also matches another company founded on this instance
  # whose HAL has ours as a prefix (hal-company vs hal-company-int). Its
  # founded users carry email <first>@<its HAL>.halcyon.test and its CI
  # account is svc-<its HAL>-ci: set those aside, keep everything else.
  others='def other: ((.email // "") | test("@hal-[a-z0-9-]+\\.halcyon\\.test$")) and (((.email // "") | endswith("@" + $hal + ".halcyon.test")) | not);
          def other_sa: .is_service_account and (.username != $sa) and (.username | test("^svc-" + $hal + "-.+-ci$"));
          [.items[] | select((other or other_sa) | not)]'
  in_org=$(printf '%s' "$CS_BODY" | jq -c --arg hal "$HAL" --arg sa "$HAL_CI_SA_USER" "$others" 2>/dev/null || echo '[]')
  have_humans=$(jq -c '[.[] | select(.is_service_account|not) | .username] | sort' <<<"$in_org")
  have_sa=$(jq -c '[.[] | select(.is_service_account) | .username] | sort' <<<"$in_org")
  missing=$(jq -nc --argjson w "$want_humans" --argjson h "$have_humans" '$w - $h')
  extra=$(jq -nc --argjson w "$want_humans" --argjson h "$have_humans" '$h - $w')
  role_re="^${HAL}-(padmin|platform-admin|firmware|fw|web|data|devops|ops|security|sec|contractor|auditor|ci|departed|departed-employee)-"
  extra_unexpected=$(jq -nc --argjson e "$extra" --arg re "$role_re" '[$e[] | select(test($re)|not)]')
  sa_want=$(jq -nc --arg s "$HAL_CI_SA_USER" '[$s]')
  if [ "$missing" = "[]" ] && [ "$extra_unexpected" = "[]" ] && [ "$have_sa" = "$sa_want" ]; then
    cs_record "2 the org is the 12 founded users plus svc CI (is_service_account)" PASS \
      "12 humans, SA ${HAL_CI_SA_USER}; role throwaways present: ${extra}"
  else
    cs_record "2 the org is the 12 founded users plus svc CI (is_service_account)" FAIL \
      "missing=${missing} unexpected=${extra_unexpected} service_accounts=${have_sa} (want ${sa_want})" "${CS_BODY:0:600}"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Review the web group: members are jun and leo (group detail, #4027)
# ---------------------------------------------------------------------------
web_members() { cs_json '[.members[]?.username] | sort | tostring'; }
cs_http GET "/api/v1/groups/${HAL_GROUP_WEB_ID}?member_limit=200" "$J"
if cs_expect "3 Priya reads the ${HAL_GROUP_WEB} group" 200; then
  want=$(jq -nrc --arg a "$HAL_WEB_LEAD_USER" --arg b "$HAL_WEB_DEV_USER" '[$a,$b]|sort|tostring')
  have=$(web_members)
  if [ "$have" = "$want" ]; then
    cs_record "3 web group members are jun and leo" PASS "members ${have}"
  else
    cs_record "3 web group members are jun and leo" FAIL "members ${have}, want ${want}" "${CS_BODY:0:400}"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Permission table for the web project (H/permissions.rs:255-330)
# Expected rows: group web [read, write], user jun [admin, delete, read, write]
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/permissions?target_type=project&target_id=${HAL_PROJECT_WEB_ID}&per_page=100" "$J"
if cs_expect "4 Priya reads the web project's permission rows" 200; then
  g=$(printf '%s' "$CS_BODY" | jq -r --arg id "$HAL_GROUP_WEB_ID" '[.items[]? | select(.principal_type=="group" and .principal_id==$id) | .actions | sort][0] // [] | tostring')
  u=$(printf '%s' "$CS_BODY" | jq -r --arg id "$HAL_WEB_LEAD_ID" '[.items[]? | select(.principal_type=="user" and .principal_id==$id) | .actions | sort][0] // [] | tostring')
  if [ "$g" = '["read","write"]' ] && [ "$u" = '["admin","delete","read","write"]' ]; then
    cs_record "4 web project: group web read,write; jun read,write,delete,admin" PASS "group ${g}; jun ${u}"
  else
    cs_record "4 web project: group web read,write; jun read,write,delete,admin" FAIL "group ${g}; jun ${u}" "${CS_BODY:0:600}"
  fi
fi

# ---------------------------------------------------------------------------
# 5-8. Offboard Leo once he has worked his last morning (barrier leo-worked)
# ---------------------------------------------------------------------------
LEO="$HAL_WEB_DEV_ID"
if cs_wait leo-worked "$BARRIER_TIMEOUT"; then
  offboard_start=$(( $(date +%s) - 5 ))

  # 5a. Deactivate (H/users.rs:539-574: revokes refresh families, flushes caches)
  cs_http PATCH "/api/v1/users/${LEO}" "$J" "${JSON[@]}" -d '{"is_active":false}'
  cs_expect "5a Priya deactivates Leo (PATCH is_active false)" 200

  # 5b. Remove him from the web group
  cs_http DELETE "/api/v1/groups/${HAL_GROUP_WEB_ID}/members" "$J" "${JSON[@]}" \
    -d "$(jq -nc --arg u "$LEO" '{user_ids:[$u]}')"
  cs_expect "5b Priya removes Leo from ${HAL_GROUP_WEB}" 200

  # 5c. List and revoke his API tokens
  cs_http GET "/api/v1/users/${LEO}/tokens" "$J"
  if cs_expect "5c Priya lists Leo's API tokens" 200; then
    tids=$(cs_json '.items[]?.id')
    n=0; bad=""
    for tid in $tids; do
      cs_http DELETE "/api/v1/users/${LEO}/tokens/${tid}" "$J"
      n=$(( n + 1 ))
      [ "$CS_STATUS" = "200" ] || bad="${bad} ${tid}:${CS_STATUS}"
    done
    if [ "$n" -eq 0 ]; then
      cs_record "5c Priya revokes each of Leo's tokens" FAIL \
        "Leo had no live token; the founder mints HAL_WEB_DEV_TOKEN, so at least one was expected"
    elif [ -z "$bad" ]; then
      cs_record "5c Priya revokes each of Leo's tokens" PASS "${n} token(s) revoked, each HTTP 200"
    else
      cs_record "5c Priya revokes each of Leo's tokens" FAIL "revocations not 200:${bad}"
    fi
    cs_http GET "/api/v1/users/${LEO}/tokens" "$J"
    left=$(cs_json '.items | length')
    if [ "$CS_STATUS" = "200" ] && [ "$left" = "0" ]; then
      cs_record "5c Leo has no live token left" PASS "HTTP 200, items 0"
    else
      cs_record "5c Leo has no live token left" FAIL "HTTP ${CS_STATUS}, items ${left}" "${CS_BODY:0:300}"
    fi
  fi

  # 6. Confirm Leo is gone
  cs_http GET "/api/v1/users/${LEO}" "$J"
  if cs_expect "6 Priya reads Leo's record" 200; then
    if [ "$(cs_json '.is_active')" = "false" ]; then
      cs_record "6 Leo is inactive" PASS "is_active false"
    else
      cs_record "6 Leo is inactive" FAIL "is_active=$(cs_json '.is_active')" "${CS_BODY:0:300}"
    fi
  fi
  cs_http GET "/api/v1/groups/${HAL_GROUP_WEB_ID}?member_limit=200" "$J"
  if [ "$CS_STATUS" = "200" ]; then
    cs_expect_no_body "6 web group detail no longer lists Leo" "\"${HAL_WEB_DEV_USER}\""
  else
    cs_expect "6 web group detail no longer lists Leo" 200
  fi

  # 7. Hand-off
  cs_signal leo-offboarded

  # 8. Audit trail: USER_UPDATED on Leo, actor Priya, is_active false
  # (H/admin.rs:64, 145-165; H/users.rs:650-661). The audit write is
  # fire-and-forget, so poll briefly.
  found=""; deadline=$(( $(date +%s) + 20 ))
  while :; do
    cs_http GET "/api/v1/admin/audit?resource_id=${LEO}&per_page=50" "$J"
    if [ "$CS_STATUS" = "200" ]; then
      found=$(printf '%s' "$CS_BODY" | jq -c --arg a "$HAL_PADMIN_ID" --argjson t "$offboard_start" \
        "[.items[]? | select(.action==\"USER_UPDATED\" and .user_id==\$a and (.details.is_active==false)
                         and ((.created_at | ${jq_epoch}) >= \$t))] | first // empty" 2>/dev/null)
    fi
    [ -n "$found" ] && break
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 2
  done
  if [ "$CS_STATUS" != "200" ]; then
    cs_expect "8 audit log shows Priya deactivating Leo" 200
  elif [ -n "$found" ]; then
    cs_record "8 audit log shows Priya deactivating Leo" PASS \
      "USER_UPDATED by $(printf '%s' "$found" | jq -r '.actor_username // .user_id') at $(printf '%s' "$found" | jq -r .created_at), details.is_active false"
  else
    cs_record "8 audit log shows Priya deactivating Leo" FAIL \
      "no USER_UPDATED row with user_id=Priya, details.is_active=false since the offboarding (actions seen: $(cs_json '[.items[]?.action]|unique|join(",")'))" \
      "${CS_BODY:0:600}"
  fi
else
  cs_record "waited for leo-worked (departed-employee)" FAIL \
    "${CS_WAIT_WHY}; Leo not offboarded (tasks 5-8 skipped)"
  cs_signal leo-offboarded failed
fi

# ---------------------------------------------------------------------------
# 9. Short-lived admin-scoped token for a script
# Admin may mint admin-only scopes (S/token_service.rs:160-196); the token
# is admin because it carries `admin` (A:298-301).
# ---------------------------------------------------------------------------
revoke_named_tokens() {
  local name="$1" tid
  cs_http GET /api/v1/users/me/tokens "$J"
  for tid in $(printf '%s' "$CS_BODY" | jq -r --arg n "$name" '.items[]? | select(.name==$n) | .id' 2>/dev/null); do
    cs_http DELETE "/api/v1/users/me/tokens/${tid}" "$J"
  done
}
TOK_NAME="${HAL}-padmin-script"
revoke_named_tokens "$TOK_NAME"
cs_http POST /api/v1/users/me/tokens "$J" "${JSON[@]}" \
  -d "$(jq -nc --arg n "$TOK_NAME" '{name:$n,scopes:["admin"],expires_in_days:1}')"
if cs_expect "9 Priya mints a 1-day admin-scoped token" 200; then
  PADMIN_SCRIPT_TOKEN=$(cs_json '.token // empty')
  tok_id=$(cs_json '.id // empty')
  cs_http GET "/api/v1/admin/audit?per_page=1" token:PADMIN_SCRIPT_TOKEN
  cs_expect "9 the admin-scoped token reads the audit log" 200 "A:298-301"
  cs_http DELETE "/api/v1/users/me/tokens/${tok_id}" "$J"
  cs_expect "9 Priya revokes the script token" 200
  cs_http GET "/api/v1/admin/audit?per_page=1" token:PADMIN_SCRIPT_TOKEN
  cs_expect "9 the revoked script token is refused" 401 "A:1807-1817"
fi

# Limit of her power: an admin-owned token without `admin`/`*` is not admin
# (A:298-301, GHSA-vvc3), so admin_middleware answers 403 (A:2027-2050).
NARROW_NAME="${HAL}-padmin-narrow"
revoke_named_tokens "$NARROW_NAME"
cs_http POST /api/v1/users/me/tokens "$J" "${JSON[@]}" \
  -d "$(jq -nc --arg n "$NARROW_NAME" '{name:$n,scopes:["read:artifacts"],expires_in_days:1}')"
if cs_expect "9 Priya mints a read:artifacts token" 200; then
  PADMIN_NARROW_TOKEN=$(cs_json '.token // empty')
  narrow_id=$(cs_json '.id // empty')
  cs_http GET "/api/v1/admin/audit?per_page=1" token:PADMIN_NARROW_TOKEN
  if cs_expect "9 her read:artifacts token is not admin (audit log 403)" 403 "A:298-301"; then
    cs_expect_body "9 refusal text is 'Admin access required'" "Admin access required"
  fi
  cs_http DELETE "/api/v1/users/me/tokens/${narrow_id}" "$J"
  cs_expect "9 Priya revokes the read:artifacts token" 200
fi

# ---------------------------------------------------------------------------
# 11. Short-lived incident repository in the ops project
# Expected: create 200; delete 202 with a job (#4311); key then 404.
# ---------------------------------------------------------------------------
INC_KEY="${HAL}-ops-incident-$(date +%s)"
cs_http POST /api/v1/repositories "$J" "${JSON[@]}" \
  -d "$(jq -nc --arg k "$INC_KEY" --arg p "$HAL_PROJECT_OPS_ID" \
        '{key:$k,name:$k,format:"generic",repo_type:"local",visibility:"private",project_id:$p}')"
if cs_expect "11 Priya creates incident repo ${INC_KEY} in ${HAL_PROJECT_OPS}" 200; then
  if [ "$(cs_json '.project_id')" = "$HAL_PROJECT_OPS_ID" ]; then
    cs_record "11 incident repo is assigned to the ops project" PASS "project_id ${HAL_PROJECT_OPS_ID}"
  else
    cs_record "11 incident repo is assigned to the ops project" FAIL "project_id=$(cs_json '.project_id')" "${CS_BODY:0:300}"
  fi
  cs_http DELETE "/api/v1/repositories/${INC_KEY}" "$J"
  if cs_expect "11 Priya deletes the incident repo (202 + job, #4311)" 202; then
    if [ -n "$(cs_json '.id // .job_id // empty')" ]; then
      cs_record "11 delete answers with a job" PASS "job $(cs_json '.id // .job_id') status $(cs_json '.status // empty'); Location $(cs_header location)"
    else
      cs_record "11 delete answers with a job" FAIL "202 body has no job id" "${CS_BODY:0:300}"
    fi
  fi
  cs_http GET "/api/v1/repositories/${INC_KEY}" "$J"
  cs_expect "11 the deleted incident key no longer resolves" 404
fi

# ---------------------------------------------------------------------------
# 12. Project key prefix is enforced: ${HAL}-fw-sneaky in the web project
# Expected: 400 naming project ${HAL}-fw (admin sees names, H/projects.rs:249-295)
# ---------------------------------------------------------------------------
SNEAKY="${HAL}-fw-sneaky"
cs_http POST /api/v1/repositories "$J" "${JSON[@]}" \
  -d "$(jq -nc --arg k "$SNEAKY" --arg p "$HAL_PROJECT_WEB_ID" \
        '{key:$k,name:$k,format:"generic",repo_type:"local",visibility:"private",project_id:$p}')"
if cs_expect "12 ${SNEAKY} in the web project is refused (#2473)" 400; then
  cs_expect_body "12 the refusal names project ${HAL_PROJECT_FW}" "'${HAL_PROJECT_FW}'"
elif [ "${CS_STATUS:0:1}" = "2" ]; then
  cs_http DELETE "/api/v1/repositories/${SNEAKY}" "$J"
  echo "  cleanup: deleted ${SNEAKY} (HTTP ${CS_STATUS})"
fi

# ---------------------------------------------------------------------------
# Should NOT work
# ---------------------------------------------------------------------------

# Deprecated POST /api/v1/users/{id}/roles (#3522): 200 with Deprecation and
# Link: </api/v1/permissions>; rel="successor-version". It writes user_roles,
# which no authorization gate reads, so a non-admin given `developer` still
# cannot see a private repository.
DEV_ROLE_ID="${HAL_DEVELOPER_ROLE_ID:-}"
DEV_ROLE_SRC="HAL_DEVELOPER_ROLE_ID"
if [ -z "$DEV_ROLE_ID" ]; then
  cs_http GET "/api/v1/users?per_page=200" "$J"
  for uid in $(cs_json '.items[]?.id'); do
    cs_http GET "/api/v1/users/${uid}/roles" "$J"
    DEV_ROLE_ID=$(cs_json '[.items[]? | select(.name=="developer") | .id][0] // empty')
    [ -n "$DEV_ROLE_ID" ] && { DEV_ROLE_SRC="GET /api/v1/users/{id}/roles"; break; }
  done
fi
if [ -z "$DEV_ROLE_ID" ] && [ -n "${AK_PG_URL:-}" ] && command -v psql >/dev/null 2>&1; then
  DEV_ROLE_ID=$(psql "$AK_PG_URL" -Atc "SELECT id FROM roles WHERE name = 'developer'" 2>/dev/null | head -n1 || true)
  [ -n "$DEV_ROLE_ID" ] && DEV_ROLE_SRC="read-only SELECT on roles (no API lists role ids)"
fi

if [ -z "$DEV_ROLE_ID" ]; then
  cs_record "deprecated roles endpoint (#3522)" SKIP \
    "cannot find the developer role id: no API lists roles; set HAL_DEVELOPER_ROLE_ID or AK_PG_URL"
else
  # (a) on herself: 200 + deprecation headers, then stop (she is an admin).
  cs_http POST "/api/v1/users/${HAL_PADMIN_ID}/roles" "$J" "${JSON[@]}" \
    -d "$(jq -nc --arg r "$DEV_ROLE_ID" '{role_id:$r}')"
  if cs_expect "deprecated: Priya assigns herself 'developer' via POST users/{id}/roles" 200 "role id from ${DEV_ROLE_SRC}"; then
    dep=$(cs_header deprecation); link=$(cs_header link)
    if [ -n "$dep" ]; then
      cs_record "deprecated: response carries a Deprecation header (#3522)" PASS "Deprecation: ${dep}"
    else
      cs_record "deprecated: response carries a Deprecation header (#3522)" FAIL "no Deprecation header" "$CS_HEADERS"
    fi
    if printf '%s' "$link" | grep -qF '</api/v1/permissions>; rel="successor-version"'; then
      cs_record "deprecated: Link points to /api/v1/permissions (successor-version)" PASS "Link: ${link}"
    else
      cs_record "deprecated: Link points to /api/v1/permissions (successor-version)" FAIL "Link: '${link}'" "$CS_HEADERS"
    fi
  fi
  # Remove it again from Priya (metadata only, but leave her as founded).
  cs_http DELETE "/api/v1/users/${HAL_PADMIN_ID}/roles/${DEV_ROLE_ID}" "$J"

  # (b) a throwaway non-admin given `developer` reads nothing private.
  PROBE_U="${HAL}-padmin-probe"
  HAL_PROBE_USER="$PROBE_U"
  HAL_PROBE_PASS="Halcyon-Probe-${HAL_RID:0:8}-2026!"
  cs_http GET "/api/v1/users?search=${PROBE_U}&per_page=100" "$J"
  for old in $(printf '%s' "$CS_BODY" | jq -r --arg u "$PROBE_U" '.items[]? | select(.username==$u) | .id' 2>/dev/null); do
    cs_http DELETE "/api/v1/users/${old}" "$J"
    echo "  cleanup: removed leftover ${PROBE_U} (HTTP ${CS_STATUS})"
  done
  cs_http POST /api/v1/users "$J" "${JSON[@]}" \
    -d "$(jq -nc --arg u "$PROBE_U" --arg p "$HAL_PROBE_PASS" --arg e "${PROBE_U}@halcyon.example" \
          '{username:$u,password:$p,email:$e,display_name:"Padmin probe",is_admin:false}')"
  if cs_expect "deprecated: Priya creates non-admin ${PROBE_U}" 200; then
    PROBE_ID=$(cs_json '.user.id // .id // empty')
    cs_http POST "/api/v1/users/${PROBE_ID}/roles" "$J" "${JSON[@]}" \
      -d "$(jq -nc --arg r "$DEV_ROLE_ID" '{role_id:$r}')"
    if cs_expect "deprecated: probe is given 'developer' (200)" 200; then
      [ -n "$(cs_header deprecation)" ] || cs_record "deprecated: probe assignment carries Deprecation" FAIL "no Deprecation header" "$CS_HEADERS"
    fi
    cs_http GET "/api/v1/users/${PROBE_ID}/roles" "$J"
    if [ "$(cs_json '[.items[]?.name] | index("developer") != null')" = "true" ]; then
      cs_record "deprecated: probe's user_roles lists developer" PASS "role stored as metadata"
    else
      cs_record "deprecated: probe's user_roles lists developer" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
    fi
    if cs_login PROBE; then
      cs_http GET "/api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}" jwt:PROBE
      cs_expect "deprecated: 'developer' probe cannot see private ${HAL_REPO_FW_CARGO_LOCAL} (REST 404)" 404 "user_roles grants nothing, #3522"
      cs_http GET "/maven/${HAL_REPO_FW_MAVEN_LOCAL}/com/halcyon/fw/hal-sdk/1.0.0/hal-sdk-1.0.0.jar" basic:PROBE
      cs_expect "deprecated: 'developer' probe cannot read the SDK jar (native 404)" 404 "A:2724"
      _cs_work; printf 'probe\n' > "${CS_WORK}/padmin-probe.txt"
      cs_put_generic "$HAL_REPO_OPS_BUILDS" "padmin/probe.txt" "${CS_WORK}/padmin-probe.txt" jwt:PROBE
      cs_expect "deprecated: 'developer' probe cannot write ${HAL_REPO_OPS_BUILDS} (404, #5458)" 404 "RS:126-226"
    else
      cs_record "deprecated: probe signs in" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
    fi
    cs_http DELETE "/api/v1/users/${PROBE_ID}" "$J"
    cs_expect "deprecated: Priya deletes ${PROBE_U}" 200
  fi
fi

# Deleting herself: 400 Cannot delete yourself (H/users.rs:729-731; AppError::Validation -> 400, error.rs:377).
cs_http DELETE "/api/v1/users/${HAL_PADMIN_ID}" "$J"
if cs_expect "Priya cannot delete herself" 400; then
  cs_expect_body "self-delete refusal says 'Cannot delete yourself'" "Cannot delete yourself"
fi

# ---------------------------------------------------------------------------
# 10. End the contract once Nina is done (barrier nina-done)
# H/permissions.rs:767-791 (admin only, invalidates the permission cache)
# ---------------------------------------------------------------------------
if cs_wait nina-done "$BARRIER_TIMEOUT"; then
  cs_http GET "/api/v1/permissions?principal_type=user&principal_id=${HAL_CONTRACTOR_ID}&per_page=100" "$J"
  if cs_expect "10 Priya finds Nina's rules" 200; then
    rows=$(printf '%s' "$CS_BODY" | jq -r --arg r "$HAL_REPO_FW_MAVEN_LOCAL_ID" \
      '.items[]? | select(.target_type=="repository" and .target_id==$r) | .id')
    others=$(cs_json '.items | length')
    if [ -z "$rows" ]; then
      cs_record "10 Nina has a read rule on ${HAL_CONTRACTOR_REPO}" FAIL "no rule found; ${others} row(s) total" "${CS_BODY:0:400}"
    else
      for rid in $rows; do
        cs_http DELETE "/api/v1/permissions/${rid}" "$J"
        cs_expect "10 Priya deletes Nina's rule on ${HAL_CONTRACTOR_REPO}" 200
      done
      cs_http GET "/api/v1/permissions?principal_type=user&principal_id=${HAL_CONTRACTOR_ID}&per_page=100" "$J"
      if [ "$CS_STATUS" = "200" ] && [ "$(cs_json '.items | length')" = "0" ]; then
        cs_record "10 Nina has no rule left" PASS "HTTP 200, items 0"
      else
        cs_record "10 Nina has no rule left" FAIL "HTTP ${CS_STATUS}, items $(cs_json '.items | length')" "${CS_BODY:0:300}"
      fi
    fi
  fi
  # Signal even after a FAIL above, so the contractor does not hang.
  cs_signal nina-offboarded
else
  cs_record "waited for nina-done (contractor)" FAIL \
    "${CS_WAIT_WHY}; Nina's rule kept (task 10 skipped)"
  cs_signal nina-offboarded failed
fi

cs_end
