#!/usr/bin/env bash
# 00-found-company.sh - the platform admin stands up Halcyon Robotics.
#
# Run as the bootstrap admin (ADMIN_USER/ADMIN_PASS) against a fresh or
# previously-founded instance. Creates, or converges to the founding state,
# every user, group, project, repository, grant, service account, token and
# policy the role scripts rely on, seeds one "day 0" artifact per hosted
# repository, and writes personas.env for the roles.
#
# Idempotent: a second run against the same RUN_ID re-activates a departed
# employee, restores group membership and grants, resets changed passwords,
# and re-mints tokens (a token secret is shown once, so it cannot be
# recovered), then rewrites personas.env.
#
# See README.md for the org chart and ROLES.md for what each role does.
#
# Env: BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, JUNIT_OUTPUT_DIR (common.sh);
#      COMPANY_SIM_STATE_DIR (default $JUNIT_OUTPUT_DIR/company-sim-<rid>);
#      HAL_UPSTREAM_{CRATES,MAVEN,NPM,PYPI,CONDA,DOCKER} to point the Remotes
#      at mirrors when the runner has no internet.
#
# Requires: curl, jq, python3, tar, sha256sum.

source "$(dirname "$0")/lib.sh"

cs_begin found --no-personas
auth_admin
cs_reset_signals

HAL_UPSTREAM_CRATES="${HAL_UPSTREAM_CRATES:-https://crates.io}"
HAL_UPSTREAM_MAVEN="${HAL_UPSTREAM_MAVEN:-https://repo1.maven.org/maven2}"
HAL_UPSTREAM_NPM="${HAL_UPSTREAM_NPM:-https://registry.npmjs.org}"
HAL_UPSTREAM_PYPI="${HAL_UPSTREAM_PYPI:-https://pypi.org}"
HAL_UPSTREAM_CONDA="${HAL_UPSTREAM_CONDA:-https://conda.anaconda.org/conda-forge}"
HAL_UPSTREAM_DOCKER="${HAL_UPSTREAM_DOCKER:-https://registry-1.docker.io}"

cs_env_set HAL_RID "$HAL_RID"
cs_env_set HAL "$HAL"
cs_env_set HAL_BASE_URL "$BASE_URL"
cs_env_set HAL_RUN_ID "$RUN_ID"

# ---------------------------------------------------------------------------
# 1. People
# ---------------------------------------------------------------------------
# PERSONA|first name|display name|is_admin|job
PEOPLE=(
  "PADMIN|priya|Priya Raman|true|Platform admin (IT)"
  "FW_LEAD|mara|Mara Okafor|false|Firmware lead"
  "FW_DEV|tomas|Tomas Berg|false|Firmware engineer"
  "WEB_LEAD|jun|Jun Park|false|Web lead"
  "WEB_DEV|leo|Leo Varga|false|Web engineer (leaves the company today)"
  "DATA_LEAD|sofia|Sofia Mendes|false|Data lead"
  "DATA_DEV|arjun|Arjun Das|false|Data engineer"
  "OPS_LEAD|kai|Kai Nakamura|false|DevOps lead"
  "SEC_LEAD|rhea|Rhea Collins|true|Security lead (instance admin)"
  "SEC_ANALYST|omar|Omar Haddad|false|Security analyst"
  "CONTRACTOR|nina|Nina Petrov|false|Contractor, Petrov Embedded LLC"
  "AUDITOR|ellen|Ellen Shaw|false|External auditor"
)

for row in "${PEOPLE[@]}"; do
  IFS='|' read -r key first display adm job <<< "$row"
  user="${HAL}-${first}"
  # Deterministic per run: a re-run converges to the same password.
  pass="Halcyon-${first^}-${HAL_RID:0:8}-2026!"
  if cs_ensure_user "$user" "$pass" "${first}@${HAL}.halcyon.test" "$display" "$adm"; then
    cs_record "user ${user} (${job})" PASS "id ${CS_ID} is_admin=${adm}"
  else
    cs_record "user ${user} (${job})" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
    end_suite
  fi
  cs_env_set "HAL_${key}_USER" "$user"
  cs_env_set "HAL_${key}_PASS" "$pass"
  cs_env_set "HAL_${key}_ID" "$CS_ID"
  cs_env_set "HAL_${key}_NAME" "$display"
done

# Every persona can sign in (and none is forced to change its password).
for row in "${PEOPLE[@]}"; do
  IFS='|' read -r key _ <<< "$row"
  if cs_login "$key"; then
    cs_http GET /api/v1/users/me "jwt:${key}"
    if [ "$(cs_json '.must_change_password')" = "false" ] && [ "$(cs_json '.is_active')" = "true" ]; then
      cs_record "login ${key}" PASS "active, no forced password change"
    else
      cs_record "login ${key}" FAIL "users/me: ${CS_BODY:0:200}"
    fi
  else
    cs_record "login ${key}" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
  fi
done

# ---------------------------------------------------------------------------
# 2. Teams = groups
# ---------------------------------------------------------------------------
# GROUP KEY|name suffix|description|member personas
TEAMS=(
  "FIRMWARE|firmware|Firmware team|FW_LEAD FW_DEV"
  "WEB|web|Web team|WEB_LEAD WEB_DEV"
  "DATA|data|Data team|DATA_LEAD DATA_DEV"
  "DEVOPS|devops|DevOps team|OPS_LEAD"
  "SECURITY|security|Security team|SEC_LEAD SEC_ANALYST"
  "AUDITORS|auditors|External auditors (read-only)|AUDITOR"
)
for row in "${TEAMS[@]}"; do
  IFS='|' read -r gk gname gdesc members <<< "$row"
  name="${HAL}-${gname}"
  if ! cs_ensure_group "$name" "Halcyon Robotics: ${gdesc}"; then
    cs_record "group ${name}" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
    continue
  fi
  gid="$CS_ID"
  ids=()
  for m in $members; do ids+=("$(cs_uid "$m")"); done
  if cs_set_group_members "$gid" "${ids[@]}"; then
    cs_record "group ${name}" PASS "id ${gid}, members: ${members}"
  else
    cs_record "group ${name}" FAIL "membership HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
  fi
  cs_env_set "HAL_GROUP_${gk}" "$name"
  cs_env_set "HAL_GROUP_${gk}_ID" "$gid"
done

# ---------------------------------------------------------------------------
# 3. Departments = projects
# ---------------------------------------------------------------------------
# PROJECT KEY|key suffix|name
DEPTS=(
  "FW|fw|Firmware"
  "WEB|web|Web"
  "DATA|data|Data"
  "OPS|ops|DevOps"
)
for row in "${DEPTS[@]}"; do
  IFS='|' read -r pk ksuf pname <<< "$row"
  pkey="${HAL}-${ksuf}"
  if cs_ensure_project "$pkey" "Halcyon ${pname}" "Halcyon Robotics ${pname} department"; then
    cs_record "project ${pkey}" PASS "id ${CS_ID}"
  else
    cs_record "project ${pkey}" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
    end_suite
  fi
  cs_env_set "HAL_PROJECT_${pk}" "$pkey"
  cs_env_set "HAL_PROJECT_${pk}_ID" "$CS_ID"
done

# ---------------------------------------------------------------------------
# 4. Repositories
# ---------------------------------------------------------------------------
# REPO VAR|key suffix|format|type|visibility|project|upstream
REPOS=(
  "FW_CARGO_LOCAL|fw-cargo-local|cargo|local|private|FW|"
  "FW_CARGO_REMOTE|fw-cargo-remote|cargo|remote|private|FW|${HAL_UPSTREAM_CRATES}"
  "FW_CARGO|fw-cargo|cargo|virtual|private|FW|"
  "FW_MAVEN_LOCAL|fw-maven-local|maven|local|private|FW|"
  "FW_MAVEN_REMOTE|fw-maven-remote|maven|remote|private|FW|${HAL_UPSTREAM_MAVEN}"
  "FW_MAVEN|fw-maven|maven|virtual|private|FW|"
  "WEB_NPM_LOCAL|web-npm-local|npm|local|private|WEB|"
  "WEB_NPM_REMOTE|web-npm-remote|npm|remote|private|WEB|${HAL_UPSTREAM_NPM}"
  "WEB_NPM|web-npm|npm|virtual|private|WEB|"
  "DATA_PYPI_LOCAL|data-pypi-local|pypi|local|private|DATA|"
  "DATA_PYPI_REMOTE|data-pypi-remote|pypi|remote|private|DATA|${HAL_UPSTREAM_PYPI}"
  "DATA_PYPI|data-pypi|pypi|virtual|private|DATA|"
  "DATA_CONDA_LOCAL|data-conda-local|conda|local|private|DATA|"
  "DATA_CONDA_REMOTE|data-conda-remote|conda|remote|private|DATA|${HAL_UPSTREAM_CONDA}"
  "DATA_CONDA|data-conda|conda|virtual|private|DATA|"
  "OPS_DOCKER_LOCAL|ops-docker-local|docker|local|private|OPS|"
  "OPS_DOCKER_REMOTE|ops-docker-remote|docker|remote|private|OPS|${HAL_UPSTREAM_DOCKER}"
  "OPS_DOCKER|ops-docker|docker|virtual|private|OPS|"
  "OPS_BUILDS|ops-builds|generic|local|private|OPS|"
  "OPS_HELM|ops-helm|helm|local|private|OPS|"
  "HANDBOOK|handbook|generic|local|internal||"
)
for row in "${REPOS[@]}"; do
  IFS='|' read -r rv ksuf fmt rtype vis proj up <<< "$row"
  key="${HAL}-${ksuf}"
  pid=""
  [ -n "$proj" ] && { v="HAL_PROJECT_${proj}_ID"; pid="${!v}"; }
  if cs_ensure_repo "$key" "$fmt" "$rtype" "$vis" "$pid" "$up"; then
    cs_record "repo ${key} (${fmt} ${rtype} ${vis})" PASS "id ${CS_ID}${proj:+ project ${proj}}"
  else
    cs_record "repo ${key} (${fmt} ${rtype} ${vis})" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
    continue
  fi
  cs_env_set "HAL_REPO_${rv}" "$key"
  cs_env_set "HAL_REPO_${rv}_ID" "$CS_ID"
done

# Virtual members: hosted first, the Remote behind it.
VMEMBERS=(
  "FW_CARGO|FW_CARGO_LOCAL FW_CARGO_REMOTE"
  "FW_MAVEN|FW_MAVEN_LOCAL FW_MAVEN_REMOTE"
  "WEB_NPM|WEB_NPM_LOCAL WEB_NPM_REMOTE"
  "DATA_PYPI|DATA_PYPI_LOCAL DATA_PYPI_REMOTE"
  "DATA_CONDA|DATA_CONDA_LOCAL DATA_CONDA_REMOTE"
  "OPS_DOCKER|OPS_DOCKER_LOCAL OPS_DOCKER_REMOTE"
)
for row in "${VMEMBERS[@]}"; do
  IFS='|' read -r vv members <<< "$row"
  vk_var="HAL_REPO_${vv}"; vkey="${!vk_var:-}"
  [ -n "$vkey" ] || continue
  prio=1; ok=true; names=""
  for m in $members; do
    mk_var="HAL_REPO_${m}"; mkey="${!mk_var:-}"
    if ! cs_ensure_virtual_member "$vkey" "$mkey" "$prio"; then ok=false; fi
    names="${names} ${mkey}@${prio}"
    prio=$(( prio + 1 ))
  done
  if $ok; then
    cs_record "virtual ${vkey} members" PASS "${names# }"
  else
    cs_record "virtual ${vkey} members" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
  fi
done

# ---------------------------------------------------------------------------
# 5. Access: project grants (team-wide) and repository grants (exceptions)
# ---------------------------------------------------------------------------
# principal type|principal id var|project|actions|why
PROJECT_GRANTS=(
  "group|HAL_GROUP_FIRMWARE_ID|FW|[\"read\",\"write\"]|firmware engineers publish and consume firmware packages"
  "user|HAL_FW_LEAD_ID|FW|[\"read\",\"write\",\"delete\",\"admin\"]|firmware lead administers the firmware department"
  "group|HAL_GROUP_WEB_ID|WEB|[\"read\",\"write\"]|web engineers publish and consume npm packages"
  "user|HAL_WEB_LEAD_ID|WEB|[\"read\",\"write\",\"delete\",\"admin\"]|web lead administers the web department"
  "group|HAL_GROUP_DATA_ID|DATA|[\"read\",\"write\"]|data engineers publish and consume python/conda packages"
  "user|HAL_DATA_LEAD_ID|DATA|[\"read\",\"write\",\"delete\",\"admin\"]|data lead administers the data department"
  "group|HAL_GROUP_DEVOPS_ID|OPS|[\"read\",\"write\",\"delete\"]|devops runs the image, chart and build-artifact repositories"
  "user|HAL_OPS_LEAD_ID|OPS|[\"read\",\"write\",\"delete\",\"admin\"]|devops lead administers the ops department"
  "group|HAL_GROUP_DEVOPS_ID|FW|[\"read\"]|devops packages firmware into images"
  "group|HAL_GROUP_DEVOPS_ID|WEB|[\"read\"]|devops packages the web front end into images"
  "group|HAL_GROUP_DEVOPS_ID|DATA|[\"read\"]|devops packages data services into images"
  "group|HAL_GROUP_SECURITY_ID|FW|[\"read\"]|security reviews every department"
  "group|HAL_GROUP_SECURITY_ID|WEB|[\"read\"]|security reviews every department"
  "group|HAL_GROUP_SECURITY_ID|DATA|[\"read\"]|security reviews every department"
  "group|HAL_GROUP_SECURITY_ID|OPS|[\"read\"]|security reviews every department"
  "group|HAL_GROUP_AUDITORS_ID|FW|[\"read\"]|auditor: view-only everywhere"
  "group|HAL_GROUP_AUDITORS_ID|WEB|[\"read\"]|auditor: view-only everywhere"
  "group|HAL_GROUP_AUDITORS_ID|DATA|[\"read\"]|auditor: view-only everywhere"
  "group|HAL_GROUP_AUDITORS_ID|OPS|[\"read\"]|auditor: view-only everywhere"
)
for row in "${PROJECT_GRANTS[@]}"; do
  IFS='|' read -r pt pvar proj acts why <<< "$row"
  prid="${!pvar}"
  pv="HAL_PROJECT_${proj}_ID"; projid="${!pv}"
  pn="HAL_PROJECT_${proj}"
  if cs_ensure_project_member "$projid" "$pt" "$prid" "$acts"; then
    cs_record "project grant ${pvar#HAL_} on ${!pn} ${acts}" PASS "$why"
  else
    cs_record "project grant ${pvar#HAL_} on ${!pn} ${acts}" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
  fi
done

# The contractor gets read on exactly one repository: the firmware SDK jars.
if cs_ensure_grant user "$HAL_CONTRACTOR_ID" repository "$HAL_REPO_FW_MAVEN_LOCAL_ID" '["read"]'; then
  cs_record "repo grant CONTRACTOR read on ${HAL_REPO_FW_MAVEN_LOCAL}" PASS "rule ${CS_ID}"
else
  cs_record "repo grant CONTRACTOR read on ${HAL_REPO_FW_MAVEN_LOCAL}" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
fi
cs_env_set HAL_CONTRACTOR_REPO "$HAL_REPO_FW_MAVEN_LOCAL"

# ---------------------------------------------------------------------------
# 6. CI service account and its tokens
# ---------------------------------------------------------------------------
if cs_ensure_service_account "${HAL}-ci" "Halcyon CI (builds and publishes on merge)"; then
  cs_record "service account svc-${HAL}-ci" PASS "id ${CS_ID}"
else
  cs_record "service account svc-${HAL}-ci" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
  end_suite
fi
cs_env_set HAL_CI_SA_ID "$CS_ID"
cs_env_set HAL_CI_SA_USER "svc-${HAL}-ci"

# What CI may do, as grants on the service account principal:
#   read on every department (resolve dependencies through the virtuals),
#   write on the hosted repositories it publishes to.
for proj in FW WEB DATA OPS; do
  pv="HAL_PROJECT_${proj}_ID"
  if cs_ensure_project_member "${!pv}" service_account "$HAL_CI_SA_ID" '["read"]'; then
    cs_record "project grant CI read on ${proj}" PASS "service_account principal"
  else
    cs_record "project grant CI read on ${proj}" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
  fi
done
CI_PUBLISH=(FW_CARGO_LOCAL FW_MAVEN_LOCAL WEB_NPM_LOCAL DATA_PYPI_LOCAL OPS_DOCKER_LOCAL OPS_BUILDS OPS_HELM)
for rv in "${CI_PUBLISH[@]}"; do
  iv="HAL_REPO_${rv}_ID"; kv="HAL_REPO_${rv}"
  if cs_ensure_grant service_account "$HAL_CI_SA_ID" repository "${!iv}" '["read","write"]'; then
    cs_record "repo grant CI write on ${!kv}" PASS "rule ${CS_ID}"
  else
    cs_record "repo grant CI write on ${!kv}" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
  fi
done

# Publish token: write scope, confined to the hosted repositories CI
# publishes to plus the virtuals it resolves through. data-conda-local is
# deliberately NOT in it (the "token scoped elsewhere -> 404" check).
ci_repos=()
for rv in "${CI_PUBLISH[@]}" FW_CARGO FW_MAVEN WEB_NPM DATA_PYPI OPS_DOCKER; do
  iv="HAL_REPO_${rv}_ID"; ci_repos+=("${!iv}")
done
ci_repo_json=$(printf '%s\n' "${ci_repos[@]}" | jq -R . | jq -sc .)
if cs_mint_sa_token "$HAL_CI_SA_ID" "${HAL}-ci-publish" '["read:artifacts","write:artifacts"]' "$ci_repo_json"; then
  cs_record "CI publish token (read+write:artifacts, ${#ci_repos[@]} repos)" PASS "minted"
  cs_env_set HAL_CI_TOKEN "$CS_TOKEN"
else
  cs_record "CI publish token" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
fi
cs_env_set HAL_CI_TOKEN_REPOS "$(printf '%s ' "${CI_PUBLISH[@]}" FW_CARGO FW_MAVEN WEB_NPM DATA_PYPI OPS_DOCKER)"

# Deploy token: read-only, images and charts only (what the cluster pulls with).
deploy_json=$(jq -nc --arg a "$HAL_REPO_OPS_DOCKER_ID" --arg b "$HAL_REPO_OPS_DOCKER_LOCAL_ID" --arg c "$HAL_REPO_OPS_HELM_ID" '[$a,$b,$c]')
if cs_mint_sa_token "$HAL_CI_SA_ID" "${HAL}-deploy-pull" '["read:artifacts"]' "$deploy_json"; then
  cs_record "deploy pull token (read:artifacts, ops-docker + ops-helm)" PASS "minted"
  cs_env_set HAL_DEPLOY_TOKEN "$CS_TOKEN"
else
  cs_record "deploy pull token" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
fi

# ---------------------------------------------------------------------------
# 7. Personal API tokens (each engineer mints their own, self-service)
# ---------------------------------------------------------------------------
for key in FW_DEV WEB_DEV DATA_DEV OPS_LEAD; do
  if cs_mint_user_token "$key" "${HAL}-${key,,}-laptop" '["read:artifacts","write:artifacts"]'; then
    cs_record "personal token ${key}" PASS "self-minted via /users/me/tokens"
    cs_env_set "HAL_${key}_TOKEN" "$CS_TOKEN"
  else
    cs_record "personal token ${key}" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
  fi
done

# ---------------------------------------------------------------------------
# 8. Security policy (see the policy section below)
# ---------------------------------------------------------------------------
# shellcheck source=found-policies.sh
source "${CS_DIR}/found-policies.sh"

# ---------------------------------------------------------------------------
# 9. Day 0 content: one artifact in each hosted repository, published by
#    the admin so every role starts from the same catalogue.
# ---------------------------------------------------------------------------
cs_env_set HAL_SEED_MAVEN_GROUP "com/halcyon/fw"
cs_env_set HAL_SEED_MAVEN_ARTIFACT "hal-sdk"
cs_env_set HAL_SEED_MAVEN_VERSION "1.0.0"
# The crate name carries HAL: on a shared-namespace storage backend (S3) a
# cargo storage key is cargo/<name>/<version>/..., not per repository, so a
# second company on the same instance could not publish the same crate
# version (409 "refusing cross-repository overwrite",
# artifact_service.rs guard_foreign_storage_key_for_backend).
cs_env_set HAL_SEED_CRATE "${HAL}-motor"
cs_env_set HAL_SEED_CRATE_VERSION "0.1.0"
cs_env_set HAL_SEED_NPM "halcyon-ui-kit"
cs_env_set HAL_SEED_NPM_VERSION "1.0.0"
cs_env_set HAL_SEED_PYPI "halcyon-telemetry"
cs_env_set HAL_SEED_PYPI_VERSION "1.0.0"
cs_env_set HAL_SEED_FW_BIN "firmware/1.0.0/hal-fw-1.0.0.bin"
cs_env_set HAL_SEED_FW_BIN_SIZE "262144"
cs_env_set HAL_SEED_HANDBOOK "handbook/onboarding.md"

ADMIN_BASIC_USER="$ADMIN_USER"
_seed() { # WHAT GET_PATH PUBLISH_CMD...
  local what="$1" get="$2"; shift 2
  cs_http GET "$get" admin
  if [ "$CS_STATUS" = "200" ]; then
    cs_record "seed ${what}" PASS "already present"
    return
  fi
  "$@"
  if [ "${CS_STATUS:0:1}" = "2" ]; then
    cs_record "seed ${what}" PASS "HTTP ${CS_STATUS}"
  else
    cs_record "seed ${what}" FAIL "HTTP ${CS_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:400}"
  fi
}
# The bootstrap admin is persona "BOOT" for Basic auth on native routes.
export HAL_BOOT_USER="$ADMIN_BASIC_USER" HAL_BOOT_PASS="$ADMIN_PASS"  # read by cs_user/cs_pass

_seed "maven ${HAL_SEED_MAVEN_ARTIFACT}-${HAL_SEED_MAVEN_VERSION}.jar" \
  "/maven/${HAL_REPO_FW_MAVEN_LOCAL}/${HAL_SEED_MAVEN_GROUP}/${HAL_SEED_MAVEN_ARTIFACT}/${HAL_SEED_MAVEN_VERSION}/${HAL_SEED_MAVEN_ARTIFACT}-${HAL_SEED_MAVEN_VERSION}.jar" \
  cs_put_maven "$HAL_REPO_FW_MAVEN_LOCAL" "$HAL_SEED_MAVEN_GROUP" "$HAL_SEED_MAVEN_ARTIFACT" "$HAL_SEED_MAVEN_VERSION" basic:BOOT
_seed "crate ${HAL_SEED_CRATE} ${HAL_SEED_CRATE_VERSION}" \
  "/cargo/${HAL_REPO_FW_CARGO_LOCAL}/api/v1/crates/${HAL_SEED_CRATE}/${HAL_SEED_CRATE_VERSION}/download" \
  cs_publish_cargo "$HAL_REPO_FW_CARGO_LOCAL" "$HAL_SEED_CRATE" "$HAL_SEED_CRATE_VERSION" basic:BOOT
_seed "npm ${HAL_SEED_NPM}@${HAL_SEED_NPM_VERSION}" \
  "/npm/${HAL_REPO_WEB_NPM_LOCAL}/${HAL_SEED_NPM}/-/${HAL_SEED_NPM}-${HAL_SEED_NPM_VERSION}.tgz" \
  cs_publish_npm "$HAL_REPO_WEB_NPM_LOCAL" "$HAL_SEED_NPM" "$HAL_SEED_NPM_VERSION" basic:BOOT
_seed "pypi ${HAL_SEED_PYPI} ${HAL_SEED_PYPI_VERSION}" \
  "/pypi/${HAL_REPO_DATA_PYPI_LOCAL}/simple/${HAL_SEED_PYPI}/" \
  cs_publish_pypi "$HAL_REPO_DATA_PYPI_LOCAL" "$HAL_SEED_PYPI" "$HAL_SEED_PYPI_VERSION" basic:BOOT
_cs_work
cs_fixture_bytes "${CS_WORK}/fw.bin" "$HAL_SEED_FW_BIN_SIZE" "halcyon-fw-1.0.0"
cs_env_set HAL_SEED_FW_BIN_SHA256 "$(sha256sum "${CS_WORK}/fw.bin" | cut -d' ' -f1)"
_seed "generic ${HAL_SEED_FW_BIN}" \
  "/api/v1/repositories/${HAL_REPO_OPS_BUILDS}/download/${HAL_SEED_FW_BIN}" \
  cs_put_generic "$HAL_REPO_OPS_BUILDS" "$HAL_SEED_FW_BIN" "${CS_WORK}/fw.bin" admin
printf '# Welcome to Halcyon Robotics\n\nEvery employee can read this handbook.\n' > "${CS_WORK}/onboarding.md"
_seed "handbook ${HAL_SEED_HANDBOOK}" \
  "/api/v1/repositories/${HAL_REPO_HANDBOOK}/download/${HAL_SEED_HANDBOOK}" \
  cs_put_generic "$HAL_REPO_HANDBOOK" "$HAL_SEED_HANDBOOK" "${CS_WORK}/onboarding.md" admin

# ---------------------------------------------------------------------------
# 10. Founding-state sanity: the access model answers the way the README says
# ---------------------------------------------------------------------------
# A handful of checks only; the roles do the real work. Permission caches
# are invalidated on every grant write, so these see the new rules at once.
cs_http GET "/maven/${HAL_REPO_FW_MAVEN_LOCAL}/${HAL_SEED_MAVEN_GROUP}/${HAL_SEED_MAVEN_ARTIFACT}/${HAL_SEED_MAVEN_VERSION}/${HAL_SEED_MAVEN_ARTIFACT}-${HAL_SEED_MAVEN_VERSION}.jar" basic:CONTRACTOR
cs_expect "sanity: contractor reads the firmware SDK jar" 200
cs_http GET "/api/v1/repositories/${HAL_REPO_WEB_NPM_LOCAL}" jwt:CONTRACTOR
cs_expect "sanity: contractor cannot see web-npm-local (deny-by-hide)" 404
cs_http GET "/api/v1/repositories/${HAL_REPO_HANDBOOK}/download/${HAL_SEED_HANDBOOK}" jwt:CONTRACTOR
cs_expect "sanity: internal handbook is readable by any login, contractor included" 200
cs_http GET "/api/v1/repositories/${HAL_REPO_HANDBOOK}/download/${HAL_SEED_HANDBOOK}" none
cs_expect "sanity: internal handbook refused to anonymous callers (401 challenge, A:1934-1940)" 401
cs_http GET "/api/v1/repositories/${HAL_REPO_DATA_PYPI_LOCAL}" jwt:AUDITOR
cs_expect "sanity: auditor sees data-pypi-local through the auditors group" 200
cs_http GET "/api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}" jwt:WEB_DEV
cs_expect "sanity: web engineer cannot see firmware repos" 404

# ---------------------------------------------------------------------------
# 11. The built-in `developer` role id, for platform-admin's check of the
#     deprecated POST /api/v1/users/{id}/roles (#3522). No API lists roles
#     (only GET /users/{id}/roles, per user), so: HAL_DEVELOPER_ROLE_ID from
#     the environment, else any user's role list, else a read-only SELECT
#     when AK_PG_URL and psql are available. Empty means the role SKIPs it.
# ---------------------------------------------------------------------------
dev_role="${HAL_DEVELOPER_ROLE_ID:-}" dev_role_src="HAL_DEVELOPER_ROLE_ID"
if [ -z "$dev_role" ]; then
  cs_http GET "/api/v1/users?per_page=200" admin
  for uid in $(cs_json '.items[]?.id'); do
    cs_http GET "/api/v1/users/${uid}/roles" admin
    dev_role=$(cs_json '[(.items // .)[]? | select(.name=="developer") | .id][0] // empty')
    [ -n "$dev_role" ] && { dev_role_src="GET /api/v1/users/{id}/roles"; break; }
  done
fi
if [ -z "$dev_role" ] && [ -n "${AK_PG_URL:-}" ] && command -v psql >/dev/null 2>&1; then
  dev_role=$(psql "$AK_PG_URL" -Atc "SELECT id FROM roles WHERE name = 'developer'" 2>/dev/null | head -n1 || true)
  [ -n "$dev_role" ] && dev_role_src="read-only SELECT on roles (AK_PG_URL)"
fi
cs_env_set HAL_DEVELOPER_ROLE_ID "$dev_role"
if [ -n "$dev_role" ]; then
  cs_record "developer role id for the deprecated roles check (#3522)" PASS "from ${dev_role_src}"
else
  cs_record "developer role id for the deprecated roles check (#3522)" SKIP \
    "no API lists role ids; set HAL_DEVELOPER_ROLE_ID or AK_PG_URL (platform-admin then SKIPs that check)"
fi

cs_env_write
cs_record "personas.env written" PASS "${PERSONAS_ENV} ($(wc -l < "$PERSONAS_ENV") lines)"

end_suite
