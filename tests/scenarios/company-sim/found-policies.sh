#!/usr/bin/env bash
# found-policies.sh - the security policy section of 00-found-company.sh.
#
# Sourced by the founder after repositories, grants and tokens exist (it uses
# their HAL_REPO_* ids). Every call is a PUT/PATCH of the desired state or a
# create-if-missing, so a re-run converges.
#
# Policies (see README "Security policy at founding" and ROLES.md):
#   1. Age gates (PUT /api/v1/repositories/{key}/age-gate, handlers/age_gate.rs):
#        web-npm-remote, data-pypi-remote: 7 days, upstream_publish_time,
#          instance_locked=false, so the department lead (repository admin
#          through the project admin grant) operates the review queue (#4238);
#        fw-maven-remote: 7 days, instance_locked=true, so the firmware lead
#          may tighten it or reject but not relax or approve (#4238).
#   2. Scan on upload + a blocking scan policy on ops-docker-local
#      (PUT .../security, POST /api/v1/security/policies): critical findings
#      block downloads with 403 (#4510).
#   3. Upload-period quarantine on ops-helm (PATCH /api/v1/repositories/{key}
#      quarantine_enabled, 60 min): a fresh chart answers 409 until an admin
#      releases it (docs/security/download-holds.md).

_age_gate() { # VAR LOCKED
  local locked="$2" kv="HAL_REPO_${1}"
  local key="${!kv}"
  cs_http PUT "/api/v1/repositories/${key}/age-gate" admin -H 'Content-Type: application/json' \
    -d "$(jq -nc --argjson l "$locked" '{enabled:true,min_age_days:7,mode:"upstream_publish_time",instance_locked:$l}')"
  if [ "${CS_STATUS:0:1}" = "2" ]; then
    cs_record "age gate on ${key} (7 days, instance_locked=${locked})" PASS "HTTP ${CS_STATUS}"
  else
    cs_record "age gate on ${key} (7 days, instance_locked=${locked})" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
  fi
}
_age_gate WEB_NPM_REMOTE false
_age_gate DATA_PYPI_REMOTE false
_age_gate FW_MAVEN_REMOTE true
cs_env_set HAL_AGE_GATE_DAYS 7
cs_env_set HAL_AGE_GATE_REPOS "WEB_NPM_REMOTE DATA_PYPI_REMOTE FW_MAVEN_REMOTE"
cs_env_set HAL_AGE_GATE_LOCKED_REPOS "FW_MAVEN_REMOTE"

# 2. Scanning on ops-docker-local.
cs_http PUT "/api/v1/repositories/${HAL_REPO_OPS_DOCKER_LOCAL}/security" admin -H 'Content-Type: application/json' \
  -d '{"scan_enabled":true,"scan_on_upload":true,"block_on_policy_violation":true,"severity_threshold":"critical"}'
if [ "${CS_STATUS:0:1}" = "2" ]; then
  cs_record "scan on upload for ${HAL_REPO_OPS_DOCKER_LOCAL}" PASS "HTTP ${CS_STATUS}"
else
  cs_record "scan on upload for ${HAL_REPO_OPS_DOCKER_LOCAL}" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
fi

POLICY_NAME="${HAL}-block-critical-images"
cs_http GET /api/v1/security/policies admin
pol_id=$(printf '%s' "$CS_BODY" | jq -r --arg n "$POLICY_NAME" '(if type=="array" then . else (.items // []) end)[]? | select(.name==$n) | .id' 2>/dev/null | head -n1 || true)
pol_body=$(jq -nc --arg n "$POLICY_NAME" --arg r "$HAL_REPO_OPS_DOCKER_LOCAL_ID" \
  '{name:$n,repository_id:$r,max_severity:"critical",block_unscanned:false,block_on_fail:true}')
if [ -z "$pol_id" ]; then
  cs_http POST /api/v1/security/policies admin -H 'Content-Type: application/json' -d "$pol_body"
  pol_id=$(cs_json '.id // empty')
else
  cs_http PUT "/api/v1/security/policies/${pol_id}" admin -H 'Content-Type: application/json' -d "$pol_body"
fi
if [ -n "$pol_id" ] && [ "${CS_STATUS:0:1}" = "2" ]; then
  cs_record "scan policy ${POLICY_NAME} (critical blocks, ops-docker-local)" PASS "id ${pol_id}"
else
  cs_record "scan policy ${POLICY_NAME} (critical blocks, ops-docker-local)" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:400}"
fi
cs_env_set HAL_SCAN_POLICY "$POLICY_NAME"
cs_env_set HAL_SCAN_POLICY_ID "${pol_id:-}"

# 3. Upload-period quarantine on ops-helm.
cs_http PATCH "/api/v1/repositories/${HAL_REPO_OPS_HELM}" admin -H 'Content-Type: application/json' \
  -d '{"quarantine_enabled":true,"quarantine_duration_minutes":60}'
if [ "${CS_STATUS:0:1}" = "2" ] && [ "$(cs_json '.quarantine_enabled')" = "true" ]; then
  cs_record "quarantine 60 min on ${HAL_REPO_OPS_HELM}" PASS "HTTP ${CS_STATUS}"
else
  cs_record "quarantine 60 min on ${HAL_REPO_OPS_HELM}" FAIL "HTTP ${CS_STATUS} quarantine_enabled=$(cs_json '.quarantine_enabled')" "${CS_BODY:0:400}"
fi
cs_env_set HAL_QUARANTINE_REPO "OPS_HELM"
cs_env_set HAL_QUARANTINE_MINUTES 60
